from __future__ import annotations

import ipaddress
import os
import threading
import time
from pathlib import Path

from .config import (
    HIGH_RISK_PROCESS_NAMES,
    NETWORK_MONITOR_INTERVAL_SECONDS,
    NETWORK_PUBLIC_BURST_THRESHOLD,
    TRUSTED_NETWORK_CLIENT_NAMES,
    TRUSTED_NETWORK_PORTS,
    USER_SPACE_HINTS,
    is_managed_path,
)
from .logging_setup import get_logger
from .models import FileScanResult, ScanFinding

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None


class NetworkConnectionMonitor:
    def __init__(self, scanner, database, interval_seconds: int = NETWORK_MONITOR_INTERVAL_SECONDS) -> None:
        self.scanner = scanner
        self.database = database
        self.interval_seconds = max(2, int(interval_seconds))
        self.logger = get_logger("ragnar_protect.network")
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._seen: dict[tuple[int, str, int], float] = {}

    @property
    def available(self) -> bool:
        return psutil is not None

    def start(self) -> None:
        if not self.available or self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, name="RagnarNetworkMonitor", daemon=True)
        self._thread.start()
        self.logger.info("network monitor started")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.logger.info("network monitor stopped")

    def _loop(self) -> None:
        while not self._stop_event.wait(self.interval_seconds):
            try:
                self._scan_connections()
            except Exception as exc:
                self.logger.exception("network monitor loop failed | %s", exc)

    def _scan_connections(self) -> None:
        if psutil is None:
            return
        public_counts: dict[int, int] = {}
        for conn in psutil.net_connections(kind="inet"):
            pid = int(getattr(conn, "pid", 0) or 0)
            raddr = getattr(conn, "raddr", None)
            status = str(getattr(conn, "status", "") or "")
            if pid <= 0 or raddr is None or not getattr(raddr, "ip", ""):
                continue
            if status not in {"ESTABLISHED", "SYN_SENT", "CLOSE_WAIT"}:
                continue
            remote_ip = str(raddr.ip)
            if not self._is_public_ip(remote_ip):
                continue
            public_counts[pid] = public_counts.get(pid, 0) + 1
            key = (pid, remote_ip, int(getattr(raddr, "port", 0) or 0))
            if self._seen.get(key, 0.0) > time.time():
                continue
            self._seen[key] = time.time() + max(self.interval_seconds * 3, 15)
            self._inspect_connection(conn, public_counts.get(pid, 1))

    def _inspect_connection(self, conn, public_count: int) -> None:
        if psutil is None:
            return
        pid = int(getattr(conn, "pid", 0) or 0)
        try:
            proc = psutil.Process(pid)
        except Exception:
            return
        name = str(getattr(conn, "pid", 0) or "")
        try:
            name = str(proc.name() or "")
        except Exception:
            pass
        try:
            exe = str(proc.exe() or "")
        except Exception:
            exe = ""
        if not exe or is_managed_path(exe):
            return
        process_name = name.lower()
        high_risk = process_name in HIGH_RISK_PROCESS_NAMES
        user_space = self._is_user_space_path(exe)
        remote_ip = str(conn.raddr.ip)
        remote_port = int(conn.raddr.port)
        trusted_client = self._is_trusted_network_client(process_name, exe)
        if (
            trusted_client
            and not high_risk
            and remote_port in TRUSTED_NETWORK_PORTS
            and public_count < max(6, NETWORK_PUBLIC_BURST_THRESHOLD * 3)
        ):
            return
        score = 0
        findings: list[ScanFinding] = []
        if high_risk:
            findings.append(
                ScanFinding(
                    kind="network_high_risk_host",
                    title="High-risk process with outbound connection",
                    score=28,
                    description="A script host or administrative binary opened an outbound public network connection.",
                    details={"remote_ip": remote_ip, "remote_port": remote_port},
                )
            )
            score += 28
        if user_space:
            findings.append(
                ScanFinding(
                    kind="network_user_space_public_connection",
                    title="User-space executable contacting public IP",
                    score=12,
                    description="User-space executable initiated a public outbound connection.",
                    details={"remote_ip": remote_ip, "remote_port": remote_port},
                )
            )
            score += 12
        if public_count >= NETWORK_PUBLIC_BURST_THRESHOLD:
            if high_risk or user_space:
                findings.append(
                    ScanFinding(
                        kind="network_public_burst",
                        title="Burst of outbound public connections",
                        score=20,
                        description="Process opened multiple public outbound connections in a short interval.",
                        details={"public_connection_count": public_count},
                    )
                )
                score += 20
            elif not trusted_client and remote_port not in TRUSTED_NETWORK_PORTS:
                findings.append(
                    ScanFinding(
                        kind="network_public_burst_untrusted",
                        title="Burst from non-trusted network client",
                        score=14,
                        description="Non-trusted process opened many public outbound connections.",
                        details={"public_connection_count": public_count},
                    )
                )
                score += 14
        if remote_port in {4444, 5555, 9001, 1337, 8081, 8443}:
            findings.append(
                ScanFinding(
                    kind="network_reverse_shell_port",
                    title="Suspicious remote service port",
                    score=18,
                    description="Outbound connection targets a port commonly seen in reverse shell or C2 activity.",
                    details={"remote_ip": remote_ip, "remote_port": remote_port},
                )
            )
            score += 18
        if trusted_client and not high_risk and score <= 20:
            return
        if score < 28:
            return
        result = FileScanResult(
            path=f"network://{pid}/{name or 'unknown'}->{remote_ip}:{remote_port}",
            sha256=f"network-{pid}-{remote_ip}-{remote_port}",
            size=0,
            extension=".network",
            status="malicious" if score >= 90 else "suspicious",
            score=score,
            findings=findings,
            metadata={
                "artifact_type": "network-connection",
                "pid": pid,
                "process_name": name,
                "exe": exe,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "state": str(getattr(conn, "status", "")),
            },
        )
        self.scanner.record_external_result(result)
        if score < 38 and not high_risk:
            return
        try:
            file_result = self.scanner.scan_file(Path(exe))
        except Exception:
            return
        if file_result.status == "malicious":
            try:
                proc.kill()
                self.database.record_block_event(pid=pid, process_name=name, exe_path=exe, sha256=file_result.sha256, reason=file_result.summary())
                self.logger.warning("network monitor killed malicious process | pid=%s exe=%s", pid, exe)
            except Exception:
                pass

    def _is_public_ip(self, value: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return not any(
            (
                address.is_private,
                address.is_loopback,
                address.is_link_local,
                address.is_multicast,
                address.is_reserved,
                address.is_unspecified,
            )
        )

    def _is_user_space_path(self, value: str) -> bool:
        normalized = str(Path(value)).lower()
        return any(normalized.startswith(prefix) for prefix in USER_SPACE_HINTS)

    def _is_trusted_network_client(self, process_name: str, exe_path: str) -> bool:
        if process_name.lower() not in TRUSTED_NETWORK_CLIENT_NAMES:
            return False
        normalized = str(Path(exe_path)).lower()
        trusted_roots = {
            str(Path(os.getenv("SystemRoot", r"C:\Windows"))).lower(),
            str(Path(os.getenv("ProgramFiles", r"C:\Program Files"))).lower(),
            str(Path(os.getenv("ProgramFiles(x86)", r"C:\Program Files (x86)"))).lower(),
            str(Path(os.getenv("LOCALAPPDATA", r"C:\Users\Default\AppData\Local")) / "Programs").lower(),
        }
        return any(normalized.startswith(root) for root in trusted_roots)
