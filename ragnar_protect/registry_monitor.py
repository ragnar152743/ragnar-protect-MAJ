from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from .config import REGISTRY_MONITOR_INTERVAL_SECONDS
from .hidden_process import run_hidden
from .logging_setup import get_logger

try:
    import winreg
except Exception:  # pragma: no cover
    winreg = None  # type: ignore


REGISTRY_TARGETS = (
    ("HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "run"),
    ("HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "runonce"),
    ("HKLM", "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "winlogon"),
)


class RegistryPersistenceMonitor:
    def __init__(self, scanner, system_inspector, interval_seconds: int = REGISTRY_MONITOR_INTERVAL_SECONDS) -> None:
        self.scanner = scanner
        self.system_inspector = system_inspector
        self.interval_seconds = max(1, int(interval_seconds))
        self.logger = get_logger("ragnar_protect.registry")
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._snapshot: dict[tuple[str, str], dict[str, str]] = {}

    @property
    def available(self) -> bool:
        return winreg is not None

    def start(self) -> None:
        if not self.available or self._thread and self._thread.is_alive():
            return
        self._snapshot = self._build_snapshot()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, name="RagnarRegistryMonitor", daemon=True)
        self._thread.start()
        self.logger.info("registry monitor started")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.logger.info("registry monitor stopped")

    def _loop(self) -> None:
        while not self._stop_event.wait(self.interval_seconds):
            try:
                current = self._build_snapshot()
                self._process_changes(current)
                self._snapshot = current
            except Exception as exc:
                self.logger.exception("registry monitor loop failed | %s", exc)

    def _build_snapshot(self) -> dict[tuple[str, str], dict[str, str]]:
        snapshot: dict[tuple[str, str], dict[str, str]] = {}
        for hive_name, subkey, _kind in REGISTRY_TARGETS:
            snapshot[(hive_name, subkey)] = self._read_key_values(hive_name, subkey)
        return snapshot

    def _read_key_values(self, hive_name: str, subkey: str) -> dict[str, str]:
        if winreg is None:
            return {}
        hive = getattr(winreg, f"HKEY_{'CURRENT_USER' if hive_name == 'HKCU' else 'LOCAL_MACHINE'}")
        values: dict[str, str] = {}
        try:
            with winreg.OpenKey(hive, subkey) as key:
                value_count = winreg.QueryInfoKey(key)[1]
                for index in range(value_count):
                    name, value, _value_type = winreg.EnumValue(key, index)
                    values[str(name)] = str(value)
        except FileNotFoundError:
            return {}
        except OSError:
            return {}
        return values

    def _process_changes(self, current: dict[tuple[str, str], dict[str, str]]) -> None:
        for target, values in current.items():
            previous = self._snapshot.get(target, {})
            for name, value in values.items():
                if previous.get(name) == value:
                    continue
                self._scan_registry_value(target[0], target[1], name, value)

    def _scan_registry_value(self, hive_name: str, subkey: str, name: str, value: str) -> None:
        artifact = self.scanner.scan_artifact(
            display_path=f"registry://{hive_name}/{subkey}/{name}",
            content=value,
            extension=".registry",
            metadata={
                "artifact_type": "registry-persistence",
                "hive": hive_name,
                "subkey": subkey,
                "value_name": name,
            },
            persist=True,
            persist_clean=False,
        )
        if artifact.status == "clean":
            return
        for candidate_path in self.system_inspector._extract_candidate_paths(value):
            if candidate_path.exists():
                try:
                    file_result = self.scanner.scan_file(candidate_path)
                    if file_result.status == "malicious":
                        self.scanner.enforce_block_on_existing_file(candidate_path, file_result)
                except Exception as exc:
                    self.logger.debug("registry target scan failed | %s | %s", candidate_path, exc)
        if artifact.status == "malicious" and "winlogon" not in subkey.lower():
            self._delete_registry_value(hive_name, subkey, name)

    def _delete_registry_value(self, hive_name: str, subkey: str, name: str) -> None:
        hive_arg = "HKCU" if hive_name == "HKCU" else "HKLM"
        try:
            run_hidden(["reg.exe", "delete", f"{hive_arg}\\{subkey}", "/v", name, "/f"])
            self.logger.warning("registry persistence removed | %s\\%s | %s", hive_name, subkey, name)
        except Exception as exc:
            self.logger.warning("registry persistence removal failed | %s\\%s | %s | %s", hive_name, subkey, name, exc)
