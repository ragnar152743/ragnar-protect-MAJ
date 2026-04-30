from __future__ import annotations

import base64
import hashlib
import sys
import threading
import time
from pathlib import Path

from .config import (
    APP_DIR,
    HIGH_RISK_PROCESS_NAMES,
    LAUNCH_ALLOW_CACHE_SECONDS,
    LAUNCH_INTERCEPT_INTERVAL_SECONDS,
    NON_DESTRUCTIVE_MODE,
    PE_EXTENSIONS,
    RAGNAR_PROTECTED_NAME_TOKENS,
    RAGNAR_PROTECTED_TASK_TOKENS,
    SENSITIVE_EXTENSIONS,
    USER_SPACE_HINTS,
    is_managed_path,
)
from .database import Database
from .logging_setup import get_logger
from .native_helper import NativeHelperClient
from .scanner import RagnarScanner
from .staged_analysis import StagePipeline

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None


class ProcessGuard:
    def __init__(
        self,
        scanner: RagnarScanner,
        database: Database,
        interval_seconds: int = LAUNCH_INTERCEPT_INTERVAL_SECONDS,
        rescan_interval_seconds: int = 20,
    ) -> None:
        self.scanner = scanner
        self.database = database
        self.interval_seconds = interval_seconds
        self.rescan_interval_seconds = rescan_interval_seconds
        self.logger = get_logger("ragnar_protect.process_guard")
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._seen: set[tuple[int, float]] = set()
        self._last_scan: dict[tuple[int, float], float] = {}
        self._last_alert: dict[tuple[int, float], float] = {}
        self._launch_allow_cache: dict[str, tuple[float, int, float]] = {}
        self._started_at = time.time()
        self._self_exe = str(Path(sys.executable).resolve()).lower()
        self.native_helper = NativeHelperClient()
        self.stage_pipeline = StagePipeline(scanner, database)
        self.native_watch_enabled = False

    @property
    def available(self) -> bool:
        return psutil is not None

    def start(self) -> None:
        if not self.available or self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._started_at = time.time()
        self.native_watch_enabled = self.native_helper.start_watch(self._handle_native_event)
        self._thread = threading.Thread(target=self._loop, name="RagnarProcessGuard", daemon=True)
        self._thread.start()
        self.logger.info(
            "process guard started | native_watch=%s helper=%s",
            self.native_watch_enabled,
            str(self.native_helper.helper_path) if self.native_helper.helper_path else "unavailable",
        )

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        if self.native_watch_enabled:
            self.native_helper.stop_watch()
        self.logger.info("process guard stopped")

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._inspect_processes()
            except Exception as exc:
                self.logger.exception("process guard loop error: %s", exc)
            self._stop_event.wait(self.interval_seconds)

    def _inspect_processes(self) -> None:
        now = time.time()
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "create_time"]):
            try:
                pid = int(self._process_info_value(proc, "pid") or 0)
                create_time_value = self._process_info_value(proc, "create_time")
                if create_time_value in (None, "", []):
                    create_time_value = self._safe_process_call(proc, "create_time")
                create_time = float(create_time_value or 0.0)
                if pid <= 0:
                    continue
                key = (pid, create_time)
                first_seen = key not in self._seen
                if first_seen:
                    self._seen.add(key)
                last_scan = self._last_scan.get(key, 0.0)
                if not first_seen and now - last_scan < self.rescan_interval_seconds:
                    continue
                self._last_scan[key] = now
                if first_seen and self.native_watch_enabled and create_time >= self._started_at - 2:
                    continue
                self._inspect_process(proc, key, first_seen)
            except Exception:
                continue

    def _handle_native_event(self, event: dict[str, object]) -> None:
        if str(event.get("event", "")) != "process_started":
            return
        if psutil is None:
            return
        pid = int(event.get("pid") or 0)
        if pid <= 0:
            return
        try:
            proc = psutil.Process(pid)
        except Exception:
            return
        create_time = float(getattr(proc, "create_time", lambda: 0.0)() or 0.0)
        key = (pid, create_time)
        self._seen.add(key)
        self._last_scan[key] = time.time()
        exe = str(event.get("executablePath") or self._process_info_value(proc, "exe") or self._safe_process_call(proc, "exe") or "")
        self._process_launch_gate(proc, key, exe, already_suspended=bool(event.get("suspended")))

    def _inspect_process(self, proc, key: tuple[int, float], first_seen: bool) -> None:
        name = str(self._process_info_value(proc, "name") or self._safe_process_call(proc, "name") or "")
        exe = str(self._process_info_value(proc, "exe") or self._safe_process_call(proc, "exe") or "")
        raw_cmdline = self._process_info_value(proc, "cmdline") or self._safe_process_call(proc, "cmdline") or []
        cmdline_list = [str(part) for part in raw_cmdline if part]
        cmdline = " ".join(cmdline_list)
        if "__PSScriptPolicyTest_" in cmdline:
            return
        if not cmdline and not exe:
            return
        tamper_reason = self._detect_ragnar_tamper_command(name, exe, cmdline_list)
        if tamper_reason:
            self._block_process_tree(proc, exe, tamper_reason)
            return

        if first_seen and key[1] >= self._started_at - 2:
            preflight_action = self._process_launch_gate(proc, key, exe, already_suspended=False)
            if preflight_action in {"allow", "blocked", "observed"}:
                return

        file_result = self._scan_live_executable(exe)
        if file_result is not None:
            if file_result.status == "malicious" and self._should_block_executable(file_result, first_seen=first_seen):
                self._block_process_tree(proc, exe, f"Process guard executable: {file_result.summary()}")
                return
            if file_result.status == "suspicious" and self._should_log_weird_executable(file_result):
                self._log_suspicious_active_process(key, proc, exe, file_result.summary(), first_seen)

        artifact_result = self.scanner.scan_artifact(
            display_path=f"process://{proc.pid}/{name or 'unknown'}",
            content=f"{name} {cmdline}".strip() or exe,
            extension=".cmdline",
            metadata={
                "artifact_type": "process-live",
                "pid": proc.pid,
                "process_name": name,
                "exe": exe,
            },
            persist=True,
            persist_clean=False,
        )

        decoded_payload = self._extract_decoded_powershell_payload(name, cmdline_list)
        payload_result = None
        if decoded_payload:
            payload_result = self.scanner.scan_artifact(
                display_path=f"process-payload://{proc.pid}/{name or 'unknown'}",
                content=decoded_payload,
                extension=".ps1",
                metadata={
                    "artifact_type": "process-payload",
                    "pid": proc.pid,
                    "process_name": name,
                    "exe": exe,
                },
                persist=True,
                persist_clean=False,
            )

        if payload_result is not None and payload_result.status != "clean" and self._should_block_process(name, cmdline_list, artifact_result, payload_result):
            self._block_process_tree(proc, exe, f"Process guard payload: {payload_result.summary()}")
            return

        if artifact_result.status == "malicious" and self._should_block_process(name, cmdline_list, artifact_result, payload_result):
            self._block_process_tree(proc, exe, f"Process guard: {artifact_result.summary()}")
            return

        if artifact_result.status == "suspicious" and self._should_log_suspicious_process(name, exe, cmdline_list):
            self._log_suspicious_active_process(key, proc, exe, artifact_result.summary(), first_seen)

    def _process_launch_gate(self, proc, key: tuple[int, float], exe: str, already_suspended: bool) -> str | None:
        preflight_action = self._intercept_launch(proc, exe, already_suspended=already_suspended)
        if preflight_action is None and already_suspended:
            if not self._resume_process(proc):
                self.native_helper.resume_process(proc.pid)
            return "allow"
        if preflight_action == "blocked":
            self._last_alert[key] = time.time()
        return preflight_action

    def _sha256(self, file_path: Path) -> str:
        digest = hashlib.sha256()
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _intercept_launch(self, proc, exe: str, already_suspended: bool = False) -> str | None:
        if not self._should_preflight_launch(exe):
            return None
        candidate = Path(exe)
        if self._is_cached_clean_launch(candidate):
            if already_suspended:
                self.native_helper.resume_process(proc.pid)
            return "allow"

        suspended = already_suspended or self._suspend_process(proc)
        try:
            decision, result = self.stage_pipeline.analyze_launch(candidate)
            if decision.action == "allow":
                if result.status == "clean":
                    self._remember_clean_launch(candidate)
                if suspended:
                    if not self._resume_process(proc):
                        self.native_helper.resume_process(proc.pid)
                self.logger.info("launch allowed | pid=%s exe=%s verdict=%s", proc.pid, exe, result.status)
                return "allow"

            if decision.action == "observe":
                if not self.stage_pipeline.native_helper.available:
                    self._hold_launch_for_observation(proc, exe, result)
                    return "observed"
                self._queue_observation_sandbox(candidate, result)
                if suspended:
                    if not self._resume_process(proc):
                        self.native_helper.resume_process(proc.pid)
                self.logger.warning(
                    "launch allowed under observation | pid=%s exe=%s reason=%s",
                    proc.pid,
                    exe,
                    result.summary(),
                )
                return "observed"

            if decision.action == "kill_quarantine":
                if NON_DESTRUCTIVE_MODE:
                    self.logger.warning(
                        "launch flagged malicious but not blocked (non-destructive mode) | pid=%s exe=%s reason=%s",
                        proc.pid,
                        exe,
                        result.summary(),
                    )
                    if suspended:
                        if not self._resume_process(proc):
                            self.native_helper.resume_process(proc.pid)
                    return "observed"
                self._block_process_tree(proc, exe, f"Launch intercept executable: {result.summary()}")
                return "blocked"
            if suspended:
                if not self._resume_process(proc):
                    self.native_helper.resume_process(proc.pid)
            return "allow"
        except Exception:
            if suspended:
                if not self._resume_process(proc):
                    self.native_helper.resume_process(proc.pid)
            raise

    def _queue_observation_sandbox(self, candidate: Path, result) -> None:
        try:
            self.database.enqueue_sandbox_sample(
                str(candidate),
                result.sha256,
                f"Launch observation deep sandbox: {result.summary()}",
                priority=30,
            )
        except Exception as exc:
            self.logger.debug("failed to enqueue observation sandbox sample | %s | %s", candidate, exc)

    def _safe_process_call(self, proc, method_name: str):
        method = getattr(proc, method_name, None)
        if method is None:
            return None
        try:
            return method()
        except Exception:
            return None

    def _process_info_value(self, proc, key: str):
        info = getattr(proc, "info", None)
        if isinstance(info, dict):
            value = info.get(key)
            if value not in (None, "", []):
                return value
        if key == "pid":
            return getattr(proc, "pid", 0)
        return None

    def _suspend_process(self, proc) -> bool:
        try:
            proc.suspend()
            return True
        except Exception:
            return False

    def _resume_process(self, proc) -> bool:
        try:
            proc.resume()
            return True
        except Exception:
            return False

    def _should_preflight_launch(self, exe: str) -> bool:
        if not exe:
            return False
        candidate = Path(exe)
        normalized = str(candidate).lower()
        if normalized == self._self_exe:
            return False
        if candidate.suffix.lower() not in PE_EXTENSIONS:
            return False
        if not candidate.exists():
            return False
        if is_managed_path(candidate):
            return False
        if not self._is_user_space_path(exe):
            return False
        return True

    def _remember_clean_launch(self, candidate: Path) -> None:
        try:
            stat = candidate.stat()
        except OSError:
            return
        self._launch_allow_cache[str(candidate).lower()] = (
            stat.st_mtime,
            stat.st_size,
            time.time() + LAUNCH_ALLOW_CACHE_SECONDS,
        )

    def _is_cached_clean_launch(self, candidate: Path) -> bool:
        key = str(candidate).lower()
        cached = self._launch_allow_cache.get(key)
        if cached is None:
            return False
        expires_at = cached[2]
        if time.time() > expires_at:
            self._launch_allow_cache.pop(key, None)
            return False
        try:
            stat = candidate.stat()
        except OSError:
            self._launch_allow_cache.pop(key, None)
            return False
        if (stat.st_mtime, stat.st_size) != cached[:2]:
            self._launch_allow_cache.pop(key, None)
            return False
        return True

    def _is_user_space_path(self, value: str) -> bool:
        normalized = str(Path(value)).lower()
        return any(normalized.startswith(prefix) for prefix in USER_SPACE_HINTS)

    def _scan_live_executable(self, exe: str):
        if not exe:
            return None
        candidate = Path(exe)
        normalized = str(candidate).lower()
        if normalized == self._self_exe:
            return None
        if candidate.suffix.lower() not in SENSITIVE_EXTENSIONS:
            return None
        try:
            if is_managed_path(candidate):
                return None
        except Exception:
            return None
        if not candidate.exists():
            return None
        if not self._is_user_space_path(exe):
            return None
        try:
            return self.scanner.scan_file(candidate)
        except Exception as exc:
            self.logger.exception("live executable scan failed | %s | %s", exe, exc)
            return None

    def _should_block_process(self, process_name: str, cmdline_list: list[str], artifact_result, payload_result) -> bool:
        lower_name = process_name.lower()
        if lower_name not in HIGH_RISK_PROCESS_NAMES:
            return False

        lower_args = [item.lower() for item in cmdline_list]
        encoded_flags = {"-enc", "-encodedcommand", "-e", "-ec"}
        critical_kinds = {
            "shadow_copy_delete",
            "backup_catalog_delete",
            "recovery_impairment",
            "event_log_clear",
            "cipher_wipe",
            "defender_tamper",
            "ransomware_note_phrase",
            "ragnar_self_tamper",
            "startup_task_tamper",
        }
        artifact_kinds = {item.kind for item in getattr(artifact_result, "findings", [])}
        payload_kinds = {item.kind for item in getattr(payload_result, "findings", [])} if payload_result is not None else set()
        if artifact_kinds.intersection(critical_kinds) or payload_kinds.intersection(critical_kinds):
            return True

        if lower_name in {"powershell.exe", "pwsh.exe"}:
            if any(arg in encoded_flags for arg in lower_args):
                return payload_result is not None and payload_result.status != "clean"
            return bool(artifact_kinds.intersection(critical_kinds))

        if lower_name in {"mshta.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe"}:
            return True

        if lower_name in {
            "cmd.exe",
            "vssadmin.exe",
            "wbadmin.exe",
            "bcdedit.exe",
            "wevtutil.exe",
            "wmic.exe",
            "diskshadow.exe",
            "cipher.exe",
            "schtasks.exe",
            "reg.exe",
        }:
            return bool(artifact_kinds.intersection(critical_kinds))

        return False

    def _detect_ragnar_tamper_command(self, process_name: str, exe: str, cmdline_list: list[str]) -> str | None:
        lower_name = process_name.lower()
        joined = " ".join(str(part) for part in cmdline_list if str(part).strip()).lower()
        if not joined:
            return None
        if "apply_update_" in joined:
            return None
        targets_names = any(token in joined for token in RAGNAR_PROTECTED_NAME_TOKENS)
        targets_tasks = any(token in joined for token in RAGNAR_PROTECTED_TASK_TOKENS)
        if not (targets_names or targets_tasks):
            return None

        if lower_name == "schtasks.exe" and "/delete" in joined and targets_tasks:
            return "Process guard self-protection: startup task tamper"

        kill_tokens = (
            "taskkill",
            "stop-process",
            "wmic",
            "delete",
            "terminate",
            "remove-item",
            " del ",
            " erase ",
        )
        if lower_name in {"taskkill.exe", "powershell.exe", "pwsh.exe", "wmic.exe", "cmd.exe", "reg.exe"}:
            if any(token in joined for token in kill_tokens):
                return "Process guard self-protection: Ragnar tamper command"
        return None

    def _is_clean_launch_result(self, result) -> bool:
        if result.status == "clean":
            return True
        reputation = result.metadata.get("reputation", {})
        reputation = reputation if isinstance(reputation, dict) else {}
        if str(reputation.get("verdict", "")) in {"trusted", "known-good"}:
            return True
        signature = result.metadata.get("authenticode", {})
        signature = signature if isinstance(signature, dict) else {}
        finding_kinds = {item.kind for item in result.findings}
        noisy_only = {
            "sensitive_extension",
            "high_entropy",
            "pe_overlay_stub",
            "pe_packer_heuristic",
            "pe_upx_sections",
            "unsigned_pe",
            "authenticode_issue",
            "yara_ragnar_pe_upx_sections",
            "yara_ragnar_pe_lowimport_overlay",
        }
        return str(signature.get("status", "")) == "Valid" and finding_kinds.issubset(noisy_only)

    def _should_hold_launch_for_observation(self, result) -> bool:
        reputation = result.metadata.get("reputation", {})
        reputation = reputation if isinstance(reputation, dict) else {}
        if str(reputation.get("verdict", "")) in {"trusted", "known-good"}:
            return False
        finding_kinds = {item.kind for item in result.findings}
        observation_kinds = {
            "pe_upx_sections",
            "pe_packer_heuristic",
            "pe_overlay_stub",
            "unsigned_pe",
            "authenticode_issue",
            "high_entropy",
            "yara_ragnar_pe_upx_sections",
            "yara_ragnar_pe_lowimport_overlay",
            "cloud_risky",
        }
        return bool(finding_kinds.intersection(observation_kinds))

    def _should_block_executable(self, result, first_seen: bool = False) -> bool:
        strong_confirmations = self.scanner.count_strong_confirmations(result)
        if strong_confirmations >= 2:
            return True
        if first_seen:
            return False
        critical_kinds = {
            "defender_malware",
            "amsi_block",
            "cloud_known_bad",
            "pe_suspicious_imports",
            "memory_injection_api",
            "shadow_copy_delete",
            "backup_catalog_delete",
            "recovery_impairment",
            "event_log_clear",
            "cipher_wipe",
            "ransomware_note_phrase",
        }
        finding_kinds = {item.kind for item in result.findings}
        return bool(finding_kinds.intersection(critical_kinds))

    def _should_log_weird_executable(self, result) -> bool:
        finding_kinds = {item.kind for item in result.findings}
        weird_kinds = {
            "pe_upx_sections",
            "pe_packer_heuristic",
            "pe_overlay_stub",
            "high_entropy",
            "unsigned_pe",
            "authenticode_issue",
        }
        return bool(finding_kinds.intersection(weird_kinds))

    def _hold_launch_for_observation(self, proc, exe: str, result) -> None:
        if NON_DESTRUCTIVE_MODE:
            self.logger.warning(
                "launch flagged for observation only (non-destructive mode) | pid=%s name=%s exe=%s",
                proc.pid,
                self._process_info_value(proc, "name"),
                exe,
            )
            return
        self._terminate_process_tree(proc)
        reason = f"Launch held for background sandbox observation: {result.summary()}"
        self.database.upsert_blocked_file(
            path=exe,
            sha256=result.sha256,
            reason=reason,
            source="launch_interceptor",
        )
        self.database.record_block_event(
            pid=self._process_info_value(proc, "pid"),
            process_name=self._process_info_value(proc, "name"),
            exe_path=exe,
            sha256=result.sha256,
            reason=reason,
        )
        self.database.enqueue_sandbox_sample(
            exe,
            result.sha256,
            reason,
            priority=10,
        )
        self.logger.warning(
            "launch intercepted for observation | pid=%s name=%s exe=%s",
            proc.pid,
            self._process_info_value(proc, "name"),
            exe,
        )

    def _should_log_suspicious_process(self, process_name: str, exe: str, cmdline_list: list[str]) -> bool:
        lower_name = process_name.lower()
        if lower_name in HIGH_RISK_PROCESS_NAMES:
            return True
        joined = " ".join(cmdline_list).lower()
        return self._is_user_space_path(exe) and any(token in joined for token in ("-enc", "powershell", "mshta", "regsvr32"))

    def _extract_decoded_powershell_payload(self, process_name: str, cmdline_list: list[str]) -> str | None:
        if process_name.lower() not in {"powershell.exe", "pwsh.exe"}:
            return None
        encoded_flags = {"-enc", "-encodedcommand", "-e", "-ec"}
        for index, arg in enumerate(cmdline_list):
            if arg.lower() not in encoded_flags:
                continue
            if index + 1 >= len(cmdline_list):
                return None
            payload = cmdline_list[index + 1]
            try:
                raw = base64.b64decode(payload + "===")
            except Exception:
                return None
            for encoding in ("utf-16-le", "utf-8", "latin-1"):
                try:
                    decoded = raw.decode(encoding)
                    if decoded.strip():
                        return decoded
                except Exception:
                    continue
        return None

    def _block_process_tree(self, proc, exe: str, reason: str) -> None:
        if NON_DESTRUCTIVE_MODE:
            self.logger.warning(
                "process flagged but not blocked (non-destructive mode) | pid=%s name=%s exe=%s reason=%s",
                proc.pid,
                self._process_info_value(proc, "name"),
                exe,
                reason,
            )
            return
        self._terminate_process_tree(proc)
        self._record_block(proc, exe, reason)
        self.logger.warning("process guard blocked | pid=%s name=%s exe=%s", proc.pid, self._process_info_value(proc, "name"), exe)

    def _terminate_process_tree(self, proc) -> None:
        try:
            children = proc.children(recursive=True)
        except Exception:
            children = []
        for child in reversed(children):
            try:
                child.terminate()
            except Exception:
                pass
        gone, alive = psutil.wait_procs(children, timeout=2) if children and psutil is not None else ([], [])
        for child in alive:
            try:
                child.kill()
            except Exception:
                pass
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def _record_block(self, proc, exe: str, reason: str) -> None:
        sha256 = None
        if exe and self._is_user_space_path(exe):
            candidate = Path(exe)
            if candidate.exists():
                sha256 = self._sha256(candidate)
                self.database.upsert_blocked_file(
                    path=str(candidate),
                    sha256=sha256,
                    reason=reason,
                    source="process_guard",
                )
        self.database.record_block_event(
            pid=self._process_info_value(proc, "pid"),
            process_name=self._process_info_value(proc, "name"),
            exe_path=exe or None,
            sha256=sha256,
            reason=reason,
        )

    def _log_suspicious_active_process(
        self,
        key: tuple[int, float],
        proc,
        exe: str,
        reason: str,
        first_seen: bool,
    ) -> None:
        now = time.time()
        if not first_seen and now - self._last_alert.get(key, 0.0) < self.rescan_interval_seconds:
            return
        self._last_alert[key] = now
        self.logger.warning(
            "suspicious active process observed | pid=%s name=%s exe=%s reason=%s",
            proc.pid,
            self._process_info_value(proc, "name"),
            exe,
            reason,
        )
