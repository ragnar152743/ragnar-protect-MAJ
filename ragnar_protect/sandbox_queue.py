from __future__ import annotations

import json
import time
import threading
from pathlib import Path
from typing import Any

from .config import PE_EXTENSIONS, SANDBOX_QUEUE_TIMEOUT_SECONDS, USER_SPACE_HINTS
from .database import Database
from .exe_sandbox import ExecutableSandbox
from .logging_setup import get_logger
from .models import FileScanResult, SandboxExecutionReport


class SandboxQueue:
    def __init__(self, database: Database, timeout_seconds: int = SANDBOX_QUEUE_TIMEOUT_SECONDS) -> None:
        self.database = database
        self.timeout_seconds = timeout_seconds
        self.logger = get_logger("ragnar_protect.sandbox_queue")
        self.sandbox = ExecutableSandbox()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        recovered = self.database.requeue_running_sandbox_items()
        if recovered:
            self.logger.warning("sandbox queue recovered %s interrupted item(s)", recovered)
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, name="RagnarSandboxQueue", daemon=True)
        self._thread.start()
        self.logger.info("sandbox queue started")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.logger.info("sandbox queue stopped")

    def consider_scan_result(self, result: FileScanResult) -> None:
        if result.status != "suspicious" or result.extension not in PE_EXTENSIONS:
            return
        candidate = Path(result.path)
        if not candidate.exists() or not candidate.is_file():
            return
        if not self._is_user_space_path(str(candidate)):
            return
        defender_report = result.metadata.get("defender", {})
        if isinstance(defender_report, dict) and defender_report.get("is_malware"):
            return
        signature = result.metadata.get("authenticode", {})
        signature_status = str(signature.get("status", "Unknown")) if isinstance(signature, dict) else "Unknown"
        finding_kinds = {item.kind for item in result.findings}
        packed = bool(finding_kinds.intersection({"pe_upx_sections", "pe_packer_heuristic", "yara_ragnar_pe_upx_sections"}))
        if signature_status == "Valid" and not packed:
            return
        self.database.enqueue_sandbox_sample(str(candidate), result.sha256, result.summary(), priority=40 if packed else 70)

    def launch_sample(self, sample_path: str | Path) -> dict[str, object]:
        candidate = Path(sample_path).expanduser().resolve()
        bundle = self.sandbox.prepare_bundle(candidate)
        launched = self.sandbox.launch_bundle(str(bundle["config_path"])) if bundle["available"] else False
        return {
            **bundle,
            "launched": launched,
        }

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            item = self.database.claim_next_sandbox_item()
            if item is None:
                self._stop_event.wait(2)
                continue
            try:
                report = self._process_item(item)
                self.database.complete_sandbox_item(int(item["id"]), "done", report=report.to_dict())
                self._apply_report(str(item["path"]), str(item["sha256"]), report)
            except Exception as exc:
                self.logger.exception("sandbox queue item failed | %s", exc)
                self.database.complete_sandbox_item(int(item["id"]), "error", report={}, error_text=str(exc))

    def _process_item(self, item: dict[str, Any]) -> SandboxExecutionReport:
        sample_path = Path(str(item["path"])).expanduser()
        bundle = self.sandbox.prepare_bundle(sample_path)
        details: dict[str, Any] = {
            "bundle_dir": bundle["bundle_dir"],
            "config_path": bundle["config_path"],
            "results_dir": bundle["results_dir"],
            "available": bundle["available"],
            "backend": "native-helper",
        }
        response = self.sandbox.native_helper.run_sandbox(sample_path, timeout_seconds=self.timeout_seconds, mode="deep")
        details.update(response if isinstance(response, dict) else {})
        verdict = str(details.get("verdict", "unknown"))
        confirms_malware = verdict == "malicious"
        return SandboxExecutionReport(
            sample_path=str(sample_path),
            sha256=str(item["sha256"]),
            verdict=verdict,
            available=bool(bundle["available"]),
            confirms_malware=confirms_malware,
            bundle_dir=str(bundle["bundle_dir"]),
            config_path=str(bundle["config_path"]),
            results_dir=str(bundle["results_dir"]),
            execution_log=json.dumps(details, ensure_ascii=True),
            details=details,
        )

    def _apply_report(self, path: str, sha256: str, report: SandboxExecutionReport) -> None:
        watch_row = self.database.get_watched_file(path, sha256)
        if watch_row is None:
            return
        metadata = dict(watch_row.get("metadata", {}))
        metadata["sandbox_report"] = report.to_dict()
        updates = {
            "sandbox_verdict": report.verdict,
            "metadata": metadata,
        }
        strong_count = self._strong_confirmation_count(watch_row, report.verdict)
        if report.verdict == "clean":
            self.database.deactivate_blocked_file_by_source(path, sha256, "launch_interceptor")
            updates["status"] = "under_watch"
        if strong_count >= 2 and report.verdict == "malicious":
            updates["confirmed_malware"] = True
            updates["status"] = "confirmed_malware"
        self.database.update_watched_file(path, sha256, **updates)
        if strong_count >= 2 and report.verdict == "malicious":
            quarantined_path = str(watch_row.get("quarantined_path") or "")
            if quarantined_path and Path(quarantined_path).exists():
                try:
                    Path(quarantined_path).unlink()
                    metadata["destroyed_from_quarantine"] = quarantined_path
                    self.database.update_watched_file(path, sha256, status="destroyed", metadata=metadata)
                except OSError as exc:
                    self.logger.warning("sandbox-driven destruction failed | %s | %s", quarantined_path, exc)

    def _strong_confirmation_count(self, row: dict[str, Any], sandbox_verdict: str) -> int:
        count = 0
        if str(row.get("local_verdict", "")) == "malicious":
            count += 1
        if str(row.get("defender_verdict", "")) == "malicious":
            count += 1
        if str(row.get("cloud_verdict", "")) in {"malicious", "known-bad"}:
            count += 1
        if sandbox_verdict == "malicious":
            count += 1
        return count

    def _wait_for_log(self, log_path: Path) -> str:
        deadline = time.time() + self.timeout_seconds
        while time.time() < deadline and not self._stop_event.is_set():
            if log_path.exists():
                try:
                    return log_path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    return ""
            time.sleep(2)
        return ""

    def _extract_int(self, text: str, key: str) -> int:
        prefix = f"{key}="
        for line in text.splitlines():
            if line.startswith(prefix):
                try:
                    return int(line.split("=", 1)[1].strip())
                except ValueError:
                    return 0
        return 0

    def _is_user_space_path(self, value: str) -> bool:
        normalized = str(Path(value)).lower()
        return any(normalized.startswith(prefix) for prefix in USER_SPACE_HINTS)
