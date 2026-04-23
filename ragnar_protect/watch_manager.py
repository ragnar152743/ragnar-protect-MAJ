from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .cloud_reputation import CloudReputationClient
from .config import WATCH_AUTO_UNBLOCK_DAYS, WATCH_REQUIRED_CLEAN_SCANS
from .database import Database
from .logging_setup import get_logger
from .models import BehaviorIncident, FileScanResult, WatchedFileState


class WatchManager:
    def __init__(
        self,
        database: Database,
        scanner,
        cloud_client: CloudReputationClient | None = None,
        unblock_days: int = WATCH_AUTO_UNBLOCK_DAYS,
        required_clean_scans: int = WATCH_REQUIRED_CLEAN_SCANS,
        interval_seconds: int = 30,
    ) -> None:
        self.database = database
        self.scanner = scanner
        self.cloud_client = cloud_client or CloudReputationClient()
        self.unblock_days = unblock_days
        self.required_clean_scans = required_clean_scans
        self.interval_seconds = interval_seconds
        self.logger = get_logger("ragnar_protect.watch")
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, name="RagnarWatchManager", daemon=True)
        self._thread.start()
        self.logger.info("watch manager started")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.logger.info("watch manager stopped")

    def status(self) -> dict[str, object]:
        info = self.cloud_client.status()
        info["pending_sync_events"] = self.database.count_pending_reputation_events()
        info["watched_files"] = len(self.database.list_watched_files(limit=500))
        return info

    def handle_scan_result(self, result: FileScanResult) -> None:
        artifact_type = str(result.metadata.get("artifact_type", "file"))
        tracked_path = str(result.metadata.get("tracked_original_path") or result.path)
        if artifact_type != "file" and result.status == "clean":
            return

        existing = self.database.get_watched_file(tracked_path, result.sha256)
        if existing is None and artifact_type != "file" and result.status == "clean":
            return

        clean_scan_count = int(existing.get("clean_scan_count", 0)) if existing else 0
        under_watch_since = str(existing.get("under_watch_since") or result.scanned_at) if existing else result.scanned_at
        last_behavior_at = None
        if existing and existing.get("last_behavior_at"):
            last_behavior_at = str(existing.get("last_behavior_at"))
        metadata = dict(existing.get("metadata", {})) if existing else {}
        metadata.update(
            {
                "last_summary": result.summary(),
                "score": result.score,
                "artifact_type": artifact_type,
                "strong_confirmations": self.scanner.count_strong_confirmations(result),
            }
        )

        if result.status == "clean":
            clean_scan_count += 1
        else:
            clean_scan_count = 0

        cloud_record = result.metadata.get("cloud_reputation", {})
        cloud_verdict = str(
            (cloud_record.get("verdict") if isinstance(cloud_record, dict) else "")
            or (existing.get("cloud_verdict") if existing else "")
            or "unknown"
        )

        sandbox_report = result.metadata.get("sandbox_report", {})
        sandbox_verdict = str(
            (sandbox_report.get("verdict") if isinstance(sandbox_report, dict) else "")
            or (existing.get("sandbox_verdict") if existing else "")
            or "unknown"
        )

        defender_report = result.metadata.get("defender", {})
        defender_verdict = str(existing.get("defender_verdict") or "unknown") if existing else "unknown"
        if isinstance(defender_report, dict):
            if defender_report.get("is_malware"):
                defender_verdict = "malicious"
            elif defender_report.get("requires_attention"):
                defender_verdict = "attention"

        confirmed_malware = bool(existing.get("confirmed_malware")) if existing else False
        strong_confirmations = self.scanner.count_strong_confirmations(result)
        if result.status == "malicious" and strong_confirmations >= 2:
            confirmed_malware = True

        watch_status = "under_watch"
        if result.status == "clean" and existing:
            watch_status = str(existing.get("status") or "under_watch")
        if confirmed_malware:
            watch_status = "confirmed_malware"
        elif result.status == "clean" and existing and str(existing.get("status")) == "auto_unblocked":
            watch_status = "auto_unblocked"

        quarantine_item_id = (
            int(result.metadata.get("quarantine_item_id"))
            if result.metadata.get("quarantine_item_id") is not None
            else (int(existing.get("quarantine_item_id")) if existing and existing.get("quarantine_item_id") else None)
        )
        quarantined_path = str(result.quarantined_path or (existing.get("quarantined_path") if existing else "") or "")

        state = WatchedFileState(
            path=tracked_path,
            sha256=result.sha256,
            status=watch_status,
            reason=result.summary(),
            last_verdict=result.status,
            clean_scan_count=clean_scan_count,
            quarantined_path=quarantined_path or None,
            quarantine_item_id=quarantine_item_id,
            cloud_verdict=cloud_verdict,
            sandbox_verdict=sandbox_verdict,
            local_verdict=result.status,
            defender_verdict=defender_verdict,
            confirmed_malware=confirmed_malware,
            last_seen_at=result.scanned_at,
            under_watch_since=under_watch_since,
            last_clean_at=result.scanned_at if result.status == "clean" else (existing.get("last_clean_at") if existing else None),
            last_behavior_at=last_behavior_at,
            auto_unblocked_at=(existing.get("auto_unblocked_at") if existing else None),
            metadata=metadata,
        )
        if (
            result.status != "clean"
            or existing is not None
            or result.quarantined_path
            or result.blocked
            or cloud_verdict != "unknown"
            or sandbox_verdict != "unknown"
        ):
            self.database.upsert_watched_file(state)
            self._queue_scan_event(result, tracked_path)

        if confirmed_malware and quarantined_path:
            self._destroy_quarantine_copy(tracked_path, result.sha256, quarantined_path)

    def observe_watch_rescan(self, watch_row: dict[str, Any], result: FileScanResult) -> None:
        tracked_path = str(watch_row["path"])
        metadata = dict(result.metadata)
        metadata["tracked_original_path"] = tracked_path
        rescan_result = FileScanResult(
            path=result.path,
            sha256=result.sha256,
            size=result.size,
            extension=result.extension,
            status=result.status,
            score=result.score,
            findings=result.findings,
            metadata=metadata,
            quarantined_path=result.quarantined_path,
            blocked=result.blocked,
            scanned_at=result.scanned_at,
        )
        self.handle_scan_result(rescan_result)

    def handle_behavior_incident(self, incident: BehaviorIncident) -> None:
        self.database.record_behavior_incident(incident)
        for path in incident.paths[:24]:
            try:
                candidate = Path(path)
            except Exception:
                continue
            if not candidate.exists():
                continue
            try:
                sha256 = self.scanner.file_sha256(candidate)
            except Exception:
                continue
            existing = self.database.get_watched_file(str(candidate), sha256)
            if existing is None:
                continue
            metadata = dict(existing.get("metadata", {}))
            metadata["last_behavior_incident"] = incident.to_dict()
            self.database.update_watched_file(
                str(candidate),
                sha256,
                last_behavior_at=incident.observed_at,
                metadata=metadata,
            )

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._flush_reputation_queue()
                self._evaluate_auto_unblock()
            except Exception as exc:
                self.logger.exception("watch manager loop failed | %s", exc)
            self._stop_event.wait(self.interval_seconds)

    def _queue_scan_event(self, result: FileScanResult, tracked_path: str) -> None:
        payload = {
            "sha256": result.sha256,
            "path": tracked_path,
            "filename": Path(tracked_path).name,
            "size": result.size,
            "status": result.status,
            "reason": result.summary(),
            "scanned_at": result.scanned_at,
            "score": result.score,
            "publisher": str(((result.metadata.get("pe") or {}) if isinstance(result.metadata.get("pe"), dict) else {}).get("company_name", "")),
            "thumbprint": str(((result.metadata.get("authenticode") or {}) if isinstance(result.metadata.get("authenticode"), dict) else {}).get("thumbprint", "")),
            "fingerprint": result.metadata.get("cloud_fingerprint", {}),
            "sandbox_summary": result.metadata.get("sandbox_report", {}),
        }
        self.database.enqueue_reputation_event("submit_event", result.sha256, tracked_path, payload)

    def _flush_reputation_queue(self) -> None:
        if not self.cloud_client.available:
            return
        while not self._stop_event.is_set():
            item = self.database.claim_next_reputation_event()
            if item is None:
                break
            payload = item.get("payload", {})
            success = False
            response: dict[str, Any] = {}
            if item["kind"] == "submit_event":
                response = self.cloud_client.submit_event(payload)
                success = bool(response.get("success", True))
            elif item["kind"] == "requalified_benign":
                response = self.cloud_client.submit_requalification(payload)
                success = bool(response.get("success", True))
            else:
                response = {"success": False, "reason": "unknown sync kind"}
            self.database.complete_reputation_event(
                int(item["id"]),
                success=success,
                response=response,
                error_text="" if success else str(response.get("reason", "")),
            )
            if success and item.get("path"):
                existing = self.database.get_watched_file(str(item["path"]), str(item["sha256"]))
                if existing is not None and isinstance(response, dict) and response.get("verdict"):
                    self.database.update_watched_file(
                        str(item["path"]),
                        str(item["sha256"]),
                        cloud_verdict=str(response.get("verdict")),
                    )

    def _evaluate_auto_unblock(self) -> None:
        now = datetime.now(timezone.utc)
        for row in self.database.list_watched_files(active_only=True, limit=500):
            if bool(row.get("confirmed_malware")):
                continue
            if str(row.get("status")) in {"auto_unblocked", "destroyed"}:
                continue
            if int(row.get("clean_scan_count", 0)) < self.required_clean_scans:
                continue
            under_watch_since = self._parse_dt(str(row.get("under_watch_since") or ""))
            if under_watch_since is None or now - under_watch_since < timedelta(days=self.unblock_days):
                continue
            if str(row.get("cloud_verdict") or "unknown") in {"malicious", "known-bad"}:
                continue
            last_behavior_at = self._parse_dt(str(row.get("last_behavior_at") or ""))
            if last_behavior_at is not None and now - last_behavior_at < timedelta(days=self.unblock_days):
                continue

            restored_path = row["path"]
            quarantine_item_id = row.get("quarantine_item_id")
            if quarantine_item_id:
                try:
                    restored_path = self.scanner.restore_quarantine_item(int(quarantine_item_id))
                except FileNotFoundError:
                    restored_path = row["path"]
                except ValueError:
                    restored_path = row["path"]
            self.database.deactivate_blocked_file(str(row["path"]), str(row["sha256"]))
            metadata = dict(row.get("metadata", {}))
            metadata["auto_unblocked_reason"] = "90d + 3 clean rescans + no bad cloud or behavior"
            self.database.update_watched_file(
                str(row["path"]),
                str(row["sha256"]),
                status="auto_unblocked",
                auto_unblocked_at=now.isoformat(timespec="seconds"),
                metadata=metadata,
            )
            self.database.enqueue_reputation_event(
                "requalified_benign",
                str(row["sha256"]),
                restored_path,
                {
                    "sha256": row["sha256"],
                    "path": restored_path,
                    "filename": Path(restored_path).name,
                    "requalified_at": now.isoformat(timespec="seconds"),
                    "reason": "90d + 3 clean rescans + no abnormal activity",
                },
            )
            self.logger.warning("auto-unblocked watched file | %s", restored_path)

    def _destroy_quarantine_copy(self, tracked_path: str, sha256: str, quarantined_path: str) -> None:
        target = Path(quarantined_path)
        if not target.exists():
            return
        try:
            target.unlink()
            metadata = (self.database.get_watched_file(tracked_path, sha256) or {}).get("metadata", {})
            metadata = dict(metadata)
            metadata["destroyed_from_quarantine"] = quarantined_path
            self.database.update_watched_file(
                tracked_path,
                sha256,
                status="destroyed",
                metadata=metadata,
            )
            self.logger.warning("destroyed confirmed malware quarantine copy | %s", quarantined_path)
        except OSError as exc:
            self.logger.warning("failed to destroy quarantine copy | %s | %s", quarantined_path, exc)

    def _parse_dt(self, value: str) -> datetime | None:
        if not value:
            return None
        try:
            if value.endswith("Z"):
                value = value[:-1] + "+00:00"
            dt = datetime.fromisoformat(value)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            try:
                dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                return None
