from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any

from .config import DB_PATH, ensure_app_dirs
from .models import BehaviorIncident, FileScanResult, LaunchDecision, RollbackArtifact, WatchedFileState


class Database:
    def __init__(self, db_path=None) -> None:
        ensure_app_dirs()
        self.db_path = db_path or DB_PATH
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _managed_connection(self):
        connection = self._connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._managed_connection() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scanned_at TEXT NOT NULL,
                    path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    extension TEXT NOT NULL,
                    status TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    summary TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    quarantined_path TEXT
                );

                CREATE TABLE IF NOT EXISTS blocklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    source TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(path, sha256)
                );

                CREATE TABLE IF NOT EXISTS block_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    blocked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    pid INTEGER,
                    process_name TEXT,
                    exe_path TEXT,
                    sha256 TEXT,
                    reason TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS allowlist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    entry_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    note TEXT NOT NULL DEFAULT '',
                    active INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(entry_type, value)
                );

                CREATE TABLE IF NOT EXISTS wallpaper_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    wallpaper_path TEXT,
                    details TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS quarantine_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    quarantined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    original_path TEXT NOT NULL,
                    quarantined_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    restored_at TEXT,
                    restored_path TEXT
                );

                CREATE TABLE IF NOT EXISTS behavior_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    observed_at TEXT NOT NULL,
                    incident_type TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    stage TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    process_pid INTEGER,
                    process_name TEXT,
                    process_path TEXT,
                    attributed INTEGER NOT NULL DEFAULT 0,
                    attribution_confidence INTEGER NOT NULL DEFAULT 0,
                    paths_json TEXT NOT NULL,
                    actions_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS watched_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    status TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    last_verdict TEXT NOT NULL,
                    clean_scan_count INTEGER NOT NULL DEFAULT 0,
                    quarantined_path TEXT,
                    quarantine_item_id INTEGER,
                    cloud_verdict TEXT NOT NULL DEFAULT 'unknown',
                    sandbox_verdict TEXT NOT NULL DEFAULT 'unknown',
                    local_verdict TEXT NOT NULL DEFAULT 'unknown',
                    defender_verdict TEXT NOT NULL DEFAULT 'unknown',
                    confirmed_malware INTEGER NOT NULL DEFAULT 0,
                    last_seen_at TEXT NOT NULL,
                    under_watch_since TEXT NOT NULL,
                    last_clean_at TEXT,
                    last_behavior_at TEXT,
                    auto_unblocked_at TEXT,
                    metadata_json TEXT NOT NULL,
                    UNIQUE(path, sha256)
                );

                CREATE TABLE IF NOT EXISTS background_scan_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS sandbox_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    priority INTEGER NOT NULL DEFAULT 100,
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    bundle_dir TEXT,
                    results_dir TEXT,
                    report_json TEXT,
                    error_text TEXT,
                    last_attempt_at TEXT
                );

                CREATE TABLE IF NOT EXISTS reputation_sync_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    kind TEXT NOT NULL,
                    path TEXT,
                    sha256 TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    response_json TEXT,
                    error_text TEXT
                );

                CREATE TABLE IF NOT EXISTS error_report_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    level TEXT NOT NULL,
                    logger_name TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    response_json TEXT,
                    error_text TEXT,
                    last_attempt_at TEXT
                );

                CREATE TABLE IF NOT EXISTS launch_decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    observed_at TEXT NOT NULL,
                    path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    action TEXT NOT NULL,
                    final_verdict TEXT NOT NULL,
                    aggregate_score INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    stage_verdicts_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS rollback_artifacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    original_path TEXT NOT NULL,
                    snapshot_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    source_mtime REAL NOT NULL,
                    source_size INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    restored_at TEXT
                );

                CREATE TABLE IF NOT EXISTS benchmark_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    observed_at TEXT NOT NULL,
                    corpus_path TEXT NOT NULL,
                    summary_json TEXT NOT NULL
                );
                """
            )

    def _json(self, payload: Any) -> str:
        return json.dumps(payload, ensure_ascii=True)

    def _row_to_dict(self, row: sqlite3.Row | None) -> dict[str, Any] | None:
        return dict(row) if row else None

    def _decode_json_fields(self, row: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
        for field in fields:
            if field in row and row[field]:
                try:
                    row[field] = json.loads(row[field])
                except json.JSONDecodeError:
                    row[field] = {}
        return row

    def record_detection(self, result: FileScanResult) -> None:
        record = result.to_record()
        with self._lock, self._managed_connection() as connection:
            connection.execute(
                """
                INSERT INTO detections (
                    scanned_at, path, sha256, size, extension, status,
                    score, summary, findings_json, metadata_json, quarantined_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["scanned_at"],
                    record["path"],
                    record["sha256"],
                    record["size"],
                    record["extension"],
                    record["status"],
                    record["score"],
                    record["summary"],
                    self._json(record["findings"]),
                    self._json(record["metadata"]),
                    record["quarantined_path"],
                ),
            )

    def upsert_blocked_file(self, path: str, sha256: str, reason: str, source: str = "scanner") -> None:
        with self._lock, self._managed_connection() as connection:
            connection.execute(
                """
                INSERT INTO blocklist (path, sha256, reason, source, active)
                VALUES (?, ?, ?, ?, 1)
                ON CONFLICT(path, sha256) DO UPDATE SET
                    reason = excluded.reason,
                    source = excluded.source,
                    active = 1
                """,
                (path, sha256, reason, source),
            )

    def get_active_blocklist(self) -> list[dict[str, Any]]:
        with self._lock, self._managed_connection() as connection:
            rows = connection.execute(
                """
                SELECT id, created_at, path, sha256, reason, source, active
                FROM blocklist
                WHERE active = 1
                ORDER BY created_at DESC
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def upsert_allowlist_entry(self, entry_type: str, value: str, note: str = "") -> None:
        normalized_type = str(entry_type).strip().lower()
        normalized_value = str(value).strip()
        with self._lock, self._managed_connection() as connection:
            connection.execute(
                """
                INSERT INTO allowlist (entry_type, value, note, active)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(entry_type, value) DO UPDATE SET
                    note = excluded.note,
                    active = 1
                """,
                (normalized_type, normalized_value, note.strip()),
            )

    def list_allowlist_entries(self, active_only: bool = True) -> list[dict[str, Any]]:
        query = """
            SELECT id, created_at, entry_type, value, note, active
            FROM allowlist
        """
        params: tuple[object, ...] = ()
        if active_only:
            query += " WHERE active = 1"
        query += " ORDER BY id DESC"
        with self._lock, self._managed_connection() as connection:
            rows = connection.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def deactivate_allowlist_entry(self, entry_id: int) -> None:
        with self._lock, self._managed_connection() as connection:
            connection.execute("UPDATE allowlist SET active = 0 WHERE id = ?", (entry_id,))

    def is_path_allowlisted(self, path: str) -> bool:
        normalized = str(path).strip().lower()
        with self._lock, self._managed_connection() as connection:
            rows = connection.execute(
                """
                SELECT value
                FROM allowlist
                WHERE active = 1 AND entry_type = 'path'
                """,
            ).fetchall()
        for row in rows:
            candidate = str(row["value"]).strip().lower()
            if not candidate:
                continue
            if normalized == candidate or normalized.startswith(candidate.rstrip("\\/") + "\\"):
                return True
        return False

    def is_hash_allowlisted(self, sha256: str) -> bool:
        with self._lock, self._managed_connection() as connection:
            row = connection.execute(
                """
                SELECT 1
                FROM allowlist
                WHERE active = 1 AND entry_type = 'hash' AND lower(value) = lower(?)
                LIMIT 1
                """,
                (sha256,),
            ).fetchone()
        return row is not None

    def deactivate_blocked_file(self, path: str, sha256: str) -> None:
        with self._lock, self._managed_connection() as connection:
            connection.execute(
                """
                UPDATE blocklist
                SET active = 0
                WHERE path = ? AND sha256 = ?
                """,
                (path, sha256),
            )

    def deactivate_blocked_file_by_source(self, path: str, sha256: str, source: str) -> None:
        with self._lock, self._managed_connection() as connection:
            connection.execute(
                """
                UPDATE blocklist
                SET active = 0
                WHERE path = ? AND sha256 = ? AND source = ?
                """,
                (path, sha256, source),
            )

    def record_block_event(
        self,
        pid: int | None,
        process_name: str | None,
        exe_path: str | None,
        sha256: str | None,
        reason: str,
    ) -> None:
        with self._lock, self._managed_connection() as connection:
            connection.execute(
                """
                INSERT INTO block_events (pid, process_name, exe_path, sha256, reason)
                VALUES (?, ?, ?, ?, ?)
                """,
                (pid, process_name, exe_path, sha256, reason),
            )

    def record_wallpaper_event(self, wallpaper_path: str | None, details: str) -> None:
        with self._lock, self._managed_connection() as connection:
            connection.execute(
                """
                INSERT INTO wallpaper_events (wallpaper_path, details)
                VALUES (?, ?)
                """,
                (wallpaper_path, details),
            )

    def record_quarantine_item(self, original_path: str, quarantined_path: str, sha256: str, reason: str) -> int:
        with self._lock, self._managed_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO quarantine_items (original_path, quarantined_path, sha256, reason)
                VALUES (?, ?, ?, ?)
                """,
                (original_path, quarantined_path, sha256, reason),
            )
            return int(cursor.lastrowid)

    def list_quarantine_items(self, active_only: bool = True, limit: int = 200) -> list[dict[str, Any]]:
        query = """
            SELECT id, quarantined_at, original_path, quarantined_path, sha256, reason, restored_at, restored_path
            FROM quarantine_items
        """
        if active_only:
            query += " WHERE restored_at IS NULL"
        query += " ORDER BY id DESC LIMIT ?"
        with self._lock, self._managed_connection() as connection:
            rows = connection.execute(query, (limit,)).fetchall()
        return [dict(row) for row in rows]

    def get_quarantine_item(self, item_id: int) -> dict[str, Any] | None:
        with self._lock, self._managed_connection() as connection:
            row = connection.execute(
                """
                SELECT id, quarantined_at, original_path, quarantined_path, sha256, reason, restored_at, restored_path
                FROM quarantine_items
                WHERE id = ?
                """,
                (item_id,),
            ).fetchone()
        return self._row_to_dict(row)

    def mark_quarantine_restored(self, item_id: int, restored_path: str) -> None:
        with self._lock, self._managed_connection() as connection:
            connection.execute(
                """
                UPDATE quarantine_items
                SET restored_at = CURRENT_TIMESTAMP,
                    restored_path = ?
                WHERE id = ?
                """,
                (restored_path, item_id),
            )

    def list_recent_detections(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self._managed_connection() as connection:
            rows = connection.execute(
                """
                SELECT scanned_at, path, sha256, size, extension, status,
                       score, summary, quarantined_path
                FROM detections
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_dashboard_summary(self) -> dict[str, Any]:
        with self._lock, self._managed_connection() as connection:
            total_scans = int(connection.execute("SELECT COUNT(*) FROM detections").fetchone()[0])
            suspicious_scans = int(connection.execute("SELECT COUNT(*) FROM detections WHERE status = 'suspicious'").fetchone()[0])
            malicious_scans = int(connection.execute("SELECT COUNT(*) FROM detections WHERE status = 'malicious'").fetchone()[0])
            today_detections = int(
                connection.execute(
                    "SELECT COUNT(*) FROM detections WHERE date(scanned_at) = date('now')"
                ).fetchone()[0]
            )
            today_blocks = int(
                connection.execute(
                    "SELECT COUNT(*) FROM block_events WHERE date(blocked_at) = date('now')"
                ).fetchone()[0]
            )
            watch_count = int(connection.execute("SELECT COUNT(*) FROM watched_files WHERE status != 'auto_unblocked'").fetchone()[0])
            sandbox_queue = int(connection.execute("SELECT COUNT(*) FROM sandbox_queue WHERE status IN ('pending', 'running')").fetchone()[0])
        return {
            "total_scans": total_scans,
            "suspicious_scans": suspicious_scans,
            "malicious_scans": malicious_scans,
            "detections_today": today_detections,
            "blocks_today": today_blocks,
            "watched_files": watch_count,
            "sandbox_queue": sandbox_queue,
        }

    def get_detection_counts_by_day(self, days: int = 7) -> list[dict[str, Any]]:
        with self._lock, self._managed_connection() as connection:
            rows = connection.execute(
                """
                SELECT date(scanned_at) AS day,
                       COUNT(*) AS scan_count,
                       SUM(CASE WHEN status = 'suspicious' THEN 1 ELSE 0 END) AS suspicious_count,
                       SUM(CASE WHEN status = 'malicious' THEN 1 ELSE 0 END) AS malicious_count
                FROM detections
                WHERE datetime(scanned_at) >= datetime('now', ?)
                GROUP BY date(scanned_at)
                ORDER BY day DESC
                """,
                (f"-{int(days)} days",),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_recent_dashboard_events(self, limit: int = 20) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for row in self.list_recent_detections(limit=max(1, limit // 2)):
            events.append(
                {
                    "event_at": row["scanned_at"],
                    "category": "detection",
                    "severity": row["status"],
                    "message": row["summary"],
                    "path": row["path"],
                }
            )
        for row in self.list_recent_block_events(limit=max(1, limit // 2)):
            events.append(
                {
                    "event_at": row["blocked_at"],
                    "category": "block",
                    "severity": "blocked",
                    "message": row["reason"],
                    "path": row.get("exe_path", ""),
                }
            )
        for row in self.list_recent_behavior_events(limit=max(1, limit // 2)):
            events.append(
                {
                    "event_at": row["observed_at"],
                    "category": "behavior",
                    "severity": row["stage"],
                    "message": row["reason"],
                    "path": row.get("process_path", ""),
                }
            )
        events.sort(key=lambda item: str(item["event_at"]), reverse=True)
        return events[:limit]

    def get_hash_history(self, sha256: str, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock, self._managed_connection() as connection:
            rows = connection.execute(
                """
                SELECT scanned_at, path, status, score, summary
                FROM detections
                WHERE sha256 = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (sha256, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def is_hash_blocked(self, sha256: str) -> bool:
        with self._lock, self._managed_connection() as connection:
            row = connection.execute(
                """
                SELECT 1
                FROM blocklist
                WHERE sha256 = ? AND active = 1
                LIMIT 1
                """,
                (sha256,),
            ).fetchone()
        return row is not None

    def list_recent_block_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self._managed_connection() as connection:
            rows = connection.execute(
                """
                SELECT blocked_at, pid, process_name, exe_path, sha256, reason
                FROM block_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_wallpaper_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self._managed_connection() as connection:
            rows = connection.execute(
                """
                SELECT event_at, wallpaper_path, details
                FROM wallpaper_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def record_behavior_incident(self, incident: BehaviorIncident) -> None:
        payload = incident.to_dict()
        with self._lock, self._managed_connection() as connection:
            connection.execute(
                """
                INSERT INTO behavior_events (
                    observed_at, incident_type, score, stage, reason,
                    process_pid, process_name, process_path,
                    attributed, attribution_confidence,
                    paths_json, actions_json, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["observed_at"],
                    payload["incident_type"],
                    payload["score"],
                    payload["stage"],
                    payload["reason"],
                    payload["process_pid"],
                    payload["process_name"],
                    payload["process_path"],
                    1 if payload["attributed"] else 0,
                    payload["attribution_confidence"],
                    self._json(payload["paths"]),
                    self._json(payload["actions"]),
                    self._json(payload["metadata"]),
                ),
            )

    def list_recent_behavior_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self._managed_connection() as connection:
            rows = connection.execute(
                """
                SELECT observed_at, incident_type, score, stage, reason,
                       process_pid, process_name, process_path,
                       attributed, attribution_confidence,
                       paths_json, actions_json, metadata_json
                FROM behavior_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item = self._decode_json_fields(item, ("paths_json", "actions_json", "metadata_json"))
            item["paths"] = item.pop("paths_json", [])
            item["actions"] = item.pop("actions_json", [])
            item["metadata"] = item.pop("metadata_json", {})
            items.append(item)
        return items

    def record_launch_decision(self, decision: LaunchDecision) -> None:
        payload = decision.to_dict()
        with self._lock, self._managed_connection() as connection:
            connection.execute(
                """
                INSERT INTO launch_decisions (
                    observed_at, path, sha256, action, final_verdict,
                    aggregate_score, reason, stage_verdicts_json, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["observed_at"],
                    payload["path"],
                    payload["sha256"],
                    payload["action"],
                    payload["final_verdict"],
                    payload["aggregate_score"],
                    payload["reason"],
                    self._json(payload["stage_verdicts"]),
                    self._json(payload["metadata"]),
                ),
            )

    def list_launch_decisions(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self._managed_connection() as connection:
            rows = connection.execute(
                """
                SELECT observed_at, path, sha256, action, final_verdict,
                       aggregate_score, reason, stage_verdicts_json, metadata_json
                FROM launch_decisions
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item = self._decode_json_fields(item, ("stage_verdicts_json", "metadata_json"))
            item["stage_verdicts"] = item.pop("stage_verdicts_json", [])
            item["metadata"] = item.pop("metadata_json", {})
            items.append(item)
        return items

    def upsert_rollback_artifact(self, artifact: RollbackArtifact) -> None:
        payload = artifact.to_dict()
        with self._lock, self._managed_connection() as connection:
            connection.execute(
                """
                INSERT INTO rollback_artifacts (
                    created_at, original_path, snapshot_path, sha256,
                    source_mtime, source_size, reason, restored_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["created_at"],
                    payload["original_path"],
                    payload["snapshot_path"],
                    payload["sha256"],
                    payload["source_mtime"],
                    payload["source_size"],
                    payload["reason"],
                    payload["restored_at"],
                ),
            )

    def get_latest_rollback_artifact(self, original_path: str) -> dict[str, Any] | None:
        with self._lock, self._managed_connection() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM rollback_artifacts
                WHERE original_path = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (original_path,),
            ).fetchone()
        return self._row_to_dict(row)

    def list_rollback_artifacts(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock, self._managed_connection() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM rollback_artifacts
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def mark_rollback_artifact_restored(self, artifact_id: int) -> None:
        with self._lock, self._managed_connection() as connection:
            connection.execute(
                """
                UPDATE rollback_artifacts
                SET restored_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (artifact_id,),
            )

    def record_benchmark_run(self, corpus_path: str, payload: dict[str, Any], observed_at: str) -> None:
        with self._lock, self._managed_connection() as connection:
            connection.execute(
                """
                INSERT INTO benchmark_runs (observed_at, corpus_path, summary_json)
                VALUES (?, ?, ?)
                """,
                (observed_at, corpus_path, self._json(payload)),
            )

    def list_benchmark_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock, self._managed_connection() as connection:
            rows = connection.execute(
                """
                SELECT observed_at, corpus_path, summary_json
                FROM benchmark_runs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item = self._decode_json_fields(item, ("summary_json",))
            item["summary"] = item.pop("summary_json", {})
            items.append(item)
        return items

    def upsert_watched_file(self, state: WatchedFileState) -> None:
        payload = state.to_dict()
        with self._lock, self._managed_connection() as connection:
            connection.execute(
                """
                INSERT INTO watched_files (
                    path, sha256, status, reason, last_verdict, clean_scan_count,
                    quarantined_path, quarantine_item_id, cloud_verdict, sandbox_verdict,
                    local_verdict, defender_verdict, confirmed_malware,
                    last_seen_at, under_watch_since, last_clean_at,
                    last_behavior_at, auto_unblocked_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(path, sha256) DO UPDATE SET
                    updated_at = CURRENT_TIMESTAMP,
                    status = excluded.status,
                    reason = excluded.reason,
                    last_verdict = excluded.last_verdict,
                    clean_scan_count = excluded.clean_scan_count,
                    quarantined_path = excluded.quarantined_path,
                    quarantine_item_id = excluded.quarantine_item_id,
                    cloud_verdict = excluded.cloud_verdict,
                    sandbox_verdict = excluded.sandbox_verdict,
                    local_verdict = excluded.local_verdict,
                    defender_verdict = excluded.defender_verdict,
                    confirmed_malware = excluded.confirmed_malware,
                    last_seen_at = excluded.last_seen_at,
                    under_watch_since = excluded.under_watch_since,
                    last_clean_at = excluded.last_clean_at,
                    last_behavior_at = excluded.last_behavior_at,
                    auto_unblocked_at = excluded.auto_unblocked_at,
                    metadata_json = excluded.metadata_json
                """,
                (
                    payload["path"],
                    payload["sha256"],
                    payload["status"],
                    payload["reason"],
                    payload["last_verdict"],
                    payload["clean_scan_count"],
                    payload["quarantined_path"],
                    payload["quarantine_item_id"],
                    payload["cloud_verdict"],
                    payload["sandbox_verdict"],
                    payload["local_verdict"],
                    payload["defender_verdict"],
                    1 if payload["confirmed_malware"] else 0,
                    payload["last_seen_at"],
                    payload["under_watch_since"],
                    payload["last_clean_at"],
                    payload["last_behavior_at"],
                    payload["auto_unblocked_at"],
                    self._json(payload["metadata"]),
                ),
            )

    def get_watched_file(self, path: str, sha256: str) -> dict[str, Any] | None:
        with self._lock, self._managed_connection() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM watched_files
                WHERE path = ? AND sha256 = ?
                """,
                (path, sha256),
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        item = self._decode_json_fields(item, ("metadata_json",))
        item["metadata"] = item.pop("metadata_json", {})
        return item

    def update_watched_file(self, path: str, sha256: str, **updates: Any) -> None:
        if not updates:
            return
        column_map = {
            "status": "status",
            "reason": "reason",
            "last_verdict": "last_verdict",
            "clean_scan_count": "clean_scan_count",
            "quarantined_path": "quarantined_path",
            "quarantine_item_id": "quarantine_item_id",
            "cloud_verdict": "cloud_verdict",
            "sandbox_verdict": "sandbox_verdict",
            "local_verdict": "local_verdict",
            "defender_verdict": "defender_verdict",
            "confirmed_malware": "confirmed_malware",
            "last_seen_at": "last_seen_at",
            "under_watch_since": "under_watch_since",
            "last_clean_at": "last_clean_at",
            "last_behavior_at": "last_behavior_at",
            "auto_unblocked_at": "auto_unblocked_at",
            "metadata": "metadata_json",
        }
        assignments: list[str] = ["updated_at = CURRENT_TIMESTAMP"]
        values: list[Any] = []
        for key, value in updates.items():
            if key not in column_map:
                continue
            column = column_map[key]
            if key == "confirmed_malware":
                value = 1 if value else 0
            if key == "metadata":
                value = self._json(value)
            assignments.append(f"{column} = ?")
            values.append(value)
        if len(assignments) == 1:
            return
        values.extend([path, sha256])
        with self._lock, self._managed_connection() as connection:
            connection.execute(
                f"UPDATE watched_files SET {', '.join(assignments)} WHERE path = ? AND sha256 = ?",
                values,
            )

    def delete_watched_file(self, path: str, sha256: str) -> None:
        with self._lock, self._managed_connection() as connection:
            connection.execute(
                """
                DELETE FROM watched_files
                WHERE path = ? AND sha256 = ?
                """,
                (path, sha256),
            )

    def list_watched_files(self, active_only: bool = True, limit: int = 200) -> list[dict[str, Any]]:
        query = "SELECT * FROM watched_files"
        if active_only:
            query += " WHERE status != 'auto_unblocked'"
        query += " ORDER BY updated_at DESC LIMIT ?"
        with self._lock, self._managed_connection() as connection:
            rows = connection.execute(query, (limit,)).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item = self._decode_json_fields(item, ("metadata_json",))
            item["metadata"] = item.pop("metadata_json", {})
            items.append(item)
        return items

    def get_background_scan_state(self, key: str, default: str = "") -> str:
        with self._lock, self._managed_connection() as connection:
            row = connection.execute(
                "SELECT value FROM background_scan_state WHERE key = ?",
                (key,),
            ).fetchone()
        if row is None:
            return default
        return str(row["value"])

    def set_background_scan_state(self, key: str, value: str) -> None:
        with self._lock, self._managed_connection() as connection:
            connection.execute(
                """
                INSERT INTO background_scan_state (key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (key, value),
            )

    def enqueue_sandbox_sample(self, path: str, sha256: str, reason: str, priority: int = 100) -> int:
        with self._lock, self._managed_connection() as connection:
            row = connection.execute(
                """
                SELECT id, priority
                FROM sandbox_queue
                WHERE path = ? AND sha256 = ? AND status IN ('pending', 'running')
                ORDER BY id DESC
                LIMIT 1
                """,
                (path, sha256),
            ).fetchone()
            if row is not None:
                connection.execute(
                    """
                    UPDATE sandbox_queue
                    SET reason = ?,
                        priority = CASE
                            WHEN priority > ? THEN ?
                            ELSE priority
                        END,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (reason, priority, priority, row["id"]),
                )
                return int(row["id"])
            cursor = connection.execute(
                """
                INSERT INTO sandbox_queue (path, sha256, reason, priority)
                VALUES (?, ?, ?, ?)
                """,
                (path, sha256, reason, priority),
            )
            return int(cursor.lastrowid)

    def claim_next_sandbox_item(self) -> dict[str, Any] | None:
        with self._lock, self._managed_connection() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM sandbox_queue
                WHERE status = 'pending'
                ORDER BY priority ASC, id ASC
                LIMIT 1
                """
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                """
                UPDATE sandbox_queue
                SET status = 'running',
                    attempts = attempts + 1,
                    last_attempt_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (row["id"],),
            )
        return dict(row)

    def requeue_running_sandbox_items(self) -> int:
        with self._lock, self._managed_connection() as connection:
            cursor = connection.execute(
                """
                UPDATE sandbox_queue
                SET status = 'pending',
                    updated_at = CURRENT_TIMESTAMP,
                    error_text = CASE
                        WHEN error_text IS NULL OR error_text = '' THEN 'Recovered after restart'
                        ELSE error_text
                    END
                WHERE status = 'running'
                """
            )
            return int(cursor.rowcount or 0)

    def complete_sandbox_item(
        self,
        item_id: int,
        status: str,
        report: dict[str, Any] | None = None,
        error_text: str = "",
    ) -> None:
        payload = report or {}
        report_json = self._json(payload)
        with self._lock, self._managed_connection() as connection:
            connection.execute(
                """
                UPDATE sandbox_queue
                SET status = ?,
                    report_json = ?,
                    bundle_dir = ?,
                    results_dir = ?,
                    error_text = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    status,
                    report_json,
                    str(payload.get("bundle_dir", "")),
                    str(payload.get("results_dir", "")),
                    error_text,
                    item_id,
                ),
            )

    def list_sandbox_queue(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self._managed_connection() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM sandbox_queue
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item = self._decode_json_fields(item, ("report_json",))
            item["report"] = item.pop("report_json", {})
            items.append(item)
        return items

    def enqueue_reputation_event(self, kind: str, sha256: str, path: str | None, payload: dict[str, Any]) -> int:
        with self._lock, self._managed_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO reputation_sync_queue (kind, path, sha256, payload_json)
                VALUES (?, ?, ?, ?)
                """,
                (kind, path, sha256, self._json(payload)),
            )
            return int(cursor.lastrowid)

    def claim_next_reputation_event(self) -> dict[str, Any] | None:
        with self._lock, self._managed_connection() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM reputation_sync_queue
                WHERE status = 'pending'
                ORDER BY id ASC
                LIMIT 1
                """
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                """
                UPDATE reputation_sync_queue
                SET status = 'running',
                    attempts = attempts + 1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (row["id"],),
            )
        item = dict(row)
        item = self._decode_json_fields(item, ("payload_json",))
        item["payload"] = item.pop("payload_json", {})
        return item

    def complete_reputation_event(
        self,
        item_id: int,
        success: bool,
        response: dict[str, Any] | None = None,
        error_text: str = "",
    ) -> None:
        with self._lock, self._managed_connection() as connection:
            connection.execute(
                """
                UPDATE reputation_sync_queue
                SET status = ?,
                    response_json = ?,
                    error_text = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                ("done" if success else "pending", self._json(response or {}), error_text, item_id),
            )

    def count_pending_reputation_events(self) -> int:
        with self._lock, self._managed_connection() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS total
                FROM reputation_sync_queue
                WHERE status = 'pending'
                """
            ).fetchone()
        return int(row["total"]) if row else 0

    def enqueue_error_report(
        self,
        level: str,
        logger_name: str,
        subject: str,
        fingerprint: str,
        payload: dict[str, Any],
    ) -> int:
        with self._lock, self._managed_connection() as connection:
            existing = connection.execute(
                """
                SELECT id
                FROM error_report_queue
                WHERE fingerprint = ? AND status IN ('pending', 'running')
                ORDER BY id DESC
                LIMIT 1
                """,
                (fingerprint,),
            ).fetchone()
            if existing is not None:
                return int(existing["id"])
            cursor = connection.execute(
                """
                INSERT INTO error_report_queue (level, logger_name, subject, fingerprint, payload_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (level, logger_name, subject, fingerprint, self._json(payload)),
            )
            return int(cursor.lastrowid)

    def claim_next_error_report(self) -> dict[str, Any] | None:
        with self._lock, self._managed_connection() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM error_report_queue
                WHERE status = 'pending'
                ORDER BY id ASC
                LIMIT 1
                """
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                """
                UPDATE error_report_queue
                SET status = 'running',
                    attempts = attempts + 1,
                    last_attempt_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (row["id"],),
            )
        item = dict(row)
        item = self._decode_json_fields(item, ("payload_json", "response_json"))
        item["payload"] = item.pop("payload_json", {})
        item["response"] = item.pop("response_json", {})
        return item

    def requeue_running_error_reports(self) -> int:
        with self._lock, self._managed_connection() as connection:
            cursor = connection.execute(
                """
                UPDATE error_report_queue
                SET status = 'pending',
                    updated_at = CURRENT_TIMESTAMP,
                    error_text = CASE
                        WHEN error_text IS NULL OR error_text = '' THEN 'Recovered after restart'
                        ELSE error_text
                    END
                WHERE status = 'running'
                """
            )
            return int(cursor.rowcount or 0)

    def complete_error_report(
        self,
        item_id: int,
        success: bool,
        response: dict[str, Any] | None = None,
        error_text: str = "",
    ) -> None:
        with self._lock, self._managed_connection() as connection:
            connection.execute(
                """
                UPDATE error_report_queue
                SET status = ?,
                    response_json = ?,
                    error_text = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                ("done" if success else "pending", self._json(response or {}), error_text, item_id),
            )

    def count_pending_error_reports(self) -> int:
        with self._lock, self._managed_connection() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS total
                FROM error_report_queue
                WHERE status = 'pending'
                """
            ).fetchone()
        return int(row["total"]) if row else 0

    def list_error_reports(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock, self._managed_connection() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM error_report_queue
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item = self._decode_json_fields(item, ("payload_json", "response_json"))
            item["payload"] = item.pop("payload_json", {})
            item["response"] = item.pop("response_json", {})
            items.append(item)
        return items
