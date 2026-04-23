from __future__ import annotations

import hashlib
import re
import threading
import time
from collections import deque
from pathlib import Path
from queue import Empty, Queue
from typing import Any

from .config import (
    BEHAVIOR_CREATE_THRESHOLD,
    BEHAVIOR_CREATE_WINDOW_SECONDS,
    BEHAVIOR_MODIFY_THRESHOLD,
    BEHAVIOR_MODIFY_WINDOW_SECONDS,
    BEHAVIOR_RENAME_THRESHOLD,
    BEHAVIOR_RENAME_WINDOW_SECONDS,
    BEHAVIOR_SENSITIVE_ZONE_THRESHOLD,
    HIGH_RISK_PROCESS_NAMES,
    RANSOMWARE_EARLY_RENAME_THRESHOLD,
    RANSOMWARE_HARD_KILL_RENAME_THRESHOLD,
    SENSITIVE_EXTENSIONS,
    SENSITIVE_ZONE_PATHS,
    USER_SPACE_HINTS,
    is_managed_path,
)
from .database import Database
from .logging_setup import get_logger
from .models import BehaviorIncident

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None


class BehaviorCorrelationEngine:
    def __init__(self, scanner, database: Database, watch_manager=None, canary_guard=None, rollback_cache=None) -> None:
        self.scanner = scanner
        self.database = database
        self.watch_manager = watch_manager
        self.canary_guard = canary_guard
        self.rollback_cache = rollback_cache
        self.logger = get_logger("ragnar_protect.behavior")
        self._queue: Queue[dict[str, Any]] = Queue()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._rename_events: deque[dict[str, Any]] = deque()
        self._modify_events: deque[dict[str, Any]] = deque()
        self._create_events: deque[dict[str, Any]] = deque()
        self._last_incidents: dict[str, float] = {}
        self._process_samples: dict[int, dict[str, float]] = {}
        self._disk_sample: dict[str, float] | None = None

    _COMMON_DATA_EXTENSIONS = {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".csv", ".db",
        ".sql", ".psd", ".zip", ".7z", ".rar", ".mp3", ".wav", ".flac", ".mp4",
        ".avi", ".mkv", ".mov", ".xml", ".json", ".md", ".odt", ".ods", ".odp",
    }
    _SAFE_TARGET_EXTENSIONS = _COMMON_DATA_EXTENSIONS | SENSITIVE_EXTENSIONS | {".tmp", ".bak", ".old", ".log"}
    _ENCRYPTED_EXTENSION_RE = re.compile(r"\.[a-z0-9_-]{2,14}$", re.IGNORECASE)
    _RANSOM_EXTENSION_TOKENS = ("locked", "lock", "encrypted", "crypt", "crypted", "enc", "wncry", "ryuk", "conti", "lockbit")
    _RANSOM_NOTE_TOKENS = (
        "readme", "decrypt", "recover", "restore", "your_files", "ransom", "how_to",
        "help", "warning", "instruction", "unlock",
    )
    _RANSOM_NOTE_SUFFIXES = {".txt", ".hta", ".html", ".url", ".bmp", ".png"}

    @property
    def available(self) -> bool:
        return psutil is not None

    def start(self) -> None:
        if not self.available or (self._thread and self._thread.is_alive()):
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, name="RagnarBehaviorEngine", daemon=True)
        self._thread.start()
        self.logger.info("behavior correlation engine started")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.logger.info("behavior correlation engine stopped")

    def handle_fs_event(
        self,
        event_type: str,
        path: str,
        dest_path: str | None = None,
        is_directory: bool = False,
    ) -> None:
        if is_directory or not path:
            return
        self._queue.put(
            {
                "event_type": event_type,
                "path": path,
                "dest_path": dest_path,
                "is_directory": is_directory,
                "timestamp": time.time(),
            }
        )

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                event = self._queue.get(timeout=1)
            except Empty:
                continue
            try:
                self._process_event(event)
            except Exception as exc:
                self.logger.exception("behavior event processing failed | %s", exc)

    def _process_event(self, event: dict[str, Any]) -> None:
        path = Path(str(event["dest_path"] or event["path"])).expanduser()
        try:
            if is_managed_path(path):
                return
        except Exception:
            return
        zone_names = self._zones_for_path(path)
        original_path = Path(str(event["path"])).expanduser()
        item = {
            "path": str(path),
            "src_path": str(original_path),
            "dest_path": str(path) if event["event_type"] == "moved" else "",
            "timestamp": float(event["timestamp"]),
            "zone_names": zone_names,
            "event_type": str(event["event_type"]),
            "src_ext": original_path.suffix.lower(),
            "dest_ext": path.suffix.lower(),
            "name": path.name.lower(),
            "is_canary": self._is_canary_event(original_path, path),
        }
        if item["event_type"] == "moved":
            self._rename_events.append(item)
        elif item["event_type"] == "created":
            if path.suffix.lower() in SENSITIVE_EXTENSIONS or self._is_ransom_note_name(path.name):
                self._create_events.append(item)
            elif item["is_canary"]:
                self._create_events.append(item)
        else:
            self._modify_events.append(item)
        self._trim_events()
        incident = self._evaluate_incident(path)
        if incident is None:
            return
        self._dispatch_incident(incident)

    def _trim_events(self) -> None:
        now = time.time()
        limits = (
            (self._rename_events, BEHAVIOR_RENAME_WINDOW_SECONDS),
            (self._modify_events, BEHAVIOR_MODIFY_WINDOW_SECONDS),
            (self._create_events, BEHAVIOR_CREATE_WINDOW_SECONDS),
        )
        for bucket, window in limits:
            while bucket and now - float(bucket[0]["timestamp"]) > window:
                bucket.popleft()

    def _evaluate_incident(self, path: Path) -> BehaviorIncident | None:
        rename_count = len(self._rename_events)
        modify_count = len(self._modify_events)
        create_count = len(self._create_events)
        ransomware_signals = self._analyze_ransomware_signals()
        if (
            rename_count < BEHAVIOR_RENAME_THRESHOLD
            and modify_count < BEHAVIOR_MODIFY_THRESHOLD
            and create_count < BEHAVIOR_CREATE_THRESHOLD
            and ransomware_signals["ransom_note_count"] == 0
            and ransomware_signals["encrypted_rename_count"] < RANSOMWARE_EARLY_RENAME_THRESHOLD
            and ransomware_signals["canary_event_count"] == 0
        ):
            return None

        touched_paths = self._collect_touched_paths()
        sensitive_zones = sorted(
            {
                zone
                for bucket in (self._rename_events, self._modify_events, self._create_events)
                for item in bucket
                for zone in item["zone_names"]
            }
        )
        process_info = self._attribute_process(path)
        attributed = process_info is not None and int(process_info.get("confidence", 0)) >= 35
        stage = "stage1"
        score = 0
        actions: list[str] = []
        incident_type = "behavior_burst"
        if rename_count >= BEHAVIOR_RENAME_THRESHOLD:
            incident_type = "rename_burst"
            score += 50
        if modify_count >= BEHAVIOR_MODIFY_THRESHOLD:
            incident_type = "modify_burst" if incident_type == "behavior_burst" else incident_type
            score += 45
        if create_count >= BEHAVIOR_CREATE_THRESHOLD:
            incident_type = "create_burst" if incident_type == "behavior_burst" else incident_type
            score += 30
        if len(sensitive_zones) >= BEHAVIOR_SENSITIVE_ZONE_THRESHOLD:
            score += 25
        if ransomware_signals["canary_event_count"] > 0:
            incident_type = "canary_trip"
            score += 90
        if ransomware_signals["encrypted_rename_count"] >= RANSOMWARE_EARLY_RENAME_THRESHOLD:
            incident_type = "encrypted_rename_burst"
            score += 55
        if ransomware_signals["dominant_encrypted_extension_count"] >= RANSOMWARE_EARLY_RENAME_THRESHOLD:
            score += 20
        if ransomware_signals["ransom_note_count"] > 0:
            incident_type = "ransom_note_burst"
            score += 60
        if ransomware_signals["unique_touched_parent_count"] >= 5:
            score += 15
        if attributed:
            score += int(process_info.get("confidence", 0)) // 2
            if bool(process_info.get("recent")):
                score += 10
            if int(process_info.get("child_count", 0)) > 0:
                score += 10
        killable_fallback = (
            process_info is not None
            and int(process_info.get("confidence", 0)) >= 20
            and (
                bool(process_info.get("recent"))
                or bool(process_info.get("user_space"))
                or str(process_info.get("name", "")).lower() in HIGH_RISK_PROCESS_NAMES
            )
            and (
                ransomware_signals["encrypted_rename_count"] >= RANSOMWARE_EARLY_RENAME_THRESHOLD
                or ransomware_signals["ransom_note_count"] > 0
                or ransomware_signals["canary_event_count"] > 0
            )
        )
        if not attributed and not killable_fallback and ransomware_signals["canary_event_count"] == 0:
            incident_type = "burst_unattributed"
            score = max(25, score - 25)

        global_metrics = self._global_metrics()
        proc_write_rate = float(process_info.get("write_rate", 0.0)) if attributed else 0.0
        effective_pid = int(process_info.get("pid")) if (attributed or killable_fallback) and process_info and process_info.get("pid") else None
        effective_write_rate = float(process_info.get("write_rate", 0.0)) if (attributed or killable_fallback) and process_info else 0.0
        causal = effective_pid is not None and (
            effective_write_rate >= 1_500_000
            or (float(global_metrics.get("cpu_percent", 0.0)) >= 65 and effective_write_rate >= 250_000)
            or (float(global_metrics.get("disk_percent", 0.0)) >= 70 and effective_write_rate >= 250_000)
            or ransomware_signals["encrypted_rename_count"] >= RANSOMWARE_HARD_KILL_RENAME_THRESHOLD
            or ransomware_signals["ransom_note_count"] > 0
            or ransomware_signals["canary_event_count"] > 0
        )

        if effective_pid is not None and (
            rename_count >= BEHAVIOR_RENAME_THRESHOLD
            or modify_count >= BEHAVIOR_MODIFY_THRESHOLD
            or (create_count >= BEHAVIOR_CREATE_THRESHOLD and len(sensitive_zones) >= BEHAVIOR_SENSITIVE_ZONE_THRESHOLD)
            or ransomware_signals["encrypted_rename_count"] >= RANSOMWARE_EARLY_RENAME_THRESHOLD
            or ransomware_signals["ransom_note_count"] > 0
            or ransomware_signals["canary_event_count"] > 0
        ):
            if (
                causal
                or rename_count >= BEHAVIOR_RENAME_THRESHOLD
                or ransomware_signals["encrypted_rename_count"] >= RANSOMWARE_EARLY_RENAME_THRESHOLD
                or ransomware_signals["ransom_note_count"] > 0
                or ransomware_signals["canary_event_count"] > 0
            ):
                stage = "stage2"
                actions.extend(["kill_process", "block_hash", "scan_recent_artifacts"])
        if stage == "stage1":
            actions.extend(["alert", "reinforced_watch"])

        process_pid = effective_pid
        signature = f"{incident_type}:{process_pid or 'none'}"
        if time.time() - self._last_incidents.get(signature, 0.0) < 15:
            return None
        self._last_incidents[signature] = time.time()

        reason = (
            f"{rename_count} renames, {modify_count} modifications, {create_count} creations, "
            f"{len(sensitive_zones)} sensitive zone(s)"
        )
        return BehaviorIncident(
            incident_type=incident_type,
            score=score,
            stage=stage,
            reason=reason,
            paths=touched_paths,
            actions=actions,
            process_pid=process_pid,
            process_name=str(process_info.get("name")) if process_pid and process_info else None,
            process_path=str(process_info.get("exe")) if process_pid and process_info else None,
            attributed=attributed,
            attribution_confidence=int(process_info.get("confidence", 0)) if attributed else 0,
            metadata={
                "rename_count": rename_count,
                "modify_count": modify_count,
                "create_count": create_count,
                "sensitive_zones": sensitive_zones,
                "ransomware_signals": ransomware_signals,
                "global_metrics": global_metrics,
                "process_metrics": process_info or {},
            },
        )

    def _dispatch_incident(self, incident: BehaviorIncident) -> None:
        if self.watch_manager is not None:
            self.watch_manager.handle_behavior_incident(incident)
        else:
            self.database.record_behavior_incident(incident)
        self.logger.warning(
            "behavior incident | type=%s stage=%s score=%s pid=%s reason=%s",
            incident.incident_type,
            incident.stage,
            incident.score,
            incident.process_pid,
            incident.reason,
        )
        if incident.stage != "stage2" or not incident.process_pid:
            return
        self._kill_and_contain(incident)

    def _kill_and_contain(self, incident: BehaviorIncident) -> None:
        if psutil is None or not incident.process_pid:
            return
        try:
            proc = psutil.Process(incident.process_pid)
        except Exception:
            return
        exe = str(incident.process_path or "")
        self._terminate_process(proc)
        sha256 = None
        if exe and Path(exe).exists():
            try:
                sha256 = self._sha256(Path(exe))
                self.database.upsert_blocked_file(exe, sha256, incident.reason, source="behavior")
                live_result = self.scanner.scan_file(Path(exe))
                if self.watch_manager is not None:
                    self.watch_manager.handle_scan_result(live_result)
            except Exception as exc:
                self.logger.warning("behavior containment scan failed | %s | %s", exe, exc)
        self.database.record_block_event(
            pid=incident.process_pid,
            process_name=incident.process_name,
            exe_path=exe or None,
            sha256=sha256,
            reason=f"Behavior correlation: {incident.reason}",
        )
        restored_paths: list[str] = []
        if self.rollback_cache is not None:
            restored_paths = self.rollback_cache.restore_paths(incident.paths, incident.reason)
            if restored_paths:
                self.logger.warning("rollback restored %s path(s) after incident", len(restored_paths))
        for touched_path in incident.paths[:8]:
            candidate = Path(touched_path)
            if not candidate.exists() or candidate.suffix.lower() not in SENSITIVE_EXTENSIONS:
                continue
            try:
                self.scanner.scan_file(candidate)
            except Exception:
                continue

    def _collect_touched_paths(self) -> list[str]:
        seen: set[str] = set()
        paths: list[str] = []
        for bucket in (self._rename_events, self._modify_events, self._create_events):
            for item in list(bucket)[-40:]:
                for value in (str(item.get("src_path") or item["path"]), str(item.get("dest_path") or item["path"])):
                    if not value or value in seen:
                        continue
                    seen.add(value)
                    paths.append(value)
        return paths

    def _attribute_process(self, target_path: Path) -> dict[str, Any] | None:
        if psutil is None:
            return None
        target_parent = str(target_path.parent).lower()
        target_name = target_path.name.lower()
        best: dict[str, Any] | None = None
        now = time.time()
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "create_time"]):
            try:
                name = str(proc.info.get("name") or "")
                exe = str(proc.info.get("exe") or "")
                cmdline = " ".join(str(part) for part in (proc.info.get("cmdline") or []) if part)
                create_time = float(proc.info.get("create_time") or 0.0)
                if not exe and not cmdline:
                    continue
                recent = now - create_time <= 90 if create_time else False
                if not recent and not self._is_user_space_path(exe) and name.lower() not in HIGH_RISK_PROCESS_NAMES:
                    continue
                confidence = 0
                if exe and self._is_user_space_path(exe):
                    confidence += 10
                if target_name and target_name in cmdline.lower():
                    confidence += 20
                if exe and str(Path(exe).parent).lower() == target_parent:
                    confidence += 15
                if recent:
                    confidence += 10
                if name.lower() in HIGH_RISK_PROCESS_NAMES:
                    confidence += 10
                open_files = []
                try:
                    open_files = proc.open_files()[:12]
                except Exception:
                    open_files = []
                if any(str(item.path).lower() == str(target_path).lower() for item in open_files):
                    confidence += 40
                elif any(str(Path(item.path).parent).lower() == target_parent for item in open_files):
                    confidence += 20
                cwd = ""
                try:
                    cwd = proc.cwd()
                except Exception:
                    cwd = ""
                if cwd and str(Path(cwd)).lower() == target_parent:
                    confidence += 15

                sample = self._sample_process(proc)
                child_count = 0
                try:
                    child_count = len(proc.children(recursive=False))
                except Exception:
                    child_count = 0
                if sample["write_rate"] >= 250_000:
                    confidence += 10
                if best is None or confidence > int(best.get("confidence", 0)):
                    best = {
                        "pid": int(proc.info.get("pid") or 0),
                        "name": name,
                        "exe": exe,
                        "cmdline": cmdline,
                        "confidence": confidence,
                        "recent": recent,
                        "user_space": bool(exe and self._is_user_space_path(exe)),
                        "child_count": child_count,
                        "write_rate": sample["write_rate"],
                        "cpu_percent": sample["cpu_percent"],
                    }
            except Exception:
                continue
        return best

    def _sample_process(self, proc) -> dict[str, float]:
        now = time.time()
        pid = int(proc.pid)
        read_bytes = 0.0
        write_bytes = 0.0
        try:
            counters = proc.io_counters()
            read_bytes = float(getattr(counters, "read_bytes", 0.0))
            write_bytes = float(getattr(counters, "write_bytes", 0.0))
        except Exception:
            pass
        try:
            cpu_percent = float(proc.cpu_percent(interval=None))
        except Exception:
            cpu_percent = 0.0
        previous = self._process_samples.get(pid)
        self._process_samples[pid] = {
            "timestamp": now,
            "read_bytes": read_bytes,
            "write_bytes": write_bytes,
            "cpu_percent": cpu_percent,
        }
        if previous is None:
            return {"read_rate": 0.0, "write_rate": 0.0, "cpu_percent": cpu_percent}
        elapsed = max(0.5, now - previous["timestamp"])
        return {
            "read_rate": max(0.0, read_bytes - previous["read_bytes"]) / elapsed,
            "write_rate": max(0.0, write_bytes - previous["write_bytes"]) / elapsed,
            "cpu_percent": cpu_percent,
        }

    def _global_metrics(self) -> dict[str, float]:
        if psutil is None:
            return {"cpu_percent": 0.0, "disk_percent": 0.0}
        cpu_percent = float(psutil.cpu_percent(interval=None))
        disk_percent = 0.0
        counters = None
        try:
            counters = psutil.disk_io_counters()
        except Exception:
            counters = None
        now = time.time()
        if counters is not None:
            current = {
                "timestamp": now,
                "read_bytes": float(getattr(counters, "read_bytes", 0.0)),
                "write_bytes": float(getattr(counters, "write_bytes", 0.0)),
                "busy_time": float(getattr(counters, "busy_time", 0.0)),
            }
            if self._disk_sample is not None:
                elapsed = max(0.5, current["timestamp"] - self._disk_sample["timestamp"])
                busy_delta = max(0.0, current["busy_time"] - self._disk_sample["busy_time"])
                if busy_delta:
                    disk_percent = min(100.0, busy_delta / (elapsed * 10.0))
                else:
                    byte_delta = max(
                        0.0,
                        (current["read_bytes"] + current["write_bytes"])
                        - (self._disk_sample["read_bytes"] + self._disk_sample["write_bytes"]),
                    )
                    disk_percent = min(100.0, byte_delta / (elapsed * 1_500_000.0))
            self._disk_sample = current
        return {"cpu_percent": cpu_percent, "disk_percent": disk_percent}

    def _zones_for_path(self, path: Path) -> list[str]:
        resolved = str(path).lower()
        zones = []
        for zone, zone_path in SENSITIVE_ZONE_PATHS.items():
            try:
                if resolved.startswith(str(zone_path).lower()):
                    zones.append(zone)
            except Exception:
                continue
        return zones

    def _is_user_space_path(self, value: str) -> bool:
        normalized = str(Path(value)).lower()
        return any(normalized.startswith(prefix) for prefix in USER_SPACE_HINTS)

    def _analyze_ransomware_signals(self) -> dict[str, Any]:
        encrypted_rename_count = 0
        encrypted_extension_counts: dict[str, int] = {}
        ransom_note_count = 0
        touched_parents: set[str] = set()
        canary_event_count = 0
        canary_paths: set[str] = set()

        for item in self._rename_events:
            src_path = Path(str(item.get("src_path") or item["path"]))
            dest_path = Path(str(item.get("dest_path") or item["path"]))
            if bool(item.get("is_canary")):
                canary_event_count += 1
                canary_paths.add(str(dest_path))
            if self._looks_encrypted_rename(src_path, dest_path):
                encrypted_rename_count += 1
                encrypted_extension_counts[dest_path.suffix.lower()] = encrypted_extension_counts.get(dest_path.suffix.lower(), 0) + 1
            touched_parents.add(str(dest_path.parent).lower())

        for item in self._create_events:
            created_path = Path(str(item.get("path") or ""))
            touched_parents.add(str(created_path.parent).lower())
            if bool(item.get("is_canary")):
                canary_event_count += 1
                canary_paths.add(str(created_path))
            if self._is_ransom_note_name(created_path.name):
                ransom_note_count += 1

        for item in self._modify_events:
            modified_path = Path(str(item.get("path") or ""))
            if bool(item.get("is_canary")):
                canary_event_count += 1
                canary_paths.add(str(modified_path))
            touched_parents.add(str(modified_path.parent).lower())

        dominant_encrypted_extension = ""
        dominant_encrypted_extension_count = 0
        if encrypted_extension_counts:
            dominant_encrypted_extension, dominant_encrypted_extension_count = max(
                encrypted_extension_counts.items(),
                key=lambda pair: pair[1],
            )

        return {
            "encrypted_rename_count": encrypted_rename_count,
            "encrypted_extension_counts": encrypted_extension_counts,
            "dominant_encrypted_extension": dominant_encrypted_extension,
            "dominant_encrypted_extension_count": dominant_encrypted_extension_count,
            "ransom_note_count": ransom_note_count,
            "unique_touched_parent_count": len(touched_parents),
            "canary_event_count": canary_event_count,
            "canary_paths": sorted(canary_paths),
        }

    def _looks_encrypted_rename(self, src_path: Path, dest_path: Path) -> bool:
        src_ext = src_path.suffix.lower()
        dest_ext = dest_path.suffix.lower()
        if not src_ext or not dest_ext or src_ext == dest_ext:
            return False
        if src_ext not in self._COMMON_DATA_EXTENSIONS:
            return False
        if dest_ext in self._SAFE_TARGET_EXTENSIONS:
            return False
        if any(token in dest_ext for token in self._RANSOM_EXTENSION_TOKENS):
            return True
        return bool(self._ENCRYPTED_EXTENSION_RE.fullmatch(dest_ext))

    def _is_ransom_note_name(self, file_name: str) -> bool:
        lower_name = file_name.lower()
        suffix = Path(lower_name).suffix.lower()
        if suffix not in self._RANSOM_NOTE_SUFFIXES:
            return False
        return any(token in lower_name for token in self._RANSOM_NOTE_TOKENS)

    def _is_canary_event(self, original_path: Path, current_path: Path) -> bool:
        if self.canary_guard is None:
            return False
        return self.canary_guard.is_canary_path(original_path) or self.canary_guard.is_canary_path(current_path)

    def _terminate_process(self, proc) -> None:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def _sha256(self, file_path: Path) -> str:
        digest = hashlib.sha256()
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
