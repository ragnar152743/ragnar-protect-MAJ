from __future__ import annotations

import threading
import time
from pathlib import Path

from .config import (
    BACKGROUND_BATCH_SIZE,
    BACKGROUND_CPU_PAUSE_THRESHOLD,
    BACKGROUND_DISK_PAUSE_THRESHOLD,
    BACKGROUND_IDLE_SECONDS,
    BACKGROUND_PRIORITY_ROOTS,
    DEFAULT_MONITORED_DIRS,
    is_managed_path,
)
from .logging_setup import get_logger

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None


class BackgroundScanScheduler:
    def __init__(self, scanner, database, system_inspector, watch_manager=None, rollback_cache=None, interval_seconds: int = BACKGROUND_IDLE_SECONDS) -> None:
        self.scanner = scanner
        self.database = database
        self.system_inspector = system_inspector
        self.watch_manager = watch_manager
        self.rollback_cache = rollback_cache
        self.interval_seconds = interval_seconds
        self.logger = get_logger("ragnar_protect.background")
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._priority_paths: list[str] = []
        self._last_hotspot_scan = 0.0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, name="RagnarBackgroundScan", daemon=True)
        self._thread.start()
        self.logger.info("background scanner started")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.logger.info("background scanner stopped")

    def prioritize(self, path: str) -> None:
        if path and path not in self._priority_paths:
            self._priority_paths.append(path)

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                if self._should_pause():
                    self._stop_event.wait(max(2.0, self.interval_seconds))
                    continue
                if self._priority_paths:
                    self._scan_priority_batch()
                else:
                    self._scan_watch_batch()
                    self._scan_regular_batch()
                    self._scan_startup_surface_if_due()
            except Exception as exc:
                self.logger.exception("background scan loop failed | %s", exc)
            self._stop_event.wait(self.interval_seconds)

    def _scan_priority_batch(self) -> None:
        batch = self._priority_paths[:BACKGROUND_BATCH_SIZE]
        self._priority_paths = self._priority_paths[BACKGROUND_BATCH_SIZE:]
        for item in batch:
            candidate = Path(item)
            if not candidate.exists() or not candidate.is_file():
                continue
            if is_managed_path(candidate):
                continue
            try:
                if self.rollback_cache is not None:
                    self.rollback_cache.snapshot_file(candidate, reason="priority")
                self.scanner.scan_file(candidate)
            except Exception as exc:
                self.logger.warning("priority scan failed | %s | %s", candidate, exc)

    def _scan_watch_batch(self) -> None:
        if self.watch_manager is None:
            return
        for row in self.database.list_watched_files(active_only=True, limit=20):
            candidate_path = str(row.get("quarantined_path") or row.get("path") or "")
            if not candidate_path:
                continue
            candidate = Path(candidate_path)
            if not candidate.exists() or not candidate.is_file():
                continue
            if is_managed_path(candidate):
                continue
            try:
                if self.rollback_cache is not None:
                    self.rollback_cache.snapshot_file(candidate, reason="watch-rescan")
                result = self.scanner.scan_file(candidate)
                self.watch_manager.observe_watch_rescan(row, result)
            except Exception as exc:
                self.logger.warning("watch rescan failed | %s | %s", candidate, exc)
            break

    def _scan_regular_batch(self) -> None:
        cursor = self.database.get_background_scan_state("cursor_path", "")
        candidates = self._collect_interesting_files()
        if not candidates:
            return
        next_items = [item for item in candidates if item > cursor][:BACKGROUND_BATCH_SIZE]
        if not next_items:
            next_items = candidates[:BACKGROUND_BATCH_SIZE]
        for item in next_items:
            candidate = Path(item)
            if not candidate.exists() or not candidate.is_file():
                continue
            if is_managed_path(candidate):
                continue
            try:
                if self.rollback_cache is not None:
                    self.rollback_cache.snapshot_file(candidate, reason="background")
                self.scanner.scan_file(candidate)
            except Exception as exc:
                self.logger.warning("background scan failed | %s | %s", candidate, exc)
        self.database.set_background_scan_state("cursor_path", next_items[-1])

    def _scan_startup_surface_if_due(self) -> None:
        now = time.time()
        if now - self._last_hotspot_scan < 300:
            return
        self._last_hotspot_scan = now
        self.system_inspector.scan_startup_entries()
        self.system_inspector.scan_scheduled_tasks()
        self.system_inspector.scan_hotspots(max_files_per_dir=16)

    def _collect_interesting_files(self) -> list[str]:
        roots = [path for path in [*BACKGROUND_PRIORITY_ROOTS, *DEFAULT_MONITORED_DIRS] if path.exists()]
        seen: set[str] = set()
        candidates: list[str] = []
        for root in roots:
            try:
                for path in root.rglob("*"):
                    if not path.is_file():
                        continue
                    if is_managed_path(path):
                        continue
                    if not self.system_inspector._is_interesting_file(path):
                        continue
                    normalized = str(path.resolve())
                    if normalized in seen:
                        continue
                    seen.add(normalized)
                    candidates.append(normalized)
            except OSError:
                continue
        return sorted(candidates)

    def _should_pause(self) -> bool:
        if psutil is None:
            return False
        try:
            cpu_percent = float(psutil.cpu_percent(interval=None))
        except Exception:
            cpu_percent = 0.0

        disk_percent = 0.0
        try:
            counters = psutil.disk_io_counters()
            if counters is not None:
                total_bytes = float(getattr(counters, "read_bytes", 0.0) + getattr(counters, "write_bytes", 0.0))
                previous = float(self.database.get_background_scan_state("disk_bytes", "0") or 0)
                if previous > 0:
                    disk_percent = min(100.0, max(0.0, total_bytes - previous) / 1_500_000.0)
                self.database.set_background_scan_state("disk_bytes", str(total_bytes))
        except Exception:
            disk_percent = 0.0

        paused = cpu_percent > BACKGROUND_CPU_PAUSE_THRESHOLD or disk_percent > BACKGROUND_DISK_PAUSE_THRESHOLD
        if paused:
            self.logger.info("background scan paused | cpu=%.1f disk=%.1f", cpu_percent, disk_percent)
        return paused
