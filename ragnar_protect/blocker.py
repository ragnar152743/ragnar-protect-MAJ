from __future__ import annotations

import hashlib
import threading
from pathlib import Path

from .database import Database
from .logging_setup import get_logger

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None


class ProcessBlocker:
    def __init__(self, database: Database, interval_seconds: int = 2) -> None:
        self.database = database
        self.interval_seconds = interval_seconds
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._hash_cache: dict[str, tuple[float, int, str]] = {}
        self.logger = get_logger("ragnar_protect.blocker")

    @property
    def available(self) -> bool:
        return psutil is not None

    def start(self) -> None:
        if not self.available or self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, name="RagnarProcessBlocker", daemon=True)
        self._thread.start()
        self.logger.info("process blocker started")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.logger.info("process blocker stopped")

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._enforce_blocklist()
            except Exception as exc:
                self.logger.exception("blocker loop error: %s", exc)
            self._stop_event.wait(self.interval_seconds)

    def _enforce_blocklist(self) -> None:
        blocklist = self.database.get_active_blocklist()
        if not blocklist:
            return
        blocked_paths = {Path(item["path"]).as_posix().lower(): item for item in blocklist}
        blocked_hashes = {item["sha256"].lower(): item for item in blocklist}

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            exe = proc.info.get("exe")
            if not exe:
                continue
            normalized = Path(exe).as_posix().lower()
            item = blocked_paths.get(normalized)
            file_hash = None
            if item is None:
                file_hash = self._cached_sha256(Path(exe))
                item = blocked_hashes.get(file_hash.lower()) if file_hash else None
            if item is None:
                continue
            try:
                self._terminate_process_tree(proc)
            except Exception:
                continue
            self.database.record_block_event(
                pid=proc.info.get("pid"),
                process_name=proc.info.get("name"),
                exe_path=exe,
                sha256=file_hash or item["sha256"],
                reason=item["reason"],
            )
            self.logger.warning("blocked process | pid=%s exe=%s", proc.info.get("pid"), exe)

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

    def _cached_sha256(self, file_path: Path) -> str | None:
        try:
            stat = file_path.stat()
        except OSError:
            return None
        cache_key = str(file_path)
        cached = self._hash_cache.get(cache_key)
        signature = (stat.st_mtime, stat.st_size)
        if cached and cached[:2] == signature:
            return cached[2]
        digest = hashlib.sha256()
        try:
            with file_path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(chunk)
        except OSError:
            return None
        value = digest.hexdigest()
        self._hash_cache[cache_key] = (stat.st_mtime, stat.st_size, value)
        return value
