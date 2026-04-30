from __future__ import annotations

import threading
import time
from pathlib import Path

from .config import CANARY_FILE_NAMES, DEFAULT_MONITORED_DIRS, OFFICE_DOCUMENT_EXTENSIONS, SENSITIVE_EXTENSIONS, is_managed_path
from .logging_setup import get_logger
from .scanner import RagnarScanner

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except Exception:  # pragma: no cover
    FileSystemEventHandler = object  # type: ignore
    Observer = None  # type: ignore


class RagnarEventHandler(FileSystemEventHandler):
    def __init__(
        self,
        scanner: RagnarScanner,
        event_callback=None,
        logger_name: str = "ragnar_protect.monitor",
    ) -> None:
        self.scanner = scanner
        self.event_callback = event_callback
        self.logger = get_logger(logger_name)
        self._recent: dict[str, float] = {}

    def on_created(self, event) -> None:  # type: ignore[override]
        self._notify("created", event.src_path, is_directory=event.is_directory)
        self._scan_candidate(event.src_path, is_directory=event.is_directory)

    def on_modified(self, event) -> None:  # type: ignore[override]
        self._notify("modified", event.src_path, is_directory=event.is_directory)
        self._scan_candidate(event.src_path, is_directory=event.is_directory)

    def on_moved(self, event) -> None:  # type: ignore[override]
        self._notify("moved", event.src_path, dest_path=getattr(event, "dest_path", None), is_directory=event.is_directory)
        self._scan_candidate(getattr(event, "dest_path", event.src_path), is_directory=event.is_directory)

    def on_deleted(self, event) -> None:  # type: ignore[override]
        self._notify("deleted", event.src_path, is_directory=event.is_directory)

    def _notify(self, event_type: str, src_path: str, dest_path: str | None = None, is_directory: bool = False) -> None:
        if self.event_callback is None:
            return
        try:
            self.event_callback(event_type=event_type, path=src_path, dest_path=dest_path, is_directory=is_directory)
        except Exception as exc:
            self.logger.debug("event callback failed | %s | %s", src_path, exc)

    def _scan_candidate(self, src_path: str, is_directory: bool) -> None:
        if is_directory:
            return
        path = Path(src_path)
        try:
            if is_managed_path(path):
                return
        except (OSError, RuntimeError):
            return
        if path.name.startswith("__PSScriptPolicyTest_"):
            return
        if path.suffix.lower() not in (SENSITIVE_EXTENSIONS | OFFICE_DOCUMENT_EXTENSIONS) and path.suffix.lower() not in {".zip", ".tar", ".gz"}:
            return
        now = time.time()
        if now - self._recent.get(src_path, 0) < 2:
            return
        self._recent[src_path] = now
        try:
            self.scanner.scan_file(path)
            self.logger.info("realtime scan | %s", src_path)
        except FileNotFoundError:
            self.logger.info("realtime scan skipped vanished file | %s", src_path)
        except Exception as exc:
            self.logger.exception("realtime scan failed | %s | %s", src_path, exc)


class FileSystemMonitor:
    def __init__(self, scanner: RagnarScanner, paths: list[Path] | None = None, event_callback=None) -> None:
        self.scanner = scanner
        self.paths = [path for path in (paths or DEFAULT_MONITORED_DIRS) if path.exists()]
        self.event_callback = event_callback
        self.logger = get_logger("ragnar_protect.monitor")
        self._observer = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    @property
    def available(self) -> bool:
        return Observer is not None and bool(self.paths)

    def start(self) -> None:
        if self.available:
            self._start_watchdog()
        elif self.paths and (self._thread is None or not self._thread.is_alive()):
            self._start_polling()

    def stop(self) -> None:
        self._stop_event.set()
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        self.logger.info("filesystem monitor stopped")

    def _start_watchdog(self) -> None:
        if self._observer is not None:
            return
        handler = RagnarEventHandler(self.scanner, event_callback=self.event_callback)
        observer = Observer()
        for path in self.paths:
            observer.schedule(handler, str(path), recursive=True)
        observer.daemon = True
        observer.start()
        self._observer = observer
        self.logger.info("filesystem monitor started with watchdog")

    def _start_polling(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._poll_loop, name="RagnarPollingMonitor", daemon=True)
        self._thread.start()
        self.logger.info("filesystem monitor started with polling")

    def _poll_loop(self) -> None:
        snapshot: dict[str, float] = {}
        while not self._stop_event.is_set():
            seen_paths: set[str] = set()
            for root in self.paths:
                for path in root.rglob("*"):
                    if not path.is_file():
                        continue
                    if is_managed_path(path):
                        continue
                    if path.suffix.lower() not in (SENSITIVE_EXTENSIONS | OFFICE_DOCUMENT_EXTENSIONS) and path.suffix.lower() not in {".zip", ".tar", ".gz"} and path.name not in CANARY_FILE_NAMES:
                        continue
                    seen_paths.add(str(path))
                    try:
                        mtime = path.stat().st_mtime
                    except OSError:
                        continue
                    previous = snapshot.get(str(path))
                    if previous is None or previous != mtime:
                        snapshot[str(path)] = mtime
                        if self.event_callback is not None:
                            try:
                                self.event_callback(
                                    event_type="modified" if previous is not None else "created",
                                    path=str(path),
                                    dest_path=None,
                                    is_directory=False,
                                )
                            except Exception:
                                pass
                        if path.suffix.lower() in (SENSITIVE_EXTENSIONS | OFFICE_DOCUMENT_EXTENSIONS) or path.suffix.lower() in {".zip", ".tar", ".gz"}:
                            try:
                                self.scanner.scan_file(path)
                            except Exception:
                                continue
            deleted_paths = [value for value in snapshot.keys() if value not in seen_paths]
            for deleted_path in deleted_paths:
                snapshot.pop(deleted_path, None)
                if self.event_callback is not None:
                    try:
                        self.event_callback(
                            event_type="deleted",
                            path=deleted_path,
                            dest_path=None,
                            is_directory=False,
                        )
                    except Exception:
                        pass
            self._stop_event.wait(5)
