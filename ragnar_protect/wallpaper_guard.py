from __future__ import annotations

import threading
from pathlib import Path

from .database import Database
from .logging_setup import get_logger

try:
    import winreg
except Exception:  # pragma: no cover
    winreg = None  # type: ignore


class WallpaperGuard:
    def __init__(self, database: Database, interval_seconds: int = 5) -> None:
        self.database = database
        self.interval_seconds = interval_seconds
        self.logger = get_logger("ragnar_protect.wallpaper")
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._last_wallpaper = self._read_wallpaper()

    @property
    def available(self) -> bool:
        return winreg is not None

    def start(self) -> None:
        if not self.available or self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, name="RagnarWallpaperGuard", daemon=True)
        self._thread.start()
        self.logger.info("wallpaper guard started")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.logger.info("wallpaper guard stopped")

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            current = self._read_wallpaper()
            if current != self._last_wallpaper:
                details = f"Wallpaper changed from {self._last_wallpaper or '<none>'} to {current or '<none>'}"
                self.database.record_wallpaper_event(current, details)
                self.logger.warning(details)
                self._last_wallpaper = current
            self._stop_event.wait(self.interval_seconds)

    def _read_wallpaper(self) -> str | None:
        if winreg is None:
            return None
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop") as key:
                value, _ = winreg.QueryValueEx(key, "Wallpaper")
                path = Path(value)
                return str(path) if value else None
        except OSError:
            return None
