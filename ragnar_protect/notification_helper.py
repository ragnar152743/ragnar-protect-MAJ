from __future__ import annotations

import threading
import time

from .config import LOGO_ICON, TOAST_DEDUP_SECONDS
from .logging_setup import get_logger

try:
    from plyer import notification  # type: ignore
except Exception:  # pragma: no cover
    notification = None  # type: ignore


class ToastNotifier:
    def __init__(self, dedup_seconds: int = TOAST_DEDUP_SECONDS) -> None:
        self.dedup_seconds = max(10, int(dedup_seconds))
        self.logger = get_logger("ragnar_protect.notifications")
        self._recent: dict[tuple[str, str], float] = {}
        self._lock = threading.RLock()

    @property
    def available(self) -> bool:
        return notification is not None

    def handle_scan_result(self, result) -> None:
        if not self.available or result.status == "clean":
            return
        key = (result.status, str(result.path))
        with self._lock:
            expires_at = self._recent.get(key, 0.0)
            if expires_at > time.time():
                return
            self._recent[key] = time.time() + self.dedup_seconds
        title = "Ragnar Protect"
        if result.status == "malicious":
            title = "Ragnar Protect - Malware blocked"
        elif result.status == "suspicious":
            title = "Ragnar Protect - Suspicious file"
        message = f"{result.summary()} | {result.path}"
        try:
            notification.notify(
                title=title,
                message=message[:240],
                app_name="Ragnar Protect",
                app_icon=str(LOGO_ICON) if LOGO_ICON.exists() else "",
                timeout=6,
            )
        except Exception as exc:
            self.logger.debug("toast notification failed | %s | %s", result.path, exc)
