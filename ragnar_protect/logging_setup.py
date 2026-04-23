from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from typing import Callable

from .config import LOG_DIR, ensure_app_dirs

_record_callbacks: list[Callable[[logging.LogRecord], None]] = []


class _DispatchHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        for callback in list(_record_callbacks):
            try:
                callback(record)
            except Exception:
                continue


def register_log_record_callback(callback: Callable[[logging.LogRecord], None]) -> None:
    for existing in _record_callbacks:
        if existing is callback:
            return
        if getattr(existing, "__self__", None) is getattr(callback, "__self__", object()) and getattr(existing, "__func__", None) is getattr(callback, "__func__", None):
            return
    _record_callbacks.append(callback)


def clear_log_record_callbacks() -> None:
    _record_callbacks.clear()


def get_logger(name: str = "ragnar_protect") -> logging.Logger:
    ensure_app_dirs()
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = RotatingFileHandler(
        LOG_DIR / "ragnar_protect.log",
        maxBytes=1_000_000,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler(stream=sys.stdout)
    stream_handler.setFormatter(formatter)

    dispatch_handler = _DispatchHandler()
    dispatch_handler.setLevel(logging.ERROR)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    logger.addHandler(dispatch_handler)
    logger.propagate = False
    return logger
