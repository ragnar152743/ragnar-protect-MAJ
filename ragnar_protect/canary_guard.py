from __future__ import annotations

import ctypes
from pathlib import Path

from .config import CANARY_ENABLED, CANARY_FILE_NAMES, CANARY_PROTECTED_DIRS
from .logging_setup import get_logger


FILE_ATTRIBUTE_HIDDEN = 0x2


class CanaryGuard:
    def __init__(self, paths: list[Path] | None = None) -> None:
        self.paths = [path for path in (paths or CANARY_PROTECTED_DIRS) if path.exists()]
        self.logger = get_logger("ragnar_protect.canary")
        self.enabled = CANARY_ENABLED and bool(self.paths)
        self._canary_paths: set[str] = set()

    def ensure_canaries(self) -> list[Path]:
        if not self.enabled:
            return []
        created: list[Path] = []
        self._canary_paths.clear()
        for root in self.paths:
            for file_name in CANARY_FILE_NAMES:
                path = root / file_name
                try:
                    if not path.exists():
                        path.write_text(
                            "Ragnar Protect canary file. Unexpected modification can indicate ransomware activity.\n",
                            encoding="utf-8",
                        )
                    self._hide_file(path)
                    self._canary_paths.add(str(path.resolve()).lower())
                    created.append(path)
                except OSError as exc:
                    self.logger.debug("canary creation failed | %s | %s", path, exc)
        if self._canary_paths:
            self.logger.info("canary guard ready | count=%s", len(self._canary_paths))
        return created

    def list_canary_paths(self) -> list[str]:
        return sorted(self._canary_paths)

    def is_canary_path(self, value: str | Path) -> bool:
        try:
            normalized = str(Path(value).resolve()).lower()
        except OSError:
            normalized = str(Path(value)).lower()
        return normalized in self._canary_paths

    def _hide_file(self, path: Path) -> None:
        if not path.exists():
            return
        try:
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            if kernel32.SetFileAttributesW(str(path), FILE_ATTRIBUTE_HIDDEN) == 0:
                raise OSError("SetFileAttributesW returned 0")
        except Exception:
            return
