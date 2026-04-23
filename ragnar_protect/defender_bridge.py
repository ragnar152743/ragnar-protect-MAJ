from __future__ import annotations

import ctypes
import os
from functools import lru_cache
from pathlib import Path

from .hidden_process import run_hidden


DEFENDER_OUTPUT_KEYWORDS = (
    "threat",
    "malware",
    "virus",
    "infected",
    "found",
    "detected",
)


class DefenderBridge:
    @property
    def available(self) -> bool:
        return self._is_admin() and self._resolve_mpcmdrun() is not None

    def scan_file(self, file_path: Path, timeout_seconds: int = 120) -> dict[str, object]:
        target = file_path.expanduser().resolve()
        if not self._is_admin():
            return {
                "available": False,
                "path": str(target),
                "is_malware": False,
                "requires_attention": False,
                "engine_path": "",
                "return_code": None,
                "output": "Administrator privileges are required for MpCmdRun custom scans",
            }
        mpcmdrun = self._resolve_mpcmdrun()
        if mpcmdrun is None:
            return {
                "available": False,
                "path": str(target),
                "is_malware": False,
                "requires_attention": False,
                "engine_path": "",
                "return_code": None,
                "output": "MpCmdRun.exe not found",
            }
        if not target.exists():
            return {
                "available": True,
                "path": str(target),
                "is_malware": False,
                "requires_attention": False,
                "engine_path": str(mpcmdrun),
                "return_code": None,
                "output": "Target file not found",
            }

        command = [
            str(mpcmdrun),
            "-Scan",
            "-ScanType",
            "3",
            "-File",
            str(target),
            "-DisableRemediation",
        ]
        try:
            completed = run_hidden(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except Exception as exc:
            return {
                "available": True,
                "path": str(target),
                "is_malware": False,
                "requires_attention": True,
                "engine_path": str(mpcmdrun),
                "return_code": None,
                "output": str(exc),
            }

        output = "\n".join(part for part in (completed.stdout.strip(), completed.stderr.strip()) if part)
        lowered_output = output.lower()
        return_code = int(completed.returncode)
        is_malware = return_code == 2 and any(keyword in lowered_output for keyword in DEFENDER_OUTPUT_KEYWORDS)
        requires_attention = return_code == 2 and not is_malware
        return {
            "available": True,
            "path": str(target),
            "is_malware": is_malware,
            "requires_attention": requires_attention,
            "engine_path": str(mpcmdrun),
            "return_code": return_code,
            "output": output[:4000],
        }

    @lru_cache(maxsize=1)
    def _resolve_mpcmdrun(self) -> Path | None:
        platform_root = Path(os.getenv("ProgramData", r"C:\ProgramData")) / "Microsoft" / "Windows Defender" / "Platform"
        if platform_root.exists():
            versions = sorted(
                [item for item in platform_root.iterdir() if item.is_dir()],
                key=lambda item: item.name,
                reverse=True,
            )
            for version_dir in versions:
                candidate = version_dir / "MpCmdRun.exe"
                if candidate.exists():
                    return candidate

        fallback = Path(os.getenv("ProgramFiles", r"C:\Program Files")) / "Windows Defender" / "MpCmdRun.exe"
        return fallback if fallback.exists() else None

    def _is_admin(self) -> bool:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
