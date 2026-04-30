from __future__ import annotations

import subprocess
from typing import Any


def _apply_hidden_windows_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    merged = dict(kwargs)

    startupinfo = merged.get("startupinfo")
    if startupinfo is None and hasattr(subprocess, "STARTUPINFO"):
        startupinfo = subprocess.STARTUPINFO()

    if startupinfo is not None and hasattr(subprocess, "STARTF_USESHOWWINDOW") and hasattr(subprocess, "SW_HIDE"):
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        merged["startupinfo"] = startupinfo

    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        merged["creationflags"] = int(merged.get("creationflags", 0)) | int(subprocess.CREATE_NO_WINDOW)

    if merged.get("text") and "errors" not in merged:
        # Avoid background reader crashes on locale-specific undecodable bytes.
        merged["errors"] = "ignore"

    return merged


def run_hidden(*popenargs: Any, **kwargs: Any):
    return subprocess.run(*popenargs, **_apply_hidden_windows_kwargs(kwargs))


def popen_hidden(*popenargs: Any, **kwargs: Any):
    return subprocess.Popen(*popenargs, **_apply_hidden_windows_kwargs(kwargs))
