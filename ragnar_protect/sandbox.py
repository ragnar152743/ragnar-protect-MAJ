from __future__ import annotations

import json
import re
import shutil
import uuid
from pathlib import Path

from .config import SANDBOX_DIR, TEXT_SCRIPT_EXTENSIONS, ensure_app_dirs
from .hidden_process import run_hidden


class LimitedSandbox:
    def __init__(self) -> None:
        ensure_app_dirs()

    def analyze_script(self, file_path: Path, text: str) -> dict[str, object]:
        report: dict[str, object] = {
            "mode": "static-limited",
            "line_count": len(text.splitlines()),
            "base64_blob_count": len(re.findall(r"[A-Za-z0-9+/=]{80,}", text)),
            "parser_errors": [],
            "temp_copy": "",
        }
        ext = file_path.suffix.lower()
        if ext not in TEXT_SCRIPT_EXTENSIONS or not file_path.exists():
            return report

        sandbox_dir = SANDBOX_DIR / uuid.uuid4().hex
        sandbox_dir.mkdir(parents=True, exist_ok=True)
        temp_copy = sandbox_dir / file_path.name
        shutil.copy2(file_path, temp_copy)
        report["temp_copy"] = str(temp_copy)

        if ext == ".ps1":
            report.update(self._powershell_parse_report(temp_copy))
        return report

    def _powershell_parse_report(self, file_path: Path) -> dict[str, object]:
        ps_file = str(file_path).replace("'", "''")
        command = (
            "$tokens = $null; "
            "$errors = $null; "
            "[System.Management.Automation.Language.Parser]::ParseFile("
            f"'{ps_file}', [ref]$tokens, [ref]$errors"
            ") | Out-Null; "
            "[pscustomobject]@{"
            "TokenCount = @($tokens).Count; "
            "ParseErrorCount = @($errors).Count; "
            "ParseErrors = @($errors | ForEach-Object { $_.Message })"
            "} | ConvertTo-Json -Compress"
        )
        try:
            completed = run_hidden(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-WindowStyle",
                    "Hidden",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    command,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=12,
            )
            if completed.returncode != 0 or not completed.stdout.strip():
                return {"parser_errors": [completed.stderr.strip() or "PowerShell parser failed"]}
            payload = json.loads(completed.stdout)
            return {
                "token_count": payload.get("TokenCount", 0),
                "parse_error_count": payload.get("ParseErrorCount", 0),
                "parser_errors": payload.get("ParseErrors", []) or [],
            }
        except Exception as exc:
            return {"parser_errors": [str(exc)]}
