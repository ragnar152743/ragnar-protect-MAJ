from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from .hidden_process import run_hidden


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


@lru_cache(maxsize=1024)
def get_signature_status(file_path: str) -> dict[str, str]:
    path = Path(file_path)
    if not path.exists():
        return {"status": "Missing", "status_message": "File not found", "signer_subject": ""}

    command = (
        "$sig = Get-AuthenticodeSignature -LiteralPath "
        f"{_ps_quote(str(path))}; "
        "[pscustomobject]@{"
        "Status = [string]$sig.Status; "
        "StatusMessage = [string]$sig.StatusMessage; "
        "SignerSubject = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Subject } else { '' }; "
        "SignerIssuer = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Issuer } else { '' }; "
        "Thumbprint = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Thumbprint } else { '' }"
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
            return {
                "status": "UnknownError",
                "status_message": completed.stderr.strip() or "Authenticode query failed",
                "signer_subject": "",
                "signer_issuer": "",
                "thumbprint": "",
            }
        payload = json.loads(completed.stdout)
        return {
            "status": payload.get("Status", "Unknown"),
            "status_message": payload.get("StatusMessage", ""),
            "signer_subject": payload.get("SignerSubject", ""),
            "signer_issuer": payload.get("SignerIssuer", ""),
            "thumbprint": payload.get("Thumbprint", ""),
        }
    except Exception as exc:
        return {
            "status": "UnknownError",
            "status_message": str(exc),
            "signer_subject": "",
            "signer_issuer": "",
            "thumbprint": "",
        }
