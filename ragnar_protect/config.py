from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path


APP_NAME = "Ragnar Protect"
LOCAL_APPDATA = Path(os.getenv("LOCALAPPDATA", Path.home() / ".ragnar"))
APP_DIR = Path(os.getenv("RAGNAR_APP_DIR", str(LOCAL_APPDATA / "RagnarProtect")))
DB_PATH = APP_DIR / "ragnar_protect.db"
LOG_DIR = APP_DIR / "logs"
QUARANTINE_DIR = APP_DIR / "quarantine"
SANDBOX_DIR = APP_DIR / "sandbox"
REPORTS_DIR = APP_DIR / "reports"
UPDATES_DIR = APP_DIR / "updates"
ERROR_REPORTS_DIR = APP_DIR / "error_reports"
ROLLBACK_DIR = APP_DIR / "rollback"
EXE_SANDBOX_DIR = SANDBOX_DIR / "executables"
RESOURCE_ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
PACKAGE_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = RESOURCE_ROOT / "rules"
YARA_RULES_DIR = RULES_DIR / "yara"
BEHAVIOR_RULES_FILE = RULES_DIR / "behavior_rules.json"
ASSETS_DIR = RESOURCE_ROOT / "assets"
NATIVE_HELPER_DIR = RESOURCE_ROOT / "native_helper"
NATIVE_HELPER_EXE = NATIVE_HELPER_DIR / "RagnarNativeHelper.exe"
LOGO_PNG = ASSETS_DIR / "ragnar_protect_logo.png"
LOGO_ICON = ASSETS_DIR / "ragnar_protect.ico"
WINDOWS_SANDBOX_EXE = Path(r"C:\Windows\System32\WindowsSandbox.exe")
WINDOWS_SANDBOX_CLI = shutil.which("wsb") or ""

DESKTOP_DIR = Path.home() / "Desktop"
DOWNLOADS_DIR = Path.home() / "Downloads"
DOCUMENTS_DIR = Path.home() / "Documents"
TEMP_DIR = Path(tempfile.gettempdir())

DEFAULT_MONITORED_DIRS = [
    DESKTOP_DIR,
    DOWNLOADS_DIR,
    DOCUMENTS_DIR,
    TEMP_DIR,
]
STARTUP_DIRS = [
    Path(os.getenv("APPDATA", str(Path.home()))) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
    Path(os.getenv("ProgramData", "C:\\ProgramData")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp",
]
SENSITIVE_ZONE_PATHS = {
    "Desktop": DESKTOP_DIR,
    "Downloads": DOWNLOADS_DIR,
    "Documents": DOCUMENTS_DIR,
    "Startup": STARTUP_DIRS[0],
    "Temp": TEMP_DIR,
}
BACKGROUND_PRIORITY_ROOTS = [
    *STARTUP_DIRS,
    DOWNLOADS_DIR,
    DESKTOP_DIR,
    TEMP_DIR,
    DOCUMENTS_DIR,
]

SENSITIVE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jse",
    ".wsf",
    ".hta",
    ".msi",
    ".lnk",
}

ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".tar.gz"}
TEXT_SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta"}
PE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr"}
AUTHENTICODE_EXTENSIONS = PE_EXTENSIONS | {".ps1", ".vbs", ".js", ".msi", ".psm1"}
ROLLBACK_PROTECTED_EXTENSIONS = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".csv", ".db",
    ".sql", ".psd", ".zip", ".7z", ".rar", ".odt", ".ods", ".odp", ".xml", ".json",
}

MAX_FILE_SCAN_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_DEPTH = 3
MAX_BASE64_BLOB_LENGTH = 256
ROLLBACK_MAX_FILE_BYTES = 8 * 1024 * 1024
ROLLBACK_MAX_TOTAL_BYTES = 512 * 1024 * 1024

SUSPICIOUS_IMPORTS = {
    "CreateRemoteThread",
    "WriteProcessMemory",
    "VirtualAlloc",
    "VirtualAllocEx",
    "NtWriteVirtualMemory",
    "NtCreateThreadEx",
    "QueueUserAPC",
    "SetWindowsHookExW",
    "SetWindowsHookExA",
}

DOUBLE_EXTENSION_LURES = {
    ".pdf",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".txt",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
}

SUSPICIOUS_PATTERNS = [
    {
        "name": "powershell_encoded_command",
        "score": 45,
        "pattern": r"(?i)(?:powershell|pwsh)(?:\.exe)?\s+.*(?:-enc|-encodedcommand)\s+",
        "description": "PowerShell encoded command execution",
    },
    {
        "name": "memory_injection_api",
        "score": 40,
        "pattern": r"(?i)\b(CreateRemoteThread|VirtualAlloc(?:Ex)?|WriteProcessMemory|NtWriteVirtualMemory|NtCreateThreadEx)\b",
        "description": "Memory injection API reference",
    },
    {
        "name": "download_and_exec",
        "score": 25,
        "pattern": r"(?i)\b(Invoke-WebRequest|DownloadString|WebClient|Start-BitsTransfer|curl(?:\.exe)?|bitsadmin)\b",
        "description": "Downloader behavior",
    },
    {
        "name": "script_exec_chain",
        "score": 20,
        "pattern": r"(?i)\b(IEX|Invoke-Expression|mshta(?:\.exe)?|rundll32(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?)\b",
        "description": "Script execution chain",
    },
    {
        "name": "registry_persistence",
        "score": 30,
        "pattern": r"(?i)(CurrentVersion\\Run(?:Once)?|Winlogon\\Shell|Image File Execution Options|\\RunServices)\b",
        "description": "Persistence registry path",
    },
    {
        "name": "wallpaper_modification",
        "score": 20,
        "pattern": r"(?i)(SystemParametersInfo|Control Panel\\\\Desktop\\\\Wallpaper|HKCU:\\\\Control Panel\\\\Desktop)",
        "description": "Wallpaper modification behavior",
    },
    {
        "name": "dangerous_script_host",
        "score": 25,
        "pattern": r"(?i)\b(Add-Type|Reflection\.Assembly|FromBase64String|EncodedCommand|ScheduledTask|schtasks)\b",
        "description": "Obfuscated or persistence-oriented script behavior",
    },
]

SUSPICIOUS_THRESHOLD = 35
MALICIOUS_THRESHOLD = 80
HIGH_RISK_PROCESS_NAMES = {
    "powershell.exe",
    "pwsh.exe",
    "cscript.exe",
    "wscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "cmd.exe",
    "vssadmin.exe",
    "wbadmin.exe",
    "bcdedit.exe",
    "wevtutil.exe",
    "wmic.exe",
    "diskshadow.exe",
    "cipher.exe",
    "schtasks.exe",
    "reg.exe",
}
USER_SPACE_HINTS = {
    str(Path.home()).lower(),
    str(DOWNLOADS_DIR).lower(),
    str(DESKTOP_DIR).lower(),
    str(DOCUMENTS_DIR).lower(),
    str(TEMP_DIR).lower(),
}

BEHAVIOR_RENAME_THRESHOLD = 25
BEHAVIOR_RENAME_WINDOW_SECONDS = 20
BEHAVIOR_MODIFY_THRESHOLD = 60
BEHAVIOR_MODIFY_WINDOW_SECONDS = 30
BEHAVIOR_CREATE_THRESHOLD = 8
BEHAVIOR_CREATE_WINDOW_SECONDS = 20
BEHAVIOR_SENSITIVE_ZONE_THRESHOLD = 3
BACKGROUND_CPU_PAUSE_THRESHOLD = 65
BACKGROUND_DISK_PAUSE_THRESHOLD = 70
BACKGROUND_BATCH_SIZE = 8
BACKGROUND_IDLE_SECONDS = 2
WATCH_REQUIRED_CLEAN_SCANS = 3
WATCH_AUTO_UNBLOCK_DAYS = 90
SANDBOX_QUEUE_TIMEOUT_SECONDS = 45
LAUNCH_INTERCEPT_INTERVAL_SECONDS = 1
LAUNCH_ALLOW_CACHE_SECONDS = 900
STAGE2_QUICK_TIMEOUT_SECONDS = 6
STAGE5_DEEP_TIMEOUT_SECONDS = 30
LAUNCH_HOLD_TIMEOUT_SECONDS = 45
NATIVE_WATCHER_POLL_MILLISECONDS = 150
NATIVE_WATCHER_STALE_SECONDS = 45
CANARY_ENABLED = os.getenv("RAGNAR_CANARY_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}
CANARY_FILE_NAMES = (
    "RAGNAR_GUARD_DO_NOT_TOUCH.txt",
    "RAGNAR_RECOVERY_CHECK.txt",
)
CANARY_PROTECTED_DIRS = [
    DOCUMENTS_DIR,
    DESKTOP_DIR,
    DOWNLOADS_DIR,
]

RAGNAR_CLOUD_LOOKUP_URL = os.getenv("RAGNAR_CLOUD_LOOKUP_URL", "")
RAGNAR_CLOUD_EVENT_URL = os.getenv("RAGNAR_CLOUD_EVENT_URL", "")
RAGNAR_CLOUD_REQUALIFY_URL = os.getenv("RAGNAR_CLOUD_REQUALIFY_URL", "")
RAGNAR_CLOUD_API_KEY = os.getenv("RAGNAR_CLOUD_API_KEY", "")
RAGNAR_CLOUD_TIMEOUT_SECONDS = int(os.getenv("RAGNAR_CLOUD_TIMEOUT_SECONDS", "8"))
RAGNAR_UPDATE_REPOSITORY = os.getenv("RAGNAR_UPDATE_REPOSITORY", "ragnar152743/ragnar-protect-MAJ")
RAGNAR_UPDATE_BRANCH = os.getenv("RAGNAR_UPDATE_BRANCH", "main")
RAGNAR_UPDATE_MANIFEST_PATH = os.getenv("RAGNAR_UPDATE_MANIFEST_PATH", "manifest.json")
RAGNAR_UPDATE_CHECK_INTERVAL_SECONDS = int(os.getenv("RAGNAR_UPDATE_CHECK_INTERVAL_SECONDS", str(6 * 60 * 60)))
RAGNAR_UPDATE_TIMEOUT_SECONDS = int(os.getenv("RAGNAR_UPDATE_TIMEOUT_SECONDS", "20"))
RAGNAR_RESEND_API_KEY = os.getenv("RAGNAR_RESEND_API_KEY", "")
RAGNAR_ERROR_REPORT_TO = os.getenv("RAGNAR_ERROR_REPORT_TO", "botfeur10@gmail.com")
RAGNAR_ERROR_REPORT_FROM = os.getenv("RAGNAR_ERROR_REPORT_FROM", "Ragnar Protect <onboarding@resend.dev>")
RAGNAR_ERROR_REPORT_TIMEOUT_SECONDS = int(os.getenv("RAGNAR_ERROR_REPORT_TIMEOUT_SECONDS", "20"))
RAGNAR_ERROR_REPORT_LOG_TAIL_LINES = int(os.getenv("RAGNAR_ERROR_REPORT_LOG_TAIL_LINES", "250"))
RAGNAR_ERROR_REPORT_ATTACH_LOG = os.getenv("RAGNAR_ERROR_REPORT_ATTACH_LOG", "1").strip().lower() not in {"0", "false", "no", "off"}


def _frozen_executable_dir() -> Path | None:
    executable = Path(getattr(sys, "executable", ""))
    if getattr(sys, "frozen", False) and executable.exists():
        return executable.resolve().parent
    return None


def get_managed_roots() -> tuple[Path, ...]:
    roots: list[Path] = []
    candidates = [
        APP_DIR,
        PACKAGE_ROOT,
        RESOURCE_ROOT,
        NATIVE_HELPER_DIR,
        RULES_DIR,
        ASSETS_DIR,
    ]
    frozen_dir = _frozen_executable_dir()
    if frozen_dir is not None:
        candidates.append(frozen_dir)
    seen: set[str] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        normalized = str(resolved).lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        roots.append(resolved)
    return tuple(roots)


def is_managed_path(path: str | Path) -> bool:
    try:
        resolved = Path(path).expanduser().resolve()
    except OSError:
        return False
    for root in get_managed_roots():
        try:
            if resolved.is_relative_to(root):
                return True
        except ValueError:
            continue
    return False


def get_resend_api_key_file_candidates() -> list[Path]:
    candidates: list[Path] = []
    env_path = os.getenv("RAGNAR_RESEND_API_KEY_PATH", "").strip()
    if env_path:
        candidates.append(Path(env_path).expanduser())
    frozen_dir = _frozen_executable_dir()
    if frozen_dir is not None:
        candidates.append(frozen_dir / "RagnarProtect.resend_key.txt")
        candidates.append(frozen_dir / "resend_api_key.txt")
    candidates.append(APP_DIR / "resend_api_key.txt")
    return candidates


def load_resend_api_key() -> tuple[str, str]:
    env_key = os.getenv("RAGNAR_RESEND_API_KEY", "").strip()
    if env_key:
        return env_key, "env"
    for candidate in get_resend_api_key_file_candidates():
        try:
            if candidate.exists():
                value = candidate.read_text(encoding="utf-8", errors="ignore").strip()
                if value:
                    return value, str(candidate.resolve())
        except OSError:
            continue
    return "", ""


def ensure_app_dirs() -> None:
    for path in (
        APP_DIR,
        LOG_DIR,
        QUARANTINE_DIR,
        SANDBOX_DIR,
        EXE_SANDBOX_DIR,
        REPORTS_DIR,
        UPDATES_DIR,
        ERROR_REPORTS_DIR,
        ROLLBACK_DIR,
        ASSETS_DIR,
    ):
        path.mkdir(parents=True, exist_ok=True)
