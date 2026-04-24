from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path

from .config import APP_DIR, SHARED_APP_DIR_HINT
from .hidden_process import run_hidden


TASK_NAME = "Ragnar Protect Background Protection"
EARLY_TASK_NAME = "Ragnar Protect Early Boot Protection"
TASK_NAMES = (TASK_NAME, EARLY_TASK_NAME)


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def build_launch_command() -> str:
    action = build_launch_action(mode="protect")
    executable = _quote_arg(action["execute"])
    arguments = action["arguments"]
    if arguments:
        return f"{executable} {arguments}"
    return executable


def build_launch_action(mode: str = "protect") -> dict[str, str]:
    arguments = "--protect --nogui" if mode != "boot-preflight" else "--boot-preflight --nogui"
    if getattr(sys, "frozen", False):
        return {
            "execute": str(Path(sys.executable).resolve()),
            "arguments": arguments,
        }

    project_root = Path(__file__).resolve().parent.parent
    dist_candidate = project_root / "dist" / "RagnarProtect.exe"
    if dist_candidate.exists():
        return {
            "execute": str(dist_candidate.resolve()),
            "arguments": arguments,
        }

    main_path = project_root / "main.py"
    return {
        "execute": str(Path(sys.executable).resolve()),
        "arguments": " ".join(
            [
                _quote_arg(str(main_path.resolve())),
                "--protect" if mode != "boot-preflight" else "--boot-preflight",
                "--nogui",
            ]
        ),
    }


def install_startup_task(task_name: str = TASK_NAME, early_task_name: str = EARLY_TASK_NAME) -> dict[str, object]:
    launch_action = build_launch_action(mode="protect")
    early_launch_action = build_launch_action(mode="boot-preflight")
    launch_command = build_launch_command()
    domain = os.getenv("USERDOMAIN", "")
    username = os.getenv("USERNAME", "")
    user_identity = f"{domain}\\{username}".strip("\\") if username else ""
    powershell_script = f"""
$action = New-ScheduledTaskAction -Execute '{_quote_ps_literal(launch_action["execute"])}' -Argument '{_quote_ps_literal(launch_action["arguments"])}'
$bootAction = New-ScheduledTaskAction -Execute '{_quote_ps_literal(early_launch_action["execute"])}' -Argument '{_quote_ps_literal(early_launch_action["arguments"])}'
$logonTrigger = New-ScheduledTaskTrigger -AtLogOn
$startupTrigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 0) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
$logonPrincipal = New-ScheduledTaskPrincipal -UserId '{user_identity.replace("'", "''")}' -RunLevel Highest
$startupPrincipal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName '{task_name.replace("'", "''")}' -Action $action -Trigger $logonTrigger -Settings $settings -Principal $logonPrincipal -Force | Out-Null
Register-ScheduledTask -TaskName '{early_task_name.replace("'", "''")}' -Action $bootAction -Trigger $startupTrigger -Settings $settings -Principal $startupPrincipal -Force | Out-Null
"""
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
            powershell_script,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    success = completed.returncode == 0
    if success:
        try:
            SHARED_APP_DIR_HINT.parent.mkdir(parents=True, exist_ok=True)
            SHARED_APP_DIR_HINT.write_text(str(APP_DIR.resolve()), encoding="utf-8")
        except OSError:
            pass
    return {
        "task_name": task_name,
        "early_task_name": early_task_name,
        "task_names": [task_name, early_task_name],
        "launch_command": launch_command,
        "early_launch_command": f"{_quote_arg(early_launch_action['execute'])} {early_launch_action['arguments']}",
        "return_code": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
        "shared_app_dir": str(APP_DIR.resolve()),
        "shared_app_dir_hint": str(SHARED_APP_DIR_HINT),
        "success": success,
        "resume_behavior": "Pending sandbox queue and background protection resume on next startup or protected logon.",
    }


def remove_startup_task(task_name: str = TASK_NAME, early_task_name: str = EARLY_TASK_NAME) -> dict[str, object]:
    outputs: list[str] = []
    errors: list[str] = []
    success = True
    return_code = 0
    for current_task in (task_name, early_task_name):
        completed = run_hidden(
            ["schtasks", "/delete", "/tn", current_task, "/f"],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        if completed.stdout.strip():
            outputs.append(completed.stdout.strip())
        if completed.stderr.strip():
            errors.append(completed.stderr.strip())
        if completed.returncode not in {0, 1}:
            success = False
            return_code = completed.returncode
    return {
        "task_name": task_name,
        "early_task_name": early_task_name,
        "task_names": [task_name, early_task_name],
        "return_code": return_code,
        "stdout": "\n".join(outputs).strip(),
        "stderr": "\n".join(errors).strip(),
        "success": success,
    }


def startup_task_exists(task_name: str = TASK_NAME, early_task_name: str = EARLY_TASK_NAME) -> bool:
    for current_task in (task_name, early_task_name):
        completed = run_hidden(
            ["schtasks", "/query", "/tn", current_task],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if completed.returncode != 0:
            return False
    return True


def relaunch_as_admin(extra_args: list[str]) -> bool:
    if is_admin():
        return True

    if getattr(sys, "frozen", False):
        executable = str(Path(sys.executable).resolve())
        parameters = " ".join(_quote_arg(arg) for arg in extra_args)
    else:
        executable = str(Path(sys.executable).resolve())
        main_path = Path(__file__).resolve().parent.parent / "main.py"
        parameters = " ".join([_quote_arg(str(main_path.resolve()))] + [_quote_arg(arg) for arg in extra_args])

    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, parameters, os.getcwd(), 1)
    return int(result) > 32


def _quote_arg(value: str) -> str:
    escaped = value.replace('"', '\\"')
    return f'"{escaped}"'


def _quote_ps_literal(value: str) -> str:
    return value.replace("'", "''")
