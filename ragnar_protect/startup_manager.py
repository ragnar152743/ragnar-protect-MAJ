from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path

from .hidden_process import run_hidden


TASK_NAME = "Ragnar Protect Background Protection"


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def build_launch_command() -> str:
    action = build_launch_action()
    executable = _quote_arg(action["execute"])
    arguments = action["arguments"]
    if arguments:
        return f"{executable} {arguments}"
    return executable


def build_launch_action() -> dict[str, str]:
    if getattr(sys, "frozen", False):
        return {
            "execute": str(Path(sys.executable).resolve()),
            "arguments": "--protect --nogui",
        }

    project_root = Path(__file__).resolve().parent.parent
    dist_candidate = project_root / "dist" / "RagnarProtect.exe"
    if dist_candidate.exists():
        return {
            "execute": str(dist_candidate.resolve()),
            "arguments": "--protect --nogui",
        }

    main_path = project_root / "main.py"
    return {
        "execute": str(Path(sys.executable).resolve()),
        "arguments": " ".join(
            [
                _quote_arg(str(main_path.resolve())),
                "--protect",
                "--nogui",
            ]
        ),
    }


def install_startup_task(task_name: str = TASK_NAME) -> dict[str, object]:
    launch_action = build_launch_action()
    launch_command = build_launch_command()
    domain = os.getenv("USERDOMAIN", "")
    username = os.getenv("USERNAME", "")
    user_identity = f"{domain}\\{username}".strip("\\") if username else ""
    powershell_script = f"""
$action = New-ScheduledTaskAction -Execute '{_quote_ps_literal(launch_action["execute"])}' -Argument '{_quote_ps_literal(launch_action["arguments"])}'
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 0) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName '{task_name.replace("'", "''")}' -Action $action -Trigger $trigger -Settings $settings -User '{user_identity.replace("'", "''")}' -RunLevel Highest -Force | Out-Null
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
    return {
        "task_name": task_name,
        "launch_command": launch_command,
        "return_code": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
        "success": completed.returncode == 0,
        "resume_behavior": "Pending sandbox queue and background protection resume on next protected logon.",
    }


def remove_startup_task(task_name: str = TASK_NAME) -> dict[str, object]:
    completed = run_hidden(
        ["schtasks", "/delete", "/tn", task_name, "/f"],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    return {
        "task_name": task_name,
        "return_code": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
        "success": completed.returncode == 0,
    }


def startup_task_exists(task_name: str = TASK_NAME) -> bool:
    completed = run_hidden(
        ["schtasks", "/query", "/tn", task_name],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return completed.returncode == 0


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
