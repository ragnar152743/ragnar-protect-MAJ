from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Sequence

import psutil

from .config import APP_DIR, UPDATES_DIR, WATCHDOG_POLL_SECONDS, WATCHDOG_UPDATE_GRACE_SECONDS, ensure_app_dirs
from .logging_setup import get_logger


LOGGER = get_logger("ragnar_protect.runtime")
BACKGROUND_WORKER_STATE = APP_DIR / "background_worker.json"
WATCHDOG_WORKER_STATE = APP_DIR / "background_watchdog.json"


def build_background_launch_command() -> list[str]:
    if getattr(sys, "frozen", False):
        return [str(Path(sys.executable).resolve()), "--protect", "--nogui", "--allow-reduced-mode"]

    project_root = Path(__file__).resolve().parent.parent
    main_path = project_root / "main.py"
    return [str(Path(sys.executable).resolve()), str(main_path.resolve()), "--protect", "--nogui", "--allow-reduced-mode"]


def build_watchdog_launch_command() -> list[str]:
    if getattr(sys, "frozen", False):
        return [str(Path(sys.executable).resolve()), "--watchdog", "--nogui"]

    project_root = Path(__file__).resolve().parent.parent
    main_path = project_root / "main.py"
    return [str(Path(sys.executable).resolve()), str(main_path.resolve()), "--watchdog", "--nogui"]


def is_background_worker_cmdline(cmdline: Sequence[str] | None) -> bool:
    if not cmdline:
        return False
    lowered = [str(part).strip().lower() for part in cmdline if str(part).strip()]
    if "--protect" not in lowered or "--nogui" not in lowered:
        return False
    if "--gui" in lowered:
        return False
    if "--monitor-seconds" in lowered:
        return False
    return True


def is_watchdog_cmdline(cmdline: Sequence[str] | None) -> bool:
    if not cmdline:
        return False
    lowered = [str(part).strip().lower() for part in cmdline if str(part).strip()]
    if "--watchdog" not in lowered:
        return False
    if "--protect" in lowered:
        return False
    return True


def list_background_workers() -> list[psutil.Process]:
    workers: list[psutil.Process] = []
    seen_pids: set[int] = set()
    current_pid = os.getpid()
    marked_proc = _get_marked_worker_process()
    if marked_proc is not None and marked_proc.pid != current_pid:
        workers.append(marked_proc)
        seen_pids.add(marked_proc.pid)
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            pid = int(_process_info_value(proc, "pid") or 0)
            if pid == current_pid or pid in seen_pids:
                continue
            cmdline = _process_info_value(proc, "cmdline")
            if not cmdline:
                cmdline = proc.cmdline()
            if is_background_worker_cmdline(cmdline):
                workers.append(proc)
                seen_pids.add(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            continue
    return workers


def background_status() -> dict[str, object]:
    workers = list_background_workers()
    return {
        "running": bool(workers),
        "count": len(workers),
        "pids": [proc.pid for proc in workers],
        "commands": [_safe_cmdline(proc) for proc in workers],
    }


def list_watchdog_workers() -> list[psutil.Process]:
    workers: list[psutil.Process] = []
    seen_pids: set[int] = set()
    current_pid = os.getpid()
    marked_proc = _get_marked_process(WATCHDOG_WORKER_STATE)
    if marked_proc is not None and marked_proc.pid != current_pid:
        workers.append(marked_proc)
        seen_pids.add(marked_proc.pid)
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            pid = int(_process_info_value(proc, "pid") or 0)
            if pid == current_pid or pid in seen_pids:
                continue
            cmdline = _process_info_value(proc, "cmdline")
            if not cmdline:
                cmdline = proc.cmdline()
            if is_watchdog_cmdline(cmdline):
                workers.append(proc)
                seen_pids.add(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            continue
    return workers


def watchdog_status() -> dict[str, object]:
    workers = list_watchdog_workers()
    return {
        "running": bool(workers),
        "count": len(workers),
        "pids": [proc.pid for proc in workers],
        "commands": [_safe_cmdline(proc) for proc in workers],
    }


def ensure_background_worker() -> dict[str, object]:
    existing = background_status()
    if existing["running"]:
        return {
            "started": False,
            "already_running": True,
            "pid": None,
            "command": build_background_launch_command(),
            "status": existing,
        }

    command = build_background_launch_command()
    creationflags = 0
    if hasattr(subprocess, "DETACHED_PROCESS"):
        creationflags |= int(subprocess.DETACHED_PROCESS)
    if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
        creationflags |= int(subprocess.CREATE_NEW_PROCESS_GROUP)

    kwargs = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
        "cwd": str(Path(__file__).resolve().parent.parent),
        "creationflags": creationflags,
    }
    if hasattr(subprocess, "STARTUPINFO") and hasattr(subprocess, "STARTF_USESHOWWINDOW") and hasattr(subprocess, "SW_HIDE"):
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        kwargs["startupinfo"] = startupinfo
    process = subprocess.Popen(command, **kwargs)
    LOGGER.info("background worker launched | pid=%s command=%s", process.pid, " ".join(command))
    return {
        "started": True,
        "already_running": False,
        "pid": process.pid,
        "command": command,
        "status": background_status(),
    }


def ensure_watchdog_worker() -> dict[str, object]:
    existing = watchdog_status()
    if existing["running"]:
        return {
            "started": False,
            "already_running": True,
            "pid": None,
            "command": build_watchdog_launch_command(),
            "status": existing,
        }

    command = build_watchdog_launch_command()
    creationflags = 0
    if hasattr(subprocess, "DETACHED_PROCESS"):
        creationflags |= int(subprocess.DETACHED_PROCESS)
    if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
        creationflags |= int(subprocess.CREATE_NEW_PROCESS_GROUP)

    kwargs = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
        "cwd": str(Path(__file__).resolve().parent.parent),
        "creationflags": creationflags,
    }
    if hasattr(subprocess, "STARTUPINFO") and hasattr(subprocess, "STARTF_USESHOWWINDOW") and hasattr(subprocess, "SW_HIDE"):
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        kwargs["startupinfo"] = startupinfo
    process = subprocess.Popen(command, **kwargs)
    LOGGER.info("watchdog worker launched | pid=%s command=%s", process.pid, " ".join(command))
    return {
        "started": True,
        "already_running": False,
        "pid": process.pid,
        "command": command,
        "status": watchdog_status(),
    }


def stop_background_workers() -> dict[str, object]:
    workers = list_background_workers()
    stopped_pids: list[int] = []
    for proc in workers:
        descendants = []
        try:
            descendants = proc.children(recursive=True)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            descendants = []

        for child in reversed(descendants):
            try:
                child.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        try:
            proc.terminate()
            stopped_pids.append(proc.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

        gone, alive = psutil.wait_procs(descendants + [proc], timeout=3)
        for survivor in alive:
            try:
                survivor.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    if stopped_pids:
        LOGGER.info("background worker stopped | pids=%s", stopped_pids)
    unregister_background_worker()
    watchdog_stopped_pids = _stop_processes(list_watchdog_workers())
    unregister_watchdog_worker()
    return {
        "requested": len(workers),
        "stopped_pids": stopped_pids,
        "watchdog_stopped_pids": watchdog_stopped_pids,
        "status": background_status(),
    }


def register_background_worker(reduced_mode: bool = False) -> dict[str, object]:
    ensure_app_dirs()
    payload = {
        "pid": os.getpid(),
        "started_at": time.time(),
        "registered_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "executable": str(Path(sys.executable).resolve()),
        "command": build_background_launch_command(),
        "reduced_mode": reduced_mode,
    }
    BACKGROUND_WORKER_STATE.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
    LOGGER.info("background worker registered | pid=%s reduced_mode=%s", payload["pid"], reduced_mode)
    return payload


def register_watchdog_worker() -> dict[str, object]:
    ensure_app_dirs()
    payload = {
        "pid": os.getpid(),
        "started_at": time.time(),
        "registered_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "executable": str(Path(sys.executable).resolve()),
        "command": build_watchdog_launch_command(),
    }
    WATCHDOG_WORKER_STATE.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
    LOGGER.info("watchdog worker registered | pid=%s", payload["pid"])
    return payload


def unregister_background_worker(expected_pid: int | None = None) -> bool:
    return _unregister_worker_state(BACKGROUND_WORKER_STATE, expected_pid=expected_pid)


def unregister_watchdog_worker(expected_pid: int | None = None) -> bool:
    return _unregister_worker_state(WATCHDOG_WORKER_STATE, expected_pid=expected_pid)


def run_watchdog_loop(poll_seconds: int = WATCHDOG_POLL_SECONDS) -> None:
    register_watchdog_worker()
    last_restart_at = 0.0
    try:
        while True:
            if _update_apply_active():
                time.sleep(max(2, poll_seconds))
                continue
            status = background_status()
            if not status.get("running") and time.time() - last_restart_at >= max(5, poll_seconds):
                ensure_background_worker()
                last_restart_at = time.time()
                LOGGER.warning("watchdog relaunched missing background worker")
            time.sleep(max(2, poll_seconds))
    finally:
        unregister_watchdog_worker(expected_pid=os.getpid())


def _safe_cmdline(proc: psutil.Process) -> str:
    try:
        cmdline = _process_info_value(proc, "cmdline")
        if not cmdline:
            cmdline = proc.cmdline()
        return " ".join(str(part) for part in cmdline)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
        return ""


def _get_marked_worker_process() -> psutil.Process | None:
    return _get_marked_process(BACKGROUND_WORKER_STATE)


def _get_marked_process(state_path: Path) -> psutil.Process | None:
    state = _read_worker_state(state_path)
    if not state:
        return None
    pid = int(state.get("pid") or 0)
    if pid <= 0:
        _unregister_worker_state(state_path)
        return None
    try:
        proc = psutil.Process(pid)
        if not proc.is_running():
            _unregister_worker_state(state_path, expected_pid=pid)
            return None
        expected_executable = str(state.get("executable") or "").lower()
        if expected_executable:
            try:
                actual_executable = str(proc.exe() or "").lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                actual_executable = ""
            if actual_executable and actual_executable != expected_executable:
                _unregister_worker_state(state_path, expected_pid=pid)
                return None
        return proc
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
        _unregister_worker_state(state_path, expected_pid=pid)
        return None


def _read_worker_state(state_path: Path = BACKGROUND_WORKER_STATE) -> dict[str, object]:
    try:
        if not state_path.exists():
            return {}
        return json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _unregister_worker_state(state_path: Path, expected_pid: int | None = None) -> bool:
    state = _read_worker_state(state_path)
    if state and expected_pid is not None and int(state.get("pid") or 0) != expected_pid:
        return False
    try:
        state_path.unlink(missing_ok=True)
    except OSError:
        return False
    if state:
        LOGGER.info("worker state cleared | path=%s pid=%s", state_path.name, state.get("pid"))
    return True


def _stop_processes(workers: list[psutil.Process]) -> list[int]:
    stopped_pids: list[int] = []
    for proc in workers:
        descendants = []
        try:
            descendants = proc.children(recursive=True)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            descendants = []

        for child in reversed(descendants):
            try:
                child.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        try:
            proc.terminate()
            stopped_pids.append(proc.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

        gone, alive = psutil.wait_procs(descendants + [proc], timeout=3)
        for survivor in alive:
            try:
                survivor.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    return stopped_pids


def _update_apply_active() -> bool:
    status_path = UPDATES_DIR / "update_status.json"
    try:
        if not status_path.exists():
            return False
        payload = json.loads(status_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return False
    if str(payload.get("state") or "") != "update_applying":
        return False
    try:
        updated_at = str(payload.get("updated_at") or "")
        if updated_at:
            refreshed = time.mktime(time.strptime(updated_at, "%Y-%m-%dT%H:%M:%S"))
        else:
            refreshed = status_path.stat().st_mtime
    except Exception:
        try:
            refreshed = status_path.stat().st_mtime
        except OSError:
            return False
    return (time.time() - refreshed) <= WATCHDOG_UPDATE_GRACE_SECONDS


def _process_info_value(proc: psutil.Process, key: str):
    info = getattr(proc, "info", None)
    if isinstance(info, dict):
        value = info.get(key)
        if value not in (None, "", []):
            return value
    if key == "pid":
        return getattr(proc, "pid", 0)
    accessor = getattr(proc, key, None)
    if callable(accessor):
        try:
            return accessor()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            return None
    return accessor
