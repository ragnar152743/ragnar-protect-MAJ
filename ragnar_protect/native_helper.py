from __future__ import annotations

import json
import subprocess
import threading
from pathlib import Path
from typing import Callable

from .config import NATIVE_HELPER_EXE, PACKAGE_ROOT, SANDBOX_DIR, ensure_app_dirs
from .logging_setup import get_logger


def _candidate_paths() -> list[Path]:
    project_publish = PACKAGE_ROOT / "native_helper" / "publish" / "RagnarNativeHelper.exe"
    project_bin = (
        PACKAGE_ROOT
        / "native_helper"
        / "RagnarNativeHelper"
        / "bin"
        / "Release"
        / "net9.0-windows"
        / "win-x64"
        / "publish"
        / "RagnarNativeHelper.exe"
    )
    return [NATIVE_HELPER_EXE, project_publish, project_bin]


class NativeHelperClient:
    def __init__(self) -> None:
        self.logger = get_logger("ragnar_protect.native")
        self._watch_process: subprocess.Popen[str] | None = None
        self._watch_thread: threading.Thread | None = None

    @property
    def helper_path(self) -> Path | None:
        for candidate in _candidate_paths():
            if candidate.exists():
                return candidate.resolve()
        return None

    @property
    def available(self) -> bool:
        return self.helper_path is not None

    def start_watch(self, callback: Callable[[dict[str, object]], None]) -> bool:
        helper = self.helper_path
        if helper is None:
            self.logger.warning("native helper watch unavailable | helper not found")
            return False
        if self._watch_process is not None and self._watch_process.poll() is None:
            return True
        try:
            process = subprocess.Popen(
                [str(helper), "watch"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="ignore",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError as exc:
            self.logger.warning("native helper watch failed to start | helper=%s error=%s", helper, exc)
            return False
        self._watch_process = process
        self._watch_thread = threading.Thread(
            target=self._watch_loop,
            args=(process, callback),
            name="RagnarNativeWatch",
            daemon=True,
        )
        self._watch_thread.start()
        self.logger.info("native helper watch started | helper=%s pid=%s", helper, process.pid)
        return True

    def stop_watch(self) -> None:
        if self._watch_process is not None and self._watch_process.poll() is None:
            self._watch_process.terminate()
            try:
                self._watch_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._watch_process.kill()
        if self._watch_thread is not None:
            self._watch_thread.join(timeout=5)
        self._watch_process = None
        self._watch_thread = None
        self.logger.info("native helper watch stopped")

    def suspend_process(self, pid: int) -> bool:
        return self._run_pid_command("suspend", pid)

    def resume_process(self, pid: int) -> bool:
        return self._run_pid_command("resume", pid)

    def terminate_process(self, pid: int) -> bool:
        return self._run_pid_command("terminate", pid)

    def run_sandbox(self, sample_path: str | Path, timeout_seconds: int, mode: str = "quick") -> dict[str, object]:
        helper = self.helper_path
        if helper is None:
            return {
                "success": False,
                "backend": "unavailable",
                "verdict": "unknown",
                "error": "native helper unavailable",
                "samplePath": str(sample_path),
            }
        ensure_app_dirs()
        results_root = SANDBOX_DIR / "native-helper"
        results_root.mkdir(parents=True, exist_ok=True)
        completed = subprocess.run(
            [
                str(helper),
                "sandbox",
                "--path",
                str(Path(sample_path).expanduser().resolve()),
                "--timeout",
                str(timeout_seconds),
                "--mode",
                mode,
                "--results",
                str(results_root),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            timeout=max(timeout_seconds + 30, 45),
            check=False,
        )
        payload = (completed.stdout or "").strip() or (completed.stderr or "").strip()
        if not payload:
            return {
                "success": False,
                "backend": "native-helper",
                "verdict": "unknown",
                "error": "empty helper response",
                "samplePath": str(sample_path),
            }
        try:
            decoded = json.loads(payload)
            if isinstance(decoded, dict):
                return decoded
        except json.JSONDecodeError:
            pass
        return {
            "success": False,
            "backend": "native-helper",
            "verdict": "unknown",
            "error": payload,
            "samplePath": str(sample_path),
        }

    def _run_pid_command(self, command: str, pid: int) -> bool:
        helper = self.helper_path
        if helper is None:
            return False
        completed = subprocess.run(
            [str(helper), command, "--pid", str(pid)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            timeout=15,
            check=False,
        )
        return completed.returncode == 0

    def _watch_loop(self, process: subprocess.Popen[str], callback: Callable[[dict[str, object]], None]) -> None:
        assert process.stdout is not None
        for line in process.stdout:
            payload = line.strip()
            if not payload:
                continue
            try:
                decoded = json.loads(payload)
            except json.JSONDecodeError:
                self.logger.warning("native helper emitted invalid json | %s", payload)
                continue
            if isinstance(decoded, dict):
                try:
                    callback(decoded)
                except Exception as exc:
                    self.logger.exception("native watch callback failed | %s", exc)
        stderr_payload = ""
        if process.stderr is not None:
            stderr_payload = process.stderr.read().strip()
        if stderr_payload:
            self.logger.warning("native helper watch stderr | %s", stderr_payload)
