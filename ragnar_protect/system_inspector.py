from __future__ import annotations

import json
import os
import re
import shlex
from pathlib import Path

from .config import (
    ARCHIVE_EXTENSIONS,
    BOOT_PREFLIGHT_MAX_WINDOWS_FILES,
    DEFAULT_MONITORED_DIRS,
    HIGH_RISK_PROCESS_NAMES,
    ROLLBACK_PROTECTED_EXTENSIONS,
    SENSITIVE_EXTENSIONS,
    STARTUP_DIRS,
    TEMP_DIR,
    USER_SPACE_HINTS,
    is_managed_path,
)
from .logging_setup import get_logger
from .scanner import RagnarScanner
from .hidden_process import run_hidden

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None

try:
    import winreg
except Exception:  # pragma: no cover
    winreg = None  # type: ignore


ABSOLUTE_PATH_RE = re.compile(
    r'(?i)([A-Z]:\\[^"\r\n|<>?*]+?\.(?:exe|dll|sys|scr|bat|cmd|ps1|vbs|js|jse|wsf|hta|msi|lnk))'
)


class SystemInspector:
    def __init__(self, scanner: RagnarScanner) -> None:
        self.scanner = scanner
        self.logger = get_logger("ragnar_protect.system")

    @property
    def process_support(self) -> bool:
        return psutil is not None

    def quick_scan(self, max_files_per_dir: int = 40) -> list:
        results = []
        results.extend(self.scan_hotspots(max_files_per_dir=max_files_per_dir))
        results.extend(self.scan_running_processes())
        results.extend(self.scan_startup_entries())
        results.extend(self.scan_scheduled_tasks())
        return results

    def system_audit(self) -> list:
        results = []
        results.extend(self.scan_running_processes())
        results.extend(self.scan_startup_entries())
        results.extend(self.scan_scheduled_tasks())
        return results

    def scan_hotspots(self, max_files_per_dir: int = 40) -> list:
        return self._scan_roots(
            [path for path in [*DEFAULT_MONITORED_DIRS, *STARTUP_DIRS] if path.exists()],
            max_files_per_dir=max_files_per_dir,
        )

    def scan_boot_hotspots(self, max_files_per_dir: int = 40) -> list:
        roots = [
            path
            for path in [*STARTUP_DIRS, *DEFAULT_MONITORED_DIRS]
            if path.exists() and path != TEMP_DIR
        ]
        roots.extend(self._all_profile_hotspot_roots())
        return self._scan_roots(roots, max_files_per_dir=max_files_per_dir)

    def _scan_roots(self, roots: list[Path], max_files_per_dir: int) -> list:
        deduped_roots: list[Path] = []
        seen_roots: set[str] = set()
        for root in roots:
            try:
                normalized = str(root.resolve()).lower()
            except OSError:
                normalized = str(root).lower()
            if normalized in seen_roots:
                continue
            seen_roots.add(normalized)
            deduped_roots.append(root)
        roots = []
        roots.extend(deduped_roots)
        results = []
        for root in roots:
            candidates = sorted(
                self._iter_interesting_files(root, max_depth=2),
                key=lambda item: item.stat().st_mtime if item.exists() else 0,
                reverse=True,
            )[:max_files_per_dir]
            for candidate in candidates:
                try:
                    results.append(self.scanner.scan_file(candidate))
                except Exception as exc:
                    self.logger.exception("hotspot scan failed | %s | %s", candidate, exc)
        return results

    def scan_running_processes(self) -> list:
        if psutil is None:
            return []
        results = []
        scanned_executables: set[str] = set()
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "create_time", "ppid"]):
            artifact_result, executable_result = self._inspect_process(
                proc.info,
                scan_executable=True,
                scanned_executables=scanned_executables,
            )
            if artifact_result is not None:
                results.append(artifact_result)
            if executable_result is not None:
                results.append(executable_result)
        return results

    def scan_startup_entries(self, remediate: bool = False) -> list:
        results = []
        scanned_targets: set[str] = set()
        for entry in self._get_startup_entries():
            command = str(entry.get("command", "")).strip()
            name = str(entry.get("name", "")).strip() or "UnnamedStartup"
            if not command:
                continue
            artifact = self.scanner.scan_artifact(
                display_path=f"startup://{name}",
                content=command,
                extension=".startup",
                metadata={
                    "artifact_type": "startup",
                    "location": entry.get("location", ""),
                    "user": entry.get("user", ""),
                    "name": name,
                },
                persist=True,
                persist_clean=False,
            )
            if artifact.status != "clean":
                results.append(artifact)
                if remediate and artifact.status == "malicious":
                    self._remediate_startup_entry(entry, "malicious startup command artifact")
            for candidate_path in self._extract_candidate_paths(command):
                normalized = str(candidate_path).lower()
                if (
                    normalized in scanned_targets
                    or not candidate_path.exists()
                    or is_managed_path(candidate_path)
                ):
                    continue
                scanned_targets.add(normalized)
                file_result = self.scanner.scan_file(candidate_path)
                if file_result.status != "clean":
                    results.append(file_result)
                if remediate and file_result.status == "malicious":
                    self._remediate_startup_entry(entry, "malicious startup executable")
                    self.scanner.enforce_block_on_existing_file(candidate_path, file_result)
        return results

    def scan_scheduled_tasks(self, remediate: bool = False) -> list:
        results = []
        scanned_targets: set[str] = set()
        for task in self._get_scheduled_tasks():
            execute = str(task.get("execute", "")).strip()
            arguments = str(task.get("arguments", "")).strip()
            if not execute and not arguments:
                continue
            command = f"{execute} {arguments}".strip()
            task_name = f"{task.get('task_path', '')}{task.get('task_name', '')}"
            artifact = self.scanner.scan_artifact(
                display_path=f"task://{task_name}",
                content=command,
                extension=".task",
                metadata={
                    "artifact_type": "scheduled-task",
                    "task_name": task.get("task_name", ""),
                    "task_path": task.get("task_path", ""),
                    "state": task.get("state", ""),
                    "execute": execute,
                    "arguments": arguments,
                },
                persist=True,
                persist_clean=False,
            )
            if artifact.status != "clean":
                results.append(artifact)
                if remediate and artifact.status == "malicious":
                    self._remediate_scheduled_task(task, "malicious scheduled task artifact")
            for candidate_path in self._extract_candidate_paths(command):
                normalized = str(candidate_path).lower()
                if (
                    normalized in scanned_targets
                    or not candidate_path.exists()
                    or is_managed_path(candidate_path)
                ):
                    continue
                scanned_targets.add(normalized)
                file_result = self.scanner.scan_file(candidate_path)
                if file_result.status != "clean":
                    results.append(file_result)
                if remediate and file_result.status == "malicious":
                    self._remediate_scheduled_task(task, "malicious scheduled task executable")
                    self.scanner.enforce_block_on_existing_file(candidate_path, file_result)
        return results

    def scan_windows_boot_surface(self, max_files: int = BOOT_PREFLIGHT_MAX_WINDOWS_FILES) -> list:
        system_root = Path(os.getenv("SystemRoot", r"C:\Windows"))
        roots = [
            system_root / "System32" / "Tasks",
            system_root / "System32" / "drivers",
            system_root / "System32",
            system_root / "SysWOW64",
        ]
        candidates: list[Path] = []
        seen: set[str] = set()
        for root in roots:
            if not root.exists():
                continue
            for candidate in self._iter_interesting_files(root, max_depth=2):
                try:
                    normalized = str(candidate.resolve()).lower()
                except OSError:
                    continue
                if normalized in seen:
                    continue
                seen.add(normalized)
                candidates.append(candidate)
        candidates = sorted(
            candidates,
            key=lambda item: item.stat().st_mtime if item.exists() else 0,
            reverse=True,
        )[:max_files]
        results = []
        for candidate in candidates:
            try:
                results.append(self.scanner.scan_file(candidate))
            except Exception as exc:
                self.logger.exception("windows boot surface scan failed | %s | %s", candidate, exc)
        return results

    def _inspect_process(
        self,
        info: dict[str, object],
        scan_executable: bool,
        scanned_executables: set[str],
    ) -> tuple[object | None, object | None]:
        pid = info.get("pid")
        name = str(info.get("name") or "")
        exe = str(info.get("exe") or "")
        cmdline_list = info.get("cmdline") or []
        try:
            cmdline_text = " ".join(str(part) for part in cmdline_list if part)
        except Exception:
            cmdline_text = ""
        if "__PSScriptPolicyTest_" in cmdline_text:
            return None, None
        if not cmdline_text and not exe:
            return None, None

        artifact_result = self.scanner.scan_artifact(
            display_path=f"process://{pid}/{name or 'unknown'}",
            content=f"{name} {cmdline_text}".strip() or exe,
            extension=".cmdline",
            metadata={
                "artifact_type": "process",
                "pid": pid,
                "process_name": name,
                "exe": exe,
                "ppid": info.get("ppid"),
                "create_time": info.get("create_time"),
            },
            persist=True,
            persist_clean=False,
        )

        executable_result = None
        if (
            scan_executable
            and artifact_result.status != "clean"
            and exe
            and self._is_user_space_path(exe)
            and not is_managed_path(exe)
            and str(exe).lower() not in scanned_executables
        ):
            scanned_executables.add(str(exe).lower())
            candidate = Path(exe)
            if candidate.exists():
                executable_result = self.scanner.scan_file(candidate)

        return (artifact_result if artifact_result.status != "clean" else None, executable_result)

    def _get_startup_entries(self) -> list[dict[str, object]]:
        command = (
            "Get-CimInstance Win32_StartupCommand | "
            "Select-Object Name, Command, Location, User | ConvertTo-Json -Compress"
        )
        items = self._run_powershell_json(command)
        if items:
            normalized = []
            for item in items:
                normalized.append(
                    {
                        "name": item.get("Name", ""),
                        "command": item.get("Command", ""),
                        "location": item.get("Location", ""),
                        "user": item.get("User", ""),
                    }
                )
            return normalized
        return self._registry_startup_entries()

    def _registry_startup_entries(self) -> list[dict[str, object]]:
        if winreg is None:
            return []
        locations = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
        ]
        items = []
        for hive, subkey, location in locations:
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    count = winreg.QueryInfoKey(key)[1]
                    for index in range(count):
                        name, value, _ = winreg.EnumValue(key, index)
                        items.append(
                            {
                                "name": name,
                                "command": str(value),
                                "location": location,
                                "user": "current-machine" if hive == winreg.HKEY_LOCAL_MACHINE else "current-user",
                            }
                        )
            except OSError:
                continue
        return items

    def _remediate_startup_entry(self, entry: dict[str, object], reason: str) -> None:
        name = str(entry.get("name", "")).strip()
        if not name:
            return
        locations = [
            (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
            (r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
            (r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
            (r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
        ]
        location_hint = str(entry.get("location", "")).strip()
        removed = False
        for registry_path, label in locations:
            if location_hint and label not in location_hint and registry_path not in location_hint:
                continue
            completed = run_hidden(
                ["reg.exe", "delete", registry_path, "/v", name, "/f"],
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
            )
            if completed.returncode == 0:
                removed = True
        if removed:
            self.logger.warning("startup entry removed | name=%s reason=%s", name, reason)

    def _remediate_scheduled_task(self, task: dict[str, object], reason: str) -> None:
        task_name = str(task.get("task_name", "")).strip()
        task_path = str(task.get("task_path", "")).strip()
        if not task_name:
            return
        full_name = f"{task_path}{task_name}" if task_path else task_name
        completed = run_hidden(
            ["schtasks", "/change", "/tn", full_name, "/disable"],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        if completed.returncode == 0:
            self.logger.warning("scheduled task disabled | task=%s reason=%s", full_name, reason)

    def _get_scheduled_tasks(self) -> list[dict[str, object]]:
        command = (
            "Get-ScheduledTask | ForEach-Object { "
            "$task = $_; "
            "foreach ($action in $task.Actions) { "
            "if ($action.Execute) { "
            "[pscustomobject]@{ "
            "TaskName = $task.TaskName; "
            "TaskPath = $task.TaskPath; "
            "State = [string]$task.State; "
            "Execute = [string]$action.Execute; "
            "Arguments = [string]$action.Arguments; "
            "WorkingDirectory = [string]$action.WorkingDirectory "
            "} "
            "} "
            "} "
            "} | ConvertTo-Json -Compress -Depth 4"
        )
        items = self._run_powershell_json(command)
        normalized = []
        for item in items:
            normalized.append(
                {
                    "task_name": item.get("TaskName", ""),
                    "task_path": item.get("TaskPath", ""),
                    "state": item.get("State", ""),
                    "execute": item.get("Execute", ""),
                    "arguments": item.get("Arguments", ""),
                    "working_directory": item.get("WorkingDirectory", ""),
                }
            )
        return normalized

    def _run_powershell_json(self, command: str) -> list[dict[str, object]]:
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
                timeout=30,
            )
            if completed.returncode != 0 or not completed.stdout.strip():
                return []
            payload = json.loads(completed.stdout)
            if isinstance(payload, list):
                return [item for item in payload if isinstance(item, dict)]
            if isinstance(payload, dict):
                return [payload]
            return []
        except Exception as exc:
            self.logger.debug("powershell json query failed: %s", exc)
            return []

    def _iter_interesting_files(self, root: Path, max_depth: int):
        stack: list[tuple[Path, int]] = [(root, 0)]
        while stack:
            current, depth = stack.pop()
            try:
                entries = list(current.iterdir())
            except OSError:
                continue
            for entry in entries:
                if entry.is_dir() and depth < max_depth:
                    stack.append((entry, depth + 1))
                    continue
                if entry.is_file() and self._is_interesting_file(entry):
                    yield entry

    def _is_interesting_file(self, path: Path) -> bool:
        if is_managed_path(path):
            return False
        extension = path.suffix.lower()
        if extension in SENSITIVE_EXTENSIONS or extension in ARCHIVE_EXTENSIONS or extension in ROLLBACK_PROTECTED_EXTENSIONS:
            return True
        if extension in {".com", ".cpl", ".ocx", ".job", ".efi"}:
            return True
        lowered_parts = [part.lower() for part in path.parts]
        if "system32" in lowered_parts and "tasks" in lowered_parts and not extension:
            return True
        return False

    def _all_profile_hotspot_roots(self) -> list[Path]:
        profiles_root = Path(os.getenv("SystemDrive", "C:")) / "Users"
        if not profiles_root.exists():
            return []
        roots: list[Path] = []
        ignored = {"default", "default user", "all users"}
        for profile in profiles_root.iterdir():
            if not profile.is_dir():
                continue
            lowered = profile.name.lower()
            if lowered in ignored or lowered.startswith("default"):
                continue
            candidates = [
                profile / "Desktop",
                profile / "Downloads",
                profile / "Documents",
                profile / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
            ]
            for candidate in candidates:
                if candidate.exists():
                    roots.append(candidate)
        return roots

    def _extract_candidate_paths(self, command: str) -> list[Path]:
        expanded = os.path.expandvars(command.strip().strip('"'))
        candidates: list[Path] = []

        try:
            split = shlex.split(expanded, posix=False)
            if split:
                token = split[0].strip('"')
                maybe_path = Path(token)
                if maybe_path.suffix.lower() in SENSITIVE_EXTENSIONS and maybe_path.drive:
                    candidates.append(maybe_path)
        except ValueError:
            pass

        for match in ABSOLUTE_PATH_RE.findall(expanded):
            candidates.append(Path(match))

        deduped = []
        seen: set[str] = set()
        for candidate in candidates:
            normalized = str(candidate).lower()
            if normalized in seen:
                continue
            seen.add(normalized)
            deduped.append(candidate)
        return deduped

    def _is_user_space_path(self, value: str) -> bool:
        normalized = str(Path(value)).lower()
        return any(normalized.startswith(prefix) for prefix in USER_SPACE_HINTS)
