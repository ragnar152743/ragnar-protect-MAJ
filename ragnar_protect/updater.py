from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import requests

from .hidden_process import popen_hidden
from .config import (
    APP_NAME,
    PACKAGE_ROOT,
    RAGNAR_UPDATE_BRANCH,
    RAGNAR_UPDATE_CHECK_INTERVAL_SECONDS,
    RAGNAR_UPDATE_MANIFEST_PATH,
    RAGNAR_UPDATE_REPOSITORY,
    RAGNAR_UPDATE_TIMEOUT_SECONDS,
    UPDATES_DIR,
    ensure_app_dirs,
)
from .logging_setup import get_logger
from .version import APP_VERSION

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None


class GitHubUpdateManager:
    def __init__(
        self,
        repository: str = RAGNAR_UPDATE_REPOSITORY,
        branch: str = RAGNAR_UPDATE_BRANCH,
        manifest_path: str = RAGNAR_UPDATE_MANIFEST_PATH,
        interval_seconds: int = RAGNAR_UPDATE_CHECK_INTERVAL_SECONDS,
        timeout_seconds: int = RAGNAR_UPDATE_TIMEOUT_SECONDS,
        current_executable_path: Path | None = None,
        session: requests.Session | None = None,
    ) -> None:
        ensure_app_dirs()
        self.repository = repository.strip()
        self.branch = branch.strip() or "main"
        self.manifest_path = manifest_path.strip().lstrip("/") or "manifest.json"
        self.interval_seconds = max(300, int(interval_seconds))
        self.timeout_seconds = max(5, int(timeout_seconds))
        self.current_executable_path = current_executable_path or self._resolve_current_executable()
        self.session = session or requests.Session()
        self.logger = get_logger("ragnar_protect.updater")
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._status_path = UPDATES_DIR / "update_status.json"

    @property
    def available(self) -> bool:
        owner, repo = self._split_repository()
        return bool(owner and repo)

    @property
    def manifest_url(self) -> str:
        owner, repo = self._split_repository()
        if not owner or not repo:
            return ""
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{self.branch}/{self.manifest_path}"

    @property
    def manifest_api_url(self) -> str:
        owner, repo = self._split_repository()
        if not owner or not repo:
            return ""
        return f"https://api.github.com/repos/{owner}/{repo}/contents/{self.manifest_path}?ref={self.branch}"

    def start(self) -> None:
        if not self.available or (self._thread and self._thread.is_alive()):
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, name="RagnarUpdater", daemon=True)
        self._thread.start()
        self.logger.info("github updater started | repo=%s branch=%s", self.repository, self.branch)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.logger.info("github updater stopped")

    def status(self) -> dict[str, object]:
        payload = self._read_status()
        payload.setdefault("repository", self.repository)
        payload.setdefault("branch", self.branch)
        payload.setdefault("manifest_url", self.manifest_url)
        payload.setdefault("manifest_api_url", self.manifest_api_url)
        payload.setdefault("current_version", APP_VERSION)
        payload.setdefault("current_executable", str(self.current_executable_path) if self.current_executable_path else "")
        payload.setdefault("available", self.available)
        payload.setdefault("can_self_update", self.can_self_update_in_place())
        return payload

    def check_now(self, auto_download: bool = True, auto_apply: bool = False) -> dict[str, object]:
        base_status = {
            "available": self.available,
            "repository": self.repository,
            "branch": self.branch,
            "manifest_url": self.manifest_url,
            "manifest_api_url": self.manifest_api_url,
            "current_version": APP_VERSION,
            "current_executable": str(self.current_executable_path) if self.current_executable_path else "",
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        if not self.available:
            status = {
                **base_status,
                "state": "disabled",
                "message": "GitHub update repository not configured.",
            }
            self._write_status(status)
            return status

        try:
            manifest = self._fetch_manifest()
            remote_version = str(manifest["version"])
            remote_sha256 = str(manifest["sha256"]).lower()
            current_sha256 = self._sha256(self.current_executable_path) if self.current_executable_path and self.current_executable_path.exists() else ""
            same_version = remote_version == APP_VERSION
            same_hash = bool(current_sha256) and current_sha256.lower() == remote_sha256

            status = {
                **base_status,
                "state": "up_to_date",
                "message": "Manifest matches the installed executable.",
                "remote_version": remote_version,
                "remote_sha256": remote_sha256,
                "current_sha256": current_sha256,
                "staged_path": "",
                "staged_sha256": "",
                "downloaded": False,
                "apply_started": False,
            }

            if not same_version or not same_hash:
                status["state"] = "update_available"
                status["message"] = "GitHub manifest differs from the installed executable."
                if auto_download:
                    staged_path = self._download_update(manifest)
                    status["state"] = "update_staged"
                    status["message"] = "Update downloaded and staged locally."
                    status["staged_path"] = str(staged_path)
                    status["staged_sha256"] = self._sha256(staged_path)
                    status["downloaded"] = True
                    if auto_apply and self.can_self_update_in_place() and self._is_remote_version_newer(remote_version, APP_VERSION):
                        apply_status = self.apply_staged_update(staged_path=staged_path)
                        status.update(apply_status)
                        status["downloaded"] = True

            self.logger.info(
                "update check complete | state=%s current=%s remote=%s",
                status["state"],
                APP_VERSION,
                status.get("remote_version", ""),
            )
            self._write_status(status)
            return status
        except Exception as exc:
            status = {
                **base_status,
                "state": "error",
                "message": str(exc),
            }
            self.logger.warning("update check failed | %s", exc)
            self._write_status(status)
            return status

    def _loop(self) -> None:
        self.check_now(auto_download=True, auto_apply=self.can_self_update_in_place())
        while not self._stop_event.wait(self.interval_seconds):
            self.check_now(auto_download=True, auto_apply=self.can_self_update_in_place())

    def can_self_update_in_place(self) -> bool:
        if not getattr(sys, "frozen", False):
            return False
        if self.current_executable_path is None or not self.current_executable_path.exists():
            return False
        try:
            return self.current_executable_path.resolve() == Path(sys.executable).resolve()
        except OSError:
            return False

    def apply_staged_update(
        self,
        staged_path: Path | str | None = None,
        restart_commands: list[list[str]] | None = None,
    ) -> dict[str, object]:
        if self.current_executable_path is None or not self.current_executable_path.exists():
            raise FileNotFoundError("Current executable path is unavailable.")
        candidate = Path(staged_path) if staged_path is not None else self._resolve_staged_update_path()
        candidate = candidate.expanduser().resolve()
        if not candidate.exists():
            raise FileNotFoundError(candidate)
        if not self.can_self_update_in_place():
            raise RuntimeError("Background self-update can only be applied from the installed RagnarProtect.exe process.")
        managed_processes = self._collect_managed_processes()
        process_ids = [int(item["pid"]) for item in managed_processes if int(item.get("pid") or 0) > 0]
        restart_specs = restart_commands if restart_commands is not None else self._build_restart_commands(managed_processes)
        script_path, plan_path = self._write_apply_update_bundle(candidate, process_ids, restart_specs)
        process = self._launch_apply_helper(script_path, plan_path)
        status = {
            "state": "update_applying",
            "message": "Background update apply started.",
            "staged_path": str(candidate),
            "staged_sha256": self._sha256(candidate),
            "apply_started": True,
            "apply_pid": process.pid,
            "restart_command_count": len(restart_specs),
            "current_sha256": self._sha256(self.current_executable_path),
            "remote_version": self._version_from_staged_name(candidate),
        }
        self.logger.warning(
            "background update apply started | apply_pid=%s staged=%s targets=%s relaunch=%s",
            process.pid,
            candidate,
            process_ids,
            len(restart_specs),
        )
        self._write_status({**self.status(), **status})
        return status

    def _launch_apply_helper(self, script_path: Path, plan_path: Path):
        return popen_hidden(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
                "-PlanPath",
                str(plan_path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )

    def _fetch_manifest(self) -> dict[str, Any]:
        response = self.session.get(
            self.manifest_api_url,
            headers={
                "User-Agent": "RagnarProtectUpdater/1.0",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "Cache-Control": "no-cache",
            },
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("Invalid manifest payload.")
        if {"version", "sha256", "exe_url"}.issubset(payload.keys()):
            manifest = payload
        else:
            encoded_content = str(payload.get("content") or "").strip()
            encoding = str(payload.get("encoding") or "").strip().lower()
            if not encoded_content or encoding != "base64":
                raise ValueError("GitHub manifest response does not contain base64 content.")
            decoded = base64.b64decode(encoded_content.replace("\n", ""))
            manifest = json.loads(decoded.decode("utf-8"))
            if not isinstance(manifest, dict):
                raise ValueError("Decoded manifest is not a JSON object.")
        required = {"version", "sha256", "exe_url"}
        missing = [key for key in required if not manifest.get(key)]
        if missing:
            raise ValueError(f"Manifest missing required field(s): {', '.join(missing)}")
        return manifest

    def _download_update(self, manifest: dict[str, Any]) -> Path:
        remote_version = str(manifest["version"]).strip()
        remote_sha256 = str(manifest["sha256"]).strip().lower()
        asset_name = str(manifest.get("asset_name") or "RagnarProtect.exe").strip() or "RagnarProtect.exe"
        exe_url = str(manifest["exe_url"]).strip()
        final_name = f"{Path(asset_name).stem}-{remote_version}{Path(asset_name).suffix or '.exe'}"
        final_path = UPDATES_DIR / final_name
        if final_path.exists() and self._sha256(final_path) == remote_sha256:
            return final_path

        temp_path = final_path.with_suffix(final_path.suffix + ".download")
        response = self.session.get(
            exe_url,
            headers={"User-Agent": "RagnarProtectUpdater/1.0"},
            timeout=self.timeout_seconds,
            stream=True,
        )
        response.raise_for_status()

        total_bytes = 0
        import hashlib

        digest = hashlib.sha256()
        with temp_path.open("wb") as handle:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if not chunk:
                    continue
                handle.write(chunk)
                digest.update(chunk)
                total_bytes += len(chunk)

        downloaded_sha256 = digest.hexdigest().lower()
        if downloaded_sha256 != remote_sha256:
            temp_path.unlink(missing_ok=True)
            raise ValueError("Downloaded update hash does not match manifest.")

        expected_size = int(manifest.get("size") or 0)
        if expected_size and total_bytes != expected_size:
            temp_path.unlink(missing_ok=True)
            raise ValueError("Downloaded update size does not match manifest.")

        temp_path.replace(final_path)
        return final_path

    def _resolve_staged_update_path(self) -> Path:
        status = self._read_status()
        staged = str(status.get("staged_path") or "").strip()
        if staged:
            return Path(staged)
        candidates = sorted(UPDATES_DIR.glob("RagnarProtect-*.exe"), key=lambda item: item.stat().st_mtime, reverse=True)
        if not candidates:
            raise FileNotFoundError("No staged update found.")
        return candidates[0]

    def _resolve_current_executable(self) -> Path | None:
        if getattr(sys, "frozen", False):
            return Path(sys.executable).resolve()
        dist_candidate = PACKAGE_ROOT / "dist" / "RagnarProtect.exe"
        if dist_candidate.exists():
            return dist_candidate.resolve()
        return None

    def _split_repository(self) -> tuple[str, str]:
        if "/" not in self.repository:
            return "", ""
        owner, repo = self.repository.split("/", 1)
        return owner.strip(), repo.strip()

    def _collect_managed_processes(self) -> list[dict[str, object]]:
        executable = self.current_executable_path
        if executable is None:
            return []
        executable_text = str(executable).lower()
        managed: list[dict[str, object]] = []
        if psutil is None:
            return [
                {
                    "pid": os.getpid(),
                    "cmdline": [str(executable), *sys.argv[1:]],
                }
            ]
        seen: set[tuple[str, ...]] = set()
        for proc in psutil.process_iter(["pid", "exe", "cmdline"]):
            try:
                exe = str(self._process_info_value(proc, "exe") or proc.exe() or "").lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                continue
            if exe != executable_text:
                continue
            try:
                raw_cmdline = self._process_info_value(proc, "cmdline") or proc.cmdline()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                raw_cmdline = []
            cmdline = [str(item) for item in raw_cmdline if str(item).strip()]
            if not cmdline:
                cmdline = [str(executable)]
            sanitized = tuple(self._sanitize_restart_command(cmdline))
            if sanitized in seen:
                managed.append({"pid": int(proc.pid), "cmdline": list(sanitized)})
                continue
            seen.add(sanitized)
            managed.append({"pid": int(proc.pid), "cmdline": list(sanitized)})
        current = tuple(self._sanitize_restart_command([str(executable), *sys.argv[1:]]))
        if current and current not in seen and self._current_process_matches_executable(executable_text):
            managed.append({"pid": int(os.getpid()), "cmdline": list(current)})
        return managed

    def _current_process_matches_executable(self, executable_text: str) -> bool:
        if not executable_text:
            return False
        if psutil is None:
            return getattr(sys, "frozen", False)
        try:
            current_exe = str(psutil.Process(os.getpid()).exe() or "").lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            return False
        return current_exe == executable_text

    def _build_restart_commands(self, processes: list[dict[str, object]]) -> list[list[str]]:
        commands: list[list[str]] = []
        seen: set[tuple[str, ...]] = set()
        for item in processes:
            raw_cmdline = item.get("cmdline") or []
            if not isinstance(raw_cmdline, list):
                continue
            cmdline = [str(part) for part in raw_cmdline if str(part).strip()]
            if not cmdline:
                continue
            key = tuple(cmdline)
            if key in seen:
                continue
            seen.add(key)
            commands.append(cmdline)
        return commands

    def _sanitize_restart_command(self, cmdline: list[str]) -> list[str]:
        if not cmdline:
            return []
        cleaned = [cmdline[0]]
        skip_next = False
        transient_flags = {"--check-updates", "--update-status", "--apply-update"}
        value_flags = {"--monitor-seconds"}
        for arg in cmdline[1:]:
            lowered = arg.lower()
            if skip_next:
                skip_next = False
                continue
            if lowered in transient_flags:
                continue
            if lowered in value_flags:
                skip_next = True
                continue
            cleaned.append(arg)
        if len(cleaned) == 2 and cleaned[1].lower() == "--nogui":
            return []
        return cleaned

    def _write_apply_update_bundle(
        self,
        staged_path: Path,
        process_ids: list[int],
        restart_commands: list[list[str]],
    ) -> tuple[Path, Path]:
        ensure_app_dirs()
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        plan_path = UPDATES_DIR / f"apply_update_{timestamp}.json"
        script_path = UPDATES_DIR / f"apply_update_{timestamp}.ps1"
        plan = {
            "current_executable": str(self.current_executable_path),
            "staged_executable": str(staged_path),
            "status_path": str(self._status_path),
            "process_ids": process_ids,
            "restart_commands": restart_commands,
            "app_name": APP_NAME,
        }
        plan_path.write_text(json.dumps(plan, ensure_ascii=True, indent=2), encoding="utf-8")
        script_path.write_text(self._build_apply_update_script(), encoding="utf-8")
        return script_path, plan_path

    def _build_apply_update_script(self) -> str:
        return (
            "param([Parameter(Mandatory=$true)][string]$PlanPath)\n"
            "$ErrorActionPreference = 'Stop'\n"
            "$plan = Get-Content -Raw -LiteralPath $PlanPath | ConvertFrom-Json\n"
            "$statusPath = [string]$plan.status_path\n"
            "function Write-Status($state, $message, $extra) {\n"
            "  $payload = [ordered]@{ state = $state; message = $message; updated_at = (Get-Date).ToString('s') }\n"
            "  if ($extra) { foreach ($entry in $extra.GetEnumerator()) { $payload[$entry.Key] = $entry.Value } }\n"
            "  ($payload | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $statusPath -Encoding UTF8\n"
            "}\n"
            "try {\n"
            "  $currentExe = [string]$plan.current_executable\n"
            "  $stagedExe = [string]$plan.staged_executable\n"
            "  $processIds = @($plan.process_ids)\n"
            "  $restartCommands = @($plan.restart_commands)\n"
            "  Write-Status 'update_applying' 'Stopping Ragnar Protect processes.' @{ staged_path = $stagedExe; apply_started = $true }\n"
            "  foreach ($targetPid in $processIds) {\n"
            "    if ($targetPid -and $targetPid -ne $PID) { Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue }\n"
            "  }\n"
            "  $waitIds = @($processIds | Where-Object { $_ -and $_ -ne $PID })\n"
            "  if ($waitIds.Count -gt 0) { Wait-Process -Id $waitIds -Timeout 30 -ErrorAction SilentlyContinue }\n"
            "  $backupExe = \"$currentExe.bak\"\n"
            "  $applied = $false\n"
            "  for ($attempt = 0; $attempt -lt 45 -and -not $applied; $attempt++) {\n"
            "    try {\n"
            "      if (Test-Path -LiteralPath $backupExe) { Remove-Item -LiteralPath $backupExe -Force -ErrorAction SilentlyContinue }\n"
            "      if (Test-Path -LiteralPath $currentExe) { Move-Item -LiteralPath $currentExe -Destination $backupExe -Force }\n"
            "      Move-Item -LiteralPath $stagedExe -Destination $currentExe -Force\n"
            "      Remove-Item -LiteralPath $stagedExe -Force -ErrorAction SilentlyContinue\n"
            "      Remove-Item -LiteralPath $backupExe -Force -ErrorAction SilentlyContinue\n"
            "      $applied = $true\n"
            "    } catch {\n"
            "      Start-Sleep -Seconds 1\n"
            "    }\n"
            "  }\n"
            "  if (-not $applied) {\n"
            "    if ((Test-Path -LiteralPath $backupExe) -and -not (Test-Path -LiteralPath $currentExe)) {\n"
            "      Move-Item -LiteralPath $backupExe -Destination $currentExe -Force -ErrorAction SilentlyContinue\n"
            "    }\n"
            "    Write-Status 'error' 'Background update apply failed.' @{ staged_path = $stagedExe }\n"
            "    exit 1\n"
            "  }\n"
            "  foreach ($command in $restartCommands) {\n"
            "    if (-not $command -or $command.Count -lt 1) { continue }\n"
            "    $args = @()\n"
            "    if ($command.Count -gt 1) { $args = @($command[1..($command.Count - 1)]) }\n"
            "    if ($args -contains '--nogui') {\n"
            "      Start-Process -FilePath $currentExe -ArgumentList $args -WorkingDirectory (Split-Path -Parent $currentExe) -WindowStyle Hidden\n"
            "    } else {\n"
            "      Start-Process -FilePath $currentExe -ArgumentList $args -WorkingDirectory (Split-Path -Parent $currentExe)\n"
            "    }\n"
            "  }\n"
            "  Write-Status 'update_applied' 'Update applied and Ragnar Protect restarted.' @{ staged_path = $stagedExe; restart_command_count = $restartCommands.Count }\n"
            "} catch {\n"
            "  Write-Status 'error' $_.Exception.Message @{ staged_path = [string]$plan.staged_executable }\n"
            "  exit 1\n"
            "}\n"
        )

    def _version_from_staged_name(self, staged_path: Path) -> str:
        name = staged_path.stem
        if "-" not in name:
            return ""
        return name.rsplit("-", 1)[-1]

    def _is_remote_version_newer(self, remote_version: str, current_version: str) -> bool:
        return self._parse_version(remote_version) > self._parse_version(current_version)

    def _parse_version(self, value: str) -> tuple[int, ...]:
        parts: list[int] = []
        for piece in str(value).split("."):
            piece = piece.strip()
            if not piece:
                parts.append(0)
                continue
            try:
                parts.append(int(piece))
            except ValueError:
                numeric = "".join(ch for ch in piece if ch.isdigit())
                parts.append(int(numeric) if numeric else 0)
        return tuple(parts)

    def _read_status(self) -> dict[str, object]:
        try:
            if not self._status_path.exists():
                return {}
            return json.loads(self._status_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def _write_status(self, payload: dict[str, object]) -> None:
        ensure_app_dirs()
        self._status_path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")

    def _process_info_value(self, proc, key: str):
        info = getattr(proc, "info", None)
        if isinstance(info, dict):
            value = info.get(key)
            if value not in (None, "", []):
                return value
        accessor = getattr(proc, key, None)
        if callable(accessor):
            try:
                return accessor()
            except Exception:
                return None
        return accessor

    def _sha256(self, file_path: Path) -> str:
        import hashlib

        digest = hashlib.sha256()
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest().lower()
