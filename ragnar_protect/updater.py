from __future__ import annotations

import base64
import json
import sys
import threading
import time
from pathlib import Path
from typing import Any

import requests

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
        return payload

    def check_now(self, auto_download: bool = True) -> dict[str, object]:
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
        self.check_now(auto_download=True)
        while not self._stop_event.wait(self.interval_seconds):
            self.check_now(auto_download=True)

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

    def _sha256(self, file_path: Path) -> str:
        import hashlib

        digest = hashlib.sha256()
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest().lower()
