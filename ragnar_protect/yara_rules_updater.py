from __future__ import annotations

import io
import json
import shutil
import threading
import time
import zipfile
from pathlib import Path
from typing import Any

import requests

from .config import COMMUNITY_YARA_RULES_DIR, RAGNAR_YARA_COMMUNITY_REPOSITORY, RAGNAR_YARA_COMMUNITY_TIMEOUT_SECONDS, RAGNAR_YARA_COMMUNITY_UPDATE_INTERVAL_SECONDS, UPDATES_DIR, ensure_app_dirs
from .logging_setup import get_logger


class CommunityYaraRulesUpdater:
    def __init__(
        self,
        yara_scanner,
        repository: str = RAGNAR_YARA_COMMUNITY_REPOSITORY,
        timeout_seconds: int = RAGNAR_YARA_COMMUNITY_TIMEOUT_SECONDS,
        interval_seconds: int = RAGNAR_YARA_COMMUNITY_UPDATE_INTERVAL_SECONDS,
        session: requests.Session | None = None,
    ) -> None:
        ensure_app_dirs()
        self.yara_scanner = yara_scanner
        self.repository = repository.strip()
        self.timeout_seconds = max(10, int(timeout_seconds))
        self.interval_seconds = max(3600, int(interval_seconds))
        self.session = session or requests.Session()
        self.logger = get_logger("ragnar_protect.yara_updater")
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._status_path = UPDATES_DIR / "yara_rules_status.json"

    @property
    def available(self) -> bool:
        owner, repo = self._split_repository()
        return bool(owner and repo)

    def start(self) -> None:
        if not self.available or self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, name="RagnarYaraUpdater", daemon=True)
        self._thread.start()
        self.logger.info("community yara updater started | repo=%s", self.repository)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.logger.info("community yara updater stopped")

    def status(self) -> dict[str, Any]:
        try:
            if self._status_path.exists():
                return json.loads(self._status_path.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {"state": "idle", "repository": self.repository}

    def check_now(self) -> dict[str, Any]:
        base = {"repository": self.repository, "checked_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        if not self.available:
            status = {**base, "state": "disabled", "message": "Repository not configured"}
            self._write_status(status)
            return status
        owner, repo = self._split_repository()
        try:
            repo_info = self.session.get(
                f"https://api.github.com/repos/{owner}/{repo}",
                headers={"Accept": "application/vnd.github+json", "User-Agent": "RagnarProtect/1.0"},
                timeout=self.timeout_seconds,
            )
            repo_info.raise_for_status()
            repo_payload = repo_info.json()
            branch = str(repo_payload.get("default_branch") or "main")
            commit = self._fetch_branch_commit(owner, repo, branch)
            previous = self.status()
            if previous.get("commit") == commit and COMMUNITY_YARA_RULES_DIR.exists():
                status = {**base, "state": "up_to_date", "branch": branch, "commit": commit}
                self._write_status(status)
                return status
            extracted_count = self._download_and_extract(owner, repo, branch)
            self.yara_scanner.reload()
            status = {
                **base,
                "state": "updated",
                "branch": branch,
                "commit": commit,
                "rules_extracted": extracted_count,
                "compiled_rulesets": self.yara_scanner.stats.get("compiled_rulesets", 0),
                "failed_rulesets": self.yara_scanner.stats.get("failed_rulesets", 0),
            }
            self._write_status(status)
            return status
        except Exception as exc:
            status = {**base, "state": "error", "message": str(exc)}
            self._write_status(status)
            self.logger.warning("community yara update failed | %s", exc)
            return status

    def _loop(self) -> None:
        self.check_now()
        while not self._stop_event.wait(self.interval_seconds):
            self.check_now()

    def _fetch_branch_commit(self, owner: str, repo: str, branch: str) -> str:
        response = self.session.get(
            f"https://api.github.com/repos/{owner}/{repo}/commits/{branch}",
            headers={"Accept": "application/vnd.github+json", "User-Agent": "RagnarProtect/1.0"},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        return str(payload.get("sha") or "")

    def _download_and_extract(self, owner: str, repo: str, branch: str) -> int:
        archive = self.session.get(
            f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}",
            headers={"User-Agent": "RagnarProtect/1.0"},
            timeout=self.timeout_seconds,
        )
        archive.raise_for_status()
        temp_root = UPDATES_DIR / "community_yara_tmp"
        if temp_root.exists():
            shutil.rmtree(temp_root, ignore_errors=True)
        temp_root.mkdir(parents=True, exist_ok=True)
        if COMMUNITY_YARA_RULES_DIR.exists():
            shutil.rmtree(COMMUNITY_YARA_RULES_DIR, ignore_errors=True)
        COMMUNITY_YARA_RULES_DIR.mkdir(parents=True, exist_ok=True)
        extracted_count = 0
        with zipfile.ZipFile(io.BytesIO(archive.content)) as bundle:
            for member in bundle.infolist():
                member_path = Path(member.filename)
                if member.is_dir():
                    continue
                if member_path.suffix.lower() not in {".yar", ".yara"}:
                    continue
                relative = Path(*member_path.parts[1:])
                target = COMMUNITY_YARA_RULES_DIR / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(member) as source, target.open("wb") as handle:
                    shutil.copyfileobj(source, handle)
                extracted_count += 1
        return extracted_count

    def _split_repository(self) -> tuple[str, str]:
        if "/" not in self.repository:
            return "", ""
        owner, repo = self.repository.split("/", 1)
        return owner.strip(), repo.strip()

    def _write_status(self, payload: dict[str, Any]) -> None:
        self._status_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
