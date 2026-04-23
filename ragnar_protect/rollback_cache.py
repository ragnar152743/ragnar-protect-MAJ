from __future__ import annotations

import hashlib
import shutil
import time
from pathlib import Path

from .config import ROLLBACK_DIR, ROLLBACK_MAX_FILE_BYTES, ROLLBACK_MAX_TOTAL_BYTES, ROLLBACK_PROTECTED_EXTENSIONS, ensure_app_dirs
from .database import Database
from .logging_setup import get_logger
from .models import RollbackArtifact


class RollbackCache:
    def __init__(self, database: Database) -> None:
        ensure_app_dirs()
        self.database = database
        self.logger = get_logger("ragnar_protect.rollback")

    def should_protect(self, path: Path) -> bool:
        extension = path.suffix.lower()
        return path.exists() and path.is_file() and extension in ROLLBACK_PROTECTED_EXTENSIONS

    def snapshot_file(self, path: Path, reason: str = "background") -> str | None:
        candidate = path.expanduser()
        if not self.should_protect(candidate):
            return None
        try:
            stat = candidate.stat()
        except OSError:
            return None
        if stat.st_size <= 0 or stat.st_size > ROLLBACK_MAX_FILE_BYTES:
            return None

        existing = self.database.get_latest_rollback_artifact(str(candidate))
        if existing is not None:
            try:
                if float(existing.get("source_mtime") or 0.0) == float(stat.st_mtime) and int(existing.get("source_size") or 0) == int(stat.st_size):
                    return str(existing.get("snapshot_path") or "")
            except Exception:
                pass

        digest = self._sha256(candidate)
        target = ROLLBACK_DIR / digest[:2] / f"{digest}_{candidate.name}"
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(candidate, target)
        except OSError as exc:
            self.logger.warning("rollback snapshot failed | %s | %s", candidate, exc)
            return None

        artifact = RollbackArtifact(
            original_path=str(candidate),
            snapshot_path=str(target),
            sha256=digest,
            source_mtime=float(stat.st_mtime),
            source_size=int(stat.st_size),
            reason=reason,
        )
        self.database.upsert_rollback_artifact(artifact)
        self._prune()
        self.logger.info("rollback snapshot saved | %s -> %s", candidate, target)
        return str(target)

    def restore_paths(self, paths: list[str], incident_reason: str) -> list[str]:
        restored: list[str] = []
        for value in paths:
            original = Path(value)
            extension = original.suffix.lower()
            if extension not in ROLLBACK_PROTECTED_EXTENSIONS:
                continue
            row = self.database.get_latest_rollback_artifact(str(original))
            if row is None:
                continue
            snapshot_path = Path(str(row.get("snapshot_path") or ""))
            if not snapshot_path.exists():
                continue
            try:
                if original.exists():
                    original.unlink()
                original.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(snapshot_path, original)
                artifact_id = int(row.get("id") or 0)
                if artifact_id:
                    self.database.mark_rollback_artifact_restored(artifact_id)
                restored.append(str(original))
                self.logger.warning("rollback restored | %s | reason=%s", original, incident_reason)
            except OSError as exc:
                self.logger.warning("rollback restore failed | %s | %s", original, exc)
        return restored

    def status(self) -> dict[str, object]:
        total_size = 0
        count = 0
        if ROLLBACK_DIR.exists():
            for path in ROLLBACK_DIR.rglob("*"):
                if not path.is_file():
                    continue
                count += 1
                try:
                    total_size += path.stat().st_size
                except OSError:
                    continue
        return {
            "enabled": True,
            "artifact_count": count,
            "total_bytes": total_size,
            "quota_bytes": ROLLBACK_MAX_TOTAL_BYTES,
        }

    def _prune(self) -> None:
        files: list[tuple[float, int, Path]] = []
        total_size = 0
        if not ROLLBACK_DIR.exists():
            return
        for path in ROLLBACK_DIR.rglob("*"):
            if not path.is_file():
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            files.append((stat.st_mtime, stat.st_size, path))
            total_size += stat.st_size
        if total_size <= ROLLBACK_MAX_TOTAL_BYTES:
            return
        for _, file_size, path in sorted(files, key=lambda item: item[0]):
            try:
                path.unlink()
                total_size -= file_size
            except OSError:
                continue
            if total_size <= ROLLBACK_MAX_TOTAL_BYTES:
                break

    def _sha256(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
