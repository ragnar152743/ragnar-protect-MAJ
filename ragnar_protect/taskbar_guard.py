from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from .config import TASKBAR_SNAPSHOT_DIR, TASKBAND_REGISTRY_KEY, USER_PINNED_TASKBAR_DIR, ensure_app_dirs
from .hidden_process import run_hidden
from .logging_setup import get_logger


class TaskbarSnapshotGuard:
    def __init__(self) -> None:
        ensure_app_dirs()
        self.logger = get_logger("ragnar_protect.taskbar")
        self.source_dir = USER_PINNED_TASKBAR_DIR
        self.snapshot_dir = TASKBAR_SNAPSHOT_DIR / "links"
        self.snapshot_reg = TASKBAR_SNAPSHOT_DIR / "taskband.reg"
        self.snapshot_meta = TASKBAR_SNAPSHOT_DIR / "snapshot.json"

    def refresh_snapshot(self) -> dict[str, object]:
        ensure_app_dirs()
        snapshot_count = 0
        source_exists = self.source_dir.exists()
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        self._clear_directory(self.snapshot_dir)
        if source_exists:
            for item in sorted(self.source_dir.glob("*")):
                if not item.is_file():
                    continue
                try:
                    shutil.copy2(item, self.snapshot_dir / item.name)
                    snapshot_count += 1
                except OSError as exc:
                    self.logger.debug("taskbar snapshot copy skipped | %s | %s", item, exc)
        reg_exported = self._export_taskband_registry()
        payload = {
            "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source_dir": str(self.source_dir),
            "links_count": snapshot_count,
            "registry_exported": reg_exported,
        }
        self.snapshot_meta.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
        self.logger.info(
            "taskbar snapshot refreshed | source_exists=%s links=%s registry=%s",
            source_exists,
            snapshot_count,
            reg_exported,
        )
        return payload

    def restore_snapshot(self, incident_reason: str, restart_explorer: bool = True) -> dict[str, object]:
        ensure_app_dirs()
        links_restored = 0
        registry_restored = False
        if self.snapshot_dir.exists():
            self.source_dir.mkdir(parents=True, exist_ok=True)
            for item in self.source_dir.glob("*"):
                if not item.is_file():
                    continue
                try:
                    item.unlink()
                except OSError:
                    continue
            for item in sorted(self.snapshot_dir.glob("*")):
                if not item.is_file():
                    continue
                try:
                    shutil.copy2(item, self.source_dir / item.name)
                    links_restored += 1
                except OSError as exc:
                    self.logger.debug("taskbar restore copy skipped | %s | %s", item, exc)
        registry_restored = self._import_taskband_registry()
        if restart_explorer and (links_restored > 0 or registry_restored):
            self._restart_explorer()
        payload = {
            "links_restored": links_restored,
            "registry_restored": registry_restored,
            "reason": incident_reason,
        }
        self.logger.warning(
            "taskbar snapshot restored | links=%s registry=%s reason=%s",
            links_restored,
            registry_restored,
            incident_reason,
        )
        return payload

    def status(self) -> dict[str, object]:
        links_count = 0
        if self.snapshot_dir.exists():
            links_count = len([item for item in self.snapshot_dir.iterdir() if item.is_file()])
        return {
            "source_dir": str(self.source_dir),
            "snapshot_dir": str(self.snapshot_dir),
            "snapshot_exists": self.snapshot_meta.exists(),
            "links_count": links_count,
            "registry_snapshot": self.snapshot_reg.exists(),
        }

    def _export_taskband_registry(self) -> bool:
        completed = run_hidden(
            ["reg.exe", "export", TASKBAND_REGISTRY_KEY, str(self.snapshot_reg), "/y"],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        return completed.returncode == 0 and self.snapshot_reg.exists()

    def _import_taskband_registry(self) -> bool:
        if not self.snapshot_reg.exists():
            return False
        completed = run_hidden(
            ["reg.exe", "import", str(self.snapshot_reg)],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        return completed.returncode == 0

    def _restart_explorer(self) -> None:
        run_hidden(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-WindowStyle",
                "Hidden",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue; Start-Process explorer.exe",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )

    def _clear_directory(self, directory: Path) -> None:
        for item in directory.glob("*"):
            try:
                if item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                else:
                    item.unlink()
            except OSError:
                continue
