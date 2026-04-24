from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

os.environ.setdefault("RAGNAR_APP_DIR", str(Path(tempfile.gettempdir()) / "ragnar-protect-tests"))

from ragnar_protect.database import Database
from ragnar_protect.rollback_cache import RollbackCache
from ragnar_protect.startup_manager import EARLY_TASK_NAME, TASK_NAME, install_startup_task, remove_startup_task
from ragnar_protect.system_inspector import SystemInspector
from ragnar_protect.taskbar_guard import TaskbarSnapshotGuard
from ragnar_protect.models import FileScanResult


class _FakeInspectorScanner:
    def scan_artifact(self, display_path: str, content: str, extension: str, metadata: dict, persist: bool, persist_clean: bool):
        return FileScanResult(
            path=display_path,
            sha256="artifact",
            size=len(content),
            extension=extension,
            status="malicious",
            score=95,
            findings=[],
            metadata=metadata,
        )

    def scan_file(self, path: Path):
        return FileScanResult(
            path=str(path),
            sha256="file",
            size=0,
            extension=path.suffix.lower(),
            status="malicious",
            score=95,
            findings=[],
            metadata={},
        )

    def enforce_block_on_existing_file(self, file_path: Path | str, result: FileScanResult) -> dict[str, object]:
        return {"blocked": True, "quarantined_path": "C:\\quarantine\\bad.exe", "quarantine_item_id": 1}


class _CleanArtifactMaliciousFileScanner(_FakeInspectorScanner):
    def scan_artifact(self, display_path: str, content: str, extension: str, metadata: dict, persist: bool, persist_clean: bool):
        return FileScanResult(
            path=display_path,
            sha256="artifact",
            size=len(content),
            extension=extension,
            status="clean",
            score=0,
            findings=[],
            metadata=metadata,
        )


class SystemHardeningTests(unittest.TestCase):
    def test_install_startup_task_registers_logon_and_startup_tasks(self) -> None:
        completed = CompletedProcess(args=["powershell.exe"], returncode=0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as temp_dir, patch(
            "ragnar_protect.startup_manager.run_hidden",
            return_value=completed,
        ) as run_hidden_mock, patch(
            "ragnar_protect.startup_manager.SHARED_APP_DIR_HINT",
            Path(temp_dir) / "shared" / "app_dir.txt",
        ):
            result = install_startup_task()
            self.assertTrue(Path(result["shared_app_dir_hint"]).exists())

        self.assertTrue(result["success"])
        self.assertEqual(result["task_names"], [TASK_NAME, EARLY_TASK_NAME])
        command_args = run_hidden_mock.call_args.args[0]
        script = command_args[-1]
        self.assertIn("New-ScheduledTaskTrigger -AtLogOn", script)
        self.assertIn("New-ScheduledTaskTrigger -AtStartup", script)
        self.assertIn("NT AUTHORITY\\SYSTEM", script)
        self.assertIn(EARLY_TASK_NAME, script)
        self.assertIn("--boot-preflight --nogui", script)

    def test_remove_startup_task_removes_both_registered_tasks(self) -> None:
        completed = CompletedProcess(args=["schtasks"], returncode=0, stdout="OK", stderr="")
        with patch("ragnar_protect.startup_manager.run_hidden", return_value=completed) as run_hidden_mock:
            result = remove_startup_task()

        self.assertTrue(result["success"])
        self.assertEqual(run_hidden_mock.call_count, 2)
        self.assertEqual(result["task_names"], [TASK_NAME, EARLY_TASK_NAME])

    def test_taskbar_snapshot_refresh_and_restore_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            source_dir = temp_root / "User Pinned" / "TaskBar"
            snapshot_root = temp_root / "snapshot"
            source_dir.mkdir(parents=True)
            (source_dir / "Explorer.lnk").write_text("shortcut", encoding="utf-8")

            def _run_hidden(args, **kwargs):
                if len(args) >= 4 and args[0] == "reg.exe" and args[1] == "export":
                    Path(args[3]).write_text("Windows Registry Editor Version 5.00", encoding="utf-8")
                return CompletedProcess(args=args, returncode=0, stdout="", stderr="")

            with patch("ragnar_protect.taskbar_guard.USER_PINNED_TASKBAR_DIR", source_dir), patch(
                "ragnar_protect.taskbar_guard.TASKBAR_SNAPSHOT_DIR",
                snapshot_root,
            ), patch("ragnar_protect.taskbar_guard.run_hidden", side_effect=_run_hidden), patch.object(
                TaskbarSnapshotGuard,
                "_restart_explorer",
            ) as restart_mock:
                guard = TaskbarSnapshotGuard()
                snapshot = guard.refresh_snapshot()
                self.assertEqual(snapshot["links_count"], 1)
                (source_dir / "Explorer.lnk").unlink()

                restored = guard.restore_snapshot("unit-test")

            self.assertEqual(restored["links_restored"], 1)
            self.assertTrue((source_dir / "Explorer.lnk").exists())
            restart_mock.assert_called_once()

    def test_rollback_cache_purge_artifacts_removes_confirmed_encrypted_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            app_dir = Path(temp_dir) / "app"
            app_dir.mkdir()
            db_path = Path(temp_dir) / "test.db"
            encrypted = Path(temp_dir) / "doc1.lockbit"
            note = Path(temp_dir) / "HOW_TO_DECRYPT.txt"
            encrypted.write_text("encrypted", encoding="utf-8")
            note.write_text("ransom note", encoding="utf-8")
            with patch.dict(os.environ, {"RAGNAR_APP_DIR": str(app_dir)}):
                cache = RollbackCache(database=Database(db_path))
                removed = cache.purge_artifacts([str(encrypted), str(note)], "unit-test")

            self.assertCountEqual(removed, [str(encrypted), str(note)])
            self.assertFalse(encrypted.exists())
            self.assertFalse(note.exists())

    def test_scan_startup_entries_remediates_malicious_registry_entry(self) -> None:
        inspector = SystemInspector(_FakeInspectorScanner())
        with patch.object(
            inspector,
            "_get_startup_entries",
            return_value=[
                {
                    "name": "BadStartup",
                    "command": r"C:\Users\Test\AppData\Local\Temp\bad.exe",
                    "location": "HKCU Run",
                    "user": "current-user",
                }
            ],
        ), patch("ragnar_protect.system_inspector.run_hidden", return_value=CompletedProcess(args=["reg.exe"], returncode=0, stdout="", stderr="")) as run_hidden_mock:
            results = inspector.scan_startup_entries(remediate=True)

        self.assertEqual(len(results), 1)
        self.assertTrue(any("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" in " ".join(call.args[0]) for call in run_hidden_mock.call_args_list))

    def test_scan_scheduled_tasks_remediates_malicious_task(self) -> None:
        inspector = SystemInspector(_FakeInspectorScanner())
        with patch.object(
            inspector,
            "_get_scheduled_tasks",
            return_value=[
                {
                    "task_name": "BadTask",
                    "task_path": "\\",
                    "state": "Ready",
                    "execute": r"C:\Users\Test\AppData\Local\Temp\bad.exe",
                    "arguments": "",
                }
            ],
        ), patch("ragnar_protect.system_inspector.run_hidden", return_value=CompletedProcess(args=["schtasks"], returncode=0, stdout="", stderr="")) as run_hidden_mock:
            results = inspector.scan_scheduled_tasks(remediate=True)

        self.assertEqual(len(results), 1)
        self.assertTrue(any("/disable" in " ".join(call.args[0]) for call in run_hidden_mock.call_args_list))

    def test_scan_startup_entries_scans_executable_even_when_command_artifact_is_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            bad_exe = Path(temp_dir) / "bad.exe"
            bad_exe.write_text("payload", encoding="utf-8")
            inspector = SystemInspector(_CleanArtifactMaliciousFileScanner())
            with patch.object(
                inspector,
                "_get_startup_entries",
                return_value=[
                    {
                        "name": "BadStartup",
                        "command": str(bad_exe),
                        "location": "HKCU Run",
                        "user": "current-user",
                    }
                ],
            ), patch("ragnar_protect.system_inspector.run_hidden", return_value=CompletedProcess(args=["reg.exe"], returncode=0, stdout="", stderr="")) as run_hidden_mock:
                results = inspector.scan_startup_entries(remediate=True)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].path, str(bad_exe))
        self.assertTrue(any(call.args[0][0].lower() == "reg.exe" for call in run_hidden_mock.call_args_list))

    def test_scan_scheduled_tasks_scans_executable_even_when_command_artifact_is_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            bad_exe = Path(temp_dir) / "bad.exe"
            bad_exe.write_text("payload", encoding="utf-8")
            inspector = SystemInspector(_CleanArtifactMaliciousFileScanner())
            with patch.object(
                inspector,
                "_get_scheduled_tasks",
                return_value=[
                    {
                        "task_name": "BadTask",
                        "task_path": "\\",
                        "state": "Ready",
                        "execute": str(bad_exe),
                        "arguments": "",
                    }
                ],
            ), patch("ragnar_protect.system_inspector.run_hidden", return_value=CompletedProcess(args=["schtasks"], returncode=0, stdout="", stderr="")):
                results = inspector.scan_scheduled_tasks(remediate=True)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].path, str(bad_exe))

    def test_extensionless_system_task_files_are_considered_interesting(self) -> None:
        inspector = SystemInspector(_FakeInspectorScanner())
        task_file = Path(r"C:\Windows\System32\Tasks\RagnarTestTask")
        self.assertTrue(inspector._is_interesting_file(task_file))


if __name__ == "__main__":
    unittest.main()
