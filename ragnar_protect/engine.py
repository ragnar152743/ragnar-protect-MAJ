from __future__ import annotations

from pathlib import Path

from .amsi import AmsiScanner
from .background_scanner import BackgroundScanScheduler
from .benchmark import BenchmarkRunner
from .behavior_engine import BehaviorCorrelationEngine
from .blocker import ProcessBlocker
from .canary_guard import CanaryGuard
from .cloud_reputation import CloudReputationClient
from .database import Database
from .error_reporter import ErrorReportMailer
from .executable_report import ExecutableFolderReport
from .logging_setup import register_log_record_callback
from .monitor import FileSystemMonitor
from .process_guard import ProcessGuard
from .rollback_cache import RollbackCache
from .sandbox_queue import SandboxQueue
from .scanner import RagnarScanner
from .staged_analysis import StagePipeline
from .system_inspector import SystemInspector
from .updater import GitHubUpdateManager
from .wallpaper_guard import WallpaperGuard
from .watch_manager import WatchManager


class RagnarProtectEngine:
    def __init__(self) -> None:
        self.database = Database()
        self.error_reporter = ErrorReportMailer(self.database)
        register_log_record_callback(self.error_reporter.handle_log_record)
        self.error_reporter.start()
        self.amsi = AmsiScanner()
        self.scanner = RagnarScanner(self.database, self.amsi)
        self.cloud = CloudReputationClient()
        self.rollback_cache = RollbackCache(self.database)
        self.stage_pipeline = StagePipeline(self.scanner, self.database)
        self.benchmark_runner = BenchmarkRunner(self.scanner, self.database)
        self.watch_manager = WatchManager(self.database, self.scanner, cloud_client=self.cloud)
        self.sandbox_queue = SandboxQueue(self.database)
        self.canary_guard = CanaryGuard()
        self.behavior_engine = BehaviorCorrelationEngine(
            self.scanner,
            self.database,
            watch_manager=self.watch_manager,
            canary_guard=self.canary_guard,
            rollback_cache=self.rollback_cache,
        )
        self.executable_report = ExecutableFolderReport(self.scanner)
        self.system_inspector = SystemInspector(self.scanner)
        self.blocker = ProcessBlocker(self.database)
        self.monitor = FileSystemMonitor(self.scanner, event_callback=self.behavior_engine.handle_fs_event)
        self.process_guard = ProcessGuard(self.scanner, self.database)
        self.wallpaper_guard = WallpaperGuard(self.database)
        self.background_scanner = BackgroundScanScheduler(
            self.scanner,
            self.database,
            self.system_inspector,
            watch_manager=self.watch_manager,
            rollback_cache=self.rollback_cache,
        )
        self.updater = GitHubUpdateManager()
        self.scanner.register_result_callback(self.watch_manager.handle_scan_result)
        self.scanner.register_result_callback(self.sandbox_queue.consider_scan_result)

    def start_protection(self, reduced_mode: bool = False) -> None:
        self.canary_guard.ensure_canaries()
        self.watch_manager.start()
        self.sandbox_queue.start()
        self.monitor.start()
        self.blocker.start()
        self.process_guard.start()
        self.behavior_engine.start()
        self.background_scanner.start()
        self.wallpaper_guard.start()
        self.updater.start()
        if reduced_mode:
            # Reduced mode still starts the same user-mode components; admin-only checks remain disabled at source.
            return

    def stop_protection(self) -> None:
        self.monitor.stop()
        self.blocker.stop()
        self.process_guard.stop()
        self.behavior_engine.stop()
        self.background_scanner.stop()
        self.sandbox_queue.stop()
        self.watch_manager.stop()
        self.wallpaper_guard.stop()
        self.updater.stop()

    def scan_targets(self, targets: list[str]) -> list:
        results = []
        for target in targets:
            results.extend(self.scanner.scan_path(Path(target)))
        return results

    def scan_executables(self, target: str) -> dict[str, object]:
        target_path = Path(target)
        if target_path.is_file():
            target_path = target_path.parent
        return self.executable_report.scan_directory(target_path)

    def prepare_executable_sandbox(self, target: str) -> dict[str, object]:
        return self.scanner.prepare_executable_sandbox(Path(target))

    def launch_executable_sandbox(self, target: str) -> dict[str, object]:
        return self.sandbox_queue.launch_sample(target)

    def quick_scan(self) -> list:
        return self.system_inspector.quick_scan()

    def run_system_audit(self) -> list:
        return self.system_inspector.system_audit()

    def list_quarantine_items(self, active_only: bool = True) -> list[dict]:
        return self.database.list_quarantine_items(active_only=active_only)

    def restore_quarantine_item(self, item_id: int) -> str:
        return self.scanner.restore_quarantine_item(item_id)

    def cloud_status(self) -> dict[str, object]:
        status = self.watch_manager.status()
        update_status = self.updater.status()
        status["updater_state"] = update_status.get("state", "idle")
        status["updater_remote_version"] = update_status.get("remote_version", "")
        status["updater_staged_path"] = update_status.get("staged_path", "")
        status["error_report_configured"] = self.error_reporter.status().get("configured", False)
        status["error_report_pending"] = self.error_reporter.status().get("pending_reports", 0)
        status["rollback"] = self.rollback_cache.status()
        return status

    def protection_status(self) -> dict[str, object]:
        status = self.cloud_status()
        status["launch_decisions"] = self.database.list_launch_decisions(limit=10)
        status["sandbox_queue_depth"] = len(self.database.list_sandbox_queue(limit=200))
        status["behavior_events"] = self.database.list_recent_behavior_events(limit=10)
        status["benchmark_runs"] = self.database.list_benchmark_runs(limit=5)
        return status

    def run_benchmark(self, corpus_dir: str) -> dict[str, object]:
        return self.benchmark_runner.run(corpus_dir).to_dict()

    def check_updates(self, auto_download: bool = True) -> dict[str, object]:
        return self.updater.check_now(auto_download=auto_download)

    def update_status(self) -> dict[str, object]:
        return self.updater.status()

    def error_report_status(self) -> dict[str, object]:
        return self.error_reporter.status()
