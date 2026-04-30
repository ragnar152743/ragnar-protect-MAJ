from __future__ import annotations

from pathlib import Path

from .amsi import AmsiScanner
from .background_scanner import BackgroundScanScheduler
from .benchmark import BenchmarkRunner
from .behavior_engine import BehaviorCorrelationEngine
from .blocker import ProcessBlocker
from .canary_guard import CanaryGuard
from .cloud_reputation import CloudReputationClient
from .config import BOOT_PREFLIGHT_HOLD_SECONDS, BOOT_PREFLIGHT_MAX_HOTSPOT_FILES, BOOT_PREFLIGHT_MAX_SANDBOX_ITEMS, BOOT_PREFLIGHT_MAX_WINDOWS_FILES
from .database import Database
from .error_reporter import ErrorReportMailer
from .executable_report import ExecutableFolderReport
from .logging_setup import register_log_record_callback
from .monitor import FileSystemMonitor
from .network_monitor import NetworkConnectionMonitor
from .notification_helper import ToastNotifier
from .process_guard import ProcessGuard
from .registry_monitor import RegistryPersistenceMonitor
from .rollback_cache import RollbackCache
from .sandbox_queue import SandboxQueue
from .scanner import RagnarScanner
from .staged_analysis import StagePipeline
from .system_inspector import SystemInspector
from .taskbar_guard import TaskbarSnapshotGuard
from .updater import GitHubUpdateManager
from .wallpaper_guard import WallpaperGuard
from .watch_manager import WatchManager
from .yara_rules_updater import CommunityYaraRulesUpdater


class RagnarProtectEngine:
    def __init__(self) -> None:
        self.database = Database()
        self.error_reporter = ErrorReportMailer(self.database)
        register_log_record_callback(self.error_reporter.handle_log_record)
        self.error_reporter.start()
        self.amsi = AmsiScanner()
        self.scanner = RagnarScanner(self.database, self.amsi)
        self.cloud = CloudReputationClient()
        self.notifications = ToastNotifier()
        self.rollback_cache = RollbackCache(self.database)
        self.taskbar_guard = TaskbarSnapshotGuard()
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
            taskbar_guard=self.taskbar_guard,
        )
        self.executable_report = ExecutableFolderReport(self.scanner)
        self.system_inspector = SystemInspector(self.scanner)
        self.blocker = ProcessBlocker(self.database)
        self.monitor = FileSystemMonitor(self.scanner, event_callback=self.behavior_engine.handle_fs_event)
        self.process_guard = ProcessGuard(self.scanner, self.database)
        self.registry_monitor = RegistryPersistenceMonitor(self.scanner, self.system_inspector)
        self.network_monitor = NetworkConnectionMonitor(self.scanner, self.database)
        self.wallpaper_guard = WallpaperGuard(self.database)
        self.background_scanner = BackgroundScanScheduler(
            self.scanner,
            self.database,
            self.system_inspector,
            watch_manager=self.watch_manager,
            rollback_cache=self.rollback_cache,
        )
        self.updater = GitHubUpdateManager()
        self.yara_updater = CommunityYaraRulesUpdater(self.scanner.yara)
        self.scanner.register_result_callback(self.watch_manager.handle_scan_result)
        self.scanner.register_result_callback(self.sandbox_queue.consider_scan_result)
        self.scanner.register_result_callback(self.notifications.handle_scan_result)

    def start_protection(self, reduced_mode: bool = False) -> None:
        self.canary_guard.ensure_canaries()
        self.taskbar_guard.refresh_snapshot()
        self.watch_manager.start()
        self.sandbox_queue.start()
        self.monitor.start()
        self.blocker.start()
        self.process_guard.start()
        self.behavior_engine.start()
        self.background_scanner.start()
        self.registry_monitor.start()
        self.network_monitor.start()
        self.wallpaper_guard.start()
        self.updater.start()
        self.yara_updater.start()
        if reduced_mode:
            # Reduced mode still starts the same user-mode components; admin-only checks remain disabled at source.
            return

    def stop_protection(self) -> None:
        self.monitor.stop()
        self.blocker.stop()
        self.process_guard.stop()
        self.behavior_engine.stop()
        self.background_scanner.stop()
        self.registry_monitor.stop()
        self.network_monitor.stop()
        self.sandbox_queue.stop()
        self.watch_manager.stop()
        self.wallpaper_guard.stop()
        self.updater.stop()
        self.yara_updater.stop()

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
        status["taskbar_snapshot"] = self.taskbar_guard.status()
        status["yara_updater"] = self.yara_updater.status()
        status["yara_compiler"] = self.scanner.yara.stats
        status["notifications_available"] = self.notifications.available
        status["registry_monitor_available"] = self.registry_monitor.available
        status["network_monitor_available"] = self.network_monitor.available
        return status

    def protection_status(self) -> dict[str, object]:
        status = self.cloud_status()
        status["launch_decisions"] = self.database.list_launch_decisions(limit=10)
        status["sandbox_queue_depth"] = len(self.database.list_sandbox_queue(limit=200))
        status["behavior_events"] = self.database.list_recent_behavior_events(limit=10)
        status["benchmark_runs"] = self.database.list_benchmark_runs(limit=5)
        status["dashboard_summary"] = self.database.get_dashboard_summary()
        return status

    def boot_preflight(self) -> dict[str, object]:
        startup_results = self.system_inspector.scan_startup_entries(remediate=True)
        task_results = self.system_inspector.scan_scheduled_tasks(remediate=True)
        windows_results = self.system_inspector.scan_windows_boot_surface(max_files=BOOT_PREFLIGHT_MAX_WINDOWS_FILES)
        hotspot_results = self.system_inspector.scan_boot_hotspots(max_files_per_dir=BOOT_PREFLIGHT_MAX_HOTSPOT_FILES)
        sandbox_processed = self.sandbox_queue.process_pending_items(max_items=BOOT_PREFLIGHT_MAX_SANDBOX_ITEMS)
        all_results = [*startup_results, *task_results, *windows_results, *hotspot_results]
        return {
            "boot_preflight": True,
            "startup_findings": len(startup_results),
            "task_findings": len(task_results),
            "windows_surface_findings": len(windows_results),
            "hotspot_findings": len(hotspot_results),
            "sandbox_items_processed": sandbox_processed,
            "detected_malicious": sum(1 for result in all_results if getattr(result, "status", "") == "malicious"),
            "hold_seconds": BOOT_PREFLIGHT_HOLD_SECONDS,
        }

    def run_benchmark(self, corpus_dir: str, profile: str = "standard") -> dict[str, object]:
        return self.benchmark_runner.run(corpus_dir, profile=profile).to_dict()

    def run_hard_benchmark(self, output_dir: str | None = None) -> dict[str, object]:
        return self.benchmark_runner.run_hard_suite(output_dir).to_dict()

    def check_updates(self, auto_download: bool = True, auto_apply: bool = False) -> dict[str, object]:
        return self.updater.check_now(auto_download=auto_download, auto_apply=auto_apply)

    def update_status(self) -> dict[str, object]:
        return self.updater.status()

    def yara_update_status(self) -> dict[str, object]:
        return self.yara_updater.status()

    def update_yara_rules(self) -> dict[str, object]:
        return self.yara_updater.check_now()

    def error_report_status(self) -> dict[str, object]:
        return self.error_reporter.status()
