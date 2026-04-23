from __future__ import annotations

import argparse
import os
import time

from .background_runtime import register_background_worker, unregister_background_worker
from .config import APP_DIR, ensure_app_dirs
from .engine import RagnarProtectEngine
from .gui import RagnarProtectApp
from .startup_manager import TASK_NAME, install_startup_task, is_admin, relaunch_as_admin, remove_startup_task, startup_task_exists


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Ragnar Protect")
    parser.add_argument("--scan", nargs="+", help="Scan one or more files or directories")
    parser.add_argument("--scan-executables", help="Scan a directory of executables and write a detailed report")
    parser.add_argument("--prepare-exe-sandbox", help="Prepare a local isolated execution bundle for an executable")
    parser.add_argument("--launch-exe-sandbox", help="Prepare and launch a local isolated execution for an executable")
    parser.add_argument("--protect", action="store_true", help="Run background protection until interrupted")
    parser.add_argument("--gui", action="store_true", help="Open the graphical interface explicitly")
    parser.add_argument(
        "--allow-reduced-mode",
        action="store_true",
        help="When protection is auto-started without admin rights, keep user-mode protection instead of prompting for elevation",
    )
    parser.add_argument("--install-startup", action="store_true", help="Install a highest-privilege startup task")
    parser.add_argument("--remove-startup", action="store_true", help="Remove the startup task")
    parser.add_argument("--quick-scan", action="store_true", help="Run a quick targeted system scan")
    parser.add_argument("--system-audit", action="store_true", help="Inspect running processes and persistence")
    parser.add_argument("--cloud-status", action="store_true", help="Show backend reputation connectivity and queue state")
    parser.add_argument("--protection-status", action="store_true", help="Show staged protection, rollback and queue status")
    parser.add_argument("--error-report-status", action="store_true", help="Show automatic error report mail status")
    parser.add_argument("--check-updates", action="store_true", help="Check the GitHub manifest and stage a newer executable")
    parser.add_argument("--update-status", action="store_true", help="Show the current updater state")
    parser.add_argument("--list-quarantine", action="store_true", help="List active quarantine items")
    parser.add_argument("--restore-quarantine", type=int, help="Restore a quarantine item by id")
    parser.add_argument("--benchmark", help="Run a local benchmark from a corpus folder with clean/malicious/ransomware subfolders")
    parser.add_argument(
        "--monitor-seconds",
        type=int,
        default=0,
        help="Start protection for a limited number of seconds",
    )
    parser.add_argument("--nogui", action="store_true", help="Do not launch the GUI")
    return parser


def _has_explicit_cli_action(args: argparse.Namespace) -> bool:
    return any(
        [
            args.scan,
            args.scan_executables,
            args.prepare_exe_sandbox,
            args.launch_exe_sandbox,
            args.protect,
            args.install_startup,
            args.remove_startup,
            args.quick_scan,
            args.system_audit,
            args.cloud_status,
            getattr(args, "protection_status", False),
            args.error_report_status,
            args.check_updates,
            args.update_status,
            args.list_quarantine,
            args.restore_quarantine is not None,
            getattr(args, "benchmark", None),
            args.monitor_seconds,
        ]
    )


def _should_launch_gui(args: argparse.Namespace) -> bool:
    return (args.gui or not args.nogui) and not _has_explicit_cli_action(args)


def _format_executable_report(report: dict[str, object]) -> str:
    report_paths = report.get("report_paths", {})
    lines = [
        f"Executable scan target: {report['target']}",
        f"Files scanned: {report['file_count']}",
        f"Malicious: {report['malicious_count']}",
        f"Suspicious: {report['suspicious_count']}",
        f"Clean: {report['clean_count']}",
    ]
    if isinstance(report_paths, dict):
        if report_paths.get("json"):
            lines.append(f"JSON report: {report_paths['json']}")
        if report_paths.get("markdown"):
            lines.append(f"Markdown report: {report_paths['markdown']}")
    results = report.get("results", [])
    for item in results[:8]:
        lines.append(
            f"{str(item['status']).upper():10} score={item['score']:>3} {item['path']}"
        )
    return "\n".join(lines)


def _emit_output(text: str) -> None:
    try:
        print(text)
    except OSError:
        ensure_app_dirs()
        with (APP_DIR / "last_cli_output.txt").open("a", encoding="utf-8") as handle:
            handle.write(text)
            if not text.endswith("\n"):
                handle.write("\n")


def main() -> int:
    args = build_parser().parse_args()
    engine = RagnarProtectEngine()

    if args.install_startup:
        if not is_admin():
            if relaunch_as_admin(["--install-startup", "--nogui"]):
                return 0
            _emit_output("Elevation failed or was cancelled.")
            return 1
        result = install_startup_task()
        _emit_output(f"Task: {result['task_name']}")
        _emit_output(f"Command: {result['launch_command']}")
        if result["success"]:
            _emit_output("Startup task installed.")
            return 0
        _emit_output(result["stderr"] or result["stdout"] or "Startup task installation failed.")
        return 1

    if args.remove_startup:
        if not is_admin():
            if relaunch_as_admin(["--remove-startup", "--nogui"]):
                return 0
            _emit_output("Elevation failed or was cancelled.")
            return 1
        result = remove_startup_task()
        _emit_output(f"Task: {TASK_NAME}")
        if result["success"]:
            _emit_output("Startup task removed.")
            return 0
        _emit_output(result["stderr"] or result["stdout"] or "Startup task removal failed.")
        return 1

    if args.scan:
        results = engine.scan_targets(args.scan)
        _emit_output(engine.scanner.format_results(results))

    if args.scan_executables:
        report = engine.scan_executables(args.scan_executables)
        _emit_output(_format_executable_report(report))

    if args.prepare_exe_sandbox:
        bundle = engine.prepare_executable_sandbox(args.prepare_exe_sandbox)
        _emit_output(f"Sandbox config: {bundle['config_path']}")
        _emit_output(f"Results dir: {bundle['results_dir']}")

    if args.launch_exe_sandbox:
        bundle = engine.launch_executable_sandbox(args.launch_exe_sandbox)
        _emit_output(f"Sandbox config: {bundle['config_path']}")
        _emit_output(f"Results dir: {bundle['results_dir']}")
        _emit_output(f"Launched: {bundle['launched']}")

    if args.quick_scan:
        results = engine.quick_scan()
        _emit_output(engine.scanner.format_results(results))

    if args.system_audit:
        results = engine.run_system_audit()
        _emit_output(engine.scanner.format_results(results))

    if args.cloud_status:
        status = engine.cloud_status()
        for key, value in status.items():
            _emit_output(f"{key}: {value}")

    if getattr(args, "protection_status", False):
        status = engine.protection_status()
        for key, value in status.items():
            _emit_output(f"{key}: {value}")

    if args.error_report_status:
        status = engine.error_report_status()
        for key, value in status.items():
            _emit_output(f"{key}: {value}")

    if args.check_updates:
        status = engine.check_updates(auto_download=True)
        for key, value in status.items():
            _emit_output(f"{key}: {value}")

    if args.update_status:
        status = engine.update_status()
        for key, value in status.items():
            _emit_output(f"{key}: {value}")

    if args.list_quarantine:
        for row in engine.list_quarantine_items():
            _emit_output(
                f"{row['id']:>4} | {row['quarantined_at']} | {row['original_path']} | {row['reason']}"
            )

    if args.restore_quarantine is not None:
        _emit_output(engine.restore_quarantine_item(args.restore_quarantine))

    if getattr(args, "benchmark", None):
        report = engine.run_benchmark(args.benchmark)
        for key, value in report.items():
            _emit_output(f"{key}: {value}")

    if args.monitor_seconds:
        engine.start_protection()
        try:
            time.sleep(args.monitor_seconds)
        finally:
            engine.stop_protection()

    if args.protect:
        reduced_mode = False
        if not is_admin():
            if args.allow_reduced_mode:
                _emit_output("Starting reduced user-mode protection without elevation.")
                reduced_mode = True
            else:
                if relaunch_as_admin(["--protect", "--nogui"]):
                    return 0
                _emit_output("Elevation failed or was cancelled. Starting reduced user-mode protection.")
                reduced_mode = True
        try:
            if not reduced_mode and is_admin() and not startup_task_exists():
                install_startup_task()
            register_background_worker(reduced_mode=reduced_mode)
            engine.start_protection(reduced_mode=reduced_mode)
            _emit_output("Background protection active. Press Ctrl+C to stop.")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            unregister_background_worker(expected_pid=os.getpid())
            engine.stop_protection()

    if _should_launch_gui(args):
        app = RagnarProtectApp(engine)
        app.mainloop()

    return 0
