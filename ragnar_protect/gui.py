from __future__ import annotations

import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, simpledialog, ttk

from .background_runtime import background_status, ensure_background_worker, stop_background_workers
from .config import ASSETS_DIR, LOGO_ICON, LOGO_PNG, is_managed_path
from .engine import RagnarProtectEngine

UI_COLORS = {
    "bg": "#f3f6fb",
    "card": "#ffffff",
    "primary": "#11243d",
    "accent": "#2f6df6",
    "accent_soft": "#deebff",
    "ok": "#16a34a",
    "warn": "#eab308",
    "danger": "#dc2626",
    "tab_idle": "#dbe4f5",
}


class RagnarProtectApp(tk.Tk):
    def __init__(self, engine: RagnarProtectEngine) -> None:
        super().__init__()
        self.engine = engine
        self.title("Ragnar Protect")
        self.geometry("1180x760")
        self.minsize(960, 640)
        self.configure(bg=UI_COLORS["bg"])

        self.scan_target = tk.StringVar(value=str(Path.home() / "Downloads"))
        self.monitor_status = tk.StringVar(value="inactive")
        self.blocker_status = tk.StringVar(value="inactive")
        self.process_guard_status = tk.StringVar(value="inactive")
        self.wallpaper_status = tk.StringVar(value="inactive")
        self.behavior_status = tk.StringVar(value="inactive")
        self.background_status = tk.StringVar(value="inactive")
        self.registry_status = tk.StringVar(value="inactive")
        self.network_status = tk.StringVar(value="inactive")
        self.watch_status = tk.StringVar(value="idle")
        self.cloud_status = tk.StringVar(value="backend unavailable")
        self.updater_status = tk.StringVar(value="idle")
        self.hero_status_text = tk.StringVar(value="pc protege")
        self.hero_system_text = tk.StringVar(value="systeme: en attente")
        self.hero_background_text = tk.StringVar(value="protection arriere plan: inactive")
        self.hero_network_text = tk.StringVar(value="surveillance reseau: inactive")
        self.logo_image = None
        self.window_icon_image = None

        self._configure_styles()
        self._apply_branding()
        self._build_ui()
        self.refresh_history()
        self.refresh_blocking()
        self.refresh_quarantine()
        self.refresh_watch()
        self.refresh_dashboard()
        self.refresh_whitelist()
        self.refresh_cloud_status()
        self.refresh_runtime_status()
        self.protocol("WM_DELETE_WINDOW", self.close_window)
        self.after(250, self._ensure_background_worker_async)
        self.after(2500, self._schedule_runtime_refresh)

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Ragnar.TFrame", background=UI_COLORS["bg"])
        style.configure("RagnarCard.TFrame", background=UI_COLORS["card"])
        style.configure("Ragnar.TLabel", background=UI_COLORS["bg"], foreground=UI_COLORS["primary"])
        style.configure("RagnarTitle.TLabel", background=UI_COLORS["bg"], foreground=UI_COLORS["primary"], font=("Segoe UI Semibold", 24))
        style.configure(
            "RagnarSubtitle.TLabel",
            background=UI_COLORS["bg"],
            foreground="#37506d",
            font=("Segoe UI", 10),
        )
        style.configure(
            "Ragnar.TNotebook",
            background=UI_COLORS["bg"],
            borderwidth=0,
            tabmargins=(0, 6, 0, 0),
        )
        style.configure(
            "Ragnar.TNotebook.Tab",
            padding=(16, 8),
            background=UI_COLORS["tab_idle"],
            foreground=UI_COLORS["primary"],
            font=("Segoe UI Semibold", 10),
            borderwidth=0,
        )
        style.map(
            "Ragnar.TNotebook.Tab",
            background=[("selected", UI_COLORS["accent"]), ("active", UI_COLORS["accent_soft"])],
            foreground=[("selected", "#ffffff"), ("active", UI_COLORS["primary"])],
        )
        style.configure(
            "Ragnar.TButton",
            background=UI_COLORS["accent"],
            foreground="#ffffff",
            borderwidth=0,
            focusthickness=1,
            focuscolor=UI_COLORS["accent"],
            padding=(10, 6),
        )
        style.map(
            "Ragnar.TButton",
            background=[("active", "#2458c9"), ("pressed", "#1e4cae")],
            foreground=[("disabled", "#d7e1f4")],
        )
        style.configure("TButton", padding=(10, 6))

    def _apply_branding(self) -> None:
        logo_candidate = ASSETS_DIR / "ragnar_protect_mark.png"
        if not logo_candidate.exists():
            logo_candidate = LOGO_PNG
        if logo_candidate.exists():
            try:
                self.window_icon_image = tk.PhotoImage(file=str(logo_candidate))
                self.iconphoto(True, self.window_icon_image)
                self.logo_image = self.window_icon_image.subsample(12, 12)
            except tk.TclError:
                self.logo_image = None
                self.window_icon_image = None
        if LOGO_ICON.exists():
            try:
                self.iconbitmap(default=str(LOGO_ICON))
            except tk.TclError:
                pass

    def _build_ui(self) -> None:
        outer = ttk.Frame(self, style="Ragnar.TFrame")
        outer.pack(fill="both", expand=True, padx=12, pady=12)

        self._build_header(outer)
        self._build_hero_strip(outer)

        notebook = ttk.Notebook(outer, style="Ragnar.TNotebook")
        notebook.pack(fill="both", expand=True)

        dashboard_tab = ttk.Frame(notebook)
        scan_tab = ttk.Frame(notebook)
        monitor_tab = ttk.Frame(notebook)
        block_tab = ttk.Frame(notebook)
        history_tab = ttk.Frame(notebook)
        quarantine_tab = ttk.Frame(notebook)
        watch_tab = ttk.Frame(notebook)
        whitelist_tab = ttk.Frame(notebook)
        cloud_tab = ttk.Frame(notebook)

        notebook.add(dashboard_tab, text="Dashboard")
        notebook.add(scan_tab, text="Scan")
        notebook.add(monitor_tab, text="Monitoring")
        notebook.add(block_tab, text="Blocklist")
        notebook.add(history_tab, text="History")
        notebook.add(quarantine_tab, text="Quarantine")
        notebook.add(watch_tab, text="Watch")
        notebook.add(whitelist_tab, text="Whitelist")
        notebook.add(cloud_tab, text="Cloud")

        self._build_dashboard_tab(dashboard_tab)
        self._build_scan_tab(scan_tab)
        self._build_monitor_tab(monitor_tab)
        self._build_block_tab(block_tab)
        self._build_history_tab(history_tab)
        self._build_quarantine_tab(quarantine_tab)
        self._build_watch_tab(watch_tab)
        self._build_whitelist_tab(whitelist_tab)
        self._build_cloud_tab(cloud_tab)

    def _build_header(self, frame: ttk.Frame) -> None:
        header = ttk.Frame(frame)
        header.pack(fill="x", pady=(0, 10))
        if self.logo_image is not None:
            logo_label = ttk.Label(header, image=self.logo_image)
            logo_label.pack(side="left", padx=(0, 10), pady=4)
        title_block = ttk.Frame(header)
        title_block.pack(side="left", fill="x", expand=True)
        ttk.Label(title_block, text="Ragnar Protect", style="RagnarTitle.TLabel").pack(anchor="w")
        ttk.Label(
            title_block,
            text="Protection active Windows, correlation comportementale, sandbox d'executables et reputation cloud backend-only.",
            style="RagnarSubtitle.TLabel",
        ).pack(anchor="w")

    def _build_hero_strip(self, frame: ttk.Frame) -> None:
        hero = tk.Frame(frame, bg=UI_COLORS["bg"])
        hero.pack(fill="x", pady=(0, 10))

        tabs_canvas = tk.Canvas(hero, width=180, height=70, bg=UI_COLORS["bg"], highlightthickness=0)
        tabs_canvas.pack(side="left", padx=(0, 12))
        self._draw_rounded_rect(tabs_canvas, 10, 12, 170, 58, 22, fill=UI_COLORS["card"], outline=UI_COLORS["primary"], width=2)
        for index, color in enumerate((UI_COLORS["danger"], UI_COLORS["warn"], UI_COLORS["ok"])):
            x = 38 + (index * 44)
            tabs_canvas.create_oval(x - 16, 35 - 16, x + 16, 35 + 16, fill=color, outline=UI_COLORS["primary"], width=2)

        self.hero_center_canvas = tk.Canvas(hero, height=150, bg=UI_COLORS["bg"], highlightthickness=0)
        self.hero_center_canvas.pack(side="left", fill="x", expand=True, padx=(0, 12))
        self._draw_rounded_rect(self.hero_center_canvas, 6, 8, 540, 142, 34, fill=UI_COLORS["card"], outline=UI_COLORS["primary"], width=2)
        self.hero_center_canvas.create_text(102, 54, text="✓", fill=UI_COLORS["ok"], font=("Segoe UI", 38, "bold"), anchor="w")
        self.hero_status_item = self.hero_center_canvas.create_text(
            20,
            108,
            text=self.hero_status_text.get(),
            fill=UI_COLORS["primary"],
            font=("Segoe UI Semibold", 36),
            anchor="w",
        )

        side_card = tk.Frame(hero, bg=UI_COLORS["card"], bd=2, relief="solid")
        side_card.pack(side="right", fill="y")
        for variable in (self.hero_system_text, self.hero_background_text, self.hero_network_text):
            tk.Label(
                side_card,
                textvariable=variable,
                bg=UI_COLORS["card"],
                fg=UI_COLORS["primary"],
                font=("Segoe UI Semibold", 11),
                anchor="w",
                justify="left",
                wraplength=210,
                padx=10,
                pady=8,
            ).pack(fill="x")

    def _draw_rounded_rect(
        self,
        canvas: tk.Canvas,
        x1: int,
        y1: int,
        x2: int,
        y2: int,
        radius: int,
        **kwargs,
    ) -> None:
        points = [
            x1 + radius,
            y1,
            x2 - radius,
            y1,
            x2,
            y1,
            x2,
            y1 + radius,
            x2,
            y2 - radius,
            x2,
            y2,
            x2 - radius,
            y2,
            x1 + radius,
            y2,
            x1,
            y2,
            x1,
            y2 - radius,
            x1,
            y1 + radius,
            x1,
            y1,
        ]
        canvas.create_polygon(points, smooth=True, **kwargs)

    def _build_dashboard_tab(self, frame: ttk.Frame) -> None:
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill="x", padx=12, pady=12)
        ttk.Button(toolbar, text="Refresh", command=self.refresh_dashboard).pack(side="left")

        self.dashboard_text = tk.Text(frame, height=8, wrap="word")
        self.dashboard_text.pack(fill="x", padx=12)

        self.dashboard_day_tree = ttk.Treeview(
            frame,
            columns=("day", "scan_count", "suspicious_count", "malicious_count"),
            show="headings",
            height=8,
        )
        for column, width in {
            "day": 140,
            "scan_count": 120,
            "suspicious_count": 140,
            "malicious_count": 140,
        }.items():
            self.dashboard_day_tree.heading(column, text=column)
            self.dashboard_day_tree.column(column, width=width, stretch=True)
        self.dashboard_day_tree.pack(fill="x", padx=12, pady=(12, 12))

        self.dashboard_event_tree = ttk.Treeview(
            frame,
            columns=("event_at", "category", "severity", "message", "path"),
            show="headings",
            height=10,
        )
        for column, width in {
            "event_at": 160,
            "category": 100,
            "severity": 100,
            "message": 320,
            "path": 420,
        }.items():
            self.dashboard_event_tree.heading(column, text=column)
            self.dashboard_event_tree.column(column, width=width, stretch=True)
        self.dashboard_event_tree.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _build_scan_tab(self, frame: ttk.Frame) -> None:
        controls = ttk.Frame(frame)
        controls.pack(fill="x", padx=12, pady=12)

        ttk.Label(controls, text="Target").pack(anchor="w")
        ttk.Entry(controls, textvariable=self.scan_target).pack(fill="x", pady=(0, 8))

        button_row = ttk.Frame(controls)
        button_row.pack(fill="x")
        ttk.Button(button_row, text="Browse File", command=self._choose_file).pack(side="left")
        ttk.Button(button_row, text="Browse Folder", command=self._choose_folder).pack(side="left", padx=8)
        ttk.Button(button_row, text="Run Scan", command=self.run_scan).pack(side="left")
        ttk.Button(button_row, text="Quick Scan", command=self.run_quick_scan).pack(side="left", padx=8)
        ttk.Button(button_row, text="System Audit", command=self.run_system_audit).pack(side="left")
        ttk.Button(button_row, text="Executable Report", command=self.run_executable_report).pack(
            side="left", padx=8
        )
        ttk.Button(button_row, text="Prepare EXE Sandbox", command=self.prepare_exe_sandbox).pack(side="left")

        self.scan_output = tk.Text(frame, wrap="word")
        self.scan_output.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _build_monitor_tab(self, frame: ttk.Frame) -> None:
        content = ttk.Frame(frame)
        content.pack(fill="both", expand=True, padx=12, pady=12)

        labels = [
            ("Real-time monitor", self.monitor_status),
            ("Process blocker", self.blocker_status),
            ("Process guard", self.process_guard_status),
            ("Behavior correlation", self.behavior_status),
            ("Background scan", self.background_status),
            ("Registry monitor", self.registry_status),
            ("Network monitor", self.network_status),
            ("Watch manager", self.watch_status),
            ("GitHub updater", self.updater_status),
            ("Cloud reputation", self.cloud_status),
            ("Wallpaper guard", self.wallpaper_status),
        ]
        for row_index, (label, variable) in enumerate(labels):
            ttk.Label(content, text=label).grid(row=row_index, column=0, sticky="w")
            ttk.Label(content, textvariable=variable).grid(row=row_index, column=1, sticky="w", padx=8)

        ttk.Button(content, text="Start Protection", command=self.start_protection).grid(
            row=len(labels), column=0, pady=16, sticky="w"
        )
        ttk.Button(content, text="Stop Protection", command=self.stop_protection).grid(
            row=len(labels), column=1, pady=16, sticky="w"
        )

        monitored = "\n".join(str(path) for path in self.engine.monitor.paths) or "No monitored directories"
        ttk.Label(content, text="Monitored paths").grid(row=len(labels) + 1, column=0, sticky="nw")
        monitor_paths = tk.Text(content, height=12, wrap="word")
        monitor_paths.grid(row=len(labels) + 2, column=0, columnspan=2, sticky="nsew")
        monitor_paths.insert("1.0", monitored)
        monitor_paths.configure(state="disabled")

        content.columnconfigure(1, weight=1)
        content.rowconfigure(len(labels) + 2, weight=1)

    def _build_block_tab(self, frame: ttk.Frame) -> None:
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill="x", padx=12, pady=12)
        ttk.Button(toolbar, text="Refresh", command=self.refresh_blocking).pack(side="left")

        self.block_tree = ttk.Treeview(
            frame,
            columns=("created_at", "path", "sha256", "reason"),
            show="headings",
            height=8,
        )
        for column, width in {
            "created_at": 150,
            "path": 420,
            "sha256": 180,
            "reason": 260,
        }.items():
            self.block_tree.heading(column, text=column)
            self.block_tree.column(column, width=width, stretch=True)
        self.block_tree.pack(fill="both", expand=False, padx=12)

        self.event_tree = ttk.Treeview(
            frame,
            columns=("blocked_at", "pid", "process_name", "exe_path", "reason"),
            show="headings",
            height=10,
        )
        for column, width in {
            "blocked_at": 150,
            "pid": 80,
            "process_name": 180,
            "exe_path": 420,
            "reason": 240,
        }.items():
            self.event_tree.heading(column, text=column)
            self.event_tree.column(column, width=width, stretch=True)
        self.event_tree.pack(fill="both", expand=True, padx=12, pady=(12, 12))

    def _build_history_tab(self, frame: ttk.Frame) -> None:
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill="x", padx=12, pady=12)
        ttk.Button(toolbar, text="Refresh", command=self.refresh_history).pack(side="left")

        self.history_tree = ttk.Treeview(
            frame,
            columns=("scanned_at", "status", "score", "path", "summary"),
            show="headings",
        )
        for column, width in {
            "scanned_at": 160,
            "status": 90,
            "score": 80,
            "path": 460,
            "summary": 280,
        }.items():
            self.history_tree.heading(column, text=column)
            self.history_tree.column(column, width=width, stretch=True)
        self.history_tree.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _build_quarantine_tab(self, frame: ttk.Frame) -> None:
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill="x", padx=12, pady=12)
        ttk.Button(toolbar, text="Refresh", command=self.refresh_quarantine).pack(side="left")
        ttk.Button(toolbar, text="Restore Selected", command=self.restore_selected_quarantine).pack(
            side="left", padx=8
        )

        self.quarantine_tree = ttk.Treeview(
            frame,
            columns=("id", "quarantined_at", "original_path", "quarantined_path", "reason"),
            show="headings",
        )
        for column, width in {
            "id": 60,
            "quarantined_at": 160,
            "original_path": 320,
            "quarantined_path": 320,
            "reason": 220,
        }.items():
            self.quarantine_tree.heading(column, text=column)
            self.quarantine_tree.column(column, width=width, stretch=True)
        self.quarantine_tree.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _build_watch_tab(self, frame: ttk.Frame) -> None:
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill="x", padx=12, pady=12)
        ttk.Button(toolbar, text="Refresh", command=self.refresh_watch).pack(side="left")

        self.watch_tree = ttk.Treeview(
            frame,
            columns=("status", "clean_scan_count", "cloud_verdict", "sandbox_verdict", "path", "reason"),
            show="headings",
        )
        for column, width in {
            "status": 120,
            "clean_scan_count": 100,
            "cloud_verdict": 120,
            "sandbox_verdict": 120,
            "path": 420,
            "reason": 240,
        }.items():
            self.watch_tree.heading(column, text=column)
            self.watch_tree.column(column, width=width, stretch=True)
        self.watch_tree.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _build_whitelist_tab(self, frame: ttk.Frame) -> None:
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill="x", padx=12, pady=12)
        ttk.Button(toolbar, text="Refresh", command=self.refresh_whitelist).pack(side="left")
        ttk.Button(toolbar, text="Add File", command=self.add_whitelist_file).pack(side="left", padx=8)
        ttk.Button(toolbar, text="Add Folder", command=self.add_whitelist_folder).pack(side="left")
        ttk.Button(toolbar, text="Add Hash", command=self.add_whitelist_hash).pack(side="left", padx=8)
        ttk.Button(toolbar, text="Remove Selected", command=self.remove_selected_whitelist).pack(side="left")

        self.whitelist_tree = ttk.Treeview(
            frame,
            columns=("id", "created_at", "entry_type", "value", "note"),
            show="headings",
        )
        for column, width in {
            "id": 70,
            "created_at": 160,
            "entry_type": 100,
            "value": 520,
            "note": 260,
        }.items():
            self.whitelist_tree.heading(column, text=column)
            self.whitelist_tree.column(column, width=width, stretch=True)
        self.whitelist_tree.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _build_cloud_tab(self, frame: ttk.Frame) -> None:
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill="x", padx=12, pady=12)
        ttk.Button(toolbar, text="Refresh", command=self.refresh_cloud_status).pack(side="left")
        ttk.Button(toolbar, text="Check Updates", command=self.check_updates).pack(side="left", padx=8)
        ttk.Button(toolbar, text="Update YARA Rules", command=self.update_yara_rules).pack(side="left")

        self.cloud_text = tk.Text(frame, height=8, wrap="word")
        self.cloud_text.pack(fill="x", padx=12)

        self.sandbox_tree = ttk.Treeview(
            frame,
            columns=("created_at", "status", "path", "reason"),
            show="headings",
            height=10,
        )
        for column, width in {
            "created_at": 160,
            "status": 120,
            "path": 520,
            "reason": 260,
        }.items():
            self.sandbox_tree.heading(column, text=column)
            self.sandbox_tree.column(column, width=width, stretch=True)
        self.sandbox_tree.pack(fill="both", expand=True, padx=12, pady=(12, 12))

    def _choose_file(self) -> None:
        selected = filedialog.askopenfilename()
        if selected:
            self.scan_target.set(selected)

    def _choose_folder(self) -> None:
        selected = filedialog.askdirectory()
        if selected:
            self.scan_target.set(selected)

    def run_scan(self) -> None:
        target = self.scan_target.get().strip()
        if not target:
            return
        self.scan_output.delete("1.0", "end")
        self.scan_output.insert("1.0", f"Scanning {target} ...\n")
        threading.Thread(target=self._scan_worker, args=(target,), daemon=True).start()

    def run_quick_scan(self) -> None:
        self.scan_output.delete("1.0", "end")
        self.scan_output.insert("1.0", "Running quick scan ...\n")
        threading.Thread(target=self._quick_scan_worker, daemon=True).start()

    def run_system_audit(self) -> None:
        self.scan_output.delete("1.0", "end")
        self.scan_output.insert("1.0", "Running system audit ...\n")
        threading.Thread(target=self._system_audit_worker, daemon=True).start()

    def run_executable_report(self) -> None:
        target = self.scan_target.get().strip()
        if not target:
            return
        self.scan_output.delete("1.0", "end")
        self.scan_output.insert("1.0", f"Scanning executables in {target} ...\n")
        threading.Thread(target=self._executable_report_worker, args=(target,), daemon=True).start()

    def prepare_exe_sandbox(self) -> None:
        target = self.scan_target.get().strip()
        if not target:
            return
        self.scan_output.delete("1.0", "end")
        self.scan_output.insert("1.0", f"Preparing executable sandbox for {target} ...\n")
        threading.Thread(target=self._prepare_exe_sandbox_worker, args=(target,), daemon=True).start()

    def _scan_worker(self, target: str) -> None:
        try:
            results = self.engine.scan_targets([target])
            text = self.engine.scanner.format_results(results) or "No files scanned."
        except Exception as exc:
            text = f"Scan failed: {exc}"
        self.after(0, lambda: self._finish_scan(text))

    def _quick_scan_worker(self) -> None:
        try:
            results = self.engine.quick_scan()
            text = self.engine.scanner.format_results(results) or "Quick scan found no issues."
        except Exception as exc:
            text = f"Quick scan failed: {exc}"
        self.after(0, lambda: self._finish_scan(text))

    def _system_audit_worker(self) -> None:
        try:
            results = self.engine.run_system_audit()
            text = self.engine.scanner.format_results(results) or "System audit found no flagged items."
        except Exception as exc:
            text = f"System audit failed: {exc}"
        self.after(0, lambda: self._finish_scan(text))

    def _executable_report_worker(self, target: str) -> None:
        try:
            target_path = Path(target).expanduser()
            if target_path.is_file():
                target_path = target_path.parent
            report = self.engine.scan_executables(str(target_path))
            report_paths = report.get("report_paths", {})
            text = "\n".join(
                [
                    f"Executable scan target: {report['target']}",
                    f"Files scanned: {report['file_count']}",
                    f"Malicious: {report['malicious_count']}",
                    f"Suspicious: {report['suspicious_count']}",
                    f"Clean: {report['clean_count']}",
                    f"JSON report: {report_paths.get('json', '')}",
                    f"Markdown report: {report_paths.get('markdown', '')}",
                ]
            )
        except Exception as exc:
            text = f"Executable report failed: {exc}"
        self.after(0, lambda: self._finish_scan(text))

    def _prepare_exe_sandbox_worker(self, target: str) -> None:
        try:
            bundle = self.engine.prepare_executable_sandbox(target)
            text = "\n".join(
                [
                    f"Sandbox available: {bundle['available']}",
                    f"Config: {bundle['config_path']}",
                    f"Results: {bundle['results_dir']}",
                    f"Sample copy: {bundle['sample_copy_path']}",
                ]
            )
        except Exception as exc:
            text = f"Sandbox preparation failed: {exc}"
        self.after(0, lambda: self._finish_scan(text))

    def _finish_scan(self, text: str) -> None:
        self.scan_output.delete("1.0", "end")
        self.scan_output.insert("1.0", text)
        self.refresh_dashboard()
        self.refresh_history()
        self.refresh_blocking()
        self.refresh_quarantine()
        self.refresh_watch()
        self.refresh_whitelist()
        self.refresh_cloud_status()
        self.refresh_runtime_status()

    def start_protection(self) -> None:
        self.scan_output.delete("1.0", "end")
        self.scan_output.insert("1.0", "Starting background protection ...\n")
        self._run_async(self._start_protection_worker)

    def stop_protection(self) -> None:
        self.scan_output.delete("1.0", "end")
        self.scan_output.insert("1.0", "Stopping background protection ...\n")
        self._run_async(self._stop_protection_worker)

    def refresh_history(self) -> None:
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        for row in self.engine.database.list_recent_detections():
            self.history_tree.insert(
                "",
                "end",
                values=(
                    row["scanned_at"],
                    row["status"],
                    row["score"],
                    row["path"],
                    row["summary"],
                ),
            )

    def refresh_blocking(self) -> None:
        for tree in (self.block_tree, self.event_tree):
            for item in tree.get_children():
                tree.delete(item)
        for row in self.engine.database.get_active_blocklist():
            self.block_tree.insert(
                "",
                "end",
                values=(row["created_at"], row["path"], row["sha256"], row["reason"]),
            )
        for row in self.engine.database.list_recent_block_events():
            self.event_tree.insert(
                "",
                "end",
                values=(
                    row["blocked_at"],
                    row["pid"],
                    row["process_name"],
                    row["exe_path"],
                    row["reason"],
                ),
            )

    def refresh_quarantine(self) -> None:
        for item in self.quarantine_tree.get_children():
            self.quarantine_tree.delete(item)
        for row in self.engine.list_quarantine_items():
            self.quarantine_tree.insert(
                "",
                "end",
                values=(
                    row["id"],
                    row["quarantined_at"],
                    row["original_path"],
                    row["quarantined_path"],
                    row["reason"],
                ),
            )

    def refresh_watch(self) -> None:
        for item in self.watch_tree.get_children():
            self.watch_tree.delete(item)
        for row in self.engine.database.list_watched_files(limit=200):
            if is_managed_path(str(row.get("path") or "")):
                continue
            self.watch_tree.insert(
                "",
                "end",
                values=(
                    row["status"],
                    row["clean_scan_count"],
                    row["cloud_verdict"],
                    row["sandbox_verdict"],
                    row["path"],
                    row["reason"],
                ),
            )

    def refresh_dashboard(self) -> None:
        summary = self.engine.database.get_dashboard_summary()
        self.dashboard_text.delete("1.0", "end")
        for key, value in summary.items():
            self.dashboard_text.insert("end", f"{key}: {value}\n")
        for item in self.dashboard_day_tree.get_children():
            self.dashboard_day_tree.delete(item)
        for row in self.engine.database.get_detection_counts_by_day(days=7):
            self.dashboard_day_tree.insert(
                "",
                "end",
                values=(row["day"], row["scan_count"], row["suspicious_count"], row["malicious_count"]),
            )
        for item in self.dashboard_event_tree.get_children():
            self.dashboard_event_tree.delete(item)
        for row in self.engine.database.list_recent_dashboard_events(limit=20):
            self.dashboard_event_tree.insert(
                "",
                "end",
                values=(row["event_at"], row["category"], row["severity"], row["message"], row["path"]),
            )

    def refresh_whitelist(self) -> None:
        for item in self.whitelist_tree.get_children():
            self.whitelist_tree.delete(item)
        for row in self.engine.database.list_allowlist_entries():
            self.whitelist_tree.insert(
                "",
                "end",
                values=(row["id"], row["created_at"], row["entry_type"], row["value"], row["note"]),
            )

    def refresh_cloud_status(self) -> None:
        status = self.engine.cloud_status()
        self.cloud_status.set("backend ready" if status.get("available") else "backend unavailable")
        updater = self.engine.update_status()
        self.updater_status.set(str(updater.get("state") or "idle"))
        self.cloud_text.delete("1.0", "end")
        for key, value in status.items():
            self.cloud_text.insert("end", f"{key}: {value}\n")
        if updater:
            self.cloud_text.insert("end", "\n[Updater]\n")
            for key, value in updater.items():
                self.cloud_text.insert("end", f"{key}: {value}\n")
        for item in self.sandbox_tree.get_children():
            self.sandbox_tree.delete(item)
        for row in self.engine.database.list_sandbox_queue(limit=50):
            self.sandbox_tree.insert(
                "",
                "end",
                values=(
                    row["created_at"],
                    row["status"],
                    row["path"],
                    row["reason"],
                ),
            )

    def add_whitelist_file(self) -> None:
        selected = filedialog.askopenfilename()
        if not selected:
            return
        self.engine.database.upsert_allowlist_entry("path", selected, note="GUI allowlisted file")
        self.refresh_whitelist()

    def add_whitelist_folder(self) -> None:
        selected = filedialog.askdirectory()
        if not selected:
            return
        self.engine.database.upsert_allowlist_entry("path", selected, note="GUI allowlisted folder")
        self.refresh_whitelist()

    def add_whitelist_hash(self) -> None:
        value = simpledialog.askstring("Add hash", "SHA256 to allowlist:")
        if not value:
            return
        self.engine.database.upsert_allowlist_entry("hash", value.strip().lower(), note="GUI allowlisted hash")
        self.refresh_whitelist()

    def remove_selected_whitelist(self) -> None:
        selected = self.whitelist_tree.selection()
        if not selected:
            return
        item = self.whitelist_tree.item(selected[0])
        values = item.get("values", [])
        if not values:
            return
        self.engine.database.deactivate_allowlist_entry(int(values[0]))
        self.refresh_whitelist()

    def restore_selected_quarantine(self) -> None:
        selected = self.quarantine_tree.selection()
        if not selected:
            return
        item = self.quarantine_tree.item(selected[0])
        values = item.get("values", [])
        if not values:
            return
        try:
            restored = self.engine.restore_quarantine_item(int(values[0]))
            self.scan_output.delete("1.0", "end")
            self.scan_output.insert("1.0", f"Restored quarantine item to {restored}")
        except Exception as exc:
            self.scan_output.delete("1.0", "end")
            self.scan_output.insert("1.0", f"Restore failed: {exc}")
        self.refresh_quarantine()
        self.refresh_blocking()
        self.refresh_watch()
        self.refresh_dashboard()

    def refresh_runtime_status(self) -> None:
        status = background_status()
        running = bool(status.get("running"))
        self.monitor_status.set("active" if running else "inactive")
        self.blocker_status.set("active" if running and self.engine.blocker.available else ("dependency missing" if self.engine.blocker.available is False else "inactive"))
        self.process_guard_status.set(
            "active" if running and self.engine.process_guard.available else ("dependency missing" if self.engine.process_guard.available is False else "inactive")
        )
        self.behavior_status.set(
            "active" if running and self.engine.behavior_engine.available else ("dependency missing" if self.engine.behavior_engine.available is False else "inactive")
        )
        self.background_status.set("active" if running else "inactive")
        self.registry_status.set("active" if running and self.engine.registry_monitor.available else "inactive")
        self.network_status.set("active" if running and self.engine.network_monitor.available else "inactive")
        self.watch_status.set("active" if running else "idle")
        self.updater_status.set(str(self.engine.update_status().get("state") or ("idle" if not running else "checking")))
        self.wallpaper_status.set("active" if running and self.engine.wallpaper_guard.available else ("windows only" if self.engine.wallpaper_guard.available is False else "inactive"))
        protection_state = "pc protege" if running else "pc en veille"
        self.hero_status_text.set(protection_state)
        self.hero_system_text.set(f"systeme: {'protection active' if running else 'mode attente'}")
        self.hero_background_text.set(
            f"protection arriere plan: {'active' if running else 'inactive'}"
        )
        self.hero_network_text.set(
            f"surveillance reseau: {'active' if running and self.engine.network_monitor.available else 'inactive'}"
        )
        if hasattr(self, "hero_center_canvas") and hasattr(self, "hero_status_item"):
            try:
                self.hero_center_canvas.itemconfigure(self.hero_status_item, text=self.hero_status_text.get())
            except tk.TclError:
                pass

    def _schedule_runtime_refresh(self) -> None:
        if not self.winfo_exists():
            return
        self.refresh_runtime_status()
        self.after(2500, self._schedule_runtime_refresh)

    def _ensure_background_worker_async(self) -> None:
        self._run_async(self._start_protection_worker, silent_if_running=True)

    def _start_protection_worker(self, silent_if_running: bool = False) -> None:
        try:
            result = ensure_background_worker()
            running = bool(result.get("status", {}).get("running"))
            if result.get("already_running"):
                text = "Background protection already active."
                if silent_if_running:
                    text = ""
            elif running:
                text = "Background protection started."
            else:
                text = "Background protection launch requested."
        except Exception as exc:
            text = f"Background protection start failed: {exc}"
        self._post_ui(lambda: self._finish_background_action(text))

    def _stop_protection_worker(self) -> None:
        try:
            result = stop_background_workers()
            text = f"Background protection stop requested for {result['requested']} process(es)."
        except Exception as exc:
            text = f"Background protection stop failed: {exc}"
        self._post_ui(lambda: self._finish_background_action(text))

    def _finish_background_action(self, text: str) -> None:
        if text:
            self.scan_output.delete("1.0", "end")
            self.scan_output.insert("1.0", text)
        self.refresh_dashboard()
        self.refresh_whitelist()
        self.refresh_runtime_status()
        self.refresh_cloud_status()

    def _run_async(self, target, **kwargs) -> None:
        threading.Thread(target=target, kwargs=kwargs, daemon=True).start()

    def check_updates(self) -> None:
        self.scan_output.delete("1.0", "end")
        self.scan_output.insert("1.0", "Checking GitHub updates ...\n")
        self._run_async(self._check_updates_worker)

    def update_yara_rules(self) -> None:
        self.scan_output.delete("1.0", "end")
        self.scan_output.insert("1.0", "Updating community YARA rules ...\n")
        self._run_async(self._update_yara_rules_worker)

    def _check_updates_worker(self) -> None:
        try:
            result = self.engine.check_updates(auto_download=True, auto_apply=True)
            lines = [f"{key}: {value}" for key, value in result.items()]
            text = "\n".join(lines)
        except Exception as exc:
            text = f"Update check failed: {exc}"
        self._post_ui(lambda: self._finish_background_action(text))

    def _update_yara_rules_worker(self) -> None:
        try:
            result = self.engine.update_yara_rules()
            lines = [f"{key}: {value}" for key, value in result.items()]
            text = "\n".join(lines)
        except Exception as exc:
            text = f"YARA update failed: {exc}"
        self._post_ui(lambda: self._finish_background_action(text))

    def _post_ui(self, callback) -> None:
        try:
            if self.winfo_exists():
                self.after(0, callback)
        except tk.TclError:
            return

    def close_window(self) -> None:
        self.destroy()
