from __future__ import annotations

import json
import shutil
import textwrap
import uuid
from pathlib import Path

from .config import EXE_SANDBOX_DIR, PE_EXTENSIONS, ensure_app_dirs
from .native_helper import NativeHelperClient


class ExecutableSandbox:
    def __init__(self) -> None:
        ensure_app_dirs()
        self.native_helper = NativeHelperClient()

    @property
    def available(self) -> bool:
        return self.native_helper.available

    @property
    def headless_available(self) -> bool:
        return self.native_helper.available

    def prepare_bundle(self, exe_path: Path) -> dict[str, object]:
        exe_path = exe_path.expanduser().resolve()
        if not exe_path.exists():
            raise FileNotFoundError(exe_path)
        if exe_path.suffix.lower() not in PE_EXTENSIONS:
            raise ValueError(f"Unsupported executable type: {exe_path.suffix}")

        bundle_dir = EXE_SANDBOX_DIR / f"{exe_path.stem}_{uuid.uuid4().hex[:8]}"
        tools_dir = bundle_dir / "tools"
        results_dir = bundle_dir / "results"
        tools_dir.mkdir(parents=True, exist_ok=True)
        results_dir.mkdir(parents=True, exist_ok=True)

        sample_copy = tools_dir / exe_path.name
        shutil.copy2(exe_path, sample_copy)

        config_path = bundle_dir / "local_sandbox.json"
        config = {
            "sample_path": str(exe_path),
            "sample_copy_path": str(sample_copy),
            "results_dir": str(results_dir),
            "backend": "native-helper",
        }
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

        notes = bundle_dir / "README.txt"
        notes.write_text(
            textwrap.dedent(
                f"""\
                Ragnar Protect local sandbox bundle

                Sample path on host:
                {exe_path}

                How it works:
                - The native helper copies the sample into a temporary isolated working directory.
                - The sample is launched hidden with job-object containment.
                - Ragnar observes child processes, dropped files, startup persistence and destructive tooling.
                - The report is written as JSON under:
                {results_dir}
                """
            ),
            encoding="utf-8",
        )

        return {
            "available": self.available,
            "bundle_dir": str(bundle_dir),
            "config_path": str(config_path),
            "results_dir": str(results_dir),
            "launcher_path": str(config_path),
            "sample_copy_path": str(sample_copy),
            "sample_path": str(exe_path),
        }

    def launch_bundle(self, config_path: str) -> bool:
        config = json.loads(Path(config_path).read_text(encoding="utf-8"))
        sample_path = str(config.get("sample_path") or "")
        results_dir = str(config.get("results_dir") or "")
        if not sample_path:
            return False
        report = self.native_helper.run_sandbox(sample_path, timeout_seconds=6, mode="quick")
        if results_dir:
            Path(results_dir).mkdir(parents=True, exist_ok=True)
            (Path(results_dir) / "sandbox-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        return bool(report.get("success", False))

    def start_headless_bundle(self, config_path: str) -> dict[str, object]:
        launched = self.launch_bundle(config_path)
        return {
            "started": launched,
            "sandbox_id": uuid.uuid4().hex,
            "stdout": "",
            "stderr": "" if launched else "native helper sandbox failed",
            "return_code": 0 if launched else 1,
        }

    def stop_headless_bundle(self, sandbox_id: str) -> bool:
        return bool(sandbox_id)
