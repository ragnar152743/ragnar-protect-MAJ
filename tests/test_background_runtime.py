from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

os.environ.setdefault("RAGNAR_APP_DIR", str(Path(tempfile.gettempdir()) / "ragnar-protect-tests"))

from ragnar_protect import background_runtime


class _FakeChildProcess:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.terminated = False
        self.killed = False

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True


class _FakeWorkerProcess(_FakeChildProcess):
    def __init__(self, pid: int, cmdline: list[str], children: list[_FakeChildProcess] | None = None) -> None:
        super().__init__(pid)
        self.info = {"pid": pid, "cmdline": list(cmdline)}
        self._children = children or []

    def cmdline(self) -> list[str]:
        return list(self.info["cmdline"])

    def children(self, recursive: bool = True) -> list[_FakeChildProcess]:
        return list(self._children)


class BackgroundRuntimeTests(unittest.TestCase):
    def test_background_worker_cmdline_match_requires_protect_and_nogui(self) -> None:
        self.assertTrue(background_runtime.is_background_worker_cmdline(["RagnarProtect.exe", "--protect", "--nogui"]))
        self.assertFalse(background_runtime.is_background_worker_cmdline(["RagnarProtect.exe", "--protect", "--gui"]))
        self.assertFalse(background_runtime.is_background_worker_cmdline(["RagnarProtect.exe"]))

    def test_ensure_background_worker_spawns_detached_process(self) -> None:
        fake_process = MagicMock(pid=4040)
        with patch("ragnar_protect.background_runtime.background_status", return_value={"running": False, "count": 0, "pids": [], "commands": []}), patch(
            "ragnar_protect.background_runtime.subprocess.Popen",
            return_value=fake_process,
        ) as popen_mock:
            result = background_runtime.ensure_background_worker()

        self.assertTrue(result["started"])
        self.assertEqual(result["pid"], 4040)
        popen_kwargs = popen_mock.call_args.kwargs
        self.assertIn("creationflags", popen_kwargs)
        self.assertNotEqual(int(popen_kwargs["creationflags"]), 0)

    def test_stop_background_workers_terminates_matching_process_tree(self) -> None:
        child = _FakeChildProcess(6002)
        worker = _FakeWorkerProcess(6001, ["RagnarProtect.exe", "--protect", "--nogui"], children=[child])
        with patch("ragnar_protect.background_runtime.list_background_workers", return_value=[worker]), patch(
            "ragnar_protect.background_runtime.psutil.wait_procs",
            return_value=([], []),
        ):
            result = background_runtime.stop_background_workers()

        self.assertEqual(result["requested"], 1)
        self.assertIn(6001, result["stopped_pids"])
        self.assertTrue(worker.terminated)
        self.assertTrue(child.terminated)

    def test_register_and_unregister_background_worker_state_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "background_worker.json"
            with patch("ragnar_protect.background_runtime.BACKGROUND_WORKER_STATE", state_path):
                payload = background_runtime.register_background_worker(reduced_mode=True)
                self.assertTrue(state_path.exists())
                self.assertEqual(int(payload["pid"]), os.getpid())
                cleared = background_runtime.unregister_background_worker(expected_pid=os.getpid())
                self.assertTrue(cleared)
                self.assertFalse(state_path.exists())


if __name__ == "__main__":
    unittest.main()
