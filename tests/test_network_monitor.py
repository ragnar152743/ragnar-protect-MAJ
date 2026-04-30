from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ["RAGNAR_APP_DIR"] = tempfile.mkdtemp(prefix="ragnar-protect-tests-")

from ragnar_protect.models import FileScanResult
from ragnar_protect.network_monitor import NetworkConnectionMonitor


class _FakeScanner:
    def __init__(self) -> None:
        self.recorded: list[FileScanResult] = []

    def record_external_result(self, result: FileScanResult) -> None:
        self.recorded.append(result)

    def scan_file(self, path: Path) -> FileScanResult:
        return FileScanResult(
            path=str(path),
            sha256="fake",
            size=0,
            extension=path.suffix.lower(),
            status="clean",
            score=0,
            findings=[],
            metadata={},
        )


class _FakeDatabase:
    def record_block_event(self, **kwargs) -> None:
        return None


class _FakeProc:
    def __init__(self, name: str, exe: str) -> None:
        self._name = name
        self._exe = exe
        self.killed = False

    def name(self) -> str:
        return self._name

    def exe(self) -> str:
        return self._exe

    def kill(self) -> None:
        self.killed = True


class _FakeRaddr:
    def __init__(self, ip: str, port: int) -> None:
        self.ip = ip
        self.port = port


class _FakeConn:
    def __init__(self, pid: int, ip: str, port: int, status: str = "ESTABLISHED") -> None:
        self.pid = pid
        self.raddr = _FakeRaddr(ip, port)
        self.status = status


class NetworkMonitorTests(unittest.TestCase):
    def test_trusted_browser_burst_on_443_is_ignored(self) -> None:
        scanner = _FakeScanner()
        monitor = NetworkConnectionMonitor(scanner=scanner, database=_FakeDatabase())
        conn = _FakeConn(pid=1111, ip="8.8.8.8", port=443)
        proc = _FakeProc(name="msedge.exe", exe=r"C:\Program Files\Microsoft\Edge\Application\msedge.exe")

        with patch("ragnar_protect.network_monitor.psutil.Process", return_value=proc):
            monitor._inspect_connection(conn, public_count=12)

        self.assertEqual(len(scanner.recorded), 0)

    def test_high_risk_process_connection_generates_detection(self) -> None:
        scanner = _FakeScanner()
        monitor = NetworkConnectionMonitor(scanner=scanner, database=_FakeDatabase())
        conn = _FakeConn(pid=2222, ip="5.5.5.5", port=4444)
        proc = _FakeProc(name="powershell.exe", exe=r"C:\Users\Test\Downloads\powershell.exe")

        with patch("ragnar_protect.network_monitor.psutil.Process", return_value=proc):
            monitor._inspect_connection(conn, public_count=3)

        self.assertEqual(len(scanner.recorded), 1)
        self.assertEqual(scanner.recorded[0].status, "suspicious")
        self.assertGreaterEqual(scanner.recorded[0].score, 28)


if __name__ == "__main__":
    unittest.main()

