from __future__ import annotations

import base64
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("RAGNAR_APP_DIR", str(Path(tempfile.gettempdir()) / "ragnar-protect-tests"))

from ragnar_protect.updater import GitHubUpdateManager
from ragnar_protect.version import APP_VERSION


class _FakeResponse:
    def __init__(self, *, json_payload=None, content: bytes = b"", status_code: int = 200) -> None:
        self._json_payload = json_payload
        self._content = content
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"http {self.status_code}")

    def json(self):
        return self._json_payload

    def iter_content(self, chunk_size: int = 1024 * 1024):
        for index in range(0, len(self._content), chunk_size):
            yield self._content[index : index + chunk_size]


class _FakeSession:
    def __init__(self, responses: dict[str, _FakeResponse]) -> None:
        self.responses = responses

    def get(self, url: str, **kwargs):
        if url not in self.responses:
            raise AssertionError(f"Unexpected URL: {url}")
        return self.responses[url]


class UpdaterTests(unittest.TestCase):
    def test_manifest_matching_current_executable_does_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            updates_dir = Path(temp_dir) / "updates"
            updates_dir.mkdir()
            current_exe = Path(temp_dir) / "RagnarProtect.exe"
            current_exe.write_bytes(b"same-binary")
            current_hash = hashlib.sha256(b"same-binary").hexdigest()
            manifest_api_url = "https://api.github.com/repos/ragnar152743/ragnar-protect-MAJ/contents/manifest.json?ref=main"
            manifest_payload = base64.b64encode(
                (
                    "{"
                    f"\"version\":\"{APP_VERSION}\","
                    f"\"sha256\":\"{current_hash}\","
                    "\"exe_url\":\"https://example.com/RagnarProtect.exe\""
                    "}"
                ).encode("utf-8")
            ).decode("ascii")
            session = _FakeSession(
                {
                    manifest_api_url: _FakeResponse(
                        json_payload={
                            "encoding": "base64",
                            "content": manifest_payload,
                        }
                    )
                }
            )
            with patch("ragnar_protect.updater.UPDATES_DIR", updates_dir):
                updater = GitHubUpdateManager(current_executable_path=current_exe, session=session)
                result = updater.check_now(auto_download=True)

            self.assertEqual(result["state"], "up_to_date")
            self.assertEqual(result["current_sha256"], current_hash)
            self.assertFalse(result["downloaded"])

    def test_manifest_change_downloads_and_stages_new_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            updates_dir = Path(temp_dir) / "updates"
            updates_dir.mkdir()
            current_exe = Path(temp_dir) / "RagnarProtect.exe"
            current_exe.write_bytes(b"old-binary")
            new_payload = b"new-binary"
            new_hash = hashlib.sha256(new_payload).hexdigest()
            manifest_api_url = "https://api.github.com/repos/ragnar152743/ragnar-protect-MAJ/contents/manifest.json?ref=main"
            exe_url = "https://raw.githubusercontent.com/ragnar152743/ragnar-protect-MAJ/main/RagnarProtect.exe"
            manifest_payload = base64.b64encode(
                (
                    "{"
                    "\"version\":\"2.2.1\","
                    f"\"sha256\":\"{new_hash}\","
                    f"\"size\":{len(new_payload)},"
                    "\"asset_name\":\"RagnarProtect.exe\","
                    f"\"exe_url\":\"{exe_url}\""
                    "}"
                ).encode("utf-8")
            ).decode("ascii")
            session = _FakeSession(
                {
                    manifest_api_url: _FakeResponse(
                        json_payload={
                            "encoding": "base64",
                            "content": manifest_payload,
                        }
                    ),
                    exe_url: _FakeResponse(content=new_payload),
                }
            )
            with patch("ragnar_protect.updater.UPDATES_DIR", updates_dir):
                updater = GitHubUpdateManager(current_executable_path=current_exe, session=session)
                result = updater.check_now(auto_download=True)

            staged_path = Path(str(result["staged_path"]))
            self.assertEqual(result["state"], "update_staged")
            self.assertTrue(staged_path.exists())
            self.assertEqual(staged_path.read_bytes(), new_payload)

    def test_manifest_change_auto_applies_when_running_from_frozen_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            updates_dir = Path(temp_dir) / "updates"
            updates_dir.mkdir()
            current_exe = Path(temp_dir) / "RagnarProtect.exe"
            current_exe.write_bytes(b"old-binary")
            new_payload = b"new-binary"
            new_hash = hashlib.sha256(new_payload).hexdigest()
            manifest_api_url = "https://api.github.com/repos/ragnar152743/ragnar-protect-MAJ/contents/manifest.json?ref=main"
            exe_url = "https://raw.githubusercontent.com/ragnar152743/ragnar-protect-MAJ/main/RagnarProtect.exe"
            manifest_payload = base64.b64encode(
                (
                    "{"
                    "\"version\":\"2.2.2\","
                    f"\"sha256\":\"{new_hash}\","
                    f"\"size\":{len(new_payload)},"
                    "\"asset_name\":\"RagnarProtect.exe\","
                    f"\"exe_url\":\"{exe_url}\""
                    "}"
                ).encode("utf-8")
            ).decode("ascii")
            session = _FakeSession(
                {
                    manifest_api_url: _FakeResponse(
                        json_payload={
                            "encoding": "base64",
                            "content": manifest_payload,
                        }
                    ),
                    exe_url: _FakeResponse(content=new_payload),
                }
            )
            with patch("ragnar_protect.updater.UPDATES_DIR", updates_dir):
                updater = GitHubUpdateManager(current_executable_path=current_exe, session=session)
                with patch("ragnar_protect.updater.sys.frozen", True, create=True), patch(
                    "ragnar_protect.updater.sys.executable",
                    str(current_exe),
                ), patch.object(
                    updater,
                    "apply_staged_update",
                    return_value={
                        "state": "update_applying",
                        "message": "Background update apply started.",
                        "apply_started": True,
                    },
                ) as apply_mock:
                    result = updater.check_now(auto_download=True, auto_apply=True)

            self.assertEqual(result["state"], "update_applying")
            self.assertTrue(result["apply_started"])
            apply_mock.assert_called_once()

    def test_collect_managed_processes_does_not_capture_current_pid_for_other_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            updates_dir = Path(temp_dir) / "updates"
            updates_dir.mkdir()
            unrelated_exe = Path(temp_dir) / "RagnarProtect.exe"
            unrelated_exe.write_bytes(b"placeholder")
            with patch("ragnar_protect.updater.UPDATES_DIR", updates_dir):
                updater = GitHubUpdateManager(current_executable_path=unrelated_exe, session=_FakeSession({}))
                processes = updater._collect_managed_processes()

            self.assertFalse(any(int(item.get("pid") or 0) == os.getpid() for item in processes))

    def test_sanitize_restart_command_drops_one_shot_update_invocations(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            updates_dir = Path(temp_dir) / "updates"
            updates_dir.mkdir()
            current_exe = Path(temp_dir) / "RagnarProtect.exe"
            current_exe.write_bytes(b"placeholder")
            with patch("ragnar_protect.updater.UPDATES_DIR", updates_dir):
                updater = GitHubUpdateManager(current_executable_path=current_exe, session=_FakeSession({}))
                cleaned = updater._sanitize_restart_command(
                    [str(current_exe), "--check-updates", "--nogui"]
                )

            self.assertEqual(cleaned, [])

    def test_apply_script_avoids_read_only_pid_variable_name(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            updates_dir = Path(temp_dir) / "updates"
            updates_dir.mkdir()
            current_exe = Path(temp_dir) / "RagnarProtect.exe"
            current_exe.write_bytes(b"placeholder")
            with patch("ragnar_protect.updater.UPDATES_DIR", updates_dir):
                updater = GitHubUpdateManager(current_executable_path=current_exe, session=_FakeSession({}))
                script = updater._build_apply_update_script()

            self.assertIn("foreach ($targetPid in $processIds)", script)
            self.assertNotIn("foreach ($pid in $processIds)", script)


if __name__ == "__main__":
    unittest.main()
