from __future__ import annotations

import logging
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("RAGNAR_APP_DIR", str(Path(tempfile.gettempdir()) / "ragnar-protect-tests"))

from ragnar_protect import config
from ragnar_protect.database import Database
from ragnar_protect.error_reporter import ErrorReportMailer


class _FakeResponse:
    def __init__(self, payload: dict[str, object] | None = None, status_code: int = 200) -> None:
        self._payload = payload or {"id": "email_123"}
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"http {self.status_code}")

    def json(self):
        return self._payload


class _FakeSession:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def post(self, url: str, **kwargs):
        self.calls.append({"url": url, **kwargs})
        return _FakeResponse()


class ErrorReporterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.temp_dir.name)
        self.db = Database(self.base / "test.db")
        self.log_dir = self.base / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir = self.base / "error_reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        (self.log_dir / "ragnar_protect.log").write_text("line1\nline2\nboom\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_error_log_record_is_queued_and_written_locally(self) -> None:
        with patch("ragnar_protect.error_reporter.LOG_DIR", self.log_dir), patch(
            "ragnar_protect.error_reporter.ERROR_REPORTS_DIR",
            self.reports_dir,
        ), patch("ragnar_protect.error_reporter.load_resend_api_key", return_value=("re_test", "env")), patch(
            "ragnar_protect.error_reporter.RAGNAR_ERROR_REPORT_TO",
            "botfeur10@gmail.com",
        ), patch(
            "ragnar_protect.error_reporter.RAGNAR_ERROR_REPORT_FROM",
            "Ragnar Protect <onboarding@resend.dev>",
        ):
            reporter = ErrorReportMailer(self.db, session=_FakeSession())
            record = logging.makeLogRecord(
                {
                    "name": "ragnar_protect.test",
                    "levelno": logging.ERROR,
                    "levelname": "ERROR",
                    "msg": "test failure",
                }
            )
            reporter.handle_log_record(record)

        self.assertEqual(self.db.count_pending_error_reports(), 1)
        reports = self.db.list_error_reports(limit=5)
        self.assertEqual(reports[0]["level"], "ERROR")
        self.assertIn("test failure", reports[0]["payload"]["record"]["message"])
        local_reports = list(self.reports_dir.glob("error_report_*.json"))
        self.assertEqual(len(local_reports), 1)

    def test_error_report_send_uses_resend_api_contract(self) -> None:
        fake_session = _FakeSession()
        with patch("ragnar_protect.error_reporter.LOG_DIR", self.log_dir), patch(
            "ragnar_protect.error_reporter.ERROR_REPORTS_DIR",
            self.reports_dir,
        ), patch("ragnar_protect.error_reporter.load_resend_api_key", return_value=("re_test", "env")), patch(
            "ragnar_protect.error_reporter.RAGNAR_ERROR_REPORT_TO",
            "botfeur10@gmail.com",
        ), patch(
            "ragnar_protect.error_reporter.RAGNAR_ERROR_REPORT_FROM",
            "Ragnar Protect <onboarding@resend.dev>",
        ):
            reporter = ErrorReportMailer(self.db, session=fake_session)
            record = logging.makeLogRecord(
                {
                    "name": "ragnar_protect.test",
                    "levelno": logging.ERROR,
                    "levelname": "ERROR",
                    "msg": "send failure",
                }
            )
            reporter.handle_log_record(record)
            item = self.db.claim_next_error_report()
            self.assertIsNotNone(item)
            response = reporter._send_error_report(item or {})

        self.assertEqual(response["id"], "email_123")
        self.assertEqual(len(fake_session.calls), 1)
        call = fake_session.calls[0]
        self.assertEqual(call["url"], "https://api.resend.com/emails")
        self.assertIn("Authorization", call["headers"])
        self.assertEqual(call["headers"]["Authorization"], "Bearer re_test")
        self.assertTrue(call["headers"]["User-Agent"].startswith("RagnarProtect/"))
        self.assertEqual(call["json"]["to"], ["botfeur10@gmail.com"])
        self.assertGreaterEqual(len(call["json"]["attachments"]), 1)

    def test_load_resend_api_key_supports_sidecar_file(self) -> None:
        sidecar = self.base / "RagnarProtect.resend_key.txt"
        sidecar.write_text("re_sidecar_test", encoding="utf-8")
        with patch("ragnar_protect.config.APP_DIR", self.base / "appdir"), patch(
            "ragnar_protect.config._frozen_executable_dir",
            return_value=self.base,
        ), patch.dict(os.environ, {"RAGNAR_RESEND_API_KEY": "", "RAGNAR_RESEND_API_KEY_PATH": ""}, clear=False):
            key, source = config.load_resend_api_key()

        self.assertEqual(key, "re_sidecar_test")
        self.assertEqual(Path(source), sidecar)


if __name__ == "__main__":
    unittest.main()
