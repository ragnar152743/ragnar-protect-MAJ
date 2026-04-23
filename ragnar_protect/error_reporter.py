from __future__ import annotations

import base64
import hashlib
import html
import json
import logging
import os
import platform
import socket
import sys
import threading
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from .config import (
    APP_DIR,
    APP_NAME,
    ERROR_REPORTS_DIR,
    LOG_DIR,
    RAGNAR_ERROR_REPORT_ATTACH_LOG,
    RAGNAR_ERROR_REPORT_FROM,
    RAGNAR_ERROR_REPORT_LOG_TAIL_LINES,
    RAGNAR_ERROR_REPORT_TIMEOUT_SECONDS,
    RAGNAR_ERROR_REPORT_TO,
    ensure_app_dirs,
    load_resend_api_key,
)
from .database import Database
from .logging_setup import get_logger
from .version import APP_VERSION


class ErrorReportMailer:
    def __init__(self, database: Database, session: requests.Session | None = None) -> None:
        self.database = database
        self.session = session or requests.Session()
        self.logger = get_logger("ragnar_protect.error_reporter")
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._hooks_installed = False

    @property
    def configured(self) -> bool:
        key, _ = load_resend_api_key()
        return bool(key and RAGNAR_ERROR_REPORT_TO and RAGNAR_ERROR_REPORT_FROM)

    def start(self) -> None:
        if not self.configured:
            return
        if self._thread and self._thread.is_alive():
            return
        recovered = self.database.requeue_running_error_reports()
        if recovered:
            self.logger.warning("error reporter recovered %s interrupted item(s)", recovered)
        self._install_exception_hooks()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, name="RagnarErrorReporter", daemon=True)
        self._thread.start()
        self.logger.info("error reporter started")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.logger.info("error reporter stopped")

    def status(self) -> dict[str, object]:
        return {
            "configured": self.configured,
            "pending_reports": self.database.count_pending_error_reports(),
            "recipient": RAGNAR_ERROR_REPORT_TO,
            "sender": RAGNAR_ERROR_REPORT_FROM,
            "api_key_source": load_resend_api_key()[1],
            "local_reports_dir": str(ERROR_REPORTS_DIR),
        }

    def handle_log_record(self, record: logging.LogRecord) -> None:
        if record.levelno < logging.ERROR:
            return
        if record.name.startswith("ragnar_protect.error_reporter"):
            return
        try:
            message = record.getMessage()
            traceback_text = ""
            if record.exc_info:
                traceback_text = "".join(traceback.format_exception(*record.exc_info))
            payload = self._build_payload(
                level=record.levelname,
                logger_name=record.name,
                message=message,
                traceback_text=traceback_text,
            )
            subject = f"[{APP_NAME}] {record.levelname} on {payload['machine']['hostname']} | {record.name}"
            fingerprint = self._fingerprint(record.name, message, traceback_text)
            item_id = self.database.enqueue_error_report(record.levelname, record.name, subject, fingerprint, payload)
            self._persist_local_report(item_id, payload)
        except Exception:
            return

    def report_exception(
        self,
        exc_type: type[BaseException],
        exc_value: BaseException,
        exc_traceback,
        source: str = "unhandled",
    ) -> None:
        traceback_text = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        message = str(exc_value)
        payload = self._build_payload(
            level="CRITICAL",
            logger_name=f"ragnar_protect.{source}",
            message=message,
            traceback_text=traceback_text,
        )
        subject = f"[{APP_NAME}] CRITICAL on {payload['machine']['hostname']} | {source}"
        fingerprint = self._fingerprint(source, message, traceback_text)
        item_id = self.database.enqueue_error_report("CRITICAL", source, subject, fingerprint, payload)
        self._persist_local_report(item_id, payload)

    def _install_exception_hooks(self) -> None:
        if self._hooks_installed:
            return
        original_sys_hook = sys.excepthook
        original_thread_hook = getattr(threading, "excepthook", None)

        def _sys_hook(exc_type, exc_value, exc_traceback):
            try:
                self.report_exception(exc_type, exc_value, exc_traceback, source="sys")
            finally:
                original_sys_hook(exc_type, exc_value, exc_traceback)

        def _thread_hook(args):
            try:
                self.report_exception(args.exc_type, args.exc_value, args.exc_traceback, source=f"thread:{args.thread.name}")
            finally:
                if original_thread_hook:
                    original_thread_hook(args)

        sys.excepthook = _sys_hook
        if original_thread_hook:
            threading.excepthook = _thread_hook
        self._hooks_installed = True

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            item = self.database.claim_next_error_report()
            if item is None:
                self._stop_event.wait(5)
                continue
            try:
                response = self._send_error_report(item)
                self.database.complete_error_report(int(item["id"]), True, response=response)
                self.logger.info("error report sent | id=%s", item["id"])
            except Exception as exc:
                self.database.complete_error_report(int(item["id"]), False, error_text=str(exc))
                self.logger.warning("error report delivery failed | id=%s | %s", item["id"], exc)
                self._stop_event.wait(15)

    def _build_payload(
        self,
        *,
        level: str,
        logger_name: str,
        message: str,
        traceback_text: str,
    ) -> dict[str, Any]:
        ensure_app_dirs()
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return {
            "reported_at": now,
            "app_name": APP_NAME,
            "app_version": APP_VERSION,
            "machine": {
                "hostname": socket.gethostname(),
                "platform": platform.platform(),
                "python_version": platform.python_version(),
                "username": os.getenv("USERNAME", ""),
            },
            "process": {
                "pid": os.getpid(),
                "argv": sys.argv,
                "app_dir": str(APP_DIR),
            },
            "record": {
                "level": level,
                "logger_name": logger_name,
                "message": message,
                "traceback": traceback_text,
            },
            "log_path": str(LOG_DIR / "ragnar_protect.log"),
            "log_tail": self._tail_log_lines(RAGNAR_ERROR_REPORT_LOG_TAIL_LINES),
            "context": {
                "pending_error_reports": self.database.count_pending_error_reports(),
                "pending_reputation_events": self.database.count_pending_reputation_events(),
                "recent_block_events": self.database.list_recent_block_events(limit=5),
                "recent_detections": self.database.list_recent_detections(limit=5),
                "recent_error_reports": [
                    {
                        "id": row.get("id"),
                        "created_at": row.get("created_at"),
                        "level": row.get("level"),
                        "logger_name": row.get("logger_name"),
                        "status": row.get("status"),
                    }
                    for row in self.database.list_error_reports(limit=3)
                ],
            },
        }

    def _persist_local_report(self, item_id: int, payload: dict[str, Any]) -> None:
        ensure_app_dirs()
        path = ERROR_REPORTS_DIR / f"error_report_{item_id}.json"
        try:
            path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
        except OSError:
            return

    def _tail_log_lines(self, count: int) -> str:
        path = LOG_DIR / "ragnar_protect.log"
        if not path.exists():
            return ""
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return ""
        return "\n".join(lines[-count:])

    def _fingerprint(self, source: str, message: str, traceback_text: str) -> str:
        digest = hashlib.sha256()
        digest.update(source.encode("utf-8", errors="ignore"))
        digest.update(b"\0")
        digest.update(message.encode("utf-8", errors="ignore"))
        digest.update(b"\0")
        digest.update(traceback_text[:4000].encode("utf-8", errors="ignore"))
        return digest.hexdigest()

    def _send_error_report(self, item: dict[str, Any]) -> dict[str, Any]:
        payload = dict(item.get("payload") or {})
        attachments = []
        report_json = json.dumps(payload, ensure_ascii=True, indent=2).encode("utf-8")
        attachments.append(
            {
                "filename": f"ragnar_error_report_{item['id']}.json",
                "content": base64.b64encode(report_json).decode("ascii"),
            }
        )
        if RAGNAR_ERROR_REPORT_ATTACH_LOG:
            log_path = Path(str(payload.get("log_path", "")))
            if log_path.exists():
                try:
                    log_bytes = log_path.read_bytes()
                    attachments.append(
                        {
                            "filename": "ragnar_protect.log",
                            "content": base64.b64encode(log_bytes).decode("ascii"),
                        }
                    )
                except OSError:
                    pass

        html_body = self._build_html_body(payload)
        text_body = self._build_text_body(payload)
        request_payload = {
            "from": RAGNAR_ERROR_REPORT_FROM,
            "to": [RAGNAR_ERROR_REPORT_TO],
            "subject": str(item["subject"]),
            "html": html_body,
            "text": text_body,
            "attachments": attachments,
            "tags": [
                {"name": "app", "value": "ragnar_protect"},
                {"name": "level", "value": str(item["level"]).lower()},
            ],
        }
        headers = {
            "Authorization": f"Bearer {self._api_key()}",
            "Content-Type": "application/json",
            "User-Agent": f"RagnarProtect/{APP_VERSION}",
            "Idempotency-Key": f"ragnar-error-{item['id']}-{uuid.uuid4()}",
        }
        response = self.session.post(
            "https://api.resend.com/emails",
            headers=headers,
            json=request_payload,
            timeout=RAGNAR_ERROR_REPORT_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        try:
            return response.json()
        except ValueError:
            return {"status_code": response.status_code}

    def _build_text_body(self, payload: dict[str, Any]) -> str:
        record = payload.get("record", {})
        machine = payload.get("machine", {})
        process = payload.get("process", {})
        return "\n".join(
            [
                f"App: {payload.get('app_name', APP_NAME)} {payload.get('app_version', '')}",
                f"ReportedAt: {payload.get('reported_at', '')}",
                f"Host: {machine.get('hostname', '')}",
                f"Platform: {machine.get('platform', '')}",
                f"PID: {process.get('pid', '')}",
                f"Logger: {record.get('logger_name', '')}",
                f"Level: {record.get('level', '')}",
                f"Message: {record.get('message', '')}",
                "",
                "Traceback:",
                str(record.get("traceback", "")),
                "",
                "Log tail:",
                str(payload.get("log_tail", "")),
            ]
        ).strip()

    def _build_html_body(self, payload: dict[str, Any]) -> str:
        record = payload.get("record", {})
        machine = payload.get("machine", {})
        process = payload.get("process", {})
        return (
            "<html><body>"
            f"<h2>{html.escape(APP_NAME)} error report</h2>"
            f"<p><strong>Version:</strong> {html.escape(str(payload.get('app_version', '')))}<br>"
            f"<strong>Reported at:</strong> {html.escape(str(payload.get('reported_at', '')))}<br>"
            f"<strong>Host:</strong> {html.escape(str(machine.get('hostname', '')))}<br>"
            f"<strong>Platform:</strong> {html.escape(str(machine.get('platform', '')))}<br>"
            f"<strong>PID:</strong> {html.escape(str(process.get('pid', '')))}<br>"
            f"<strong>Logger:</strong> {html.escape(str(record.get('logger_name', '')))}<br>"
            f"<strong>Level:</strong> {html.escape(str(record.get('level', '')))}</p>"
            f"<h3>Message</h3><pre>{html.escape(str(record.get('message', '')))}</pre>"
            f"<h3>Traceback</h3><pre>{html.escape(str(record.get('traceback', '')))}</pre>"
            f"<h3>Log tail</h3><pre>{html.escape(str(payload.get('log_tail', '')))}</pre>"
            "</body></html>"
        )

    def _api_key(self) -> str:
        key, _ = load_resend_api_key()
        if not key:
            raise RuntimeError("Resend API key is not configured.")
        return key
