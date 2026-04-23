from __future__ import annotations

import json
from typing import Any
from urllib import error, request

from .config import (
    RAGNAR_CLOUD_API_KEY,
    RAGNAR_CLOUD_EVENT_URL,
    RAGNAR_CLOUD_LOOKUP_URL,
    RAGNAR_CLOUD_REQUALIFY_URL,
    RAGNAR_CLOUD_TIMEOUT_SECONDS,
)
from .logging_setup import get_logger
from .models import CloudReputationRecord

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None


class CloudReputationClient:
    def __init__(
        self,
        lookup_url: str | None = None,
        event_url: str | None = None,
        requalify_url: str | None = None,
        api_key: str | None = None,
        timeout_seconds: int | None = None,
    ) -> None:
        self.lookup_url = (lookup_url or RAGNAR_CLOUD_LOOKUP_URL).strip()
        self.event_url = (event_url or RAGNAR_CLOUD_EVENT_URL).strip()
        self.requalify_url = (requalify_url or RAGNAR_CLOUD_REQUALIFY_URL).strip()
        self.api_key = (api_key or RAGNAR_CLOUD_API_KEY).strip()
        self.timeout_seconds = timeout_seconds or RAGNAR_CLOUD_TIMEOUT_SECONDS
        self.logger = get_logger("ragnar_protect.cloud")

    @property
    def misconfigured_secret(self) -> bool:
        lowered = self.api_key.lower()
        return lowered.startswith("sb_secret_") or "service_role" in lowered

    @property
    def available(self) -> bool:
        return bool(self.lookup_url and self.event_url and self.requalify_url and not self.misconfigured_secret)

    def status(self) -> dict[str, object]:
        return {
            "available": self.available,
            "lookup_url": self.lookup_url,
            "event_url": self.event_url,
            "requalify_url": self.requalify_url,
            "has_api_key": bool(self.api_key),
            "misconfigured_secret": self.misconfigured_secret,
            "pending_guidance": (
                "Rotate the leaked sb_secret key and expose only a backend-owned endpoint."
                if self.misconfigured_secret
                else ""
            ),
        }

    def lookup_file(self, payload: dict[str, object]) -> CloudReputationRecord | None:
        if not self.available:
            return None
        response = self._post_json(self.lookup_url, payload)
        if not isinstance(response, dict):
            return None
        verdict = str(response.get("verdict", "unknown")).strip() or "unknown"
        confidence = float(response.get("confidence", 0.0) or 0.0)
        strong = bool(response.get("strong_confirmation")) or (verdict in {"known-bad", "malicious"} and confidence >= 0.8)
        reasons = response.get("reasons", [])
        if not isinstance(reasons, list):
            reasons = [str(reasons)]
        return CloudReputationRecord(
            sha256=str(response.get("sha256") or payload.get("sha256") or ""),
            verdict=verdict,
            confidence=confidence,
            strong_confirmation=strong,
            reasons=[str(item) for item in reasons[:8]],
            publisher=str(response.get("publisher") or payload.get("publisher") or ""),
            thumbprint=str(response.get("thumbprint") or payload.get("thumbprint") or ""),
            metadata={key: value for key, value in response.items() if key not in {"verdict", "confidence", "reasons"}},
        )

    def submit_event(self, payload: dict[str, object]) -> dict[str, object]:
        if not self.available:
            return {"success": False, "reason": "cloud unavailable"}
        response = self._post_json(self.event_url, payload)
        return response if isinstance(response, dict) else {"success": False, "reason": "invalid response"}

    def submit_requalification(self, payload: dict[str, object]) -> dict[str, object]:
        if not self.available:
            return {"success": False, "reason": "cloud unavailable"}
        response = self._post_json(self.requalify_url, payload)
        return response if isinstance(response, dict) else {"success": False, "reason": "invalid response"}

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-ragnar-client": "ragnar-protect",
        }
        if self.api_key:
            headers["apikey"] = self.api_key
        return headers

    def _post_json(self, url: str, payload: dict[str, object]) -> dict[str, Any] | None:
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        try:
            if requests is not None:
                response = requests.post(url, json=payload, headers=self._headers(), timeout=self.timeout_seconds)
                response.raise_for_status()
                return response.json() if response.content else {"success": True}

            req = request.Request(url, data=body, method="POST", headers=self._headers())
            with request.urlopen(req, timeout=self.timeout_seconds) as response:  # noqa: S310
                payload_bytes = response.read()
            if not payload_bytes:
                return {"success": True}
            return json.loads(payload_bytes.decode("utf-8"))
        except (error.URLError, TimeoutError, ValueError) as exc:
            self.logger.warning("cloud request failed | %s | %s", url, exc)
            return None
        except Exception as exc:
            self.logger.warning("cloud request error | %s | %s", url, exc)
            return None
