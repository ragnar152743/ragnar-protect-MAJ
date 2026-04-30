from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(slots=True)
class ScanFinding:
    kind: str
    title: str
    score: int
    description: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "title": self.title,
            "score": self.score,
            "description": self.description,
            "details": self.details,
        }


@dataclass(slots=True)
class FileScanResult:
    path: str
    sha256: str
    size: int
    extension: str
    status: str
    score: int
    findings: list[ScanFinding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    quarantined_path: str | None = None
    blocked: bool = False
    scanned_at: str = field(default_factory=_utc_now)

    def summary(self) -> str:
        if not self.findings:
            return "No threat indicators"
        return ", ".join(finding.title for finding in self.findings[:4])

    def to_record(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "extension": self.extension,
            "status": self.status,
            "score": self.score,
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": self.metadata,
            "quarantined_path": self.quarantined_path,
            "blocked": self.blocked,
            "scanned_at": self.scanned_at,
            "summary": self.summary(),
        }


@dataclass(slots=True)
class BehaviorIncident:
    incident_type: str
    score: int
    stage: str
    reason: str
    paths: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    process_pid: int | None = None
    process_name: str | None = None
    process_path: str | None = None
    attributed: bool = False
    attribution_confidence: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    observed_at: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_type": self.incident_type,
            "score": self.score,
            "stage": self.stage,
            "reason": self.reason,
            "paths": self.paths,
            "actions": self.actions,
            "process_pid": self.process_pid,
            "process_name": self.process_name,
            "process_path": self.process_path,
            "attributed": self.attributed,
            "attribution_confidence": self.attribution_confidence,
            "metadata": self.metadata,
            "observed_at": self.observed_at,
        }


@dataclass(slots=True)
class WatchedFileState:
    path: str
    sha256: str
    status: str = "under_watch"
    reason: str = ""
    last_verdict: str = "unknown"
    clean_scan_count: int = 0
    quarantined_path: str | None = None
    quarantine_item_id: int | None = None
    cloud_verdict: str = "unknown"
    sandbox_verdict: str = "unknown"
    local_verdict: str = "unknown"
    defender_verdict: str = "unknown"
    confirmed_malware: bool = False
    last_seen_at: str = field(default_factory=_utc_now)
    under_watch_since: str = field(default_factory=_utc_now)
    last_clean_at: str | None = None
    last_behavior_at: str | None = None
    auto_unblocked_at: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "status": self.status,
            "reason": self.reason,
            "last_verdict": self.last_verdict,
            "clean_scan_count": self.clean_scan_count,
            "quarantined_path": self.quarantined_path,
            "quarantine_item_id": self.quarantine_item_id,
            "cloud_verdict": self.cloud_verdict,
            "sandbox_verdict": self.sandbox_verdict,
            "local_verdict": self.local_verdict,
            "defender_verdict": self.defender_verdict,
            "confirmed_malware": self.confirmed_malware,
            "last_seen_at": self.last_seen_at,
            "under_watch_since": self.under_watch_since,
            "last_clean_at": self.last_clean_at,
            "last_behavior_at": self.last_behavior_at,
            "auto_unblocked_at": self.auto_unblocked_at,
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class SandboxExecutionReport:
    sample_path: str
    sha256: str
    verdict: str
    available: bool
    confirms_malware: bool = False
    bundle_dir: str = ""
    config_path: str = ""
    results_dir: str = ""
    execution_log: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    observed_at: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_path": self.sample_path,
            "sha256": self.sha256,
            "verdict": self.verdict,
            "available": self.available,
            "confirms_malware": self.confirms_malware,
            "bundle_dir": self.bundle_dir,
            "config_path": self.config_path,
            "results_dir": self.results_dir,
            "execution_log": self.execution_log,
            "details": self.details,
            "observed_at": self.observed_at,
        }


@dataclass(slots=True)
class CloudReputationRecord:
    sha256: str
    verdict: str
    confidence: float = 0.0
    strong_confirmation: bool = False
    reasons: list[str] = field(default_factory=list)
    publisher: str = ""
    thumbprint: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    observed_at: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "strong_confirmation": self.strong_confirmation,
            "reasons": self.reasons,
            "publisher": self.publisher,
            "thumbprint": self.thumbprint,
            "metadata": self.metadata,
            "observed_at": self.observed_at,
        }


@dataclass(slots=True)
class StageVerdict:
    stage: str
    verdict: str
    score: int
    summary: str
    reasons: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    observed_at: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "verdict": self.verdict,
            "score": self.score,
            "summary": self.summary,
            "reasons": self.reasons,
            "details": self.details,
            "observed_at": self.observed_at,
        }


@dataclass(slots=True)
class LaunchDecision:
    path: str
    sha256: str
    action: str
    final_verdict: str
    aggregate_score: int
    reason: str
    stage_verdicts: list[StageVerdict] = field(default_factory=list)
    observed_at: str = field(default_factory=_utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "action": self.action,
            "final_verdict": self.final_verdict,
            "aggregate_score": self.aggregate_score,
            "reason": self.reason,
            "stage_verdicts": [item.to_dict() for item in self.stage_verdicts],
            "observed_at": self.observed_at,
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class IsolatedExecutionReport:
    sample_path: str
    mode: str
    verdict: str
    duration_seconds: int
    process_started: bool
    backend: str
    details: dict[str, Any] = field(default_factory=dict)
    observed_at: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_path": self.sample_path,
            "mode": self.mode,
            "verdict": self.verdict,
            "duration_seconds": self.duration_seconds,
            "process_started": self.process_started,
            "backend": self.backend,
            "details": self.details,
            "observed_at": self.observed_at,
        }


@dataclass(slots=True)
class RollbackArtifact:
    original_path: str
    snapshot_path: str
    sha256: str
    source_mtime: float
    source_size: int
    reason: str
    created_at: str = field(default_factory=_utc_now)
    restored_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_path": self.original_path,
            "snapshot_path": self.snapshot_path,
            "sha256": self.sha256,
            "source_mtime": self.source_mtime,
            "source_size": self.source_size,
            "reason": self.reason,
            "created_at": self.created_at,
            "restored_at": self.restored_at,
        }


@dataclass(slots=True)
class BenchmarkReport:
    corpus_path: str
    profile: str
    clean_count: int
    malicious_count: int
    ransomware_count: int
    advanced_count: int
    detection_coverage: float
    advanced_detection_rate: float
    pre_execution_block_rate: float
    ransomware_interruption_rate: float
    false_positive_count: int
    report_paths: dict[str, str] = field(default_factory=dict)
    results: list[dict[str, Any]] = field(default_factory=list)
    observed_at: str = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "corpus_path": self.corpus_path,
            "profile": self.profile,
            "clean_count": self.clean_count,
            "malicious_count": self.malicious_count,
            "ransomware_count": self.ransomware_count,
            "advanced_count": self.advanced_count,
            "detection_coverage": self.detection_coverage,
            "advanced_detection_rate": self.advanced_detection_rate,
            "pre_execution_block_rate": self.pre_execution_block_rate,
            "ransomware_interruption_rate": self.ransomware_interruption_rate,
            "false_positive_count": self.false_positive_count,
            "report_paths": self.report_paths,
            "results": self.results,
            "observed_at": self.observed_at,
        }
