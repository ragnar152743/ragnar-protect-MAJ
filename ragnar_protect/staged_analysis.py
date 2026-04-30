from __future__ import annotations

from pathlib import Path

from .config import MALICIOUS_THRESHOLD, PE_EXTENSIONS, STAGE2_QUICK_TIMEOUT_SECONDS, STAGE5_DEEP_TIMEOUT_SECONDS, SUSPICIOUS_THRESHOLD
from .logging_setup import get_logger
from .models import FileScanResult, IsolatedExecutionReport, LaunchDecision, ScanFinding, StageVerdict
from .native_helper import NativeHelperClient


RANSOMWARE_KINDS = {
    "shadow_copy_delete",
    "backup_catalog_delete",
    "recovery_impairment",
    "event_log_clear",
    "cipher_wipe",
    "ransomware_note_phrase",
}

STAGE2_ESCALATION_KINDS = RANSOMWARE_KINDS | {
    "memory_injection_api",
    "pe_suspicious_imports",
    "download_and_exec",
    "script_exec_chain",
    "dangerous_script_host",
    "registry_persistence",
    "defender_tamper",
    "cloud_risky",
}


class StagePipeline:
    def __init__(self, scanner, database) -> None:
        self.scanner = scanner
        self.database = database
        self.native_helper = NativeHelperClient()
        self.logger = get_logger("ragnar_protect.stages")

    def analyze_launch(self, path: str | Path) -> tuple[LaunchDecision, FileScanResult]:
        candidate = Path(path).expanduser().resolve()
        stage_verdicts: list[StageVerdict] = []
        stage1 = self.scanner.scan_file(candidate, persist=True)
        stage1_kinds = {finding.kind for finding in stage1.findings}
        stage1_verdict = StageVerdict(
            stage="stage1",
            verdict=stage1.status,
            score=stage1.score,
            summary="Static and reputation scan",
            reasons=[finding.kind for finding in stage1.findings[:10]],
            details={"finding_count": len(stage1.findings)},
        )
        stage_verdicts.append(stage1_verdict)

        quick_report = None
        if self._should_run_quick_stage(candidate, stage1.status, stage1.score, stage1_kinds):
            quick_report = self._run_isolated(candidate, "quick", STAGE2_QUICK_TIMEOUT_SECONDS)
            stage_verdicts.append(self._isolated_to_stage("stage2", quick_report))

        aggregate_stage3 = self._aggregate(stage1, stage_verdicts, stage_name="stage3")
        stage_verdicts.append(aggregate_stage3)

        stage4 = self._evaluate_ransomware(stage1, quick_report)
        stage_verdicts.append(stage4)

        deep_report = None
        stage3_or_4_suspicious = aggregate_stage3.verdict in {"suspicious", "malicious"} or stage4.verdict in {"suspicious", "malicious"}
        if candidate.suffix.lower() in PE_EXTENSIONS and stage3_or_4_suspicious and aggregate_stage3.verdict != "clean":
            deep_report = self._run_isolated(candidate, "deep", STAGE5_DEEP_TIMEOUT_SECONDS)
            stage_verdicts.append(self._isolated_to_stage("stage5", deep_report))

        final_verdict, aggregate_score, action = self._final_decision(stage1, stage_verdicts, quick_report, deep_report)
        final_result = FileScanResult(
            path=stage1.path,
            sha256=stage1.sha256,
            size=stage1.size,
            extension=stage1.extension,
            status=final_verdict,
            score=aggregate_score,
            findings=self._merge_stage_findings(stage1.findings, quick_report, deep_report),
            metadata=dict(stage1.metadata),
            quarantined_path=stage1.quarantined_path,
            blocked=stage1.blocked,
            scanned_at=stage1.scanned_at,
        )
        final_result.metadata["stage_verdicts"] = [item.to_dict() for item in stage_verdicts]
        final_result.metadata["launch_action"] = action
        if quick_report is not None:
            final_result.metadata["sandbox_report"] = quick_report.to_dict()
        if deep_report is not None:
            final_result.metadata["deep_sandbox_report"] = deep_report.to_dict()

        if action == "kill_quarantine" and not final_result.blocked:
            remediation = self.scanner.enforce_block_on_existing_file(candidate, final_result)
            if remediation.get("quarantined_path"):
                final_result.quarantined_path = str(remediation["quarantined_path"])
                final_result.metadata["quarantine_item_id"] = remediation.get("quarantine_item_id")
            final_result.blocked = bool(remediation.get("blocked", False))

        decision = LaunchDecision(
            path=str(candidate),
            sha256=final_result.sha256,
            action=action,
            final_verdict=final_verdict,
            aggregate_score=aggregate_score,
            reason=stage_verdicts[-1].summary if stage_verdicts else final_result.summary(),
            stage_verdicts=stage_verdicts,
            metadata={
                "quick_report": quick_report.to_dict() if quick_report is not None else {},
                "deep_report": deep_report.to_dict() if deep_report is not None else {},
            },
        )
        self.database.record_launch_decision(decision)
        self.scanner.record_external_result(final_result)
        return decision, final_result

    def _should_run_quick_stage(self, candidate: Path, status: str, score: int, finding_kinds: set[str]) -> bool:
        if candidate.suffix.lower() not in PE_EXTENSIONS:
            return False
        if status == "malicious":
            return False
        if status == "suspicious":
            return True
        if score >= max(0, SUSPICIOUS_THRESHOLD - 10):
            return True
        return bool(finding_kinds.intersection(STAGE2_ESCALATION_KINDS))

    def _run_isolated(self, path: Path, mode: str, timeout_seconds: int) -> IsolatedExecutionReport:
        response = self.native_helper.run_sandbox(path, timeout_seconds=timeout_seconds, mode=mode)
        details = dict(response)
        verdict = str(response.get("verdict", "unknown"))
        return IsolatedExecutionReport(
            sample_path=str(path),
            mode=mode,
            verdict=verdict,
            duration_seconds=int(response.get("durationSeconds", timeout_seconds) or timeout_seconds),
            process_started=bool(response.get("processStarted", False)),
            backend=str(response.get("backend", "native-helper")),
            details=details,
        )

    def _isolated_to_stage(self, stage_name: str, report: IsolatedExecutionReport) -> StageVerdict:
        score = 0
        if report.verdict == "malicious":
            score = 65 if stage_name == "stage2" else 80
        elif report.verdict == "suspicious":
            score = 30 if stage_name == "stage2" else 45
        elif report.verdict == "clean":
            score = -15
        bonus_score, bonus_reasons = self._sandbox_signal_bonus(report, stage_name)
        score += bonus_score
        reasons = self._report_reasons(report)
        reasons.extend(item for item in bonus_reasons if item not in reasons)
        return StageVerdict(
            stage=stage_name,
            verdict=report.verdict,
            score=score,
            summary=f"Local isolated execution {report.mode}",
            reasons=reasons,
            details=report.to_dict(),
        )

    def _aggregate(self, stage1: FileScanResult, stage_verdicts: list[StageVerdict], stage_name: str) -> StageVerdict:
        score = stage1.score
        for verdict in stage_verdicts[1:]:
            score += verdict.score
        strong_count = self.scanner.count_strong_confirmations(stage1)
        score += 15 * max(0, strong_count - 1)
        verdict = "clean"
        if any(item.verdict == "malicious" for item in stage_verdicts if item.stage != stage_name):
            verdict = "malicious"
        elif score >= MALICIOUS_THRESHOLD:
            verdict = "malicious"
        elif score >= SUSPICIOUS_THRESHOLD or any(item.verdict == "suspicious" for item in stage_verdicts):
            verdict = "suspicious"
        return StageVerdict(
            stage=stage_name,
            verdict=verdict,
            score=score,
            summary="Aggregate verdict from prior stages",
            reasons=[f"{item.stage}:{item.verdict}" for item in stage_verdicts],
            details={"strong_confirmations": strong_count},
        )

    def _evaluate_ransomware(self, stage1: FileScanResult, report: IsolatedExecutionReport | None) -> StageVerdict:
        finding_kinds = {item.kind for item in stage1.findings}
        score = 0
        reasons: list[str] = []
        if finding_kinds.intersection(RANSOMWARE_KINDS):
            score += 65
            reasons.extend(sorted(finding_kinds.intersection(RANSOMWARE_KINDS)))
        if report is not None:
            destructive = bool(report.details.get("destructiveToolSeen"))
            if destructive:
                score += 50
                reasons.append("destructive_tool_seen")
            if int(report.details.get("runKeyChangeCount", 0) or 0) > 0:
                score += 20
                reasons.append("run_key_change")
            if bool(report.details.get("wallpaperChanged")):
                score += 10
                reasons.append("wallpaper_change")
        verdict = "clean"
        if score >= 80:
            verdict = "malicious"
        elif score >= 25:
            verdict = "suspicious"
        return StageVerdict(
            stage="stage4",
            verdict=verdict,
            score=score,
            summary="Ransomware and sabotage correlation",
            reasons=reasons,
            details={"finding_kinds": sorted(finding_kinds)},
        )

    def _final_decision(
        self,
        stage1: FileScanResult,
        stage_verdicts: list[StageVerdict],
        quick_report: IsolatedExecutionReport | None,
        deep_report: IsolatedExecutionReport | None,
    ) -> tuple[str, int, str]:
        aggregate_score = sum(item.score for item in stage_verdicts if item.stage != "stage1") + stage1.score
        if self._should_allow_after_clean_quick_stage(stage1, stage_verdicts, quick_report, deep_report):
            return "clean", min(aggregate_score, 18), "allow"

        strong_confirmations = self.scanner.count_strong_confirmations(stage1)
        stage4_malicious = any(item.stage == "stage4" and item.verdict == "malicious" for item in stage_verdicts)
        stage5_malicious = any(item.stage == "stage5" and item.verdict == "malicious" for item in stage_verdicts)
        stage2_malicious = any(item.stage == "stage2" and item.verdict == "malicious" for item in stage_verdicts)
        hard_sandbox_signal = bool(
            (quick_report is not None and bool(quick_report.details.get("destructiveToolSeen")))
            or (deep_report is not None and bool(deep_report.details.get("destructiveToolSeen")))
        )
        verdict = "clean"
        if any(item.verdict == "malicious" for item in stage_verdicts):
            verdict = "malicious"
        elif aggregate_score >= MALICIOUS_THRESHOLD:
            verdict = "malicious"
        elif aggregate_score >= SUSPICIOUS_THRESHOLD or any(item.verdict == "suspicious" for item in stage_verdicts):
            verdict = "suspicious"
        action = "allow"
        if verdict == "malicious":
            # Progressive response: require strong confirmation or hard ransomware/sandbox evidence
            # before destructive action.
            if strong_confirmations >= 2 or stage4_malicious or stage5_malicious or (stage2_malicious and hard_sandbox_signal):
                action = "kill_quarantine"
            else:
                verdict = "suspicious"
                action = "observe"
        elif verdict == "suspicious":
            action = "observe"
        return verdict, aggregate_score, action

    def _should_allow_after_clean_quick_stage(
        self,
        stage1: FileScanResult,
        stage_verdicts: list[StageVerdict],
        quick_report: IsolatedExecutionReport | None,
        deep_report: IsolatedExecutionReport | None,
    ) -> bool:
        if quick_report is None or quick_report.verdict != "clean":
            return False
        if deep_report is not None and deep_report.verdict == "malicious":
            return False
        if any(item.stage in {"stage4", "stage5"} and item.verdict == "malicious" for item in stage_verdicts):
            return False
        if self.scanner.count_strong_confirmations(stage1) > 0:
            return False
        return bool(getattr(self.scanner, "is_low_signal_packed_pe_result", lambda _result: False)(stage1))

    def _merge_stage_findings(
        self,
        findings: list[ScanFinding],
        quick_report: IsolatedExecutionReport | None,
        deep_report: IsolatedExecutionReport | None,
    ) -> list[ScanFinding]:
        merged = list(findings)
        for report, kind_prefix in ((quick_report, "quick"), (deep_report, "deep")):
            if report is None:
                continue
            score = 0
            if report.verdict == "malicious":
                score = 40
            elif report.verdict == "suspicious":
                score = 20
            elif report.verdict == "clean":
                score = -5
            merged.append(
                ScanFinding(
                    kind=f"{kind_prefix}_isolated_execution",
                    title=f"{kind_prefix.title()} isolated execution {report.verdict}",
                    score=score,
                    description=f"Native helper isolated execution returned {report.verdict}.",
                    details=report.to_dict(),
                )
            )
        return merged

    def _report_reasons(self, report: IsolatedExecutionReport) -> list[str]:
        reasons: list[str] = []
        if int(report.details.get("childCount", 0) or 0) > 0:
            reasons.append("child_process")
        if int(report.details.get("droppedExecutableCount", 0) or 0) > 0:
            reasons.append("dropped_executable")
        if int(report.details.get("startupDropCount", 0) or 0) > 0:
            reasons.append("startup_drop")
        if int(report.details.get("externalDropCount", 0) or 0) > 0:
            reasons.append("external_drop")
        if int(report.details.get("runKeyChangeCount", 0) or 0) > 0:
            reasons.append("run_key_change")
        if bool(report.details.get("wallpaperChanged")):
            reasons.append("wallpaper_change")
        if bool(report.details.get("destructiveToolSeen")):
            reasons.append("destructive_tool_seen")
        return reasons

    def _sandbox_signal_bonus(self, report: IsolatedExecutionReport, stage_name: str) -> tuple[int, list[str]]:
        details = report.details
        score = 0
        reasons: list[str] = []
        child_count = int(details.get("childCount", 0) or 0)
        dropped_exec_count = int(details.get("droppedExecutableCount", 0) or 0)
        startup_drop_count = int(details.get("startupDropCount", 0) or 0)
        external_drop_count = int(details.get("externalDropCount", 0) or 0)
        run_key_change_count = int(details.get("runKeyChangeCount", 0) or 0)
        destructive_tool = bool(details.get("destructiveToolSeen"))

        if child_count >= 3:
            score += 8 if stage_name == "stage2" else 12
            reasons.append("child_burst")
        if dropped_exec_count > 0:
            score += min(35, 12 + dropped_exec_count * 5)
            reasons.append("dropper_behavior")
        if startup_drop_count > 0:
            score += min(28, 10 + startup_drop_count * 4)
            reasons.append("startup_drop_chain")
        if external_drop_count >= 2:
            score += min(25, 8 + external_drop_count * 3)
            reasons.append("external_drop_chain")
        if run_key_change_count > 0:
            score += min(24, 10 + run_key_change_count * 3)
            reasons.append("runkey_persistence")
        if destructive_tool:
            score += 35
            reasons.append("destructive_tool_chain")
        return score, reasons
