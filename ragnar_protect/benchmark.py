from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .config import PE_EXTENSIONS, REPORTS_DIR, ensure_app_dirs
from .models import BenchmarkReport
from .staged_analysis import StagePipeline


class BenchmarkRunner:
    def __init__(self, scanner, database) -> None:
        self.scanner = scanner
        self.database = database
        self.pipeline = StagePipeline(scanner, database)

    def run(self, corpus_dir: str | Path) -> BenchmarkReport:
        ensure_app_dirs()
        corpus = Path(corpus_dir).expanduser().resolve()
        buckets = {
            "clean": list((corpus / "clean").rglob("*")) if (corpus / "clean").exists() else [],
            "malicious": list((corpus / "malicious").rglob("*")) if (corpus / "malicious").exists() else [],
            "ransomware": list((corpus / "ransomware").rglob("*")) if (corpus / "ransomware").exists() else [],
        }
        initial_counts = {
            label: len([item for item in items if item.is_file()])
            for label, items in buckets.items()
        }
        results: list[dict[str, object]] = []
        clean_false_positives = 0
        detected_bad = 0
        total_bad = 0
        blocked_bad = 0
        total_bad_launchable = 0
        ransomware_interrupted = 0

        for label, items in buckets.items():
            for path in items:
                if not path.is_file():
                    continue
                if path.suffix.lower() in PE_EXTENSIONS:
                    decision, result = self.pipeline.analyze_launch(path)
                    action = decision.action
                    final_verdict = decision.final_verdict
                else:
                    result = self.scanner.scan_file(path)
                    action = "n/a"
                    final_verdict = result.status
                results.append(
                    {
                        "label": label,
                        "path": str(path),
                        "status": final_verdict,
                        "score": result.score,
                        "action": action,
                    }
                )
                if label == "clean" and final_verdict != "clean":
                    clean_false_positives += 1
                if label in {"malicious", "ransomware"}:
                    total_bad += 1
                    if final_verdict != "clean":
                        detected_bad += 1
                    if path.suffix.lower() in PE_EXTENSIONS:
                        total_bad_launchable += 1
                        if action == "kill_quarantine":
                            blocked_bad += 1
                    if label == "ransomware" and final_verdict != "clean":
                        ransomware_interrupted += 1

        report = BenchmarkReport(
            corpus_path=str(corpus),
            clean_count=initial_counts["clean"],
            malicious_count=initial_counts["malicious"],
            ransomware_count=initial_counts["ransomware"],
            detection_coverage=(detected_bad / total_bad * 100.0) if total_bad else 0.0,
            pre_execution_block_rate=(blocked_bad / total_bad_launchable * 100.0) if total_bad_launchable else 0.0,
            ransomware_interruption_rate=(ransomware_interrupted / max(1, initial_counts["ransomware"]) * 100.0),
            false_positive_count=clean_false_positives,
            results=results,
        )
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = REPORTS_DIR / f"benchmark_{timestamp}.json"
        md_path = REPORTS_DIR / f"benchmark_{timestamp}.md"
        json_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        md_path.write_text(self._to_markdown(report), encoding="utf-8")
        report.report_paths = {"json": str(json_path), "markdown": str(md_path)}
        self.database.record_benchmark_run(str(corpus), report.to_dict(), report.observed_at)
        return report

    def _to_markdown(self, report: BenchmarkReport) -> str:
        lines = [
            "# Ragnar Protect Benchmark",
            "",
            f"- Corpus: `{report.corpus_path}`",
            f"- Detection coverage: `{report.detection_coverage:.2f}%`",
            f"- Pre-execution block rate: `{report.pre_execution_block_rate:.2f}%`",
            f"- Ransomware interruption rate: `{report.ransomware_interruption_rate:.2f}%`",
            f"- False positives: `{report.false_positive_count}`",
            "",
            "## Results",
        ]
        for item in report.results[:80]:
            lines.append(f"- `{item['label']}` | `{item['status']}` | `{item['action']}` | `{item['path']}`")
        return "\n".join(lines)
