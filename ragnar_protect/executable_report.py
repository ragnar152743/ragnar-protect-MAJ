from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .config import PE_EXTENSIONS, REPORTS_DIR, ensure_app_dirs
from .scanner import RagnarScanner


class ExecutableFolderReport:
    def __init__(self, scanner: RagnarScanner) -> None:
        self.scanner = scanner
        ensure_app_dirs()

    def scan_directory(self, target: Path) -> dict[str, object]:
        target = target.expanduser().resolve()
        if not target.exists():
            raise FileNotFoundError(target)
        files = [path for path in target.rglob("*") if path.is_file() and path.suffix.lower() in PE_EXTENSIONS]
        results = []
        sandbox_budget = 10
        for file_path in files:
            result = self.scanner.scan_file(file_path)
            sandbox_bundle = None
            if result.status != "clean" and sandbox_budget > 0:
                sample_path = Path(result.quarantined_path or result.path)
                try:
                    sandbox_bundle = self.scanner.prepare_executable_sandbox(sample_path)
                    sandbox_budget -= 1
                except Exception as exc:
                    sandbox_bundle = {
                        "available": self.scanner.exe_sandbox.available,
                        "error": str(exc),
                        "sample_path": str(sample_path),
                    }
            results.append(
                {
                    "path": result.path,
                    "status": result.status,
                    "score": result.score,
                    "sha256": result.sha256,
                    "summary": result.summary(),
                    "quarantined_path": result.quarantined_path,
                    "metadata": result.metadata,
                    "findings": [finding.to_dict() for finding in result.findings],
                    "sandbox_bundle": sandbox_bundle,
                }
            )

        report = {
            "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "target": str(target),
            "file_count": len(results),
            "malicious_count": sum(1 for item in results if item["status"] == "malicious"),
            "suspicious_count": sum(1 for item in results if item["status"] == "suspicious"),
            "clean_count": sum(1 for item in results if item["status"] == "clean"),
            "results": results,
        }
        report["report_paths"] = self.write_report(report)
        return report

    def write_report(self, report: dict[str, object]) -> dict[str, str]:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        json_path = REPORTS_DIR / f"executables_scan_{timestamp}.json"
        md_path = REPORTS_DIR / f"executables_scan_{timestamp}.md"
        json_path.write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding="utf-8")
        md_path.write_text(self._to_markdown(report), encoding="utf-8")
        return {"json": str(json_path), "markdown": str(md_path)}

    def _to_markdown(self, report: dict[str, object]) -> str:
        lines = [
            "# Ragnar Protect Executable Scan",
            "",
            f"Target: `{report['target']}`",
            f"Generated at: `{report['generated_at']}`",
            "",
            f"- Files scanned: {report['file_count']}",
            f"- Malicious: {report['malicious_count']}",
            f"- Suspicious: {report['suspicious_count']}",
            f"- Clean: {report['clean_count']}",
            "",
            "## Results",
            "",
        ]
        for item in report["results"]:
            lines.append(f"### `{item['path']}`")
            lines.append(f"- Status: `{item['status']}`")
            lines.append(f"- Score: `{item['score']}`")
            lines.append(f"- SHA256: `{item['sha256']}`")
            lines.append(f"- Summary: {item['summary']}")
            reputation = item.get("metadata", {}).get("reputation", {})
            if reputation:
                lines.append(
                    f"- Reputation: `{reputation.get('verdict', 'unknown')}` (score {reputation.get('score', 0)})"
                )
            pe_meta = item.get("metadata", {}).get("pe", {})
            if pe_meta.get("company_name"):
                lines.append(f"- Publisher: `{pe_meta['company_name']}`")
            signature = item.get("metadata", {}).get("authenticode", {})
            if signature.get("status"):
                lines.append(f"- Authenticode: `{signature['status']}`")
            if item.get("quarantined_path"):
                lines.append(f"- Quarantine: `{item['quarantined_path']}`")
            sandbox_bundle = item.get("sandbox_bundle")
            if sandbox_bundle and sandbox_bundle.get("config_path"):
                lines.append(f"- EXE sandbox: `{sandbox_bundle['config_path']}`")
            for finding in item["findings"][:6]:
                lines.append(f"- Finding: `{finding['title']}` (+{finding['score']})")
            lines.append("")
        return "\n".join(lines)
