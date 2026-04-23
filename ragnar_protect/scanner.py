from __future__ import annotations

import base64
import hashlib
import io
import math
import os
import re
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Callable, Iterable

from .amsi import AmsiScanner
from .authenticode import get_signature_status
from .cloud_reputation import CloudReputationClient
from .config import (
    APP_DIR,
    ARCHIVE_EXTENSIONS,
    AUTHENTICODE_EXTENSIONS,
    DOUBLE_EXTENSION_LURES,
    MALICIOUS_THRESHOLD,
    MAX_ARCHIVE_DEPTH,
    MAX_ARCHIVE_MEMBER_BYTES,
    MAX_ARCHIVE_TOTAL_BYTES,
    MAX_BASE64_BLOB_LENGTH,
    MAX_FILE_SCAN_BYTES,
    PE_EXTENSIONS,
    QUARANTINE_DIR,
    SENSITIVE_EXTENSIONS,
    SUSPICIOUS_IMPORTS,
    SUSPICIOUS_THRESHOLD,
    TEXT_SCRIPT_EXTENSIONS,
    USER_SPACE_HINTS,
    ensure_app_dirs,
    is_managed_path,
)
from .database import Database
from .defender_bridge import DefenderBridge
from .exe_sandbox import ExecutableSandbox
from .logging_setup import get_logger
from .models import FileScanResult, ScanFinding
from .rule_loader import compile_behavior_rules
from .sandbox import LimitedSandbox
from .yara_support import YaraScanner

try:
    import pefile  # type: ignore
except Exception:  # pragma: no cover
    pefile = None


TEXT_ENCODINGS = ("utf-8", "utf-16", "utf-16-le", "latin-1")
ASCII_STRINGS_RE = re.compile(rb"[ -~]{5,}")
BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/=]{80,}")
PE_STRING_RULE_NAMES = {
    "shadow_copy_delete",
    "backup_catalog_delete",
    "recovery_impairment",
    "event_log_clear",
    "cipher_wipe",
    "defender_tamper",
    "ransomware_note_phrase",
}


class RagnarScanner:
    def __init__(self, database: Database, amsi: AmsiScanner | None = None) -> None:
        ensure_app_dirs()
        self.database = database
        self.amsi = amsi or AmsiScanner()
        self.cloud = CloudReputationClient()
        self.defender = DefenderBridge()
        self.logger = get_logger("ragnar_protect.scanner")
        self.sandbox = LimitedSandbox()
        self.exe_sandbox = ExecutableSandbox()
        self.compiled_patterns = compile_behavior_rules()
        self.yara = YaraScanner()
        self._result_callbacks: list[Callable[[FileScanResult], None]] = []

    def register_result_callback(self, callback: Callable[[FileScanResult], None]) -> None:
        if callback not in self._result_callbacks:
            self._result_callbacks.append(callback)

    def scan_path(self, target: Path) -> list[FileScanResult]:
        target = target.expanduser()
        if not target.exists():
            raise FileNotFoundError(target)
        if target.is_file():
            return [self.scan_file(target)]

        results: list[FileScanResult] = []
        for file_path in target.rglob("*"):
            if not file_path.is_file():
                continue
            try:
                results.append(self.scan_file(file_path))
            except Exception as exc:
                self.logger.exception("scan failed for %s: %s", file_path, exc)
        return results

    def scan_file(self, file_path: Path, persist: bool = True, archive_depth: int = 0) -> FileScanResult:
        file_path = file_path.expanduser().resolve()
        size = file_path.stat().st_size
        sha256 = self._sha256_file(file_path)
        data = self._read_scan_bytes(file_path)
        return self._scan_bytes(
            display_path=str(file_path),
            data=data,
            full_size=size,
            extension=self._normalized_extension(file_path),
            sha256=sha256,
            on_disk_path=file_path,
            archive_depth=archive_depth,
            persist=persist,
            persist_clean=True,
            allow_archive_scan=True,
            base_metadata={"artifact_type": "file", "on_disk": True},
        )

    def scan_artifact(
        self,
        display_path: str,
        content: str | bytes,
        extension: str = ".artifact",
        metadata: dict[str, object] | None = None,
        persist: bool = True,
        persist_clean: bool = False,
    ) -> FileScanResult:
        data = content.encode("utf-8", errors="ignore") if isinstance(content, str) else content
        sha256 = hashlib.sha256(data).hexdigest()
        artifact_metadata = {"artifact_type": "logical", **(metadata or {})}
        return self._scan_bytes(
            display_path=display_path,
            data=data,
            full_size=len(data),
            extension=extension,
            sha256=sha256,
            on_disk_path=None,
            archive_depth=0,
            persist=persist,
            persist_clean=persist_clean,
            allow_archive_scan=False,
            base_metadata=artifact_metadata,
        )

    def _scan_bytes(
        self,
        display_path: str,
        data: bytes,
        full_size: int,
        extension: str,
        sha256: str,
        on_disk_path: Path | None,
        archive_depth: int,
        persist: bool,
        persist_clean: bool,
        allow_archive_scan: bool,
        base_metadata: dict[str, object] | None = None,
    ) -> FileScanResult:
        findings: list[ScanFinding] = []
        metadata: dict[str, object] = {
            "archive_depth": archive_depth,
            "sampled_bytes": len(data),
            "full_size": full_size,
        }
        if base_metadata:
            metadata.update(base_metadata)
        score = 0
        path_obj = Path(display_path)

        if extension in SENSITIVE_EXTENSIONS:
            findings.append(
                ScanFinding(
                    kind="sensitive_extension",
                    title="Sensitive extension",
                    score=8,
                    description=f"{extension} is a monitored high-risk extension.",
                )
            )
            score += 8

        if len(path_obj.suffixes) >= 2:
            if path_obj.suffixes[-2].lower() in DOUBLE_EXTENSION_LURES and extension in SENSITIVE_EXTENSIONS:
                findings.append(
                    ScanFinding(
                        kind="double_extension",
                        title="Double extension lure",
                        score=20,
                        description="Filename uses a lure extension before an executable or script extension.",
                    )
                )
                score += 20

        entropy = self._shannon_entropy(data)
        metadata["entropy"] = round(entropy, 3)
        if entropy >= 7.25 and extension in (PE_EXTENSIONS | TEXT_SCRIPT_EXTENSIONS):
            findings.append(
                ScanFinding(
                    kind="high_entropy",
                    title="High entropy content",
                    score=15,
                    description="Content entropy suggests obfuscation or packing.",
                    details={"entropy": round(entropy, 3)},
                )
            )
            score += 15

        text = None if extension in PE_EXTENSIONS else self._decode_text(data)
        if text:
            text_findings, text_score = self._apply_text_rules(text)
            findings.extend(text_findings)
            score += text_score

            long_hits = [item for item in BASE64_BLOB_RE.findall(text) if len(item) >= MAX_BASE64_BLOB_LENGTH]
            if long_hits:
                decoded_count = sum(1 for blob in long_hits[:5] if self._can_decode_base64(blob))
                findings.append(
                    ScanFinding(
                        kind="base64_blob",
                        title="Embedded Base64 payload",
                        score=15,
                        description="Large Base64-looking blobs were found in the content.",
                        details={"blob_count": len(long_hits), "decodable_samples": decoded_count},
                    )
                )
                score += 15

            if extension in TEXT_SCRIPT_EXTENSIONS and on_disk_path is not None:
                sandbox_report = self.sandbox.analyze_script(on_disk_path, text)
                metadata["sandbox"] = sandbox_report
                if sandbox_report.get("parse_error_count", 0) == 0 and sandbox_report.get("base64_blob_count", 0):
                    findings.append(
                        ScanFinding(
                            kind="sandbox_script_payload",
                            title="Sandbox script payload indicators",
                            score=10,
                            description="Static sandbox detected opaque payload material inside the script.",
                            details={
                                "base64_blob_count": sandbox_report.get("base64_blob_count", 0),
                                "token_count": sandbox_report.get("token_count", 0),
                            },
                        )
                    )
                    score += 10

            if extension in TEXT_SCRIPT_EXTENSIONS:
                amsi_report = self.amsi.scan_text(text, display_path)
                metadata["amsi"] = amsi_report
                if amsi_report.get("available") and amsi_report.get("is_malware"):
                    findings.append(
                        ScanFinding(
                            kind="amsi_block",
                            title="AMSI malware verdict",
                            score=90,
                            description="Windows AMSI marked the content as malware.",
                            details={"amsi_result": amsi_report.get("result")},
                        )
                    )
                    score += 90

        if text is None and extension not in PE_EXTENSIONS:
            string_findings, string_score = self._apply_binary_string_rules(data)
            findings.extend(string_findings)
            score += string_score

        pe_findings, pe_score, pe_metadata = self._inspect_pe(data, on_disk_path, extension)
        findings.extend(pe_findings)
        score += pe_score
        if pe_metadata:
            metadata["pe"] = pe_metadata

        pe_string_findings, pe_string_score = self._apply_pe_string_rules(data, extension)
        findings.extend(pe_string_findings)
        score += pe_string_score

        yara_findings, yara_score = self._apply_yara(data, on_disk_path, extension, metadata)
        findings.extend(yara_findings)
        score += yara_score

        if allow_archive_scan and (extension in ARCHIVE_EXTENSIONS or zipfile.is_zipfile(io.BytesIO(data))):
            archive_findings, archive_score, archive_metadata = self._inspect_archive(
                display_path=display_path,
                data=data,
                archive_depth=archive_depth,
            )
            findings.extend(archive_findings)
            score += archive_score
            if archive_metadata:
                metadata["archive"] = archive_metadata

        if on_disk_path is not None and extension in AUTHENTICODE_EXTENSIONS:
            signature = get_signature_status(str(on_disk_path))
            metadata["authenticode"] = signature
            status = signature.get("status", "Unknown")
            if status not in {"Valid", "Unknown"}:
                signature_score = 25 if status in {"HashMismatch", "NotTrusted", "NotSignatureValid"} else 12
                findings.append(
                    ScanFinding(
                        kind="authenticode_issue",
                        title="Authenticode issue",
                        score=signature_score,
                        description=f"Signature status is {status}.",
                        details=signature,
                    )
                )
                score += signature_score
            elif status == "NotSigned" and extension in PE_EXTENSIONS:
                findings.append(
                    ScanFinding(
                        kind="unsigned_pe",
                        title="Unsigned PE file",
                        score=10,
                        description="Portable executable is unsigned.",
                        details=signature,
                    )
                )
                score += 10

        if self._should_use_defender(on_disk_path, extension, score):
            defender_report = self.defender.scan_file(on_disk_path)
            metadata["defender"] = defender_report
            if defender_report.get("is_malware"):
                findings.append(
                    ScanFinding(
                        kind="defender_malware",
                        title="Microsoft Defender malware verdict",
                        score=95,
                        description="Microsoft Defender custom scan flagged the file as malware.",
                        details=defender_report,
                    )
                )
                score += 95
            elif defender_report.get("requires_attention"):
                findings.append(
                    ScanFinding(
                        kind="defender_attention",
                        title="Microsoft Defender requires attention",
                        score=15,
                        description="Microsoft Defender scan returned an attention-required state.",
                        details=defender_report,
                    )
                )
                score += 15

        reputation, reputation_adjustment, reputation_findings = self._build_local_reputation(
            sha256=sha256,
            extension=extension,
            on_disk_path=on_disk_path,
            metadata=metadata,
        )
        if reputation:
            metadata["reputation"] = reputation
        if reputation_findings:
            findings.extend(reputation_findings)
        if reputation_adjustment:
            if reputation:
                reputation["risk_adjustment"] = reputation_adjustment
            score = max(0, score + reputation_adjustment)

        cloud_fingerprint = self._build_cloud_fingerprint(metadata)
        if cloud_fingerprint:
            metadata["cloud_fingerprint"] = cloud_fingerprint
        cloud_record, cloud_score, cloud_findings = self._lookup_cloud_reputation(
            sha256=sha256,
            display_path=display_path,
            extension=extension,
            on_disk_path=on_disk_path,
            metadata=metadata,
        )
        if cloud_record:
            metadata["cloud_reputation"] = cloud_record
        if cloud_findings:
            findings.extend(cloud_findings)
            score += cloud_score

        status = "clean"
        if score >= MALICIOUS_THRESHOLD or any(f.kind == "amsi_block" for f in findings):
            status = "malicious"
        elif score >= SUSPICIOUS_THRESHOLD:
            status = "suspicious"

        if status == "malicious" and extension in PE_EXTENSIONS and self._should_cap_packed_pe_verdict(findings, metadata):
            status = "suspicious"
            metadata["verdict_cap"] = "packed-pe-heuristics-only"

        result = FileScanResult(
            path=display_path,
            sha256=sha256,
            size=full_size,
            extension=extension,
            status=status,
            score=score,
            findings=findings,
            metadata=metadata,
        )

        if (
            status == "malicious"
            and on_disk_path is not None
            and self._is_user_space_path(str(on_disk_path))
            and not self._is_managed_app_path(on_disk_path)
        ):
            quarantine_path = self._quarantine(on_disk_path, sha256)
            if quarantine_path:
                result.quarantined_path = quarantine_path
                quarantine_item_id = self.database.record_quarantine_item(
                    original_path=str(on_disk_path),
                    quarantined_path=quarantine_path,
                    sha256=sha256,
                    reason=result.summary(),
                )
                result.metadata["quarantine_item_id"] = quarantine_item_id
            self.database.upsert_blocked_file(
                path=str(on_disk_path),
                sha256=sha256,
                reason=result.summary(),
                source="scan",
            )
            result.blocked = True
        elif status == "malicious" and on_disk_path is not None:
            metadata["remediation_skipped"] = "non-user-space-path"

        if persist and (persist_clean or status != "clean"):
            self.database.record_detection(result)

        artifact_type = str(metadata.get("artifact_type", "file"))
        if not (status == "clean" and artifact_type != "file"):
            self.logger.info("scan result | %s | status=%s score=%s", display_path, result.status, result.score)
        self._emit_result(result)
        return result

    def _apply_text_rules(self, text: str) -> tuple[list[ScanFinding], int]:
        return self._apply_selected_text_rules(text)

    def _apply_selected_text_rules(self, text: str, allowed_names: set[str] | None = None) -> tuple[list[ScanFinding], int]:
        findings: list[ScanFinding] = []
        score = 0
        for pattern in self.compiled_patterns:
            if allowed_names is not None and str(pattern["name"]) not in allowed_names:
                continue
            matches = pattern["regex"].findall(text)
            if not matches:
                continue
            findings.append(
                ScanFinding(
                    kind=pattern["name"],
                    title=pattern["description"],
                    score=int(pattern["score"]),
                    description=pattern["description"],
                    details={"match_count": len(matches)},
                )
            )
            score += int(pattern["score"])
        return findings, score

    def _apply_pe_string_rules(self, data: bytes, extension: str) -> tuple[list[ScanFinding], int]:
        if extension not in PE_EXTENSIONS:
            return [], 0
        strings = [
            match.decode("latin-1", errors="ignore")
            for match in ASCII_STRINGS_RE.findall(data[:MAX_FILE_SCAN_BYTES])
        ]
        if not strings:
            return [], 0
        return self._apply_selected_text_rules("\n".join(strings[:4000]), allowed_names=PE_STRING_RULE_NAMES)

    def _apply_yara(
        self, data: bytes, on_disk_path: Path | None, extension: str, metadata: dict[str, object]
    ) -> tuple[list[ScanFinding], int]:
        artifact_type = str(metadata.get("artifact_type", ""))
        if extension in PE_EXTENSIONS:
            allowed_tags = {"pe"}
        else:
            if artifact_type == "file" and extension not in TEXT_SCRIPT_EXTENSIONS:
                return [], 0
            allowed_tags = {"script", "generic"}

        if not self.yara.available:
            return [], 0

        if on_disk_path is not None:
            matches = self.yara.scan_file(str(on_disk_path), allowed_tags=allowed_tags)
        else:
            matches = self.yara.scan_bytes(data, allowed_tags=allowed_tags)
        findings: list[ScanFinding] = []
        score = 0
        for match in matches:
            meta = match.get("meta", {})
            severity = int(meta.get("severity", 50))
            severity = max(20, min(90, severity))
            findings.append(
                ScanFinding(
                    kind=f"yara_{str(match['rule']).lower()}",
                    title=f"YARA rule matched: {match['rule']}",
                    score=severity,
                    description=str(meta.get("description", "YARA rule match")),
                    details=match,
                )
            )
            score += severity
        return findings, score

    def _apply_binary_string_rules(self, data: bytes) -> tuple[list[ScanFinding], int]:
        strings = [
            match.decode("latin-1", errors="ignore")
            for match in ASCII_STRINGS_RE.findall(data[:MAX_FILE_SCAN_BYTES])
        ]
        if not strings:
            return [], 0
        return self._apply_text_rules("\n".join(strings[:4000]))

    def _inspect_pe(
        self, data: bytes, on_disk_path: Path | None, extension: str
    ) -> tuple[list[ScanFinding], int, dict[str, object]]:
        if pefile is None or extension not in PE_EXTENSIONS:
            return [], 0, {}
        findings: list[ScanFinding] = []
        metadata: dict[str, object] = {}
        score = 0
        try:
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                ]
            )
            imports: set[str] = set()
            imported_libraries: set[str] = set()
            imported_function_count = 0
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    if getattr(entry, "dll", None):
                        imported_libraries.add(entry.dll.decode("ascii", errors="ignore"))
                    for imported in entry.imports:
                        if imported.name:
                            imports.add(imported.name.decode("ascii", errors="ignore"))
                            imported_function_count += 1

            metadata["imported_function_count"] = imported_function_count
            metadata["imported_libraries"] = sorted(item for item in imported_libraries if item)[:24]

            suspicious = sorted(imports.intersection(SUSPICIOUS_IMPORTS))
            if suspicious:
                import_score = min(45, 10 * len(suspicious))
                findings.append(
                    ScanFinding(
                        kind="pe_suspicious_imports",
                        title="Suspicious PE imports",
                        score=import_score,
                        description="Portable executable imports APIs often used for injection or process tampering.",
                        details={"imports": suspicious},
                    )
                )
                score += import_score
                metadata["suspicious_imports"] = suspicious

            rwx_sections: list[str] = []
            upx_sections: list[str] = []
            high_entropy_exec_sections: list[dict[str, object]] = []
            section_rows: list[dict[str, object]] = []
            for section in pe.sections:
                name = section.Name.decode("ascii", errors="ignore").strip("\x00")
                entropy = round(float(section.get_entropy()), 3)
                executable = bool(section.IMAGE_SCN_MEM_EXECUTE)
                writable = bool(section.IMAGE_SCN_MEM_WRITE)
                section_rows.append(
                    {
                        "name": name,
                        "entropy": entropy,
                        "virtual_size": int(section.Misc_VirtualSize),
                        "raw_size": int(section.SizeOfRawData),
                        "executable": executable,
                        "writable": writable,
                    }
                )
                if writable and executable:
                    rwx_sections.append(name)
                if name.upper().startswith("UPX"):
                    upx_sections.append(name)
                if executable and entropy >= 7.2:
                    high_entropy_exec_sections.append({"name": name, "entropy": entropy})
            if rwx_sections:
                findings.append(
                    ScanFinding(
                        kind="pe_rwx_section",
                        title="Executable writable PE section",
                        score=25,
                        description="PE contains sections that are both writable and executable.",
                        details={"sections": rwx_sections},
                    )
                )
                score += 25
                metadata["rwx_sections"] = rwx_sections

            if upx_sections:
                findings.append(
                    ScanFinding(
                        kind="pe_upx_sections",
                        title="UPX-like PE sections",
                        score=32,
                        description="Portable executable exposes classic UPX section names.",
                        details={"sections": upx_sections},
                    )
                )
                score += 32
                metadata["upx_sections"] = upx_sections

            if high_entropy_exec_sections and imported_function_count <= 18:
                findings.append(
                    ScanFinding(
                        kind="pe_packer_heuristic",
                        title="Packed executable heuristic",
                        score=22,
                        description="Executable sections are highly entropic while the import surface is unusually small.",
                        details={
                            "sections": high_entropy_exec_sections[:6],
                            "imported_function_count": imported_function_count,
                        },
                    )
                )
                score += 22

            overlay_offset = pe.get_overlay_data_start_offset()
            if overlay_offset is not None:
                overlay_size = max(0, len(data) - overlay_offset)
                metadata["overlay_size"] = overlay_size
                if overlay_size >= 4096 and imported_function_count <= 10:
                    findings.append(
                        ScanFinding(
                            kind="pe_overlay_stub",
                            title="Overlay plus tiny import table",
                            score=14,
                            description="Executable carries overlay data alongside a very small import table, a pattern often seen in packed droppers.",
                            details={"overlay_size": overlay_size, "imported_function_count": imported_function_count},
                        )
                    )
                    score += 14

            version_info = self._extract_pe_version_info(pe)
            if version_info:
                metadata.update(version_info)

            metadata["sections"] = section_rows[:12]
            metadata["section_names"] = [item["name"] for item in section_rows]
            metadata["entry_point_rva"] = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            metadata["machine"] = hex(int(pe.FILE_HEADER.Machine))
            metadata["number_of_sections"] = len(pe.sections)
            metadata["is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
            metadata["pe_path"] = str(on_disk_path) if on_disk_path else ""
        except Exception:
            return [], 0, {}
        return findings, score, metadata

    def _inspect_archive(
        self, display_path: str, data: bytes, archive_depth: int
    ) -> tuple[list[ScanFinding], int, dict[str, object]]:
        findings: list[ScanFinding] = []
        metadata: dict[str, object] = {"members": []}
        score = 0
        if archive_depth >= MAX_ARCHIVE_DEPTH:
            findings.append(
                ScanFinding(
                    kind="archive_depth_limit",
                    title="Archive depth limit reached",
                    score=5,
                    description="Nested archive depth exceeded configured maximum.",
                )
            )
            return findings, 5, metadata

        total_processed = 0
        malicious_children = 0
        suspicious_children = 0

        def handle_member(member_name: str, member_bytes: bytes) -> None:
            nonlocal total_processed, malicious_children, suspicious_children
            total_processed += len(member_bytes)
            child_result = self._scan_bytes(
                display_path=f"{display_path}!{member_name}",
                data=member_bytes,
                full_size=len(member_bytes),
                extension=self._normalized_extension(Path(member_name)),
                sha256=hashlib.sha256(member_bytes).hexdigest(),
                on_disk_path=None,
                archive_depth=archive_depth + 1,
                persist=False,
                persist_clean=False,
                allow_archive_scan=True,
                base_metadata={"artifact_type": "archive-member", "container": display_path},
            )
            if child_result.status == "malicious":
                malicious_children += 1
            elif child_result.status == "suspicious":
                suspicious_children += 1
            metadata["members"].append(
                {
                    "path": child_result.path,
                    "status": child_result.status,
                    "score": child_result.score,
                    "summary": child_result.summary(),
                }
            )

        try:
            if zipfile.is_zipfile(io.BytesIO(data)):
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    for info in archive.infolist():
                        if info.is_dir() or info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                            continue
                        if total_processed + info.file_size > MAX_ARCHIVE_TOTAL_BYTES:
                            break
                        handle_member(info.filename, archive.read(info))
            else:
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                    for member in archive.getmembers():
                        if not member.isfile() or member.size > MAX_ARCHIVE_MEMBER_BYTES:
                            continue
                        if total_processed + member.size > MAX_ARCHIVE_TOTAL_BYTES:
                            break
                        extracted = archive.extractfile(member)
                        if extracted is None:
                            continue
                        handle_member(member.name, extracted.read())
        except (tarfile.ReadError, zipfile.BadZipFile):
            return findings, score, {}
        except Exception:
            return findings, score, {}

        if malicious_children:
            findings.append(
                ScanFinding(
                    kind="archive_malicious_member",
                    title="Malicious archive member",
                    score=80,
                    description="Archive contains at least one member classified as malicious.",
                    details={"malicious_members": malicious_children},
                )
            )
            score += 80
        if suspicious_children:
            findings.append(
                ScanFinding(
                    kind="archive_suspicious_member",
                    title="Suspicious archive member",
                    score=35,
                    description="Archive contains suspicious members.",
                    details={"suspicious_members": suspicious_children},
                )
            )
            score += 35

        metadata["total_processed_bytes"] = total_processed
        return findings, score, metadata

    def prepare_executable_sandbox(self, file_path: Path | str) -> dict[str, object]:
        target = Path(file_path).expanduser().resolve()
        return self.exe_sandbox.prepare_bundle(target)

    def _build_local_reputation(
        self,
        sha256: str,
        extension: str,
        on_disk_path: Path | None,
        metadata: dict[str, object],
    ) -> tuple[dict[str, object], int, list[ScanFinding]]:
        if on_disk_path is None or extension not in AUTHENTICODE_EXTENSIONS:
            return {}, 0, []

        signature = metadata.get("authenticode", {})
        signature = signature if isinstance(signature, dict) else {}
        pe_metadata = metadata.get("pe", {})
        pe_metadata = pe_metadata if isinstance(pe_metadata, dict) else {}

        history = self.database.get_hash_history(sha256, limit=6)
        blocked_hash = self.database.is_hash_blocked(sha256)
        malicious_hits = sum(1 for row in history if row.get("status") == "malicious")
        suspicious_hits = sum(1 for row in history if row.get("status") == "suspicious")
        clean_hits = sum(1 for row in history if row.get("status") == "clean")

        signer_subject = str(signature.get("signer_subject", "")).strip()
        thumbprint = str(signature.get("thumbprint", "")).strip()
        company_name = str(pe_metadata.get("company_name", "")).strip()
        signature_status = str(signature.get("status", "Unknown"))

        reputation_score = 0
        reasons: list[str] = []
        findings: list[ScanFinding] = []
        normalized_path = str(on_disk_path).lower()

        if blocked_hash:
            reputation_score -= 100
            reasons.append("hash already exists in the local blocklist")
            findings.append(
                ScanFinding(
                    kind="reputation_blocked_hash",
                    title="Hash already blocked locally",
                    score=60,
                    description="This exact hash already exists in the local blocklist.",
                    details={"sha256": sha256},
                )
            )

        if malicious_hits >= 2:
            reputation_score -= min(45, 18 + (malicious_hits * 8))
            reasons.append(f"{malicious_hits} previous malicious local detection(s)")
            findings.append(
                ScanFinding(
                    kind="reputation_bad_history",
                    title="Known-bad local history",
                    score=min(32, 16 + (malicious_hits * 4)),
                    description="This hash was previously seen locally with a malicious verdict.",
                    details={"malicious_hits": malicious_hits, "history_depth": len(history)},
                )
            )
        elif malicious_hits == 1:
            reputation_score -= 14
            reasons.append("1 previous malicious local detection")
        elif suspicious_hits:
            reputation_score -= min(18, 6 + (suspicious_hits * 3))
            reasons.append(f"{suspicious_hits} previous suspicious local detection(s)")
        elif clean_hits:
            reputation_score += min(18, 6 * clean_hits)
            reasons.append(f"{clean_hits} previous clean local scan(s)")

        if signature_status == "Valid":
            reputation_score += 24
            reasons.append("valid Authenticode signature")
            if signer_subject and "microsoft" in signer_subject.lower():
                reputation_score += 16
                reasons.append("Microsoft signer subject")
            if company_name and signer_subject and self._publisher_matches_subject(company_name, signer_subject):
                reputation_score += 10
                reasons.append("publisher metadata matches certificate subject")
        elif signature_status == "NotSigned" and extension in PE_EXTENSIONS:
            reputation_score -= 12
            reasons.append("unsigned portable executable")
        elif signature_status in {"HashMismatch", "NotTrusted", "NotSignatureValid"}:
            reputation_score -= 25
            reasons.append(f"Authenticode status {signature_status}")
        elif signature_status not in {"Unknown", "UnknownError", "NotSupportedFileFormat", "Missing"}:
            reputation_score -= 8
            reasons.append(f"Authenticode status {signature_status}")

        if self._is_system_trust_path(normalized_path) and signature_status == "Valid":
            reputation_score += 12
            reasons.append("validly signed binary under a trusted system path")

        if extension in PE_EXTENSIONS and self._is_user_space_path(normalized_path) and signature_status != "Valid":
            reputation_score -= 10
            reasons.append("portable executable in user space without a strong signature")

        if extension in PE_EXTENSIONS and any(
            token in normalized_path for token in ("\\downloads\\", "\\appdata\\local\\temp\\", "\\temp\\")
        ):
            reputation_score -= 6
            reasons.append("portable executable staged in a high-risk user path")

        if extension in PE_EXTENSIONS and not company_name:
            reputation_score -= 4
            reasons.append("publisher metadata missing")

        if reputation_score <= -60:
            verdict = "known-bad"
            risk_adjustment = 20
        elif reputation_score <= -25:
            verdict = "risky"
            risk_adjustment = 10
        elif reputation_score >= 50:
            verdict = "trusted"
            risk_adjustment = -18
        elif reputation_score >= 25:
            verdict = "known-good"
            risk_adjustment = -8
        else:
            verdict = "unknown"
            risk_adjustment = 0

        reputation = {
            "score": reputation_score,
            "verdict": verdict,
            "history_hits": len(history),
            "blocked_hash": blocked_hash,
            "signer_subject": signer_subject,
            "thumbprint": thumbprint,
            "publisher": company_name,
            "reasons": reasons[:8],
        }
        return reputation, risk_adjustment, findings

    def _build_cloud_fingerprint(self, metadata: dict[str, object]) -> dict[str, object]:
        pe_metadata = metadata.get("pe", {})
        pe_metadata = pe_metadata if isinstance(pe_metadata, dict) else {}
        signature = metadata.get("authenticode", {})
        signature = signature if isinstance(signature, dict) else {}
        return {
            "imported_libraries": pe_metadata.get("imported_libraries", [])[:12] if isinstance(pe_metadata.get("imported_libraries", []), list) else [],
            "section_names": pe_metadata.get("section_names", [])[:10] if isinstance(pe_metadata.get("section_names", []), list) else [],
            "entry_point_rva": pe_metadata.get("entry_point_rva"),
            "machine": pe_metadata.get("machine", ""),
            "thumbprint": signature.get("thumbprint", ""),
            "signer_subject": signature.get("signer_subject", ""),
        }

    def _lookup_cloud_reputation(
        self,
        sha256: str,
        display_path: str,
        extension: str,
        on_disk_path: Path | None,
        metadata: dict[str, object],
    ) -> tuple[dict[str, object], int, list[ScanFinding]]:
        if on_disk_path is None or extension not in AUTHENTICODE_EXTENSIONS or not self.cloud.available:
            return {}, 0, []

        signature = metadata.get("authenticode", {})
        signature = signature if isinstance(signature, dict) else {}
        pe_metadata = metadata.get("pe", {})
        pe_metadata = pe_metadata if isinstance(pe_metadata, dict) else {}
        payload = {
            "sha256": sha256,
            "path": display_path,
            "filename": Path(display_path).name,
            "size": int(metadata.get("full_size", 0) or 0),
            "extension": extension,
            "publisher": str(pe_metadata.get("company_name", "")),
            "thumbprint": str(signature.get("thumbprint", "")),
            "fingerprint": metadata.get("cloud_fingerprint", {}),
            "last_local_verdict": str(metadata.get("reputation", {}).get("verdict", "")) if isinstance(metadata.get("reputation"), dict) else "",
        }
        record = self.cloud.lookup_file(payload)
        if record is None:
            return {}, 0, []

        findings: list[ScanFinding] = []
        score = 0
        if record.verdict in {"known-bad", "malicious"}:
            severity = 70 if record.strong_confirmation else 45
            findings.append(
                ScanFinding(
                    kind="cloud_known_bad",
                    title="Cloud reputation known bad",
                    score=severity,
                    description="Backend reputation identified the hash or fingerprint as known bad.",
                    details=record.to_dict(),
                )
            )
            score += severity
        elif record.verdict in {"risky", "suspicious"}:
            findings.append(
                ScanFinding(
                    kind="cloud_risky",
                    title="Cloud reputation risky",
                    score=20,
                    description="Backend reputation marked the sample as risky.",
                    details=record.to_dict(),
                )
            )
            score += 20
        elif record.verdict in {"trusted", "known-good"}:
            score -= 10
        return record.to_dict(), score, findings

    def _extract_pe_version_info(self, pe) -> dict[str, object]:
        version_entries: dict[str, str] = {}
        for file_info in getattr(pe, "FileInfo", []) or []:
            info_items = file_info if isinstance(file_info, list) else [file_info]
            for info in info_items:
                if getattr(info, "Key", b"") != b"StringFileInfo":
                    continue
                for string_table in getattr(info, "StringTable", []) or []:
                    for key, value in getattr(string_table, "entries", {}).items():
                        decoded_key = key.decode("utf-8", errors="ignore") if isinstance(key, bytes) else str(key)
                        decoded_value = (
                            value.decode("utf-8", errors="ignore") if isinstance(value, bytes) else str(value)
                        ).strip()
                        if decoded_value:
                            version_entries[decoded_key] = decoded_value

        mapping = {
            "CompanyName": "company_name",
            "FileDescription": "file_description",
            "OriginalFilename": "original_filename",
            "ProductName": "product_name",
            "FileVersion": "file_version",
            "ProductVersion": "product_version",
            "InternalName": "internal_name",
        }
        return {
            target: version_entries[source]
            for source, target in mapping.items()
            if source in version_entries and version_entries[source]
        }

    def _publisher_matches_subject(self, publisher: str, subject: str) -> bool:
        publisher_token = re.sub(r"[^a-z0-9]+", " ", publisher.lower()).strip()
        subject_token = re.sub(r"[^a-z0-9]+", " ", subject.lower()).strip()
        if not publisher_token or not subject_token:
            return False
        return publisher_token in subject_token or subject_token in publisher_token

    def _should_use_defender(self, on_disk_path: Path | None, extension: str, score: int) -> bool:
        if on_disk_path is None or not self.defender.available:
            return False
        if extension not in (PE_EXTENSIONS | TEXT_SCRIPT_EXTENSIONS | {".msi"}):
            return False
        if score >= MALICIOUS_THRESHOLD:
            return False
        normalized = str(on_disk_path).lower()
        return not self._is_system_trust_path(normalized)

    def _is_system_trust_path(self, value: str) -> bool:
        trusted_roots = {
            str(Path(os.getenv("SystemRoot", r"C:\Windows"))).lower(),
            str(Path(os.getenv("ProgramFiles", r"C:\Program Files"))).lower(),
            str(Path(os.getenv("ProgramFiles(x86)", r"C:\Program Files (x86)"))).lower(),
        }
        return any(value.startswith(root) for root in trusted_roots)

    def _should_cap_packed_pe_verdict(
        self,
        findings: list[ScanFinding],
        metadata: dict[str, object],
    ) -> bool:
        allowed_kinds = {
            "sensitive_extension",
            "high_entropy",
            "pe_rwx_section",
            "pe_upx_sections",
            "pe_packer_heuristic",
            "pe_overlay_stub",
            "yara_ragnar_pe_upx_sections",
            "yara_ragnar_pe_rwx_section",
            "yara_ragnar_pe_lowimport_overlay",
            "authenticode_issue",
            "unsigned_pe",
            "reputation_bad_history",
        }
        finding_kinds = {finding.kind for finding in findings}
        if not finding_kinds.intersection({"pe_upx_sections", "pe_packer_heuristic", "yara_ragnar_pe_upx_sections"}):
            return False
        if any(kind not in allowed_kinds for kind in finding_kinds):
            return False

        pe_metadata = metadata.get("pe", {})
        pe_metadata = pe_metadata if isinstance(pe_metadata, dict) else {}
        reputation = metadata.get("reputation", {})
        reputation = reputation if isinstance(reputation, dict) else {}
        signature = metadata.get("authenticode", {})
        signature = signature if isinstance(signature, dict) else {}

        if pe_metadata.get("suspicious_imports"):
            return False
        if reputation.get("blocked_hash"):
            return False
        return str(signature.get("status", "Unknown")) not in {"HashMismatch", "NotTrusted", "NotSignatureValid"}

    def _quarantine(self, file_path: Path, sha256: str) -> str | None:
        ensure_app_dirs()
        target = QUARANTINE_DIR / f"{sha256[:12]}_{file_path.name}"
        if file_path.resolve() == target.resolve():
            return str(target)
        try:
            shutil.move(str(file_path), target)
            self.logger.warning("quarantined file | %s -> %s", file_path, target)
            return str(target)
        except Exception as exc:
            self.logger.error("quarantine failed | %s | %s", file_path, exc)
            return None

    def restore_quarantine_item(self, item_id: int) -> str:
        item = self.database.get_quarantine_item(item_id)
        if item is None:
            raise ValueError(f"Unknown quarantine item {item_id}")
        source = Path(item["quarantined_path"])
        if not source.exists():
            raise FileNotFoundError(source)
        target = Path(item["original_path"])
        if target.exists():
            target = target.with_name(f"{target.stem}_restored{target.suffix}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), target)
        self.database.mark_quarantine_restored(item_id, str(target))
        self.database.deactivate_blocked_file(item["original_path"], item["sha256"])
        self.logger.warning("restored quarantine item | id=%s -> %s", item_id, target)
        return str(target)

    def enforce_block_on_existing_file(self, file_path: Path | str, result: FileScanResult) -> dict[str, object]:
        candidate = Path(file_path).expanduser().resolve()
        remediation = {
            "blocked": False,
            "quarantined_path": "",
            "quarantine_item_id": None,
        }
        if not candidate.exists() or not candidate.is_file():
            return remediation
        if not self._is_user_space_path(str(candidate)) or self._is_managed_app_path(candidate):
            return remediation
        quarantine_path = self._quarantine(candidate, result.sha256)
        if quarantine_path:
            remediation["quarantined_path"] = quarantine_path
            remediation["quarantine_item_id"] = self.database.record_quarantine_item(
                original_path=str(candidate),
                quarantined_path=quarantine_path,
                sha256=result.sha256,
                reason=result.summary(),
            )
        self.database.upsert_blocked_file(
            path=str(candidate),
            sha256=result.sha256,
            reason=result.summary(),
            source="stage-pipeline",
        )
        remediation["blocked"] = True
        return remediation

    def record_external_result(self, result: FileScanResult, persist_clean: bool = False) -> None:
        if result.status != "clean" or persist_clean:
            self.database.record_detection(result)
        self.logger.info("external scan result | %s | status=%s score=%s", result.path, result.status, result.score)
        self._emit_result(result)

    def _is_user_space_path(self, value: str) -> bool:
        normalized = str(Path(value)).lower()
        return any(normalized.startswith(prefix) for prefix in USER_SPACE_HINTS)

    def _is_managed_app_path(self, file_path: Path) -> bool:
        return is_managed_path(file_path)

    def file_sha256(self, file_path: Path | str) -> str:
        return self._sha256_file(Path(file_path))

    def count_strong_confirmations(self, result: FileScanResult) -> int:
        confirmations = 0
        if result.status == "malicious":
            confirmations += 1
        defender = result.metadata.get("defender", {})
        if isinstance(defender, dict) and defender.get("is_malware"):
            confirmations += 1
        sandbox_report = result.metadata.get("sandbox_report", {})
        if isinstance(sandbox_report, dict) and sandbox_report.get("verdict") == "malicious":
            confirmations += 1
        cloud = result.metadata.get("cloud_reputation", {})
        if isinstance(cloud, dict) and str(cloud.get("verdict", "")) in {"known-bad", "malicious"}:
            confirmations += 1
        return confirmations

    def _emit_result(self, result: FileScanResult) -> None:
        for callback in self._result_callbacks:
            try:
                callback(result)
            except Exception as exc:
                self.logger.debug("scan result callback failed | %s | %s", result.path, exc)

    def _sha256_file(self, file_path: Path) -> str:
        digest = hashlib.sha256()
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _read_scan_bytes(self, file_path: Path) -> bytes:
        size = file_path.stat().st_size
        if size <= MAX_FILE_SCAN_BYTES:
            return file_path.read_bytes()
        with file_path.open("rb") as handle:
            head = handle.read(MAX_FILE_SCAN_BYTES // 2)
            handle.seek(max(0, size - (MAX_FILE_SCAN_BYTES // 2)))
            tail = handle.read(MAX_FILE_SCAN_BYTES // 2)
        return head + b"\n[...TRUNCATED...]\n" + tail

    def _decode_text(self, data: bytes) -> str | None:
        for encoding in TEXT_ENCODINGS:
            try:
                text = data.decode(encoding)
                if text.count("\x00") < max(8, len(text) // 20):
                    return text
            except UnicodeDecodeError:
                continue
        return None

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counts = {}
        for byte in data[:MAX_FILE_SCAN_BYTES]:
            counts[byte] = counts.get(byte, 0) + 1
        length = sum(counts.values())
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _can_decode_base64(self, blob: str) -> bool:
        try:
            base64.b64decode(blob, validate=True)
            return True
        except Exception:
            return False

    def _normalized_extension(self, path: Path) -> str:
        suffixes = [suffix.lower() for suffix in path.suffixes]
        if len(suffixes) >= 2 and "".join(suffixes[-2:]) == ".tar.gz":
            return ".tar.gz"
        return path.suffix.lower()

    def format_results(self, results: Iterable[FileScanResult]) -> str:
        lines = []
        for result in results:
            lines.append(f"{result.status.upper():10} score={result.score:3} {result.path}")
            for finding in result.findings[:6]:
                lines.append(f"  - {finding.title} (+{finding.score})")
            if result.quarantined_path:
                lines.append(f"  - Quarantine: {result.quarantined_path}")
        return "\n".join(lines)
