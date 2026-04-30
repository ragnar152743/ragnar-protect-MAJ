from __future__ import annotations

from pathlib import Path
from typing import Any

from .logging_setup import get_logger


class OfficeMacroScanner:
    def __init__(self) -> None:
        self.logger = get_logger("ragnar_protect.office")
        self._vba_parser_cls = None
        self._import_attempted = False

    @property
    def available(self) -> bool:
        return self._load_parser() is not None

    def analyze(self, file_path: Path) -> dict[str, Any]:
        result: dict[str, Any] = {
            "available": self.available,
            "path": str(file_path),
            "has_macros": False,
            "autoexec_count": 0,
            "suspicious_count": 0,
            "ioc_count": 0,
            "hex_count": 0,
            "base64_count": 0,
            "dridex_count": 0,
            "module_count": 0,
            "keywords": [],
            "error": "",
        }
        parser_cls = self._load_parser()
        if parser_cls is None:
            return result
        parser = None
        try:
            parser = parser_cls(str(file_path))
            result["has_macros"] = bool(parser.detect_vba_macros())
            if result["has_macros"]:
                module_count = 0
                for _filename, _stream_path, _vba_filename, _code in parser.extract_macros():
                    module_count += 1
                result["module_count"] = module_count
            keywords: list[dict[str, str]] = []
            for item in parser.analyze_macros():
                if not isinstance(item, tuple) or len(item) < 3:
                    continue
                kind = str(item[0])
                keyword = str(item[1])
                description = str(item[2])
                keywords.append({"type": kind, "keyword": keyword, "description": description})
                lowered = kind.lower()
                if lowered == "autoexec":
                    result["autoexec_count"] += 1
                elif lowered == "suspicious":
                    result["suspicious_count"] += 1
                elif lowered == "ioc":
                    result["ioc_count"] += 1
                elif lowered == "hex string":
                    result["hex_count"] += 1
                elif lowered == "base64 string":
                    result["base64_count"] += 1
                elif lowered == "dridex string":
                    result["dridex_count"] += 1
            result["keywords"] = keywords[:64]
            return result
        except Exception as exc:
            result["error"] = str(exc)
            self.logger.debug("office macro scan failed | %s | %s", file_path, exc)
            return result
        finally:
            try:
                if parser is not None:
                    parser.close()
            except Exception:
                pass

    def _load_parser(self):
        if self._import_attempted:
            return self._vba_parser_cls
        self._import_attempted = True
        try:
            from oletools.olevba import VBA_Parser  # type: ignore

            self._vba_parser_cls = VBA_Parser
        except Exception as exc:  # pragma: no cover
            self.logger.debug("oletools VBA parser unavailable | %s", exc)
            self._vba_parser_cls = None
        return self._vba_parser_cls
