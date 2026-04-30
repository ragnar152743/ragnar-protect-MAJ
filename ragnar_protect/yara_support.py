from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import COMMUNITY_YARA_RULES_DIR, YARA_RULES_DIR

try:
    import yara  # type: ignore
except Exception:  # pragma: no cover
    yara = None


class YaraScanner:
    def __init__(self, rules_dir: Path | None = None, community_rules_dir: Path | None = None) -> None:
        self.rules_dir = rules_dir or YARA_RULES_DIR
        self.community_rules_dir = community_rules_dir or COMMUNITY_YARA_RULES_DIR
        self._compiled_rules: list[tuple[str, Any]] = []
        self._compile_error = ""
        self._compiled_count = 0
        self._failed_count = 0
        if yara is not None:
            self.reload()

    @property
    def available(self) -> bool:
        return bool(self._compiled_rules)

    @property
    def compile_error(self) -> str:
        return self._compile_error

    @property
    def stats(self) -> dict[str, object]:
        return {
            "available": self.available,
            "compiled_rulesets": self._compiled_count,
            "failed_rulesets": self._failed_count,
            "compile_error": self._compile_error,
        }

    def reload(self) -> None:
        self._compiled_rules = []
        self._compile_error = ""
        self._compiled_count = 0
        self._failed_count = 0
        if yara is None:
            return
        files = self._iter_rule_files()
        for index in range(0, len(files), 50):
            batch = files[index : index + 50]
            try:
                compiled = yara.compile(
                    sources={
                        f"{path.stem}_{index + offset}": path.read_text(encoding="utf-8", errors="ignore")
                        for offset, path in enumerate(batch)
                    }
                )
                self._compiled_rules.append((f"batch_{index}", compiled))
                self._compiled_count += len(batch)
            except Exception as exc:
                if not self._compile_error:
                    self._compile_error = str(exc)
                for path in batch:
                    try:
                        compiled = yara.compile(filepath=str(path))
                        self._compiled_rules.append((path.name, compiled))
                        self._compiled_count += 1
                    except Exception as inner_exc:
                        self._failed_count += 1
                        if not self._compile_error:
                            self._compile_error = str(inner_exc)

    def scan_bytes(self, data: bytes, allowed_tags: set[str] | None = None) -> list[dict[str, object]]:
        if not self._compiled_rules or not data:
            return []
        matches: list[dict[str, object]] = []
        for source_name, compiled in self._compiled_rules:
            try:
                matches.extend(self._filter_matches(compiled.match(data=data), allowed_tags, source_name))
            except Exception:
                continue
        return matches

    def scan_file(self, file_path: str, allowed_tags: set[str] | None = None) -> list[dict[str, object]]:
        if not self._compiled_rules:
            return []
        matches: list[dict[str, object]] = []
        for source_name, compiled in self._compiled_rules:
            try:
                matches.extend(self._filter_matches(compiled.match(filepath=file_path), allowed_tags, source_name))
            except Exception:
                continue
        return matches

    def _iter_rule_files(self) -> list[Path]:
        candidates: list[Path] = []
        for root in (self.rules_dir, self.community_rules_dir):
            if not root.exists():
                continue
            for path in sorted(root.rglob("*")):
                if path.suffix.lower() not in {".yar", ".yara"}:
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                if "include " in text:
                    continue
                candidates.append(path)
        return candidates

    def _filter_matches(self, matches, allowed_tags: set[str] | None, source_name: str) -> list[dict[str, object]]:
        serialized = [self._serialize_match(match, source_name) for match in matches]
        if not allowed_tags:
            return serialized
        return [
            match
            for match in serialized
            if set(str(tag) for tag in match.get("tags", [])).intersection(allowed_tags)
        ]

    def _serialize_match(self, match, source_name: str) -> dict[str, object]:
        return {
            "rule": match.rule,
            "tags": list(match.tags),
            "meta": dict(match.meta),
            "strings": len(match.strings),
            "source": source_name,
        }
