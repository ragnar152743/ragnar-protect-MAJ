from __future__ import annotations

from pathlib import Path

from .config import YARA_RULES_DIR

try:
    import yara  # type: ignore
except Exception:  # pragma: no cover
    yara = None


class YaraScanner:
    def __init__(self, rules_dir: Path | None = None) -> None:
        self.rules_dir = rules_dir or YARA_RULES_DIR
        self._rules = None
        self._compile_error = ""
        if yara is not None:
            self._compile()

    @property
    def available(self) -> bool:
        return self._rules is not None

    @property
    def compile_error(self) -> str:
        return self._compile_error

    def _compile(self) -> None:
        sources: dict[str, str] = {}
        for path in sorted(self.rules_dir.glob("*.yar")):
            sources[path.stem] = path.read_text(encoding="utf-8")
        if not sources:
            return
        try:
            self._rules = yara.compile(sources=sources)
        except Exception as exc:
            self._compile_error = str(exc)
            self._rules = None

    def scan_bytes(self, data: bytes, allowed_tags: set[str] | None = None) -> list[dict[str, object]]:
        if not self._rules or not data:
            return []
        matches = self._rules.match(data=data)
        return self._filter_matches(matches, allowed_tags)

    def scan_file(self, file_path: str, allowed_tags: set[str] | None = None) -> list[dict[str, object]]:
        if not self._rules:
            return []
        matches = self._rules.match(filepath=file_path)
        return self._filter_matches(matches, allowed_tags)

    def _filter_matches(self, matches, allowed_tags: set[str] | None) -> list[dict[str, object]]:
        serialized = [self._serialize_match(match) for match in matches]
        if not allowed_tags:
            return serialized
        return [
            match
            for match in serialized
            if set(str(tag) for tag in match.get("tags", [])).intersection(allowed_tags)
        ]

    def _serialize_match(self, match) -> dict[str, object]:
        return {
            "rule": match.rule,
            "tags": list(match.tags),
            "meta": dict(match.meta),
            "strings": len(match.strings),
        }
