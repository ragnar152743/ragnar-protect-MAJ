from __future__ import annotations

import json
import re
from pathlib import Path

from .config import BEHAVIOR_RULES_FILE, SUSPICIOUS_PATTERNS


def load_behavior_rules(path: Path | None = None) -> list[dict[str, object]]:
    rules_path = path or BEHAVIOR_RULES_FILE
    try:
        if rules_path.exists():
            data = json.loads(rules_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
    except Exception:
        pass
    return list(SUSPICIOUS_PATTERNS)


def compile_behavior_rules(path: Path | None = None) -> list[dict[str, object]]:
    compiled = []
    for item in load_behavior_rules(path):
        try:
            compiled.append(
                {
                    "name": item["name"],
                    "score": int(item["score"]),
                    "description": str(item["description"]),
                    "regex": re.compile(str(item["pattern"])),
                }
            )
        except Exception:
            continue
    return compiled
