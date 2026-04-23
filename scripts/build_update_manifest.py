from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ragnar_protect.version import APP_VERSION


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().lower()


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a GitHub update manifest for Ragnar Protect.")
    parser.add_argument("--exe", required=True, help="Path to the built RagnarProtect.exe")
    parser.add_argument("--repo", default="ragnar152743/ragnar-protect-MAJ", help="GitHub owner/repo that hosts the manifest and exe")
    parser.add_argument("--branch", default="main", help="GitHub branch used for the updater manifest")
    parser.add_argument("--out", default="manifest.json", help="Output manifest path")
    args = parser.parse_args()

    exe_path = Path(args.exe).resolve()
    if not exe_path.exists():
        raise FileNotFoundError(exe_path)

    payload = {
        "schema_version": 1,
        "app_name": "Ragnar Protect",
        "channel": "stable",
        "version": APP_VERSION,
        "asset_name": exe_path.name,
        "size": exe_path.stat().st_size,
        "sha256": sha256_file(exe_path),
        "exe_url": f"https://raw.githubusercontent.com/{args.repo}/{args.branch}/{exe_path.name}",
    }

    output_path = Path(args.out).resolve()
    output_path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
