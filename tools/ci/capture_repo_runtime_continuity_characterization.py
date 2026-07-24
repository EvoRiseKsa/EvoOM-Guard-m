"""Capture/check the frozen repository runtime-continuity vector."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "tests"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from repo_runtime_continuity_characterization_harness import (  # noqa: E402
    SCHEMA_VERSION,
    canonical_json,
    capture_all,
)

VECTOR = (
    TESTS
    / "fixtures"
    / "refactor-safety"
    / "repo-runtime-continuity-v1.json"
)


def _digest_cases(payload: dict) -> dict:
    return {
        "cases": {
            name: {
                "sha256": hashlib.sha256(
                    canonical_json(value).encode("utf-8")
                ).hexdigest()
            }
            for name, value in payload["cases"].items()
        },
        "schema_version": SCHEMA_VERSION,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        action="store_true",
        help="replace the reviewed frozen digest vector",
    )
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(
        prefix="evoguard-repo-runtime-characterization-"
    ) as temp:
        observed = _digest_cases(capture_all(Path(temp)))

    rendered = (
        json.dumps(
            observed,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    if args.write:
        VECTOR.parent.mkdir(parents=True, exist_ok=True)
        VECTOR.write_text(rendered, encoding="utf-8", newline="\n")
        print(f"Wrote {VECTOR.relative_to(ROOT)}")
        return 0

    if not VECTOR.exists():
        print(f"Missing frozen vector: {VECTOR}", file=sys.stderr)
        return 1
    if VECTOR.read_text(encoding="utf-8") != rendered:
        print(
            "Repository runtime characterization drifted; "
            "run with --write only after review.",
            file=sys.stderr,
        )
        return 1
    print("Repository runtime characterization matches the frozen vector.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
