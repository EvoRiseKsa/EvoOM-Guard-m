#!/usr/bin/env python3
"""Reproduce or explicitly replace the black-box pack phase vector."""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "tests"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from blackbox_pack_characterization_harness import (  # noqa: E402
    canonical_json,
    capture_all,
)

FIXTURE = TESTS / "fixtures" / "refactor-safety" / "blackbox-pack-phase-v1.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        action="store_true",
        help="replace the reviewed vector instead of checking it",
    )
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="blackbox-pack-capture-") as temp:
        current = canonical_json(capture_all(Path(temp)))

    if args.write:
        FIXTURE.write_text(current, encoding="utf-8", newline="\n")
        print(f"wrote {FIXTURE.relative_to(ROOT)}")
        return 0
    expected = FIXTURE.read_text(encoding="utf-8")
    if current != expected:
        print(
            "black-box pack vector drifted; review and rerun with --write",
            file=sys.stderr,
        )
        return 1
    print("black-box pack vector reproduced exactly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
