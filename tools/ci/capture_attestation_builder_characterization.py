"""Check or explicitly replace the reviewed Guard attestation vector."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "tests"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(TESTS))

from attestation_builder_characterization_harness import (  # noqa: E402
    canonical_json,
    capture_all,
)

VECTOR = TESTS / "fixtures" / "refactor-safety" / "attestation-builder-v1.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        action="store_true",
        help="replace the reviewed vector (never used by tests or CI)",
    )
    args = parser.parse_args()

    current = canonical_json(capture_all())
    if args.write:
        VECTOR.write_text(current, encoding="utf-8", newline="\n")
        print(f"wrote {VECTOR.relative_to(ROOT)}")
        return 0

    if not VECTOR.is_file():
        print(f"missing frozen vector: {VECTOR.relative_to(ROOT)}", file=sys.stderr)
        return 1
    if VECTOR.read_text(encoding="utf-8") != current:
        print(
            "Guard attestation characterization differs; run pytest for a case diff.",
            file=sys.stderr,
        )
        return 1
    print("Guard attestation characterization matches the frozen vector.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
