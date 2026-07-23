"""Check or explicitly replace the reviewed diff-coverage gate vector."""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "tests"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(TESTS))

from diff_coverage_gate_characterization_harness import (  # noqa: E402
    canonical_json,
    capture_all,
)

VECTOR = TESTS / "fixtures" / "refactor-safety" / "diff-coverage-gate-v1.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        action="store_true",
        help="replace the reviewed vector (never used by tests or CI)",
    )
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="evo-diff-coverage-gate-") as temp:
        current = canonical_json(capture_all(Path(temp)))
    if args.write:
        VECTOR.write_text(current, encoding="utf-8", newline="\n")
        print(f"wrote {VECTOR.relative_to(ROOT)}")
        return 0

    if not VECTOR.is_file():
        print(f"missing frozen vector: {VECTOR.relative_to(ROOT)}", file=sys.stderr)
        return 1
    if VECTOR.read_text(encoding="utf-8") != current:
        print(
            "Diff-coverage gate characterization differs; run pytest for a case diff.",
            file=sys.stderr,
        )
        return 1
    print("Diff-coverage gate characterization matches the frozen vector.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
