"""Explicitly check or write the reviewed CandidateRunner golden vector."""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "tests"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(TESTS))

from candidate_runner_characterization_harness import (  # noqa: E402
    canonical_json,
    capture_all,
)

VECTOR = TESTS / "fixtures" / "refactor-safety" / "candidate-runner-v1.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        action="store_true",
        help="replace the reviewed vector (never used implicitly by tests or CI)",
    )
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(
        prefix="evoguard-candidate-runner-characterization-"
    ) as temp:
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
            "CandidateRunner characterization differs; run pytest for a case diff.",
            file=sys.stderr,
        )
        return 1
    print("CandidateRunner characterization matches the frozen vector.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
