"""Check or explicitly replace the black-box judge process contract vector."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "tests"
VECTOR = (
    TESTS
    / "fixtures"
    / "refactor-safety"
    / "blackbox-judge-process-contract-v1.json"
)
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(TESTS))

from blackbox_judge_contract_harness import (  # noqa: E402
    canonical_json,
    capture_contract,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        action="store_true",
        help="replace the reviewed vector explicitly; check-only is the default",
    )
    args = parser.parse_args()
    current = canonical_json(capture_contract())

    if args.write:
        VECTOR.parent.mkdir(parents=True, exist_ok=True)
        VECTOR.write_text(current, encoding="utf-8", newline="\n")
        print(f"wrote {VECTOR.relative_to(ROOT)}")
        return 0

    if not VECTOR.is_file():
        print(f"Black-box judge contract is missing: {VECTOR.relative_to(ROOT)}", file=sys.stderr)
        return 1
    if VECTOR.read_text(encoding="utf-8") != current:
        print(
            "Black-box judge process contract differs; run the focused pytest "
            "for a case diff.",
            file=sys.stderr,
        )
        return 1
    print("Black-box judge process contract matches the reviewed vector.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
