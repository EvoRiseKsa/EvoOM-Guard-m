"""Check or explicitly replace the reviewed black-box characterization vectors."""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "tests"
FIXTURE_ROOT = TESTS / "fixtures" / "refactor-safety"
sys.path.insert(0, str(TESTS))

from blackbox_characterization_harness import (  # noqa: E402
    GROUP_CASES,
    VECTOR_FILES,
    canonical_json,
    capture_contract,
    capture_group,
)


def _selected_groups(requested: list[str]) -> list[str]:
    known = ["contract", *GROUP_CASES]
    unknown = sorted(set(requested) - set(known))
    if unknown:
        raise ValueError("unknown group(s): " + ", ".join(unknown))
    return [group for group in known if not requested or group in requested]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        action="store_true",
        help="replace reviewed vectors explicitly; check-only is the default",
    )
    parser.add_argument(
        "--group",
        action="append",
        default=[],
        help="check/write one group (repeatable)",
    )
    args = parser.parse_args()
    try:
        groups = _selected_groups(args.group)
    except ValueError as exc:
        parser.error(str(exc))

    FIXTURE_ROOT.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="evoguard-blackbox-characterization-") as temp:
        workspace = Path(temp)
        for group_name in groups:
            payload = (
                capture_contract()
                if group_name == "contract"
                else capture_group(group_name, workspace / group_name)
            )
            current = canonical_json(payload)
            vector = FIXTURE_ROOT / VECTOR_FILES[group_name]
            if args.write:
                vector.write_text(current, encoding="utf-8", newline="\n")
                print(f"wrote {vector.relative_to(ROOT)}")
                continue
            if not vector.is_file():
                failures.append(f"missing {vector.relative_to(ROOT)}")
            elif vector.read_text(encoding="utf-8") != current:
                failures.append(
                    f"{group_name} differs; run the focused pytest for a case diff"
                )

    if failures:
        print("Black-box characterization failed:\n" + "\n".join(failures), file=sys.stderr)
        return 1
    print("Black-box characterization matches all reviewed vectors.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
