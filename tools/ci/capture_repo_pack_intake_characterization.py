#!/usr/bin/env python3
"""Print the reviewed verifier-pack intake characterization vector."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "tests"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(TESTS))

from repo_pack_intake_characterization_harness import (  # noqa: E402
    canonical_json,
    capture_all,
)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="evo_pack_intake_capture_") as tmp:
        print(canonical_json(capture_all(Path(tmp))), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
