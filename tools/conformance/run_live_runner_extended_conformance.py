"""Create or verify one exact extended live-runner matrix cell."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from tools.conformance.live_runner_extended_result import (
    LiveRunnerExtendedResultError,
    build_result,
    load_result,
    verify_result,
    write_result,
)
from tools.conformance.secure_io import ConformanceIOError


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create or verify a bounded extended real-runner conformance cell."
    )
    parser.add_argument("--junit", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path)
    mode.add_argument("--verify", type=Path, metavar="RESULT")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.verify is not None:
            verify_result(load_result(args.verify), args.junit)
            return 0
        assert args.output is not None
        write_result(build_result(args.junit), args.output)
    except FileExistsError:
        parser.error(f"output already exists (create-only): {args.output}")
    except (ConformanceIOError, LiveRunnerExtendedResultError, OSError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
