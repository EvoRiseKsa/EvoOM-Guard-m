"""Command-line entry point for offline runner-adapter conformance."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from tools.conformance.runner_kit import (
    DEFAULT_MANIFEST,
    ManifestError,
    ResultVerificationError,
    exit_code,
    load_result,
    run_conformance,
    verify_result,
    write_result_create_only,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Exercise all runner adapters offline and write a create-only, "
            "schema-versioned JSON result."
        )
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="runner manifest (default: tools/conformance/runner-manifest.json)",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--output",
        type=Path,
        help="new result path; an existing file is never replaced",
    )
    mode.add_argument(
        "--verify",
        type=Path,
        metavar="RESULT",
        help="verify one unsigned result against the trusted manifest and current source",
    )
    parser.add_argument(
        "--discover-tools",
        action="store_true",
        help=(
            "observe local --version output only; this is non-gating and does "
            "not execute runner suites"
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.verify is not None:
        if args.discover_tools:
            parser.error("--discover-tools is only valid while producing a result")
        try:
            verify_result(load_result(args.verify), manifest_path=args.manifest)
        except (ManifestError, ResultVerificationError) as exc:
            parser.error(str(exc))
        return 0
    try:
        result = run_conformance(
            manifest_path=args.manifest,
            discover_tools=args.discover_tools,
        )
        assert args.output is not None
        write_result_create_only(result, args.output)
    except ManifestError as exc:
        parser.error(str(exc))
    except FileExistsError:
        parser.error(f"output already exists (create-only): {args.output}")
    return exit_code(str(result["status"]))


if __name__ == "__main__":
    raise SystemExit(main())
