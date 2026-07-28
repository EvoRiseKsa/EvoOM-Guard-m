"""Command-line entry point for the isolation conformance kit."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from tools.conformance.isolation_kit import (
    DEFAULT_MANIFEST,
    ManifestError,
    ResultVerificationError,
    exit_code,
    load_result,
    run_conformance,
    verify_result,
    write_result,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run bounded Docker/gVisor isolation probes and emit a "
            "schema-versioned evidence result."
        )
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="conformance manifest (default: tools/conformance/isolation-manifest.json)",
    )
    parser.add_argument(
        "--image",
        help=(
            "image reference to resolve and bind; defaults to "
            "EVOGUARD_E2E_IMAGE or the manifest default"
        ),
    )
    parser.add_argument(
        "--profile",
        action="append",
        dest="profiles",
        help="profile id to run; repeat as needed, or use all (default: all)",
    )
    parser.add_argument(
        "--require-gvisor",
        action="store_true",
        help="make missing/unusable runsc a non-successful required result",
    )
    parser.add_argument(
        "--no-pull",
        action="store_true",
        help="do not pull a missing image",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--output",
        type=Path,
        help="create-only JSON output path (default: stdout)",
    )
    mode.add_argument(
        "--verify",
        type=Path,
        metavar="RESULT",
        help="verify unsigned result consistency against trusted local inputs",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.verify is not None:
        if args.profiles or args.require_gvisor or args.image or args.no_pull:
            parser.error("profile/image/run flags are invalid with --verify")
        try:
            verify_result(load_result(args.verify), manifest_path=args.manifest)
        except (ManifestError, ResultVerificationError) as exc:
            parser.error(str(exc))
        return 0
    image = args.image
    if image is None:
        import os

        image = os.environ.get("EVOGUARD_E2E_IMAGE")
    try:
        result = run_conformance(
            manifest_path=args.manifest,
            image=image,
            selected_profiles=args.profiles,
            require_gvisor=args.require_gvisor,
            pull=not args.no_pull,
            output_path=args.output,
        )
    except ManifestError as exc:
        parser.error(str(exc))
    try:
        write_result(result, args.output)
    except FileExistsError:
        parser.error(f"output already exists (create-only): {args.output}")
    return exit_code(result["status"])


if __name__ == "__main__":
    raise SystemExit(main())
