# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""CLI adapters for deterministic Trusted Finalizer deployment tooling."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from typing import Any


def execute_finalizer_init(
    args: argparse.Namespace,
    *,
    installer: Callable[[str, str], dict[str, Any]],
    error_type: type[Exception],
    json_dumps: Callable[..., str],
    out: Callable[[str], None] = print,
) -> int:
    """Install one no-clobber finalizer kit and render its bounded result."""

    try:
        result = installer(args.root, args.public_key)
    except error_type as exc:
        out(f"finalizer-init: {exc}")
        return 1
    if getattr(args, "finalizer_init_json", False):
        out(json_dumps(result, indent=2, sort_keys=True))
    else:
        out(f"Trusted Finalizer files installed under: {result['root']}")
        for path in result["written"]:
            out(f"  wrote: {path}")
        out(f"  public key: {result['public_key_id']}")
        out("GitHub controls were not configured by this local command.")
        out("Run `evo-guard finalizer-doctor --root <repo>` before live setup.")
    return 0


def execute_finalizer_doctor(
    args: argparse.Namespace,
    *,
    inspector: Callable[[str], dict[str, Any]],
    json_dumps: Callable[..., str],
    out: Callable[[str], None] = print,
) -> int:
    """Render one static-only finalizer report; never imply GitHub readiness."""

    report = inspector(args.root)
    if getattr(args, "finalizer_doctor_json", False):
        out(json_dumps(report, indent=2, sort_keys=True))
    else:
        out(f"Trusted Finalizer static inspection: {report['root']}")
        for check in report["checks"]:
            out(f"  {check['status']:4} {check['id']}: {check['message']}")
        out(f"  static ready: {'yes' if report['static_ready'] else 'no'}")
        out("  GitHub controls checked: no")
        out("  enforcement ready: no")
        out("Required live controls:")
        for item in report["required_live_controls"]:
            out(f"  - {item}")
    return 0 if report["static_ready"] else 1


__all__ = ["execute_finalizer_doctor", "execute_finalizer_init"]
