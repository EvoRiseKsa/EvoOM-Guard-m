# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Typed stdlib-only owner for CLI signing-key generation."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class KeygenServices:
    """Entry-snapshotted signing effects for one key-generation command."""

    generate_keypair: Callable[[str, str], None]


def execute_keygen(
    args: argparse.Namespace,
    *,
    services: KeygenServices,
    out: Callable[[str], None] = print,
) -> int:
    """Generate one Ed25519 keypair without weakening no-clobber behavior."""

    try:
        services.generate_keypair(args.key, args.pub)
    except FileExistsError as exc:
        out(str(exc))
        return 2
    out(f"wrote {args.key} (private — keep it a CI secret) and {args.pub} (public)")
    return 0
