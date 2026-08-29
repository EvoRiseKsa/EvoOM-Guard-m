# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ─────────────────────────────────────────────────────────────────────────────
"""Every ``evoom_guard`` module must carry the license header for its side.

``LICENSING.md`` promises that every source file states its license in a header:
Apache-2.0 for the open-core paths, the EvoRise source-available notice for the
platform paths. :mod:`test_license_boundaries` already turns the path→license map
into an *import* boundary; this gate makes the same map a *header* boundary, so a
module can never ship without declaring its side — the gap that once left
``finalizer_derivation.py`` (a trust-root module) headerless while the map
claimed universal coverage.
"""

from __future__ import annotations

from test_import_boundaries import PACKAGE_ROOT, _discover_modules
from test_license_boundaries import is_platform_module

# The marker each side's header must contain within its opening lines. Core files
# carry the Apache SPDX identifier; platform files carry the source-available
# notice (and deliberately no SPDX identifier, so an automated scan reads the
# package as the restrictive umbrella — see LICENSING.md).
CORE_MARKER = "SPDX-License-Identifier: Apache-2.0"
PLATFORM_MARKER = "Source-available"
HEADER_SCAN_LINES = 8


def _header(path) -> str:
    with path.open("r", encoding="utf-8") as handle:
        return "".join(handle.readline() for _ in range(HEADER_SCAN_LINES))


def test_every_module_declares_its_license_in_a_header() -> None:
    """A module without the header for its classified side fails here."""

    modules, _packages = _discover_modules(PACKAGE_ROOT)
    missing: list[str] = []
    for module, path in sorted(modules.items()):
        marker = PLATFORM_MARKER if is_platform_module(module) else CORE_MARKER
        if marker not in _header(path):
            side = "platform" if is_platform_module(module) else "core"
            missing.append(f"{module} [{side}] missing {marker!r} ({path})")
    assert not missing, (
        "modules are missing the license header their side requires "
        "(LICENSING.md promises every file is headered):\n  " + "\n  ".join(missing)
    )
