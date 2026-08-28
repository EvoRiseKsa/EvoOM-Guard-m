# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ─────────────────────────────────────────────────────────────────────────────
"""Vitest JUnit report adapter."""

from __future__ import annotations

import evoom_guard.runners._command as _command


class VitestAdapter:
    """Vitest with a judge-owned JUnit output file."""

    name = "vitest"

    def matches(self, cmd: list[str]) -> bool:
        return _command._invokes_runner(cmd, "vitest")

    def instrument(self, cmd: list[str], report_path: str) -> list[str] | None:
        if any(str(token).startswith(("--reporter", "--outputFile")) for token in cmd):
            return None
        return [*cmd, "--reporter=default", "--reporter=junit", f"--outputFile={report_path}"]


__all__ = ["VitestAdapter"]
