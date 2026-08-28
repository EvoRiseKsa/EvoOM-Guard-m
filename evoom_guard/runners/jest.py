# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ─────────────────────────────────────────────────────────────────────────────
"""Jest JUnit report adapter."""

from __future__ import annotations

import evoom_guard.runners._command as _command


class JestAdapter:
    """Jest using ``jest-junit`` and a judge-owned environment path."""

    name = "jest"

    def matches(self, cmd: list[str]) -> bool:
        return _command._invokes_runner(cmd, "jest")

    def instrument(self, cmd: list[str], report_path: str) -> list[str] | None:
        if any(str(token).startswith("--reporters") for token in cmd):
            return None
        return [*cmd, "--reporters=default", "--reporters=jest-junit"]

    def report_env(self, report_path: str) -> dict[str, str]:
        """Point ``jest-junit`` at the judge-owned report."""

        return {"JEST_JUNIT_OUTPUT_FILE": report_path}


__all__ = ["JestAdapter"]
