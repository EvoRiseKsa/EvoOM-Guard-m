# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ─────────────────────────────────────────────────────────────────────────────
"""Mocha JUnit report adapter."""

from __future__ import annotations

import evoom_guard.runners._command as _command


class MochaAdapter:
    """JavaScript Mocha via ``mocha-junit-reporter``."""

    name = "mocha"

    def matches(self, cmd: list[str]) -> bool:
        return _command._invokes_runner(cmd, "mocha")

    def instrument(self, cmd: list[str], report_path: str) -> list[str] | None:
        tokens = [str(token) for token in cmd]
        if any(
            token in ("--reporter", "-R")
            or token.startswith(("--reporter=", "--reporter-options"))
            for token in tokens
        ):
            return None
        return [
            *tokens,
            "--reporter",
            "mocha-junit-reporter",
            "--reporter-options",
            f"mochaFile={report_path}",
        ]


__all__ = ["MochaAdapter"]
