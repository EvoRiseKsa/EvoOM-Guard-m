# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ─────────────────────────────────────────────────────────────────────────────
"""Mocha built-in xUnit report adapter."""

from __future__ import annotations

import evoom_guard.runners._command as _command


class MochaAdapter:
    """JavaScript Mocha via its built-in ``xunit`` reporter."""

    name = "mocha"

    def matches(self, cmd: list[str]) -> bool:
        return _command._invokes_runner(cmd, "mocha")

    def instrument(self, cmd: list[str], report_path: str) -> list[str] | None:
        tokens = [str(token) for token in cmd]
        if any(
            token
            in {
                "--reporter",
                "-R",
                "--reporter-option",
                "--reporter-options",
                "-O",
            }
            or token.startswith(
                (
                    "--reporter=",
                    "--reporter-option=",
                    "--reporter-options=",
                    "-R",
                    "-O",
                )
            )
            for token in tokens
        ):
            return None
        return [
            *tokens,
            "--posix-exit-codes",
            "--reporter",
            "xunit",
            "--reporter-option",
            f"output={report_path}",
        ]


__all__ = ["MochaAdapter"]
