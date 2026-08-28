# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ─────────────────────────────────────────────────────────────────────────────
"""RSpec JUnit report adapter."""

from __future__ import annotations

import evoom_guard.runners._command as _command


class RspecAdapter:
    """Ruby RSpec via ``rspec_junit_formatter``."""

    name = "rspec"

    def matches(self, cmd: list[str]) -> bool:
        return _command._invokes_runner(cmd, "rspec")

    def instrument(self, cmd: list[str], report_path: str) -> list[str] | None:
        tokens = [str(token) for token in cmd]
        if any(
            token in ("--format", "-f") or token.startswith(("--format=", "--out"))
            for token in tokens
        ):
            return None
        return [
            *tokens,
            "--format",
            "progress",
            "--format",
            "RspecJunitFormatter",
            "--out",
            report_path,
        ]


__all__ = ["RspecAdapter"]
