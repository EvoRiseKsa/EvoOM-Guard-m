# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ─────────────────────────────────────────────────────────────────────────────
"""Node built-in test-runner JUnit adapter."""

from __future__ import annotations

import evoom_guard.runners._command as _command


class NodeTestAdapter:
    """Node's built-in ``node --test`` runner."""

    name = "node --test"

    def matches(self, cmd: list[str]) -> bool:
        tokens = [str(token) for token in cmd]
        return (
            bool(tokens)
            and _command._executable_name(tokens[0]) == "node"
            and "--test" in tokens
        )

    def instrument(self, cmd: list[str], report_path: str) -> list[str] | None:
        tokens = [str(token) for token in cmd]
        if any(token.startswith("--test-reporter") for token in tokens):
            return None
        report = [
            "--test-reporter=junit",
            f"--test-reporter-destination={report_path}",
            "--test-reporter=spec",
            "--test-reporter-destination=stdout",
        ]
        index = tokens.index("--test")
        return [*cmd[: index + 1], *report, *cmd[index + 1 :]]


__all__ = ["NodeTestAdapter"]
