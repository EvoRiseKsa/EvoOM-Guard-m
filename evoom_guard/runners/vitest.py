# Copyright © 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
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
