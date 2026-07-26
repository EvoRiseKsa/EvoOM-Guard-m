# Copyright © 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
"""pytest JUnit report adapter."""

from __future__ import annotations

import evoom_guard.runners._command as _command


class PytestAdapter:
    """pytest — append ``--junitxml=<path>`` after positional test paths."""

    name = "pytest"

    def matches(self, cmd: list[str]) -> bool:
        if _command._invokes_runner(cmd, "pytest"):
            return True
        return _command._invokes_python_module(cmd, "pytest")

    def instrument(self, cmd: list[str], report_path: str) -> list[str] | None:
        return [*cmd, f"--junitxml={report_path}", "-o", "junit_family=xunit2"]


__all__ = ["PytestAdapter"]
