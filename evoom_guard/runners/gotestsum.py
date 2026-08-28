# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ─────────────────────────────────────────────────────────────────────────────
"""gotestsum JUnit report adapter."""

from __future__ import annotations

import evoom_guard.runners._command as _command


class GotestsumAdapter:
    """Go via ``gotestsum`` and its judge-owned ``--junitfile``."""

    name = "gotestsum"

    def matches(self, cmd: list[str]) -> bool:
        return _command._invokes_runner(cmd, "gotestsum")

    def instrument(self, cmd: list[str], report_path: str) -> list[str] | None:
        tokens = [str(token) for token in cmd]
        if any(token.startswith("--junitfile") for token in tokens):
            return None
        flag = f"--junitfile={report_path}"
        if "--" in tokens:
            index = tokens.index("--")
            return [*tokens[:index], flag, *tokens[index:]]
        return [*tokens, flag]


__all__ = ["GotestsumAdapter"]
