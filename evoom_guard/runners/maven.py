# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ─────────────────────────────────────────────────────────────────────────────
"""Maven Surefire report adapter."""

from __future__ import annotations

import evoom_guard.runners._command as _command


class MavenAdapter:
    """Maven Surefire redirected to a judge-owned reports directory."""

    name = "maven"

    def matches(self, cmd: list[str]) -> bool:
        return bool(cmd) and _command._executable_name(cmd[0]) in {"mvn", "mvnw"}

    def instrument(self, cmd: list[str], report_path: str) -> list[str] | None:
        tokens = [str(token) for token in cmd]
        if any(token.startswith("-Dsurefire.reportsDirectory") for token in tokens):
            return None
        return [*tokens, f"-Dsurefire.reportsDirectory={report_path}.d"]


__all__ = ["MavenAdapter"]
