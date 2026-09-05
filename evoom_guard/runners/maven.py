# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ─────────────────────────────────────────────────────────────────────────────
"""Maven Surefire report adapter for the explicit EvoGuard POM bridge."""

from __future__ import annotations

import evoom_guard.runners._command as _command


class MavenAdapter:
    """Redirect Surefire through a project-declared EvoGuard property bridge.

    Surefire's ``reportsDirectory`` mojo parameter is not a Maven CLI user
    property.  A supported project therefore maps
    ``evoguard.surefire.reportsDirectory`` to that parameter in its POM; a
    project without the bridge emits no judge-owned report and fails closed.
    """

    name = "maven"

    def matches(self, cmd: list[str]) -> bool:
        return bool(cmd) and _command._executable_name(cmd[0]) in {"mvn", "mvnw"}

    def instrument(self, cmd: list[str], report_path: str) -> list[str] | None:
        tokens = [str(token) for token in cmd]
        property_names = (
            "evoguard.surefire.reportsDirectory",
            "surefire.reportsDirectory",
            "reportsDirectory",
        )
        if any(
            token == f"-D{name}" or token.startswith(f"-D{name}=")
            for token in tokens
            for name in property_names
        ) or any(
            token == "-D"
            and index + 1 < len(tokens)
            and any(
                tokens[index + 1] == name
                or tokens[index + 1].startswith(f"{name}=")
                for name in property_names
            )
            for index, token in enumerate(tokens)
        ):
            return None
        return [
            *tokens,
            f"-Devoguard.surefire.reportsDirectory={report_path}.d",
        ]


__all__ = ["MavenAdapter"]
