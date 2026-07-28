# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Dependency-free runner instrumentation contract."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class RunnerAdapter(Protocol):
    """One test runner's judge-owned report wiring."""

    name: str

    def matches(self, cmd: list[str]) -> bool: ...

    def instrument(self, cmd: list[str], report_path: str) -> list[str] | None: ...


__all__ = ["RunnerAdapter"]
