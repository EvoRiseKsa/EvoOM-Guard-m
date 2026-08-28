# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
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
