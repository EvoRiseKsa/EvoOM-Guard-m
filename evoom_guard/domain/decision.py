# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Dependency-free decision value produced from verification evidence."""

from __future__ import annotations

from dataclasses import dataclass

from evoom_guard.domain.verdict import PASS


@dataclass(frozen=True, slots=True)
class GuardDecision:
    """One immutable verdict, stable reason code, and human explanation."""

    verdict: str
    reason_code: str
    reason: str

    @property
    def passed(self) -> bool:
        """Derive success from the verdict instead of storing duplicate state."""

        return self.verdict == PASS


__all__ = ["GuardDecision"]
