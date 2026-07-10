# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Sole owner & author: Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""Shared contracts.

This module holds the single interface that makes the framework reusable: any
new domain is just a new :class:`Verifier` that satisfies this protocol, without
touching the generic core.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, TypedDict, runtime_checkable


class Problem(TypedDict, total=False):
    """A problem definition handed to a verifier.

    Fields are domain-flavoured; the code verifier uses ``signature``,
    ``description`` and ``tests``. Only ``name`` is treated as universal (it
    scopes memory). Extra keys are allowed because ``total=False``.
    """

    name: str
    signature: str
    description: str
    tests: list[str]
    # names of sibling sub-problems whose solved output should be available first
    depends_on: list[str]


@dataclass
class VerdictResult:
    """The structured result returned by every verifier.

    The whole framework rests on this object being produced by *objective*
    measurement, never by the model's opinion of its own output.
    """

    passed: bool
    """Did the hypothesis fully pass?"""

    score: float
    """Numeric score used for ranking, in [0..1]."""

    diagnostics: str
    """Diagnostic trace the generator learns from."""

    artifact: dict[str, Any] = field(default_factory=dict)
    """Extra outputs (logs, metrics)."""


@runtime_checkable
class Verifier(Protocol):
    """The unified verifier interface.

    This is the contract that makes the framework domain-agnostic. A code
    verifier runs unit tests; a trading verifier runs a strict backtest; a math
    verifier checks a proof — but they all return a :class:`VerdictResult`.

    Golden rule: a verifier must never trust the model. It executes, measures,
    and returns facts. Any trust in the model's report about itself opens the
    door to self-deception.
    """

    domain: str

    def verify(self, hypothesis: str, problem: Problem) -> VerdictResult:
        """Test ``hypothesis`` against ``problem`` and return an objective verdict."""
        ...
