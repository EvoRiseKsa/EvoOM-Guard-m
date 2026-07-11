# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""The score gradient shared by the verdict engine.

Two small, pure scoring helpers used by :func:`evoom_guard.verifiers.repo_verifier.grade_repo_run`
to turn a passed/total fraction into a ``[0, 1]`` score that climbs as more tests
pass. Kept separate from any one verifier so the gradient is identical wherever it
is applied. Stdlib-only, deterministic, trivially testable.
"""

from __future__ import annotations

# Gradient anchors. A run that executes but passes zero tests stays at the
# historical 0.25 plateau; partially passing runs climb from there, always
# staying strictly below a full pass (1.0).
PARTIAL_FLOOR = 0.25
PARTIAL_CEIL = 0.95


def partial_score(stderr: str) -> float:
    """Partial credit: a syntax error is worse than a logic error.

    This gradient gives a climbing signal even before a full pass: runnable-but-wrong
    scores higher than not-runnable. The exception name is read from ``stderr``.
    """
    if "SyntaxError" in stderr:
        return 0.05
    if "NameError" in stderr:
        return 0.10
    return 0.25  # ran, but an assertion failed


def fraction_score(passed: int, total: int, stderr: str = "") -> float:
    """Map a passed/total fraction onto the score gradient.

    Zero passing tests delegates to :func:`partial_score` so the historical
    SyntaxError < NameError < AssertionError ordering is preserved. Partial passes
    land strictly inside ``(PARTIAL_FLOOR, PARTIAL_CEIL]``; only a full pass reaches
    ``1.0``.
    """
    if passed <= 0 or total <= 0:
        return partial_score(stderr)
    if passed >= total:
        return 1.0
    return PARTIAL_FLOOR + (PARTIAL_CEIL - PARTIAL_FLOOR) * (passed / total)
