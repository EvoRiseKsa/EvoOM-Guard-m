# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Pure, ordered demotions applied after the core repository decision."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from evoom_guard.domain.decision import GuardDecision
from evoom_guard.domain.verdict import (
    ERROR,
    FAIL,
    PASS,
    REASON_ASSURANCE_REQUIREMENT_NOT_MET,
    REASON_DIFF_COVERAGE_BELOW_THRESHOLD,
    REASON_FIX_NOT_DEMONSTRATED,
)


def apply_diff_coverage_gate(
    decision: GuardDecision,
    *,
    coverage_evidence: Mapping[str, Any],
    min_diff_coverage: int | float | None,
) -> GuardDecision:
    """Demote a completed PASS that lacks the required changed-line coverage.

    The count ratio is compared exactly. The rounded ``percent`` field is
    display evidence only and is read only when composing a shortfall reason.
    Prior non-PASS decisions and optional evidence remain untouched without
    reading the coverage mapping.
    """

    if decision.verdict != PASS or min_diff_coverage is None:
        return decision

    coverage_below_floor = False
    if coverage_evidence.get("measured") is not True:
        return GuardDecision(
            verdict=ERROR,
            reason_code=REASON_ASSURANCE_REQUIREMENT_NOT_MET,
            reason=(
                "required changed-line coverage could not be measured: "
                f"{coverage_evidence.get('note', 'the collector returned no reason')}"
            ),
        )

    coverage_executed = int(coverage_evidence["executed"])
    coverage_total = int(coverage_evidence["total"])
    if isinstance(min_diff_coverage, int):
        floor_numerator, floor_denominator = min_diff_coverage, 1
    else:
        floor_numerator, floor_denominator = min_diff_coverage.as_integer_ratio()
    coverage_below_floor = (
        coverage_total > 0
        and 100 * coverage_executed * floor_denominator < floor_numerator * coverage_total
    )
    if coverage_below_floor:
        return GuardDecision(
            verdict=FAIL,
            reason_code=REASON_DIFF_COVERAGE_BELOW_THRESHOLD,
            reason=(
                "the suite passes but executed only "
                f"{coverage_evidence['executed']}/{coverage_evidence['total']} of the "
                "changed executable lines; the exact ratio is below the required "
                f"{min_diff_coverage:g}% (the evidence display rounds it to "
                f"{coverage_evidence['percent']}%) — the change is largely "
                "unexercised by the tests that judged it"
            ),
        )
    return decision


def apply_demonstrated_fix_gate(
    decision: GuardDecision,
    *,
    baseline_evidence: Mapping[str, Any],
    require_demonstrated_fix: bool,
) -> GuardDecision:
    """Demote a PASS unless the prepared baseline shows the required transition."""

    if (
        require_demonstrated_fix
        and decision.verdict == PASS
        and baseline_evidence["repair_effect"] != "demonstrated"
    ):
        baseline_state = (
            "already passes the same suite"
            if baseline_evidence.get("verdict") == PASS
            else "produced no clean baseline verdict"
        )
        return GuardDecision(
            verdict=FAIL,
            reason_code=REASON_FIX_NOT_DEMONSTRATED,
            reason=(
                "the suite passes on the candidate, but the fix is not "
                "demonstrated: the pristine base "
                f"{baseline_state}"
                " — --require-demonstrated-fix demands baseline FAIL → "
                "candidate PASS under an unchanged harness"
            ),
        )
    return decision


__all__ = [
    "apply_demonstrated_fix_gate",
    "apply_diff_coverage_gate",
]
