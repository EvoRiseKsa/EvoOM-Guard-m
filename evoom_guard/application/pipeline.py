# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Typed, immutable cursor over the pure verification decision pipeline."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from evoom_guard.application.decision_gates import (
    AssuranceShortfallEvaluator,
    apply_assurance_gate,
    apply_demonstrated_fix_gate,
    apply_diff_coverage_gate,
)
from evoom_guard.application.repo_decision import compose_repo_decision
from evoom_guard.domain.decision import GuardDecision
from evoom_guard.domain.evidence import VerificationEvidence


@dataclass(frozen=True, slots=True)
class VerificationPipeline:
    """Carry one decision through pure stages without sequencing runtime effects.

    Guard retains ownership of when candidate execution, coverage collection,
    baseline execution, attestation assembly, and assurance-profile construction
    happen. This cursor only makes the already characterized decision order
    explicit and keeps each stage independently callable at its historical point.
    """

    decision: GuardDecision

    @classmethod
    def from_repo_facts(
        cls,
        *,
        has_changes: bool,
        unsafe_paths: Sequence[str],
        protected_violations: Sequence[str],
        verifier_present: bool,
        verifier_passed: bool | None,
        verifier_score: float | None,
        diagnostics: str,
        evidence: VerificationEvidence | None,
    ) -> VerificationPipeline:
        """Start the repo-native path from its frozen decision composer."""

        return cls(
            compose_repo_decision(
                has_changes=has_changes,
                unsafe_paths=unsafe_paths,
                protected_violations=protected_violations,
                verifier_present=verifier_present,
                verifier_passed=verifier_passed,
                verifier_score=verifier_score,
                diagnostics=diagnostics,
                evidence=evidence,
            )
        )

    @classmethod
    def from_decision(
        cls,
        decision: GuardDecision,
    ) -> VerificationPipeline:
        """Start from an already composed decision without copying it."""

        return cls(decision)

    def apply_diff_coverage(
        self,
        *,
        coverage_evidence: Mapping[str, Any],
        min_diff_coverage: int | float | None,
    ) -> VerificationPipeline:
        """Apply changed-line coverage at Guard's existing effect boundary."""

        return VerificationPipeline(
            apply_diff_coverage_gate(
                self.decision,
                coverage_evidence=coverage_evidence,
                min_diff_coverage=min_diff_coverage,
            )
        )

    def apply_demonstrated_fix(
        self,
        *,
        baseline_evidence: Mapping[str, Any],
        require_demonstrated_fix: bool,
    ) -> VerificationPipeline:
        """Apply the prepared baseline gate without running the baseline."""

        return VerificationPipeline(
            apply_demonstrated_fix_gate(
                self.decision,
                baseline_evidence=baseline_evidence,
                require_demonstrated_fix=require_demonstrated_fix,
            )
        )

    def apply_assurance(
        self,
        *,
        assurance: Mapping[str, Any],
        execution_state: str,
        execution_requested: bool,
        require_report_integrity: str | None,
        require_candidate_isolation: str | None,
        shortfall_evaluator: AssuranceShortfallEvaluator,
        eager_shortfall: bool,
    ) -> VerificationPipeline:
        """Apply delivered-assurance policy with explicit compatibility timing."""

        return VerificationPipeline(
            apply_assurance_gate(
                self.decision,
                assurance=assurance,
                execution_state=execution_state,
                execution_requested=execution_requested,
                require_report_integrity=require_report_integrity,
                require_candidate_isolation=require_candidate_isolation,
                shortfall_evaluator=shortfall_evaluator,
                eager_shortfall=eager_shortfall,
            )
        )


__all__ = ["VerificationPipeline"]
