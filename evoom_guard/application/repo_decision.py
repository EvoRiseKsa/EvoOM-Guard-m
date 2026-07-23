# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Pure composition of repository verification facts into one Guard decision."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import cast

from evoom_guard.domain.decision import GuardDecision
from evoom_guard.domain.evidence import VerificationEvidence
from evoom_guard.domain.verdict import (
    ERROR,
    FAIL,
    PASS,
    REASON_ASSURANCE_REQUIREMENT_NOT_MET,
    REASON_CANDIDATE_TREE_CHANGED,
    REASON_JUNIT_EXIT_MISMATCH,
    REASON_NO_PARSEABLE_EDITS,
    REASON_NO_TEST_VERDICT,
    REASON_PATCH_APPLY_FAILED,
    REASON_PROTECTED_HARNESS_EDIT,
    REASON_RUNTIME_CLEANUP_FAILED,
    REASON_SETUP_FAILED,
    REASON_SETUP_TIMEOUT,
    REASON_TEST_COMMAND_UNAVAILABLE,
    REASON_TEST_TIMEOUT,
    REASON_TESTS_FAILED,
    REASON_TESTS_PASSED,
    REASON_UNSAFE_PATH,
    REASON_VERIFIER_PACK_IDENTITY_MISMATCH,
    REASON_VERIFIER_PACK_INVALID,
    REASON_VERIFIER_PACK_NOT_FOUND,
    REASON_VERIFIER_PACK_SNAPSHOT_CHANGED,
    REJECTED,
    TAMPERED,
)

# Shared outcome policy for repo-native composition and Guard's existing
# black-box compatibility path. Moving this table does not change its values or
# priority; both callers import the same objects from this application owner.
OUTCOME_REASON_POLICY: Mapping[str, tuple[str, str]] = MappingProxyType(
    {
        "test_timeout": (FAIL, REASON_TEST_TIMEOUT),
        "test_output_limit": (ERROR, REASON_TEST_TIMEOUT),
        "setup_timeout": (ERROR, REASON_SETUP_TIMEOUT),
        "setup_output_limit": (ERROR, REASON_SETUP_TIMEOUT),
        "setup_failed": (ERROR, REASON_SETUP_FAILED),
        "runtime_containment_error": (ERROR, REASON_RUNTIME_CLEANUP_FAILED),
        "isolation_unavailable": (ERROR, REASON_ASSURANCE_REQUIREMENT_NOT_MET),
        "runtime_identity_unavailable": (
            ERROR,
            REASON_ASSURANCE_REQUIREMENT_NOT_MET,
        ),
        "pack_identity_mismatch": (
            ERROR,
            REASON_VERIFIER_PACK_IDENTITY_MISMATCH,
        ),
        "pack_invalid": (ERROR, REASON_VERIFIER_PACK_INVALID),
        "test_command_unavailable": (ERROR, REASON_TEST_COMMAND_UNAVAILABLE),
        "pack_no_tests": (ERROR, REASON_NO_TEST_VERDICT),
        "pack_no_verdict": (ERROR, REASON_NO_TEST_VERDICT),
        "no_test_verdict": (ERROR, REASON_NO_TEST_VERDICT),
    }
)

TAMPER_OUTCOME_REASON_POLICY: Mapping[str, tuple[str, str]] = MappingProxyType(
    {
        "candidate_tree_changed": (
            REASON_CANDIDATE_TREE_CHANGED,
            "prepared candidate runtime tree changed during the repo-suite/verifier-pack run",
        ),
        "pack_snapshot_changed": (
            REASON_VERIFIER_PACK_SNAPSHOT_CHANGED,
            "the accepted verifier-pack snapshot changed before or during execution",
        ),
    }
)


def compose_repo_decision(
    *,
    has_changes: bool,
    unsafe_paths: Sequence[str],
    protected_violations: Sequence[str],
    verifier_present: bool,
    verifier_passed: bool | None,
    verifier_score: float | None,
    diagnostics: str,
    evidence: VerificationEvidence | None,
) -> GuardDecision:
    """Apply the frozen repo-native decision priority to typed inputs."""

    if not has_changes:
        return GuardDecision(
            verdict=ERROR,
            reason_code=REASON_NO_PARSEABLE_EDITS,
            reason=(
                "no parseable edit blocks — the patch produced no <<<FILE>>> or "
                "<<<PATCH>>> edits (and no deletions) to verify"
            ),
        )
    if unsafe_paths:
        return GuardDecision(
            verdict=ERROR,
            reason_code=REASON_UNSAFE_PATH,
            reason=(
                "the patch references an unsafe path (absolute, '..', or escaping the "
                f"repo root) — refusing to apply: {', '.join(unsafe_paths)}"
            ),
        )
    if protected_violations:
        return GuardDecision(
            verdict=REJECTED,
            reason_code=REASON_PROTECTED_HARNESS_EDIT,
            reason=(
                "reward-hack guard: the patch edits or deletes the judging tests, their "
                "configuration, the gate's CI/config, or an auto-executed file — fix "
                "the source under test, not the harness "
                f"({', '.join(protected_violations)})"
            ),
        )

    if evidence is not None and evidence.outcome in TAMPER_OUTCOME_REASON_POLICY:
        assert evidence.outcome is not None
        reason_code, summary = TAMPER_OUTCOME_REASON_POLICY[evidence.outcome]
        return GuardDecision(
            verdict=TAMPERED,
            reason_code=reason_code,
            reason=f"{summary}: {diagnostics}",
        )
    if evidence is not None and evidence.tamper:
        tests_passed = evidence.tests_passed if evidence.tests_passed_present else 0
        tests_total = evidence.tests_total if evidence.tests_total_present else 0
        return GuardDecision(
            verdict=TAMPERED,
            reason_code=REASON_JUNIT_EXIT_MISMATCH,
            reason=(
                "tamper signature: the suite's exit code and its judge-owned JUnit "
                f"report disagree ({tests_passed}/{tests_total} in the report) — "
                "refusing to read this as a pass"
            ),
        )
    if (
        evidence is not None
        and evidence.outcome == "pack_invalid"
        and evidence.verifier_pack.present is False
    ):
        return GuardDecision(
            verdict=ERROR,
            reason_code=REASON_VERIFIER_PACK_NOT_FOUND,
            reason=diagnostics or "the configured verifier-pack path does not exist",
        )
    if (
        evidence is not None
        and evidence.outcome in OUTCOME_REASON_POLICY
        and evidence.outcome != "no_test_verdict"
    ):
        assert evidence.outcome is not None
        verdict, reason_code = OUTCOME_REASON_POLICY[evidence.outcome]
        return GuardDecision(
            verdict=verdict,
            reason_code=reason_code,
            reason=diagnostics or f"run ended: {evidence.outcome}",
        )
    if verifier_passed:
        return GuardDecision(
            verdict=PASS,
            reason_code=REASON_TESTS_PASSED,
            reason=("all repo tests pass and the patch leaves the test harness untouched"),
        )
    if evidence is not None and evidence.tests_total:
        tests_passed = evidence.tests_passed if evidence.tests_passed_present else 0
        return GuardDecision(
            verdict=FAIL,
            reason_code=REASON_TESTS_FAILED,
            reason=(
                "the repo's tests fail on this patch "
                f"({tests_passed}/{evidence.tests_total} passed)"
            ),
        )
    if evidence is not None and evidence.outcome in OUTCOME_REASON_POLICY:
        assert evidence.outcome is not None
        verdict, reason_code = OUTCOME_REASON_POLICY[evidence.outcome]
        return GuardDecision(
            verdict=verdict,
            reason_code=reason_code,
            reason=diagnostics or f"run ended: {evidence.outcome}",
        )
    # ``verifier_present`` deliberately remains separate from the score.
    # Historically a malformed VerdictResult with score=None raised the native
    # comparison TypeError; collapsing it into "no verifier" would silently
    # change that compatibility behavior.
    if verifier_present and cast(float, verifier_score) <= 0.08:
        return GuardDecision(
            verdict=ERROR,
            reason_code=REASON_PATCH_APPLY_FAILED,
            reason="the patch did not apply cleanly (a PATCH anchor did not match)",
        )
    return GuardDecision(
        verdict=FAIL,
        reason_code=REASON_NO_TEST_VERDICT,
        reason="the test session produced no clean verdict (collection/usage error)",
    )


__all__ = [
    "compose_repo_decision",
]
