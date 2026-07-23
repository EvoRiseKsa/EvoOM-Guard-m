"""Contracts for pure repo-native decision composition."""

from __future__ import annotations

import ast
import math
from dataclasses import FrozenInstanceError, fields
from pathlib import Path
from typing import cast

import pytest

import evoom_guard.domain as domain
import evoom_guard.guard as guard_module
from evoom_guard.application import compose_repo_decision
from evoom_guard.application.repo_decision import (
    OUTCOME_REASON_POLICY,
    TAMPER_OUTCOME_REASON_POLICY,
)
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
from evoom_guard.verifiers.repo_evidence import (
    repo_verification_evidence_from_artifact,
)


def _evidence(artifact: dict[str, object]) -> VerificationEvidence:
    return repo_verification_evidence_from_artifact(
        artifact,
        default_isolation="subprocess",
    )


def _compose(
    *,
    has_changes: bool = True,
    unsafe_paths: tuple[str, ...] = (),
    protected_violations: tuple[str, ...] = (),
    verifier_present: bool = True,
    verifier_passed: bool | None = False,
    verifier_score: float | None = 0.5,
    diagnostics: str = "diagnostic",
    evidence: VerificationEvidence | None = None,
) -> GuardDecision:
    return compose_repo_decision(
        has_changes=has_changes,
        unsafe_paths=unsafe_paths,
        protected_violations=protected_violations,
        verifier_present=verifier_present,
        verifier_passed=verifier_passed,
        verifier_score=verifier_score,
        diagnostics=diagnostics,
        evidence=evidence,
    )


def test_decision_domain_value_is_public_frozen_slotted_and_derived() -> None:
    assert domain.GuardDecision is GuardDecision
    assert tuple(field.name for field in fields(GuardDecision)) == (
        "verdict",
        "reason_code",
        "reason",
    )
    assert "__slots__" in GuardDecision.__dict__
    assert "__dict__" not in GuardDecision.__dict__

    passed = GuardDecision(PASS, REASON_TESTS_PASSED, "ok")
    failed = GuardDecision(FAIL, REASON_TESTS_FAILED, "no")

    assert passed.passed is True
    assert failed.passed is False
    with pytest.raises(FrozenInstanceError):
        passed.verdict = FAIL  # type: ignore[misc]


def test_guard_and_repo_composer_share_exact_outcome_policy_objects() -> None:
    assert guard_module._OUTCOME_REASON is OUTCOME_REASON_POLICY
    assert guard_module._TAMPER_OUTCOME_REASON is TAMPER_OUTCOME_REASON_POLICY


def test_outcome_policy_tables_are_exact_and_immutable() -> None:
    assert dict(OUTCOME_REASON_POLICY) == {
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
    assert dict(TAMPER_OUTCOME_REASON_POLICY) == {
        "candidate_tree_changed": (
            REASON_CANDIDATE_TREE_CHANGED,
            "prepared candidate runtime tree changed during the repo-suite/verifier-pack run",
        ),
        "pack_snapshot_changed": (
            REASON_VERIFIER_PACK_SNAPSHOT_CHANGED,
            "the accepted verifier-pack snapshot changed before or during execution",
        ),
    }

    with pytest.raises(TypeError):
        cast(dict[str, tuple[str, str]], OUTCOME_REASON_POLICY)["test_timeout"] = (
            PASS,
            REASON_TESTS_PASSED,
        )
    with pytest.raises(TypeError):
        cast(dict[str, tuple[str, str]], TAMPER_OUTCOME_REASON_POLICY)["candidate_tree_changed"] = (
            REASON_TESTS_PASSED,
            "changed",
        )


@pytest.mark.parametrize(
    ("decision", "expected"),
    (
        (
            _compose(has_changes=False, verifier_passed=None, verifier_score=None),
            (
                ERROR,
                REASON_NO_PARSEABLE_EDITS,
                "no parseable edit blocks — the patch produced no <<<FILE>>> or "
                "<<<PATCH>>> edits (and no deletions) to verify",
            ),
        ),
        (
            _compose(unsafe_paths=("../escape",)),
            (
                ERROR,
                REASON_UNSAFE_PATH,
                "the patch references an unsafe path (absolute, '..', or escaping "
                "the repo root) — refusing to apply: ../escape",
            ),
        ),
        (
            _compose(protected_violations=("tests/test_app.py",)),
            (
                REJECTED,
                REASON_PROTECTED_HARNESS_EDIT,
                "reward-hack guard: the patch edits or deletes the judging tests, "
                "their configuration, the gate's CI/config, or an auto-executed "
                "file — fix the source under test, not the harness "
                "(tests/test_app.py)",
            ),
        ),
        (
            _compose(evidence=_evidence({"outcome": "candidate_tree_changed"})),
            (
                TAMPERED,
                REASON_CANDIDATE_TREE_CHANGED,
                "prepared candidate runtime tree changed during the "
                "repo-suite/verifier-pack run: diagnostic",
            ),
        ),
        (
            _compose(
                evidence=_evidence(
                    {
                        "tamper": True,
                        "tests_passed": None,
                        "tests_total": None,
                    }
                )
            ),
            (
                TAMPERED,
                REASON_JUNIT_EXIT_MISMATCH,
                "tamper signature: the suite's exit code and its judge-owned JUnit "
                "report disagree (None/None in the report) — refusing to read this "
                "as a pass",
            ),
        ),
        (
            _compose(
                evidence=_evidence(
                    {
                        "outcome": "pack_invalid",
                        "verifier_pack_present": False,
                    }
                )
            ),
            (
                ERROR,
                REASON_VERIFIER_PACK_NOT_FOUND,
                "diagnostic",
            ),
        ),
        (
            _compose(
                verifier_passed=True,
                evidence=_evidence({"outcome": "test_timeout"}),
            ),
            (
                FAIL,
                REASON_TEST_TIMEOUT,
                "diagnostic",
            ),
        ),
        (
            _compose(verifier_passed=True, evidence=_evidence({})),
            (
                PASS,
                REASON_TESTS_PASSED,
                "all repo tests pass and the patch leaves the test harness untouched",
            ),
        ),
        (
            _compose(evidence=_evidence({"tests_passed": None, "tests_total": 1})),
            (
                FAIL,
                REASON_TESTS_FAILED,
                "the repo's tests fail on this patch (None/1 passed)",
            ),
        ),
        (
            _compose(evidence=_evidence({"outcome": "no_test_verdict"})),
            (
                ERROR,
                REASON_NO_TEST_VERDICT,
                "diagnostic",
            ),
        ),
        (
            _compose(
                verifier_score=0.08,
                evidence=_evidence({}),
            ),
            (
                ERROR,
                REASON_PATCH_APPLY_FAILED,
                "the patch did not apply cleanly (a PATCH anchor did not match)",
            ),
        ),
        (
            _compose(evidence=_evidence({})),
            (
                FAIL,
                REASON_NO_TEST_VERDICT,
                "the test session produced no clean verdict (collection/usage error)",
            ),
        ),
    ),
)
def test_repo_decision_branch_matrix_is_exact(
    decision: GuardDecision,
    expected: tuple[str, str, str],
) -> None:
    assert (
        decision.verdict,
        decision.reason_code,
        decision.reason,
    ) == expected


def test_missing_pack_uses_fallback_message_only_when_diagnostics_empty() -> None:
    decision = _compose(
        diagnostics="",
        evidence=_evidence(
            {
                "outcome": "pack_invalid",
                "verifier_pack_present": False,
            }
        ),
    )

    assert decision.reason == "the configured verifier-pack path does not exist"


def test_existing_invalid_pack_is_not_mislabeled_as_missing() -> None:
    decision = _compose(
        evidence=_evidence(
            {
                "outcome": "pack_invalid",
                "verifier_pack_present": True,
            }
        )
    )

    assert decision.verdict == ERROR
    assert decision.reason_code == REASON_VERIFIER_PACK_INVALID


def test_positive_counts_precede_no_test_verdict_fallback() -> None:
    decision = _compose(
        evidence=_evidence(
            {
                "outcome": "no_test_verdict",
                "tests_passed": 1,
                "tests_total": 2,
            }
        )
    )

    assert decision.verdict == FAIL
    assert decision.reason_code == REASON_TESTS_FAILED


def test_static_refusals_precede_runtime_tamper_evidence() -> None:
    evidence = _evidence({"outcome": "candidate_tree_changed"})

    assert _compose(has_changes=False, evidence=evidence).reason_code == (REASON_NO_PARSEABLE_EDITS)
    assert _compose(unsafe_paths=("../escape",), evidence=evidence).reason_code == (
        REASON_UNSAFE_PATH
    )
    assert (
        _compose(
            protected_violations=("tests/test_app.py",),
            evidence=evidence,
        ).reason_code
        == REASON_PROTECTED_HARNESS_EDIT
    )


def test_every_overlapping_decision_gate_keeps_the_frozen_priority() -> None:
    tamper = _evidence({"outcome": "candidate_tree_changed"})
    timeout = _evidence({"outcome": "test_timeout", "tests_total": 3})
    no_verdict_with_counts = _evidence(
        {
            "outcome": "no_test_verdict",
            "tests_passed": 1,
            "tests_total": 2,
        }
    )

    assert (
        _compose(
            unsafe_paths=("../escape",),
            protected_violations=("tests/test_app.py",),
            evidence=tamper,
            verifier_passed=True,
        ).reason_code
        == REASON_UNSAFE_PATH
    )
    assert (
        _compose(
            protected_violations=("tests/test_app.py",),
            evidence=tamper,
            verifier_passed=True,
        ).reason_code
        == REASON_PROTECTED_HARNESS_EDIT
    )
    assert (
        _compose(
            evidence=tamper,
            verifier_passed=True,
        ).reason_code
        == REASON_CANDIDATE_TREE_CHANGED
    )
    assert (
        _compose(
            evidence=timeout,
            verifier_passed=True,
        ).reason_code
        == REASON_TEST_TIMEOUT
    )
    assert (
        _compose(
            evidence=no_verdict_with_counts,
            verifier_passed=True,
        ).reason_code
        == REASON_TESTS_PASSED
    )
    assert (
        _compose(
            evidence=no_verdict_with_counts,
        ).reason_code
        == REASON_TESTS_FAILED
    )


def test_pack_presence_keeps_false_distinct_from_unknown() -> None:
    missing = _compose(
        evidence=_evidence(
            {
                "outcome": "pack_invalid",
                "verifier_pack_present": False,
            }
        )
    )
    unknown = _compose(
        evidence=_evidence(
            {
                "outcome": "pack_invalid",
                "verifier_pack_present": None,
            }
        )
    )

    assert missing.reason_code == REASON_VERIFIER_PACK_NOT_FOUND
    assert unknown.reason_code == REASON_VERIFIER_PACK_INVALID


def test_absent_and_explicit_null_counts_keep_their_legacy_rendering() -> None:
    absent = _compose(
        evidence=_evidence({"tamper": True}),
    )
    explicit_null = _compose(
        evidence=_evidence(
            {
                "tamper": True,
                "tests_passed": None,
                "tests_total": None,
            }
        ),
    )

    assert "(0/0 in the report)" in absent.reason
    assert "(None/None in the report)" in explicit_null.reason


def test_tamper_summary_retains_separator_with_empty_diagnostics() -> None:
    decision = _compose(
        diagnostics="",
        evidence=_evidence({"outcome": "candidate_tree_changed"}),
    )

    assert decision.reason.endswith("run: ")


@pytest.mark.parametrize(
    ("score", "expected_reason_code"),
    (
        (0.08, REASON_PATCH_APPLY_FAILED),
        (0.0800001, REASON_NO_TEST_VERDICT),
        (math.nan, REASON_NO_TEST_VERDICT),
    ),
)
def test_patch_apply_score_boundary_is_exact(
    score: float,
    expected_reason_code: str,
) -> None:
    assert (
        _compose(
            verifier_score=score,
            evidence=_evidence({}),
        ).reason_code
        == expected_reason_code
    )


def test_verifier_presence_stays_distinct_from_malformed_null_score() -> None:
    assert (
        _compose(
            verifier_present=False,
            verifier_passed=None,
            verifier_score=None,
            evidence=_evidence({}),
        ).reason_code
        == REASON_NO_TEST_VERDICT
    )

    with pytest.raises(TypeError, match="not supported"):
        _compose(
            verifier_present=True,
            verifier_passed=False,
            verifier_score=None,
            evidence=_evidence({}),
        )


def test_application_decision_module_has_no_effectful_or_upper_layer_imports() -> None:
    module_path = (
        Path(__file__).resolve().parents[1] / "evoom_guard" / "application" / "repo_decision.py"
    )
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    imported_modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}

    forbidden_prefixes = (
        "evoom_guard.guard",
        "evoom_guard.verifiers",
        "evoom_guard.execution",
        "evoom_guard.isolation",
        "subprocess",
        "pathlib",
        "os",
    )
    assert not {module for module in imported_modules if module.startswith(forbidden_prefixes)}
