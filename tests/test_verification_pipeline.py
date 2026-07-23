"""Contracts for the pure, effect-free verification decision cursor."""

from __future__ import annotations

import ast
from collections.abc import Iterator, Mapping
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest

import evoom_guard.application as application
from evoom_guard.application.pipeline import VerificationPipeline
from evoom_guard.application.repo_decision import compose_repo_decision
from evoom_guard.domain.decision import GuardDecision
from evoom_guard.domain.verdict import (
    ERROR,
    EXECUTION_COMPLETED,
    EXECUTION_STARTED_INCOMPLETE,
    FAIL,
    PASS,
    REASON_ASSURANCE_REQUIREMENT_NOT_MET,
    REASON_DIFF_COVERAGE_BELOW_THRESHOLD,
    REASON_FIX_NOT_DEMONSTRATED,
    REASON_NO_PARSEABLE_EDITS,
    REASON_TESTS_FAILED,
    REASON_TESTS_PASSED,
)


class _TrackingMapping(Mapping[str, Any]):
    def __init__(self, values: Mapping[str, Any]) -> None:
        self._values = dict(values)
        self.events: list[str] = []

    def __getitem__(self, key: str) -> Any:
        self.events.append(f"getitem:{key}")
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        self.events.append("iter")
        return iter(self._values)

    def __len__(self) -> int:
        self.events.append("len")
        return len(self._values)

    def get(self, key: str, default: Any = None) -> Any:
        self.events.append(f"get:{key}")
        return self._values.get(key, default)


class _ShortfallEvaluator:
    def __init__(
        self,
        result: str | None,
        *,
        error: Exception | None = None,
    ) -> None:
        self._result = result
        self._error = error
        self.calls: list[tuple[Mapping[str, Any], str | None, str | None]] = []

    def __call__(
        self,
        assurance: Mapping[str, Any],
        *,
        require_report_integrity: str | None,
        require_candidate_isolation: str | None,
    ) -> str | None:
        self.calls.append(
            (
                assurance,
                require_report_integrity,
                require_candidate_isolation,
            )
        )
        if self._error is not None:
            raise self._error
        return self._result


PASS_DECISION = GuardDecision(
    verdict=PASS,
    reason_code=REASON_TESTS_PASSED,
    reason="core pass",
)


def test_pipeline_is_public_frozen_and_slotted() -> None:
    pipeline = VerificationPipeline.from_decision(PASS_DECISION)

    assert application.VerificationPipeline is VerificationPipeline
    assert pipeline.decision is PASS_DECISION
    assert not hasattr(pipeline, "__dict__")
    with pytest.raises(FrozenInstanceError):
        pipeline.decision = PASS_DECISION  # type: ignore[misc]


@pytest.mark.parametrize(
    "facts",
    (
        {
            "has_changes": True,
            "unsafe_paths": (),
            "protected_violations": (),
            "verifier_present": True,
            "verifier_passed": True,
            "verifier_score": 1.0,
            "diagnostics": "",
            "evidence": None,
        },
        {
            "has_changes": False,
            "unsafe_paths": (),
            "protected_violations": (),
            "verifier_present": False,
            "verifier_passed": None,
            "verifier_score": None,
            "diagnostics": "",
            "evidence": None,
        },
    ),
)
def test_repo_factory_delegates_all_facts_to_frozen_composer(
    facts: dict[str, Any],
) -> None:
    expected = compose_repo_decision(**facts)

    pipeline = VerificationPipeline.from_repo_facts(**facts)

    assert pipeline.decision == expected


def test_no_op_stages_preserve_decision_and_do_not_read_inputs() -> None:
    coverage = _TrackingMapping({"measured": "must-not-be-read"})
    baseline = _TrackingMapping({"repair_effect": "must-not-be-read"})
    assurance = _TrackingMapping({"report_integrity": "must-not-be-read"})
    evaluator = _ShortfallEvaluator("must not be evaluated")

    pipeline = (
        VerificationPipeline.from_decision(PASS_DECISION)
        .apply_diff_coverage(
            coverage_evidence=coverage,
            min_diff_coverage=None,
        )
        .apply_demonstrated_fix(
            baseline_evidence=baseline,
            require_demonstrated_fix=False,
        )
        .apply_assurance(
            assurance=assurance,
            execution_state=EXECUTION_STARTED_INCOMPLETE,
            execution_requested=True,
            require_report_integrity="external_process_isolated",
            require_candidate_isolation="docker",
            shortfall_evaluator=evaluator,
            eager_shortfall=False,
        )
    )

    assert pipeline.decision is PASS_DECISION
    assert coverage.events == []
    assert baseline.events == []
    assert assurance.events == []
    assert evaluator.calls == []


def test_coverage_failure_remains_authoritative_through_later_lazy_gates() -> None:
    baseline = _TrackingMapping({"repair_effect": "not_demonstrated"})
    assurance = _TrackingMapping({})
    evaluator = _ShortfallEvaluator("synthetic assurance shortfall")

    pipeline = (
        VerificationPipeline.from_decision(PASS_DECISION)
        .apply_diff_coverage(
            coverage_evidence={
                "measured": True,
                "executed": 0,
                "total": 1,
                "percent": 0.0,
            },
            min_diff_coverage=100,
        )
        .apply_demonstrated_fix(
            baseline_evidence=baseline,
            require_demonstrated_fix=True,
        )
        .apply_assurance(
            assurance=assurance,
            execution_state=EXECUTION_COMPLETED,
            execution_requested=True,
            require_report_integrity="external_process_isolated",
            require_candidate_isolation="docker",
            shortfall_evaluator=evaluator,
            eager_shortfall=False,
        )
    )

    assert pipeline.decision.verdict == FAIL
    assert pipeline.decision.reason_code == REASON_DIFF_COVERAGE_BELOW_THRESHOLD
    assert baseline.events == []
    assert assurance.events == []
    assert evaluator.calls == []


def test_demonstrated_fix_failure_precedes_lazy_assurance() -> None:
    assurance = _TrackingMapping({})
    evaluator = _ShortfallEvaluator("synthetic assurance shortfall")

    pipeline = (
        VerificationPipeline.from_decision(PASS_DECISION)
        .apply_diff_coverage(
            coverage_evidence={
                "measured": True,
                "executed": 1,
                "total": 1,
            },
            min_diff_coverage=100,
        )
        .apply_demonstrated_fix(
            baseline_evidence={
                "repair_effect": "not_demonstrated",
                "verdict": PASS,
            },
            require_demonstrated_fix=True,
        )
        .apply_assurance(
            assurance=assurance,
            execution_state=EXECUTION_COMPLETED,
            execution_requested=True,
            require_report_integrity="external_process_isolated",
            require_candidate_isolation=None,
            shortfall_evaluator=evaluator,
            eager_shortfall=False,
        )
    )

    assert pipeline.decision.verdict == FAIL
    assert pipeline.decision.reason_code == REASON_FIX_NOT_DEMONSTRATED
    assert assurance.events == []
    assert evaluator.calls == []


def test_assurance_is_the_final_demotion_after_prior_gates_pass() -> None:
    assurance: Mapping[str, Any] = {
        "report_integrity": "same_process_candidate_writable"
    }
    evaluator = _ShortfallEvaluator("synthetic assurance shortfall")

    pipeline = (
        VerificationPipeline.from_decision(PASS_DECISION)
        .apply_diff_coverage(
            coverage_evidence={
                "measured": True,
                "executed": 1,
                "total": 1,
            },
            min_diff_coverage=100,
        )
        .apply_demonstrated_fix(
            baseline_evidence={"repair_effect": "demonstrated"},
            require_demonstrated_fix=True,
        )
        .apply_assurance(
            assurance=assurance,
            execution_state=EXECUTION_COMPLETED,
            execution_requested=True,
            require_report_integrity="external_process_isolated",
            require_candidate_isolation=None,
            shortfall_evaluator=evaluator,
            eager_shortfall=False,
        )
    )

    assert pipeline.decision == GuardDecision(
        verdict=ERROR,
        reason_code=REASON_ASSURANCE_REQUIREMENT_NOT_MET,
        reason="synthetic assurance shortfall",
    )
    assert evaluator.calls == [
        (assurance, "external_process_isolated", None)
    ]
    assert evaluator.calls[0][0] is assurance


def test_eager_assurance_evaluates_but_preserves_completed_prior_failure() -> None:
    prior = GuardDecision(
        verdict=FAIL,
        reason_code=REASON_TESTS_FAILED,
        reason="prior failure",
    )
    assurance: Mapping[str, Any] = {"candidate_isolation": "subprocess"}
    evaluator = _ShortfallEvaluator("synthetic shortfall")

    pipeline = VerificationPipeline.from_decision(prior).apply_assurance(
        assurance=assurance,
        execution_state=EXECUTION_COMPLETED,
        execution_requested=False,
        require_report_integrity=None,
        require_candidate_isolation="docker",
        shortfall_evaluator=evaluator,
        eager_shortfall=True,
    )

    assert pipeline.decision is prior
    assert evaluator.calls == [(assurance, None, "docker")]


def test_pipeline_does_not_translate_stage_exceptions() -> None:
    coverage = _TrackingMapping({"measured": True})
    evaluator = _ShortfallEvaluator(
        None,
        error=RuntimeError("synthetic shortfall failure"),
    )

    with pytest.raises(KeyError, match="executed"):
        VerificationPipeline.from_decision(PASS_DECISION).apply_diff_coverage(
            coverage_evidence=coverage,
            min_diff_coverage=100,
        )
    with pytest.raises(KeyError, match="repair_effect"):
        VerificationPipeline.from_decision(PASS_DECISION).apply_demonstrated_fix(
            baseline_evidence={},
            require_demonstrated_fix=True,
        )
    with pytest.raises(RuntimeError, match="synthetic shortfall failure"):
        VerificationPipeline.from_decision(PASS_DECISION).apply_assurance(
            assurance={},
            execution_state=EXECUTION_COMPLETED,
            execution_requested=True,
            require_report_integrity=None,
            require_candidate_isolation=None,
            shortfall_evaluator=evaluator,
            eager_shortfall=False,
        )


def test_pipeline_module_is_effect_free_and_guard_uses_only_the_facade() -> None:
    root = Path(__file__).resolve().parents[1]
    pipeline_tree = ast.parse(
        (root / "evoom_guard" / "application" / "pipeline.py").read_text(
            encoding="utf-8"
        )
    )
    imported_modules = {
        alias.name
        for node in ast.walk(pipeline_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module or ""
        for node in ast.walk(pipeline_tree)
        if isinstance(node, ast.ImportFrom)
    }
    forbidden_prefixes = (
        "evoom_guard.guard",
        "evoom_guard.execution",
        "evoom_guard.verifiers",
        "evoom_guard.evidence",
        "subprocess",
        "pathlib",
        "os",
    )
    assert not {
        module
        for module in imported_modules
        if module.startswith(forbidden_prefixes)
    }

    guard_tree = ast.parse(
        (root / "evoom_guard" / "guard.py").read_text(encoding="utf-8")
    )
    direct_calls = {
        node.func.id
        for node in ast.walk(guard_tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not direct_calls & {
        "apply_assurance_gate",
        "apply_demonstrated_fix_gate",
        "apply_diff_coverage_gate",
        "compose_repo_decision",
    }


def test_no_changes_factory_retains_the_frozen_reason() -> None:
    pipeline = VerificationPipeline.from_repo_facts(
        has_changes=False,
        unsafe_paths=(),
        protected_violations=(),
        verifier_present=False,
        verifier_passed=None,
        verifier_score=None,
        diagnostics="",
        evidence=None,
    )

    assert pipeline.decision.verdict == ERROR
    assert pipeline.decision.reason_code == REASON_NO_PARSEABLE_EDITS
