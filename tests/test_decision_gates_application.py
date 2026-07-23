"""Contracts for pure post-decision application gates."""

from __future__ import annotations

import ast
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, cast

import pytest

import evoom_guard.application as application
from evoom_guard.application.decision_gates import (
    apply_demonstrated_fix_gate,
    apply_diff_coverage_gate,
)
from evoom_guard.domain.decision import GuardDecision
from evoom_guard.domain.verdict import (
    ERROR,
    FAIL,
    PASS,
    REASON_ASSURANCE_REQUIREMENT_NOT_MET,
    REASON_DIFF_COVERAGE_BELOW_THRESHOLD,
    REASON_FIX_NOT_DEMONSTRATED,
    REASON_TESTS_FAILED,
    REASON_TESTS_PASSED,
)


class _TrackingCoverage(Mapping[str, Any]):
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


class _IndependentComparison:
    def __init__(
        self,
        *,
        equal: bool = False,
        not_equal: bool = False,
        raise_equal: bool = False,
        raise_not_equal: bool = False,
    ) -> None:
        self._equal = equal
        self._not_equal = not_equal
        self._raise_equal = raise_equal
        self._raise_not_equal = raise_not_equal
        self.events: list[str] = []

    def __eq__(self, other: object) -> bool:
        self.events.append(f"eq:{other}")
        if self._raise_equal:
            raise RuntimeError("synthetic __eq__ failure")
        return self._equal

    def __ne__(self, other: object) -> bool:
        self.events.append(f"ne:{other}")
        if self._raise_not_equal:
            raise RuntimeError("synthetic __ne__ failure")
        return self._not_equal


PASS_DECISION = GuardDecision(
    verdict=PASS,
    reason_code=REASON_TESTS_PASSED,
    reason="core pass",
)


def test_application_exports_diff_coverage_gate() -> None:
    assert application.apply_diff_coverage_gate is apply_diff_coverage_gate


def test_application_exports_demonstrated_fix_gate() -> None:
    assert application.apply_demonstrated_fix_gate is apply_demonstrated_fix_gate


@pytest.mark.parametrize(
    "decision,minimum",
    [
        (PASS_DECISION, None),
        (
            GuardDecision(
                verdict=FAIL,
                reason_code=REASON_TESTS_FAILED,
                reason="prior failure",
            ),
            100,
        ),
        (
            GuardDecision(
                verdict=ERROR,
                reason_code=REASON_ASSURANCE_REQUIREMENT_NOT_MET,
                reason="prior error",
            ),
            100,
        ),
    ],
)
def test_optional_or_prior_non_pass_returns_identity_without_evidence_reads(
    decision: GuardDecision,
    minimum: int | None,
) -> None:
    coverage = _TrackingCoverage({"measured": True})

    result = apply_diff_coverage_gate(
        decision,
        coverage_evidence=coverage,
        min_diff_coverage=minimum,
    )

    assert result is decision
    assert coverage.events == []


def test_required_unmeasured_fails_closed_with_historical_read_order() -> None:
    coverage = _TrackingCoverage(
        {
            "measured": False,
            "note": "coverage report unavailable",
        }
    )

    result = apply_diff_coverage_gate(
        PASS_DECISION,
        coverage_evidence=coverage,
        min_diff_coverage=80.0,
    )

    assert result == GuardDecision(
        verdict=ERROR,
        reason_code=REASON_ASSURANCE_REQUIREMENT_NOT_MET,
        reason=(
            "required changed-line coverage could not be measured: coverage report unavailable"
        ),
    )
    assert coverage.events == ["get:measured", "get:note"]


def test_exact_ratio_controls_shortfall_and_display_fields_are_read_late() -> None:
    coverage = _TrackingCoverage(
        {
            "measured": True,
            "executed": 2,
            "total": 3,
            "percent": 66.7,
        }
    )

    result = apply_diff_coverage_gate(
        PASS_DECISION,
        coverage_evidence=coverage,
        min_diff_coverage=66.66666666666667,
    )

    assert result.verdict == FAIL
    assert result.reason_code == REASON_DIFF_COVERAGE_BELOW_THRESHOLD
    assert "2/3" in result.reason
    assert "66.7%" in result.reason
    assert coverage.events == [
        "get:measured",
        "getitem:executed",
        "getitem:total",
        "getitem:executed",
        "getitem:total",
        "getitem:percent",
    ]


@pytest.mark.parametrize(
    "executed,total,minimum",
    [
        (80, 100, 80),
        (81, 100, 80),
        (1, 8, 12.5),
        (0, 0, 100),
        (0, -1, 100),
    ],
)
def test_satisfied_or_empty_denominator_preserves_decision_without_percent_read(
    executed: int,
    total: int,
    minimum: int | float,
) -> None:
    coverage = _TrackingCoverage(
        {
            "measured": True,
            "executed": executed,
            "total": total,
            "percent": "must-not-be-read",
        }
    )

    result = apply_diff_coverage_gate(
        PASS_DECISION,
        coverage_evidence=coverage,
        min_diff_coverage=minimum,
    )

    assert result is PASS_DECISION
    assert coverage.events == [
        "get:measured",
        "getitem:executed",
        "getitem:total",
    ]


@pytest.mark.parametrize(
    "values,error_type",
    [
        ({"measured": True, "total": 1}, KeyError),
        (
            {
                "measured": True,
                "executed": "not-an-integer",
                "total": 1,
            },
            ValueError,
        ),
    ],
)
def test_malformed_evidence_retains_native_exception_contract(
    values: Mapping[str, Any],
    error_type: type[Exception],
) -> None:
    with pytest.raises(error_type):
        apply_diff_coverage_gate(
            PASS_DECISION,
            coverage_evidence=values,
            min_diff_coverage=80,
        )


@pytest.mark.parametrize(
    "decision,required",
    [
        (PASS_DECISION, False),
        (
            GuardDecision(
                verdict=FAIL,
                reason_code=REASON_DIFF_COVERAGE_BELOW_THRESHOLD,
                reason="prior coverage failure",
            ),
            True,
        ),
        (
            GuardDecision(
                verdict=ERROR,
                reason_code=REASON_ASSURANCE_REQUIREMENT_NOT_MET,
                reason="prior error",
            ),
            True,
        ),
    ],
)
def test_demonstrated_fix_optional_or_non_pass_returns_identity_without_reads(
    decision: GuardDecision,
    required: bool,
) -> None:
    baseline = _TrackingCoverage({})

    result = apply_demonstrated_fix_gate(
        decision,
        baseline_evidence=baseline,
        require_demonstrated_fix=required,
    )

    assert result is decision
    assert baseline.events == []


def test_demonstrated_repair_effect_preserves_pass_without_verdict_read() -> None:
    baseline = _TrackingCoverage(
        {
            "repair_effect": "demonstrated",
            "verdict": "must-not-be-read",
        }
    )

    result = apply_demonstrated_fix_gate(
        PASS_DECISION,
        baseline_evidence=baseline,
        require_demonstrated_fix=True,
    )

    assert result is PASS_DECISION
    assert baseline.events == ["getitem:repair_effect"]


def test_green_baseline_demotes_with_exact_read_order_and_reason() -> None:
    baseline = _TrackingCoverage(
        {
            "repair_effect": "not_demonstrated",
            "verdict": PASS,
        }
    )

    result = apply_demonstrated_fix_gate(
        PASS_DECISION,
        baseline_evidence=baseline,
        require_demonstrated_fix=True,
    )

    assert result == GuardDecision(
        verdict=FAIL,
        reason_code=REASON_FIX_NOT_DEMONSTRATED,
        reason=(
            "the suite passes on the candidate, but the fix is not "
            "demonstrated: the pristine base already passes the same suite"
            " — --require-demonstrated-fix demands baseline FAIL → "
            "candidate PASS under an unchanged harness"
        ),
    )
    assert baseline.events == ["getitem:repair_effect", "get:verdict"]


def test_missing_baseline_verdict_uses_historical_fallback() -> None:
    baseline = _TrackingCoverage({"repair_effect": "not_demonstrated"})

    result = apply_demonstrated_fix_gate(
        PASS_DECISION,
        baseline_evidence=baseline,
        require_demonstrated_fix=True,
    )

    assert "produced no clean baseline verdict" in result.reason
    assert baseline.events == ["getitem:repair_effect", "get:verdict"]


def test_missing_repair_effect_retains_key_error_contract() -> None:
    with pytest.raises(KeyError, match="repair_effect"):
        apply_demonstrated_fix_gate(
            PASS_DECISION,
            baseline_evidence={},
            require_demonstrated_fix=True,
        )


def test_demonstrated_fix_preserves_historical_verdict_equality_protocol() -> None:
    verdict = _IndependentComparison(equal=False, raise_not_equal=True)
    decision = GuardDecision(
        verdict=cast(str, verdict),
        reason_code=REASON_TESTS_FAILED,
        reason="synthetic prior decision",
    )
    baseline = _TrackingCoverage({})

    result = apply_demonstrated_fix_gate(
        decision,
        baseline_evidence=baseline,
        require_demonstrated_fix=True,
    )

    assert result is decision
    assert verdict.events == [f"eq:{PASS}"]
    assert baseline.events == []


def test_demonstrated_fix_preserves_historical_effect_inequality_protocol() -> None:
    repair_effect = _IndependentComparison(
        not_equal=False,
        raise_equal=True,
    )
    baseline = _TrackingCoverage(
        {
            "repair_effect": repair_effect,
            "verdict": "must-not-be-read",
        }
    )

    result = apply_demonstrated_fix_gate(
        PASS_DECISION,
        baseline_evidence=baseline,
        require_demonstrated_fix=True,
    )

    assert result is PASS_DECISION
    assert repair_effect.events == ["ne:demonstrated"]
    assert baseline.events == ["getitem:repair_effect"]


def test_decision_gate_module_has_no_effectful_or_upstream_imports() -> None:
    module_path = (
        Path(__file__).resolve().parents[1] / "evoom_guard" / "application" / "decision_gates.py"
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
        "evoom_guard.execution",
        "evoom_guard.verifiers",
        "evoom_guard.evidence",
        "subprocess",
        "pathlib",
        "os",
    )
    assert not {module for module in imported_modules if module.startswith(forbidden_prefixes)}
