"""Architecture contracts for the extracted black-box finalization owner."""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest

import evoom_guard.application as application
from evoom_guard.application.blackbox_finalization import (
    BlackboxFinalizationInput,
    BlackboxFinalizationOutcome,
    BlackboxFinalizationServices,
    finalize_blackbox_verification,
)
from evoom_guard.domain.decision import GuardDecision


def test_blackbox_finalization_is_public_and_outcome_is_frozen_slotted() -> None:
    decision = GuardDecision(
        verdict="PASS",
        reason_code="tests_passed",
        reason="ok",
    )
    baseline = {"repair_effect": "unmeasured"}
    coverage = {"measured": False}
    attestation = {"mode": "blackbox"}
    assurance = {"execution_state": "completed"}
    outcome = BlackboxFinalizationOutcome(
        decision=decision,
        risk_level="low",
        risk_score=0.1,
        tests_passed=1,
        tests_total=1,
        test_command_started=True,
        execution_state="completed",
        execution_phase="blackbox_pack",
        verdict_source="blackbox",
        diagnostics="",
        effective_candidate_isolation="subprocess",
        baseline=baseline,
        diff_coverage=coverage,
        attestation=attestation,
        assurance=assurance,
    )

    assert (
        application.finalize_blackbox_verification
        is finalize_blackbox_verification
    )
    assert (
        application.BlackboxFinalizationOutcome
        is BlackboxFinalizationOutcome
    )
    assert not hasattr(outcome, "__dict__")
    assert outcome.baseline is baseline
    assert outcome.diff_coverage is coverage
    assert outcome.attestation is attestation
    assert outcome.assurance is assurance
    with pytest.raises(FrozenInstanceError):
        outcome.execution_state = "changed"  # type: ignore[misc]


def test_blackbox_finalization_owner_has_no_runtime_effect_imports() -> None:
    root = Path(__file__).resolve().parents[1]
    tree = ast.parse(
        (
            root
            / "evoom_guard"
            / "application"
            / "blackbox_finalization.py"
        ).read_text(encoding="utf-8")
    )
    imported_modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    forbidden_prefixes = (
        "evoom_guard.blackbox",
        "evoom_guard.contracts",
        "evoom_guard.guard",
        "evoom_guard.evidence",
        "evoom_guard.execution",
        "evoom_guard.isolation",
        "evoom_guard.patchmin",
        "evoom_guard.verifiers",
        "os",
        "pathlib",
        "subprocess",
        "tempfile",
    )

    assert not {
        module
        for module in imported_modules
        if module.startswith(forbidden_prefixes)
    }


def test_guard_delegates_blackbox_finalization_once_after_runtime() -> None:
    root = Path(__file__).resolve().parents[1]
    tree = ast.parse(
        (root / "evoom_guard" / "guard.py").read_text(encoding="utf-8")
    )
    guard_function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "guard"
    )
    calls = [
        node
        for node in ast.walk(guard_function)
        if isinstance(node, ast.Call)
    ]
    runtime_calls = [
        node
        for node in calls
        if isinstance(node.func, ast.Name) and node.func.id == "run_blackbox"
    ]
    finalization_calls = [
        node
        for node in calls
        if isinstance(node.func, ast.Name)
        and node.func.id == "finalize_blackbox_verification"
    ]

    assert len(runtime_calls) == 1
    assert len(finalization_calls) == 1
    assert runtime_calls[0].lineno < finalization_calls[0].lineno


def test_guard_no_longer_owns_blackbox_decision_or_evidence_projection() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "evoom_guard" / "guard.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    guard_source = ast.unparse(
        next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "guard"
        )
    )
    owner_source = (
        root
        / "evoom_guard"
        / "application"
        / "blackbox_finalization.py"
    ).read_text(encoding="utf-8")

    for marker in (
        "REASON_CANDIDATE_NOT_EXERCISED",
        '"composite:blackbox+repo"',
        '"verifier_pack_tests_passed"',
        '"repo_suite_state"',
        "eager_shortfall=True",
    ):
        assert marker not in guard_source
        assert marker in owner_source


def test_final_wire_reads_still_precede_attestation_provider() -> None:
    timeline: list[str] = []

    class RuntimeResult:
        passed = True
        tests_passed = 1
        tests_total = 1
        ran = True
        error = None
        pack_sha256 = "a" * 64
        pack_manifest = {"id": "probe", "version": "1.0.0"}
        junit_sha256 = "b" * 64
        isolation = {
            "requested": "subprocess",
            "delivered": "subprocess",
        }
        deleted_applied: list[str] = []
        started = True
        completed = True
        execution_state = "completed"
        execution_phase = "blackbox_pack"
        pack_present = True
        candidate_invocations = 1
        candidate_launcher_invocation_observed = True

        @property
        def diagnostics(self) -> str:
            timeline.append("runtime:diagnostics")
            return ""

    class Risk:
        @property
        def level(self) -> str:
            timeline.append("risk:level")
            return "low"

        @property
        def score(self) -> float:
            timeline.append("risk:score")
            return 0.1

    def assurance(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"execution_state": "completed"}

    def shortfall(*_args: Any, **_kwargs: Any) -> None:
        return None

    def attestation(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        timeline.append("attestation:build")
        return {"mode": "blackbox"}

    outcome = finalize_blackbox_verification(
        BlackboxFinalizationInput(
            runtime_result=RuntimeResult(),
            blackbox_only=True,
            verifier_pack_path="/trusted/pack",
            candidate_text="candidate",
            safe_deleted_paths=[],
            test_command=None,
            effective_policy={},
            collect_baseline_evidence=False,
            collect_diff_coverage=False,
            require_report_integrity=None,
            require_candidate_isolation=None,
            base_sha=None,
            head_sha=None,
            base_tree_sha=None,
            head_tree_sha=None,
            policy_id=None,
            policy_version=None,
        ),
        services=BlackboxFinalizationServices(
            risk_assessor_provider=lambda: lambda: Risk(),
            composed_repo_verifier_provider=lambda: (
                lambda: pytest.fail("repo phase must not run")
            ),
            assurance_builder_provider=lambda: assurance,
            assurance_shortfall_provider=lambda: shortfall,
            attestation_builder_provider=lambda: attestation,
        ),
    )

    assert outcome.attestation == {"mode": "blackbox"}
    assert timeline[-4:] == [
        "risk:level",
        "risk:score",
        "runtime:diagnostics",
        "attestation:build",
    ]
