"""Contracts for the extracted repo-native finalization coordinator."""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import evoom_guard.application as application
from evoom_guard.application.repo_finalization import (
    RepoFinalizationOutcome,
    finalize_repo_verification,
)
from evoom_guard.domain.decision import GuardDecision


def test_finalization_owner_is_public_and_outcome_is_frozen_slotted() -> None:
    decision = GuardDecision(verdict="PASS", reason_code="tests_passed", reason="ok")
    coverage = {"measured": True}
    baseline = {"repair_effect": "demonstrated"}
    attestation = {"mode": "repo"}
    assurance = {"execution_state": "completed"}

    outcome = RepoFinalizationOutcome(
        decision=decision,
        execution_state="completed",
        execution_phase="repo_suite",
        test_command_started=True,
        effective_candidate_isolation="subprocess",
        diff_coverage=coverage,
        baseline=baseline,
        attestation=attestation,
        assurance=assurance,
    )

    assert application.finalize_repo_verification is finalize_repo_verification
    assert application.RepoFinalizationOutcome is RepoFinalizationOutcome
    assert not hasattr(outcome, "__dict__")
    assert outcome.diff_coverage is coverage
    assert outcome.baseline is baseline
    assert outcome.attestation is attestation
    assert outcome.assurance is assurance
    with pytest.raises(FrozenInstanceError):
        outcome.execution_state = "changed"  # type: ignore[misc]


def test_finalization_owner_has_no_runtime_effect_imports() -> None:
    root = Path(__file__).resolve().parents[1]
    tree = ast.parse(
        (root / "evoom_guard" / "application" / "repo_finalization.py").read_text(
            encoding="utf-8"
        )
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
        "evoom_guard.guard",
        "evoom_guard.evidence",
        "evoom_guard.verifiers",
        "evoom_guard.execution",
        "evoom_guard.isolation",
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


def test_guard_delegates_repo_finalization_once() -> None:
    root = Path(__file__).resolve().parents[1]
    tree = ast.parse(
        (root / "evoom_guard" / "guard.py").read_text(encoding="utf-8")
    )
    guard_function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "guard"
    )
    delegated_calls = [
        node
        for node in ast.walk(guard_function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "finalize_repo_verification"
    ]

    assert len(delegated_calls) == 1
