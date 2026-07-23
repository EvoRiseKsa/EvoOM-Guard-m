# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Contracts for dependency-free verdict and lifecycle semantics."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import evoom_guard.domain.verdict as verdict
import evoom_guard.guard as guard_module
import evoom_guard.verdict_contract_v1_11 as legacy

ROOT = Path(__file__).resolve().parents[1]

SEMANTIC_EXPORTS = (
    "ERROR",
    "EXECUTION_COMPLETED",
    "EXECUTION_NOT_STARTED",
    "EXECUTION_STARTED_INCOMPLETE",
    "EXECUTION_STATES",
    "EXECUTION_STATIC_GATE",
    "FAIL",
    "PASS",
    "REASON_ASSURANCE_REQUIREMENT_NOT_MET",
    "REASON_BINARY_PATCH",
    "REASON_CANDIDATE_NOT_EXERCISED",
    "REASON_CANDIDATE_TREE_CHANGED",
    "REASON_CODES",
    "REASON_CONTRACT",
    "REASON_DIFF_COVERAGE_BELOW_THRESHOLD",
    "REASON_EMPTY_DIFF",
    "REASON_FIX_NOT_DEMONSTRATED",
    "REASON_JUNIT_EXIT_MISMATCH",
    "REASON_NO_PARSEABLE_EDITS",
    "REASON_NO_TEST_VERDICT",
    "REASON_NO_VERIFIABLE_CHANGES",
    "REASON_PATCH_APPLY_FAILED",
    "REASON_POLICY_REQUIREMENT_UNSUPPORTED",
    "REASON_PROTECTED_HARNESS_EDIT",
    "REASON_REVERSE_APPLY_FAILED",
    "REASON_RUNTIME_CLEANUP_FAILED",
    "REASON_SETUP_FAILED",
    "REASON_SETUP_TIMEOUT",
    "REASON_TEST_COMMAND_UNAVAILABLE",
    "REASON_TEST_TIMEOUT",
    "REASON_TESTS_FAILED",
    "REASON_TESTS_PASSED",
    "REASON_UNSAFE_PATH",
    "REASON_VERIFIER_PACK_IDENTITY_MISMATCH",
    "REASON_VERIFIER_PACK_INVALID",
    "REASON_VERIFIER_PACK_NOT_FOUND",
    "REASON_VERIFIER_PACK_REQUIRED",
    "REASON_VERIFIER_PACK_SNAPSHOT_CHANGED",
    "REJECTED",
    "TAMPERED",
    "VERDICTS",
)

VERSIONED_EXPORTS = {
    "ALLOWED_POLICY_KEYS",
    "OPTIONAL_POLICY_KEYS",
    "POLICY_KEYS",
    "REQUIRED_ASSURANCE",
    "REQUIRED_ATTESTATION",
    "REQUIRED_TOP_LEVEL",
    "SCHEMA_VERSION",
}


def test_domain_verdict_surface_is_explicit_and_frozen() -> None:
    assert tuple(verdict.__all__) == SEMANTIC_EXPORTS


def test_versioned_contract_reexports_exact_semantic_objects() -> None:
    for name in SEMANTIC_EXPORTS:
        assert getattr(legacy, name) is getattr(verdict, name), name
        if hasattr(guard_module, name):
            assert getattr(guard_module, name) is getattr(verdict, name), name


def test_versioned_contract_preserves_annotation_metadata() -> None:
    assert legacy.__annotations__ == {
        "REASON_CONTRACT": "Mapping[str, tuple[frozenset[str], frozenset[str]]]"
    }


def test_versioned_contract_remains_an_explicit_strict_mypy_api() -> None:
    source = """
from evoom_guard.verdict_contract_v1_11 import (
    PASS,
    REASON_CONTRACT,
)

verdict: str = PASS
contract: object = REASON_CONTRACT
"""
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "mypy",
            f"--config-file={os.devnull}",
            "--strict",
            "--no-incremental",
            "-c",
            source,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_versioned_wire_contract_does_not_leak_into_generic_domain() -> None:
    for name in VERSIONED_EXPORTS:
        assert not hasattr(verdict, name), name


def test_legacy_public_surface_remains_frozen() -> None:
    incidental_legacy_exports = {"Mapping", "MappingProxyType", "annotations"}
    public = {name for name in dir(legacy) if not name.startswith("_")}
    assert public == set(SEMANTIC_EXPORTS) | VERSIONED_EXPORTS | (
        incidental_legacy_exports
    )
    assert set(legacy.__all__) == public


def test_reason_contract_is_read_only_through_both_paths() -> None:
    assert legacy.REASON_CONTRACT is verdict.REASON_CONTRACT
    with pytest.raises(TypeError):
        verdict.REASON_CONTRACT["invented_reason"] = (  # type: ignore[index]
            frozenset({"PASS"}),
            frozenset({"completed"}),
        )


def test_domain_verdict_import_does_not_initialize_higher_layers() -> None:
    code = """
import sys
sys.path.insert(0, sys.argv[1])
import evoom_guard.domain.verdict

forbidden = (
    "evoom_guard.guard",
    "evoom_guard.verifiers",
    "evoom_guard.record_verifier",
    "evoom_guard.evidence",
    "evoom_guard.application",
)
loaded = sorted(
    name
    for name in sys.modules
    if any(name == root or name.startswith(root + ".") for root in forbidden)
)
assert loaded == [], loaded
"""
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code, str(ROOT)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
