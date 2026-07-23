"""Contracts for immutable, pure assurance composition."""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError, fields
from pathlib import Path
from typing import cast

import pytest

import evoom_guard.application as application
import evoom_guard.domain as domain
import evoom_guard.guard as guard_module
from evoom_guard.application.assurance import (
    ISOLATION_RANK_POLICY,
    REPORT_INTEGRITY_RANK_POLICY,
    assurance_profile,
    assurance_shortfall,
    pack_assurance,
    preflight_assurance_profile,
    static_assurance_profile,
)
from evoom_guard.domain.assurance import AssuranceProfile, VerifierPackAssurance
from evoom_guard.domain.verdict import (
    EXECUTION_COMPLETED,
    EXECUTION_STARTED_INCOMPLETE,
    EXECUTION_STATIC_GATE,
)


def _profile(*, repo_native_suite_present: bool = False) -> AssuranceProfile:
    return AssuranceProfile(
        execution_state=EXECUTION_COMPLETED,
        execution_phase="complete",
        harness_integrity="pre_gate_enforced",
        report_integrity="same_process_candidate_writable",
        candidate_isolation="subprocess",
        suite_isolation="subprocess",
        setup_isolation=None,
        runtime_continuity="not_applicable",
        verifier_pack=None,
        overall_profile="repo_native_same_process",
        note="note",
        repo_native_suite=None,
        repo_native_suite_present=repo_native_suite_present,
    )


def test_assurance_domain_values_are_public_frozen_and_slotted() -> None:
    assert domain.AssuranceProfile is AssuranceProfile
    assert domain.VerifierPackAssurance is VerifierPackAssurance
    assert tuple(field.name for field in fields(VerifierPackAssurance)) == (
        "configured",
        "present",
        "integrity",
        "identity_verified",
        "execution_state",
        "secrecy",
        "snapshot_sha256",
    )
    assert tuple(field.name for field in fields(AssuranceProfile)) == (
        "execution_state",
        "execution_phase",
        "harness_integrity",
        "report_integrity",
        "candidate_isolation",
        "suite_isolation",
        "setup_isolation",
        "runtime_continuity",
        "verifier_pack",
        "overall_profile",
        "note",
        "repo_native_suite",
        "repo_native_suite_present",
    )
    assert "__slots__" in AssuranceProfile.__dict__
    assert "__dict__" not in AssuranceProfile.__dict__

    profile = _profile()
    with pytest.raises(FrozenInstanceError):
        profile.execution_state = "changed"  # type: ignore[misc]
    with pytest.raises(TypeError, match="present must be bool or None"):
        VerifierPackAssurance(
            configured=True,
            present=[],  # type: ignore[arg-type]
            integrity="not_evaluated",
            identity_verified=None,
            execution_state="not_started",
            secrecy="not_evaluated_no_execution",
            snapshot_sha256=None,
        )
    typed_pack = VerifierPackAssurance(
        configured=True,
        present=True,
        integrity="verified_snapshot_pre_post",
        identity_verified=True,
        execution_state=EXECUTION_COMPLETED,
        secrecy="unmounted_from_candidate",
        snapshot_sha256="sha256:pack",
    )
    assert isinstance(hash(typed_pack), int)


def test_payload_projection_returns_fresh_exact_key_shapes() -> None:
    without_repo_suite = _profile()
    with_repo_suite = _profile(repo_native_suite_present=True)

    first = without_repo_suite.to_payload()
    second = without_repo_suite.to_payload()
    assert first == second
    assert first is not second
    assert tuple(first) == (
        "execution_state",
        "execution_phase",
        "harness_integrity",
        "report_integrity",
        "candidate_isolation",
        "suite_isolation",
        "setup_isolation",
        "runtime_continuity",
        "verifier_pack",
        "overall_profile",
        "note",
    )
    assert "repo_native_suite" not in first
    with_repo_payload = with_repo_suite.to_payload()
    assert with_repo_payload["repo_native_suite"] is None
    assert tuple(with_repo_payload) == (
        "execution_state",
        "execution_phase",
        "harness_integrity",
        "report_integrity",
        "candidate_isolation",
        "suite_isolation",
        "setup_isolation",
        "runtime_continuity",
        "verifier_pack",
        "repo_native_suite",
        "overall_profile",
        "note",
    )

    first["execution_state"] = "mutated"
    assert without_repo_suite.execution_state == EXECUTION_COMPLETED
    assert without_repo_suite.to_payload()["execution_state"] == EXECUTION_COMPLETED


def test_assurance_policies_are_exact_immutable_and_shared_with_guard() -> None:
    assert dict(REPORT_INTEGRITY_RANK_POLICY) == {
        "same_process_candidate_writable": 0,
        "external_process_isolated": 1,
    }
    assert dict(ISOLATION_RANK_POLICY) == {
        "subprocess": 0,
        "docker": 1,
        "gvisor": 2,
    }
    assert guard_module._REPORT_INTEGRITY_RANK is REPORT_INTEGRITY_RANK_POLICY
    assert guard_module._ISOLATION_RANK is ISOLATION_RANK_POLICY

    with pytest.raises(TypeError):
        cast(dict[str, int], REPORT_INTEGRITY_RANK_POLICY)["same_process_candidate_writable"] = 99
    with pytest.raises(TypeError):
        cast(dict[str, int], ISOLATION_RANK_POLICY)["subprocess"] = 99


def test_guard_compatibility_names_delegate_to_application_owners() -> None:
    assert guard_module._assurance_profile is assurance_profile
    assert guard_module._assurance_shortfall is assurance_shortfall
    assert guard_module._pack_assurance is pack_assurance
    assert guard_module._preflight_assurance_profile is preflight_assurance_profile
    assert guard_module._static_assurance_profile is static_assurance_profile
    assert application.assurance_profile is assurance_profile
    assert application.assurance_shortfall is assurance_shortfall


def test_static_profile_and_pack_shape_are_exact() -> None:
    assert static_assurance_profile("pack") == {
        "execution_state": EXECUTION_STATIC_GATE,
        "execution_phase": "pre_gate",
        "harness_integrity": "pre_gate_enforced",
        "report_integrity": "not_applicable_static_gate",
        "candidate_isolation": "not_run",
        "suite_isolation": "not_run",
        "setup_isolation": None,
        "runtime_continuity": "not_applicable",
        "verifier_pack": {
            "configured": True,
            "present": None,
            "integrity": "not_evaluated_static_gate",
            "identity_verified": None,
            "execution_state": EXECUTION_STATIC_GATE,
            "secrecy": "not_evaluated_static_gate",
            "snapshot_sha256": None,
        },
        "overall_profile": "static_gate",
        "note": (
            "the diff pre-gate decided this result before candidate execution; "
            "no test command, runtime boundary, report channel, setup, or verifier "
            "pack was exercised. Requested runtime policy is recorded only in "
            "attestation.effective_policy."
        ),
    }


def test_partial_pack_and_preflight_truthiness_remain_compatible() -> None:
    pack = pack_assurance(
        "pack",
        evidence={
            "present": None,
            "snapshot_sha256": "sha256:pack",
            "started": 1,
            "completed": 0,
        },
    )
    assert pack == {
        "configured": True,
        "present": None,
        "integrity": "verified_snapshot_pre_execution",
        "identity_verified": True,
        "execution_state": EXECUTION_STARTED_INCOMPLETE,
        "secrecy": "readable_in_judge_process",
        "snapshot_sha256": "sha256:pack",
    }
    assert tuple(pack) == (
        "configured",
        "present",
        "integrity",
        "identity_verified",
        "execution_state",
        "secrecy",
        "snapshot_sha256",
    )

    preflight = preflight_assurance_profile(
        "pack",
        execution_state=EXECUTION_STARTED_INCOMPLETE,
        execution_phase="setup",
        pack_evidence={
            "present": True,
            "snapshot_sha256": "sha256:pack",
        },
    )
    assert preflight["overall_profile"] == "execution_incomplete_before_tests"
    assert preflight["candidate_isolation"] == "not_run"
    assert preflight["verifier_pack"] == {
        "configured": True,
        "present": True,
        "integrity": "verified_snapshot_pre_execution",
        "identity_verified": True,
        "execution_state": "not_started",
        "secrecy": "not_evaluated_no_execution",
        "snapshot_sha256": "sha256:pack",
    }


def test_untyped_private_pack_inputs_are_confined_to_compatibility_payload() -> None:
    legacy_present: list[str] = []
    legacy_snapshot: dict[str, str] = {"digest": "nonstandard"}
    evidence = {
        "present": legacy_present,
        "snapshot_sha256": legacy_snapshot,
    }

    direct = pack_assurance("pack", evidence=evidence)
    profile = preflight_assurance_profile("pack", pack_evidence=evidence)
    assert direct is not None
    nested = cast(dict[str, object], profile["verifier_pack"])
    # Preserve the historical private-helper aliasing for malformed inputs,
    # but no VerifierPackAssurance value can contain either mutable object.
    assert direct["present"] is legacy_present
    assert direct["snapshot_sha256"] is legacy_snapshot
    assert nested["present"] is legacy_present
    assert nested["snapshot_sha256"] is legacy_snapshot
    legacy_present.append("changed")
    assert direct["present"] == ["changed"]


def test_repo_and_blackbox_profiles_keep_distinct_wire_shapes() -> None:
    repo = assurance_profile("docker", None)
    blackbox = assurance_profile(
        "docker",
        "pack",
        blackbox=True,
        candidate_isolation="docker",
        repo_suite_required=False,
    )

    assert "repo_native_suite" not in repo
    assert repo["candidate_isolation"] == "docker"
    assert repo["report_integrity"] == "same_process_candidate_writable"
    assert blackbox["repo_native_suite"] == "not_required_blackbox_only"
    assert blackbox["report_integrity"] == "external_process_isolated"
    assert blackbox["candidate_isolation"] == "docker"


def test_assurance_floor_priority_and_exact_reasons_are_frozen() -> None:
    profile = assurance_profile("subprocess", None)
    assert (
        assurance_shortfall(
            profile,
            require_report_integrity="unknown",
            require_candidate_isolation="docker",
        )
        == "unknown --require-report-integrity value: 'unknown'"
    )
    assert assurance_shortfall(
        profile,
        require_report_integrity="external_process_isolated",
        require_candidate_isolation=None,
    ) == (
        "required report_integrity ≥ 'external_process_isolated' but the run "
        "delivered 'same_process_candidate_writable' "
        "(use --blackbox for external_process_isolated)"
    )
    assert assurance_shortfall(
        profile,
        require_report_integrity=None,
        require_candidate_isolation="docker",
    ) == ("required candidate_isolation ≥ 'docker' but the run used 'subprocess'")


def test_assurance_application_imports_only_domain_and_standard_library() -> None:
    module_path = (
        Path(__file__).resolve().parents[1] / "evoom_guard" / "application" / "assurance.py"
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
