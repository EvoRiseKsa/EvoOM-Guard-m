"""Direct contracts for typed repository result/evidence projection."""

from __future__ import annotations

import inspect
from dataclasses import FrozenInstanceError
from typing import Any

import pytest

from evoom_guard.contracts import VerdictResult
from evoom_guard.domain.execution import ExecutionPhaseResult, IsolationObservation
from evoom_guard.domain.verification import PackPhaseResult, RepoPhaseResult
from evoom_guard.verifiers.repo_result import (
    RepoFinalArtifactRequest,
    RepoPackIdentityArtifact,
    RepoPackPhaseArtifact,
    RepoResultProjection,
    RepoSuitePhaseArtifact,
    build_final_repo_artifact,
)
from evoom_guard.verifiers.repo_verifier import RepoVerifier


def _repo_phase(*, verdict_source: str | None = "junit+exit") -> RepoPhaseResult:
    return RepoPhaseResult(
        passed=True,
        score=1.0,
        tests_passed=2,
        tests_total=2,
        tampered=False,
        output="repo output",
        verdict_source=verdict_source,
        outcome=None if verdict_source is not None else "no_test_verdict",
        returncode=0,
        junit_text="<repo/>",
        junit_sha256="b" * 64,
        junit_digest_format="JUNIT_XML_SHA256",
    )


def _pack_phase() -> PackPhaseResult:
    return PackPhaseResult(
        passed=True,
        score=1.0,
        tests_passed=1,
        tests_total=1,
        tampered=False,
        output_suffix="pack output",
        verdict_source="junit+exit",
        outcome=None,
        junit_text="<pack/>",
        junit_sha256="c" * 64,
        junit_digest_format="JUNIT_XML_SHA256",
    )


def _execution() -> ExecutionPhaseResult:
    return ExecutionPhaseResult(
        execution_state="completed",
        execution_phase="verifier_pack",
        test_command_started=True,
        test_command_completed=True,
        verifier_pack_started=True,
        verifier_pack_completed=True,
        delivered_isolation="subprocess",
        setup_isolation_evidence=None,
        repo_suite_isolation_evidence=None,
        verifier_pack_isolation_evidence=None,
        primary_isolation_evidence=None,
    )


def _isolation() -> IsolationObservation:
    return IsolationObservation(
        requested="subprocess",
        delivered="subprocess",
        image_digest=None,
        network=None,
        runtime=None,
    )


def _runtime() -> dict[str, object]:
    return {
        "runtime_tree_sha256": None,
        "runtime_tree_digest_format": None,
        "runtime_tree_entries": None,
        "runtime_tree_bytes": None,
        "runtime_identity_elapsed_ms": 0.0,
        "runtime_continuity": "not_applicable",
    }


def test_pack_identity_is_sticky_and_defensively_owned() -> None:
    manifest: dict[str, Any] = {
        "id": "pack",
        "nested": {"value": "accepted"},
    }
    projection = RepoResultProjection()
    projection.bind_pack_identity(
        sha256="a" * 64,
        manifest=manifest,
    )

    manifest["id"] = "caller-mutated"
    manifest["nested"]["value"] = "caller-mutated"
    first = projection.sticky_payload()
    assert first == {
        "verifier_pack_sha256": "a" * 64,
        "verifier_pack_manifest": {
            "id": "pack",
            "nested": {"value": "accepted"},
        },
    }

    first["verifier_pack_manifest"]["nested"]["value"] = "result-mutated"
    assert projection.sticky_payload()["verifier_pack_manifest"] == {
        "id": "pack",
        "nested": {"value": "accepted"},
    }


def test_repo_phase_sticky_projection_does_not_invent_a_clean_verdict() -> None:
    projection = RepoResultProjection()
    projection.bind_repo_suite_phase(_repo_phase(verdict_source=None))

    assert projection.sticky_payload() == {
        "repo_suite_started": True,
        "repo_suite_completed": True,
        "repo_suite_state": "repo_phase_completed",
        "repo_suite_passed": None,
        "repo_suite_tests_passed": 2,
        "repo_suite_tests_total": 2,
        "repo_suite_verdict_source": None,
        "repo_suite_returncode": 0,
        "repo_suite_junit_sha256": "b" * 64,
        "repo_suite_junit_digest_format": "JUNIT_XML_SHA256",
    }


def test_finalization_preserves_overwrite_order_and_explicit_presence() -> None:
    projection = RepoResultProjection()
    projection.bind_pack_identity(sha256="a" * 64, manifest=None)
    projection.bind_repo_suite_phase(_repo_phase())
    result = VerdictResult(
        passed=False,
        score=0.0,
        diagnostics="terminal",
        artifact={
            "verifier_pack_sha256": "stale",
            "verifier_pack_present": None,
            "terminal": True,
        },
    )

    returned = projection.finalize(
        result,
        execution=_execution(),
        verifier_pack_present=True,
    )

    assert returned is result
    assert result.artifact["verifier_pack_sha256"] == "a" * 64
    assert result.artifact["verifier_pack_present"] is None
    assert list(result.artifact)[:3] == [
        "verifier_pack_sha256",
        "verifier_pack_present",
        "terminal",
    ]
    assert list(result.artifact).index("repo_suite_started") < list(result.artifact).index(
        "execution_state"
    )


def test_no_pack_final_artifact_keeps_nullable_fields_but_omits_pack_junit() -> None:
    artifact = build_final_repo_artifact(
        RepoFinalArtifactRequest(
            returncode=0,
            elapsed_seconds=0.5,
            phase=_repo_phase(),
            files_changed=("app.py",),
            files_deleted=(),
            pack_identity=None,
            expected_pack_sha256="",
            pack_phase=None,
            pack_configured=False,
            setup_isolation=None,
            setup_configured=False,
            runtime_evidence=_runtime(),
            resolved_image=None,
            suite_isolation_evidence=_isolation(),
            container_mode=False,
        )
    )

    assert artifact["verifier_pack_sha256"] is None
    assert artifact["expected_verifier_pack_sha256"] is None
    assert artifact["verifier_pack_manifest"] is None
    assert artifact["verifier_pack_tests_passed"] is None
    assert artifact["verifier_pack_tests_total"] is None
    assert "verifier_pack_junit_sha256" not in artifact
    assert "verifier_pack_junit_digest_format" not in artifact
    assert artifact["isolation_evidence"] is None


def test_configured_pack_final_artifact_has_pack_junit_presence_and_values() -> None:
    pack_identity = RepoPackIdentityArtifact(
        sha256="a" * 64,
        manifest={"id": "pack"},
    )
    pack_phase = RepoPackPhaseArtifact.from_phase(_pack_phase())
    artifact = build_final_repo_artifact(
        RepoFinalArtifactRequest(
            returncode=0,
            elapsed_seconds=0.5,
            phase=_repo_phase(),
            files_changed=("app.py",),
            files_deleted=("old.py",),
            pack_identity=pack_identity,
            expected_pack_sha256="a" * 64,
            pack_phase=pack_phase,
            pack_configured=True,
            setup_isolation="subprocess",
            setup_configured=True,
            runtime_evidence=_runtime(),
            resolved_image=None,
            suite_isolation_evidence=_isolation(),
            container_mode=False,
        )
    )

    assert artifact["verifier_pack_sha256"] == "a" * 64
    assert artifact["verifier_pack_manifest"] == {"id": "pack"}
    assert artifact["verifier_pack_tests_passed"] == 1
    assert artifact["verifier_pack_tests_total"] == 1
    assert artifact["verifier_pack_junit_sha256"] == "c" * 64
    assert artifact["verifier_pack_junit_digest_format"] == "JUNIT_XML_SHA256"
    assert artifact["setup_fidelity"] == "verified"
    assert artifact["candidate_fidelity"] == "verified"


def test_projection_contract_values_are_immutable() -> None:
    identity = RepoPackIdentityArtifact(sha256="a" * 64, manifest=None)
    repo_phase = RepoSuitePhaseArtifact.from_phase(_repo_phase())
    pack_phase = RepoPackPhaseArtifact.from_phase(_pack_phase())

    with pytest.raises(FrozenInstanceError):
        identity.sha256 = "b" * 64  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        repo_phase.passed = False  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        pack_phase.tests_total = 0  # type: ignore[misc]


def test_repo_verifier_delegates_all_result_projection_ownership() -> None:
    source = inspect.getsource(RepoVerifier)

    assert "sticky_evidence" not in source
    assert "RepoResultProjection()" in source
    assert "result_projection.bind_pack_identity(" in source
    assert "result_projection.bind_repo_suite_phase(repo_phase)" in source
    assert "build_final_repo_artifact(" in source
    assert "result_projection.finalize(" in source
