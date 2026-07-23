"""Contracts for typed repository-verification evidence and its projection."""

from __future__ import annotations

import inspect
import json
from dataclasses import FrozenInstanceError, fields
from typing import cast

import pytest

import evoom_guard.domain as domain
from evoom_guard import guard as guard_module
from evoom_guard.contracts import VerdictResult
from evoom_guard.domain.evidence import (
    IsolationPayloadEvidence,
    RepositorySuiteEvidence,
    RuntimeIdentityEvidence,
    VerificationEvidence,
    VerifierPackEvidence,
)
from evoom_guard.verifiers.repo_evidence import (
    repo_attestation_evidence_payload,
    repo_verification_evidence_from_artifact,
)
from evoom_guard.verifiers.repo_verifier import RepoVerifier


def _maximal_artifact() -> dict[str, object]:
    isolation = {
        "requested": "docker",
        "delivered": "docker",
        "image_digest": "sha256:judge",
        "network": "none",
        "runtime": "runsc",
        "note": "observed",
    }
    return {
        "execution_state": "completed",
        "execution_phase": "verifier_pack",
        "test_command_started": True,
        "test_command_completed": True,
        "verifier_pack_started": True,
        "verifier_pack_completed": True,
        "delivered_isolation": "docker",
        "isolation_evidence": isolation,
        "setup_isolation_evidence": isolation,
        "repo_suite_isolation_evidence": isolation,
        "verifier_pack_isolation_evidence": isolation,
        "outcome": "tests_failed",
        "tamper": False,
        "tests_passed": 8,
        "tests_total": 10,
        "verdict_source": "repo:junit+exit;pack:junit+exit",
        "junit_sha256": "composite",
        "junit_digest_format": "EVOGUARD_COMPOSITE_JUNIT_V1",
        "setup_isolation": "docker",
        "verifier_pack_present": True,
        "verifier_pack_sha256": "pack",
        "verifier_pack_manifest": {"id": "contract", "version": "1"},
        "verifier_pack_tests_passed": 3,
        "verifier_pack_tests_total": 4,
        "verifier_pack_junit_sha256": "pack-junit",
        "verifier_pack_junit_digest_format": "EVOGUARD_JUNIT_XML_V1",
        "repo_suite_started": True,
        "repo_suite_completed": True,
        "repo_suite_state": "repo_phase_completed",
        "repo_suite_passed": True,
        "repo_suite_tests_passed": 5,
        "repo_suite_tests_total": 6,
        "repo_suite_verdict_source": "junit+exit",
        "repo_suite_returncode": 0,
        "repo_suite_junit_sha256": "repo-junit",
        "repo_suite_junit_digest_format": "EVOGUARD_JUNIT_XML_V1",
        "repo_suite_image_digest": None,
        "runtime_tree_sha256": "runtime",
        "runtime_tree_digest_format": "EVOGUARD_RUNTIME_TREE_V1",
        "runtime_tree_entries": 41,
        "runtime_tree_bytes": 8192,
        "runtime_identity_elapsed_ms": 12.75,
        "runtime_continuity": "read_only_enforced",
    }


def test_domain_public_api_reexports_evidence_contracts() -> None:
    assert domain.VerificationEvidence is VerificationEvidence
    assert domain.VerifierPackEvidence is VerifierPackEvidence
    assert domain.IsolationPayloadEvidence is IsolationPayloadEvidence
    assert domain.RepositorySuiteEvidence is RepositorySuiteEvidence
    assert domain.RuntimeIdentityEvidence is RuntimeIdentityEvidence


@pytest.mark.parametrize(
    "model",
    (
        VerificationEvidence,
        VerifierPackEvidence,
        IsolationPayloadEvidence,
        RepositorySuiteEvidence,
        RuntimeIdentityEvidence,
    ),
)
def test_evidence_models_are_frozen_and_slotted(model: type[object]) -> None:
    assert "__slots__" in model.__dict__
    assert "__dict__" not in model.__dict__
    assert tuple(field.name for field in fields(model))


def test_maximal_artifact_is_owned_and_projects_to_plain_json() -> None:
    artifact = _maximal_artifact()
    manifest = artifact["verifier_pack_manifest"]
    assert isinstance(manifest, dict)

    evidence = repo_verification_evidence_from_artifact(
        artifact,
        default_isolation="docker",
    )
    manifest["version"] = "rewritten"
    isolation = artifact["isolation_evidence"]
    assert isinstance(isolation, dict)
    isolation["delivered"] = "rewritten"

    assert evidence.verifier_pack.manifest == {
        "id": "contract",
        "version": "1",
    }
    with pytest.raises(TypeError):
        assert evidence.verifier_pack.manifest is not None
        evidence.verifier_pack.manifest["version"] = "2"  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        evidence.outcome = "pass"  # type: ignore[misc]

    payload = repo_attestation_evidence_payload(evidence)
    assert payload == {
        "junit_sha256": "composite",
        "junit_digest_format": "EVOGUARD_COMPOSITE_JUNIT_V1",
        "verifier_pack_sha256": "pack",
        "verifier_pack_manifest": {"id": "contract", "version": "1"},
        "verifier_pack_tests_passed": 3,
        "verifier_pack_tests_total": 4,
        "verifier_pack_junit_sha256": "pack-junit",
        "verifier_pack_junit_digest_format": "EVOGUARD_JUNIT_XML_V1",
        "isolation_evidence": {
            "requested": "docker",
            "delivered": "docker",
            "image_digest": "sha256:judge",
            "network": "none",
            "runtime": "runsc",
            "note": "observed",
        },
        "setup_isolation_evidence": {
            "requested": "docker",
            "delivered": "docker",
            "image_digest": "sha256:judge",
            "network": "none",
            "runtime": "runsc",
            "note": "observed",
        },
        "repo_suite_isolation_evidence": {
            "requested": "docker",
            "delivered": "docker",
            "image_digest": "sha256:judge",
            "network": "none",
            "runtime": "runsc",
            "note": "observed",
        },
        "verifier_pack_isolation_evidence": {
            "requested": "docker",
            "delivered": "docker",
            "image_digest": "sha256:judge",
            "network": "none",
            "runtime": "runsc",
            "note": "observed",
        },
        "repo_suite_junit_sha256": "repo-junit",
        "repo_suite_junit_digest_format": "EVOGUARD_JUNIT_XML_V1",
        "repo_suite_tests_passed": 5,
        "repo_suite_tests_total": 6,
        "repo_suite_verdict_source": "junit+exit",
        "repo_suite_returncode": 0,
        "repo_suite_passed": True,
        "repo_suite_started": True,
        "repo_suite_completed": True,
        "repo_suite_state": "repo_phase_completed",
        "repo_suite_image_digest": None,
        "execution_state": "completed",
        "execution_phase": "verifier_pack",
        "test_command_started": True,
        "delivered_isolation": "docker",
        "verifier_pack_present": True,
        "verifier_pack_started": True,
        "verifier_pack_completed": True,
        "setup_isolation": "docker",
        "runtime_tree_sha256": "runtime",
        "runtime_tree_digest_format": "EVOGUARD_RUNTIME_TREE_V1",
        "runtime_tree_entries": 41,
        "runtime_tree_bytes": 8192,
        "runtime_identity_elapsed_ms": 12.75,
        "runtime_continuity": "read_only_enforced",
    }
    assert isinstance(payload["verifier_pack_manifest"], dict)
    assert payload["isolation_evidence"]["delivered"] == "docker"  # type: ignore[index]
    assert "test_command_completed" not in payload
    json.dumps(payload, sort_keys=True)


def test_sparse_artifact_preserves_null_phase_evidence() -> None:
    evidence = repo_verification_evidence_from_artifact(
        {},
        default_isolation="docker",
    )

    assert evidence.execution.execution_state == "not_started"
    assert evidence.execution.execution_phase == "repo_suite"
    assert evidence.execution.test_command_started is False
    assert evidence.execution.delivered_isolation == "not_run"
    assert evidence.verifier_pack.present is None
    assert evidence.verifier_pack.started is None
    assert evidence.verifier_pack.completed is None
    assert evidence.repo_suite.started is None
    assert evidence.repo_suite.completed is None
    assert evidence.repo_suite.passed is None
    assert evidence.runtime.elapsed_ms is None
    assert repo_attestation_evidence_payload(evidence)["repo_suite_started"] is None
    assert repo_attestation_evidence_payload(evidence)["verifier_pack_started"] is None
    json.dumps(repo_attestation_evidence_payload(evidence), sort_keys=True)


def test_nested_manifest_is_deeply_owned_and_thaws_to_plain_json() -> None:
    nested = {
        "id": "future-shape",
        "metadata": {"owners": ["EvoRise Tech"]},
    }
    evidence = repo_verification_evidence_from_artifact(
        {"verifier_pack_manifest": nested},
        default_isolation="subprocess",
    )
    metadata = nested["metadata"]
    assert isinstance(metadata, dict)
    owners = metadata["owners"]
    assert isinstance(owners, list)
    owners.append("rewriter")

    payload = repo_attestation_evidence_payload(evidence)
    assert payload["verifier_pack_manifest"] == {
        "id": "future-shape",
        "metadata": {"owners": ["EvoRise Tech"]},
    }
    assert isinstance(payload["verifier_pack_manifest"], dict)
    json.dumps(payload, sort_keys=True)


@pytest.mark.parametrize(
    ("artifact", "state", "started", "delivered"),
    (
        (
            {"verdict_source": "junit+exit"},
            "completed",
            True,
            "docker",
        ),
        (
            {"verdict_source": ""},
            "not_started",
            True,
            "docker",
        ),
        (
            {"outcome": "test_timeout"},
            "started_incomplete",
            True,
            "docker",
        ),
        (
            {"outcome": "runtime_containment_error"},
            "started_incomplete",
            False,
            "not_run",
        ),
    ),
)
def test_partial_artifact_lifecycle_fallbacks_are_frozen(
    artifact: dict[str, object],
    state: str,
    started: bool,
    delivered: str,
) -> None:
    evidence = repo_verification_evidence_from_artifact(
        artifact,
        default_isolation="docker",
    )

    assert evidence.execution.execution_state == state
    assert evidence.execution.test_command_started is started
    assert evidence.execution.delivered_isolation == delivered


def test_repo_native_decision_segment_no_longer_reads_raw_artifact() -> None:
    source = inspect.getsource(guard_module.guard)
    segment = source.split("art = verdict.artifact or {}", 1)[1]
    segment = segment.split("return GuardResult(", 1)[0]

    assert "art.get(" not in segment
    assert "art[" not in segment


def _guard_with_artifact(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    artifact: dict[str, object],
    *,
    passed: bool,
    score: float,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    mocked = VerdictResult(
        passed=passed,
        score=score,
        diagnostics="diagnostic",
        artifact=artifact,
    )
    monkeypatch.setattr(RepoVerifier, "verify", lambda *_args, **_kwargs: mocked)
    return guard_module.guard(
        str(repo),
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n",
    )


def test_malformed_null_verdict_score_preserves_native_failure(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(TypeError, match="not supported"):
        _guard_with_artifact(
            tmp_path,
            monkeypatch,
            {},
            passed=False,
            score=cast(float, None),
        )


def test_partial_artifact_preserves_unknown_pack_lifecycle_in_attestation(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _guard_with_artifact(
        tmp_path,
        monkeypatch,
        {
            "tests_passed": 1,
            "tests_total": 1,
            "verdict_source": "junit+exit",
        },
        passed=True,
        score=1.0,
    )

    assert result.attestation is not None
    assert result.attestation["verifier_pack_started"] is None
    assert result.attestation["verifier_pack_completed"] is None


def test_partial_isolation_payload_retains_its_exact_wire_shape(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    partial = {
        "requested": "docker",
        "delivered": "docker",
        "extension": "preserved",
    }
    result = _guard_with_artifact(
        tmp_path,
        monkeypatch,
        {
            "tests_passed": 1,
            "tests_total": 1,
            "verdict_source": "junit+exit",
            "isolation_evidence": partial,
        },
        passed=True,
        score=1.0,
    )

    assert result.attestation is not None
    assert result.attestation["isolation_evidence"] == partial


def test_explicit_null_tamper_counts_keep_the_historical_reason_text(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _guard_with_artifact(
        tmp_path,
        monkeypatch,
        {
            "tamper": True,
            "tests_passed": None,
            "tests_total": None,
        },
        passed=False,
        score=0.5,
    )

    assert result.verdict == "TAMPERED"
    assert "(None/None in the report)" in result.reason


def test_explicit_null_failed_count_keeps_the_historical_reason_text(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _guard_with_artifact(
        tmp_path,
        monkeypatch,
        {
            "tests_passed": None,
            "tests_total": 1,
        },
        passed=False,
        score=0.5,
    )

    assert result.verdict == "FAIL"
    assert "(None/1 passed)" in result.reason
