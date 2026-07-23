"""Contracts for typed repository execution evidence and its wire projection."""

from __future__ import annotations

import inspect
import json
import sys
from dataclasses import FrozenInstanceError, fields
from pathlib import Path

import pytest

import evoom_guard.domain as domain
from evoom_guard.domain.execution import ExecutionPhaseResult, IsolationObservation
from evoom_guard.verifiers import repo_verifier
from evoom_guard.verifiers.repo_execution import (
    RepoExecutionTrace,
    execution_phase_payload,
    isolation_observation_payload,
)
from evoom_guard.verifiers.repo_verifier import RepoVerifier


def test_domain_public_api_reexports_exact_execution_types() -> None:
    assert domain.ExecutionPhaseResult is ExecutionPhaseResult
    assert domain.IsolationObservation is IsolationObservation


def test_execution_result_is_frozen_and_has_stable_field_order() -> None:
    assert [field.name for field in fields(ExecutionPhaseResult)] == [
        "execution_state",
        "execution_phase",
        "test_command_started",
        "test_command_completed",
        "verifier_pack_started",
        "verifier_pack_completed",
        "delivered_isolation",
        "setup_isolation_evidence",
        "repo_suite_isolation_evidence",
        "verifier_pack_isolation_evidence",
        "primary_isolation_evidence",
    ]
    snapshot = RepoExecutionTrace().snapshot()
    with pytest.raises(FrozenInstanceError):
        snapshot.execution_phase = "repo_suite"  # type: ignore[misc]


def test_default_trace_projection_is_exactly_wire_compatible() -> None:
    assert execution_phase_payload(RepoExecutionTrace().snapshot()) == {
        "execution_state": "not_started",
        "execution_phase": "preflight",
        "test_command_started": False,
        "test_command_completed": False,
        "verifier_pack_started": False,
        "verifier_pack_completed": False,
        "delivered_isolation": "not_run",
        "setup_isolation_evidence": None,
        "repo_suite_isolation_evidence": None,
        "verifier_pack_isolation_evidence": None,
    }


def test_snapshot_is_independent_from_later_builder_mutation() -> None:
    trace = RepoExecutionTrace()
    snapshot = trace.snapshot()

    trace.execution_state = "completed"
    trace.execution_phase = "repo_suite"
    trace.test_command_started = True
    trace.test_command_completed = True

    assert snapshot.execution_state == "not_started"
    assert snapshot.execution_phase == "preflight"
    assert snapshot.test_command_started is False
    assert execution_phase_payload(trace.snapshot())["execution_state"] == "completed"


def test_isolation_projection_omits_absent_note_and_preserves_present_note() -> None:
    without_note = IsolationObservation(
        requested="docker",
        delivered="docker",
        image_digest="sha256:judge",
        network="none",
        runtime=None,
    )
    with_note = IsolationObservation(
        requested="docker",
        delivered="not_run",
        image_digest="sha256:judge",
        network="none",
        runtime=None,
        note="container start was not proven",
    )

    assert list(isolation_observation_payload(without_note)) == [
        "requested",
        "delivered",
        "image_digest",
        "network",
        "runtime",
    ]
    assert isolation_observation_payload(with_note)["note"] == (
        "container start was not proven"
    )


def test_primary_isolation_key_exists_only_after_observation() -> None:
    trace = RepoExecutionTrace()
    assert "isolation_evidence" not in execution_phase_payload(trace.snapshot())

    trace.primary_isolation_evidence = IsolationObservation(
        requested="docker",
        delivered="docker",
        image_digest="sha256:judge",
        network="none",
        runtime=None,
    )

    assert execution_phase_payload(trace.snapshot())["isolation_evidence"] == {
        "requested": "docker",
        "delivered": "docker",
        "image_digest": "sha256:judge",
        "network": "none",
        "runtime": None,
    }


def test_repo_verifier_no_longer_mutates_an_untyped_trace_mapping() -> None:
    source = inspect.getsource(repo_verifier)
    assert "trace[" not in source
    assert "trace.update(" not in source


def test_repo_verifier_artifact_contains_only_json_data(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    result = RepoVerifier(
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
        mem_limit_mb=0,
    ).verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n",
        {"repo_path": str(repo)},
    )

    encoded = json.dumps(result.artifact, sort_keys=True)

    assert '"execution_state": "completed"' in encoded
    assert '"repo_suite_isolation_evidence": {' in encoded
