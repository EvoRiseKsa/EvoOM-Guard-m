"""Frozen equivalence gates for RepoVerifier's verifier-pack phase."""

from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from repo_pack_characterization_harness import (
    CASE_NAMES,
    SCHEMA_VERSION,
    canonical_json,
    capture_case,
    observe_live_container_provider_timing,
    observe_live_host_provider_timing,
)

from evoom_guard.domain.execution import IsolationObservation
from evoom_guard.verifiers import repo_pack

VECTOR = Path(__file__).parent / "fixtures" / "refactor-safety" / "repo-pack-v1.json"


def _frozen() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_repo_pack_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_repo_pack_behavior(
    case_name: str,
    tmp_path: Path,
) -> None:
    expected = _frozen()["cases"][case_name]["sha256"]
    actual = capture_case(case_name, tmp_path)
    observed = hashlib.sha256(canonical_json(actual).encode("utf-8")).hexdigest()
    if observed != expected:
        pytest.fail(
            "repository pack behavior drifted:\n"
            f"expected sha256: {expected}\n"
            f"observed sha256: {observed}\n"
            "observed behavior:\n" + canonical_json(actual)
        )


def test_host_command_order_and_strict_cleanup_are_frozen(
    tmp_path: Path,
) -> None:
    case = capture_case("host_pass_strict", tmp_path)
    operations = [event["op"] for event in case["events"]]

    assert operations == [
        "runtime-capture",
        "suite-execute",
        "verify-runtime",
        "suite-interpret",
        "verify-pack",
        "instrument",
        "resolve-host",
        "host-run",
        "verify-pack",
        "verify-runtime",
        "read-pack-report",
        "parse-pack-report",
        "evaluate-pack",
        "compose",
        "distill",
    ]
    instrument = case["events"][5]
    assert instrument["report_outside_candidate"] is True
    assert instrument["command"] == [
        "<PYTHON>",
        "-m",
        "pytest",
        "-q",
        "--color=no",
        "-p",
        "no:cacheprovider",
        "--confcutdir=<PACK>",
        "<PACK>",
    ]
    assert case["events"][7]["strict_cleanup"] is True


@pytest.mark.parametrize(
    ("case_name", "delivered", "runtime"),
    (
        ("docker_pass", "docker", None),
        ("gvisor_pass", "gvisor", "runsc"),
    ),
)
def test_container_pack_delivery_and_trace_are_frozen(
    case_name: str,
    delivered: str,
    runtime: str | None,
    tmp_path: Path,
) -> None:
    case = capture_case(case_name, tmp_path)
    artifact = case["result"]["artifact"]

    assert artifact["execution_state"] == "completed"
    assert artifact["execution_phase"] == "verifier_pack"
    assert artifact["verifier_pack_started"] is True
    assert artifact["verifier_pack_completed"] is True
    evidence = artifact["verifier_pack_isolation_evidence"]
    assert evidence["delivered"] == delivered
    assert evidence["runtime"] == runtime


@pytest.mark.parametrize(
    "case_name",
    (
        "pack_drift_before_execution",
        "pack_drift_after_execution",
        "runtime_drift_after_execution",
    ),
)
def test_pack_or_runtime_drift_precedes_junit_read(
    case_name: str,
    tmp_path: Path,
) -> None:
    case = capture_case(case_name, tmp_path)
    operations = [event["op"] for event in case["events"]]
    assert "read-pack-report" not in operations
    assert case["result"]["artifact"]["tamper"] is True


@pytest.mark.parametrize(
    "case_name",
    (
        "host_timeout",
        "host_output_limit",
        "host_containment",
        "host_not_found",
        "docker_timeout_started",
        "docker_timeout_unstarted",
        "docker_output_limit_started",
        "docker_output_limit_unstarted",
        "docker_containment_started",
        "docker_containment_unstarted",
        "docker_not_found",
        "docker_exit_125",
    ),
)
def test_pack_failure_preserves_sticky_repo_facts(
    case_name: str,
    tmp_path: Path,
) -> None:
    artifact = capture_case(case_name, tmp_path)["result"]["artifact"]
    assert artifact["repo_suite_started"] is True
    assert artifact["repo_suite_completed"] is True
    assert artifact["repo_suite_state"] == "repo_phase_completed"
    assert artifact["repo_suite_passed"] is True
    assert artifact["repo_suite_tests_passed"] == 2
    assert artifact["repo_suite_tests_total"] == 2
    assert artifact["repo_suite_returncode"] == 0
    assert artifact["repo_suite_junit_sha256"] == ("b" * 64)


def test_host_pack_dependencies_are_resolved_live_in_order(
    tmp_path: Path,
) -> None:
    assert observe_live_host_provider_timing(tmp_path) == [
        "runtime:1",
        "pack:1",
        "instrument:late",
        "resolve:late",
        "run:late",
        "phase:late",
        "pack:2",
        "runtime:2",
        "read:late",
        "parse:late",
        "evaluate:late",
        "compose:late",
    ]


@pytest.mark.parametrize("isolation", ("docker", "gvisor"))
def test_container_pack_runner_and_trace_builder_are_live(
    isolation: str,
    tmp_path: Path,
) -> None:
    assert observe_live_container_provider_timing(
        tmp_path,
        isolation=isolation,
    ) == [
        "pack:1",
        "docker:late",
        "phase:late",
        "pack:2",
    ]


def test_repo_pack_owner_exposes_separate_immutable_contracts() -> None:
    completed = repo_pack.RepoPackCompleted(
        report_path="report.xml",
        returncode=0,
        stdout="",
        stderr="",
        report_expected=True,
    )
    execution = repo_pack.RepoPackExecutionRequest(
        candidate_copy="copy",
        workdir="judge",
        pack_snapshot="pack",
        files_changed=("app.py",),
        environment={},
        container_mode=False,
        resolved_image=None,
        setup_isolation=None,
        suite_isolation_evidence=IsolationObservation(
            requested="subprocess",
            delivered="subprocess",
            image_digest=None,
            network=None,
            runtime=None,
        ),
        strict_harness=True,
    )
    interpretation = repo_pack.RepoPackInterpretationRequest(
        completed=completed,
    )

    assert repo_pack.execute_repo_pack.__module__ == (
        "evoom_guard.verifiers.repo_pack"
    )
    assert repo_pack.interpret_repo_pack.__module__ == (
        "evoom_guard.verifiers.repo_pack"
    )
    with pytest.raises(FrozenInstanceError):
        completed.returncode = 1  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        execution.pack_snapshot = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        interpretation.completed = completed  # type: ignore[misc]
