"""Frozen equivalence gates for RepoVerifier's repository-suite phase."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from repo_suite_characterization_harness import (
    CASE_NAMES,
    SCHEMA_VERSION,
    canonical_json,
    capture_case,
    observe_live_container_provider_timing,
    observe_live_provider_timing,
)

VECTOR = (
    Path(__file__).parent
    / "fixtures"
    / "refactor-safety"
    / "repo-suite-v1.json"
)


def _frozen() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_repo_suite_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_repo_suite_behavior(case_name: str, tmp_path: Path) -> None:
    expected = _frozen()["cases"][case_name]["sha256"]
    actual = capture_case(case_name, tmp_path)
    observed = hashlib.sha256(canonical_json(actual).encode("utf-8")).hexdigest()
    if observed != expected:
        pytest.fail(
            "repository suite behavior drifted:\n"
            f"expected sha256: {expected}\n"
            f"observed sha256: {observed}\n"
            "observed behavior:\n" + canonical_json(actual)
        )


def test_completed_branch_order_and_junit_ownership_are_frozen(
    tmp_path: Path,
) -> None:
    file_case = capture_case("host_junit_file_pass", tmp_path)
    directory_case = capture_case("host_junit_directory_pass", tmp_path)

    assert [event["op"] for event in file_case["events"]] == [
        "command",
        "instrument",
        "resolve-host",
        "host-run",
        "phase-evidence",
        "read-report",
        "parse-xml",
        "evaluate",
        "distill",
    ]
    assert file_case["events"][2]["report_outside_candidate"] is True
    assert file_case["events"][3]["strict_cleanup"] is True
    assert file_case["events"][5]["outside_candidate"] is True
    assert [event["op"] for event in directory_case["events"]][-5:] == [
        "read-report",
        "parse-xml",
        "parse-directory",
        "evaluate",
        "distill",
    ]
    assert directory_case["events"][-3]["matches_owned_sibling"] is True
    assert directory_case["events"][-3]["outside_candidate"] is True


@pytest.mark.parametrize(
    ("case_name", "delivered", "runtime"),
    (
        ("docker_junit_file_pass", "docker", None),
        ("gvisor_junit_file_pass", "gvisor", "runsc"),
    ),
)
def test_container_branches_preserve_delivery_and_trace(
    case_name: str,
    delivered: str,
    runtime: str | None,
    tmp_path: Path,
) -> None:
    case = capture_case(case_name, tmp_path)
    artifact = case["result"]["artifact"]

    assert artifact["execution_state"] == "completed"
    assert artifact["execution_phase"] == "repo_suite"
    assert artifact["test_command_started"] is True
    assert artifact["test_command_completed"] is True
    assert artifact["delivered_isolation"] == delivered
    assert artifact["repo_suite_isolation_evidence"]["delivered"] == delivered
    assert artifact["repo_suite_isolation_evidence"]["runtime"] == runtime
    docker_event = next(
        event for event in case["events"] if event["op"] == "docker-run"
    )
    assert docker_event["report_outside_candidate"] is True


def test_terminal_suite_failure_never_starts_the_pack(tmp_path: Path) -> None:
    case = capture_case("pack_configured_host_timeout", tmp_path)
    artifact = case["result"]["artifact"]

    assert [event["op"] for event in case["events"]] == [
        "command",
        "instrument",
        "resolve-host",
        "host-run",
        "phase-evidence",
    ]
    assert artifact["outcome"] == "test_timeout"
    assert artifact["execution_phase"] == "repo_suite"
    assert artifact["test_command_started"] is True
    assert artifact["test_command_completed"] is False
    assert artifact["verifier_pack_started"] is False
    assert artifact["verifier_pack_completed"] is False


def test_suite_dependencies_are_resolved_live_in_historical_order(
    tmp_path: Path,
) -> None:
    assert observe_live_provider_timing(tmp_path) == [
        "command",
        "instrument:late",
        "resolve:late",
        "run:late",
        "phase:late",
        "read:late",
        "parse:late",
        "evaluate:late",
    ]


def test_container_runner_and_trace_builder_are_resolved_live(
    tmp_path: Path,
) -> None:
    assert observe_live_container_provider_timing(tmp_path) == [
        "command",
        "docker:late",
        "phase:late",
    ]
