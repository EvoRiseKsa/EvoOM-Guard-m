"""Frozen observable BlackboxResult, evidence, and cleanup characterization."""

from __future__ import annotations

import difflib
import json
from pathlib import Path

import pytest
from blackbox_characterization_harness import (
    GROUP_CASES,
    NORMALIZED_FIELDS,
    SCHEMA_VERSION,
    VECTOR_FILES,
    canonical_json,
    capture_case,
    capture_contract,
)

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "refactor-safety"


def _frozen(group_name: str) -> dict:
    return json.loads(
        (FIXTURE_ROOT / VECTOR_FILES[group_name]).read_text(encoding="utf-8")
    )


def _assert_exact(expected: dict, actual: dict, label: str) -> None:
    if actual == expected:
        return
    diff = "".join(
        difflib.unified_diff(
            canonical_json(expected).splitlines(keepends=True),
            canonical_json(actual).splitlines(keepends=True),
            fromfile=f"frozen/{label}",
            tofile=f"current/{label}",
        )
    )
    pytest.fail(f"black-box characterization drifted for {label}:\n{diff}")


def test_blackbox_public_contract_and_field_order_are_frozen() -> None:
    _assert_exact(_frozen("contract"), capture_contract(), "contract")


@pytest.mark.parametrize(
    ("group_name", "case_name"),
    [
        (group_name, case_name)
        for group_name, cases in GROUP_CASES.items()
        for case_name in cases
    ],
)
def test_blackbox_behavior_evidence_and_cleanup_are_frozen(
    group_name: str,
    case_name: str,
    tmp_path: Path,
) -> None:
    frozen = _frozen(group_name)
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert frozen["normalization"] == list(NORMALIZED_FIELDS)
    assert frozen["group"] == group_name
    assert tuple(frozen["cases"]) == tuple(sorted(GROUP_CASES[group_name]))

    _assert_exact(
        frozen["cases"][case_name],
        capture_case(case_name, tmp_path / case_name),
        f"{group_name}/{case_name}",
    )


def test_judge_is_bound_to_the_verified_pack_snapshot(tmp_path: Path) -> None:
    observed = capture_case("exit_0_pass", tmp_path / "judge-binding")
    trace = observed["trace"]
    verifications = trace["snapshot_verifications"]
    invocation = trace["judge_invocations"][0]
    snapshot = verifications[0]["path"]

    assert len(verifications) == 2
    assert verifications[0] == verifications[1]
    assert invocation["argv"][0] == "<CURRENT_PYTHON>"
    assert invocation["cwd"] == snapshot
    assert snapshot in invocation["argv"]
    assert invocation["timeout"] == 7
    assert invocation["env"]["HOME"] != snapshot
    assert invocation["env"]["EVOGUARD_TARGET"] != snapshot
    assert invocation["env"]["EVOGUARD_EXEC"] == "characterization-launcher"
    assert any(part.startswith("--junitxml=") for part in invocation["argv"])


@pytest.mark.parametrize(
    "case_name",
    ["docker_receipt_without_cid", "docker_cid_without_receipt"],
)
def test_docker_requires_both_receipt_and_container_id(
    case_name: str,
    tmp_path: Path,
) -> None:
    observed = capture_case(case_name, tmp_path / case_name)["result"]

    assert observed["candidate_invocations"] == 0
    assert observed["candidate_launcher_invocation_observed"] is False
    assert observed["isolation"]["delivered"] == "not_run"


def test_cleanup_flags_distinguish_completed_and_active_judge(
    tmp_path: Path,
) -> None:
    completed = capture_case(
        "normal_cleanup_contract", tmp_path / "completed"
    )["trace"]
    timed_out = capture_case(
        "timeout_cleanup_contract", tmp_path / "timed-out"
    )["trace"]

    assert completed["cleanup_strict"] is True
    assert completed["cleanup_wait_for_late_cidfiles"] is False
    assert timed_out["cleanup_strict"] is False
    assert timed_out["cleanup_wait_for_late_cidfiles"] is True


@pytest.mark.parametrize(
    ("case_name", "exception_type", "message"),
    [
        ("cleanup_keyboard_interrupt", "KeyboardInterrupt", "cleanup interrupt"),
        ("cleanup_system_exit", "SystemExit", "cleanup exit"),
        (
            "primary_keyboard_interrupt_cleanup_system_exit",
            "KeyboardInterrupt",
            "primary interrupt",
        ),
        (
            "primary_system_exit_cleanup_keyboard_interrupt",
            "SystemExit",
            "primary exit",
        ),
        (
            "recorder_close_keyboard_interrupt",
            "KeyboardInterrupt",
            "recorder close interrupt",
        ),
        (
            "primary_keyboard_interrupt_recorder_close_system_exit",
            "KeyboardInterrupt",
            "primary interrupt",
        ),
    ],
)
def test_cleanup_and_recorder_baseexception_precedence(
    case_name: str,
    exception_type: str,
    message: str,
    tmp_path: Path,
) -> None:
    observed = capture_case(case_name, tmp_path / case_name)

    assert observed["exception"]["type"] == exception_type
    assert message in observed["exception"]["message"]
    assert observed["trace"]["recorder"]["close_calls"] == 1
