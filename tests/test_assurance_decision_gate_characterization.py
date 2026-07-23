"""Frozen behavioral seam for extracting Guard's final assurance gate."""

from __future__ import annotations

import difflib
import json
from pathlib import Path
from typing import Any, cast

import pytest
from assurance_decision_gate_characterization_harness import (
    CASE_NAMES,
    NORMALIZED_FIELDS,
    SCHEMA_VERSION,
    canonical_json,
    capture_case,
)

VECTOR = (
    Path(__file__).parent
    / "fixtures"
    / "refactor-safety"
    / "assurance-decision-gate-v1.json"
)


def _frozen() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(VECTOR.read_text(encoding="utf-8")))


def test_assurance_decision_gate_characterization_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert frozen["normalization"] == list(NORMALIZED_FIELDS)
    assert tuple(frozen["cases"]) == CASE_NAMES


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_assurance_decision_timing_identity_and_priority(
    case_name: str,
    tmp_path: Path,
) -> None:
    expected = _frozen()["cases"][case_name]
    actual = capture_case(case_name, tmp_path)
    if actual != expected:
        diff = "".join(
            difflib.unified_diff(
                canonical_json(expected).splitlines(keepends=True),
                canonical_json(actual).splitlines(keepends=True),
                fromfile=f"frozen/{case_name}",
                tofile=f"current/{case_name}",
            )
        )
        pytest.fail("final assurance decision contract drifted:\n" + diff)


def test_repo_gate_is_lazy_and_follows_attestation_and_profile(tmp_path: Path) -> None:
    passed = capture_case("repo_completed_pass_none", tmp_path)
    failed = capture_case(
        "repo_completed_fail_preserves_prior_without_shortfall",
        tmp_path,
    )
    incomplete = capture_case("repo_incomplete_error_skips_shortfall", tmp_path)

    assert passed["timeline"][-3:] == [
        "attestation:build",
        "profile:runtime",
        "shortfall:call",
    ]
    assert failed["decision"]["reason_code"] == "tests_failed"
    assert incomplete["decision"]["reason_code"] == "setup_failed"
    assert failed["shortfall_calls"] == []
    assert incomplete["shortfall_calls"] == []


def test_blackbox_gate_is_eager_but_preserves_prior_decisions(tmp_path: Path) -> None:
    failed = capture_case(
        "blackbox_completed_fail_eager_preserves_prior",
        tmp_path,
    )
    incomplete = capture_case(
        "blackbox_incomplete_error_eager_preserves_prior",
        tmp_path,
    )
    not_started = capture_case(
        "blackbox_not_started_error_eager_preserves_prior",
        tmp_path,
    )

    assert failed["decision"]["reason_code"] == "tests_failed"
    assert incomplete["decision"]["reason_code"] == "test_timeout"
    assert not_started["decision"]["reason_code"] == "verifier_pack_invalid"
    for case in (failed, incomplete, not_started):
        assert case["timeline"][-3:] == [
            "profile:runtime",
            "shortfall:call",
            "attestation:build",
        ]
        assert len(case["shortfall_calls"]) == 1


@pytest.mark.parametrize(
    "case_name",
    (
        "repo_completed_pass_empty_shortfall",
        "blackbox_completed_pass_empty_shortfall",
    ),
)
def test_empty_string_is_a_real_shortfall(
    case_name: str,
    tmp_path: Path,
) -> None:
    case = capture_case(case_name, tmp_path)
    assert case["decision"]["verdict"] == "ERROR"
    assert case["decision"]["reason_code"] == "assurance_requirement_not_met"
    assert case["decision"]["reason"] == ""
    assert case["shortfall_calls"][0]["returned"] == ""


def test_static_rejection_never_evaluates_runtime_assurance_floor(
    tmp_path: Path,
) -> None:
    case = capture_case("repo_static_rejection_skips_runtime_gate", tmp_path)
    assert case["decision"]["verdict"] == "REJECTED"
    assert case["decision"]["execution_state"] == "static_gate"
    assert case["shortfall_calls"] == []
    assert case["timeline"][-2:] == ["attestation:build", "profile:static"]


def test_repo_and_blackbox_freeze_opposite_exception_order(
    tmp_path: Path,
) -> None:
    repo = capture_case(
        "repo_shortfall_exception_after_attestation_profile",
        tmp_path,
    )
    blackbox = capture_case(
        "blackbox_shortfall_exception_precedes_attestation",
        tmp_path,
    )
    assert repo["timeline"][-3:] == [
        "attestation:build",
        "profile:runtime",
        "shortfall:call",
    ]
    assert blackbox["timeline"][-2:] == [
        "profile:runtime",
        "shortfall:call",
    ]
    assert repo["exception"]["message"] == "synthetic shortfall failure"
    assert blackbox["exception"]["message"] == "synthetic shortfall failure"
    assert blackbox["attestation_calls"] == []


def test_profile_mapping_identity_and_access_are_preserved(tmp_path: Path) -> None:
    case = capture_case("repo_completed_pass_none", tmp_path)
    assert case["shortfall_calls"][0]["assurance_is_profile_source"] is True
    assert case["result_assurance_is_profile_source"] is True
    assert case["assurance_access_trace"] == [
        "get:report_integrity",
        "get:candidate_isolation",
    ]


def test_composite_uses_the_weaker_repo_native_report_channel(
    tmp_path: Path,
) -> None:
    composite = capture_case("blackbox_composite_external_floor", tmp_path)
    blackbox_only = capture_case("blackbox_only_external_floor", tmp_path)

    assert composite["profile_snapshot"]["report_integrity"] == (
        "same_process_candidate_writable"
    )
    assert composite["decision"]["reason_code"] == (
        "assurance_requirement_not_met"
    )
    assert blackbox_only["profile_snapshot"]["report_integrity"] == (
        "external_process_isolated"
    )
    assert blackbox_only["decision"]["verdict"] == "PASS"
