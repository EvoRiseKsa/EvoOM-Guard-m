# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Frozen behavioral boundary for the nested record-validation extraction."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from record_nested_characterization_harness import (
    capture,
    capture_all,
    capture_public_all,
    cases,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/refactor-safety/record-nested-validation-v1.json"
EXPECTED_IDS = [
    "assurance.required_fields",
    "assurance.types",
    "assurance.shape",
    "attestation.required_fields",
    "attestation.types",
    "attestation.shape",
]


def _digest(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _fixture() -> dict[str, Any]:
    value = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_all_nested_validation_traces_match_pre_extraction_digests() -> None:
    expected = _fixture()
    observed = capture_all()

    assert expected["format"] == "record-nested-validation-characterization-v1"
    assert sorted(observed) == sorted(expected["case_sha256"])
    assert {
        name: _digest(trace) for name, trace in observed.items()
    } == expected["case_sha256"]


def test_full_public_reports_for_both_schemas_match_pre_extraction_digests() -> None:
    observed = capture_public_all()

    assert {
        name: _digest(report) for name, report in observed.items()
    } == _fixture()["public_report_sha256"]


@pytest.mark.parametrize("name", sorted(cases()))
def test_nested_validation_preserves_check_ids_order_and_inputs(name: str) -> None:
    trace = capture(cases()[name])

    assert [item["id"] for item in trace] == EXPECTED_IDS


def test_null_and_preflight_exception_messages_are_frozen_verbatim() -> None:
    null_trace = capture(cases()["both_null"])
    preflight_trace = capture(cases()["preflight_null_effective_valid"])

    assert null_trace == _fixture()["exact_traces"]["both_null"]
    assert preflight_trace == _fixture()["exact_traces"][
        "preflight_null_effective_valid"
    ]


@pytest.mark.parametrize(
    ("name", "prefix"),
    [
        ("assurance_non_object", "assurance."),
        ("attestation_non_object", "attestation."),
    ],
)
def test_public_non_object_values_fail_closed_with_nested_skip_semantics(
    name: str,
    prefix: str,
) -> None:
    report = capture_public_all()[name]
    nested = [item for item in report["checks"] if item["id"].startswith(prefix)]

    assert report["ok"] is False
    assert all(item["status"] == "skip" for item in nested[:3])
    assert not any(item["id"] == "document.semantic_processing" for item in report["checks"])


@pytest.mark.parametrize(
    ("name", "expected_type_status", "expected_shape_status"),
    [
        ("preflight_null_effective_valid", "pass", "pass"),
        ("preflight_null_wrong_state", "fail", "fail"),
        ("preflight_null_command_started", "fail", "fail"),
        ("preflight_null_wrong_delivery", "fail", "fail"),
    ],
)
def test_preflight_null_isolation_truth_table_is_frozen(
    name: str,
    expected_type_status: str,
    expected_shape_status: str,
) -> None:
    trace = {item["id"]: item for item in capture(cases()[name])}

    assert trace["attestation.types"]["status"] == expected_type_status
    assert trace["attestation.shape"]["status"] == expected_shape_status
