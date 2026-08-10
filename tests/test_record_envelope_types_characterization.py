# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Frozen behavioral boundary for record-envelope type extraction."""

from __future__ import annotations

import hashlib
import json
import pickle
from pathlib import Path
from typing import Any

import pytest
from record_envelope_types_characterization_harness import (
    access_traces,
    capture,
    capture_all,
    capture_public_all,
    cases,
    generated_differential_digest,
    legacy_top_level_type_errors,
    raising_baseline_trace,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/refactor-safety/record-envelope-types-v1.json"


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


def test_all_envelope_type_traces_match_pre_extraction_truth() -> None:
    expected = _fixture()
    assert expected["format"] == "record-envelope-types-characterization-v1"
    observed = capture_all()
    assert len(observed) == expected["case_count"]
    assert _digest(observed) == expected["case_errors_sha256"]
    assert capture_all(projector=legacy_top_level_type_errors) == observed


@pytest.mark.parametrize("name", sorted(cases()))
def test_envelope_type_projection_never_mutates_input(name: str) -> None:
    value = cases()[name]
    before = pickle.dumps(value, protocol=5)
    capture(value)
    assert pickle.dumps(value, protocol=5) == before


def test_public_reports_preserve_schema_1_11_and_1_12_output() -> None:
    observed = capture_public_all()
    assert {name: _digest(report) for name, report in observed.items()} == _fixture()[
        "public_report_sha256"
    ]


def test_generated_envelope_trace_matches_pre_extraction_digest() -> None:
    assert generated_differential_digest() == _fixture()["generated_trace_sha256"]


def test_mapping_access_order_and_repeated_object_reads_are_frozen() -> None:
    observed = access_traces()
    assert _digest(observed) == _fixture()["access_trace_sha256"]
    assert access_traces(projector=legacy_top_level_type_errors) == observed


def test_lookup_exception_identity_and_precedence_are_frozen() -> None:
    observed = raising_baseline_trace()
    assert _digest(observed) == _fixture()["raising_baseline_trace_sha256"]
    assert raising_baseline_trace(projector=legacy_top_level_type_errors) == observed


def test_simultaneous_envelope_fault_order_is_frozen() -> None:
    assert capture(cases()["ordered_multiple_faults"]) == _fixture()[
        "ordered_multiple_faults"
    ]
