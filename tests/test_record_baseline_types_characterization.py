# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Frozen behavioral boundary for baseline-record validation extraction."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from record_baseline_types_characterization_harness import (
    TrackingBaseline,
    access_traces,
    capture,
    capture_all,
    capture_public_all,
    cases,
    generated_trace_digest,
)

from evoom_guard import record_verifier

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/refactor-safety/record-baseline-types-v1.json"


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


def test_all_baseline_validation_traces_match_pre_extraction_truth() -> None:
    expected = _fixture()
    assert expected["format"] == "record-baseline-types-characterization-v1"
    assert capture_all() == expected["case_errors"]


@pytest.mark.parametrize("name", sorted(cases()))
def test_baseline_validation_never_mutates_its_input(name: str) -> None:
    capture(cases()[name])


def test_public_reports_preserve_canonical_ordered_output() -> None:
    observed = capture_public_all()
    assert {name: _digest(report) for name, report in observed.items()} == _fixture()[
        "public_report_sha256"
    ]


def test_generated_baseline_trace_matches_pre_extraction_digest() -> None:
    assert generated_trace_digest() == _fixture()["generated_trace_sha256"]


def test_mapping_access_order_and_early_return_are_frozen() -> None:
    assert access_traces() == _fixture()["access_traces"]


def test_lookup_exception_identity_and_precedence_are_frozen() -> None:
    sentinel = RuntimeError("tests_total lookup failed")

    class RaisingBaseline(TrackingBaseline):
        def get(self, key: str, default: object = None) -> object:
            value = super().get(key, default)
            if key == "tests_total":
                raise sentinel
            return value

    baseline = RaisingBaseline(cases()["valid_fail"])
    with pytest.raises(RuntimeError) as captured:
        record_verifier._baseline_type_errors(baseline)

    assert captured.value is sentinel
    assert baseline.events == [
        "iter",
        "iter",
        "get:note",
        "get:scope",
        "get:verdict",
        "get:tests_passed",
        "get:tests_total",
    ]


def test_simultaneous_baseline_fault_order_is_frozen() -> None:
    assert capture(cases()["ordered_multiple_faults"]) == _fixture()["case_errors"][
        "ordered_multiple_faults"
    ]
