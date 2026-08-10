# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Frozen behavioral boundary for coverage-record validation extraction."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from record_coverage_types_characterization_harness import (
    capture,
    capture_all,
    capture_public_all,
    cases,
    generated_trace_digest,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/refactor-safety/record-coverage-types-v1.json"


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


def test_all_coverage_validation_traces_match_pre_extraction_truth() -> None:
    expected = _fixture()
    assert expected["format"] == "record-coverage-types-characterization-v1"
    assert capture_all() == expected["case_errors"]


@pytest.mark.parametrize("name", sorted(cases()))
def test_coverage_validation_never_mutates_its_input(name: str) -> None:
    capture(cases()[name])


def test_public_reports_preserve_canonical_ordered_output() -> None:
    observed = capture_public_all()
    assert {name: _digest(report) for name, report in observed.items()} == _fixture()[
        "public_report_sha256"
    ]


def test_generated_coverage_trace_matches_pre_extraction_digest() -> None:
    assert generated_trace_digest() == _fixture()["generated_trace_sha256"]


def test_simultaneous_totals_and_percentage_fault_order_is_frozen() -> None:
    assert capture(cases()["executed_total_mismatch"]) == [
        "executed does not equal the per-file executed-line total",
        "total does not equal the per-file measurable-line total",
        "percent must equal the producer calculation 25.0",
    ]
