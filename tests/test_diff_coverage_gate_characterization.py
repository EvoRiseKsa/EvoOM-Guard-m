"""Frozen behavioral seam for extracting Guard's diff-coverage decision gate."""

from __future__ import annotations

import difflib
import json
from pathlib import Path
from typing import Any, cast

import pytest
from diff_coverage_gate_characterization_harness import (
    CASE_NAMES,
    NORMALIZED_FIELDS,
    SCHEMA_VERSION,
    canonical_json,
    capture_case,
)

VECTOR = Path(__file__).parent / "fixtures" / "refactor-safety" / "diff-coverage-gate-v1.json"


def _frozen() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(VECTOR.read_text(encoding="utf-8")))


def test_diff_coverage_gate_characterization_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert frozen["normalization"] == list(NORMALIZED_FIELDS)
    assert tuple(frozen["cases"]) == CASE_NAMES


@pytest.mark.parametrize("case_name", CASE_NAMES)  # type: ignore[untyped-decorator]
def test_frozen_diff_coverage_decision_access_and_priority(
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
        pytest.fail("diff-coverage decision contract drifted:\n" + diff)


def test_required_unmeasured_fails_closed_with_exact_read_order(tmp_path: Path) -> None:
    case = capture_case("required_unmeasured", tmp_path)
    assert case["decision"]["verdict"] == "ERROR"
    assert case["decision"]["reason_code"] == "assurance_requirement_not_met"
    assert case["coverage_access_trace"] == ["get:measured", "get:note"]


def test_exact_ratio_uses_counts_not_rounded_percent(tmp_path: Path) -> None:
    case = capture_case("below_exact_float_ratio", tmp_path)
    assert case["decision"]["verdict"] == "FAIL"
    assert case["decision"]["reason_code"] == "diff_coverage_below_threshold"
    assert "2/3" in case["decision"]["reason"]
    assert "66.7%" in case["decision"]["reason"]


def test_non_pass_core_decisions_never_read_coverage(tmp_path: Path) -> None:
    failed = capture_case("prior_fail_collects_without_access", tmp_path)
    errored = capture_case("prior_error_does_not_collect_or_access", tmp_path)
    assert failed["coverage_access_trace"] == []
    assert len(failed["collector_calls"]) == 1
    assert errored["coverage_access_trace"] == []
    assert errored["collector_calls"] == []


def test_coverage_failure_precedes_later_policy_gates(tmp_path: Path) -> None:
    case = capture_case("below_floor_precedes_later_gates", tmp_path)
    assert case["decision"]["reason_code"] == "diff_coverage_below_threshold"
    assert case["baseline"]["repair_effect"] == "not_demonstrated"
    assert case["assurance_shortfall_calls"] == 0
