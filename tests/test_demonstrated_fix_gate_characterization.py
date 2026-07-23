"""Frozen behavioral seam for extracting Guard's demonstrated-fix gate."""

from __future__ import annotations

import difflib
import json
from pathlib import Path
from typing import Any, cast

import pytest
from demonstrated_fix_gate_characterization_harness import (
    CASE_NAMES,
    NORMALIZED_FIELDS,
    SCHEMA_VERSION,
    canonical_json,
    capture_case,
)

VECTOR = Path(__file__).parent / "fixtures" / "refactor-safety" / "demonstrated-fix-gate-v1.json"


def _frozen() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(VECTOR.read_text(encoding="utf-8")))


def test_demonstrated_fix_gate_characterization_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert frozen["normalization"] == list(NORMALIZED_FIELDS)
    assert tuple(frozen["cases"]) == CASE_NAMES


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_demonstrated_fix_decision_access_and_priority(
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
        pytest.fail("demonstrated-fix decision contract drifted:\n" + diff)


def test_required_baseline_pass_has_exact_reads_and_reason(tmp_path: Path) -> None:
    case = capture_case("required_baseline_pass", tmp_path)
    assert case["decision"] == {
        "verdict": "FAIL",
        "passed": False,
        "reason_code": "fix_not_demonstrated",
        "reason": (
            "the suite passes on the candidate, but the fix is not "
            "demonstrated: the pristine base already passes the same suite "
            "— --require-demonstrated-fix demands baseline FAIL → candidate "
            "PASS under an unchanged harness"
        ),
    }
    assert case["baseline_access_trace"] == [
        "get:verdict",
        "get:verdict",
        "setitem:repair_effect",
        "setitem:scope",
        "setitem:note",
        "getitem:repair_effect",
        "get:verdict",
    ]


def test_no_clean_and_missing_verdict_are_distinct_frozen_shapes(
    tmp_path: Path,
) -> None:
    no_clean = capture_case("required_no_clean_verdict", tmp_path)
    missing = capture_case("required_missing_verdict", tmp_path)
    assert no_clean["baseline"]["repair_effect"] == "unmeasured"
    assert missing["baseline"]["repair_effect"] == "not_demonstrated"
    assert no_clean["decision"]["reason"] == missing["decision"]["reason"]


def test_missing_repair_effect_fails_loud_before_assurance(tmp_path: Path) -> None:
    case = capture_case("required_missing_repair_effect", tmp_path)
    assert case["decision"] is None
    assert case["exception"] == {
        "type": "KeyError",
        "message": "'repair_effect'",
    }
    assert case["baseline_access_trace"][-1] == "getitem:repair_effect"
    assert case["assurance_profile_calls"] == 0
    assert case["assurance_shortfall_calls"] == 0


def test_prior_diff_failure_keeps_priority_over_later_gates(tmp_path: Path) -> None:
    case = capture_case("prior_diff_coverage_fail_preserved", tmp_path)
    assert case["decision"]["reason_code"] == "diff_coverage_below_threshold"
    assert case["baseline"]["repair_effect"] == "not_demonstrated"
    assert "getitem:repair_effect" not in case["baseline_access_trace"]
    assert case["assurance_shortfall_calls"] == 0


def test_demonstrated_fix_gate_precedes_assurance(tmp_path: Path) -> None:
    rejected = capture_case(
        "required_baseline_pass_precedes_assurance",
        tmp_path,
    )
    allowed = capture_case(
        "required_demonstrated_allows_assurance",
        tmp_path,
    )
    assert rejected["decision"]["reason_code"] == "fix_not_demonstrated"
    assert rejected["assurance_shortfall_calls"] == 0
    assert allowed["decision"]["reason_code"] == "assurance_requirement_not_met"
    assert allowed["assurance_shortfall_calls"] == 1
    assert allowed["timeline"].index("baseline:getitem:repair_effect") < (
        allowed["timeline"].index("assurance:shortfall")
    )
