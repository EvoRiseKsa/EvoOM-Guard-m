"""Frozen public seam for extracting Guard's candidate preflight."""

from __future__ import annotations

import difflib
import json
from pathlib import Path
from typing import Any, cast

import pytest
from candidate_preflight_characterization_harness import (
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
    / "candidate-preflight-v1.json"
)


def _frozen() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(VECTOR.read_text(encoding="utf-8")))


def test_candidate_preflight_characterization_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert frozen["normalization"] == list(NORMALIZED_FIELDS)
    assert tuple(frozen["cases"]) == CASE_NAMES


@pytest.mark.parametrize("case_name", CASE_NAMES)  # type: ignore[untyped-decorator]
def test_frozen_candidate_preflight_classification_and_execution_boundary(
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
        pytest.fail("candidate-preflight contract drifted:\n" + diff)


def test_mixed_deletions_fail_closed_before_execution(tmp_path: Path) -> None:
    case = capture_case("mixed_deletions", tmp_path)
    assert case["verdict"] == "ERROR"
    assert case["reason_code"] == "unsafe_path"
    assert case["test_command_ran"] is False
    assert case["protected_violations"] == ["tests/test_base.py"]


def test_feature_mode_only_relaxes_a_net_new_plain_test(tmp_path: Path) -> None:
    default = capture_case("new_test_default", tmp_path)
    enabled = capture_case("new_test_feature_mode", tmp_path)
    assert default["verdict"] == "REJECTED"
    assert default["test_command_ran"] is False
    assert enabled["verdict"] == "PASS"
    assert enabled["test_command_ran"] is True
