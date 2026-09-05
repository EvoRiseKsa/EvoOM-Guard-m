"""Frozen equivalence seam for the CandidateRunner extraction."""

from __future__ import annotations

import difflib
import json
from pathlib import Path

import pytest
from candidate_runner_characterization_harness import (
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
    / "candidate-runner-v3.json"
)
LEGACY_V1_VECTOR = (
    Path(__file__).parent
    / "fixtures"
    / "refactor-safety"
    / "candidate-runner-v1.json"
)
LEGACY_V2_VECTOR = (
    Path(__file__).parent
    / "fixtures"
    / "refactor-safety"
    / "candidate-runner-v2.json"
)


def _frozen() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_candidate_runner_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert frozen["normalization"] == list(NORMALIZED_FIELDS)
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))


def test_security_ratchet_preserves_the_historical_v1_vector() -> None:
    legacy = json.loads(LEGACY_V1_VECTOR.read_text(encoding="utf-8"))
    assert legacy["schema_version"] == "candidate-runner-characterization-v1"
    assert (
        legacy["cases"]["image_inspect_hit"]["digest"]
        == "sha256:0123456789abcdef"
    )


def test_go_cache_ratchet_preserves_the_historical_v2_vector() -> None:
    legacy = json.loads(LEGACY_V2_VECTOR.read_text(encoding="utf-8"))
    assert legacy["schema_version"] == "candidate-runner-characterization-v2"
    prefix = legacy["cases"]["docker_plan"]["config"]["prefix"]
    assert "GOCACHE=/tmp/go-build" not in prefix

    current = _frozen()
    current_prefix = current["cases"]["docker_plan"]["config"]["prefix"]
    assert "GOCACHE=/tmp/go-build" in current_prefix


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_candidate_runner_behavior(case_name: str, tmp_path: Path) -> None:
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
        pytest.fail("CandidateRunner behavior drifted:\n" + diff)
