"""Frozen behavioral/evidence equivalence seam for the verifier refactor."""

from __future__ import annotations

import difflib
import json
from pathlib import Path

import pytest
from repo_verifier_characterization_harness import (
    CASE_NAMES,
    NORMALIZED_FIELDS,
    SCHEMA_VERSION,
    canonical_json,
    capture_case,
)

VECTOR = Path(__file__).parent / "fixtures" / "refactor-safety" / "repo-verifier-v1.json"


def _frozen() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_characterization_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert frozen["normalization"] == list(NORMALIZED_FIELDS)
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_repo_verifier_behavior_and_evidence(case_name: str, tmp_path: Path) -> None:
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
        pytest.fail("repo verifier behavior/evidence drifted:\n" + diff)
