"""Frozen equivalence gates for the repository verifier-pack intake seam."""

from __future__ import annotations

import difflib
import json
from pathlib import Path

import pytest
from repo_pack_intake_characterization_harness import (
    CASE_NAMES,
    SCHEMA_VERSION,
    canonical_json,
    capture_case,
)

VECTOR = (
    Path(__file__).parent
    / "fixtures"
    / "refactor-safety"
    / "repo-pack-intake-v1.json"
)


def _frozen() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_repo_pack_intake_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_repo_pack_intake_behavior(case_name: str, tmp_path: Path) -> None:
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
        pytest.fail("repo verifier-pack intake behavior drifted:\n" + diff)
