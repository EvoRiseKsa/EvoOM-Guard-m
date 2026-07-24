"""Frozen equivalence gates for repository pack-snapshot continuity."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from repo_pack_continuity_characterization_harness import (
    CASE_NAMES,
    SCHEMA_VERSION,
    canonical_json,
    capture_case,
)

VECTOR = (
    Path(__file__).parent
    / "fixtures"
    / "refactor-safety"
    / "repo-pack-continuity-v1.json"
)


def _frozen() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_repo_pack_continuity_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_repo_pack_continuity_behavior(
    case_name: str,
    tmp_path: Path,
) -> None:
    expected = _frozen()["cases"][case_name]["sha256"]
    actual = capture_case(case_name, tmp_path)
    observed = hashlib.sha256(canonical_json(actual).encode("utf-8")).hexdigest()
    if observed != expected:
        pytest.fail(
            "repository pack-continuity behavior drifted:\n"
            f"expected sha256: {expected}\n"
            f"observed sha256: {observed}\n"
            "observed behavior:\n" + canonical_json(actual)
        )
