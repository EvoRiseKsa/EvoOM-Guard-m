"""Frozen equivalence and ownership gates for repo materialization."""

from __future__ import annotations

import difflib
import json
from pathlib import Path

import pytest
from repo_materialization_characterization_harness import (
    CASE_NAMES,
    SCHEMA_VERSION,
    canonical_json,
    capture_case,
)

from evoom_guard.verifiers import repo_materialization, repo_verifier

VECTOR = (
    Path(__file__).parent
    / "fixtures"
    / "refactor-safety"
    / "repo-materialization-v1.json"
)


def _frozen() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_repo_materialization_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_repo_materialization_behavior(case_name: str) -> None:
    expected = _frozen()["cases"][case_name]
    actual = capture_case(case_name)
    if actual != expected:
        diff = "".join(
            difflib.unified_diff(
                canonical_json(expected).splitlines(keepends=True),
                canonical_json(actual).splitlines(keepends=True),
                fromfile=f"frozen/{case_name}",
                tofile=f"current/{case_name}",
            )
        )
        pytest.fail("repo materialization behavior drifted:\n" + diff)


def test_repo_verifier_retains_facade_while_new_module_owns_logic() -> None:
    assert repo_verifier.apply_blocks_to_copy.__module__ == (
        "evoom_guard.verifiers.repo_verifier"
    )
    assert repo_materialization.materialize_candidate_edits.__module__ == (
        "evoom_guard.verifiers.repo_materialization"
    )
