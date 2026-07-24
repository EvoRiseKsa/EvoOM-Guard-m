"""Frozen equivalence gates for RepoVerifier's setup-command phase."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from repo_setup_characterization_harness import (
    CASE_NAMES,
    SCHEMA_VERSION,
    canonical_json,
    capture_case,
    capture_command,
    observe_live_operation_order,
)

VECTOR = Path(__file__).parent / "fixtures" / "refactor-safety" / "repo-setup-v1.json"


def _frozen() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_repo_setup_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_repo_setup_behavior(case_name: str, tmp_path: Path) -> None:
    expected = _frozen()["cases"][case_name]["sha256"]
    actual = capture_case(case_name, tmp_path)
    observed = hashlib.sha256(canonical_json(actual).encode("utf-8")).hexdigest()
    if observed != expected:
        pytest.fail(
            "repository setup behavior drifted:\n"
            f"expected sha256: {expected}\n"
            f"observed sha256: {observed}\n"
            "observed behavior:\n" + canonical_json(actual)
        )


@pytest.mark.parametrize(
    ("constructor", "problem", "expected"),
    (
        (["constructor", 1], ["problem"], ["constructor", "1"]),
        ([], ["problem", 2], ["problem", "2"]),
        (None, "tool  --flag value", ["tool", "--flag", "value"]),
    ),
)
def test_setup_command_precedence_and_token_normalization_are_frozen(
    constructor: object,
    problem: object,
    expected: list[str],
    tmp_path: Path,
) -> None:
    observed, events = capture_command(
        tmp_path,
        constructor_command=constructor,
        problem_command=problem,
    )
    assert observed == expected
    assert events == ["resolve", "pre-snapshot"]


def test_setup_operation_order_is_frozen(tmp_path: Path) -> None:
    assert observe_live_operation_order(tmp_path) == [
        "resolve-setup",
        "snapshot-pre",
        "run-setup",
        "snapshot-post",
        "changes",
        "resolve-suite",
        "run-suite",
    ]
