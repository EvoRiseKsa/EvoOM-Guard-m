"""Frozen equivalence gates for repository-judgment cleanup effects."""

from __future__ import annotations

import difflib
import inspect
import json
from pathlib import Path

import pytest
from repo_cleanup_characterization_harness import (
    CASE_NAMES,
    SCHEMA_VERSION,
    canonical_json,
    capture_case,
)

from evoom_guard.verifiers import repo_cleanup, repo_verifier

VECTOR = (
    Path(__file__).parent
    / "fixtures"
    / "refactor-safety"
    / "repo-cleanup-v1.json"
)


def _frozen() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_repo_cleanup_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_repo_cleanup_behavior(
    case_name: str,
    tmp_path: Path,
) -> None:
    expected = _frozen()["cases"][case_name]
    actual = capture_case(case_name, tmp_path / case_name)
    if actual != expected:
        diff = "".join(
            difflib.unified_diff(
                canonical_json(expected).splitlines(keepends=True),
                canonical_json(actual).splitlines(keepends=True),
                fromfile=f"frozen/{case_name}",
                tofile=f"current/{case_name}",
            )
        )
        pytest.fail("repository-cleanup behavior drifted:\n" + diff)


def test_repo_cleanup_legacy_facades_are_frozen() -> None:
    assert str(inspect.signature(repo_verifier._note_repo_cleanup_failure)) == (
        "(primary: 'BaseException', message: 'str') -> 'None'"
    )
    assert str(inspect.signature(repo_verifier._cleanup_repo_workspaces)) == (
        "(workspaces: 'tuple[tuple[str, str | None], ...]', "
        "*, primary: 'BaseException | None') -> 'None'"
    )
    assert inspect.getdoc(repo_verifier._note_repo_cleanup_failure) == (
        "Attach cleanup diagnostics without ever replacing ``primary``."
    )
    assert inspect.getdoc(repo_verifier._cleanup_repo_workspaces) == inspect.cleandoc(
        """
        Remove every judge-owned workspace with explicit exception precedence.

        All paths are attempted.  With no active exception, the first cleanup
        failure remains visible (and any later failures are attached as notes).
        While another exception is unwinding, that exact exception remains primary
        and receives one note per cleanup failure instead of being masked.
        """
    )


def test_repo_cleanup_owner_is_distinct_from_the_legacy_facade() -> None:
    assert repo_verifier._cleanup_repo_workspaces.__module__ == (
        "evoom_guard.verifiers.repo_verifier"
    )
    assert repo_cleanup.cleanup_repo_verification.__module__ == (
        "evoom_guard.verifiers.repo_cleanup"
    )
    verifier_source = inspect.getsource(repo_verifier.RepoVerifier._verify)
    assert "finally:" in verifier_source
    assert "_cleanup_repo_workspaces(" in verifier_source
    assert "cleanup_repo_verification(" not in verifier_source
