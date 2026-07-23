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


def test_repo_verifier_facade_resolves_operation_seams_at_each_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An earlier operation may replace every later historical module seam."""

    files = {"package.json": "original"}
    events: list[str] = []

    def late_read(_root: str, path: str) -> str:
        events.append("late-read")
        return files[path]

    def late_restore(_original: str | None, candidate: str) -> str:
        events.append("late-restore")
        return candidate

    def late_patch(source: str, search: str, replace: str) -> str:
        events.append("late-patch")
        monkeypatch.setattr(
            repo_verifier, "restore_judge_package_json", late_restore
        )
        return source.replace(search, replace)

    def late_write(_root: str, path: str, content: str) -> None:
        events.append("late-write")
        files[path] = content
        monkeypatch.setattr(repo_verifier, "read_text_within_root", late_read)
        monkeypatch.setattr(repo_verifier, "apply_patch", late_patch)

    def early_read(_root: str, path: str) -> str:
        events.append("early-read")
        monkeypatch.setattr(repo_verifier, "write_text_within_root", late_write)
        return files[path]

    def unexpected(*_args: object) -> None:
        pytest.fail("a snapshotted operation seam was used")

    monkeypatch.setattr(repo_verifier, "read_text_within_root", early_read)
    monkeypatch.setattr(repo_verifier, "write_text_within_root", unexpected)
    monkeypatch.setattr(repo_verifier, "apply_patch", unexpected)
    monkeypatch.setattr(repo_verifier, "restore_judge_package_json", unexpected)

    error = repo_verifier.apply_blocks_to_copy(
        "repo-copy",
        {"package.json": "file-value"},
        [repo_verifier.PatchBlock("package.json", "file", "patched")],
    )

    assert error is None
    assert files == {"package.json": "patched-value"}
    assert events == [
        "early-read",
        "late-write",
        "late-read",
        "late-patch",
        "late-write",
        "late-read",
        "late-restore",
    ]
