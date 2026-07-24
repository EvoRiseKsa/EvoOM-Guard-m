# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Contracts for the low-level repository-workspace owner and its facade."""

from __future__ import annotations

import importlib
import importlib.util
import os
from pathlib import Path
from types import ModuleType

import pytest

import evoom_guard.blackbox as blackbox
import evoom_guard.evidence as evidence
import evoom_guard.guard as guard
import evoom_guard.verifiers.repo_verifier as repo_verifier


def _repository_workspace() -> ModuleType:
    module_name = "evoom_guard.workspace.repository"
    assert importlib.util.find_spec(module_name) is not None, (
        "repository copying and workspace cleanup need one workspace-layer owner"
    )
    return importlib.import_module(module_name)


def test_repository_workspace_owner_freezes_the_historical_copy_contract() -> None:
    owner = _repository_workspace()

    assert owner.COPY_IGNORE == (
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        "node_modules",
        ".evo_runs",
        ".pytest_cache",
        ".mypy_cache",
        "dist",
        "build",
    )

    captured: dict[str, object] = {}
    ignore_callback = object()

    def fake_ignore_patterns(*patterns: str) -> object:
        captured["patterns"] = patterns
        return ignore_callback

    def fake_copytree(src: str, dst: str, **kwargs: object) -> None:
        captured["copytree"] = (src, dst, kwargs)

    owner.copy_repo_tree(
        "source",
        "destination",
        copy_ignore=("first-cache", "second-cache"),
        copytree=fake_copytree,
        ignore_patterns=fake_ignore_patterns,
    )

    assert captured["patterns"] == ("first-cache", "second-cache")
    assert captured["copytree"] == (
        "source",
        "destination",
        {"symlinks": True, "ignore": ignore_callback},
    )


@pytest.mark.skipif(os.name != "nt", reason="requires Windows normcase semantics")
def test_repository_copy_ignore_is_case_insensitive_on_windows(tmp_path: Path) -> None:
    owner = _repository_workspace()
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    (source / ".GIT").write_text("gitdir: C:/untrusted.git\n", encoding="utf-8")
    dependencies = source / "NODE_MODULES"
    dependencies.mkdir()
    (dependencies / "candidate.js").write_text("ignored\n", encoding="utf-8")
    (source / ".GITIGNORE").write_text(".cache/\n", encoding="utf-8")
    workflows = source / ".GITHUB" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "guard.yml").write_text("name: guard\n", encoding="utf-8")

    owner.copy_repo_tree(str(source), str(destination))

    assert not (destination / ".GIT").exists()
    assert not (destination / "NODE_MODULES").exists()
    assert (destination / ".GITIGNORE").is_file()
    assert (destination / ".GITHUB" / "workflows" / "guard.yml").is_file()


def test_repo_verifier_copy_facade_resolves_legacy_globals_at_call_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    ignore_callback = object()

    def fake_ignore_patterns(*patterns: str) -> object:
        captured["patterns"] = patterns
        return ignore_callback

    def fake_copytree(src: str, dst: str, **kwargs: object) -> None:
        captured["copytree"] = (src, dst, kwargs)

    monkeypatch.setattr(repo_verifier, "COPY_IGNORE", ("live-cache",))
    monkeypatch.setattr(repo_verifier.shutil, "ignore_patterns", fake_ignore_patterns)
    monkeypatch.setattr(repo_verifier.shutil, "copytree", fake_copytree)

    repo_verifier.copy_repo_tree("source", "destination")

    assert captured["patterns"] == ("live-cache",)
    assert captured["copytree"] == (
        "source",
        "destination",
        {"symlinks": True, "ignore": ignore_callback},
    )


def test_existing_consumers_retain_the_exact_repo_verifier_copy_facade() -> None:
    assert guard.copy_repo_tree is repo_verifier.copy_repo_tree
    assert blackbox.copy_repo_tree is repo_verifier.copy_repo_tree
    assert evidence.copy_repo_tree is repo_verifier.copy_repo_tree
    assert guard.COPY_IGNORE is repo_verifier.COPY_IGNORE


def test_repo_verifier_cleanup_facade_resolves_note_provider_at_call_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = RuntimeError("primary")
    cleanup_error = OSError("busy")
    notes: list[tuple[BaseException, str]] = []

    def fail_remove(_path: str) -> None:
        raise cleanup_error

    def record_note(error: BaseException, message: str) -> None:
        notes.append((error, message))

    monkeypatch.setattr(repo_verifier.shutil, "rmtree", fail_remove)
    monkeypatch.setattr(repo_verifier, "_note_repo_cleanup_failure", record_note)

    repo_verifier._cleanup_repo_workspaces(
        (("candidate workspace", "candidate"),),
        primary=primary,
    )

    assert notes == [
        (
            primary,
            "RepoVerifier candidate workspace cleanup failed while preserving "
            "the primary exception: OSError: busy",
        )
    ]


def test_repository_workspace_cleanup_attempts_every_path_and_preserves_primary() -> None:
    owner = _repository_workspace()
    primary = KeyboardInterrupt("operator interruption")
    attempts: list[str] = []
    notes: list[tuple[BaseException, str]] = []
    failures = {
        "candidate": OSError("candidate busy"),
        "pack": SystemExit("pack busy"),
    }

    def fail_remove(path: str) -> None:
        attempts.append(path)
        raise failures[path]

    def record_note(error: BaseException, message: str) -> None:
        notes.append((error, message))

    owner.cleanup_repo_workspaces(
        (
            ("candidate workspace", "candidate"),
            ("verifier-pack snapshot", "pack"),
        ),
        primary=primary,
        remove_tree=fail_remove,
        note_failure=record_note,
        owner_name="RepoVerifier",
    )

    assert attempts == ["candidate", "pack"]
    assert [error for error, _message in notes] == [primary, primary]
    assert "OSError: candidate busy" in notes[0][1]
    assert "SystemExit: pack busy" in notes[1][1]


def test_repository_workspace_cleanup_keeps_first_failure_after_normal_result() -> None:
    owner = _repository_workspace()
    first = OSError("candidate busy")
    second = SystemExit("pack busy")
    attempts: list[str] = []
    notes: list[tuple[BaseException, str]] = []
    failures = {"candidate": first, "pack": second}

    def fail_remove(path: str) -> None:
        attempts.append(path)
        raise failures[path]

    def record_note(error: BaseException, message: str) -> None:
        notes.append((error, message))

    with pytest.raises(OSError) as caught:
        owner.cleanup_repo_workspaces(
            (
                ("candidate workspace", "candidate"),
                ("verifier-pack snapshot", "pack"),
            ),
            primary=None,
            remove_tree=fail_remove,
            note_failure=record_note,
            owner_name="RepoVerifier",
        )

    assert caught.value is first
    assert attempts == ["candidate", "pack"]
    assert notes[0] == (first, "RepoVerifier candidate workspace cleanup failed")
    assert notes[1] == (
        first,
        "Additional RepoVerifier verifier-pack snapshot cleanup failure: "
        "SystemExit: pack busy",
    )
