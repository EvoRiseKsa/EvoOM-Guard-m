# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Contracts for the low-level repository-workspace owner and its facade."""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import os
import subprocess
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
    def fake_ignore_patterns(*patterns: str):
        captured["patterns"] = patterns
        return lambda _directory, names: [name for name in names if name in patterns]

    def fake_copytree(src: str, dst: str, **kwargs: object) -> None:
        captured["copytree"] = (src, dst, kwargs)

    owner.copy_repo_tree(
        "source",
        "destination",
        copy_ignore=("first-cache", "second-cache"),
        platform_name="posix",
        copytree=fake_copytree,
        ignore_patterns=fake_ignore_patterns,
    )

    assert captured["patterns"] == ("first-cache", "second-cache")
    source, destination, kwargs = captured["copytree"]
    assert (source, destination) == ("source", "destination")
    assert kwargs["symlinks"] is True
    ignore = kwargs["ignore"]
    assert callable(ignore)
    assert ignore("source", ["first-cache", "kept.py"]) == ["first-cache"]


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


def test_repository_copy_rejects_simulated_windows_reparse_before_copying() -> None:
    owner = _repository_workspace()
    copied: list[tuple[str, str]] = []

    def fake_ignore_patterns(*_patterns: str):
        return lambda _directory, names: [name for name in names if name == ".git"]

    def fake_copytree(src: str, dst: str, **kwargs: object) -> None:
        ignore = kwargs["ignore"]
        assert callable(ignore)
        ignore(src, [".git", "ordinary.py", "linked"])
        copied.append((src, dst))

    def simulated_reparse(path: str) -> bool:
        return path.replace("\\", "/").endswith("/linked")

    with pytest.raises(owner.UnsafeRepositoryTree, match="reparse"):
        owner.copy_repo_tree(
            "source",
            "destination",
            platform_name="nt",
            unsafe_reparse_probe=simulated_reparse,
            copytree=fake_copytree,
            ignore_patterns=fake_ignore_patterns,
        )

    assert copied == []


def test_repository_copy_rejects_a_simulated_windows_symlink_root() -> None:
    owner = _repository_workspace()
    copied: list[tuple[str, str]] = []

    def fake_copytree(src: str, dst: str, **_kwargs: object) -> None:
        copied.append((src, dst))

    with pytest.raises(owner.UnsafeRepositoryTree, match="root"):
        owner.copy_repo_tree(
            "source-link",
            "destination",
            platform_name="nt",
            unsafe_reparse_probe=lambda _path: False,
            unsafe_root_reparse_probe=lambda path: path == "source-link",
            copytree=fake_copytree,
            ignore_patterns=lambda *_patterns: lambda _directory, _names: (),
        )

    assert copied == []


@pytest.mark.skipif(os.name != "nt", reason="requires a real Windows symlink")
def test_repository_copy_does_not_follow_a_windows_symlink_root(
    tmp_path: Path,
) -> None:
    owner = _repository_workspace()
    external = tmp_path / "external"
    source_link = tmp_path / "source-link"
    destination = tmp_path / "destination"
    external.mkdir()
    secret = external / "secret.txt"
    secret.write_text("outside-content\n", encoding="utf-8")
    try:
        source_link.symlink_to(external, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"cannot create a Windows directory symlink: {exc}")

    with pytest.raises(owner.UnsafeRepositoryTree, match="root"):
        owner.copy_repo_tree(str(source_link), str(destination))

    assert secret.read_text(encoding="utf-8") == "outside-content\n"
    assert not (destination / "secret.txt").exists()


@pytest.mark.skipif(os.name != "nt", reason="requires a real Windows junction")
def test_repository_copy_does_not_materialize_a_windows_junction(
    tmp_path: Path,
) -> None:
    owner = _repository_workspace()
    source = tmp_path / "source"
    external = tmp_path / "external"
    destination = tmp_path / "destination"
    source.mkdir()
    external.mkdir()
    secret = external / "secret.txt"
    secret.write_text("outside-content\n", encoding="utf-8")
    junction = source / "linked"
    created = subprocess.run(
        [
            os.environ.get("COMSPEC", "cmd.exe"),
            "/d",
            "/c",
            "mklink",
            "/J",
            str(junction),
            str(external),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if created.returncode != 0:
        pytest.skip(f"cannot create an unprivileged junction: {created.stderr}")

    with pytest.raises(owner.UnsafeRepositoryTree, match="reparse"):
        owner.copy_repo_tree(str(source), str(destination))

    assert secret.read_text(encoding="utf-8") == "outside-content\n"
    assert not (destination / "linked" / "secret.txt").exists()


def test_repo_verifier_copy_facade_resolves_legacy_globals_at_call_time(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    source_path = tmp_path / "source"
    destination_path = tmp_path / "destination"
    source_path.mkdir()

    def fake_ignore_patterns(*patterns: str):
        captured["patterns"] = patterns
        return lambda _directory, names: [name for name in names if name in patterns]

    def fake_copytree(src: str, dst: str, **kwargs: object) -> None:
        captured["copytree"] = (src, dst, kwargs)
        ignore = kwargs["ignore"]
        assert callable(ignore)
        captured["ignored"] = ignore(src, ["live-cache"])

    monkeypatch.setattr(repo_verifier, "COPY_IGNORE", ("live-cache",))
    monkeypatch.setattr(repo_verifier.shutil, "ignore_patterns", fake_ignore_patterns)
    monkeypatch.setattr(repo_verifier.shutil, "copytree", fake_copytree)

    repo_verifier.copy_repo_tree(str(source_path), str(destination_path))

    assert captured["patterns"] == ("live-cache",)
    source, destination, kwargs = captured["copytree"]
    assert (source, destination) == (str(source_path), str(destination_path))
    assert kwargs["symlinks"] is True
    assert captured["ignored"] == ["live-cache"]


def test_existing_consumers_retain_the_exact_repo_verifier_copy_facade() -> None:
    assert guard.copy_repo_tree is repo_verifier.copy_repo_tree
    assert blackbox.copy_repo_tree is repo_verifier.copy_repo_tree
    assert evidence.copy_repo_tree is repo_verifier.copy_repo_tree
    assert guard.COPY_IGNORE is repo_verifier.COPY_IGNORE


def test_repo_verifier_workspace_facades_retain_historical_docstrings() -> None:
    assert inspect.getdoc(repo_verifier.copy_repo_tree) == inspect.cleandoc(
        """
        Copy a repository into a throwaway working copy, faithfully.

        ``symlinks=True`` keeps symlinks *as symlinks* (and regular files keep their
        permission bits via ``copy2``), which matters twice:

        * **No crash on dangling links.** Real repos routinely carry symlinks into
          directories ``COPY_IGNORE`` strips (``.venv/``, ``node_modules/``) or
          plain broken links; dereferencing (the ``symlinks=False`` default) makes
          ``copytree`` raise on those, crashing the judge instead of judging.
        * **No content smuggling.** Dereferencing would copy the link's *target
          content* into the copy — for an absolute link that means host files get
          materialized inside the tree that container isolation later mounts.

        Writing *through* a symlink is prevented separately by the descriptor-bound
        workspace helpers used in :func:`apply_blocks_to_copy`.
        """
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


def test_repo_verifier_cleanup_facade_resolves_absence_proof_at_call_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = _repository_workspace()
    primary = RuntimeError("primary")
    cleanup_error = FileNotFoundError("raced child disappeared")
    notes: list[tuple[BaseException, str]] = []
    absence_checks: list[str] = []

    def fail_remove(_path: str) -> None:
        raise cleanup_error

    def root_still_exists(path: str) -> bool:
        absence_checks.append(path)
        return False

    def record_note(error: BaseException, message: str) -> None:
        notes.append((error, message))

    monkeypatch.setattr(repo_verifier.shutil, "rmtree", fail_remove)
    monkeypatch.setattr(owner, "repository_path_absent", root_still_exists, raising=False)
    monkeypatch.setattr(repo_verifier, "_note_repo_cleanup_failure", record_note)

    repo_verifier._cleanup_repo_workspaces(
        (("candidate workspace", "candidate"),),
        primary=primary,
    )

    assert absence_checks == ["candidate"]
    assert len(notes) == 1
    assert notes[0][0] is primary
    assert "FileNotFoundError: raced child disappeared" in notes[0][1]


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


def test_repository_workspace_cleanup_requires_positive_root_absence_proof() -> None:
    owner = _repository_workspace()
    primary = RuntimeError("verification failed")
    attempts: list[str] = []
    absence_checks: list[str] = []
    notes: list[tuple[BaseException, str]] = []
    child_race = FileNotFoundError("candidate/raced-child")
    later_failure = OSError("pack busy")

    def fail_remove(path: str) -> None:
        attempts.append(path)
        if path == "candidate":
            raise child_race
        raise later_failure

    def root_absent(path: str) -> bool:
        absence_checks.append(path)
        return False

    def record_note(error: BaseException, message: str) -> None:
        notes.append((error, message))

    owner.cleanup_repo_workspaces(
        (
            ("candidate workspace", "candidate"),
            ("verifier-pack snapshot", "pack"),
        ),
        primary=primary,
        remove_tree=fail_remove,
        path_absent=root_absent,
        note_failure=record_note,
        owner_name="RepoVerifier",
    )

    assert attempts == ["candidate", "pack"]
    assert absence_checks == ["candidate"]
    assert [error for error, _message in notes] == [primary, primary]
    assert "FileNotFoundError: candidate/raced-child" in notes[0][1]
    assert "OSError: pack busy" in notes[1][1]


def test_repository_workspace_cleanup_accepts_proven_prior_removal() -> None:
    owner = _repository_workspace()
    attempts: list[str] = []
    absence_checks: list[str] = []

    def remove(path: str) -> None:
        attempts.append(path)
        if path == "already-absent":
            raise FileNotFoundError(path)

    def root_absent(path: str) -> bool:
        absence_checks.append(path)
        return path == "already-absent"

    owner.cleanup_repo_workspaces(
        (
            ("candidate workspace", "already-absent"),
            ("verifier-pack snapshot", "pack"),
        ),
        primary=None,
        remove_tree=remove,
        path_absent=root_absent,
    )

    assert attempts == ["already-absent", "pack"]
    assert absence_checks == ["already-absent"]


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
