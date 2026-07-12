"""Regression tests for deletions through symlinked workspace paths."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import evoom_guard.blackbox as blackbox_module
import evoom_guard.evidence as evidence_module
from evoom_guard.blackbox import run_blackbox
from evoom_guard.candidate_runner import IsolationUnavailable
from evoom_guard.evidence import collect_diff_coverage
from evoom_guard.verifiers.repo_verifier import RepoVerifier
from evoom_guard.workspace import UnsafeWorkspacePath, delete_path_within_root


def _outside_link(repo: Path, outside: Path) -> Path:
    """Create an absolute directory symlink, or skip where Windows forbids it."""
    link = repo / "escape"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")
    return link


def _escape_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    repo.mkdir()
    outside.mkdir()
    (repo / "app.py").write_text("value = 1\n", encoding="utf-8")
    victim = outside / "victim.txt"
    victim.write_text("must survive\n", encoding="utf-8")
    _outside_link(repo, outside)
    return repo, outside, victim


def test_safe_delete_preserves_file_directory_and_missing_semantics(tmp_path: Path):
    root = tmp_path / "workspace"
    root.mkdir()
    file_path = root / "file.txt"
    file_path.write_text("content\n", encoding="utf-8")
    directory = root / "directory"
    directory.mkdir()
    (directory / "nested.txt").write_text("nested\n", encoding="utf-8")

    assert delete_path_within_root(str(root), "file.txt") is True
    assert delete_path_within_root(str(root), "directory") is True
    assert delete_path_within_root(str(root), "missing.txt") is False
    assert not file_path.exists()
    assert not directory.exists()


def test_safe_delete_rejects_non_normalized_relative_path(tmp_path: Path):
    root = tmp_path / "workspace"
    root.mkdir()

    with pytest.raises(UnsafeWorkspacePath, match="normalized relative"):
        delete_path_within_root(str(root), "../outside.txt")


def test_safe_delete_unlinks_leaf_symlink_without_following_it(tmp_path: Path):
    root = tmp_path / "workspace"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    victim = outside / "victim.txt"
    victim.write_text("must survive\n", encoding="utf-8")
    link = root / "leaf"
    try:
        link.symlink_to(victim)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"file symlinks are unavailable: {exc}")

    assert delete_path_within_root(str(root), "leaf") is True
    assert not link.exists()
    assert victim.read_text(encoding="utf-8") == "must survive\n"


def test_repo_verifier_refuses_child_delete_through_parent_symlink(tmp_path: Path):
    repo, _outside, victim = _escape_fixture(tmp_path)
    verifier = RepoVerifier(
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
        mem_limit_mb=0,
    )

    result = verifier.verify(
        "",
        {"repo_path": str(repo), "deleted": ["escape/victim.txt"]},
    )

    assert victim.read_text(encoding="utf-8") == "must survive\n"
    assert not result.passed
    assert "deletion" in result.diagnostics.lower()


def test_blackbox_refuses_child_delete_through_parent_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repo, _outside, victim = _escape_fixture(tmp_path)
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "test_protocol.py").write_text("def test_protocol():\n    assert True\n", encoding="utf-8")

    def stop_before_candidate(*_args, **_kwargs):
        raise IsolationUnavailable("candidate runner must not be reached")

    monkeypatch.setattr(blackbox_module.CandidateRunner, "prepare", stop_before_candidate)
    result = run_blackbox(
        str(repo),
        "",
        str(pack),
        deleted_paths=("escape/victim.txt",),
    )

    assert victim.read_text(encoding="utf-8") == "must survive\n"
    assert not result.passed
    assert result.error == "unsafe deletion path"


def test_diff_coverage_refuses_child_delete_through_parent_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repo, _outside, victim = _escape_fixture(tmp_path)
    monkeypatch.setitem(sys.modules, "coverage", object())

    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess([], 1, "", "")

    monkeypatch.setattr(evidence_module.subprocess, "run", fake_run)
    candidate = "<<<FILE: app.py>>>\nvalue = 2\n<<<END FILE>>>\n"
    result = collect_diff_coverage(
        str(repo),
        candidate,
        deleted=("escape/victim.txt",),
        test_command=[sys.executable, "-m", "pytest", "-q"],
    )

    assert victim.read_text(encoding="utf-8") == "must survive\n"
    assert result["measured"] is False
    assert "deletion" in result["note"].lower()
