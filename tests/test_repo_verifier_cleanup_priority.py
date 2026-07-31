"""Exception-precedence contract for RepoVerifier-owned cleanup."""

from __future__ import annotations

from pathlib import Path

import pytest

import evoom_guard.verifiers.repo_verifier as repo_verifier
from evoom_guard.verifiers.repo_verifier import RepoVerifier


def _candidate() -> str:
    return "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n"


def _problem(root: Path) -> dict[str, str]:
    root.joinpath("app.py").write_text("VALUE = 1\n", encoding="utf-8")
    return {"repo_path": str(root)}


def test_workspace_cleanup_baseexception_cannot_mask_primary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    problem = _problem(repo)
    workdir = tmp_path / "judge-workdir"
    workdir.mkdir()
    primary = KeyboardInterrupt("operator interrupted copy")
    cleanup_error = SystemExit("candidate workspace cleanup exited")

    monkeypatch.setattr(
        repo_verifier.tempfile,
        "mkdtemp",
        lambda *, prefix: str(workdir),
    )
    monkeypatch.setattr(
        repo_verifier,
        "copy_repo_tree",
        lambda *_args: (_ for _ in ()).throw(primary),
    )
    monkeypatch.setattr(
        repo_verifier.shutil,
        "rmtree",
        lambda _path: (_ for _ in ()).throw(cleanup_error),
    )

    with pytest.raises(KeyboardInterrupt) as caught:
        RepoVerifier(mem_limit_mb=0).verify(_candidate(), problem)

    assert caught.value is primary
    notes = getattr(caught.value, "__notes__", [])
    assert any("candidate workspace cleanup failed" in note for note in notes)
    assert any("SystemExit" in note and str(cleanup_error) in note for note in notes)


def test_workspace_cleanup_failure_is_visible_after_pending_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    problem = _problem(repo)
    workdir = tmp_path / "judge-workdir"
    workdir.mkdir()
    cleanup_error = SystemExit("cleanup must remain visible")

    monkeypatch.setattr(
        repo_verifier.tempfile,
        "mkdtemp",
        lambda *, prefix: str(workdir),
    )
    monkeypatch.setattr(repo_verifier, "copy_repo_tree", lambda *_args: None)
    monkeypatch.setattr(
        repo_verifier,
        "apply_blocks_to_copy",
        lambda *_args: "candidate application failed",
    )
    monkeypatch.setattr(
        repo_verifier.shutil,
        "rmtree",
        lambda _path: (_ for _ in ()).throw(cleanup_error),
    )

    with pytest.raises(SystemExit) as caught:
        RepoVerifier(mem_limit_mb=0).verify(_candidate(), problem)

    assert caught.value is cleanup_error
    assert any(
        "RepoVerifier candidate workspace cleanup failed" in note
        for note in getattr(caught.value, "__notes__", [])
    )


def test_every_workspace_cleanup_is_attempted_and_reported_on_primary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = RuntimeError("verification failed")
    failures = {
        "candidate": OSError("candidate busy"),
        "pack": SystemExit("pack cleanup exited"),
    }
    attempts: list[str] = []

    def fail_cleanup(path: str) -> None:
        attempts.append(path)
        raise failures[path]

    monkeypatch.setattr(repo_verifier.shutil, "rmtree", fail_cleanup)

    repo_verifier._cleanup_repo_workspaces(
        (
            ("candidate workspace", "candidate"),
            ("verifier-pack snapshot", "pack"),
        ),
        primary=primary,
    )

    assert attempts == ["candidate", "pack"]
    notes = getattr(primary, "__notes__", [])
    assert len(notes) == 2
    assert "candidate workspace" in notes[0]
    assert "OSError: candidate busy" in notes[0]
    assert "verifier-pack snapshot" in notes[1]
    assert "SystemExit: pack cleanup exited" in notes[1]


def test_first_cleanup_failure_remains_primary_after_normal_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = OSError("candidate busy")
    second = SystemExit("pack cleanup exited")
    failures = {"candidate": first, "pack": second}
    attempts: list[str] = []

    def fail_cleanup(path: str) -> None:
        attempts.append(path)
        raise failures[path]

    monkeypatch.setattr(repo_verifier.shutil, "rmtree", fail_cleanup)

    with pytest.raises(OSError) as caught:
        repo_verifier._cleanup_repo_workspaces(
            (
                ("candidate workspace", "candidate"),
                ("verifier-pack snapshot", "pack"),
            ),
            primary=None,
        )

    assert caught.value is first
    assert attempts == ["candidate", "pack"]
    notes = getattr(first, "__notes__", [])
    assert "candidate workspace cleanup failed" in notes[0]
    assert "SystemExit: pack cleanup exited" in notes[1]


def test_pack_snapshot_exception_cleans_registered_workspaces_in_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    problem = _problem(repo)
    pack = tmp_path / "pack"
    pack.mkdir()
    problem["verifier_pack"] = str(pack)
    candidate_workspace = tmp_path / "candidate-workspace"
    pack_workspace = tmp_path / "pack-workspace"
    workspaces = iter((candidate_workspace, pack_workspace))
    allocations: list[tuple[str, str]] = []
    cleanup_attempts: list[str] = []
    primary = RuntimeError("snapshot provider failed")

    def create_workspace(*, prefix: str) -> str:
        path = next(workspaces)
        # Preserve tempfile.mkdtemp's contract: allocation returns an existing
        # directory whose identity can be captured immediately.
        path.mkdir()
        allocations.append((prefix, str(path)))
        return str(path)

    def fail_snapshot(*_args: object) -> tuple[str, dict[str, object] | None]:
        raise primary

    monkeypatch.setattr(repo_verifier.tempfile, "mkdtemp", create_workspace)
    monkeypatch.setattr(repo_verifier, "copy_repo_tree", lambda *_args: None)
    monkeypatch.setattr(
        repo_verifier,
        "apply_blocks_to_copy",
        lambda *_args: None,
    )
    monkeypatch.setattr(repo_verifier, "snapshot_pack", fail_snapshot)
    monkeypatch.setattr(
        repo_verifier.shutil,
        "rmtree",
        lambda path: cleanup_attempts.append(path),
    )

    with pytest.raises(RuntimeError) as caught:
        RepoVerifier(mem_limit_mb=0).verify(_candidate(), problem)

    assert caught.value is primary
    assert allocations == [
        ("evo_repo_", str(candidate_workspace)),
        ("evo_pack_snapshot_", str(pack_workspace)),
    ]
    assert cleanup_attempts == [
        str(candidate_workspace),
        str(pack_workspace),
    ]
    assert all(
        isinstance(path, str) and type(path) is not str
        for path in cleanup_attempts
    )
