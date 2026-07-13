# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Adversarial regression tests for TOCTOU and hardlink containment.

Every filesystem target stays below ``tmp_path``; no host path is read or
modified. Controlled monkeypatches place the race at the former check/use seam.
"""

from __future__ import annotations

import hashlib
import os
import stat
from contextlib import contextmanager
from pathlib import Path

import pytest

import evoom_guard.verifiers.fidelity as fidelity
import evoom_guard.verifiers.repo_verifier as repo_verifier
import evoom_guard.workspace as workspace


@pytest.mark.skipif(os.name != "posix", reason="POSIX capability contract")
def test_required_descriptor_primitives_are_detected_on_supported_posix() -> None:
    assert workspace._HAS_DESCRIPTOR_RELATIVE


def _require_file_symlink(tmp_path: Path) -> None:
    target = tmp_path / "symlink-probe-target"
    link = tmp_path / "symlink-probe"
    target.write_text("probe", encoding="utf-8")
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"file symlinks are unavailable: {exc}")
    finally:
        link.unlink(missing_ok=True)


def _require_directory_symlink(tmp_path: Path) -> None:
    target = tmp_path / "directory-symlink-probe-target"
    link = tmp_path / "directory-symlink-probe"
    target.mkdir()
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")
    finally:
        link.unlink(missing_ok=True)


def _require_hardlink(tmp_path: Path) -> None:
    target = tmp_path / "hardlink-probe-target"
    link = tmp_path / "hardlink-probe"
    target.write_text("probe", encoding="utf-8")
    try:
        os.link(target, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"hardlinks are unavailable: {exc}")
    finally:
        link.unlink(missing_ok=True)


def test_fidelity_lstat_to_open_race_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A regular-file lstat cannot authorize opening a later symlink target."""
    _require_file_symlink(tmp_path)
    judged = tmp_path / "workspace" / "candidate.bin"
    outside = tmp_path / "outside" / "controlled-secret.bin"
    judged.parent.mkdir()
    outside.parent.mkdir()
    judged.write_bytes(b"candidate-before-race")
    outside_bytes = b"controlled-outside-content"
    outside.write_bytes(outside_bytes)

    original_lstat = os.lstat
    swapped = False

    def lstat_then_swap(path: os.PathLike[str] | str):
        nonlocal swapped
        observed = original_lstat(path)
        if os.path.abspath(os.fspath(path)) == os.path.abspath(judged) and not swapped:
            judged.unlink()
            judged.symlink_to(outside)
            swapped = True
        return observed

    with monkeypatch.context() as patch:
        patch.setattr(fidelity.os, "lstat", lstat_then_swap)
        with pytest.raises(fidelity.SetupFidelityError):
            fidelity._fidelity_entry_state(str(judged))

    assert swapped
    assert judged.is_symlink()
    assert outside.read_bytes() == outside_bytes


@pytest.mark.skipif(
    not workspace._HAS_DESCRIPTOR_RELATIVE,
    reason="descriptor-relative traversal is POSIX-only",
)
def test_descriptor_relative_write_rejects_parent_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A held parent descriptor prevents a checked path from redirecting writes."""
    _require_directory_symlink(tmp_path)
    workspace_root = tmp_path / "workspace"
    parent = workspace_root / "safe-parent"
    outside = tmp_path / "outside"
    parent.mkdir(parents=True)
    outside.mkdir()

    original_open_parent = workspace._open_parent_dir_fd
    swapped = False

    @contextmanager
    def open_then_swap(root: str, relative_path: str, *, create: bool):
        nonlocal swapped
        with original_open_parent(root, relative_path, create=create) as opened:
            if not swapped:
                parent.rmdir()
                parent.symlink_to(outside, target_is_directory=True)
                swapped = True
            yield opened

    monkeypatch.setattr(workspace, "_open_parent_dir_fd", open_then_swap)
    error = repo_verifier.apply_blocks_to_copy(
        str(workspace_root),
        {"safe-parent/escaped.txt": "controlled-write\n"},
        [],
    )

    escaped = outside / "escaped.txt"
    assert swapped
    assert error is not None
    assert "changed" in error or "symlink" in error
    assert not escaped.exists()


@pytest.mark.skipif(
    not workspace._HAS_DESCRIPTOR_RELATIVE,
    reason="descriptor-relative traversal is POSIX-only",
)
def test_descriptor_relative_delete_rejects_parent_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A held parent descriptor prevents deletion through a swapped path."""
    _require_directory_symlink(tmp_path)
    root = tmp_path / "delete-workspace"
    parent = root / "safe-parent"
    outside = tmp_path / "delete-outside"
    parent.mkdir(parents=True)
    outside.mkdir()
    victim = outside / "victim.txt"
    victim.write_text("controlled-victim\n", encoding="utf-8")

    original_open_parent = workspace._open_parent_dir_fd
    swapped = False

    @contextmanager
    def open_then_swap(root: str, relative_path: str, *, create: bool):
        nonlocal swapped
        with original_open_parent(root, relative_path, create=create) as opened:
            if not swapped:
                parent.rmdir()
                parent.symlink_to(outside, target_is_directory=True)
                swapped = True
            yield opened

    monkeypatch.setattr(workspace, "_open_parent_dir_fd", open_then_swap)
    with pytest.raises(workspace.UnsafeWorkspacePath):
        workspace.delete_path_within_root(str(root), "safe-parent/victim.txt")

    assert swapped
    assert victim.read_text(encoding="utf-8") == "controlled-victim\n"


def test_fidelity_rejects_hardlink_identity_alias(tmp_path: Path) -> None:
    """Fidelity refuses a regular file whose identity has multiple names."""
    _require_hardlink(tmp_path)
    outside = tmp_path / "outside" / "shared.bin"
    judged = tmp_path / "workspace" / "candidate.bin"
    outside.parent.mkdir()
    judged.parent.mkdir()
    outside.write_bytes(b"same-content")
    os.link(outside, judged)

    outside_stat = outside.stat()
    linked_stat = judged.stat()
    assert (linked_stat.st_dev, linked_stat.st_ino) == (
        outside_stat.st_dev,
        outside_stat.st_ino,
    )
    with pytest.raises(fidelity.SetupFidelityError, match="hardlinked"):
        fidelity._fidelity_entry_state(str(judged))

    judged.unlink()
    judged.write_bytes(outside.read_bytes())
    os.chmod(judged, stat.S_IMODE(outside_stat.st_mode))
    independent_stat = judged.stat()
    assert (independent_stat.st_dev, independent_stat.st_ino) != (
        outside_stat.st_dev,
        outside_stat.st_ino,
    )
    independent_state = fidelity._fidelity_entry_state(str(judged))
    assert independent_state == (
        "file",
        stat.S_IMODE(independent_stat.st_mode),
        hashlib.sha256(b"same-content").hexdigest(),
    )


@pytest.mark.skipif(
    not workspace._HAS_DESCRIPTOR_RELATIVE,
    reason="descriptor-relative traversal is POSIX-only",
)
def test_open_parent_closes_root_fd_when_post_open_identity_check_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The root descriptor is owned immediately after open, even on lstat failure."""
    root = tmp_path / "workspace"
    root.mkdir()
    original_open = workspace.os.open
    original_lstat = workspace.os.lstat
    root_fd: int | None = None
    root_lstat_calls = 0

    def capture_open(path, flags, *args, **kwargs):
        nonlocal root_fd
        fd = original_open(path, flags, *args, **kwargs)
        if os.path.abspath(os.fspath(path)) == os.path.abspath(root):
            root_fd = fd
        return fd

    def fail_second_root_lstat(path):
        nonlocal root_lstat_calls
        if os.path.abspath(os.fspath(path)) == os.path.abspath(root):
            root_lstat_calls += 1
            if root_lstat_calls == 2:
                raise OSError("controlled root identity failure")
        return original_lstat(path)

    with monkeypatch.context() as patch:
        patch.setattr(workspace.os, "open", capture_open)
        patch.setattr(workspace.os, "lstat", fail_second_root_lstat)
        with pytest.raises(workspace.UnsafeWorkspacePath):
            with workspace._open_parent_dir_fd(str(root), "file.txt", create=False):
                pytest.fail("identity failure must happen before yielding")

    assert root_fd is not None
    with pytest.raises(OSError):
        os.fstat(root_fd)


@pytest.mark.skipif(
    not workspace._HAS_DESCRIPTOR_RELATIVE,
    reason="descriptor-relative recursive deletion is POSIX-only",
)
def test_recursive_delete_never_reports_absent_after_partial_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A mid-recursion disappearance fails closed after earlier entries changed."""
    root = tmp_path / "workspace"
    tree = root / "tree"
    tree.mkdir(parents=True)
    first = tree / "a.txt"
    second = tree / "b.txt"
    first.write_text("first", encoding="utf-8")
    second.write_text("second", encoding="utf-8")
    original_stat = workspace.os.stat
    injected = False

    def fail_second_child(path, *args, **kwargs):
        nonlocal injected
        if path == "b.txt" and kwargs.get("dir_fd") is not None and not injected:
            injected = True
            raise FileNotFoundError("controlled recursive deletion race")
        return original_stat(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(workspace.os, "stat", fail_second_child)
        with pytest.raises(workspace.UnsafeWorkspacePath, match="mutation began"):
            workspace.delete_path_within_root(str(root), "tree")

    assert injected
    assert not first.exists()
    assert second.exists()
    assert tree.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode-race semantics")
def test_fidelity_binds_mode_from_opened_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A same-inode chmod between lstat and open is not silently accepted."""
    judged = tmp_path / "candidate.bin"
    judged.write_bytes(b"candidate")
    os.chmod(judged, 0o600)
    original_lstat = fidelity.os.lstat
    changed = False

    def lstat_then_chmod(path):
        nonlocal changed
        observed = original_lstat(path)
        if os.path.abspath(os.fspath(path)) == os.path.abspath(judged) and not changed:
            os.chmod(judged, 0o400)
            changed = True
        return observed

    with monkeypatch.context() as patch:
        patch.setattr(fidelity.os, "lstat", lstat_then_chmod)
        with pytest.raises(fidelity.SetupFidelityError, match="lstat and open"):
            fidelity._fidelity_entry_state(str(judged))

    assert changed


def test_fidelity_rejects_directory_namespace_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An entry appearing during traversal invalidates the entire snapshot."""
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "stable.txt").write_text("stable", encoding="utf-8")
    original_listdir = fidelity.os.listdir
    calls = 0

    def listdir_then_add(path):
        nonlocal calls
        calls += 1
        if calls == 2:
            (root / "late.txt").write_text("late", encoding="utf-8")
        return original_listdir(path)

    with monkeypatch.context() as patch:
        patch.setattr(fidelity.os, "listdir", listdir_then_add)
        with pytest.raises(fidelity.SetupFidelityError, match="namespace changed"):
            fidelity._setup_fidelity_snapshot(str(root))

    assert calls >= 2


def test_best_effort_target_rejects_reparse_workspace_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The Windows fallback validates the root itself, not just descendants."""
    root = tmp_path / "workspace"
    root.mkdir()

    def root_is_junction(path) -> bool:
        return os.path.abspath(os.fspath(path)) == os.path.abspath(root)

    monkeypatch.setattr(
        workspace.os.path, "isjunction", root_is_junction, raising=False
    )
    with pytest.raises(workspace.UnsafeWorkspacePath, match="root"):
        workspace._best_effort_target(str(root), "file.txt", create=False)


@pytest.mark.skipif(os.name != "nt", reason="Windows fallback only")
def test_best_effort_write_closes_raw_fd_when_fdopen_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Failure to wrap mkstemp's descriptor does not leak the raw handle."""
    root = tmp_path / "workspace"
    root.mkdir()
    original_mkstemp = workspace.tempfile.mkstemp
    captured_fd: int | None = None
    temporary: str | None = None

    def capture_mkstemp(*args, **kwargs):
        nonlocal captured_fd, temporary
        captured_fd, temporary = original_mkstemp(*args, **kwargs)
        return captured_fd, temporary

    def fail_fdopen(*_args, **_kwargs):
        raise OSError("controlled fdopen failure")

    with monkeypatch.context() as patch:
        patch.setattr(workspace.tempfile, "mkstemp", capture_mkstemp)
        patch.setattr(workspace.os, "fdopen", fail_fdopen)
        with pytest.raises(OSError, match="fdopen failure"):
            workspace.write_text_within_root(str(root), "file.txt", "content")

    assert captured_fd is not None
    with pytest.raises(OSError):
        os.fstat(captured_fd)
    assert temporary is not None
    assert not os.path.exists(temporary)


def test_package_manifest_unsafe_read_is_not_treated_as_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unsafe existing package manifest aborts before any candidate write."""
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "package.json").write_text('{"scripts": {}}', encoding="utf-8")
    writes: list[tuple[str, str]] = []

    def unsafe_read(_root: str, relative_path: str) -> str:
        raise workspace.UnsafeWorkspacePath(f"controlled unsafe read: {relative_path}")

    def capture_write(_root: str, relative_path: str, content: str) -> None:
        writes.append((relative_path, content))

    monkeypatch.setattr(repo_verifier, "read_text_within_root", unsafe_read)
    monkeypatch.setattr(repo_verifier, "write_text_within_root", capture_write)
    error = repo_verifier.apply_blocks_to_copy(
        str(root), {"package.json": '{"scripts": {"test": "candidate"}}'}, []
    )

    assert error is not None
    assert "could not be read safely" in error
    assert "refusing to treat it as absent" in error
    assert writes == []
