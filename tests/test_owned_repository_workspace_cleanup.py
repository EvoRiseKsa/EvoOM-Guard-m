# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Security and lifecycle contracts for claimed repository workspaces."""

from __future__ import annotations

import errno
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

import evoom_guard.verifiers.repo_verifier as repo_verifier
from evoom_guard.verifiers.repo_verifier import RepoVerifier
from evoom_guard.workspace import repository as workspace_owner


class _HostileFormatError(OSError):
    def __format__(self, _format_spec: str) -> str:
        raise SystemExit("secondary formatting escaped")


def _claim(root: Path, *, platform_name: str | None = None):
    return workspace_owner.allocate_owned_workspace(
        prefix="owned-test-",
        create_workspace=lambda *, prefix: str(root),
        platform_name=platform_name,
    )


def test_failed_ownership_capture_rolls_back_the_allocated_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "allocated"
    failure = OSError("identity capture failed")

    def create_workspace(*, prefix: str) -> str:
        root.mkdir()
        return str(root)

    monkeypatch.setattr(
        workspace_owner,
        "_claim_owned_workspace",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(failure),
    )

    with pytest.raises(OSError) as caught:
        workspace_owner.allocate_owned_workspace(
            prefix="owned-test-",
            create_workspace=create_workspace,
        )

    assert caught.value is failure
    assert not root.exists()


def test_failed_capture_preserves_primary_when_rollback_also_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "allocated"
    primary = KeyboardInterrupt("identity capture interrupted")
    rollback = OSError("rollback denied")

    def create_workspace(*, prefix: str) -> str:
        root.mkdir()
        return str(root)

    monkeypatch.setattr(
        workspace_owner,
        "_claim_owned_workspace",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(primary),
    )
    monkeypatch.setattr(
        workspace_owner.os,
        "rmdir",
        lambda _path: (_ for _ in ()).throw(rollback),
    )
    with pytest.raises(KeyboardInterrupt) as caught:
        workspace_owner.allocate_owned_workspace(
            prefix="owned-test-",
            create_workspace=create_workspace,
        )

    assert caught.value is primary
    notes = getattr(primary, "__notes__", [])
    assert any("OSError: rollback denied" in note for note in notes)
    assert any("without proving absence" in note for note in notes)
    assert root.is_dir()


@pytest.mark.parametrize("proof_raises", [False, True])
def test_hostile_rollback_formatting_cannot_mask_capture_primary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    proof_raises: bool,
) -> None:
    root = tmp_path / "allocated"
    primary = KeyboardInterrupt("identity capture interrupted")
    rollback = _HostileFormatError("rollback denied")

    def create_workspace(*, prefix: str) -> str:
        root.mkdir()
        return str(root)

    monkeypatch.setattr(
        workspace_owner,
        "_claim_owned_workspace",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(primary),
    )
    monkeypatch.setattr(
        workspace_owner.os,
        "rmdir",
        lambda _path: (_ for _ in ()).throw(rollback),
    )
    if proof_raises:
        monkeypatch.setattr(
            workspace_owner,
            "repository_path_absent",
            lambda _path: (_ for _ in ()).throw(
                OSError("absence proof unavailable")
            ),
        )

    with pytest.raises(KeyboardInterrupt) as caught:
        workspace_owner.allocate_owned_workspace(
            prefix="owned-test-",
            create_workspace=create_workspace,
        )

    assert caught.value is primary
    notes = getattr(primary, "__notes__", ())
    assert any("_HostileFormatError: rollback denied" in note for note in notes)
    assert root.is_dir()


def test_failed_capture_never_recursively_deletes_a_populated_unclaimed_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "allocated"
    sentinel = root / "must-survive.txt"
    primary = RuntimeError("identity capture failed")

    def create_workspace(*, prefix: str) -> str:
        root.mkdir()
        sentinel.write_text("must survive\n", encoding="utf-8")
        return str(root)

    monkeypatch.setattr(
        workspace_owner,
        "_claim_owned_workspace",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(primary),
    )

    with pytest.raises(RuntimeError) as caught:
        workspace_owner.allocate_owned_workspace(
            prefix="owned-test-",
            create_workspace=create_workspace,
        )

    assert caught.value is primary
    assert sentinel.read_text(encoding="utf-8") == "must survive\n"
    assert any(
        "rollback failed" in note
        for note in getattr(primary, "__notes__", [])
    )


def test_failed_capture_does_not_remove_an_empty_replacement_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "allocated"
    displaced = tmp_path / "displaced"
    primary = RuntimeError("identity capture failed")

    def create_workspace(*, prefix: str) -> str:
        root.mkdir()
        return str(root)

    def replace_then_fail(*_args: object, **_kwargs: object) -> None:
        root.rename(displaced)
        root.mkdir()
        raise primary

    monkeypatch.setattr(
        workspace_owner,
        "_claim_owned_workspace",
        replace_then_fail,
    )

    with pytest.raises(RuntimeError) as caught:
        workspace_owner.allocate_owned_workspace(
            prefix="owned-test-",
            create_workspace=create_workspace,
        )

    assert caught.value is primary
    assert displaced.is_dir()
    assert root.is_dir()
    assert any(
        "root identity changed" in note
        for note in getattr(primary, "__notes__", [])
    )


def test_failed_capture_preserves_primary_when_absence_probe_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "allocated"
    primary = RuntimeError("identity capture failed")
    proof_error = SystemExit("absence probe exited")

    def create_workspace(*, prefix: str) -> str:
        root.mkdir()
        return str(root)

    monkeypatch.setattr(
        workspace_owner,
        "_claim_owned_workspace",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(primary),
    )
    monkeypatch.setattr(
        workspace_owner,
        "repository_path_absent",
        lambda _path: (_ for _ in ()).throw(proof_error),
    )

    with pytest.raises(RuntimeError) as caught:
        workspace_owner.allocate_owned_workspace(
            prefix="owned-test-",
            create_workspace=create_workspace,
        )

    assert caught.value is primary
    assert any(
        "SystemExit: absence probe exited" in note
        for note in getattr(primary, "__notes__", [])
    )


def test_hostile_absence_proof_formatting_cannot_mask_capture_primary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "allocated"
    primary = RuntimeError("identity capture failed")
    proof_error = _HostileFormatError("absence proof denied")

    def create_workspace(*, prefix: str) -> str:
        root.mkdir()
        return str(root)

    monkeypatch.setattr(
        workspace_owner,
        "_claim_owned_workspace",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(primary),
    )
    monkeypatch.setattr(
        workspace_owner,
        "repository_path_absent",
        lambda _path: (_ for _ in ()).throw(proof_error),
    )

    with pytest.raises(RuntimeError) as caught:
        workspace_owner.allocate_owned_workspace(
            prefix="owned-test-",
            create_workspace=create_workspace,
        )

    assert caught.value is primary
    notes = getattr(primary, "__notes__", ())
    assert any("_HostileFormatError: absence proof denied" in note for note in notes)


def test_claimed_workspace_is_string_compatible_and_proves_removal(
    tmp_path: Path,
) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    (root / "payload.txt").write_text("payload\n", encoding="utf-8")
    owned = _claim(root, platform_name="posix")

    assert isinstance(owned, str)
    assert owned == str(root)

    workspace_owner._remove_owned_workspace_tree(
        owned,
        remove_tree=shutil.rmtree,
        path_absent=workspace_owner.repository_path_absent,
    )

    assert not root.exists()
    # A second cleanup is an idempotent success only after a fresh absence
    # observation; no stale success flag is retained in the lease.
    workspace_owner._remove_owned_workspace_tree(
        owned,
        remove_tree=lambda _path: pytest.fail("absent root was removed again"),
        path_absent=workspace_owner.repository_path_absent,
    )


def test_claimed_workspace_binds_removal_to_its_absolute_allocation_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    allocation_parent = tmp_path / "allocation-parent"
    later_cwd = tmp_path / "later-cwd"
    allocated_root = allocation_parent / "owned"
    unrelated_root = later_cwd / "owned"
    allocated_root.mkdir(parents=True)
    unrelated_root.mkdir(parents=True)
    sentinel = unrelated_root / "must-survive.txt"
    sentinel.write_text("must survive\n", encoding="utf-8")
    monkeypatch.chdir(allocation_parent)
    owned = workspace_owner.allocate_owned_workspace(
        prefix="ignored-",
        create_workspace=lambda *, prefix: "owned",
        platform_name="posix",
    )
    monkeypatch.chdir(later_cwd)

    assert os.path.isabs(owned)
    workspace_owner._remove_owned_workspace_tree(
        owned,
        remove_tree=shutil.rmtree,
        path_absent=workspace_owner.repository_path_absent,
    )

    assert not allocated_root.exists()
    assert sentinel.read_text(encoding="utf-8") == "must survive\n"


def test_claimed_workspace_rejects_a_replaced_root_without_deleting_it(
    tmp_path: Path,
) -> None:
    root = tmp_path / "owned"
    displaced = tmp_path / "displaced"
    root.mkdir()
    owned = _claim(root, platform_name="posix")
    root.rename(displaced)
    root.mkdir()
    sentinel = root / "replacement.txt"
    sentinel.write_text("must survive\n", encoding="utf-8")
    attempts: list[str] = []

    with pytest.raises(
        workspace_owner.UnsafeOwnedWorkspace,
        match="root identity changed",
    ):
        workspace_owner._remove_owned_workspace_tree(
            owned,
            remove_tree=lambda path: attempts.append(path),
            path_absent=workspace_owner.repository_path_absent,
        )

    assert attempts == []
    assert sentinel.read_text(encoding="utf-8") == "must survive\n"


def test_claimed_workspace_rejects_a_replaced_parent_without_deleting_it(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "parent"
    root = parent / "owned"
    displaced = tmp_path / "displaced-parent"
    root.mkdir(parents=True)
    owned = _claim(root, platform_name="posix")
    parent.rename(displaced)
    root.mkdir(parents=True)
    sentinel = root / "replacement.txt"
    sentinel.write_text("must survive\n", encoding="utf-8")
    attempts: list[str] = []

    with pytest.raises(
        workspace_owner.UnsafeOwnedWorkspace,
        match="parent identity changed",
    ):
        workspace_owner._remove_owned_workspace_tree(
            owned,
            remove_tree=lambda path: attempts.append(path),
            path_absent=workspace_owner.repository_path_absent,
        )

    assert attempts == []
    assert sentinel.read_text(encoding="utf-8") == "must survive\n"


def test_claimed_workspace_requires_fresh_absence_after_remover_success(
    tmp_path: Path,
) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    owned = _claim(root, platform_name="posix")

    with pytest.raises(
        workspace_owner.OwnedWorkspaceRemovalUnproven,
        match="without proving absence",
    ):
        workspace_owner._remove_owned_workspace_tree(
            owned,
            remove_tree=lambda _path: None,
            path_absent=workspace_owner.repository_path_absent,
        )

    assert root.is_dir()


def test_posix_claim_does_not_attempt_windows_readonly_repair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    target = root / "readonly.txt"
    target.write_text("payload\n", encoding="utf-8")
    owned = _claim(root, platform_name="posix")
    failure = PermissionError(errno.EACCES, "denied", str(target))
    chmod_attempts: list[tuple[str, int]] = []

    monkeypatch.setattr(
        workspace_owner.os,
        "chmod",
        lambda path, mode: chmod_attempts.append((path, mode)),
    )

    with pytest.raises(PermissionError) as caught:
        workspace_owner._remove_owned_workspace_tree(
            owned,
            remove_tree=lambda _path: (_ for _ in ()).throw(failure),
            path_absent=workspace_owner.repository_path_absent,
        )

    assert caught.value is failure
    assert chmod_attempts == []


def test_plain_path_never_receives_owned_windows_repair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "arbitrary"
    root.mkdir()
    target = root / "readonly.txt"
    target.write_text("payload\n", encoding="utf-8")
    failure = PermissionError(errno.EACCES, "denied", str(target))
    chmod_attempts: list[tuple[str, int]] = []

    monkeypatch.setattr(
        workspace_owner.os,
        "chmod",
        lambda path, mode: chmod_attempts.append((path, mode)),
    )

    with pytest.raises(PermissionError) as caught:
        workspace_owner.cleanup_repo_workspaces(
            (("arbitrary path", str(root)),),
            primary=None,
            remove_tree=lambda _path: (_ for _ in ()).throw(failure),
        )

    assert caught.value is failure
    assert chmod_attempts == []
    assert root.is_dir()


def test_windows_retry_rejects_an_out_of_root_permission_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("must survive\n", encoding="utf-8")
    owned = _claim(root, platform_name="nt")
    failure = PermissionError(errno.EACCES, "denied", str(outside))
    chmod_attempts: list[tuple[str, int]] = []

    monkeypatch.setattr(
        workspace_owner.os,
        "chmod",
        lambda path, mode: chmod_attempts.append((path, mode)),
    )

    with pytest.raises(
        workspace_owner.UnsafeOwnedWorkspace,
        match="escaped",
    ):
        workspace_owner._remove_owned_workspace_tree(
            owned,
            remove_tree=lambda _path: (_ for _ in ()).throw(failure),
            path_absent=workspace_owner.repository_path_absent,
        )

    assert chmod_attempts == []
    assert outside.read_text(encoding="utf-8") == "must survive\n"


def test_windows_retry_refuses_a_hardlink_to_an_external_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("must survive\n", encoding="utf-8")
    linked = root / "linked.txt"
    os.link(outside, linked)
    assert os.lstat(linked).st_nlink == 2
    owned = _claim(root, platform_name="nt")
    failure = PermissionError(errno.EACCES, "denied", str(linked))
    chmod_attempts: list[tuple[str, int]] = []

    monkeypatch.setattr(
        workspace_owner.os,
        "chmod",
        lambda path, mode: chmod_attempts.append((path, mode)),
    )

    with pytest.raises(
        workspace_owner.UnsafeOwnedWorkspace,
        match="multiply linked",
    ):
        workspace_owner._remove_owned_workspace_tree(
            owned,
            remove_tree=lambda _path: (_ for _ in ()).throw(failure),
            path_absent=workspace_owner.repository_path_absent,
        )

    assert chmod_attempts == []
    assert outside.read_text(encoding="utf-8") == "must survive\n"


def test_windows_retry_does_not_chmod_a_writable_permission_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    target = root / "writable.txt"
    target.write_text("payload\n", encoding="utf-8")
    owned = _claim(root, platform_name="nt")
    failure = PermissionError(errno.EACCES, "ACL or sharing denial", str(target))
    attempts: list[str] = []
    chmod_attempts: list[tuple[str, int]] = []

    def fail(path: str) -> None:
        attempts.append(path)
        raise failure

    monkeypatch.setattr(
        workspace_owner.os,
        "chmod",
        lambda path, mode: chmod_attempts.append((path, mode)),
    )

    with pytest.raises(PermissionError) as caught:
        workspace_owner._remove_owned_workspace_tree(
            owned,
            remove_tree=fail,
            path_absent=workspace_owner.repository_path_absent,
        )

    assert caught.value is failure
    assert attempts == [str(root)]
    assert chmod_attempts == []


def test_windows_retry_does_not_loop_on_the_same_failed_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    target = root / "readonly.txt"
    target.write_text("payload\n", encoding="utf-8")
    real_chmod = os.chmod
    real_chmod(target, stat.S_IREAD)
    owned = _claim(root, platform_name="nt")
    failure = PermissionError(errno.EACCES, "denied", str(target))
    attempts: list[str] = []
    chmod_attempts: list[tuple[str, int]] = []

    def always_fail(path: str) -> None:
        attempts.append(path)
        raise failure

    def record_chmod(path: str, mode: int) -> None:
        chmod_attempts.append((path, mode))
        real_chmod(path, mode)

    monkeypatch.setattr(workspace_owner.os, "chmod", record_chmod)

    with pytest.raises(PermissionError) as caught:
        workspace_owner._remove_owned_workspace_tree(
            owned,
            remove_tree=always_fail,
            path_absent=workspace_owner.repository_path_absent,
        )

    assert caught.value is failure
    assert attempts == [str(root), str(root)]
    assert [path for path, _mode in chmod_attempts] == [str(target)]


def test_windows_readonly_repairs_are_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    first = root / "first.txt"
    second = root / "second.txt"
    first.write_text("first\n", encoding="utf-8")
    second.write_text("second\n", encoding="utf-8")
    real_chmod = os.chmod
    real_chmod(first, stat.S_IREAD)
    real_chmod(second, stat.S_IREAD)
    owned = _claim(root, platform_name="nt")
    failures = iter(
        (
            PermissionError(errno.EACCES, "denied", str(first)),
            PermissionError(errno.EACCES, "denied", str(second)),
        )
    )
    attempts: list[str] = []
    chmod_attempts: list[tuple[str, int]] = []

    def fail_next(path: str) -> None:
        attempts.append(path)
        raise next(failures)

    monkeypatch.setattr(workspace_owner, "_MAX_WINDOWS_READONLY_REPAIRS", 1)
    def record_chmod(path: str, mode: int) -> None:
        chmod_attempts.append((path, mode))
        real_chmod(path, mode)

    monkeypatch.setattr(workspace_owner.os, "chmod", record_chmod)

    with pytest.raises(
        workspace_owner.UnsafeOwnedWorkspace,
        match="bounded",
    ):
        workspace_owner._remove_owned_workspace_tree(
            owned,
            remove_tree=fail_next,
            path_absent=workspace_owner.repository_path_absent,
        )

    assert attempts == [str(root), str(root)]
    assert [path for path, _mode in chmod_attempts] == [str(first)]
    real_chmod(second, stat.S_IWRITE)


@pytest.mark.skipif(os.name != "nt", reason="requires Windows READONLY semantics")
@pytest.mark.parametrize("readonly_directory", [False, True])
def test_windows_claimed_workspace_removes_readonly_entries(
    tmp_path: Path,
    readonly_directory: bool,
) -> None:
    root = tmp_path / "owned"
    nested = root / "nested"
    nested.mkdir(parents=True)
    target = nested / "readonly.txt"
    target.write_text("payload\n", encoding="utf-8")
    os.chmod(target, stat.S_IREAD)
    if readonly_directory:
        os.chmod(nested, stat.S_IREAD)
    owned = _claim(root)

    workspace_owner.cleanup_repo_workspaces(
        (("candidate workspace", owned),),
        primary=None,
    )

    assert not root.exists()


@pytest.mark.skipif(os.name != "nt", reason="requires a real Windows junction")
def test_windows_retry_refuses_a_junction_component(
    tmp_path: Path,
) -> None:
    root = tmp_path / "owned"
    external = tmp_path / "external"
    root.mkdir()
    external.mkdir()
    sentinel = external / "sentinel.txt"
    sentinel.write_text("must survive\n", encoding="utf-8")
    junction = root / "linked"
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
    owned = _claim(root)
    failure = PermissionError(
        errno.EACCES,
        "denied",
        str(junction / "sentinel.txt"),
    )

    with pytest.raises(
        workspace_owner.UnsafeOwnedWorkspace,
        match="reparse",
    ):
        workspace_owner._remove_owned_workspace_tree(
            owned,
            remove_tree=lambda _path: (_ for _ in ()).throw(failure),
            path_absent=workspace_owner.repository_path_absent,
        )

    assert sentinel.read_text(encoding="utf-8") == "must survive\n"


@pytest.mark.skipif(os.name != "nt", reason="requires Windows READONLY semantics")
def test_repo_verifier_emits_a_verdict_and_removes_readonly_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    tests_dir = source / "tests"
    tests_dir.mkdir(parents=True)
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    tests_dir.joinpath("test_readonly.py").write_text(
        """
import os
import stat
from pathlib import Path


def test_candidate_can_create_a_readonly_git_object():
    target = Path(".git") / "objects" / "01" / "readonly"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("candidate residue\\n", encoding="utf-8")
    os.chmod(target, stat.S_IREAD)
""".lstrip(),
        encoding="utf-8",
    )
    original_mkdtemp = repo_verifier.tempfile.mkdtemp
    allocations: list[str] = []

    def recording_mkdtemp(*, prefix: str) -> str:
        path = original_mkdtemp(prefix=prefix)
        allocations.append(path)
        return path

    monkeypatch.setattr(repo_verifier.tempfile, "mkdtemp", recording_mkdtemp)
    verifier = RepoVerifier(
        timeout=60,
        mem_limit_mb=0,
        test_command=[sys.executable, "-m", "pytest", "-q"],
    )

    result = verifier.verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n",
        {"repo_path": str(source)},
    )

    assert result.passed is True
    assert allocations
    assert all(not os.path.lexists(path) for path in allocations)
