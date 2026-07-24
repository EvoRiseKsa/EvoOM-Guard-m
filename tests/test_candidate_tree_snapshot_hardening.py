"""Security contracts for base/head candidate-tree snapshot intake.

The base/head scanner must not follow Windows reparse directories, and every
regular-file read/compare must remain bound to the exact object classified by
the preceding ``lstat`` snapshot.
"""

from __future__ import annotations

import importlib
import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from evoom_guard.workspace import candidate_tree

guard_module = importlib.import_module("evoom_guard.guard")


def _replace_with_hardlink(path: Path, source: Path) -> None:
    path.unlink()
    os.link(source, path)


def test_windows_reparse_attribute_detection_is_python_310_compatible() -> None:
    """Detection must not depend only on ``os.path.isjunction`` (3.12+)."""

    info = SimpleNamespace(st_file_attributes=0x400)

    assert guard_module._is_windows_reparse(
        "junction",
        info,
        platform_name="nt",
        junction_probe=lambda _path: False,
    )
    assert not guard_module._is_windows_reparse(
        "ordinary",
        SimpleNamespace(st_file_attributes=0),
        platform_name="nt",
        junction_probe=lambda _path: False,
    )
    assert not guard_module._is_windows_reparse(
        "posix",
        info,
        platform_name="posix",
        junction_probe=lambda _path: True,
    )


def test_tree_entry_rejects_a_reparse_directory_before_walk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Portable classification coverage for the Windows-only path kind."""

    fake_info = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o755,
        st_size=0,
        st_dev=1,
        st_ino=2,
        st_nlink=1,
        st_mtime_ns=3,
        st_ctime_ns=4,
    )
    monkeypatch.setattr(guard_module.os, "lstat", lambda _path: fake_info)
    monkeypatch.setattr(
        guard_module,
        "_is_windows_reparse",
        lambda _path, _info: True,
    )

    entry = guard_module._tree_entry("junction")

    assert entry.kind == "special"
    assert entry.problem == "path is a Windows reparse point"


def test_blocks_from_dirs_rejects_a_non_directory_root_before_walk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def root_entry(path: str) -> Any:
        if path == "base":
            return guard_module._TreeEntry(path, "directory", 0o755, None)
        return guard_module._TreeEntry(
            path,
            "special",
            0o755,
            None,
            problem="path is a Windows reparse point",
        )

    monkeypatch.setattr(guard_module, "_tree_entry", root_entry)
    monkeypatch.setattr(
        guard_module,
        "_walk_tree_entries",
        lambda _root: pytest.fail("invalid root reached os.walk"),
    )

    with pytest.raises(
        guard_module._UnverifiableChangedPathsError,
        match=r"<head-root>: path is a Windows reparse point",
    ):
        guard_module.blocks_from_dirs("base", "head")


@pytest.mark.skipif(os.name != "nt", reason="requires a real Windows junction")
def test_walk_tree_does_not_follow_a_real_windows_junction(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "external.txt").write_text("outside", encoding="utf-8")
    junction = root / "junction"
    completed = subprocess.run(
        [
            "cmd.exe",
            "/d",
            "/c",
            "mklink",
            "/J",
            str(junction),
            str(outside),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        pytest.skip(f"could not create a Windows junction: {completed.stderr}")
    try:
        walked = guard_module._walk_tree_entries(str(root))
    finally:
        os.rmdir(junction)

    assert walked["junction"].kind == "special"
    assert walked["junction"].problem == "path is a Windows reparse point"
    assert "junction/external.txt" not in walked


def test_changed_text_rejects_hardlink_replacement_after_lstat(
    tmp_path: Path,
) -> None:
    target = tmp_path / "candidate.txt"
    replacement = tmp_path / "replacement.txt"
    target.write_text("SAFE", encoding="utf-8")
    replacement.write_text("EVIL", encoding="utf-8")
    entry = guard_module._tree_entry(str(target))
    _replace_with_hardlink(target, replacement)

    with pytest.raises(OSError, match="identity changed after it was classified"):
        guard_module._read_changed_text(entry, 100)


def test_posix_open_flags_require_no_follow_and_non_block() -> None:
    with pytest.raises(
        OSError,
        match="lacks no-follow/non-blocking file-open support",
    ):
        guard_module._regular_snapshot_open_flags(
            platform_name="posix",
            flag_provider=lambda _name: None,
        )

    expected = {"O_NOFOLLOW": 0x01, "O_NONBLOCK": 0x02}
    flags = guard_module._regular_snapshot_open_flags(
        platform_name="posix",
        flag_provider=expected.get,
    )

    assert flags & expected["O_NOFOLLOW"]
    assert flags & expected["O_NONBLOCK"]


def test_windows_open_dispatch_uses_write_exclusive_provider(
    tmp_path: Path,
) -> None:
    target = tmp_path / "candidate.txt"
    target.write_bytes(b"stable")
    entry = guard_module._tree_entry(str(target))
    calls: list[tuple[str, int]] = []

    def portable_windows_open(path: str, flags: int) -> int:
        calls.append((path, flags))
        return os.open(path, flags)

    descriptor = candidate_tree.open_regular_snapshot(
        entry,
        is_windows_reparse=guard_module._is_windows_reparse,
        verify_regular_snapshot_provider=(
            lambda candidate, observed, problem, path_observation: (
                guard_module._verify_regular_snapshot(
                    candidate,
                    observed,
                    problem=problem,
                    path_observation=path_observation,
                )
            )
        ),
        open_flags=guard_module._regular_snapshot_open_flags,
        platform_name="nt",
        windows_open_provider=portable_windows_open,
    )
    try:
        assert os.read(descriptor, 6) == b"stable"
    finally:
        os.close(descriptor)

    assert calls == [(str(target), guard_module._regular_snapshot_open_flags())]


def test_windows_native_open_contract_denies_write_delete_and_follows_ownership() -> None:
    create_calls: list[tuple[Any, ...]] = []
    close_calls: list[int] = []
    conversion_calls: list[tuple[int, int]] = []

    def create_file(*args: Any) -> int:
        create_calls.append(args)
        return 123

    def open_osfhandle(handle: int, flags: int) -> int:
        conversion_calls.append((handle, flags))
        return 456

    descriptor = candidate_tree._open_windows_regular_snapshot_handle(
        "candidate.txt",
        os.O_RDONLY | getattr(os, "O_BINARY", 0),
        create_file=create_file,
        close_handle=lambda handle: close_calls.append(handle),
        open_osfhandle=open_osfhandle,
        get_last_error=lambda: 5,
        win_error=lambda code: OSError(code, "win32"),
        invalid_handle_value=(1 << 64) - 1,
    )

    assert descriptor == 456
    assert create_calls == [
        (
            "candidate.txt",
            0x80000000,
            0x00000001,
            None,
            3,
            0x00200000 | 0x08000000,
            None,
        )
    ]
    assert conversion_calls == [
        (
            123,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOINHERIT", 0),
        )
    ]
    assert close_calls == []


def test_windows_native_open_rejects_pointer_sized_invalid_handle() -> None:
    invalid_handle = (1 << 64) - 1
    close_calls: list[int] = []

    with pytest.raises(OSError, match="win32"):
        candidate_tree._open_windows_regular_snapshot_handle(
            "candidate.txt",
            os.O_RDONLY,
            create_file=lambda *_args: invalid_handle,
            close_handle=lambda handle: close_calls.append(handle),
            open_osfhandle=lambda *_args: pytest.fail(
                "invalid handle reached descriptor conversion"
            ),
            get_last_error=lambda: 32,
            win_error=lambda code: OSError(code, "win32"),
            invalid_handle_value=invalid_handle,
        )

    assert close_calls == []


def test_windows_native_handle_closes_only_when_descriptor_conversion_fails() -> None:
    close_calls: list[int] = []

    with pytest.raises(RuntimeError, match="conversion failed"):
        candidate_tree._open_windows_regular_snapshot_handle(
            "candidate.txt",
            os.O_RDONLY,
            create_file=lambda *_args: 123,
            close_handle=lambda handle: close_calls.append(handle),
            open_osfhandle=lambda *_args: (_ for _ in ()).throw(
                RuntimeError("conversion failed")
            ),
            get_last_error=lambda: 0,
            win_error=lambda code: OSError(code, "win32"),
            invalid_handle_value=(1 << 64) - 1,
        )

    assert close_calls == [123]


@pytest.mark.skipif(
    os.name != "nt",
    reason="requires Windows CreateFileW sharing enforcement",
)
def test_windows_existing_writer_causes_candidate_read_to_fail_closed(
    tmp_path: Path,
) -> None:
    target = tmp_path / "candidate.txt"
    target.write_bytes(b"SAFE")
    entry = guard_module._tree_entry(str(target))

    with target.open("r+b"):
        with pytest.raises(OSError):
            guard_module._read_changed_text(entry, 100)


@pytest.mark.skipif(
    os.name != "nt",
    reason="requires Windows CreateFileW sharing enforcement",
)
def test_windows_same_size_rewrite_with_restored_mtime_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "candidate.txt"
    target.write_bytes(b"SAFE")
    captured_times = target.stat()
    entry = guard_module._tree_entry(str(target))
    original_read = guard_module._read_fd_bounded

    def read_then_attempt_rewrite(descriptor: int, maximum: int) -> bytes:
        data = original_read(descriptor, maximum)
        target.write_bytes(b"EVIL")
        os.utime(
            target,
            ns=(captured_times.st_atime_ns, captured_times.st_mtime_ns),
        )
        return data

    monkeypatch.setattr(
        guard_module,
        "_read_fd_bounded",
        read_then_attempt_rewrite,
    )

    with pytest.raises(OSError):
        guard_module._read_changed_text(entry, 100)

    assert target.read_bytes() == b"SAFE"


@pytest.mark.skipif(
    os.name != "nt",
    reason="requires Windows CreateFileW delete-share enforcement",
)
@pytest.mark.parametrize("operation", ["delete", "rename"])
def test_windows_delete_or_rename_during_read_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    target = tmp_path / "candidate.txt"
    moved = tmp_path / "moved.txt"
    target.write_bytes(b"SAFE")
    entry = guard_module._tree_entry(str(target))
    original_read = guard_module._read_fd_bounded

    def read_then_attempt_path_mutation(
        descriptor: int,
        maximum: int,
    ) -> bytes:
        data = original_read(descriptor, maximum)
        if operation == "delete":
            target.unlink()
        else:
            target.rename(moved)
        return data

    monkeypatch.setattr(
        guard_module,
        "_read_fd_bounded",
        read_then_attempt_path_mutation,
    )

    with pytest.raises(OSError):
        guard_module._read_changed_text(entry, 100)

    assert target.read_bytes() == b"SAFE"
    assert not moved.exists()


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "mkfifo"),
    reason="requires a POSIX FIFO",
)
def test_regular_to_fifo_swap_is_non_blocking_and_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "candidate.txt"
    target.write_bytes(b"regular")
    entry = guard_module._tree_entry(str(target))
    real_open = guard_module.os.open
    swapped = False

    def swap_to_fifo(path: str, flags: int, *args: Any, **kwargs: Any) -> int:
        nonlocal swapped
        if not swapped and os.fspath(path) == str(target):
            swapped = True
            assert flags & os.O_NOFOLLOW
            assert flags & os.O_NONBLOCK
            target.unlink()
            os.mkfifo(target)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(guard_module.os, "open", swap_to_fifo)

    with pytest.raises(OSError, match="identity changed after it was classified"):
        guard_module._read_changed_text(entry, 100)


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX O_NOFOLLOW")
def test_regular_to_symlink_swap_is_rejected_at_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "candidate.txt"
    replacement = tmp_path / "replacement.txt"
    target.write_bytes(b"regular")
    replacement.write_bytes(b"outside")
    entry = guard_module._tree_entry(str(target))
    real_open = guard_module.os.open
    swapped = False

    def swap_to_symlink(path: str, flags: int, *args: Any, **kwargs: Any) -> int:
        nonlocal swapped
        if not swapped and os.fspath(path) == str(target):
            swapped = True
            assert flags & os.O_NOFOLLOW
            target.unlink()
            target.symlink_to(replacement)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(guard_module.os, "open", swap_to_symlink)

    with pytest.raises(OSError):
        guard_module._read_changed_text(entry, 100)
    assert swapped


def test_equal_file_comparison_rejects_hardlink_replacement_after_lstat(
    tmp_path: Path,
) -> None:
    base_path = tmp_path / "base.txt"
    head_path = tmp_path / "head.txt"
    replacement = tmp_path / "replacement.txt"
    base_path.write_text("SAME", encoding="utf-8")
    head_path.write_text("SAME", encoding="utf-8")
    replacement.write_text("EVIL", encoding="utf-8")
    base_entry = guard_module._tree_entry(str(base_path))
    head_entry = guard_module._tree_entry(str(head_path))
    _replace_with_hardlink(head_path, replacement)

    changed, problem = guard_module._entries_changed(base_entry, head_entry)

    assert changed is True
    assert problem is not None
    assert "identity changed after it was classified" in problem


def test_changed_text_rejects_metadata_drift_during_bounded_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "candidate.txt"
    target.write_text("payload", encoding="utf-8")
    entry = guard_module._tree_entry(str(target))
    original_read = guard_module._read_fd_bounded

    def read_then_drift(fd: int, maximum: int) -> bytes:
        data = original_read(fd, maximum)
        current = target.stat()
        os.utime(
            target,
            ns=(current.st_atime_ns, current.st_mtime_ns + 1_000_000_000),
        )
        return data

    monkeypatch.setattr(guard_module, "_read_fd_bounded", read_then_drift)

    with pytest.raises(OSError, match="changed while it was being read"):
        guard_module._read_changed_text(entry, 100)


def test_stable_snapshot_read_and_comparison_remain_bounded_and_exact(
    tmp_path: Path,
) -> None:
    base_path = tmp_path / "base.txt"
    head_path = tmp_path / "head.txt"
    base_path.write_bytes(b"stable\n")
    head_path.write_bytes(b"stable\n")
    base_entry = guard_module._tree_entry(str(base_path))
    head_entry = guard_module._tree_entry(str(head_path))

    assert guard_module._read_changed_text(head_entry, 7) == "stable\n"
    assert guard_module._entries_changed(base_entry, head_entry) == (False, None)


def test_snapshot_identity_binds_type_mode_size_and_object() -> None:
    first = SimpleNamespace(
        st_dev=1,
        st_ino=2,
        st_mode=stat.S_IFREG | 0o644,
        st_nlink=1,
        st_size=3,
        st_mtime_ns=4,
        st_ctime_ns=5,
    )
    changed_mode = SimpleNamespace(**{**vars(first), "st_mode": stat.S_IFREG | 0o600})
    changed_size = SimpleNamespace(**{**vars(first), "st_size": 4})
    changed_object = SimpleNamespace(**{**vars(first), "st_ino": 9})

    identity = guard_module._stat_identity(first)

    assert identity != guard_module._stat_identity(changed_mode)
    assert identity != guard_module._stat_identity(changed_size)
    assert identity != guard_module._stat_identity(changed_object)


def test_snapshot_verifier_rejects_object_drift_independently_of_times() -> None:
    first = SimpleNamespace(
        st_dev=1,
        st_ino=2,
        st_mode=stat.S_IFREG | 0o644,
        st_nlink=1,
        st_size=3,
        st_mtime_ns=4,
        st_ctime_ns=5,
    )
    replacement = SimpleNamespace(**{**vars(first), "st_ino": 9})
    entry = guard_module._TreeEntry(
        "candidate.txt",
        "regular",
        0o644,
        3,
        identity=guard_module._stat_identity(first),
        path_times=guard_module._stat_path_times(first),
    )

    with pytest.raises(OSError, match="object drift"):
        guard_module._verify_regular_snapshot(
            entry,
            replacement,
            problem="object drift",
            path_observation=False,
        )
