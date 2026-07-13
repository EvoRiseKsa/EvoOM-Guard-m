# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Canonical full-runtime identity and race-safe file reads."""

from __future__ import annotations

import os

import pytest

import evoom_guard.runtime_identity as runtime_identity
from evoom_guard.runtime_identity import (
    RUNTIME_DIGEST_FORMAT,
    RuntimeIdentityError,
    capture_runtime_identity,
    verify_runtime_identity,
)


def test_identity_is_deterministic_and_binds_root_directories_and_bytes(tmp_path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "data.bin").write_bytes(b"abc")

    first = capture_runtime_identity(str(tmp_path))
    second = capture_runtime_identity(str(tmp_path))

    assert first.sha256 == second.sha256
    assert first.digest_format == RUNTIME_DIGEST_FORMAT
    assert first.entries == 3
    assert first.regular_bytes == 3
    assert [record.path for record in first.records] == [".", "pkg", "pkg/data.bin"]


def test_content_addition_and_deletion_have_deterministic_change_paths(tmp_path) -> None:
    first_file = tmp_path / "z.txt"
    first_file.write_text("before", encoding="utf-8")
    expected = capture_runtime_identity(str(tmp_path))

    first_file.unlink()
    (tmp_path / "a.txt").write_text("after", encoding="utf-8")
    _observed, changes = verify_runtime_identity(str(tmp_path), expected)

    assert changes == ["a.txt", "z.txt"]


def test_runtime_change_details_are_memory_bounded(tmp_path, monkeypatch) -> None:
    (tmp_path / "a.txt").write_text("before-a", encoding="utf-8")
    (tmp_path / "b.txt").write_text("before-b", encoding="utf-8")
    expected = capture_runtime_identity(str(tmp_path))
    (tmp_path / "a.txt").write_text("after-a", encoding="utf-8")
    (tmp_path / "b.txt").write_text("after-b", encoding="utf-8")
    monkeypatch.setattr(runtime_identity, "RUNTIME_IDENTITY_MAX_REPORTED_CHANGES", 1)

    _observed, changes = verify_runtime_identity(str(tmp_path), expected)

    assert changes == ["a.txt", "<runtime-change-list-truncated>"]


@pytest.mark.skipif(not hasattr(os, "link"), reason="hardlinks unavailable")
def test_pnpm_style_hardlinks_are_allowed_and_content_drift_is_seen(tmp_path) -> None:
    store = tmp_path / "store.js"
    linked = tmp_path / "package.js"
    store.write_text("module.exports = 1;\n", encoding="utf-8")
    try:
        os.link(store, linked)
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")

    expected = capture_runtime_identity(str(tmp_path))
    linked.write_text("module.exports = 2;\n", encoding="utf-8")
    _observed, changes = verify_runtime_identity(str(tmp_path), expected)

    assert changes == ["package.js", "store.js"]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_symlink_target_is_bound_without_following_it(tmp_path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("inside", encoding="utf-8")
    (tmp_path / "other.txt").write_text("other", encoding="utf-8")
    link = tmp_path / "runtime-link"
    try:
        os.symlink("target.txt", link)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    expected = capture_runtime_identity(str(tmp_path))

    link.unlink()
    os.symlink("other.txt", link)
    _observed, changes = verify_runtime_identity(str(tmp_path), expected)
    assert changes == ["runtime-link"]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
@pytest.mark.parametrize("target_kind", ("file", "directory"))
def test_relative_symlink_escaping_runtime_root_is_rejected(
    tmp_path, target_kind: str
) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    outside = tmp_path / "outside"
    if target_kind == "directory":
        outside.mkdir()
    else:
        outside.write_text("outside", encoding="utf-8")
    try:
        os.symlink("../outside", root / "escape", target_is_directory=target_kind == "directory")
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(RuntimeIdentityError, match="escapes the candidate tree"):
        capture_runtime_identity(str(root))


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_absolute_symlink_is_rejected_even_when_it_points_inside(tmp_path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("inside", encoding="utf-8")
    try:
        os.symlink(str(target.resolve()), tmp_path / "absolute-link")
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(RuntimeIdentityError, match="absolute runtime symlink"):
        capture_runtime_identity(str(tmp_path))


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_dangling_internal_symlink_fails_closed(tmp_path) -> None:
    try:
        os.symlink("missing.txt", tmp_path / "dangling")
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(RuntimeIdentityError, match="dangling runtime symlink"):
        capture_runtime_identity(str(tmp_path))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable")
def test_special_runtime_entry_is_rejected(tmp_path) -> None:
    os.mkfifo(tmp_path / "runtime-pipe")
    with pytest.raises(RuntimeIdentityError, match="unsupported special runtime entry"):
        capture_runtime_identity(str(tmp_path))


def test_sparse_file_is_rejected_before_content_read(tmp_path) -> None:
    sparse = tmp_path / "sparse.bin"
    with sparse.open("wb") as stream:
        stream.seek(4096)
        stream.write(b"x")

    with pytest.raises(RuntimeIdentityError, match="per-file budget"):
        capture_runtime_identity(str(tmp_path), max_file_bytes=4096)


def test_entry_and_logical_byte_budgets_fail_closed(tmp_path) -> None:
    (tmp_path / "one.bin").write_bytes(b"1234")
    (tmp_path / "two.bin").write_bytes(b"5678")

    with pytest.raises(RuntimeIdentityError, match="entry budget"):
        capture_runtime_identity(str(tmp_path), max_entries=2)
    with pytest.raises(RuntimeIdentityError, match="logical-byte budget"):
        capture_runtime_identity(str(tmp_path), max_logical_bytes=7)


def test_deadline_budget_fails_closed(tmp_path, monkeypatch) -> None:
    ticks = iter((10.0, 12.0))
    monkeypatch.setattr(runtime_identity.time, "perf_counter", lambda: next(ticks))
    with pytest.raises(RuntimeIdentityError, match="deadline exceeded"):
        capture_runtime_identity(str(tmp_path), deadline_seconds=1.0)


def test_deep_tree_is_scanned_iteratively(tmp_path) -> None:
    current = tmp_path
    # Exceed Python's default recursion limit on platforms whose path limit
    # permits it; path-limited platforms skip the fixture explicitly below.
    depth = 1_100
    try:
        for _index in range(depth):
            current /= "d"
            current.mkdir()
    except OSError as exc:
        pytest.skip(f"filesystem path limit is too small for deep-tree fixture: {exc}")
    (current / "leaf.txt").write_text("leaf", encoding="utf-8")

    identity = capture_runtime_identity(str(tmp_path))
    assert identity.entries == depth + 2


@pytest.mark.skipif(
    not hasattr(os, "mkfifo") or not hasattr(os, "O_NONBLOCK"),
    reason="POSIX FIFO/O_NONBLOCK unavailable",
)
def test_fifo_swap_does_not_block_and_fails_closed(tmp_path, monkeypatch) -> None:
    target = tmp_path / "runtime.bin"
    target.write_bytes(b"regular")
    real_open = runtime_identity.os.open
    swapped = False

    def swap_to_fifo(path, flags, *args, **kwargs):
        nonlocal swapped
        if not swapped and os.path.basename(os.fspath(path)) == target.name:
            swapped = True
            target.unlink()
            os.mkfifo(target)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(runtime_identity.os, "open", swap_to_fifo)
    with pytest.raises(RuntimeIdentityError, match="changed while opening"):
        capture_runtime_identity(str(tmp_path))


def test_unreadable_runtime_file_fails_closed(tmp_path, monkeypatch) -> None:
    target = tmp_path / "secret.bin"
    target.write_bytes(b"secret")
    real_open = runtime_identity.os.open

    def deny(path, flags, *args, **kwargs):
        if os.path.basename(os.fspath(path)) == target.name:
            raise PermissionError("denied by test")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(runtime_identity.os, "open", deny)
    with pytest.raises(RuntimeIdentityError, match="cannot open runtime file"):
        capture_runtime_identity(str(tmp_path))


def test_file_replacement_between_lstat_and_open_is_rejected(tmp_path, monkeypatch) -> None:
    target = tmp_path / "runtime.bin"
    replacement = tmp_path / "replacement.bin"
    target.write_bytes(b"accepted")
    replacement.write_bytes(b"replacement")
    real_open = runtime_identity.os.open
    replaced = False

    def swap_then_open(path, flags, *args, **kwargs):
        nonlocal replaced
        if not replaced and os.path.basename(os.fspath(path)) == target.name:
            replaced = True
            os.replace(replacement, target)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(runtime_identity.os, "open", swap_then_open)
    with pytest.raises(RuntimeIdentityError, match="changed while opening"):
        capture_runtime_identity(str(tmp_path))


@pytest.mark.skipif(
    not runtime_identity._DESCRIPTOR_SCAN_SUPPORTED,
    reason="descriptor-relative directory traversal is POSIX-only",
)
def test_directory_swap_to_symlink_cannot_redirect_descriptor_scan(
    tmp_path, monkeypatch
) -> None:
    root = tmp_path / "runtime"
    judged = root / "judged"
    outside = tmp_path / "outside"
    judged.mkdir(parents=True)
    outside.mkdir()
    (judged / "inside.txt").write_text("inside", encoding="utf-8")
    secret = outside / "secret.txt"
    secret.write_text("controlled-secret", encoding="utf-8")
    original = root / "judged-original"
    real_open = runtime_identity.os.open
    swapped = False

    def swap_then_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if path == "judged" and kwargs.get("dir_fd") is not None and not swapped:
            judged.rename(original)
            try:
                judged.symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                original.rename(judged)
                pytest.skip(f"directory symlinks unavailable: {exc}")
            swapped = True
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(runtime_identity.os, "open", swap_then_open)
    with pytest.raises(RuntimeIdentityError):
        capture_runtime_identity(str(root))

    assert swapped
    assert secret.read_text(encoding="utf-8") == "controlled-secret"


@pytest.mark.skipif(os.name != "nt", reason="Windows best-effort traversal only")
def test_windows_best_effort_rejects_child_junction(tmp_path, monkeypatch) -> None:
    child = tmp_path / "junction"
    child.mkdir()
    real_isjunction = getattr(os.path, "isjunction", lambda _path: False)

    def controlled_junction(path) -> bool:
        if os.path.abspath(os.fspath(path)) == os.path.abspath(child):
            return True
        return real_isjunction(path)

    monkeypatch.setattr(runtime_identity.os.path, "isjunction", controlled_junction)
    with pytest.raises(RuntimeIdentityError, match="junction"):
        capture_runtime_identity(str(tmp_path))


def test_mode_race_between_lstat_and_open_fails_closed(tmp_path, monkeypatch) -> None:
    target = tmp_path / "runtime.bin"
    target.write_bytes(b"stable")
    os.chmod(target, 0o600)
    real_open = runtime_identity.os.open
    changed = False

    def chmod_then_open(path, flags, *args, **kwargs):
        nonlocal changed
        if os.path.basename(os.fspath(path)) == target.name and not changed:
            os.chmod(target, 0o400)
            changed = True
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(runtime_identity.os, "open", chmod_then_open)
    with pytest.raises(RuntimeIdentityError, match="changed while opening"):
        capture_runtime_identity(str(tmp_path))

    assert changed


def test_canonical_path_byte_budget_fails_before_unbounded_records(tmp_path) -> None:
    name = "long-runtime-entry.bin"
    (tmp_path / name).write_bytes(b"x")
    root_bytes = len(os.fsencode("."))
    child_bytes = len(os.fsencode(name))

    with pytest.raises(RuntimeIdentityError, match="path-byte budget"):
        capture_runtime_identity(
            str(tmp_path), max_path_bytes=root_bytes + child_bytes - 1
        )


def test_memory_error_is_converted_to_runtime_identity_error(
    tmp_path, monkeypatch
) -> None:
    (tmp_path / "entry.txt").write_text("entry", encoding="utf-8")
    real_fsencode = runtime_identity.os.fsencode

    def fail_entry_encoding(path):
        if path == "entry.txt":
            raise MemoryError("controlled allocation failure")
        return real_fsencode(path)

    monkeypatch.setattr(runtime_identity.os, "fsencode", fail_entry_encoding)
    with pytest.raises(RuntimeIdentityError, match="memory budget exhausted"):
        capture_runtime_identity(str(tmp_path))
