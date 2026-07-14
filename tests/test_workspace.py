# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Direct branch coverage for the workspace containment primitives.

``workspace.py`` was previously exercised only indirectly through the guard
flow, leaving its rejection branches — unsafe paths, reparse parents,
non-regular targets, identity drift — mostly uncovered. These tests drive the
public API (``write_text_within_root``, ``read_text_within_root``,
``delete_path_within_root``) straight at those branches.

The POSIX descriptor-relative path and the Windows best-effort path share this
public contract, so the same assertions bind both; the CI Linux job covers the
``openat``/``unlinkat`` branches that a single-OS run cannot.
"""

from __future__ import annotations

import os
import tempfile

import pytest

from evoom_guard.workspace import (
    UnsafeWorkspacePath,
    _is_safe_relative_path,
    _is_within,
    delete_path_within_root,
    read_text_within_root,
    write_text_within_root,
)


@pytest.fixture()
def root(tmp_path):
    return str(tmp_path)


def _can_symlink(directory: str) -> bool:
    probe = os.path.join(directory, ".symlink-probe")
    try:
        os.symlink(directory, probe, target_is_directory=True)
    except (OSError, NotImplementedError, AttributeError):
        return False
    os.remove(probe)
    return True


# --------------------------------------------------------------------------- #
# Pure path predicates                                                        #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/abs/path",
        "back\\slash",
        ".",
        "..",
        "a/../b",
        "a/./b",
        "a//b",
        "trailing/",
        "/",
    ],
)
def test_is_safe_relative_path_rejects(path: str) -> None:
    assert _is_safe_relative_path(path) is False


@pytest.mark.parametrize("path", ["a", "a/b", "pkg/mod.py", "x/y/z.txt"])
def test_is_safe_relative_path_accepts(path: str) -> None:
    assert _is_safe_relative_path(path) is True


def test_is_within_true_and_false(tmp_path) -> None:
    root_dir = str(tmp_path)
    inside = os.path.join(root_dir, "a", "b")
    assert _is_within(root_dir, inside) is True
    assert _is_within(root_dir, root_dir) is True
    assert _is_within(os.path.join(root_dir, "sub"), root_dir) is False
    # Different drives / unrelated roots raise ValueError internally -> False.
    assert _is_within(root_dir, "relative/other") is False


# --------------------------------------------------------------------------- #
# write / read / delete happy paths                                           #
# --------------------------------------------------------------------------- #


def test_write_then_read_roundtrip_creates_intermediate_dirs(root) -> None:
    write_text_within_root(root, "pkg/sub/mod.py", "value = 1\n")
    assert os.path.isfile(os.path.join(root, "pkg", "sub", "mod.py"))
    assert read_text_within_root(root, "pkg/sub/mod.py") == "value = 1\n"


def test_write_overwrites_existing_regular_file(root) -> None:
    write_text_within_root(root, "a.txt", "first")
    write_text_within_root(root, "a.txt", "second")
    assert read_text_within_root(root, "a.txt") == "second"


def test_write_preserves_wide_unicode_content_and_name(root) -> None:
    write_text_within_root(root, "é世/mod.py", "x = 'café ❯ مرحبا'\n")
    assert read_text_within_root(root, "é世/mod.py") == "x = 'café ❯ مرحبا'\n"


def test_delete_reports_presence_then_absence(root) -> None:
    write_text_within_root(root, "gone.txt", "bye")
    assert delete_path_within_root(root, "gone.txt") is True
    assert delete_path_within_root(root, "gone.txt") is False


def test_delete_removes_a_whole_subtree(root) -> None:
    write_text_within_root(root, "d/e/f.txt", "deep")
    assert delete_path_within_root(root, "d") is True
    assert not os.path.exists(os.path.join(root, "d"))


# --------------------------------------------------------------------------- #
# Unsafe path rejection across all three operations                           #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("bad", ["../escape", "/abs", "a\\b", "", "a/../b", "."])
def test_operations_reject_unsafe_relative_paths(root, bad: str) -> None:
    with pytest.raises(UnsafeWorkspacePath):
        write_text_within_root(root, bad, "x")
    with pytest.raises(UnsafeWorkspacePath):
        delete_path_within_root(root, bad)


# --------------------------------------------------------------------------- #
# Non-regular targets and missing parents                                     #
# --------------------------------------------------------------------------- #


def test_write_refuses_to_replace_a_directory(root) -> None:
    os.mkdir(os.path.join(root, "adir"))
    with pytest.raises(UnsafeWorkspacePath):
        write_text_within_root(root, "adir", "x")


def test_read_refuses_a_directory(root) -> None:
    os.mkdir(os.path.join(root, "adir"))
    with pytest.raises((UnsafeWorkspacePath, IsADirectoryError, PermissionError, OSError)):
        read_text_within_root(root, "adir")


def test_read_missing_file_raises_filenotfound(root) -> None:
    with pytest.raises(FileNotFoundError):
        read_text_within_root(root, "nope/missing.txt")


def test_read_refuses_a_hardlinked_file(root) -> None:
    write_text_within_root(root, "orig.txt", "shared")
    try:
        os.link(os.path.join(root, "orig.txt"), os.path.join(root, "alias.txt"))
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("hard links unavailable on this filesystem")
    # nlink == 2 now: the reader must refuse an aliased file.
    with pytest.raises(UnsafeWorkspacePath):
        read_text_within_root(root, "orig.txt")


# --------------------------------------------------------------------------- #
# Reparse / symlink rejection (skipped where symlinks need privilege)         #
# --------------------------------------------------------------------------- #


def test_write_refuses_a_symlinked_parent(root) -> None:
    if not _can_symlink(root):
        pytest.skip("symlink creation not permitted on this host")
    outside = tempfile.mkdtemp()
    os.symlink(outside, os.path.join(root, "link"), target_is_directory=True)
    with pytest.raises(UnsafeWorkspacePath):
        write_text_within_root(root, "link/evil.txt", "x")


def test_operations_refuse_a_symlinked_root(root) -> None:
    if not _can_symlink(root):
        pytest.skip("symlink creation not permitted on this host")
    real = os.path.join(root, "real")
    os.mkdir(real)
    link_root = os.path.join(root, "root-link")
    os.symlink(real, link_root, target_is_directory=True)
    with pytest.raises(UnsafeWorkspacePath):
        write_text_within_root(link_root, "a.txt", "x")


def test_delete_leaf_symlink_is_removed_without_following(root) -> None:
    if not _can_symlink(root):
        pytest.skip("symlink creation not permitted on this host")
    outside_dir = tempfile.mkdtemp()
    outside_file = os.path.join(outside_dir, "keep.txt")
    with open(outside_file, "w", encoding="utf-8") as f:
        f.write("must survive")
    os.symlink(outside_file, os.path.join(root, "leaf-link"))
    assert delete_path_within_root(root, "leaf-link") is True
    # The symlink is gone; its target outside the root is untouched.
    assert not os.path.lexists(os.path.join(root, "leaf-link"))
    assert os.path.isfile(outside_file)
