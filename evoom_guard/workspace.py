# ---------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ---------------------------------------------------------------------------
"""Shared containment primitives for judge-owned throwaway workspaces."""

from __future__ import annotations

import os
import shutil


class UnsafeWorkspacePath(ValueError):
    """A requested workspace operation would escape its judge-owned root."""


def _is_safe_relative_path(path: str) -> bool:
    if not path or os.path.isabs(path) or "\\" in path:
        return False
    return all(part not in ("", ".", "..") for part in path.split("/"))


def _is_within(root: str, path: str) -> bool:
    try:
        common = os.path.commonpath((root, path))
    except ValueError:
        return False
    return os.path.normcase(common) == os.path.normcase(root)


def delete_path_within_root(root: str, relative_path: str) -> bool:
    """Delete one relative path without following a parent outside ``root``.

    The leaf may itself be a symlink: deleting that link is safe and must not
    dereference its target.  A symlinked *parent* is resolved before deletion;
    if it leaves the workspace, the operation fails closed.

    Returns ``True`` when an existing entry was deleted and ``False`` when it
    was already absent. Other filesystem failures are intentionally propagated.
    """
    if not _is_safe_relative_path(relative_path):
        raise UnsafeWorkspacePath(
            f"unsafe deletion path is not a normalized relative path: "
            f"{relative_path!r}"
        )

    real_root = os.path.realpath(root)
    target = os.path.join(root, *relative_path.split("/"))
    real_parent = os.path.realpath(os.path.dirname(target))
    if not _is_within(real_root, real_parent):
        raise UnsafeWorkspacePath(
            "unsafe deletion path escapes the workspace through a symlinked "
            f"parent: {relative_path!r}"
        )

    if not os.path.lexists(target):
        return False

    if os.path.islink(target):
        os.unlink(target)
    elif getattr(os.path, "isjunction", lambda _path: False)(target):
        os.rmdir(target)
    elif os.path.isdir(target):
        shutil.rmtree(target)
    else:
        os.remove(target)
    return True
