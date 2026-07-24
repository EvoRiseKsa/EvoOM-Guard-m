# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Low-level repository-copy and judge-workspace lifecycle contracts.

This dependency-free owner contains only repository-tree copying and cleanup
effects. It does not decide candidate admission, execute repository code,
interpret evidence, or compose a verdict. Compatibility facades inject their
live module globals at each call so existing monkeypatch seams keep their
historical timing.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable, Iterable

# Directories never copied into a throwaway candidate working copy.
COPY_IGNORE = (
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

CopyTree = Callable[..., object]
CopyIgnore = Callable[[str, list[str]], Iterable[str]]
IgnorePatterns = Callable[..., CopyIgnore]
RemoveTree = Callable[[str], object]
NoteFailure = Callable[[BaseException, str], None]


def copy_repo_tree(
    src: str,
    dst: str,
    *,
    copy_ignore: tuple[str, ...] = COPY_IGNORE,
    copytree: CopyTree | None = None,
    ignore_patterns: IgnorePatterns | None = None,
) -> None:
    """Copy a repository faithfully into one throwaway working tree.

    ``symlinks=True`` preserves dangling links and prevents copying the contents
    of an absolute link target into the candidate tree. Regular-file metadata,
    including executable bits, continues to be copied through ``copytree``'s
    default ``copy2`` operation.
    """

    copytree_provider: CopyTree = shutil.copytree if copytree is None else copytree
    ignore_patterns_provider: IgnorePatterns = (
        shutil.ignore_patterns if ignore_patterns is None else ignore_patterns
    )
    copytree_provider(
        src,
        dst,
        symlinks=True,
        ignore=ignore_patterns_provider(*copy_ignore),
    )


def note_cleanup_failure(primary: BaseException, message: str) -> None:
    """Attach secondary cleanup diagnostics without replacing ``primary``."""

    try:
        add_note = getattr(primary, "add_note", None)
        if callable(add_note):
            add_note(message)
            return
        notes = getattr(primary, "__notes__", None)
        if isinstance(notes, list):
            notes.append(message)
        else:
            # Python 3.10 has no add_note(), but BaseException permits a
            # machine-readable notes attribute for callers and tests.
            primary.__dict__["__notes__"] = [message]
    except BaseException:
        # Cleanup diagnostics are secondary by contract. Even a hostile or
        # constrained exception object cannot replace the primary failure.
        pass


def cleanup_repo_workspaces(
    workspaces: tuple[tuple[str, str | None], ...],
    *,
    primary: BaseException | None,
    remove_tree: RemoveTree | None = None,
    note_failure: NoteFailure | None = None,
    owner_name: str = "RepoVerifier",
) -> None:
    """Remove all owned workspaces with explicit exception precedence.

    Every path is attempted. With no active exception, the first cleanup
    failure remains visible and later failures are attached as notes. During
    exception unwinding, the exact active exception remains primary and
    receives one note per cleanup failure.
    """

    if remove_tree is None:
        remove_tree = shutil.rmtree
    if note_failure is None:
        note_failure = note_cleanup_failure

    failures: list[tuple[str, BaseException]] = []
    for label, path in workspaces:
        if path is None:
            continue
        try:
            remove_tree(path)
        except FileNotFoundError:
            # Absence is the cleanup postcondition, so an earlier removal is an
            # idempotent success rather than a lifecycle failure.
            continue
        except BaseException as exc:
            failures.append((label, exc))

    if not failures:
        return

    if primary is not None:
        for label, cleanup_error in failures:
            note_failure(
                primary,
                f"{owner_name} {label} cleanup failed while preserving the "
                f"primary exception: {type(cleanup_error).__name__}: {cleanup_error}",
            )
        return

    first_label, first_error = failures[0]
    note_failure(
        first_error,
        f"{owner_name} {first_label} cleanup failed",
    )
    for label, cleanup_error in failures[1:]:
        note_failure(
            first_error,
            f"Additional {owner_name} {label} cleanup failure: "
            f"{type(cleanup_error).__name__}: {cleanup_error}",
        )
    raise first_error


__all__ = (
    "COPY_IGNORE",
    "cleanup_repo_workspaces",
    "copy_repo_tree",
    "note_cleanup_failure",
)
