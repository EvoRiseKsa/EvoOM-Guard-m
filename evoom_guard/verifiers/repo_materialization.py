# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Contained materialization of candidate edits inside a throwaway repo copy.

This module owns only the ordered FILE/PATCH write transaction and restoration
of judge-owned ``package.json`` fields. It does not copy repositories, launch
processes, select verifier packs, or decide a verdict.

Filesystem and patch operations are injected deliberately. The public
``repo_verifier.apply_blocks_to_copy`` compatibility facade supplies its current
module globals on every call so existing monkeypatch seams remain dynamic.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

from evoom_guard.candidate import PatchBlock, PatchError
from evoom_guard.workspace import UnsafeWorkspacePath

ReadText = Callable[[str, str], str]
WriteText = Callable[[str, str, str], None]
PatchText = Callable[[str, str, str], str]
RestorePackageJson = Callable[[str | None, str], str]


def materialize_candidate_edits(
    root: str,
    file_blocks: Mapping[str, str],
    patch_blocks: Sequence[PatchBlock],
    *,
    read_text: ReadText,
    write_text: WriteText,
    patcher: PatchText,
    restore_package_json: RestorePackageJson,
) -> str | None:
    """Apply FILE blocks, then PATCH blocks, while preserving judge manifests.

    A returned string is the historical user-facing rejection reason. ``None``
    means materialization completed. Reads and writes stay descriptor-contained
    through the injected workspace operations; an unsafe or unstable source is
    never treated as an absent file.
    """

    def safe_read(relative_path: str) -> tuple[str | None, str | None]:
        try:
            return read_text(root, relative_path), None
        except FileNotFoundError:
            return None, None
        except (UnicodeError, UnsafeWorkspacePath, OSError) as exc:
            return None, (
                "edit source could not be read safely — refusing to treat it "
                f"as absent: {relative_path} ({exc})"
            )

    def safe_write(relative_path: str, content: str) -> str | None:
        try:
            write_text(root, relative_path, content)
        except (OSError, UnsafeWorkspacePath) as exc:
            return (
                "edit target escapes the repo copy or changed inside it — "
                f"refusing to write: {relative_path} ({exc})"
            )
        return None

    package_paths = sorted(
        {path for path in file_blocks if path.split("/")[-1] == "package.json"}
        | {
            block.path
            for block in patch_blocks
            if block.path.split("/")[-1] == "package.json"
        }
    )
    package_originals: dict[str, str | None] = {}
    for relative_path in package_paths:
        original, read_error = safe_read(relative_path)
        if read_error is not None:
            return read_error
        package_originals[relative_path] = original

    for path, content in file_blocks.items():
        write_error = safe_write(path, content)
        if write_error is not None:
            return write_error

    for block in patch_blocks:
        source, read_error = safe_read(block.path)
        if read_error is not None:
            return read_error
        if source is None:
            return (
                f"PATCH target not found: {block.path} — "
                "use a <<<FILE>>> block "
                "to create new files"
            )
        try:
            patched = patcher(source, block.search, block.replace)
        except (PatchError, ValueError) as exc:
            return (
                f"PATCH did not apply to {block.path}: "
                f"{type(exc).__name__}: {exc} — "
                ""
                "copy a unique anchor verbatim from the shown file"
            )
        write_error = safe_write(block.path, patched)
        if write_error is not None:
            return write_error

    for relative_path in package_paths:
        candidate_package, read_error = safe_read(relative_path)
        if read_error is not None:
            return read_error
        if candidate_package is None:
            return (
                "edited package manifest disappeared before verification: "
                f"{relative_path}"
            )
        restored = restore_package_json(
            package_originals.get(relative_path), candidate_package
        )
        if restored != candidate_package:
            write_error = safe_write(relative_path, restored)
            if write_error is not None:
                return write_error
    return None


__all__ = ["materialize_candidate_edits"]
