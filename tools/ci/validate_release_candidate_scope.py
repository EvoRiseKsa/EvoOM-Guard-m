#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Validate the exact, parent-owned v4.7.0 release-candidate scope.

This validator is executed from the trusted parent checkout before candidate
code or the candidate verifier pack runs.  It deliberately overlays EvoGuard's
historical case-insensitive adopter allowlist with a release-specific,
case-sensitive literal path contract.  Allowed paths must already exist and
remain regular files with the same mode.  The validator also proves that the
only executable source change allowed in the release commit is the exact
development-to-stable ``__version__`` byte replacement.

The filesystem comparison is appropriate only for the two fresh, exact
GitHub-hosted checkouts used by the protected release workflow.  It rejects
links, reparse points, hard links, special files, non-NFC names, portable-case
collisions, unstable reads, and trees that overlap each other.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

RELEASE_VERSION = "4.7.0"
VERSION_PATH = "evoom_guard/__init__.py"
ALLOWED_PATHS = (
    "CHANGELOG.md",
    "PROJECT_STATUS.json",
    "README.md",
    "ROADMAP.md",
    "SECURITY.md",
    "docs/GITHUB_ARTIFACT_ATTESTATIONS.md",
    "docs/PROJECT_STATUS.md",
    "docs/RELEASE_STATUS.md",
    "docs/SBOM.md",
    "docs/architecture/REFACTOR_PROGRAM.md",
    VERSION_PATH,
)

_PARENT_VERSION_ASSIGNMENT = (
    f'__version__ = "{RELEASE_VERSION}.dev0"'.encode("ascii")
)
_CANDIDATE_VERSION_ASSIGNMENT = (
    f'__version__ = "{RELEASE_VERSION}"'.encode("ascii")
)
_MAX_FILES = 20_000
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_TREE_BYTES = 512 * 1024 * 1024


class CandidateScopeError(ValueError):
    """The candidate is outside the exact reviewed v4.7.0 release scope."""


@dataclass(frozen=True, slots=True)
class FileSnapshot:
    """Stable identity used to compare one regular source file."""

    mode: int
    size: int
    sha256: str
    content: bytes | None = None


def _fail(message: str) -> NoReturn:
    raise CandidateScopeError(message)


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(stat.S_IFMT(metadata.st_mode)),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _path_is_within(path: Path, root: Path) -> bool:
    path_text = os.path.normcase(str(_absolute(path)))
    root_text = os.path.normcase(str(_absolute(root)))
    try:
        return os.path.commonpath((path_text, root_text)) == root_text
    except ValueError:
        return False


def _require_disjoint_roots(base: Path, candidate: Path) -> tuple[Path, Path]:
    base = _absolute(base)
    candidate = _absolute(candidate)
    if _path_is_within(base, candidate) or _path_is_within(candidate, base):
        _fail("trusted base and candidate roots must be disjoint")
    return base, candidate


def _validate_component(name: str) -> None:
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or unicodedata.normalize("NFC", name) != name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        _fail(f"source tree contains a non-canonical path component: {name!r}")


def _require_plain_directory(path: Path, *, label: str) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise CandidateScopeError(f"cannot inspect {label}: {path}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _is_reparse_point(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        _fail(f"{label} must be a real directory: {path}")
    return metadata


def _read_regular_file(path: Path, *, retain_content: bool) -> FileSnapshot:
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise CandidateScopeError(f"cannot inspect source file: {path}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or _is_reparse_point(before)
        or not stat.S_ISREG(before.st_mode)
        or int(before.st_nlink) != 1
    ):
        _fail(f"source entry must be one regular non-link file: {path}")
    if before.st_size > _MAX_FILE_BYTES:
        _fail(f"source file exceeds the {_MAX_FILE_BYTES}-byte limit: {path}")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CandidateScopeError(f"cannot open source file safely: {path}") from exc

    digest = hashlib.sha256()
    chunks: list[bytes] | None = [] if retain_content else None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse_point(opened)
            or int(opened.st_nlink) != 1
            or _identity(opened) != _identity(before)
        ):
            _fail(f"source file changed while it was opened: {path}")
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_FILE_BYTES:
                _fail(f"source file exceeds the {_MAX_FILE_BYTES}-byte limit: {path}")
            digest.update(chunk)
            if chunks is not None:
                chunks.append(chunk)
        after_read = os.fstat(descriptor)
        if _identity(after_read) != _identity(opened):
            _fail(f"source file changed while it was read: {path}")
    finally:
        os.close(descriptor)

    try:
        after_close = os.lstat(path)
    except OSError as exc:
        raise CandidateScopeError(f"cannot re-inspect source file: {path}") from exc
    if _identity(after_close) != _identity(before):
        _fail(f"source file changed during validation: {path}")
    content = b"".join(chunks) if chunks is not None else None
    return FileSnapshot(
        mode=stat.S_IMODE(before.st_mode),
        size=int(before.st_size),
        sha256=digest.hexdigest(),
        content=content,
    )


def _scan_tree(root: Path, *, label: str) -> dict[str, FileSnapshot]:
    root_metadata = _require_plain_directory(root, label=label)
    files: dict[str, FileSnapshot] = {}
    portable_paths: dict[str, str] = {}
    total_bytes = 0

    def visit(directory: Path, relative: tuple[str, ...]) -> None:
        nonlocal total_bytes
        before = _require_plain_directory(directory, label=f"{label} directory")
        try:
            with os.scandir(directory) as scanner:
                entries = sorted(scanner, key=lambda entry: entry.name)
        except OSError as exc:
            raise CandidateScopeError(f"cannot enumerate {label}: {directory}") from exc
        for entry in entries:
            if not relative and entry.name == ".git":
                continue
            _validate_component(entry.name)
            components = (*relative, entry.name)
            relative_path = "/".join(components)
            folded = relative_path.casefold()
            prior = portable_paths.get(folded)
            if prior is not None and prior != relative_path:
                _fail(
                    f"{label} contains a portable-case path collision: "
                    f"{prior!r} and {relative_path!r}"
                )
            portable_paths[folded] = relative_path
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise CandidateScopeError(
                    f"cannot inspect {label} entry: {relative_path}"
                ) from exc
            if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
                _fail(f"{label} contains a link-like entry: {relative_path}")
            if stat.S_ISDIR(metadata.st_mode):
                visit(Path(entry.path), components)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                _fail(f"{label} contains a special entry: {relative_path}")
            if len(files) >= _MAX_FILES:
                _fail(f"{label} exceeds the {_MAX_FILES}-file limit")
            snapshot = _read_regular_file(
                Path(entry.path),
                retain_content=relative_path == VERSION_PATH,
            )
            total_bytes += snapshot.size
            if total_bytes > _MAX_TREE_BYTES:
                _fail(f"{label} exceeds the {_MAX_TREE_BYTES}-byte tree limit")
            files[relative_path] = snapshot
        after = _require_plain_directory(directory, label=f"{label} directory")
        if _identity(after) != _identity(before):
            _fail(f"{label} directory changed during validation: {directory}")

    visit(root, ())
    after_root = _require_plain_directory(root, label=label)
    if _identity(after_root) != _identity(root_metadata):
        _fail(f"{label} root changed during validation")
    return files


def validate_changed_paths(changed_paths: tuple[str, ...]) -> None:
    """Require a non-empty, exact-case subset of the frozen release path set."""

    if not changed_paths:
        _fail("release candidate has no source changes")
    if len(set(changed_paths)) != len(changed_paths):
        _fail("release candidate change paths are not unique")
    unexpected = tuple(path for path in changed_paths if path not in ALLOWED_PATHS)
    if unexpected:
        _fail(
            "release candidate changed path(s) outside the exact-case scope: "
            + ", ".join(unexpected)
        )
    if VERSION_PATH not in changed_paths:
        _fail(f"release candidate must change {VERSION_PATH} exactly once")


def _validate_version_transition(
    base: dict[str, FileSnapshot],
    candidate: dict[str, FileSnapshot],
) -> None:
    before = base.get(VERSION_PATH)
    after = candidate.get(VERSION_PATH)
    if before is None or after is None:
        _fail(f"{VERSION_PATH} must remain one regular file")
    if before.content is None or after.content is None:
        _fail(f"{VERSION_PATH} content snapshot is unavailable")
    if before.mode != after.mode:
        _fail(f"{VERSION_PATH} mode must not change")
    if before.content.count(_PARENT_VERSION_ASSIGNMENT) != 1:
        _fail(
            f"trusted parent must contain one exact "
            f"{RELEASE_VERSION}.dev0 version assignment"
        )
    expected = before.content.replace(
        _PARENT_VERSION_ASSIGNMENT,
        _CANDIDATE_VERSION_ASSIGNMENT,
        1,
    )
    if after.content != expected:
        _fail(
            f"{VERSION_PATH} may change only the exact "
            f"{RELEASE_VERSION}.dev0-to-{RELEASE_VERSION} assignment bytes"
        )


def validate_candidate_scope(base_root: Path, candidate_root: Path) -> tuple[str, ...]:
    """Validate two fresh checkout trees and return their exact changed paths."""

    base_root, candidate_root = _require_disjoint_roots(base_root, candidate_root)
    base = _scan_tree(base_root, label="trusted base")
    candidate = _scan_tree(candidate_root, label="candidate")
    changed = tuple(
        sorted(
            path
            for path in set(base) | set(candidate)
            if base.get(path) != candidate.get(path)
        )
    )
    validate_changed_paths(changed)
    for path in changed:
        before = base.get(path)
        after = candidate.get(path)
        if before is None or after is None:
            _fail(f"release candidate may not add or delete an allowed path: {path}")
        if before.mode != after.mode:
            _fail(f"release candidate may not change an allowed path mode: {path}")
    _validate_version_transition(base, candidate)
    return changed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate the exact parent-owned v4.7.0 release-candidate scope."
    )
    parser.add_argument("--base", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        changed = validate_candidate_scope(args.base, args.candidate)
    except CandidateScopeError as exc:
        print(f"release candidate scope rejected: {exc}", file=sys.stderr)
        return 1
    print(
        f"release candidate scope valid: {len(changed)} exact path(s), "
        f"version={RELEASE_VERSION}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
