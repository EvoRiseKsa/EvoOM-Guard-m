# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Setup and candidate-tree fidelity snapshots for the repository verifier.

This module is deliberately independent of :mod:`repo_verifier` so the legacy
module can re-export these helpers without creating an import cycle.

POSIX scans bind the traversed namespace through directory descriptors.
Platforms without those primitives use explicit pre/post identity checks and
are therefore best-effort. Content, entry type and mode are bound; extended
attributes and ACLs are intentionally outside this snapshot contract.
"""

from __future__ import annotations

import hashlib
import os
import stat
from fnmatch import fnmatch

_DEFAULT_SETUP_OUTPUT_DIRS = frozenset({
    ".cache", ".evoguard-setup", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".tox", ".venv", "build", "dist", "node_modules", "target", "venv",
    "vendor", "__pycache__",
})


class SetupFidelityError(RuntimeError):
    """The judge could not prove what setup changed; fail closed."""


def _matches_globs(path: str, globs: tuple[str, ...]) -> bool:
    """Local cycle-free equivalent of the verifier's path-glob matcher."""
    return any(fnmatch(path.lower(), glob.lower()) for glob in globs)


def _is_default_setup_output(path: str) -> bool:
    return any(part in _DEFAULT_SETUP_OUTPUT_DIRS for part in path.split("/") if part)


def _stat_fingerprint(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    # Windows can expose different ctime values for lstat(path) and fstat(fd)
    # on the same unchanged object. Bind every cross-view stable field there;
    # POSIX additionally binds inode-change time, whose semantics are stable.
    stable_ctime_ns = info.st_ctime_ns if os.name == "posix" else 0
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        stable_ctime_ns,
    )


def _fidelity_entry_state(path: str) -> tuple[str, int, str]:
    try:
        before_path = os.lstat(path)
        mode = before_path.st_mode
        if stat.S_ISLNK(mode):
            target = os.readlink(path)
            if _stat_fingerprint(before_path) != _stat_fingerprint(os.lstat(path)):
                raise SetupFidelityError(f"path changed while reading link: {path!r}")
            return ("link", stat.S_IMODE(mode), target)
        if stat.S_ISDIR(mode):
            if _stat_fingerprint(before_path) != _stat_fingerprint(os.lstat(path)):
                raise SetupFidelityError(f"path changed while reading directory: {path!r}")
            return ("dir", stat.S_IMODE(mode), "")
        if not stat.S_ISREG(mode):
            after_path = os.lstat(path)
            if _stat_fingerprint(before_path) != _stat_fingerprint(after_path):
                raise SetupFidelityError(f"special path changed while reading: {path!r}")
            return ("special", stat.S_IMODE(mode), str(stat.S_IFMT(mode)))
        if before_path.st_nlink != 1:
            raise SetupFidelityError(
                f"hardlinked file has {before_path.st_nlink} names; refusing ambiguous "
                f"fidelity identity: {path!r}"
            )

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if os.name == "posix":
            if not hasattr(os, "O_NOFOLLOW"):
                raise SetupFidelityError(
                    "this POSIX runtime cannot bind fidelity reads with O_NOFOLLOW"
                )
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        try:
            before_fd = os.fstat(fd)
            if (
                not stat.S_ISREG(before_fd.st_mode)
                or before_fd.st_nlink != 1
                or _stat_fingerprint(before_path) != _stat_fingerprint(before_fd)
            ):
                raise SetupFidelityError(
                    f"path identity changed between lstat and open: {path!r}"
                )
            digest = hashlib.sha256()
            while chunk := os.read(fd, 1024 * 1024):
                digest.update(chunk)
            after_fd = os.fstat(fd)
        finally:
            os.close(fd)
        after_path = os.lstat(path)
        if not (
            _stat_fingerprint(before_fd) == _stat_fingerprint(after_fd)
            and _stat_fingerprint(after_path) == _stat_fingerprint(after_fd)
        ):
            raise SetupFidelityError(f"file changed while hashing: {path!r}")
        return ("file", stat.S_IMODE(before_fd.st_mode), digest.hexdigest())
    except SetupFidelityError:
        raise
    except OSError as exc:
        raise SetupFidelityError(f"cannot read {path!r}: {exc}") from exc


_DESCRIPTOR_SCAN_SUPPORTED = (
    os.name == "posix"
    and hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
    and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.readlink in os.supports_dir_fd
    and os.listdir in os.supports_fd
)


def _scan_entry_is_ignored(
    rel: str,
    *,
    is_directory: bool,
    extra_output_globs: tuple[str, ...],
    baseline: dict[str, tuple[str, int, str]] | None,
    baseline_keys: frozenset[str],
) -> bool:
    if _matches_globs(rel, extra_output_globs):
        return True
    if is_directory and _matches_globs(rel + "/", extra_output_globs):
        return True
    return (
        baseline is not None
        and _is_default_setup_output(rel)
        and rel not in baseline_keys
    )


def _scan_fidelity_with_descriptors(
    root: str,
    snapshot: dict[str, tuple[str, int, str]],
    extra_output_globs: tuple[str, ...],
    baseline: dict[str, tuple[str, int, str]] | None,
    baseline_keys: frozenset[str],
) -> None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )

    def scan_directory(directory_fd: int, rel_dir: str) -> None:
        before_directory = os.fstat(directory_fd)
        names_before = sorted(os.listdir(directory_fd))
        for name in names_before:
            rel = name if not rel_dir else f"{rel_dir}/{name}"
            initial = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            is_directory = stat.S_ISDIR(initial.st_mode)
            if _scan_entry_is_ignored(
                rel,
                is_directory=is_directory,
                extra_output_globs=extra_output_globs,
                baseline=baseline,
                baseline_keys=baseline_keys,
            ):
                continue

            if stat.S_ISLNK(initial.st_mode):
                target = os.readlink(name, dir_fd=directory_fd)
                after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if _stat_fingerprint(initial) != _stat_fingerprint(after):
                    raise SetupFidelityError(
                        f"path changed while reading link: {rel!r}"
                    )
                snapshot[rel] = ("link", stat.S_IMODE(initial.st_mode), target)
                continue

            if is_directory:
                child_fd = os.open(name, flags, dir_fd=directory_fd)
                try:
                    opened = os.fstat(child_fd)
                    if _stat_fingerprint(initial) != _stat_fingerprint(opened):
                        raise SetupFidelityError(
                            f"directory changed while it was opened: {rel!r}"
                        )
                    snapshot[rel] = ("dir", stat.S_IMODE(opened.st_mode), "")
                    scan_directory(child_fd, rel)
                    after_open = os.fstat(child_fd)
                finally:
                    os.close(child_fd)
                after_path = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )
                if not (
                    _stat_fingerprint(opened) == _stat_fingerprint(after_open)
                    == _stat_fingerprint(after_path)
                ):
                    raise SetupFidelityError(
                        f"directory changed while it was scanned: {rel!r}"
                    )
                continue

            if stat.S_ISREG(initial.st_mode):
                if initial.st_nlink != 1:
                    raise SetupFidelityError(
                        f"hardlinked file has {initial.st_nlink} names; refusing "
                        f"ambiguous fidelity identity: {rel!r}"
                    )
                file_flags = (
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                )
                file_fd = os.open(name, file_flags, dir_fd=directory_fd)
                try:
                    opened_file = os.fstat(file_fd)
                    if (
                        _stat_fingerprint(initial)
                        != _stat_fingerprint(opened_file)
                        or not stat.S_ISREG(opened_file.st_mode)
                        or opened_file.st_nlink != 1
                    ):
                        raise SetupFidelityError(
                            f"file changed while it was opened: {rel!r}"
                        )
                    digest = hashlib.sha256()
                    while chunk := os.read(file_fd, 1024 * 1024):
                        digest.update(chunk)
                    after_open_file = os.fstat(file_fd)
                finally:
                    os.close(file_fd)
                after_file = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )
                if not (
                    _stat_fingerprint(opened_file)
                    == _stat_fingerprint(after_open_file)
                    == _stat_fingerprint(after_file)
                ):
                    raise SetupFidelityError(
                        f"file changed while it was hashed: {rel!r}"
                    )
                snapshot[rel] = (
                    "file",
                    stat.S_IMODE(opened_file.st_mode),
                    digest.hexdigest(),
                )
                continue

            after_special = os.stat(
                name, dir_fd=directory_fd, follow_symlinks=False
            )
            if _stat_fingerprint(initial) != _stat_fingerprint(after_special):
                raise SetupFidelityError(
                    f"special path changed while it was read: {rel!r}"
                )
            snapshot[rel] = (
                "special",
                stat.S_IMODE(initial.st_mode),
                str(stat.S_IFMT(initial.st_mode)),
            )

        names_after = sorted(os.listdir(directory_fd))
        after_directory = os.fstat(directory_fd)
        if (
            names_before != names_after
            or _stat_fingerprint(before_directory)
            != _stat_fingerprint(after_directory)
        ):
            where = rel_dir or "."
            raise SetupFidelityError(
                f"directory namespace changed while it was scanned: {where!r}"
            )

    root_before = os.lstat(root)
    root_fd = os.open(root, flags)
    try:
        root_opened = os.fstat(root_fd)
        if _stat_fingerprint(root_before) != _stat_fingerprint(root_opened):
            raise SetupFidelityError("setup root changed while it was opened")
        scan_directory(root_fd, "")
        root_after_fd = os.fstat(root_fd)
        root_after_path = os.lstat(root)
        if not (
            _stat_fingerprint(root_opened) == _stat_fingerprint(root_after_fd)
            == _stat_fingerprint(root_after_path)
        ):
            raise SetupFidelityError("setup root changed while it was scanned")
    finally:
        os.close(root_fd)


def _scan_fidelity_best_effort(
    root: str,
    snapshot: dict[str, tuple[str, int, str]],
    extra_output_globs: tuple[str, ...],
    baseline: dict[str, tuple[str, int, str]] | None,
    baseline_keys: frozenset[str],
) -> None:
    is_junction = getattr(os.path, "isjunction", lambda _path: False)

    def scan_directory(path: str, rel_dir: str) -> None:
        before_directory = os.lstat(path)
        if (
            not stat.S_ISDIR(before_directory.st_mode)
            or os.path.islink(path)
            or is_junction(path)
        ):
            raise SetupFidelityError(
                f"setup scan root/parent is a reparse point: {path!r}"
            )
        names_before = sorted(os.listdir(path))
        for name in names_before:
            child = os.path.join(path, name)
            rel = name if not rel_dir else f"{rel_dir}/{name}"
            initial = os.lstat(child)
            is_directory = stat.S_ISDIR(initial.st_mode)
            if _scan_entry_is_ignored(
                rel,
                is_directory=is_directory,
                extra_output_globs=extra_output_globs,
                baseline=baseline,
                baseline_keys=baseline_keys,
            ):
                continue
            state = _fidelity_entry_state(child)
            snapshot[rel] = state
            if state[0] == "dir":
                scan_directory(child, rel)
                after_child = os.lstat(child)
                if _stat_fingerprint(initial) != _stat_fingerprint(after_child):
                    raise SetupFidelityError(
                        f"directory changed while it was scanned: {rel!r}"
                    )

        names_after = sorted(os.listdir(path))
        after_directory = os.lstat(path)
        if (
            names_before != names_after
            or _stat_fingerprint(before_directory)
            != _stat_fingerprint(after_directory)
        ):
            where = rel_dir or "."
            raise SetupFidelityError(
                f"directory namespace changed while it was scanned: {where!r}"
            )

    scan_directory(root, "")


def _setup_fidelity_snapshot(
    root: str,
    extra_output_globs: tuple[str, ...] = (),
    *,
    baseline: dict[str, tuple[str, int, str]] | None = None,
) -> dict[str, tuple[str, int, str]]:
    """Return content/type/mode identities setup is not allowed to mutate.

    Every pre-existing entry is bound, including conventional output trees.
    On a post-setup scan only new entries below such trees are ignored. Explicit
    adopter globs are trusted exceptions on both scans. POSIX traversal is
    descriptor-relative and fail-closed; other platforms use explicit stable
    pre/post scans and therefore provide best-effort namespace binding.
    """
    snapshot: dict[str, tuple[str, int, str]] = {}
    baseline_keys = frozenset(baseline or {})
    try:
        if _DESCRIPTOR_SCAN_SUPPORTED:
            _scan_fidelity_with_descriptors(
                root,
                snapshot,
                extra_output_globs,
                baseline,
                baseline_keys,
            )
        else:
            _scan_fidelity_best_effort(
                root,
                snapshot,
                extra_output_globs,
                baseline,
                baseline_keys,
            )
    except SetupFidelityError:
        raise
    except OSError as exc:
        raise SetupFidelityError(
            f"cannot inspect setup output tree: {exc}"
        ) from exc
    return snapshot


def _setup_fidelity_changes(
    before: dict[str, tuple[str, int, str]],
    after: dict[str, tuple[str, int, str]],
) -> list[str]:
    return sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))
