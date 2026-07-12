# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Setup and candidate-tree fidelity snapshots for the repository verifier.

This module is deliberately independent of :mod:`repo_verifier` so the legacy
module can re-export these helpers without creating an import cycle.
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


def _fidelity_entry_state(path: str) -> tuple[str, int, str]:
    try:
        mode = os.lstat(path).st_mode
        permissions = stat.S_IMODE(mode)
        if stat.S_ISLNK(mode):
            return ("link", permissions, os.readlink(path))
        if stat.S_ISDIR(mode):
            return ("dir", permissions, "")
        if not stat.S_ISREG(mode):
            return ("special", permissions, str(stat.S_IFMT(mode)))
        digest = hashlib.sha256()
        with open(path, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return ("file", permissions, digest.hexdigest())
    except OSError as exc:
        raise SetupFidelityError(f"cannot read {path!r}: {exc}") from exc


def _setup_fidelity_snapshot(
    root: str,
    extra_output_globs: tuple[str, ...] = (),
    *,
    baseline: dict[str, tuple[str, int, str]] | None = None,
) -> dict[str, tuple[str, int, str]]:
    """Identity of files setup is not allowed to mutate.

    Every pre-existing file, directory, symlink and permission bit is bound,
    including content under conventional output directories. On the post-setup
    scan, only *new* entries below those conventional directories are ignored.
    This lets setup create ``node_modules``/``.venv``/``target`` without allowing
    it to rewrite a checked-in ``vendor`` or ``build`` tree. Explicit adopter
    globs are trusted exceptions and are omitted on both scans.
    """
    snapshot: dict[str, tuple[str, int, str]] = {}
    baseline_keys = frozenset(baseline or {})

    def walk_error(exc: OSError) -> None:
        raise SetupFidelityError(f"cannot inspect setup output tree: {exc}") from exc

    for dirpath, dirnames, filenames in os.walk(root, onerror=walk_error):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        kept: list[str] = []
        for dirname in sorted(dirnames):
            path = os.path.join(dirpath, dirname)
            rel = dirname if rel_dir == "." else f"{rel_dir}/{dirname}"
            if _matches_globs(rel, extra_output_globs) or _matches_globs(
                rel + "/", extra_output_globs
            ):
                continue
            if baseline is not None and _is_default_setup_output(rel) and rel not in baseline_keys:
                continue
            state = _fidelity_entry_state(path)
            snapshot[rel] = state
            if state[0] == "dir":
                kept.append(dirname)
        dirnames[:] = kept
        for filename in sorted(filenames):
            path = os.path.join(dirpath, filename)
            rel = filename if rel_dir == "." else f"{rel_dir}/{filename}"
            if _matches_globs(rel, extra_output_globs):
                continue
            if baseline is not None and _is_default_setup_output(rel) and rel not in baseline_keys:
                continue
            snapshot[rel] = _fidelity_entry_state(path)
    return snapshot


def _setup_fidelity_changes(
    before: dict[str, tuple[str, int, str]],
    after: dict[str, tuple[str, int, str]],
) -> list[str]:
    return sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))
