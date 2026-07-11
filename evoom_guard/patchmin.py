# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────

"""Patch minimization + blast-radius risk scoring — pure, additive primitives.

This module holds two small, *model-free* helpers that reason about a patch
without ever applying it or talking to a model/verifier:

1. :func:`minimize_patch` — generic delta-debugging. Given a patch expressed as
   an ordered list of independent edits and an *injected* ``passes`` predicate,
   it shrinks the patch to a **1-minimal** subset that still passes. The
   predicate is supplied by the caller, so the function stays pure and offline:
   in production the predicate applies the candidate subset and runs the repo
   verifier; in tests it is a trivial membership check.

2. :func:`risk_score` (with :func:`parse_unified_diff`) — turns a unified-diff
   string (or a precomputed ``{file: (added, removed)}`` map) into a bounded,
   deterministic :class:`RiskScore` describing the blast radius: how many files
   are touched, how many lines change, whether any *protected* path is hit, and
   a single ``0..1`` score plus a coarse ``low``/``medium``/``high`` level.

Nothing here imports the engine, the serving layer, or the verifier. Everything
is standard library and deterministic, so it is trivially testable and reusable.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import TypeAlias, TypeVar

__all__ = [
    "minimize_patch",
    "RiskScore",
    "parse_unified_diff",
    "risk_score",
]

T = TypeVar("T")


# ─────────────────────────── A1. delta-debugging ────────────────────────────
def minimize_patch(edits: list[T], passes: Callable[[list[T]], bool]) -> list[T]:
    """Shrink a passing patch to a 1-minimal subset that still passes.

    ``edits`` is the full patch as an ordered list of independent edits (hunks /
    search-replace ops / lines — opaque to this function). ``passes(subset)``
    returns True iff applying ``subset`` still satisfies the goal (e.g. the repo
    tests pass); it is injected so this stays pure and offline-testable (the real
    predicate applies the subset and runs the verifier).

    Returns a subset, preserving original order, that is **1-MINIMAL**: removing
    any single remaining edit makes ``passes`` False. Greedy to a fixpoint.

    - If ``passes([])`` is True, returns ``[]`` (the patch was unnecessary).
    - If ``passes(edits)`` is False, raises :class:`ValueError` (cannot minimize a
      patch that does not pass to begin with).

    Deterministic: the elements are scanned in their original order and the
    earliest removable one is dropped on each sweep, so identical inputs always
    yield identical output.
    """
    # The empty patch already passes -> nothing was needed.
    if passes([]):
        return []
    # We can only minimize something that passes as a whole.
    current: list[T] = list(edits)
    if not passes(current):
        raise ValueError(
            "minimize_patch: the full patch does not pass; cannot minimize a "
            "patch that fails to begin with"
        )

    # Greedy 1-minimization to a fixpoint. Each sweep walks the *current* list in
    # order; the first element whose removal still passes is dropped, then we
    # restart the sweep on the shrunken list. When a full sweep removes nothing,
    # the result is 1-minimal: no single remaining element can be dropped.
    changed = True
    while changed:
        changed = False
        for i in range(len(current)):
            candidate = current[:i] + current[i + 1 :]
            if passes(candidate):
                current = candidate
                changed = True
                break  # restart the sweep on the smaller list

    return current


# ─────────────────────────── A2. risk scoring ───────────────────────────────
@dataclass(frozen=True)
class RiskScore:
    """Blast-radius summary of a patch (see :func:`risk_score`)."""

    files_touched: int
    lines_added: int
    lines_removed: int
    protected_hits: list[str]   # touched files matching a protected glob (sorted, unique)
    score: float                # 0..1 blast-radius score
    level: str                  # "low" | "medium" | "high"


def parse_unified_diff(diff: str) -> dict[str, tuple[int, int]]:
    """Parse a unified diff into ``{file_path: (added, removed)}`` line counts.

    Recognizes ``+++ b/<path>`` (or ``+++ <path>``) as the current file and then
    counts content lines starting with ``'+'`` / ``'-'`` for that file, excluding
    the ``+++`` / ``---`` file headers and ``@@`` hunk headers. ``/dev/null``
    targets (pure deletions) are ignored as a destination. Multiple files in one
    diff are handled; counts accumulate per resolved path. Standard library only.

    The leading ``b/`` (or ``a/``) prefix produced by ``git diff`` is stripped so
    the returned paths are repo-relative. A file that appears with a ``+++``
    header but no ``+``/``-`` content lines still shows up with ``(0, 0)``.
    """
    counts: dict[str, list[int]] = {}
    current: str | None = None

    for line in diff.splitlines():
        if line.startswith("+++"):
            # File header for the *new* side: "+++ b/path" or "+++ path".
            path = _strip_diff_path(line[3:].strip())
            if path == "/dev/null" or path == "":
                # Pure deletion (or malformed) — no destination file to attribute
                # added/removed lines to under the new path.
                current = None
            else:
                current = path
                counts.setdefault(path, [0, 0])
            continue
        if line.startswith("---"):
            # Old-side header — never counted as content; does not change the
            # current destination (the matching "+++" line does that).
            continue
        if line.startswith("@@"):
            # Hunk header — structural, never content.
            continue
        if current is None:
            continue
        if line.startswith("+"):
            counts[current][0] += 1
        elif line.startswith("-"):
            counts[current][1] += 1

    return {path: (added, removed) for path, (added, removed) in counts.items()}


def _strip_diff_path(token: str) -> str:
    """Strip a leading ``a/`` or ``b/`` git prefix (but leave ``/dev/null``)."""
    if token == "/dev/null":
        return token
    if token.startswith("a/") or token.startswith("b/"):
        return token[2:]
    return token


# A diff string or a precomputed {file: (added, removed)} mapping.
DiffLike: TypeAlias = "str | Mapping[str, tuple[int, int]]"


def risk_score(
    diff: DiffLike,
    *,
    protected: Sequence[str] = (),
    medium_files: int = 3,
    high_files: int = 8,
    medium_lines: int = 40,
    high_lines: int = 200,
) -> RiskScore:
    """Compute a blast-radius :class:`RiskScore` from a patch.

    ``diff`` is either a unified-diff string (parsed via
    :func:`parse_unified_diff`) or an already-computed
    ``{file: (added, removed)}`` mapping. ``protected`` is a list of fnmatch
    globs; any touched file matching one is a *protected hit* (matched
    case-insensitively against the whole path, mirroring the verifier's
    protected-path convention).

    Returns
    -------
    RiskScore
        - ``files_touched`` — number of distinct touched files.
        - ``lines_added`` / ``lines_removed`` — totals across all files.
        - ``protected_hits`` — sorted, unique touched files matching any glob.
        - ``score`` — bounded blast-radius score in ``[0, 1]`` (formula below).
        - ``level`` — ``'high'`` if there is any protected hit OR
          ``files_touched >= high_files`` OR ``total_lines >= high_lines``; else
          ``'medium'`` if ``files_touched >= medium_files`` OR
          ``total_lines >= medium_lines``; else ``'low'``.

    Score formula (monotone in both files and lines, bounded, then clamped)::

        files_term     = min(1.0, files_touched / high_files)
        lines_term     = min(1.0, total_lines   / high_lines)
        protected_term = 0.25 if protected_hits else 0.0
        score = min(1.0, 0.5 * files_term + 0.5 * lines_term + protected_term)

    With ``high_files``/``high_lines`` <= 0 the corresponding term saturates to
    ``1.0`` (any touch is treated as maximal) to avoid division by zero. The
    result is deterministic and pure.
    """
    file_counts = diff if isinstance(diff, Mapping) else parse_unified_diff(diff)

    touched = list(file_counts.keys())
    files_touched = len(touched)
    lines_added = sum(added for added, _removed in file_counts.values())
    lines_removed = sum(removed for _added, removed in file_counts.values())
    total_lines = lines_added + lines_removed

    # Protected hits: touched files matching any glob, case-insensitively on the
    # whole path; sorted + unique for a deterministic, stable list.
    protected_hits = sorted(
        {
            path
            for path in touched
            for glob in protected
            if fnmatch(path.lower(), glob.lower())
        }
    )

    # Bounded, monotone score; clamp to [0, 1]. Guard non-positive thresholds so
    # the term saturates instead of dividing by zero.
    files_term = 1.0 if high_files <= 0 else min(1.0, files_touched / high_files)
    lines_term = 1.0 if high_lines <= 0 else min(1.0, total_lines / high_lines)
    protected_term = 0.25 if protected_hits else 0.0
    score = min(1.0, 0.5 * files_term + 0.5 * lines_term + protected_term)

    if protected_hits or files_touched >= high_files or total_lines >= high_lines:
        level = "high"
    elif files_touched >= medium_files or total_lines >= medium_lines:
        level = "medium"
    else:
        level = "low"

    return RiskScore(
        files_touched=files_touched,
        lines_added=lines_added,
        lines_removed=lines_removed,
        protected_hits=protected_hits,
        score=score,
        level=level,
    )
