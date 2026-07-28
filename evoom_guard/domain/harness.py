# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Dependency-free contracts for explicit repository-local judge inputs."""

from __future__ import annotations

import ntpath
import posixpath
import re
from collections.abc import Sequence
from fnmatch import fnmatch

_PATTERN_CHARACTERS = frozenset("*?[]{}")
_WINDOWS_INVALID_CHARACTERS = frozenset('<>:"|?*')
_WINDOWS_RESERVED_STEMS = frozenset(
    {
        "aux",
        "clock$",
        "con",
        "nul",
        "prn",
        *(f"com{number}" for number in range(1, 10)),
        *(f"lpt{number}" for number in range(1, 10)),
        "com¹",
        "com²",
        "com³",
        "lpt¹",
        "lpt²",
        "lpt³",
    }
)
_WINDOWS_SHORT_ALIAS = re.compile(r".*~[0-9]+(?:\..*)?\Z", re.IGNORECASE)


class HarnessInputPolicyError(ValueError):
    """A trusted harness-input declaration is invalid or cannot be enforced."""


def is_windows_ambiguous_path_segment(segment: str) -> bool:
    """Return whether Win32 can reinterpret or redirect this path segment."""

    if (
        not segment
        or segment.endswith((" ", "."))
        or any(
            ord(character) < 32
            or ord(character) == 127
            or character in _WINDOWS_INVALID_CHARACTERS
            for character in segment
        )
        or _WINDOWS_SHORT_ALIAS.fullmatch(segment) is not None
    ):
        return True
    stem = segment.split(".", 1)[0].rstrip(" .").casefold()
    return stem in _WINDOWS_RESERVED_STEMS


def is_portable_repo_path(path: str) -> bool:
    """Return whether one exact path has unambiguous cross-platform spelling."""

    if (
        not path
        or "\\" in path
        or posixpath.isabs(path)
        or ntpath.isabs(path)
    ):
        return False
    parts = path.split("/")
    return all(
        part not in {"", ".", ".."}
        and not is_windows_ambiguous_path_segment(part)
        for part in parts
    )


def normalize_harness_inputs(values: Sequence[str]) -> tuple[str, ...]:
    """Validate canonical repository-relative harness files."""

    if isinstance(values, (str, bytes)):
        raise HarnessInputPolicyError(
            "harness_inputs must be a sequence of exact path strings"
        )

    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise HarnessInputPolicyError(
                "harness_inputs must contain only strings"
            )
        if (
            not is_portable_repo_path(value)
            or any(character in value for character in _PATTERN_CHARACTERS)
        ):
            raise HarnessInputPolicyError(
                "harness_inputs must contain exact non-empty repository-relative "
                "portable forward-slash paths, not globs, device names, aliases, "
                "or platform-ambiguous spellings"
            )
        parts = value.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise HarnessInputPolicyError(
                "harness_inputs must be normalized and cannot contain '.', '..', "
                "or empty path segments"
            )
        normalized.append(value)
    if len(set(normalized)) != len(normalized):
        raise HarnessInputPolicyError(
            "harness_inputs cannot contain duplicate paths"
        )
    if len({value.casefold() for value in normalized}) != len(normalized):
        raise HarnessInputPolicyError(
            "harness_inputs cannot contain case-colliding paths"
        )
    return tuple(sorted(normalized))


def is_harness_input_path(path: str, roots: Sequence[str]) -> bool:
    """Return whether ``path`` is one declared exact harness file."""

    normalized = path.casefold()
    return any(
        normalized == root.casefold()
        for root in normalize_harness_inputs(roots)
    )


def harness_input_path_conflicts(
    path: str,
    roots: Sequence[str],
) -> bool:
    """Return whether a candidate path is a declared input or its ancestor."""

    candidate = path.casefold()
    return any(
        candidate == root.casefold()
        or root.casefold().startswith(candidate + "/")
        for root in normalize_harness_inputs(roots)
    )


def setup_output_harness_conflicts(
    harness_inputs: Sequence[str],
    setup_output_globs: Sequence[str],
) -> tuple[str, ...]:
    """Return harness files a setup-fidelity exclusion would hide."""

    return tuple(
        path
        for path in normalize_harness_inputs(harness_inputs)
        if any(
            fnmatch(candidate.casefold(), pattern.casefold())
            for candidate in (
                "/".join(path.split("/")[:end]) + suffix
                for end in range(1, len(path.split("/")) + 1)
                for suffix in ("", "/")
            )
            for pattern in setup_output_globs
        )
    )


__all__ = [
    "HarnessInputPolicyError",
    "harness_input_path_conflicts",
    "is_harness_input_path",
    "is_portable_repo_path",
    "is_windows_ambiguous_path_segment",
    "normalize_harness_inputs",
    "setup_output_harness_conflicts",
]
