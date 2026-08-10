# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available - see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Canonical, materialized-change Blast Radius V2 contracts.

V2 deliberately does not parse a textual Git diff.  Rename, copy, binary, and
mode-only semantics cannot be reconstructed completely from every raw-diff
form, so callers must materialize the base/head relation first and provide one
explicit net change per affected path.  Invalid or unsupported representations
fail closed instead of being partially measured.
"""

from __future__ import annotations

import json
import unicodedata
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Final, Literal, TypeAlias, cast

from evoom_guard.domain.harness import is_portable_repo_path

BLAST_RADIUS_V2_FORMAT: Final = "EVOGUARD_BLAST_RADIUS_V2"
BLAST_RADIUS_V2_SCORE_FORMAT: Final = "EVOGUARD_BLAST_RADIUS_SCORE_V2"
MAX_MATERIALIZED_CHANGES_V2: Final = 10_000
MAX_MATERIALIZED_PATH_BYTES_V2: Final = 4_096
MAX_MATERIALIZED_COUNTER_V2: Final = (1 << 63) - 1
MAX_PROTECTED_PATTERNS_V2: Final = 10_000
MAX_PROTECTED_MATCH_EVALUATIONS_V2: Final = 2_000_000

MaterializedOperationV2: TypeAlias = Literal[
    "add", "modify", "delete", "rename", "copy", "mode"
]

_OPERATIONS: Final = ("add", "modify", "delete", "rename", "copy", "mode")
_CHANGE_KEYS: Final = frozenset(
    {
        "operation",
        "old_path",
        "new_path",
        "lines_added",
        "lines_removed",
        "binary",
    }
)
_ROOT_KEYS: Final = frozenset({"format", "changes"})


class BlastRadiusV2ContractError(ValueError):
    """The supplied V2 materialized-change contract is invalid or unsupported."""


def _contract_error(message: str) -> BlastRadiusV2ContractError:
    return BlastRadiusV2ContractError(f"blast-radius V2 contract: {message}")


def _validate_counter(value: object, *, field: str) -> int:
    if type(value) is not int:
        raise _contract_error(f"{field} must be an integer")
    counter = value
    if counter < 0 or counter > MAX_MATERIALIZED_COUNTER_V2:
        raise _contract_error(
            f"{field} must be between 0 and {MAX_MATERIALIZED_COUNTER_V2}"
        )
    return counter


def _validate_path(value: object, *, field: str, optional: bool) -> str | None:
    if value is None and optional:
        return None
    if type(value) is not str:
        expected = "a string or null" if optional else "a string"
        raise _contract_error(f"{field} must be {expected}")
    path = value
    if len(path.encode("utf-8")) > MAX_MATERIALIZED_PATH_BYTES_V2:
        raise _contract_error(f"{field} exceeds the UTF-8 byte limit")
    if unicodedata.normalize("NFC", path) != path:
        raise _contract_error(f"{field} must use NFC Unicode normalization")
    if not is_portable_repo_path(path):
        raise _contract_error(
            f"{field} must be one portable, normalized, repository-relative path"
        )
    if any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs"}
        for character in path
    ):
        raise _contract_error(f"{field} cannot contain control or format characters")
    if any(segment.casefold() == ".git" for segment in path.split("/")):
        raise _contract_error(f"{field} cannot address Git administrative paths")
    return path


def _validate_add(change: MaterializedChangeV2) -> None:
    if (
        change.old_path is not None
        or change.new_path is None
        or change.lines_removed != 0
    ):
        raise _contract_error(
            "add requires old_path=null, one new_path, and lines_removed=0"
        )


def _validate_delete(change: MaterializedChangeV2) -> None:
    if (
        change.old_path is None
        or change.new_path is not None
        or change.lines_added != 0
    ):
        raise _contract_error(
            "delete requires one old_path, new_path=null, and lines_added=0"
        )


def _validate_same_path(change: MaterializedChangeV2) -> None:
    old_path = change.old_path
    new_path = change.new_path
    if old_path is None or new_path is None or old_path != new_path:
        raise _contract_error(
            f"{change.operation} requires identical non-null old_path and new_path"
        )


def _validate_modify(change: MaterializedChangeV2) -> None:
    _validate_same_path(change)
    if not change.binary and change.lines_added == change.lines_removed == 0:
        raise _contract_error("a zero-line text modify must be represented as mode")


def _validate_mode(change: MaterializedChangeV2) -> None:
    _validate_same_path(change)
    if change.lines_added != 0 or change.lines_removed != 0:
        raise _contract_error("mode requires zero line counters")


def _validate_distinct_paths(change: MaterializedChangeV2) -> None:
    old_path = change.old_path
    new_path = change.new_path
    if old_path is None or new_path is None or old_path == new_path:
        raise _contract_error(
            f"{change.operation} requires distinct non-null old_path and new_path"
        )


def _validate_rename(change: MaterializedChangeV2) -> None:
    _validate_distinct_paths(change)


def _validate_copy(change: MaterializedChangeV2) -> None:
    _validate_distinct_paths(change)
    if change.lines_removed != 0:
        raise _contract_error("copy requires lines_removed=0")


_OPERATION_VALIDATORS: Final[
    dict[str, Callable[[MaterializedChangeV2], None]]
] = {
    "add": _validate_add,
    "modify": _validate_modify,
    "delete": _validate_delete,
    "rename": _validate_rename,
    "copy": _validate_copy,
    "mode": _validate_mode,
}


def _validate_change_semantics(change: MaterializedChangeV2) -> None:
    validator = _OPERATION_VALIDATORS.get(change.operation)
    if validator is None:  # retained as a fail-closed invariant
        raise _contract_error(f"unsupported operation: {change.operation!r}")
    validator(change)

    if change.binary and (change.lines_added != 0 or change.lines_removed != 0):
        raise _contract_error("binary changes require zero line counters")


@dataclass(frozen=True, slots=True)
class MaterializedChangeV2:
    """One explicit net base/head change under V2 materialization semantics.

    Text add/delete/copy counters are full destination/source line counts.
    Text rename counters are the full new-side lines added and old-side lines
    removed, not a similarity-diff approximation.  Text modify counters are
    exact changed-line counts.  Binary and mode-only records have zero line
    counters; their affected paths still contribute to the measurement.
    """

    operation: MaterializedOperationV2
    old_path: str | None
    new_path: str | None
    lines_added: int
    lines_removed: int
    binary: bool = False

    def __post_init__(self) -> None:
        if type(self.operation) is not str or self.operation not in _OPERATIONS:
            raise _contract_error(f"unsupported operation: {self.operation!r}")
        object.__setattr__(
            self,
            "old_path",
            _validate_path(self.old_path, field="old_path", optional=True),
        )
        object.__setattr__(
            self,
            "new_path",
            _validate_path(self.new_path, field="new_path", optional=True),
        )
        object.__setattr__(
            self,
            "lines_added",
            _validate_counter(self.lines_added, field="lines_added"),
        )
        object.__setattr__(
            self,
            "lines_removed",
            _validate_counter(self.lines_removed, field="lines_removed"),
        )
        if type(self.binary) is not bool:
            raise _contract_error("binary must be a boolean")
        _validate_change_semantics(self)

    @classmethod
    def from_dict(cls, value: object) -> MaterializedChangeV2:
        if type(value) is not dict:
            raise _contract_error("each changes entry must be an object")
        raw = cast(dict[object, object], value)
        if set(raw) != _CHANGE_KEYS:
            raise _contract_error(
                "each changes entry must contain exactly: "
                + ", ".join(sorted(_CHANGE_KEYS))
            )
        return cls(
            operation=cast(MaterializedOperationV2, raw["operation"]),
            old_path=cast(str | None, raw["old_path"]),
            new_path=cast(str | None, raw["new_path"]),
            lines_added=cast(int, raw["lines_added"]),
            lines_removed=cast(int, raw["lines_removed"]),
            binary=cast(bool, raw["binary"]),
        )

    @property
    def affected_paths(self) -> tuple[str, ...]:
        """Paths changed by the operation, excluding an unchanged copy source."""

        if self.operation == "add":
            return (cast(str, self.new_path),)
        if self.operation == "delete":
            return (cast(str, self.old_path),)
        if self.operation == "rename":
            return (cast(str, self.old_path), cast(str, self.new_path))
        return (cast(str, self.new_path),)

    def as_dict(self) -> dict[str, object]:
        return {
            "operation": self.operation,
            "old_path": self.old_path,
            "new_path": self.new_path,
            "lines_added": self.lines_added,
            "lines_removed": self.lines_removed,
            "binary": self.binary,
        }


def _change_sort_key(change: MaterializedChangeV2) -> tuple[object, ...]:
    return (
        change.affected_paths[0].casefold(),
        change.operation,
        change.old_path or "",
        change.new_path or "",
        change.lines_added,
        change.lines_removed,
        change.binary,
    )


@dataclass(frozen=True, slots=True)
class MaterializedChangeSetV2:
    """Canonical, immutable V2 input containing explicit net changes."""

    changes: tuple[MaterializedChangeV2, ...]
    format: str = BLAST_RADIUS_V2_FORMAT

    def __post_init__(self) -> None:
        if self.format != BLAST_RADIUS_V2_FORMAT:
            raise _contract_error(f"format must be {BLAST_RADIUS_V2_FORMAT!r}")
        if type(self.changes) is not tuple:
            raise _contract_error("changes must be an immutable tuple")
        if len(self.changes) > MAX_MATERIALIZED_CHANGES_V2:
            raise _contract_error("changes exceeds the entry limit")
        if any(type(change) is not MaterializedChangeV2 for change in self.changes):
            raise _contract_error("changes must contain only MaterializedChangeV2 values")

        canonical = tuple(sorted(self.changes, key=_change_sort_key))
        affected: list[str] = [
            path for change in canonical for path in change.affected_paths
        ]
        folded = [path.casefold() for path in affected]
        if len(set(folded)) != len(folded):
            raise _contract_error(
                "affected paths must be unique without cross-platform case collisions"
            )
        if sum(change.lines_added for change in canonical) > MAX_MATERIALIZED_COUNTER_V2:
            raise _contract_error("aggregate lines_added exceeds the counter limit")
        if sum(change.lines_removed for change in canonical) > MAX_MATERIALIZED_COUNTER_V2:
            raise _contract_error("aggregate lines_removed exceeds the counter limit")
        object.__setattr__(self, "changes", canonical)

    @classmethod
    def from_dict(cls, value: object) -> MaterializedChangeSetV2:
        if type(value) is not dict:
            raise _contract_error(
                "input must be a V2 object, not raw diff text or another representation"
            )
        raw = cast(dict[object, object], value)
        if set(raw) != _ROOT_KEYS:
            raise _contract_error("input must contain exactly format and changes")
        if raw["format"] != BLAST_RADIUS_V2_FORMAT:
            raise _contract_error(f"format must be {BLAST_RADIUS_V2_FORMAT!r}")
        changes = raw["changes"]
        if type(changes) is not list:
            raise _contract_error("changes must be an array")
        return cls(
            changes=tuple(
                MaterializedChangeV2.from_dict(change)
                for change in cast(list[object], changes)
            )
        )

    @property
    def affected_paths(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                (path for change in self.changes for path in change.affected_paths),
                key=lambda path: (path.casefold(), path),
            )
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "changes": [change.as_dict() for change in self.changes],
        }


def materialized_change_set_v2(value: object) -> MaterializedChangeSetV2:
    """Validate and canonicalize a V2 object; raw diff strings are rejected."""

    if type(value) is MaterializedChangeSetV2:
        return value
    return MaterializedChangeSetV2.from_dict(value)


def canonical_materialized_change_v2_bytes(value: object) -> bytes:
    """Return deterministic UTF-8 JSON bytes for one validated V2 input."""

    checked = materialized_change_set_v2(value)
    return json.dumps(
        checked.as_dict(),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _validate_protected_patterns(protected: Sequence[str]) -> tuple[str, ...]:
    if isinstance(protected, (str, bytes)):
        raise _contract_error("protected must be a sequence of path globs")
    patterns = tuple(protected)
    if len(patterns) > MAX_PROTECTED_PATTERNS_V2:
        raise _contract_error("protected exceeds the pattern limit")
    for pattern in patterns:
        if type(pattern) is not str or not pattern:
            raise _contract_error("protected patterns must be non-empty strings")
        if len(pattern.encode("utf-8")) > MAX_MATERIALIZED_PATH_BYTES_V2:
            raise _contract_error("a protected pattern exceeds the UTF-8 byte limit")
        if unicodedata.normalize("NFC", pattern) != pattern:
            raise _contract_error("protected patterns must use NFC normalization")
        if (
            pattern.startswith("/")
            or "\\" in pattern
            or "//" in pattern
            or any(part in {".", ".."} for part in pattern.split("/"))
            or any(
                unicodedata.category(character) in {"Cc", "Cf", "Cs"}
                for character in pattern
            )
        ):
            raise _contract_error(
                "protected patterns must be normalized repository-relative globs"
            )
    return patterns


def _validate_threshold(value: object, *, field: str) -> int:
    threshold = _validate_counter(value, field=field)
    if threshold == 0:
        raise _contract_error(f"{field} must be positive")
    return threshold


@dataclass(frozen=True, slots=True)
class BlastRadiusScoreV2:
    """Deterministic V2 measurement; it is not a vulnerability probability."""

    files_touched: int
    lines_added: int
    lines_removed: int
    protected_hits: tuple[str, ...]
    operation_counts: tuple[tuple[str, int], ...]
    binary_changes: int
    mode_only_changes: int
    score: float
    level: str
    format: str = BLAST_RADIUS_V2_SCORE_FORMAT

    def as_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "files_touched": self.files_touched,
            "lines_added": self.lines_added,
            "lines_removed": self.lines_removed,
            "protected_hits": list(self.protected_hits),
            "operation_counts": dict(self.operation_counts),
            "binary_changes": self.binary_changes,
            "mode_only_changes": self.mode_only_changes,
            "score": self.score,
            "level": self.level,
        }


def blast_radius_score_v2(
    materialized_change: object,
    *,
    protected: Sequence[str] = (),
    medium_files: int = 3,
    high_files: int = 8,
    medium_lines: int = 40,
    high_lines: int = 200,
) -> BlastRadiusScoreV2:
    """Measure one validated materialized change without parsing or guessing."""

    change_set = materialized_change_set_v2(materialized_change)
    patterns = _validate_protected_patterns(protected)
    medium_file_limit = _validate_threshold(medium_files, field="medium_files")
    high_file_limit = _validate_threshold(high_files, field="high_files")
    medium_line_limit = _validate_threshold(medium_lines, field="medium_lines")
    high_line_limit = _validate_threshold(high_lines, field="high_lines")
    if medium_file_limit > high_file_limit:
        raise _contract_error("medium_files cannot exceed high_files")
    if medium_line_limit > high_line_limit:
        raise _contract_error("medium_lines cannot exceed high_lines")

    touched = change_set.affected_paths
    if len(touched) * len(patterns) > MAX_PROTECTED_MATCH_EVALUATIONS_V2:
        raise _contract_error(
            "affected-path/protected-pattern product exceeds the matching-work limit"
        )
    lines_added = sum(change.lines_added for change in change_set.changes)
    lines_removed = sum(change.lines_removed for change in change_set.changes)
    total_lines = lines_added + lines_removed
    protected_hits = tuple(
        sorted(
            {
                path
                for path in touched
                for pattern in patterns
                if fnmatch(path.lower(), pattern.lower())
            },
            key=lambda path: (path.casefold(), path),
        )
    )
    operation_counts = tuple(
        (operation, sum(change.operation == operation for change in change_set.changes))
        for operation in _OPERATIONS
    )
    files_term = min(1.0, len(touched) / high_file_limit)
    lines_term = min(1.0, total_lines / high_line_limit)
    protected_term = 0.25 if protected_hits else 0.0
    score = min(1.0, 0.5 * files_term + 0.5 * lines_term + protected_term)

    if (
        protected_hits
        or len(touched) >= high_file_limit
        or total_lines >= high_line_limit
    ):
        level = "high"
    elif len(touched) >= medium_file_limit or total_lines >= medium_line_limit:
        level = "medium"
    else:
        level = "low"

    return BlastRadiusScoreV2(
        files_touched=len(touched),
        lines_added=lines_added,
        lines_removed=lines_removed,
        protected_hits=protected_hits,
        operation_counts=operation_counts,
        binary_changes=sum(change.binary for change in change_set.changes),
        mode_only_changes=sum(
            change.operation == "mode" for change in change_set.changes
        ),
        score=score,
        level=level,
    )


__all__ = [
    "BLAST_RADIUS_V2_FORMAT",
    "BLAST_RADIUS_V2_SCORE_FORMAT",
    "BlastRadiusScoreV2",
    "BlastRadiusV2ContractError",
    "MaterializedChangeSetV2",
    "MaterializedChangeV2",
    "MaterializedOperationV2",
    "blast_radius_score_v2",
    "canonical_materialized_change_v2_bytes",
    "materialized_change_set_v2",
]
