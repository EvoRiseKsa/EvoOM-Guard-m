# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ------------------------------------------------------------------------------
"""Pure type/shape projection for diff-coverage evidence in verdict records.

The public record verifier retains report mutation, sequencing, and policy
semantics. This owner only returns immutable ordered validation errors. It
performs no I/O, hashing, process execution, cleanup, or verdict mutation.
"""

from __future__ import annotations

import math
from typing import Any, TypeGuard

_MEASURED_COVERAGE_KEYS = frozenset(
    {
        "measured",
        "percent",
        "executed",
        "total",
        "files",
        "unmeasured_files",
        "caveat",
    }
)
_UNMEASURED_COVERAGE_KEYS = frozenset({"measured", "note"})
_UNMEASURED_COVERAGE_DETAIL_KEYS = frozenset({"measured", "note", "unmeasured_files", "caveat"})
_FILE_DETAIL_KEYS = frozenset({"executed", "missed"})
_FILE_DETAIL_KEYS_WITH_NOTE = frozenset({"executed", "missed", "note"})


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> TypeGuard[int | float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return isinstance(value, int) or math.isfinite(value)


def _is_string_list(value: object) -> TypeGuard[list[str]]:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _positive_line_array(value: object) -> TypeGuard[list[int]]:
    return (
        isinstance(value, list)
        and all(_is_int(item) and item > 0 for item in value)
        and value == sorted(set(value))
    )


def _coverage_path(value: object, *, python: bool) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/"):
        return False
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return False
    return value.endswith(".py") if python else not value.endswith(".py")


def _measured_scalar_errors(coverage: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    percent = coverage.get("percent")
    executed = coverage.get("executed")
    total = coverage.get("total")
    if not (_is_number(percent) and 0 <= percent <= 100):
        errors.append("percent must be a finite number in 0..100")
    if not (_is_int(executed) and _is_int(total) and 0 <= executed <= total):
        errors.append("executed/total must be non-negative ordered integers")
    return errors


def _file_detail_projection(path: object, detail: object) -> tuple[list[str], int, int]:
    if not _coverage_path(path, python=True):
        return ["files keys must be safe repo-relative .py paths"], 0, 0
    if not isinstance(detail, dict) or any(not isinstance(key, str) for key in detail):
        return [f"files[{path!r}] must be an object with string keys"], 0, 0

    errors: list[str] = []
    detail_keys = frozenset(detail)
    if detail_keys not in (_FILE_DETAIL_KEYS, _FILE_DETAIL_KEYS_WITH_NOTE):
        errors.append(f"files[{path!r}] has an invalid producer shape")
    executed_lines = detail.get("executed")
    missed_lines = detail.get("missed")
    if not _positive_line_array(executed_lines) or not _positive_line_array(missed_lines):
        errors.append(f"files[{path!r}] executed/missed must be sorted unique positive lines")
        return errors, 0, 0
    if set(executed_lines) & set(missed_lines):
        errors.append(f"files[{path!r}] executed and missed lines overlap")
    note = detail.get("note")
    if "note" in detail and not (isinstance(note, str) and bool(note)):
        errors.append(f"files[{path!r}].note must be non-empty")
    return errors, len(executed_lines), len(executed_lines) + len(missed_lines)


def _measured_file_projection(
    files: object,
) -> tuple[list[str], int, int]:
    if not isinstance(files, dict):
        return ["files must be an object"], 0, 0
    errors: list[str] = []
    file_executed = 0
    file_total = 0
    for path, detail in files.items():
        detail_errors, detail_executed, detail_total = _file_detail_projection(
            path,
            detail,
        )
        errors.extend(detail_errors)
        file_executed += detail_executed
        file_total += detail_total
    return errors, file_executed, file_total


def _measured_path_and_caveat_errors(coverage: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    unmeasured = coverage.get("unmeasured_files")
    if not (
        _is_string_list(unmeasured)
        and unmeasured == sorted(set(unmeasured))
        and all(_coverage_path(path, python=False) for path in unmeasured)
    ):
        errors.append("unmeasured_files must be sorted unique safe non-Python paths")
    caveat = coverage.get("caveat")
    if not (isinstance(caveat, str) and bool(caveat)):
        errors.append("caveat must be a non-empty string")
    return errors


def _measured_consistency_errors(
    coverage: dict[str, Any],
    *,
    file_executed: int,
    file_total: int,
) -> list[str]:
    errors: list[str] = []
    executed = coverage.get("executed")
    total = coverage.get("total")
    percent = coverage.get("percent")
    if _is_int(executed) and executed != file_executed:
        errors.append("executed does not equal the per-file executed-line total")
    if _is_int(total) and total != file_total:
        errors.append("total does not equal the per-file measurable-line total")
    if _is_number(percent) and _is_int(executed) and _is_int(total):
        calculated = round(100.0 * executed / total, 1) if total else 100.0
        if percent != calculated:
            errors.append(f"percent must equal the producer calculation {calculated}")
    return errors


def _measured_errors(coverage: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if frozenset(coverage) != _MEASURED_COVERAGE_KEYS:
        errors.append("measured coverage must contain exactly the seven producer keys")
    errors.extend(_measured_scalar_errors(coverage))
    file_errors, file_executed, file_total = _measured_file_projection(coverage.get("files"))
    errors.extend(file_errors)
    errors.extend(_measured_path_and_caveat_errors(coverage))
    errors.extend(
        _measured_consistency_errors(
            coverage,
            file_executed=file_executed,
            file_total=file_total,
        )
    )
    return errors


def _unmeasured_errors(coverage: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    keys = frozenset(coverage)
    if keys not in (_UNMEASURED_COVERAGE_KEYS, _UNMEASURED_COVERAGE_DETAIL_KEYS):
        errors.append("unmeasured coverage has an invalid producer shape")
    note = coverage.get("note")
    if not (isinstance(note, str) and bool(note)):
        errors.append("unmeasured coverage note must be non-empty")
    if keys == _UNMEASURED_COVERAGE_DETAIL_KEYS:
        unmeasured = coverage.get("unmeasured_files")
        if not (
            _is_string_list(unmeasured)
            and unmeasured == sorted(set(unmeasured))
            and all(isinstance(path, str) and bool(path) for path in unmeasured)
        ):
            errors.append("unmeasured_files must be a sorted unique string array")
        caveat = coverage.get("caveat")
        if not (isinstance(caveat, str) and bool(caveat)):
            errors.append("unmeasured coverage caveat must be non-empty")
    return errors


def project_diff_coverage_type_errors(coverage: dict[str, Any]) -> tuple[str, ...]:
    """Return exact ordered producer-shape errors without mutating input state."""

    if any(not isinstance(key, str) for key in coverage):
        return ("all diff_coverage keys must be strings",)
    measured = coverage.get("measured")
    if measured is True:
        return tuple(_measured_errors(coverage))
    if measured is False:
        return tuple(_unmeasured_errors(coverage))
    return ("measured must be a boolean",)
