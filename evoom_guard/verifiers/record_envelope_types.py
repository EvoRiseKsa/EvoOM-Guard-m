# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ------------------------------------------------------------------------------
"""Pure top-level type projection for verdict-record envelopes.

The public record verifier retains report mutation, check sequencing, schema
selection, semantic validation, and verdict authority. This owner only returns
immutable ordered type errors. It performs no I/O, hashing, execution, cleanup,
serialization, policy interpretation, or report mutation.
"""

from __future__ import annotations

import math
from typing import Any, TypeGuard

_STRING_FIELDS = (
    "schema_version",
    "tool",
    "tool_version",
    "verdict",
    "reason_code",
    "reason",
    "risk_level",
    "execution_state",
    "execution_phase",
    "isolation",
    "diagnostics",
)
_BOOLEAN_FIELDS = ("passed", "test_command_ran")
_NULLABLE_INTEGER_FIELDS = ("tests_passed", "tests_total")
_STRING_LIST_FIELDS = ("files_changed", "protected_violations")
_NULLABLE_STRING_FIELDS = ("verdict_source", "source", "base_reconstruction")
_NULLABLE_OBJECT_FIELDS = ("diff_coverage", "baseline")


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> TypeGuard[int | float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return isinstance(value, int) or math.isfinite(value)


def _is_string_list(value: object) -> TypeGuard[list[str]]:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _is_nullable_int(value: object) -> bool:
    return value is None or _is_int(value)


def _is_nullable_string(value: object) -> bool:
    return value is None or isinstance(value, str)


def _string_field_errors(record: dict[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    for field in _STRING_FIELDS:
        if field in record and not isinstance(record[field], str):
            errors.append(f"{field} must be a string")
    return tuple(errors)


def _boolean_field_errors(record: dict[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    for field in _BOOLEAN_FIELDS:
        if field in record and not isinstance(record[field], bool):
            errors.append(f"{field} must be a boolean")
    return tuple(errors)


def _numeric_field_errors(record: dict[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    if "exit_code" in record and not _is_int(record["exit_code"]):
        errors.append("exit_code must be an integer")
    if "risk_score" in record and not _is_number(record["risk_score"]):
        errors.append("risk_score must be a number")
    return tuple(errors)


def _nullable_integer_errors(record: dict[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    for field in _NULLABLE_INTEGER_FIELDS:
        if field in record and not _is_nullable_int(record[field]):
            errors.append(f"{field} must be a non-boolean integer or null")
    return tuple(errors)


def _string_list_errors(record: dict[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    for field in _STRING_LIST_FIELDS:
        if field in record and not _is_string_list(record[field]):
            errors.append(f"{field} must be an array of strings")
    return tuple(errors)


def _nullable_string_errors(record: dict[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    for field in _NULLABLE_STRING_FIELDS:
        if field in record and not _is_nullable_string(record[field]):
            errors.append(f"{field} must be a string or null")
    return tuple(errors)


def _nullable_object_errors(record: dict[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    for field in _NULLABLE_OBJECT_FIELDS:
        if field in record and record[field] is not None and not isinstance(record[field], dict):
            errors.append(f"{field} must be an object or null")
    return tuple(errors)


def _assurance_object_errors(record: dict[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    if "assurance" in record and not isinstance(record["assurance"], dict):
        errors.append("assurance must be an object")
    if (
        "attestation" in record
        and record["attestation"] is not None
        and not isinstance(record["attestation"], dict)
    ):
        errors.append("attestation must be an object or null")
    return tuple(errors)


def project_envelope_type_errors(record: dict[str, Any]) -> tuple[str, ...]:
    """Return exact ordered top-level type errors without mutating input state."""

    return (
        *_string_field_errors(record),
        *_boolean_field_errors(record),
        *_numeric_field_errors(record),
        *_nullable_integer_errors(record),
        *_string_list_errors(record),
        *_nullable_string_errors(record),
        *_nullable_object_errors(record),
        *_assurance_object_errors(record),
    )
