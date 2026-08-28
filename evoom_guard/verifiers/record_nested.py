# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ------------------------------------------------------------------------------
"""Pure nested-object validation for supported verdict records.

The public verifier owns report ordering and rendering.  This module only
projects assurance and attestation objects into immutable missing/type/shape
error tuples; it performs no I/O and mutates neither input nor report state.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, TypeGuard

from evoom_guard.verdict_contract_v1_11 import (
    EXECUTION_STATES,
    REQUIRED_ASSURANCE,
    REQUIRED_ATTESTATION,
)
from evoom_guard.verifiers.junit_oracle import (
    JUNIT_COMPOSITE_DIGEST_FORMAT,
    JUNIT_REPORT_SET_DIGEST_FORMAT,
    JUNIT_XML_DIGEST_FORMAT,
)

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_UTC_SECONDS = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_ISOLATIONS = frozenset({"not_run", "subprocess", "docker", "gvisor"})
_SETUP_ISOLATIONS = frozenset(
    {"subprocess", "docker", "gvisor", "subprocess_host_opt_in", "unavailable"}
)
_REPORT_INTEGRITIES = frozenset(
    {
        "same_process_candidate_writable",
        "external_process_isolated",
        "not_applicable_static_gate",
        "not_applicable_not_run",
    }
)
_OVERALL_PROFILES = frozenset(
    {
        "static_gate",
        "preflight",
        "execution_incomplete_before_tests",
        "execution_incomplete",
        "repo_native_same_process",
        "isolated_repo_native",
        "mixed_host_setup_repo_native",
        "black_box_external_judge",
        "composite_blackbox_repo_native",
        "blackbox_composite_short_circuit",
    }
)
_REPO_SUITE_STATES = frozenset(
    {
        "not_required_blackbox_only",
        "required_not_run_short_circuit",
        "required_not_started",
        "required_started_incomplete",
        "composed_completed",
    }
)
_PACK_INTEGRITIES = frozenset(
    {
        "not_evaluated_static_gate",
        "not_evaluated_missing",
        "invalid",
        "snapshot_identity_mismatch",
        "verified_snapshot_pre_execution",
        "verified_snapshot_pre_post",
        "verified_snapshot_read_only",
        "snapshot_changed",
        "not_evaluated",
    }
)
_PACK_SECRECY = frozenset(
    {
        "not_evaluated_static_gate",
        "not_evaluated_no_execution",
        "readable_in_judge_process",
        "not_evaluated_no_candidate_execution",
        "reachable_same_host",
        "unmounted_from_candidate",
    }
)
_PACK_ASSURANCE_KEYS = frozenset(
    {
        "configured",
        "present",
        "integrity",
        "identity_verified",
        "execution_state",
        "secrecy",
        "snapshot_sha256",
    }
)
_JUNIT_PHASE_FORMATS = frozenset(
    {JUNIT_XML_DIGEST_FORMAT, JUNIT_REPORT_SET_DIGEST_FORMAT}
)
_JUNIT_TOP_FORMATS = frozenset(
    {
        JUNIT_XML_DIGEST_FORMAT,
        JUNIT_REPORT_SET_DIGEST_FORMAT,
        "EVOGUARD_JUNIT_COMPOSITE_V1",
        JUNIT_COMPOSITE_DIGEST_FORMAT,
    }
)
_ASSURANCE_STRING_FIELDS = (
    "execution_state",
    "execution_phase",
    "harness_integrity",
    "report_integrity",
    "candidate_isolation",
    "suite_isolation",
    "runtime_continuity",
    "overall_profile",
)
_ATTESTATION_STRING_FIELDS = (
    "created_utc",
    "guard_version",
    "mode",
    "candidate_sha256",
    "policy_sha256",
    "execution_state",
    "execution_phase",
    "delivered_isolation",
    "effective_candidate_isolation",
)
_PACK_BOOL_FIELDS = (
    "verifier_pack_present",
    "verifier_pack_started",
    "verifier_pack_completed",
)
_PACK_INT_FIELDS = ("verifier_pack_tests_passed", "verifier_pack_tests_total")
_REPO_INT_FIELDS = (
    "repo_suite_tests_passed",
    "repo_suite_tests_total",
    "repo_suite_returncode",
)
_REPO_BOOL_FIELDS = (
    "repo_suite_started",
    "repo_suite_completed",
    "repo_suite_passed",
)
_ATTESTATION_NULLABLE_STRING_FIELDS = (
    "junit_sha256",
    "junit_digest_format",
    "verifier_pack_junit_sha256",
    "verifier_pack_junit_digest_format",
    "repo_suite_state",
    "repo_suite_junit_sha256",
    "repo_suite_junit_digest_format",
    "repo_suite_verdict_source",
)
_PACK_NULLABLE_STRING_FIELDS = (
    "verifier_pack_sha256",
    "verifier_pack_digest_format",
)


@dataclass(frozen=True, slots=True)
class NestedObjectValidation:
    """Pure validation projection for one present nested object."""

    missing_fields: tuple[str, ...]
    type_errors: tuple[str, ...]
    shape_errors: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NestedValidationProjection:
    """Presence-aware assurance and attestation validation results."""

    assurance: NestedObjectValidation | None
    attestation: NestedObjectValidation | None


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_nullable_int(value: object) -> bool:
    return value is None or _is_int(value)


def _is_nullable_bool(value: object) -> bool:
    return value is None or isinstance(value, bool)


def _is_nullable_string(value: object) -> bool:
    return value is None or isinstance(value, str)


def _known_string(value: object, allowed: frozenset[str]) -> bool:
    return isinstance(value, str) and value in allowed


def _valid_sha256(value: object) -> bool:
    return isinstance(value, str) and _HEX_64.fullmatch(value) is not None


def _valid_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str) or _UTC_SECONDS.fullmatch(value) is None:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def _field_type_errors(
    value: dict[str, Any],
    fields: tuple[str, ...],
    predicate: Callable[[object], bool],
    requirement: str,
) -> list[str]:
    return [
        f"{field} {requirement}"
        for field in fields
        if field in value and not predicate(value[field])
    ]


def _allows_null_effective_isolation(attestation: dict[str, Any]) -> bool:
    return (
        attestation.get("effective_candidate_isolation") is None
        and attestation.get("execution_state") == "not_started"
        and attestation.get("test_command_started") is False
        and attestation.get("delivered_isolation") == "not_run"
    )


def _pack_shape_errors(pack: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = sorted(_PACK_ASSURANCE_KEYS - pack.keys())
    if missing:
        errors.append(f"missing pack assurance keys: {', '.join(missing)}")
    if pack.get("configured") is not True:
        errors.append("configured must be true")
    if not _is_nullable_bool(pack.get("present")):
        errors.append("present must be a boolean or null")
    if not _known_string(pack.get("integrity"), _PACK_INTEGRITIES):
        errors.append("integrity is invalid")
    if not _is_nullable_bool(pack.get("identity_verified")):
        errors.append("identity_verified must be a boolean or null")
    if not _known_string(pack.get("execution_state"), EXECUTION_STATES):
        errors.append("execution_state is invalid")
    if not _known_string(pack.get("secrecy"), _PACK_SECRECY):
        errors.append("secrecy is invalid")
    snapshot = pack.get("snapshot_sha256")
    if snapshot is not None and not _valid_sha256(snapshot):
        errors.append("snapshot_sha256 must be a lowercase SHA-256 or null")
    return errors


def _assurance_type_errors(assurance: dict[str, Any]) -> list[str]:
    errors = _field_type_errors(
        assurance,
        _ASSURANCE_STRING_FIELDS,
        lambda value: isinstance(value, str),
        "must be a string",
    )
    if "setup_isolation" in assurance and not _is_nullable_string(
        assurance["setup_isolation"]
    ):
        errors.append("setup_isolation must be a string or null")
    pack = assurance.get("verifier_pack")
    if pack is not None and not isinstance(pack, dict):
        errors.append("verifier_pack must be an object or null")
    return errors


def _assurance_nested_shape_errors(assurance: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    pack = assurance.get("verifier_pack")
    if isinstance(pack, dict):
        errors.extend(_pack_shape_errors(pack))
    repo_suite = assurance.get("repo_native_suite")
    if repo_suite is not None and not _known_string(repo_suite, _REPO_SUITE_STATES):
        errors.append("repo_native_suite is invalid")
    return errors


def _assurance_shape_errors(assurance: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not _known_string(assurance.get("execution_state"), EXECUTION_STATES):
        errors.append("execution_state is invalid")
    phase = assurance.get("execution_phase")
    if not (isinstance(phase, str) and bool(phase)):
        errors.append("execution_phase must be non-empty")
    if assurance.get("harness_integrity") != "pre_gate_enforced":
        errors.append("harness_integrity must be pre_gate_enforced")
    if not _known_string(assurance.get("report_integrity"), _REPORT_INTEGRITIES):
        errors.append("report_integrity is invalid")
    for field in ("candidate_isolation", "suite_isolation"):
        if not _known_string(assurance.get(field), _ISOLATIONS):
            errors.append(f"{field} is invalid")
    setup_isolation = assurance.get("setup_isolation")
    if setup_isolation is not None and not _known_string(
        setup_isolation, _SETUP_ISOLATIONS
    ):
        errors.append("setup_isolation is invalid")
    if not _known_string(assurance.get("overall_profile"), _OVERALL_PROFILES):
        errors.append("overall_profile is invalid")
    errors.extend(_assurance_nested_shape_errors(assurance))
    return errors


def _attestation_type_errors(attestation: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for field in _ATTESTATION_STRING_FIELDS:
        if field not in attestation:
            continue
        value = attestation[field]
        if field == "effective_candidate_isolation" and _allows_null_effective_isolation(
            attestation
        ):
            continue
        if not isinstance(value, str):
            errors.append(f"{field} must be a string")
    if "effective_policy" in attestation and not isinstance(
        attestation["effective_policy"], dict
    ):
        errors.append("effective_policy must be an object")
    if "test_command_started" in attestation and not isinstance(
        attestation["test_command_started"], bool
    ):
        errors.append("test_command_started must be a boolean")
    errors.extend(
        _field_type_errors(
            attestation,
            ("candidate_invocations",),
            _is_nullable_int,
            "must be an integer or null",
        )
    )
    errors.extend(
        _field_type_errors(
            attestation,
            ("candidate_launcher_invocation_observed",),
            _is_nullable_bool,
            "must be a boolean or null",
        )
    )
    errors.extend(
        _field_type_errors(
            attestation,
            _PACK_BOOL_FIELDS,
            _is_nullable_bool,
            "must be a boolean or null",
        )
    )
    errors.extend(
        _field_type_errors(
            attestation,
            _PACK_INT_FIELDS,
            _is_nullable_int,
            "must be an integer or null",
        )
    )
    errors.extend(
        _field_type_errors(
            attestation,
            _REPO_INT_FIELDS,
            _is_nullable_int,
            "must be an integer or null",
        )
    )
    errors.extend(
        _field_type_errors(
            attestation,
            _REPO_BOOL_FIELDS,
            _is_nullable_bool,
            "must be a boolean or null",
        )
    )
    errors.extend(
        _field_type_errors(
            attestation,
            _ATTESTATION_NULLABLE_STRING_FIELDS,
            _is_nullable_string,
            "must be a string or null",
        )
    )
    errors.extend(
        _field_type_errors(
            attestation,
            _PACK_NULLABLE_STRING_FIELDS,
            _is_nullable_string,
            "must be a string or null",
        )
    )
    return errors


def _recognized_digest_pair(
    digest: object,
    digest_format: object,
    allowed_formats: frozenset[str],
) -> bool:
    return (digest is None and digest_format is None) or (
        _valid_sha256(digest) and _known_string(digest_format, allowed_formats)
    )


def _attestation_identity_shape_errors(attestation: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not _valid_utc_timestamp(attestation.get("created_utc")):
        errors.append("created_utc must be a valid YYYY-MM-DDTHH:MM:SSZ timestamp")
    guard_version = attestation.get("guard_version")
    if not (isinstance(guard_version, str) and bool(guard_version)):
        errors.append("guard_version must be non-empty")
    if not _known_string(attestation.get("mode"), frozenset({"repo", "blackbox"})):
        errors.append("mode is invalid")
    if not _valid_sha256(attestation.get("candidate_sha256")):
        errors.append("candidate_sha256 must be a lowercase SHA-256")
    if not _valid_sha256(attestation.get("policy_sha256")):
        errors.append("policy_sha256 must be a lowercase SHA-256")
    return errors


def _attestation_junit_shape_errors(attestation: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not _recognized_digest_pair(
        attestation.get("junit_sha256"),
        attestation.get("junit_digest_format"),
        _JUNIT_TOP_FORMATS,
    ):
        errors.append("junit digest and format must form a recognized SHA-256 pair")
    if "repo_suite_junit_digest_format" in attestation and not _recognized_digest_pair(
        attestation.get("repo_suite_junit_sha256"),
        attestation.get("repo_suite_junit_digest_format"),
        _JUNIT_PHASE_FORMATS,
    ):
        errors.append(
            "repo-suite JUnit digest and format must form a recognized SHA-256 pair"
        )
    if "verifier_pack_junit_digest_format" in attestation and not _recognized_digest_pair(
        attestation.get("verifier_pack_junit_sha256"),
        attestation.get("verifier_pack_junit_digest_format"),
        frozenset({JUNIT_XML_DIGEST_FORMAT}),
    ):
        errors.append(
            "verifier-pack JUnit digest and format must form a recognized SHA-256 pair"
        )
    return errors


def _attestation_execution_shape_errors(attestation: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not _known_string(attestation.get("execution_state"), EXECUTION_STATES):
        errors.append("execution_state is invalid")
    phase = attestation.get("execution_phase")
    if not (isinstance(phase, str) and bool(phase)):
        errors.append("execution_phase must be non-empty")
    if not _known_string(attestation.get("delivered_isolation"), _ISOLATIONS):
        errors.append("delivered_isolation is invalid")
    effective = attestation.get("effective_candidate_isolation")
    if not (
        _known_string(effective, _ISOLATIONS)
        or _allows_null_effective_isolation(attestation)
    ):
        errors.append("effective_candidate_isolation is invalid")
    invocations = attestation.get("candidate_invocations")
    if _is_int(invocations) and invocations < 0:
        errors.append("candidate_invocations must be non-negative")
    return errors


def _attestation_shape_errors(attestation: dict[str, Any]) -> list[str]:
    return [
        *_attestation_identity_shape_errors(attestation),
        *_attestation_junit_shape_errors(attestation),
        *_attestation_execution_shape_errors(attestation),
    ]


def project_nested_validation(
    assurance: dict[str, Any] | None,
    attestation: dict[str, Any] | None,
) -> NestedValidationProjection:
    """Return an immutable validation projection without rendering a report."""

    assurance_result = (
        None
        if assurance is None
        else NestedObjectValidation(
            missing_fields=tuple(sorted(REQUIRED_ASSURANCE - assurance.keys())),
            type_errors=tuple(_assurance_type_errors(assurance)),
            shape_errors=tuple(_assurance_shape_errors(assurance)),
        )
    )
    attestation_result = (
        None
        if attestation is None
        else NestedObjectValidation(
            missing_fields=tuple(sorted(REQUIRED_ATTESTATION - attestation.keys())),
            type_errors=tuple(_attestation_type_errors(attestation)),
            shape_errors=tuple(_attestation_shape_errors(attestation)),
        )
    )
    return NestedValidationProjection(
        assurance=assurance_result,
        attestation=attestation_result,
    )


__all__ = [
    "NestedObjectValidation",
    "NestedValidationProjection",
    "project_nested_validation",
]
