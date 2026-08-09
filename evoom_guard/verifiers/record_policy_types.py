# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Pure type/shape projection for effective policies in verdict records.

The public record verifier retains report mutation, contract selection, and the
operating-profile decision call.  This owner only returns immutable ordered
errors plus the already-validated profile selector.  It performs no I/O,
cleanup, process execution, hashing, or verdict/report mutation.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeGuard, cast

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_MODES = frozenset({"repo", "blackbox"})
_REQUESTED_ISOLATIONS = frozenset({"subprocess", "docker", "gvisor"})
_OPERATING_PROFILES = frozenset({"local", "protected", "hostile"})
_REPORT_INTEGRITIES = frozenset(
    {"same_process_candidate_writable", "external_process_isolated"}
)
_BOOLEAN_FIELDS = (
    "trust_setup_on_host",
    "allow_new_tests",
    "verifier_pack_required",
    "blackbox",
    "blackbox_only",
    "baseline_evidence",
    "require_demonstrated_fix",
)


@dataclass(frozen=True, slots=True)
class PolicyTypeProjection:
    """Ordered pure validation result consumed by the public verifier."""

    errors: tuple[str, ...]
    operating_profile: str | None


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> TypeGuard[int | float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return isinstance(value, int) or math.isfinite(value)


def _is_string_list(value: object) -> TypeGuard[list[str]]:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _is_nullable_string(value: object) -> bool:
    return value is None or isinstance(value, str)


def _known_string(value: object, allowed: frozenset[str]) -> bool:
    return isinstance(value, str) and value in allowed


def _schema_errors(
    policy: dict[str, Any],
    schema_version: object,
    *,
    policy_keys: frozenset[str],
    allowed_policy_keys: frozenset[str],
) -> list[str]:
    errors: list[str] = []
    missing = sorted(policy_keys - policy.keys())
    extra = sorted(
        key
        for key in policy
        if isinstance(key, str) and key not in allowed_policy_keys
    )
    if missing:
        errors.append(f"missing keys: {', '.join(missing)}")
    if extra:
        errors.append(
            f"unexpected schema-{schema_version} keys: {', '.join(extra)}"
        )
    if any(not isinstance(key, str) for key in policy):
        errors.append("all policy keys must be strings")
    return errors


def _execution_errors(policy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not _known_string(policy.get("mode"), _MODES):
        errors.append("mode must be repo or blackbox")
    if not _known_string(policy.get("isolation"), _REQUESTED_ISOLATIONS):
        errors.append("isolation must be subprocess, docker, or gvisor")
    docker_image = policy.get("docker_image")
    if docker_image is not None and not isinstance(docker_image, str):
        errors.append("docker_image must be a string or null")
    if not isinstance(policy.get("docker_network"), str):
        errors.append("docker_network must be a string")
    return errors


def _command_errors(policy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    test_command = policy.get("test_command")
    if not (
        test_command == "default:python -m pytest"
        or _is_string_list(test_command)
        and bool(test_command)
    ):
        errors.append("test_command must be the default marker or a non-empty string array")
    setup_command = policy.get("setup_command")
    if setup_command is not None and not (
        _is_string_list(setup_command) and bool(setup_command)
    ):
        errors.append("setup_command must be a non-empty string array or null")
    return errors


def _collection_and_boolean_errors(policy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for field in ("setup_output_globs", "protected", "allow"):
        if not _is_string_list(policy.get(field)):
            errors.append(f"{field} must be an array of strings")
    for field in _BOOLEAN_FIELDS:
        if not isinstance(policy.get(field), bool):
            errors.append(f"{field} must be a boolean")
    if "strict_harness" in policy and not isinstance(policy["strict_harness"], bool):
        errors.append("strict_harness must be a boolean when present")
    return errors


def _harness_errors(
    policy: dict[str, Any],
    *,
    harness_input_validator: Callable[[object], bool],
    setup_conflict_predicate: Callable[[str, list[str]], bool],
) -> list[str]:
    if "harness_inputs" not in policy:
        return []
    if not harness_input_validator(policy["harness_inputs"]):
        return [
            "harness_inputs must be a non-empty sorted unique array of exact "
            "canonical repository-relative paths when present"
        ]
    harness_inputs = cast(list[str], policy["harness_inputs"])
    setup_globs = policy.get("setup_output_globs")
    if not _is_string_list(setup_globs):
        return []
    conflicts = [
        path
        for path in harness_inputs
        if setup_conflict_predicate(path, setup_globs)
    ]
    if conflicts:
        return [
            "setup_output_globs cannot exclude harness_inputs: " + ", ".join(conflicts)
        ]
    return []


def _profile_and_limit_errors(
    policy: dict[str, Any],
    *,
    operating_profile_supported: bool,
) -> tuple[list[str], str | None]:
    errors: list[str] = []
    operating_profile = policy.get("operating_profile")
    valid_profile = (
        operating_profile_supported
        and isinstance(operating_profile, str)
        and operating_profile in _OPERATING_PROFILES
    )
    if operating_profile_supported and "operating_profile" in policy and not valid_profile:
        errors.append(
            "operating_profile must be local, protected, or hostile when present"
        )
    timeout = policy.get("timeout")
    if not _is_int(timeout) or timeout <= 0:
        errors.append("timeout must be a positive integer")
    memory = policy.get("mem_limit_mb")
    if not _is_int(memory) or memory < 0:
        errors.append("mem_limit_mb must be a non-negative integer")
    return errors, cast(str, operating_profile) if valid_profile else None


def _assurance_limit_errors(policy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    expected_pack = policy.get("expect_verifier_pack_sha256")
    if expected_pack is not None and not (
        isinstance(expected_pack, str) and bool(_HEX_64.fullmatch(expected_pack))
    ):
        errors.append("expect_verifier_pack_sha256 must be a lowercase SHA-256 or null")
    report_floor = policy.get("require_report_integrity")
    if report_floor is not None and not _known_string(
        report_floor, _REPORT_INTEGRITIES
    ):
        errors.append("require_report_integrity is invalid")
    isolation_floor = policy.get("require_candidate_isolation")
    if isolation_floor is not None and not _known_string(
        isolation_floor, _REQUESTED_ISOLATIONS
    ):
        errors.append("require_candidate_isolation is invalid")
    coverage = policy.get("min_diff_coverage")
    if coverage is not None and not (_is_number(coverage) and 0 <= coverage <= 100):
        errors.append("min_diff_coverage must be a finite number in 0..100 or null")
    return errors


def _identity_and_semantic_errors(policy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for field in ("policy_id", "policy_version"):
        if not _is_nullable_string(policy.get(field)):
            errors.append(f"{field} must be a string or null")
    mode = policy.get("mode")
    blackbox = policy.get("blackbox")
    if isinstance(blackbox, bool) and isinstance(mode, str):
        if blackbox != (mode == "blackbox"):
            errors.append("mode must agree with blackbox")
    if policy.get("blackbox_only") is True and blackbox is not True:
        errors.append("blackbox_only requires blackbox")
    expected_pack = policy.get("expect_verifier_pack_sha256")
    if expected_pack is not None and policy.get("verifier_pack_required") is not True:
        errors.append("an expected pack digest requires verifier_pack_required")
    return errors


def project_policy_type_validation(
    policy: dict[str, Any],
    schema_version: object,
    *,
    policy_keys: frozenset[str],
    allowed_policy_keys: frozenset[str],
    harness_input_validator: Callable[[object], bool],
    setup_conflict_predicate: Callable[[str, list[str]], bool],
) -> PolicyTypeProjection:
    """Project exact ordered type/shape errors without changing authority."""

    errors = _schema_errors(
        policy,
        schema_version,
        policy_keys=policy_keys,
        allowed_policy_keys=allowed_policy_keys,
    )
    errors.extend(_execution_errors(policy))
    errors.extend(_command_errors(policy))
    errors.extend(_collection_and_boolean_errors(policy))
    errors.extend(
        _harness_errors(
            policy,
            harness_input_validator=harness_input_validator,
            setup_conflict_predicate=setup_conflict_predicate,
        )
    )
    profile_errors, operating_profile = _profile_and_limit_errors(
        policy,
        operating_profile_supported="operating_profile" in allowed_policy_keys,
    )
    errors.extend(profile_errors)
    errors.extend(_assurance_limit_errors(policy))
    errors.extend(_identity_and_semantic_errors(policy))
    return PolicyTypeProjection(tuple(errors), operating_profile)


__all__ = ["PolicyTypeProjection", "project_policy_type_validation"]
