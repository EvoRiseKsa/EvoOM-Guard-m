"""Offline semantic verification for EvoGuard verdict records.

This module deliberately does not verify a detached signature or re-run a
candidate.  It answers a narrower question: is a schema-1.11 record internally
consistent with the public EvoGuard contract?  Signature verification remains
the responsibility of ``verify-verdict``; admission systems should normally run
both checks.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime
from typing import Any, TypeGuard, cast

from evoom_guard import verdict_contract_v1_11 as _contract
from evoom_guard.pack_manifest import PACK_DIGEST_FORMAT
from evoom_guard.record_verification.isolation import (
    check_isolation as _check_isolation,
)
from evoom_guard.record_verification.report import (
    RECORD_VERIFIER_VERSION as RECORD_VERIFIER_VERSION,
)
from evoom_guard.record_verification.report import (
    SUPPORTED_SCHEMA_VERSIONS as SUPPORTED_SCHEMA_VERSIONS,
)
from evoom_guard.record_verification.report import _Checks as _Checks
from evoom_guard.strict_json import strict_json_loads as strict_json_loads
from evoom_guard.verifiers.junit_oracle import (
    JUNIT_COMPOSITE_DIGEST_FORMAT,
    JUNIT_REPORT_SET_DIGEST_FORMAT,
    JUNIT_XML_DIGEST_FORMAT,
)

_VERDICTS = _contract.VERDICTS
_EXECUTION_STATES = _contract.EXECUTION_STATES
_REASON_CODES = _contract.REASON_CODES
_REASON_CONTRACT = _contract.REASON_CONTRACT
_POLICY_KEYS = _contract.POLICY_KEYS
_OPTIONAL_POLICY_KEYS = _contract.OPTIONAL_POLICY_KEYS
_ALLOWED_POLICY_KEYS = _contract.ALLOWED_POLICY_KEYS
_REQUIRED_TOP_LEVEL = _contract.REQUIRED_TOP_LEVEL
_REQUIRED_ASSURANCE = _contract.REQUIRED_ASSURANCE
_REQUIRED_ATTESTATION = _contract.REQUIRED_ATTESTATION

_VERDICT_SOURCES = frozenset(
    {
        "junit+exit",
        "exit",
        "blackbox",
        "composite:repo+verifier-pack",
        "composite:blackbox+repo",
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
_ISOLATIONS = frozenset({"not_run", "subprocess", "docker", "gvisor"})
_REQUESTED_ISOLATIONS = frozenset({"subprocess", "docker", "gvisor"})
_SETUP_ISOLATIONS = frozenset(
    {"subprocess", "docker", "gvisor", "subprocess_host_opt_in", "unavailable"}
)
_RISK_LEVELS = frozenset({"low", "medium", "high"})
_REPORT_INTEGRITY_RANK = {
    "same_process_candidate_writable": 0,
    "external_process_isolated": 1,
}
_ISOLATION_RANK = {"not_run": -1, "subprocess": 0, "docker": 1, "gvisor": 2}
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
_UNMEASURED_COVERAGE_DETAIL_KEYS = frozenset(
    {"measured", "note", "unmeasured_files", "caveat"}
)
_BASELINE_KEYS = frozenset(
    {
        "verdict",
        "tests_passed",
        "tests_total",
        "repair_effect",
        "scope",
        "note",
    }
)
_BASELINE_SETUP_KEYS = frozenset({"setup_fidelity", "setup_fidelity_changes"})

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_UTC_SECONDS = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> TypeGuard[int | float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return isinstance(value, int) or math.isfinite(value)


def _coverage_meets_threshold(
    coverage: dict[str, Any] | None,
    threshold: object,
) -> bool:
    """Compare the exact executed/total ratio, never its rounded display field."""
    if not isinstance(coverage, dict) or coverage.get("measured") is not True:
        return False
    executed = coverage.get("executed")
    total = coverage.get("total")
    if not (_is_int(executed) and _is_int(total) and _is_number(threshold)):
        return False
    if isinstance(threshold, int):
        floor_numerator, floor_denominator = threshold, 1
    else:
        floor_numerator, floor_denominator = threshold.as_integer_ratio()
    return 100 * executed * floor_denominator >= floor_numerator * total


def _known_string(value: object, allowed: frozenset[str]) -> bool:
    """Membership that is total for arbitrary JSON values."""
    return isinstance(value, str) and value in allowed


def _is_string_list(value: object) -> TypeGuard[list[str]]:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _is_nullable_int(value: object) -> bool:
    return value is None or _is_int(value)


def _is_nullable_bool(value: object) -> bool:
    return value is None or isinstance(value, bool)


def _is_nullable_string(value: object) -> bool:
    return value is None or isinstance(value, str)


def _valid_count_pair(passed: object, total: object) -> bool:
    if passed is None or total is None:
        return passed is None and total is None
    if not _is_int(passed) or not _is_int(total):
        return False
    return 0 <= passed <= total


def _valid_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str) or _UTC_SECONDS.fullmatch(value) is None:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def _policy_type_errors(policy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = sorted(_POLICY_KEYS - policy.keys())
    extra = sorted(
        key for key in policy if isinstance(key, str) and key not in _ALLOWED_POLICY_KEYS
    )
    if missing:
        errors.append(f"missing keys: {', '.join(missing)}")
    if extra:
        errors.append(f"unexpected schema-1.11 keys: {', '.join(extra)}")
    if any(not isinstance(key, str) for key in policy):
        errors.append("all policy keys must be strings")

    if not _known_string(policy.get("mode"), frozenset({"repo", "blackbox"})):
        errors.append("mode must be repo or blackbox")
    if not _known_string(policy.get("isolation"), _REQUESTED_ISOLATIONS):
        errors.append("isolation must be subprocess, docker, or gvisor")
    docker_image = policy.get("docker_image")
    if docker_image is not None and not isinstance(docker_image, str):
        errors.append("docker_image must be a string or null")
    if not isinstance(policy.get("docker_network"), str):
        errors.append("docker_network must be a string")

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
    for field in ("setup_output_globs", "protected", "allow"):
        if not _is_string_list(policy.get(field)):
            errors.append(f"{field} must be an array of strings")
    for field in (
        "trust_setup_on_host",
        "allow_new_tests",
        "verifier_pack_required",
        "blackbox",
        "blackbox_only",
        "baseline_evidence",
        "require_demonstrated_fix",
    ):
        if not isinstance(policy.get(field), bool):
            errors.append(f"{field} must be a boolean")
    if "strict_harness" in policy and not isinstance(policy["strict_harness"], bool):
        errors.append("strict_harness must be a boolean when present")
    timeout = policy.get("timeout")
    if not _is_int(timeout) or timeout <= 0:
        errors.append("timeout must be a positive integer")
    memory = policy.get("mem_limit_mb")
    if not _is_int(memory) or memory < 0:
        errors.append("mem_limit_mb must be a non-negative integer")
    expected_pack = policy.get("expect_verifier_pack_sha256")
    if expected_pack is not None and not (
        isinstance(expected_pack, str) and bool(_HEX_64.fullmatch(expected_pack))
    ):
        errors.append("expect_verifier_pack_sha256 must be a lowercase SHA-256 or null")
    report_floor = policy.get("require_report_integrity")
    if report_floor is not None and not _known_string(
        report_floor,
        frozenset({"same_process_candidate_writable", "external_process_isolated"}),
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
    if expected_pack is not None and policy.get("verifier_pack_required") is not True:
        errors.append("an expected pack digest requires verifier_pack_required")
    return errors


def _pack_type_errors(pack: dict[str, Any]) -> list[str]:
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
    if not _known_string(pack.get("execution_state"), _EXECUTION_STATES):
        errors.append("execution_state is invalid")
    if not _known_string(pack.get("secrecy"), _PACK_SECRECY):
        errors.append("secrecy is invalid")
    snapshot = pack.get("snapshot_sha256")
    if snapshot is not None and not (
        isinstance(snapshot, str) and bool(_HEX_64.fullmatch(snapshot))
    ):
        errors.append("snapshot_sha256 must be a lowercase SHA-256 or null")
    return errors


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


def _diff_coverage_type_errors(coverage: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if any(not isinstance(key, str) for key in coverage):
        return ["all diff_coverage keys must be strings"]
    keys = frozenset(coverage)
    measured = coverage.get("measured")
    if measured is True:
        if keys != _MEASURED_COVERAGE_KEYS:
            errors.append("measured coverage must contain exactly the seven producer keys")
        percent = coverage.get("percent")
        executed = coverage.get("executed")
        total = coverage.get("total")
        if not (_is_number(percent) and 0 <= percent <= 100):
            errors.append("percent must be a finite number in 0..100")
        if not (_is_int(executed) and _is_int(total) and 0 <= executed <= total):
            errors.append("executed/total must be non-negative ordered integers")
        files = coverage.get("files")
        file_executed = 0
        file_total = 0
        if not isinstance(files, dict):
            errors.append("files must be an object")
        else:
            for path, detail in files.items():
                if not _coverage_path(path, python=True):
                    errors.append("files keys must be safe repo-relative .py paths")
                    continue
                if not isinstance(detail, dict) or any(
                    not isinstance(key, str) for key in detail
                ):
                    errors.append(f"files[{path!r}] must be an object with string keys")
                    continue
                detail_keys = frozenset(detail)
                allowed_keys = frozenset({"executed", "missed"})
                allowed_with_note = frozenset({"executed", "missed", "note"})
                if detail_keys not in (allowed_keys, allowed_with_note):
                    errors.append(f"files[{path!r}] has an invalid producer shape")
                executed_lines = detail.get("executed")
                missed_lines = detail.get("missed")
                if not _positive_line_array(executed_lines) or not _positive_line_array(
                    missed_lines
                ):
                    errors.append(
                        f"files[{path!r}] executed/missed must be sorted unique positive lines"
                    )
                    continue
                executed_set = set(executed_lines)
                missed_set = set(missed_lines)
                if executed_set & missed_set:
                    errors.append(f"files[{path!r}] executed and missed lines overlap")
                file_executed += len(executed_lines)
                file_total += len(executed_lines) + len(missed_lines)
                note = detail.get("note")
                if "note" in detail and not (isinstance(note, str) and bool(note)):
                    errors.append(f"files[{path!r}].note must be non-empty")
        unmeasured = coverage.get("unmeasured_files")
        if not (
            _is_string_list(unmeasured)
            and unmeasured == sorted(set(unmeasured))
            and all(_coverage_path(path, python=False) for path in unmeasured)
        ):
            errors.append(
                "unmeasured_files must be sorted unique safe non-Python paths"
            )
        caveat = coverage.get("caveat")
        if not (isinstance(caveat, str) and bool(caveat)):
            errors.append("caveat must be a non-empty string")
        if _is_int(executed) and executed != file_executed:
            errors.append("executed does not equal the per-file executed-line total")
        if _is_int(total) and total != file_total:
            errors.append("total does not equal the per-file measurable-line total")
        if _is_number(percent) and _is_int(executed) and _is_int(total):
            calculated = round(100.0 * executed / total, 1) if total else 100.0
            if percent != calculated:
                errors.append(f"percent must equal the producer calculation {calculated}")
    elif measured is False:
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
    else:
        errors.append("measured must be a boolean")
    return errors


def _baseline_type_errors(baseline: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if any(not isinstance(key, str) for key in baseline):
        return ["all baseline keys must be strings"]
    keys = frozenset(baseline)
    if not _BASELINE_KEYS <= keys or not keys <= _BASELINE_KEYS | _BASELINE_SETUP_KEYS:
        errors.append("baseline has missing or unknown producer keys")
    note = baseline.get("note")
    if not (isinstance(note, str) and bool(note)):
        errors.append("baseline.note must be a non-empty string")
    scope = baseline.get("scope")
    verdict = baseline.get("verdict")
    passed = baseline.get("tests_passed")
    total = baseline.get("tests_total")
    effect = baseline.get("repair_effect")
    if scope == "unsupported_mode":
        if keys != _BASELINE_KEYS:
            errors.append("unsupported-mode baseline cannot contain setup fields")
        if not (
            verdict is None
            and passed is None
            and total is None
            and effect == "unmeasured"
        ):
            errors.append("unsupported-mode baseline must contain only null evidence")
        return errors
    if scope != "repo_suite_only":
        errors.append("baseline.scope is invalid")
    if verdict not in ("PASS", "FAIL", "NO_CLEAN_VERDICT"):
        errors.append("baseline.verdict is invalid")
    if not _valid_count_pair(passed, total):
        errors.append("baseline counts must be a null or ordered integer pair")
    if verdict in ("PASS", "FAIL") and not (_is_int(passed) and _is_int(total)):
        errors.append("clean baseline verdicts require integer counts")
    if verdict == "PASS" and _is_int(passed) and _is_int(total):
        if not (passed == total == 0 or total > 0 and passed == total):
            errors.append("a PASS baseline must have all-passing counts")
    if verdict == "FAIL" and _is_int(passed) and _is_int(total):
        if not (passed == total == 0 or total > 0 and passed < total):
            errors.append("a FAIL baseline must have zero exit-only counts or a failed test")
    if verdict == "NO_CLEAN_VERDICT":
        if effect != "unmeasured":
            errors.append("NO_CLEAN_VERDICT requires an unmeasured repair effect")
    elif effect not in ("demonstrated", "not_demonstrated"):
        errors.append("clean baseline verdict requires a measured repair effect")
    setup = baseline.get("setup_fidelity")
    changes = baseline.get("setup_fidelity_changes")
    if "setup_fidelity" in baseline:
        if setup not in ("unverified", "setup_failed", "changed_judged_tree"):
            errors.append("setup_fidelity is invalid")
        if verdict != "NO_CLEAN_VERDICT" or effect != "unmeasured":
            errors.append("setup fidelity failures require an unclean baseline")
    if setup == "changed_judged_tree":
        if not (
            _is_string_list(changes)
            and bool(changes)
            and changes == sorted(set(changes))
        ):
            errors.append("changed judged tree requires sorted unique changed paths")
    elif "setup_fidelity_changes" in baseline:
        errors.append("setup_fidelity_changes requires changed_judged_tree")
    return errors


def _policy_sha256(policy: dict[str, Any]) -> str:
    """Reproduce the canonical schema-1.11 policy digest exactly."""
    encoded = json.dumps(policy, sort_keys=True, allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _top_level_type_errors(record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    string_fields = (
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
    for field in string_fields:
        if field in record and not isinstance(record[field], str):
            errors.append(f"{field} must be a string")
    for field in ("passed", "test_command_ran"):
        if field in record and not isinstance(record[field], bool):
            errors.append(f"{field} must be a boolean")
    if "exit_code" in record and not _is_int(record["exit_code"]):
        errors.append("exit_code must be an integer")
    if "risk_score" in record and not _is_number(record["risk_score"]):
        errors.append("risk_score must be a number")
    for field in ("tests_passed", "tests_total"):
        if field in record and not _is_nullable_int(record[field]):
            errors.append(f"{field} must be a non-boolean integer or null")
    for field in ("files_changed", "protected_violations"):
        if field in record and not _is_string_list(record[field]):
            errors.append(f"{field} must be an array of strings")
    for field in ("verdict_source", "source", "base_reconstruction"):
        if field in record and not _is_nullable_string(record[field]):
            errors.append(f"{field} must be a string or null")
    for field in ("diff_coverage", "baseline"):
        if field in record and record[field] is not None and not isinstance(record[field], dict):
            errors.append(f"{field} must be an object or null")
    if "assurance" in record and not isinstance(record["assurance"], dict):
        errors.append("assurance must be an object")
    if (
        "attestation" in record
        and record["attestation"] is not None
        and not isinstance(record["attestation"], dict)
    ):
        errors.append("attestation must be an object or null")
    return errors


def _nested_type_checks(
    checks: _Checks,
    assurance: dict[str, Any] | None,
    attestation: dict[str, Any] | None,
) -> None:
    if assurance is None:
        checks.skip("assurance.required_fields", "assurance is not an object")
        checks.skip("assurance.types", "assurance is not an object")
        checks.skip("assurance.shape", "assurance is not an object")
    else:
        missing = sorted(_REQUIRED_ASSURANCE - assurance.keys())
        checks.expect(
            "assurance.required_fields",
            not missing,
            "all schema-1.11 assurance fields are present",
            f"missing assurance fields: {', '.join(missing)}",
        )
        errors: list[str] = []
        for field in (
            "execution_state",
            "execution_phase",
            "harness_integrity",
            "report_integrity",
            "candidate_isolation",
            "suite_isolation",
            "runtime_continuity",
            "overall_profile",
        ):
            if field in assurance and not isinstance(assurance[field], str):
                errors.append(f"{field} must be a string")
        if "setup_isolation" in assurance and not _is_nullable_string(
            assurance["setup_isolation"]
        ):
            errors.append("setup_isolation must be a string or null")
        pack = assurance.get("verifier_pack")
        if pack is not None and not isinstance(pack, dict):
            errors.append("verifier_pack must be an object or null")
        checks.expect(
            "assurance.types",
            not errors,
            "assurance field types are valid",
            "; ".join(errors),
        )
        shape_errors: list[str] = []
        if not _known_string(assurance.get("execution_state"), _EXECUTION_STATES):
            shape_errors.append("execution_state is invalid")
        if not (
            isinstance(assurance.get("execution_phase"), str)
            and bool(assurance.get("execution_phase"))
        ):
            shape_errors.append("execution_phase must be non-empty")
        if assurance.get("harness_integrity") != "pre_gate_enforced":
            shape_errors.append("harness_integrity must be pre_gate_enforced")
        if not _known_string(assurance.get("report_integrity"), _REPORT_INTEGRITIES):
            shape_errors.append("report_integrity is invalid")
        for field in ("candidate_isolation", "suite_isolation"):
            if not _known_string(assurance.get(field), _ISOLATIONS):
                shape_errors.append(f"{field} is invalid")
        setup_isolation = assurance.get("setup_isolation")
        if setup_isolation is not None and not _known_string(
            setup_isolation, _SETUP_ISOLATIONS
        ):
            shape_errors.append("setup_isolation is invalid")
        if not _known_string(assurance.get("overall_profile"), _OVERALL_PROFILES):
            shape_errors.append("overall_profile is invalid")
        pack = assurance.get("verifier_pack")
        if isinstance(pack, dict):
            shape_errors.extend(_pack_type_errors(pack))
        repo_suite = assurance.get("repo_native_suite")
        if repo_suite is not None and not _known_string(repo_suite, _REPO_SUITE_STATES):
            shape_errors.append("repo_native_suite is invalid")
        checks.expect(
            "assurance.shape",
            not shape_errors,
            "assurance enums and nested pack shape are valid",
            "; ".join(shape_errors),
        )

    if attestation is None:
        checks.skip(
            "attestation.required_fields",
            "the contract permits a null attestation; attestation claims are unverified",
        )
        checks.skip("attestation.types", "attestation is null")
        checks.skip("attestation.shape", "attestation is null")
        return

    missing = sorted(_REQUIRED_ATTESTATION - attestation.keys())
    checks.expect(
        "attestation.required_fields",
        not missing,
        "all schema-1.11 semantic attestation fields are present",
        f"missing attestation fields: {', '.join(missing)}",
    )
    errors = []
    for field in (
        "created_utc",
        "guard_version",
        "mode",
        "candidate_sha256",
        "policy_sha256",
        "execution_state",
        "execution_phase",
        "delivered_isolation",
        "effective_candidate_isolation",
    ):
        if field not in attestation:
            continue
        value = attestation[field]
        preflight_null_isolation = (
            field == "effective_candidate_isolation"
            and value is None
            and attestation.get("execution_state") == "not_started"
            and attestation.get("test_command_started") is False
            and attestation.get("delivered_isolation") == "not_run"
        )
        if not isinstance(value, str) and not preflight_null_isolation:
            errors.append(f"{field} must be a string")
    if "effective_policy" in attestation and not isinstance(
        attestation["effective_policy"], dict
    ):
        errors.append("effective_policy must be an object")
    if "test_command_started" in attestation and not isinstance(
        attestation["test_command_started"], bool
    ):
        errors.append("test_command_started must be a boolean")
    if "candidate_invocations" in attestation and not _is_nullable_int(
        attestation["candidate_invocations"]
    ):
        errors.append("candidate_invocations must be an integer or null")
    if "candidate_launcher_invocation_observed" in attestation and not _is_nullable_bool(
        attestation["candidate_launcher_invocation_observed"]
    ):
        errors.append("candidate_launcher_invocation_observed must be a boolean or null")
    for field in ("verifier_pack_present", "verifier_pack_started", "verifier_pack_completed"):
        if field in attestation and not _is_nullable_bool(attestation[field]):
            errors.append(f"{field} must be a boolean or null")
    for field in ("verifier_pack_tests_passed", "verifier_pack_tests_total"):
        if field in attestation and not _is_nullable_int(attestation[field]):
            errors.append(f"{field} must be an integer or null")
    for field in (
        "repo_suite_tests_passed",
        "repo_suite_tests_total",
        "repo_suite_returncode",
    ):
        if field in attestation and not _is_nullable_int(attestation[field]):
            errors.append(f"{field} must be an integer or null")
    for field in ("repo_suite_started", "repo_suite_completed", "repo_suite_passed"):
        if field in attestation and not _is_nullable_bool(attestation[field]):
            errors.append(f"{field} must be a boolean or null")
    for field in (
        "junit_sha256",
        "junit_digest_format",
        "verifier_pack_junit_sha256",
        "verifier_pack_junit_digest_format",
        "repo_suite_state",
        "repo_suite_junit_sha256",
        "repo_suite_junit_digest_format",
        "repo_suite_verdict_source",
    ):
        if field in attestation and not _is_nullable_string(attestation[field]):
            errors.append(f"{field} must be a string or null")
    for field in ("verifier_pack_sha256", "verifier_pack_digest_format"):
        if field in attestation and not _is_nullable_string(attestation[field]):
            errors.append(f"{field} must be a string or null")
    checks.expect(
        "attestation.types",
        not errors,
        "attestation field types are valid",
        "; ".join(errors),
    )
    shape_errors = []
    if not _valid_utc_timestamp(attestation.get("created_utc")):
        shape_errors.append("created_utc must be a valid YYYY-MM-DDTHH:MM:SSZ timestamp")
    if not (
        isinstance(attestation.get("guard_version"), str)
        and bool(attestation.get("guard_version"))
    ):
        shape_errors.append("guard_version must be non-empty")
    if not _known_string(attestation.get("mode"), frozenset({"repo", "blackbox"})):
        shape_errors.append("mode is invalid")
    candidate_sha = attestation.get("candidate_sha256")
    if not (isinstance(candidate_sha, str) and bool(_HEX_64.fullmatch(candidate_sha))):
        shape_errors.append("candidate_sha256 must be a lowercase SHA-256")
    policy_sha = attestation.get("policy_sha256")
    if not (isinstance(policy_sha, str) and bool(_HEX_64.fullmatch(policy_sha))):
        shape_errors.append("policy_sha256 must be a lowercase SHA-256")
    junit_digest = attestation.get("junit_sha256")
    junit_format = attestation.get("junit_digest_format")
    if not (
        (junit_digest is None and junit_format is None)
        or (
            isinstance(junit_digest, str)
            and bool(_HEX_64.fullmatch(junit_digest))
            and _known_string(junit_format, _JUNIT_TOP_FORMATS)
        )
    ):
        shape_errors.append("junit digest and format must form a recognized SHA-256 pair")
    if "repo_suite_junit_digest_format" in attestation:
        repo_digest = attestation.get("repo_suite_junit_sha256")
        repo_format = attestation.get("repo_suite_junit_digest_format")
        if not (
            (repo_digest is None and repo_format is None)
            or (
                isinstance(repo_digest, str)
                and bool(_HEX_64.fullmatch(repo_digest))
                and _known_string(repo_format, _JUNIT_PHASE_FORMATS)
            )
        ):
            shape_errors.append(
                "repo-suite JUnit digest and format must form a recognized SHA-256 pair"
            )
    if "verifier_pack_junit_digest_format" in attestation:
        pack_junit_digest = attestation.get("verifier_pack_junit_sha256")
        pack_junit_format = attestation.get("verifier_pack_junit_digest_format")
        if not (
            (pack_junit_digest is None and pack_junit_format is None)
            or (
                isinstance(pack_junit_digest, str)
                and bool(_HEX_64.fullmatch(pack_junit_digest))
                and pack_junit_format == JUNIT_XML_DIGEST_FORMAT
            )
        ):
            shape_errors.append(
                "verifier-pack JUnit digest and format must form a recognized SHA-256 pair"
            )
    if not _known_string(attestation.get("execution_state"), _EXECUTION_STATES):
        shape_errors.append("execution_state is invalid")
    if not (
        isinstance(attestation.get("execution_phase"), str)
        and bool(attestation.get("execution_phase"))
    ):
        shape_errors.append("execution_phase must be non-empty")
    if not _known_string(attestation.get("delivered_isolation"), _ISOLATIONS):
        shape_errors.append("delivered_isolation is invalid")
    effective = attestation.get("effective_candidate_isolation")
    effective_valid = _known_string(effective, _ISOLATIONS)
    if (
        effective is None
        and attestation.get("execution_state") == "not_started"
        and attestation.get("test_command_started") is False
        and attestation.get("delivered_isolation") == "not_run"
    ):
        effective_valid = True
    if not effective_valid:
        shape_errors.append("effective_candidate_isolation is invalid")
    invocations = attestation.get("candidate_invocations")
    if _is_int(invocations) and invocations < 0:
        shape_errors.append("candidate_invocations must be non-negative")
    checks.expect(
        "attestation.shape",
        not shape_errors,
        "attestation identities, timestamp, and enums are valid",
        "; ".join(shape_errors),
    )


def _check_lifecycle(
    checks: _Checks,
    record: dict[str, Any],
    assurance: dict[str, Any] | None,
    attestation: dict[str, Any] | None,
) -> None:
    state = record.get("execution_state")
    phase = record.get("execution_phase")
    started = record.get("test_command_ran")

    if assurance is None:
        checks.skip("lifecycle.assurance_parity", "assurance is unavailable")
    else:
        checks.expect(
            "lifecycle.assurance_parity",
            assurance.get("execution_state") == state
            and assurance.get("execution_phase") == phase,
            "top-level and assurance lifecycle fields match",
            "execution_state/execution_phase disagree between top-level and assurance",
        )

    if attestation is None:
        checks.skip("lifecycle.attestation_parity", "attestation is unavailable")
    else:
        checks.expect(
            "lifecycle.attestation_parity",
            attestation.get("execution_state") == state
            and attestation.get("execution_phase") == phase
            and attestation.get("test_command_started") == started,
            "top-level and attestation lifecycle fields match",
            "state, phase, or process-start fact disagrees with the attestation",
        )

    if not _known_string(state, _EXECUTION_STATES) or not isinstance(started, bool):
        checks.skip("lifecycle.state_semantics", "execution state/start fields are invalid")
        return
    source = record.get("verdict_source")
    isolation = record.get("isolation")
    counts_empty = record.get("tests_passed") is None and record.get("tests_total") is None
    if state in ("static_gate", "not_started"):
        valid = not started and source is None and isolation == "not_run" and counts_empty
    elif state == "completed":
        valid = started
    else:
        # A setup process may start before the narrower test_command_ran fact;
        # started_incomplete therefore does not imply that boolean is true.
        valid = source is None and counts_empty
    checks.expect(
        "lifecycle.state_semantics",
        valid,
        "execution state agrees with process, source, isolation, and count semantics",
        "execution state contradicts process, source, isolation, or count semantics",
    )


def _check_verdict_and_counts(checks: _Checks, record: dict[str, Any]) -> None:
    verdict = record.get("verdict")
    passed = record.get("passed")
    exit_code = record.get("exit_code")
    checks.expect(
        "verdict.boolean_exit",
        _known_string(verdict, _VERDICTS)
        and isinstance(passed, bool)
        and _is_int(exit_code)
        and passed == (verdict == "PASS")
        and exit_code == (0 if verdict == "PASS" else 1),
        "passed and exit_code agree with the verdict",
        "passed or exit_code contradicts the verdict",
    )

    reason_code = record.get("reason_code")
    reason_contract = _REASON_CONTRACT.get(reason_code) if isinstance(reason_code, str) else None
    reason_valid = False
    if reason_contract is not None:
        verdicts, states = reason_contract
        reason_valid = _known_string(verdict, verdicts) and _known_string(
            record.get("execution_state"), states
        )
    checks.expect(
        "verdict.reason_code",
        reason_valid,
        "reason_code agrees with its schema-1.11 verdict and lifecycle mapping",
        "reason_code is unknown or contradicts the verdict/execution_state",
    )

    violations = record.get("protected_violations")
    protected_valid = _is_string_list(violations) and (
        bool(violations) == (verdict == "REJECTED")
    )
    checks.expect(
        "verdict.protected_violations",
        protected_valid,
        "protected_violations presence agrees with the verdict",
        "only REJECTED may carry protected violations, and REJECTED requires one",
    )

    tests_passed = record.get("tests_passed")
    tests_total = record.get("tests_total")
    counts_valid = _valid_count_pair(tests_passed, tests_total)
    checks.expect(
        "counts.range_pair",
        counts_valid,
        "test counts are a null pair or a non-negative ordered integer pair",
        "test counts must be paired and satisfy 0 <= tests_passed <= tests_total",
    )

    source = record.get("verdict_source")
    if source == "exit":
        source_counts_valid = tests_passed == 0 and tests_total == 0
    elif source in (
        "junit+exit",
        "blackbox",
        "composite:repo+verifier-pack",
        "composite:blackbox+repo",
    ):
        source_counts_valid = (
            _is_int(tests_passed) and _is_int(tests_total) and tests_total > 0
        )
    else:
        # A missing/invalid source is handled by lifecycle/source checks. Some
        # no-clean-verdict producer paths intentionally have no source.
        source_counts_valid = source is None
    checks.expect(
        "counts.source_semantics",
        source_counts_valid,
        "test counts agree with the structured or exit-only verdict source",
        "exit-only sources require 0/0 counts; structured sources require a non-empty total",
    )

    if reason_code == "tests_failed":
        failed_test_evidence = (
            _is_int(tests_passed)
            and _is_int(tests_total)
            and tests_total > 0
            and 0 <= tests_passed < tests_total
        )
        checks.expect(
            "verdict.failure_evidence",
            failed_test_evidence,
            "tests_failed is backed by a non-empty count with at least one failure",
            "tests_failed requires 0 <= tests_passed < tests_total and tests_total > 0",
        )
    else:
        checks.skip("verdict.failure_evidence", "reason_code is not tests_failed")

    if reason_code == "junit_exit_mismatch":
        tamper_count_evidence = (
            _is_int(tests_passed)
            and _is_int(tests_total)
            and tests_total > 0
            and 0 <= tests_passed <= tests_total
        )
        checks.expect(
            "verdict.tamper_evidence",
            tamper_count_evidence,
            "JUnit/exit disagreement is backed by a non-empty JUnit count",
            "junit_exit_mismatch requires a non-empty JUnit count",
        )
    else:
        checks.skip(
            "verdict.tamper_evidence", "reason_code is not junit_exit_mismatch"
        )

    if verdict != "PASS":
        checks.skip("verdict.pass_evidence", "record is not a PASS")
        return
    valid_pass = _completed_all_pass_evidence(record)
    checks.expect(
        "verdict.pass_evidence",
        valid_pass,
        "PASS is backed by completed all-passing structured or clean exit evidence",
        "PASS lacks completed all-passing structured or clean exit evidence",
    )


def _check_policy(
    checks: _Checks,
    record: dict[str, Any],
    attestation: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if attestation is None:
        checks.skip("policy.digest", "attestation is unavailable")
        checks.skip("policy.contract", "attestation is unavailable")
        checks.skip("policy.context_parity", "attestation is unavailable")
        return None
    policy = attestation.get("effective_policy")
    claimed = attestation.get("policy_sha256")
    if not isinstance(policy, dict) or not isinstance(claimed, str):
        checks.fail("policy.digest", "effective_policy or policy_sha256 is invalid")
        checks.fail("policy.contract", "effective_policy is not an object")
        checks.skip("policy.context_parity", "effective policy is invalid")
        return None
    policy_errors = _policy_type_errors(policy)
    checks.expect(
        "policy.contract",
        not policy_errors,
        "effective_policy has the complete typed schema-1.11 contract",
        "; ".join(policy_errors),
    )
    try:
        calculated = _policy_sha256(policy)
    except (TypeError, ValueError, RecursionError) as exc:
        checks.fail("policy.digest", f"effective_policy is not canonically encodable: {exc}")
        checks.skip("policy.context_parity", "effective policy is not encodable")
        return policy
    checks.expect(
        "policy.digest",
        bool(_HEX_64.fullmatch(claimed)) and claimed == calculated,
        "policy_sha256 matches the canonical effective_policy bytes",
        f"policy_sha256 mismatch: calculated {calculated}",
    )
    mode = attestation.get("mode")
    context_valid = (
        _known_string(mode, frozenset({"repo", "blackbox"}))
        and policy.get("mode") == mode
        and policy.get("blackbox") == (mode == "blackbox")
        and policy.get("policy_id") == attestation.get("policy_id")
        and policy.get("policy_version") == attestation.get("policy_version")
    )
    checks.expect(
        "policy.context_parity",
        context_valid,
        "attestation mode/identity agree with effective_policy",
        "attestation mode or policy identity contradicts effective_policy",
    )
    return policy


def _completed_all_pass_evidence(record: dict[str, Any]) -> bool:
    passed = record.get("tests_passed")
    total = record.get("tests_total")
    source = record.get("verdict_source")
    count_evidence = (
        passed == 0 and total == 0
        if source == "exit"
        else _is_int(passed) and _is_int(total) and total > 0 and passed == total
    )
    return (
        record.get("execution_state") == "completed"
        and record.get("test_command_ran") is True
        and _known_string(source, _VERDICT_SOURCES)
        and count_evidence
    )


def _producer_version_at_least(
    attestation: dict[str, Any], minimum: tuple[int, int, int]
) -> bool:
    """Compare the producer's numeric semantic version prefix."""
    version = attestation.get("guard_version")
    if not isinstance(version, str):
        return False
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[^0-9].*)?", version)
    if match is None:
        return False
    return tuple(int(part) for part in match.groups()) >= minimum


def _requires_repo_phase_evidence(attestation: dict[str, Any]) -> bool:
    """Whether the producer version implements the explicit repo-phase contract."""
    policy = attestation.get("effective_policy")
    return bool(
        isinstance(policy, dict)
        and policy.get("mode") == "repo"
        and policy.get("verifier_pack_required") is True
        and _producer_version_at_least(attestation, (4, 0, 2))
    )


def _repo_suite_pass_evidence(
    record: dict[str, Any],
    attestation: dict[str, Any] | None,
) -> bool:
    """Prove candidate repo-suite PASS independently of a composed pack."""
    if not isinstance(attestation, dict):
        return _completed_all_pass_evidence(record)
    suite_passed = attestation.get("repo_suite_passed")
    suite_count = attestation.get("repo_suite_tests_passed")
    suite_total = attestation.get("repo_suite_tests_total")
    suite_source = attestation.get("repo_suite_verdict_source")
    suite_returncode = attestation.get("repo_suite_returncode")
    suite_digest = attestation.get("repo_suite_junit_sha256")
    suite_digest_format = attestation.get("repo_suite_junit_digest_format")
    suite_digest_valid = (
        isinstance(suite_digest, str)
        and bool(_HEX_64.fullmatch(suite_digest))
        and _known_string(suite_digest_format, _JUNIT_PHASE_FORMATS)
        if suite_source == "junit+exit"
        else suite_digest is None and suite_digest_format is None
    )
    phase_complete = (
        attestation.get("repo_suite_started") is True
        and attestation.get("repo_suite_completed") is True
        and attestation.get("repo_suite_state") == "repo_phase_completed"
        and isinstance(suite_passed, bool)
        and _is_int(suite_count)
        and _is_int(suite_total)
        and _is_int(suite_returncode)
        and suite_returncode in (0, 1)
        and suite_source in ("junit+exit", "exit")
        and suite_digest_valid
    )
    if not phase_complete:
        if _requires_repo_phase_evidence(attestation):
            return False
        return _completed_all_pass_evidence(record)
    suite_count_i = cast(int, suite_count)
    suite_total_i = cast(int, suite_total)
    suite_returncode_i = cast(int, suite_returncode)
    if suite_source == "exit":
        count_pass = (
            suite_returncode_i == 0 and suite_count_i == 0 and suite_total_i == 0
        )
    else:
        count_pass = (
            suite_returncode_i == 0
            and suite_total_i > 0
            and suite_count_i == suite_total_i
        )

    # A clean composite carries the same repo counts as the top-level remainder.
    # Bind the explicit phase snapshot to that independently checkable arithmetic.
    if record.get("verdict_source") == "composite:repo+verifier-pack":
        top_passed = record.get("tests_passed")
        top_total = record.get("tests_total")
        pack_passed = attestation.get("verifier_pack_tests_passed")
        pack_total = attestation.get("verifier_pack_tests_total")
        if not all(
            _is_int(value)
            for value in (top_passed, top_total, pack_passed, pack_total)
        ):
            return False
        top_passed_i = cast(int, top_passed)
        top_total_i = cast(int, top_total)
        pack_passed_i = cast(int, pack_passed)
        pack_total_i = cast(int, pack_total)
        if (
            suite_count_i != top_passed_i - pack_passed_i
            or suite_total_i != top_total_i - pack_total_i
        ):
            return False
    return suite_passed is True and count_pass


def _required_coverage_unmeasured(
    record: dict[str, Any], policy: dict[str, Any]
) -> bool:
    """Whether an all-pass run truthfully reports a required coverage shortfall."""
    coverage = record.get("diff_coverage")
    return (
        _is_number(policy.get("min_diff_coverage"))
        and policy.get("mode") == "repo"
        and policy.get("isolation") == "subprocess"
        and isinstance(coverage, dict)
        and coverage.get("measured") is False
        and _completed_all_pass_evidence(record)
    )


def _check_evidence_contracts(
    checks: _Checks,
    record: dict[str, Any],
    policy: dict[str, Any] | None,
    attestation: dict[str, Any] | None,
) -> None:
    coverage_value = record.get("diff_coverage")
    coverage = coverage_value if isinstance(coverage_value, dict) else None
    if coverage_value is None:
        checks.skip("diff_coverage.shape", "diff coverage evidence is absent")
        coverage_shape_valid = True
    elif coverage is None:
        checks.fail("diff_coverage.shape", "diff_coverage must be an object or null")
        coverage_shape_valid = False
    else:
        coverage_errors = _diff_coverage_type_errors(coverage)
        coverage_shape_valid = not coverage_errors
        checks.expect(
            "diff_coverage.shape",
            coverage_shape_valid,
            "diff coverage matches a producer evidence shape",
            "; ".join(coverage_errors),
        )

    baseline_value = record.get("baseline")
    baseline = baseline_value if isinstance(baseline_value, dict) else None
    if baseline_value is None:
        checks.skip("baseline.shape", "baseline evidence is absent")
        baseline_shape_valid = True
    elif baseline is None:
        checks.fail("baseline.shape", "baseline must be an object or null")
        baseline_shape_valid = False
    else:
        baseline_errors = _baseline_type_errors(baseline)
        baseline_shape_valid = not baseline_errors
        checks.expect(
            "baseline.shape",
            baseline_shape_valid,
            "baseline matches a producer evidence shape",
            "; ".join(baseline_errors),
        )

    if policy is None:
        checks.skip("diff_coverage.policy_semantics", "effective policy is unavailable")
        checks.skip("baseline.policy_semantics", "effective policy is unavailable")
        return

    threshold = policy.get("min_diff_coverage")
    reason = record.get("reason_code")
    verdict = record.get("verdict")
    measured_coverage = (
        coverage
        if coverage_shape_valid
        and isinstance(coverage, dict)
        and coverage.get("measured") is True
        else None
    )
    measured_meets_threshold = _coverage_meets_threshold(
        measured_coverage, threshold
    )
    coverage_semantics = True
    if reason == "diff_coverage_below_threshold":
        coverage_semantics = (
            _is_number(threshold)
            and measured_coverage is not None
            and not measured_meets_threshold
            and policy.get("mode") == "repo"
            and policy.get("isolation") == "subprocess"
            and _completed_all_pass_evidence(record)
        )
    elif (
        reason == "assurance_requirement_not_met"
        and verdict == "ERROR"
        and threshold is not None
        and _completed_all_pass_evidence(record)
    ):
        # The same reason also represents report/isolation floor shortfalls.
        # With a coverage gate present, either the measured threshold was met
        # before another assurance floor failed, or coverage itself was
        # explicitly unavailable and therefore could not authorize PASS.
        coverage_semantics = _required_coverage_unmeasured(record, policy) or (
            measured_coverage is not None and measured_meets_threshold
        )
    elif verdict == "PASS" and threshold is not None:
        coverage_semantics = (
            _is_number(threshold)
            and measured_coverage is not None
            and measured_meets_threshold
            and policy.get("mode") == "repo"
            and policy.get("isolation") == "subprocess"
        )
    checks.expect(
        "diff_coverage.policy_semantics",
        coverage_semantics,
        "coverage evidence agrees with its policy threshold and verdict reason",
        "coverage threshold, measured percent, PASS, or reason_code contradict",
    )

    requested_baseline = (
        policy.get("baseline_evidence") is True
        or policy.get("require_demonstrated_fix") is True
    )
    baseline_semantics = baseline_shape_valid
    if baseline is not None:
        baseline_semantics = baseline_semantics and requested_baseline
        if baseline.get("scope") == "repo_suite_only":
            baseline_semantics = baseline_semantics and (
                policy.get("mode") == "repo"
                and policy.get("isolation") == "subprocess"
            )
        elif baseline.get("scope") == "unsupported_mode":
            baseline_semantics = baseline_semantics and (
                policy.get("baseline_evidence") is True
                and policy.get("require_demonstrated_fix") is False
                and (
                    policy.get("mode") == "blackbox"
                    or policy.get("isolation") != "subprocess"
                )
            )
    if verdict == "PASS" and requested_baseline:
        baseline_semantics = baseline_semantics and baseline is not None
    if isinstance(baseline, dict) and baseline.get("scope") == "repo_suite_only":
        baseline_verdict = baseline.get("verdict")
        candidate_suite_passed = _repo_suite_pass_evidence(record, attestation)
        expected_effect = (
            "unmeasured"
            if baseline_verdict == "NO_CLEAN_VERDICT"
            else "demonstrated"
            if baseline_verdict == "FAIL" and candidate_suite_passed
            else "not_demonstrated"
        )
        baseline_semantics = baseline_semantics and (
            baseline.get("repair_effect") == expected_effect
        )
    if verdict == "PASS" and isinstance(baseline, dict):
        if policy.get("require_demonstrated_fix") is True:
            baseline_semantics = baseline_semantics and (
                baseline.get("scope") == "repo_suite_only"
                and baseline.get("verdict") == "FAIL"
                and baseline.get("repair_effect") == "demonstrated"
            )
    if reason == "fix_not_demonstrated":
        failed_fix_gate = (
            policy.get("require_demonstrated_fix") is True
            and isinstance(baseline, dict)
            and baseline.get("scope") == "repo_suite_only"
            and (
                baseline.get("verdict") == "PASS"
                and baseline.get("repair_effect") == "not_demonstrated"
                or baseline.get("verdict") == "NO_CLEAN_VERDICT"
                and baseline.get("repair_effect") == "unmeasured"
            )
            and _completed_all_pass_evidence(record)
        )
        baseline_semantics = baseline_semantics and failed_fix_gate
    checks.expect(
        "baseline.policy_semantics",
        bool(baseline_semantics),
        "baseline evidence agrees with policy, PASS, and repair-effect reason",
        "baseline request, scope, repair effect, PASS, or reason_code contradict",
    )


def _check_policy_runtime_bindings(
    checks: _Checks,
    record: dict[str, Any],
    assurance: dict[str, Any] | None,
    attestation: dict[str, Any] | None,
    policy: dict[str, Any] | None,
) -> None:
    if policy is None or assurance is None:
        checks.skip("policy.assurance_floors", "effective policy or assurance is unavailable")
    else:
        report_floor = policy.get("require_report_integrity")
        isolation_floor = policy.get("require_candidate_isolation")
        actual_report = assurance.get("report_integrity")
        actual_isolation = assurance.get("candidate_isolation")
        report_shortfall = (
            isinstance(report_floor, str)
            and _REPORT_INTEGRITY_RANK.get(
                actual_report if isinstance(actual_report, str) else "", -1
            )
            < _REPORT_INTEGRITY_RANK.get(report_floor, 99)
        )
        isolation_shortfall = (
            isinstance(isolation_floor, str)
            and _ISOLATION_RANK.get(
                actual_isolation if isinstance(actual_isolation, str) else "", -2
            )
            < _ISOLATION_RANK.get(isolation_floor, 99)
        )
        floor_shortfall = report_shortfall or isolation_shortfall
        coverage_shortfall = _required_coverage_unmeasured(record, policy)
        floor_valid = True
        if record.get("verdict") == "PASS":
            floor_valid = not floor_shortfall
        elif (
            record.get("reason_code") == "assurance_requirement_not_met"
            and record.get("execution_state") == "completed"
        ):
            floor_valid = (
                (floor_shortfall or coverage_shortfall)
                and _completed_all_pass_evidence(record)
            )
        checks.expect(
            "policy.assurance_floors",
            floor_valid,
            "observed assurance satisfies PASS floors or proves the named shortfall",
            "PASS is below a required assurance floor, or the completed shortfall reason is unsupported",
        )

    if policy is None or assurance is None or attestation is None:
        checks.skip(
            "policy.pack_digest_pin",
            "effective policy, assurance, or attestation is unavailable",
        )
        return
    expected = policy.get("expect_verifier_pack_sha256")
    observed = attestation.get("verifier_pack_sha256")
    reason = record.get("reason_code")
    pack = assurance.get("verifier_pack")
    pin_valid = True
    if expected is None:
        pin_valid = reason != "verifier_pack_identity_mismatch"
    elif isinstance(expected, str):
        if record.get("verdict") == "PASS":
            pin_valid = observed == expected
        if isinstance(observed, str):
            mismatch = observed != expected
            if mismatch:
                pin_valid = pin_valid and (
                    reason == "verifier_pack_identity_mismatch"
                    and record.get("verdict") == "ERROR"
                    and record.get("execution_state") == "not_started"
                    and record.get("verdict_source") is None
                    and isinstance(pack, dict)
                    and pack.get("present") is True
                    and pack.get("identity_verified") is False
                    and pack.get("integrity") == "snapshot_identity_mismatch"
                )
            else:
                pin_valid = pin_valid and reason != "verifier_pack_identity_mismatch"
        elif reason == "verifier_pack_identity_mismatch":
            pin_valid = False
    else:
        pin_valid = False
    checks.expect(
        "policy.pack_digest_pin",
        bool(pin_valid),
        "observed verifier-pack identity agrees with its expected digest pin",
        "expected and observed verifier-pack identity contradict PASS or reason_code",
    )


def _check_receipts(
    checks: _Checks,
    record: dict[str, Any],
    assurance: dict[str, Any] | None,
    attestation: dict[str, Any] | None,
) -> None:
    if attestation is None:
        checks.skip("candidate_receipt.zero_nonzero", "attestation is unavailable")
        checks.skip("candidate_receipt.isolation", "attestation is unavailable")
        return
    mode = attestation.get("mode")
    invocations = attestation.get("candidate_invocations")
    observed = attestation.get("candidate_launcher_invocation_observed")
    state = record.get("execution_state")
    if mode == "repo":
        checks.expect(
            "candidate_receipt.zero_nonzero",
            invocations is None and observed is None,
            "repo-native record does not invent black-box candidate receipts",
            "repo-native record contains black-box candidate receipt claims",
        )
        checks.skip("candidate_receipt.isolation", "candidate receipts apply to black-box mode")
        return
    if mode != "blackbox":
        checks.skip("candidate_receipt.zero_nonzero", "attestation mode is invalid")
        checks.skip("candidate_receipt.isolation", "attestation mode is invalid")
        return
    if _known_string(state, frozenset({"static_gate", "not_started"})):
        no_runtime_receipt = (invocations is None and observed is None) or (
            invocations == 0 and observed is False
        )
        checks.expect(
            "candidate_receipt.zero_nonzero",
            no_runtime_receipt,
            "no-run black-box request claims no runtime receipt",
            "a no-run state must not claim black-box runtime receipts",
        )
        checks.expect(
            "candidate_receipt.isolation",
            record.get("isolation") == "not_run"
            and (
                attestation.get("effective_candidate_isolation") == "not_run"
                if state == "static_gate"
                else attestation.get("effective_candidate_isolation") in (None, "not_run")
            ),
            "no-run black-box request claims no delivered candidate boundary",
            "a no-run state claims a delivered candidate boundary",
        )
        return

    receipt_valid = False
    if _is_int(invocations) and isinstance(observed, bool):
        receipt_valid = invocations >= 0 and observed == (invocations > 0)
    checks.expect(
        "candidate_receipt.zero_nonzero",
        receipt_valid,
        "candidate receipt boolean matches zero/non-zero invocation semantics",
        "candidate invocation count and observed boolean disagree",
    )
    assurance_isolation = assurance.get("candidate_isolation") if assurance else None
    effective = attestation.get("effective_candidate_isolation")
    isolation_valid = (
        isinstance(observed, bool)
        and (
            observed
            and _known_string(record.get("isolation"), _REQUESTED_ISOLATIONS)
            or not observed
            and record.get("isolation") == "not_run"
        )
        and assurance_isolation == record.get("isolation")
        and effective == record.get("isolation")
    )
    if record.get("reason_code") == "candidate_not_exercised":
        isolation_valid = isolation_valid and invocations == 0 and observed is False
    if record.get("verdict") == "PASS":
        isolation_valid = isolation_valid and observed is True
    checks.expect(
        "candidate_receipt.isolation",
        isolation_valid,
        "receipt presence agrees with delivered candidate isolation and verdict semantics",
        "candidate receipt contradicts isolation, candidate_not_exercised, or PASS semantics",
    )


def _check_source_contract(
    checks: _Checks,
    record: dict[str, Any],
    assurance: dict[str, Any] | None,
    attestation: dict[str, Any] | None,
    policy: dict[str, Any] | None,
) -> None:
    if attestation is None or policy is None or assurance is None:
        checks.skip("source.mode_policy", "policy, assurance, or attestation is unavailable")
        return
    mode = policy.get("mode")
    blackbox_only = policy.get("blackbox_only")
    pack_required = policy.get("verifier_pack_required")
    source = record.get("verdict_source")
    phase = record.get("execution_phase")
    state = record.get("execution_state")
    verdict = record.get("verdict")
    valid = (
        _known_string(mode, frozenset({"repo", "blackbox"}))
        and isinstance(blackbox_only, bool)
        and isinstance(pack_required, bool)
        and (source is None or _known_string(source, _VERDICT_SOURCES))
    )
    junit_digest = attestation.get("junit_sha256")
    junit_format = attestation.get("junit_digest_format")
    legacy_missing_junit_identity = (
        not _producer_version_at_least(attestation, (4, 0, 2))
        and junit_digest is None
        and junit_format is None
    )
    if source == "junit+exit":
        structured_junit_identity = (
            isinstance(junit_digest, str)
            and bool(_HEX_64.fullmatch(junit_digest))
            and _known_string(junit_format, _JUNIT_PHASE_FORMATS)
        )
        valid = valid and (
            structured_junit_identity or legacy_missing_junit_identity
        )
    elif source == "exit":
        valid = valid and junit_digest is None and junit_format is None
    elif source in ("blackbox", "composite:blackbox+repo"):
        valid = valid and (
            (
                isinstance(junit_digest, str)
                and bool(_HEX_64.fullmatch(junit_digest))
                and junit_format == JUNIT_XML_DIGEST_FORMAT
            )
            or legacy_missing_junit_identity
        )
    elif source == "composite:repo+verifier-pack":
        repo_source = attestation.get("repo_suite_verdict_source")
        expected_composite_format = (
            JUNIT_COMPOSITE_DIGEST_FORMAT
            if _requires_repo_phase_evidence(attestation)
            and repo_source == "junit+exit"
            else "EVOGUARD_JUNIT_COMPOSITE_V1"
        )
        valid = valid and (
            (
                isinstance(junit_digest, str)
                and bool(_HEX_64.fullmatch(junit_digest))
                and junit_format == expected_composite_format
            )
            or legacy_missing_junit_identity
        )
    if not valid:
        checks.fail("source.mode_policy", "source policy fields are malformed")
        return
    pack_is_required = pack_required is True
    blackbox_is_only = blackbox_only is True

    phase_by_source = {
        "junit+exit": "repo_suite",
        "exit": "repo_suite",
        "blackbox": "blackbox_pack",
        "composite:repo+verifier-pack": "verifier_pack",
        "composite:blackbox+repo": "repo_suite",
    }
    expected_phase = phase_by_source.get(source) if isinstance(source, str) else None
    if source is not None:
        valid = valid and state == "completed" and phase == expected_phase

    if mode == "repo":
        valid = valid and source not in ("blackbox", "composite:blackbox+repo")
        if source == "composite:repo+verifier-pack":
            valid = (
                valid
                and pack_is_required
                and attestation.get("verifier_pack_completed") is True
            )
        if source in ("junit+exit", "exit"):
            valid = valid and not pack_is_required
        if verdict == "PASS":
            valid = valid and (
                source == "composite:repo+verifier-pack"
                if pack_is_required
                else source in ("junit+exit", "exit")
            )
    else:
        valid = valid and source not in (
            "junit+exit",
            "exit",
            "composite:repo+verifier-pack",
        )
        # Preflight can refuse an unrelated unsupported policy before pack
        # discovery.  Once execution starts, however, black-box mode has no
        # judgment channel without a configured verifier pack.
        if state not in ("static_gate", "not_started"):
            valid = valid and pack_is_required
        if source == "composite:blackbox+repo":
            valid = (
                valid
                and not blackbox_is_only
                and attestation.get("verifier_pack_completed") is True
                and assurance.get("repo_native_suite") == "composed_completed"
            )
        elif source == "blackbox":
            valid = valid and attestation.get("verifier_pack_completed") is True
            if not blackbox_is_only:
                valid = valid and assurance.get("repo_native_suite") == (
                    "required_not_run_short_circuit"
                )
        if verdict == "PASS":
            valid = valid and (
                source == "blackbox"
                if blackbox_is_only
                else source == "composite:blackbox+repo"
            )
    checks.expect(
        "source.mode_policy",
        bool(valid),
        "verdict_source agrees with mode, pack policy, phase, and composition",
        "verdict_source drops or contradicts a required judgment channel",
    )


def _check_assurance_semantics(
    checks: _Checks,
    record: dict[str, Any],
    assurance: dict[str, Any] | None,
    policy: dict[str, Any] | None,
) -> None:
    if assurance is None:
        checks.skip("assurance.lifecycle_profile", "assurance is unavailable")
        return
    state = record.get("execution_state")
    ran = record.get("test_command_ran")
    valid = assurance.get("harness_integrity") == "pre_gate_enforced"
    if state == "static_gate":
        valid = valid and (
            assurance.get("overall_profile") == "static_gate"
            and assurance.get("report_integrity") == "not_applicable_static_gate"
            and assurance.get("candidate_isolation") == "not_run"
            and assurance.get("suite_isolation") == "not_run"
            and assurance.get("runtime_continuity") == "not_applicable"
        )
    elif state == "not_started":
        valid = valid and (
            assurance.get("overall_profile") == "preflight"
            and assurance.get("report_integrity") == "not_applicable_not_run"
            and assurance.get("candidate_isolation") == "not_run"
            and assurance.get("suite_isolation") == "not_run"
        )
    elif state == "started_incomplete" and ran is False:
        valid = valid and (
            assurance.get("overall_profile") == "execution_incomplete_before_tests"
            and assurance.get("report_integrity") == "not_applicable_not_run"
            and assurance.get("candidate_isolation") == "not_run"
            and assurance.get("suite_isolation") == "not_run"
        )
    elif state in ("started_incomplete", "completed") and ran is True:
        if policy is None or not _known_string(
            policy.get("mode"), frozenset({"repo", "blackbox"})
        ):
            checks.skip("assurance.lifecycle_profile", "effective policy mode is unavailable")
            return
        mode = policy.get("mode")
        if state == "started_incomplete":
            valid = valid and assurance.get("overall_profile") == "execution_incomplete"
            if mode == "repo":
                valid = valid and assurance.get("report_integrity") == (
                    "same_process_candidate_writable"
                )
            else:
                repo_state = assurance.get("repo_native_suite")
                expected_report = (
                    "same_process_candidate_writable"
                    if repo_state in ("required_started_incomplete", "composed_completed")
                    else "external_process_isolated"
                )
                valid = valid and assurance.get("report_integrity") == expected_report
        elif mode == "repo":
            setup = assurance.get("setup_isolation")
            suite = assurance.get("suite_isolation")
            expected_profile = (
                "mixed_host_setup_repo_native"
                if setup == "subprocess_host_opt_in"
                else "isolated_repo_native"
                if suite in ("docker", "gvisor")
                else "repo_native_same_process"
            )
            valid = valid and (
                assurance.get("report_integrity") == "same_process_candidate_writable"
                and assurance.get("overall_profile") == expected_profile
            )
        else:
            blackbox_only = policy.get("blackbox_only")
            repo_state = assurance.get("repo_native_suite")
            if blackbox_only is True:
                valid = valid and (
                    repo_state == "not_required_blackbox_only"
                    and assurance.get("report_integrity") == "external_process_isolated"
                    and assurance.get("overall_profile") == "black_box_external_judge"
                )
            elif blackbox_only is False and repo_state == "composed_completed":
                valid = valid and (
                    assurance.get("report_integrity") == "same_process_candidate_writable"
                    and assurance.get("overall_profile") == "composite_blackbox_repo_native"
                )
            else:
                valid = valid and (
                    repo_state
                    in (
                        "required_not_run_short_circuit",
                        "required_not_started",
                        "required_started_incomplete",
                    )
                    and assurance.get("report_integrity") == "external_process_isolated"
                    and assurance.get("overall_profile") == "blackbox_composite_short_circuit"
                )
    else:
        valid = False
    checks.expect(
        "assurance.lifecycle_profile",
        bool(valid),
        "assurance profile and report channel agree with lifecycle and mode",
        "assurance profile, harness, or report-integrity claims contradict lifecycle/mode",
    )


def _check_pack(
    checks: _Checks,
    record: dict[str, Any],
    assurance: dict[str, Any] | None,
    attestation: dict[str, Any] | None,
    policy: dict[str, Any] | None,
) -> None:
    if assurance is None or policy is None:
        checks.skip("pack.configuration_parity", "assurance or policy is unavailable")
        checks.skip("pack.identity_parity", "assurance or policy is unavailable")
        checks.skip("pack.lifecycle_parity", "assurance or policy is unavailable")
        checks.skip("pack.counts", "assurance or policy is unavailable")
        checks.skip(
            "pack.blackbox_count_parity", "assurance or policy is unavailable"
        )
        checks.skip("pack.pass_evidence", "assurance or policy is unavailable")
        return
    configured = policy.get("verifier_pack_required")
    pack = assurance.get("verifier_pack")
    config_valid = isinstance(configured, bool) and (
        isinstance(pack, dict) if configured else pack is None
    )
    if isinstance(pack, dict):
        config_valid = config_valid and pack.get("configured") is True
    checks.expect(
        "pack.configuration_parity",
        config_valid,
        "policy and assurance agree on verifier-pack configuration",
        "policy and assurance disagree on verifier-pack configuration",
    )
    if attestation is None:
        checks.skip("pack.identity_parity", "attestation is unavailable")
        checks.skip("pack.lifecycle_parity", "attestation is unavailable")
        checks.skip("pack.counts", "attestation is unavailable")
        checks.skip("pack.blackbox_count_parity", "attestation is unavailable")
        checks.skip("pack.pass_evidence", "attestation is unavailable")
        return

    digest = attestation.get("verifier_pack_sha256")
    digest_format = attestation.get("verifier_pack_digest_format")
    if isinstance(pack, dict):
        identity_valid = (
            pack.get("snapshot_sha256") == digest
            and pack.get("present") == attestation.get("verifier_pack_present")
        )
        if digest is None:
            identity_valid = identity_valid and digest_format is None
        else:
            identity_valid = identity_valid and (
                isinstance(digest, str)
                and bool(_HEX_64.fullmatch(digest))
                and digest_format == PACK_DIGEST_FORMAT
            )
        if pack.get("identity_verified") is True:
            identity_valid = identity_valid and digest is not None
        if attestation.get("verifier_pack_present") is False:
            identity_valid = identity_valid and digest is None
    else:
        identity_valid = (
            digest is None
            and digest_format is None
            and attestation.get("verifier_pack_present") in (None, False)
        )
    checks.expect(
        "pack.identity_parity",
        identity_valid,
        "pack presence, digest, format, and assurance snapshot agree",
        "pack identity views disagree or use an invalid digest/format",
    )

    top_state = record.get("execution_state")
    if not isinstance(pack, dict):
        lifecycle_valid = (
            attestation.get("verifier_pack_started") in (None, False)
            and attestation.get("verifier_pack_completed") in (None, False)
        )
    elif top_state == "static_gate":
        lifecycle_valid = (
            pack.get("execution_state") == "static_gate"
            and attestation.get("verifier_pack_started") in (None, False)
            and attestation.get("verifier_pack_completed") in (None, False)
        )
    elif top_state == "not_started":
        lifecycle_valid = (
            pack.get("execution_state") == "not_started"
            and attestation.get("verifier_pack_started") in (None, False)
            and attestation.get("verifier_pack_completed") in (None, False)
        )
    else:
        pack_started = attestation.get("verifier_pack_started")
        pack_completed = attestation.get("verifier_pack_completed")
        expected_state = (
            "completed"
            if pack_completed is True
            else "started_incomplete"
            if pack_started is True
            else "not_started"
        )
        lifecycle_valid = (
            isinstance(pack_started, bool)
            and isinstance(pack_completed, bool)
            and (not pack_completed or pack_started)
            and pack.get("execution_state") == expected_state
        )
    checks.expect(
        "pack.lifecycle_parity",
        lifecycle_valid,
        "pack start/completion facts agree with pack execution_state",
        "pack lifecycle fields contradict each other",
    )

    pack_passed = attestation.get("verifier_pack_tests_passed")
    pack_total = attestation.get("verifier_pack_tests_total")
    pack_completed = attestation.get("verifier_pack_completed") is True
    null_counts = pack_passed is None and pack_total is None
    # The producer marks the process complete before its post-execution pack
    # and candidate-tree checks.  A failure there intentionally withholds the
    # not-yet-consumed JUnit counts even though execution itself completed.
    post_execution_tamper = record.get("reason_code") in (
        "verifier_pack_snapshot_changed",
        "candidate_tree_changed_during_run",
    )
    completed_zero_test_error = (
        pack_completed
        and pack_passed == 0
        and pack_total == 0
        and record.get("execution_state") == "completed"
        and record.get("verdict") == "ERROR"
        and record.get("reason_code") == "no_test_verdict"
        and record.get("verdict_source") is None
    )
    counts_valid = (
        _valid_count_pair(pack_passed, pack_total)
        and (
            pack_completed
            and (
                _is_int(pack_passed)
                and _is_int(pack_total)
                and pack_total > 0
                or completed_zero_test_error
                or post_execution_tamper
                and null_counts
            )
            or not pack_completed
            and null_counts
        )
    )
    checks.expect(
        "pack.counts",
        counts_valid,
        "pack counts are a valid null or ordered integer pair",
        "pack counts are unpaired, negative, or out of order",
    )

    if record.get("verdict_source") == "blackbox":
        blackbox_count_parity = (
            _is_int(record.get("tests_passed"))
            and _is_int(record.get("tests_total"))
            and _is_int(pack_passed)
            and _is_int(pack_total)
            and record.get("tests_passed") == pack_passed
            and record.get("tests_total") == pack_total
            and pack_total > 0
        )
        checks.expect(
            "pack.blackbox_count_parity",
            blackbox_count_parity,
            "black-box-only top-level counts equal the external pack counts",
            "black-box-only top-level counts must equal non-empty pack counts",
        )
    else:
        checks.skip(
            "pack.blackbox_count_parity",
            "verdict_source is not the black-box-only channel",
        )

    if record.get("verdict") != "PASS" or configured is not True:
        checks.skip("pack.pass_evidence", "record is not a PASS that requires a pack")
        return
    pass_valid = (
        isinstance(pack, dict)
        and pack.get("configured") is True
        and pack.get("present") is True
        and pack.get("identity_verified") is True
        and _known_string(
            pack.get("integrity"),
            frozenset({"verified_snapshot_pre_post", "verified_snapshot_read_only"}),
        )
        and pack.get("execution_state") == "completed"
        and isinstance(digest, str)
        and bool(_HEX_64.fullmatch(digest))
        and attestation.get("verifier_pack_present") is True
        and attestation.get("verifier_pack_started") is True
        and attestation.get("verifier_pack_completed") is True
        and _is_int(pack_passed)
        and _is_int(pack_total)
        and pack_total > 0
        and pack_passed == pack_total
    )
    checks.expect(
        "pack.pass_evidence",
        pass_valid,
        "PASS includes a present, identity-verified, completed, all-passing pack",
        "PASS requiring a pack lacks complete trusted pack evidence",
    )


def _check_composite(
    checks: _Checks,
    record: dict[str, Any],
    assurance: dict[str, Any] | None,
    attestation: dict[str, Any] | None,
) -> None:
    source = record.get("verdict_source")
    if not _known_string(
        source,
        frozenset({"composite:repo+verifier-pack", "composite:blackbox+repo"}),
    ):
        checks.skip("composite.counts", "record does not claim a composite verdict source")
        checks.skip("composite.phase_semantics", "record is not a completed composite")
        return
    if attestation is None:
        checks.fail("composite.counts", "composite counts cannot be checked without attestation")
        checks.fail("composite.phase_semantics", "composite phases require attestation")
        return
    top_passed = record.get("tests_passed")
    top_total = record.get("tests_total")
    pack_passed = attestation.get("verifier_pack_tests_passed")
    pack_total = attestation.get("verifier_pack_tests_total")
    numeric = all(_is_int(value) for value in (top_passed, top_total, pack_passed, pack_total))
    counts_valid = False
    numeric_counts: tuple[int, int, int, int] | None = None
    if numeric:
        numeric_counts = (
            cast(int, top_passed),
            cast(int, top_total),
            cast(int, pack_passed),
            cast(int, pack_total),
        )
        top_passed_i, top_total_i, pack_passed_i, pack_total_i = numeric_counts
        counts_valid = (
            0 <= pack_passed_i <= pack_total_i <= top_total_i
            and pack_passed_i <= top_passed_i
            and 0
            <= top_passed_i - pack_passed_i
            <= top_total_i - pack_total_i
        )
    checks.expect(
        "composite.counts",
        counts_valid,
        "top-level totals contain the pack totals and leave a valid repo remainder",
        "composite totals cannot be decomposed into valid pack and repo counts",
    )

    phase_valid = (
        record.get("execution_state") == "completed"
        and record.get("test_command_ran") is True
        and attestation.get("verifier_pack_started") is True
        and attestation.get("verifier_pack_completed") is True
    )
    repo_phase_claimed = any(
        attestation.get(field) is not None
        for field in (
            "repo_suite_started",
            "repo_suite_completed",
            "repo_suite_state",
            "repo_suite_passed",
            "repo_suite_tests_passed",
            "repo_suite_tests_total",
            "repo_suite_verdict_source",
            "repo_suite_returncode",
            "repo_suite_junit_sha256",
            "repo_suite_junit_digest_format",
        )
    )
    if source == "composite:blackbox+repo":
        phase_valid = phase_valid and (
            attestation.get("repo_suite_started") is True
            and attestation.get("repo_suite_completed") is True
            and attestation.get("repo_suite_state") == "composed_completed"
            and isinstance(attestation.get("repo_suite_passed"), bool)
            and assurance is not None
            and assurance.get("repo_native_suite") == "composed_completed"
            and assurance.get("report_integrity") == "same_process_candidate_writable"
        )
        if numeric_counts is not None:
            top_passed_i, top_total_i, pack_passed_i, pack_total_i = numeric_counts
            repo_passed = top_passed_i - pack_passed_i
            repo_total = top_total_i - pack_total_i
            phase_valid = (
                phase_valid and pack_total_i > 0 and pack_passed_i == pack_total_i
            )
            if attestation.get("repo_suite_passed") is True:
                phase_valid = phase_valid and repo_total > 0 and repo_passed == repo_total
            else:
                phase_valid = phase_valid and repo_total > 0 and repo_passed < repo_total
    elif _requires_repo_phase_evidence(attestation) and not repo_phase_claimed:
        phase_valid = False
    elif repo_phase_claimed:
        suite_passed = attestation.get("repo_suite_tests_passed")
        suite_total = attestation.get("repo_suite_tests_total")
        suite_source = attestation.get("repo_suite_verdict_source")
        suite_returncode = attestation.get("repo_suite_returncode")
        suite_digest = attestation.get("repo_suite_junit_sha256")
        suite_digest_format = attestation.get("repo_suite_junit_digest_format")
        suite_digest_valid = (
            isinstance(suite_digest, str)
            and bool(_HEX_64.fullmatch(suite_digest))
            and _known_string(suite_digest_format, _JUNIT_PHASE_FORMATS)
            if suite_source == "junit+exit"
            else suite_digest is None and suite_digest_format is None
        )
        composite_digest_valid = True
        if attestation.get("junit_digest_format") == JUNIT_COMPOSITE_DIGEST_FORMAT:
            pack_digest = attestation.get("verifier_pack_junit_sha256")
            pack_digest_format = attestation.get(
                "verifier_pack_junit_digest_format"
            )
            top_digest = attestation.get("junit_sha256")
            top_digest_format = attestation.get("junit_digest_format")
            composite_digest_valid = (
                isinstance(suite_digest, str)
                and bool(_HEX_64.fullmatch(suite_digest))
                and _known_string(suite_digest_format, _JUNIT_PHASE_FORMATS)
                and isinstance(pack_digest, str)
                and bool(_HEX_64.fullmatch(pack_digest))
                and pack_digest_format == JUNIT_XML_DIGEST_FORMAT
                and isinstance(top_digest, str)
                and bool(_HEX_64.fullmatch(top_digest))
                and top_digest_format == JUNIT_COMPOSITE_DIGEST_FORMAT
            )
            if composite_digest_valid:
                composite_identity = (
                    JUNIT_COMPOSITE_DIGEST_FORMAT
                    + "\0repo\0"
                    + cast(str, suite_digest_format)
                    + "\0"
                    + cast(str, suite_digest)
                    + "\0verifier-pack\0"
                    + JUNIT_XML_DIGEST_FORMAT
                    + "\0"
                    + cast(str, pack_digest)
                )
                composite_digest_valid = hashlib.sha256(
                    composite_identity.encode("utf-8")
                ).hexdigest() == cast(str, top_digest)
        elif (
            suite_digest_format == JUNIT_REPORT_SET_DIGEST_FORMAT
            or _requires_repo_phase_evidence(attestation)
            and suite_source == "junit+exit"
        ):
            composite_digest_valid = False
        phase_valid = phase_valid and (
            attestation.get("repo_suite_started") is True
            and attestation.get("repo_suite_completed") is True
            and attestation.get("repo_suite_state") == "repo_phase_completed"
            and isinstance(attestation.get("repo_suite_passed"), bool)
            and _is_int(suite_passed)
            and _is_int(suite_total)
            and suite_source in ("junit+exit", "exit")
            and _is_int(suite_returncode)
            and suite_returncode in (0, 1)
            and suite_digest_valid
            and composite_digest_valid
        )
        if numeric_counts is not None and _is_int(suite_passed) and _is_int(suite_total):
            top_passed_i, top_total_i, pack_passed_i, pack_total_i = numeric_counts
            repo_passed = top_passed_i - pack_passed_i
            repo_total = top_total_i - pack_total_i
            clean_repo_pass = (
                suite_returncode == 0
                and (
                    suite_passed == 0 and suite_total == 0
                    if suite_source == "exit"
                    else suite_total > 0 and suite_passed == suite_total
                )
            )
            phase_valid = phase_valid and (
                pack_total_i > 0
                and suite_passed == repo_passed
                and suite_total == repo_total
                and attestation.get("repo_suite_passed") is clean_repo_pass
            )
    checks.expect(
        "composite.phase_semantics",
        bool(phase_valid),
        "composite lifecycle and weakest-channel semantics are consistent",
        "composite source contradicts phase lifecycle or channel semantics",
    )


def _verify_record(record: object) -> dict[str, Any]:
    """Return a machine-readable semantic verification report.

    ``ok`` means no contradiction was found in the claims that were available.
    A ``skip`` is intentionally not upgraded into a pass: for example, a null
    attestation is allowed by the record schema but cannot prove policy binding.
    """
    checks = _Checks()
    if not isinstance(record, dict):
        checks.fail("document.object", "the JSON root must be an object")
        return checks.report()
    checks.pass_("document.object", "the JSON root is an object")

    missing = sorted(_REQUIRED_TOP_LEVEL - record.keys())
    checks.expect(
        "envelope.required_fields",
        not missing,
        "all schema-1.11 top-level fields are present",
        f"missing top-level fields: {', '.join(missing)}",
    )
    type_errors = _top_level_type_errors(record)
    checks.expect(
        "envelope.types",
        not type_errors,
        "top-level field types are valid",
        "; ".join(type_errors),
    )
    diagnostics = record.get("diagnostics")
    envelope_shape = (
        isinstance(record.get("reason"), str)
        and bool(record.get("reason"))
        and isinstance(record.get("execution_phase"), str)
        and bool(record.get("execution_phase"))
        and isinstance(diagnostics, str)
        and len(diagnostics) <= 2000
        and record.get("base_reconstruction") in (None, "ok", "failed")
    )
    checks.expect(
        "envelope.shape",
        envelope_shape,
        "top-level strings, diagnostics bound, and reconstruction state are valid",
        "reason/phase must be non-empty, diagnostics <= 2000, and reconstruction valid",
    )

    schema_version = record.get("schema_version")
    checks.expect(
        "identity.schema_version",
        _known_string(schema_version, SUPPORTED_SCHEMA_VERSIONS),
        f"schema_version {schema_version!r} is supported",
        f"unsupported schema_version {schema_version!r}",
    )
    checks.expect(
        "identity.tool",
        record.get("tool") == "evoguard",
        "tool identity is evoguard",
        f"unexpected tool identity {record.get('tool')!r}",
    )
    checks.expect(
        "identity.tool_version",
        isinstance(record.get("tool_version"), str) and bool(record.get("tool_version")),
        "tool_version is a non-empty string",
        "tool_version must be a non-empty string",
    )
    checks.expect(
        "identity.enums",
        _known_string(record.get("verdict"), _VERDICTS)
        and _known_string(record.get("reason_code"), _REASON_CODES)
        and _known_string(record.get("risk_level"), _RISK_LEVELS)
        and _known_string(record.get("execution_state"), _EXECUTION_STATES)
        and (
            record.get("verdict_source") is None
            or _known_string(record.get("verdict_source"), _VERDICT_SOURCES)
        )
        and _known_string(record.get("isolation"), _ISOLATIONS),
        "verdict, risk, lifecycle, source, and isolation values are recognized",
        "one or more schema-1.11 enum values are unknown",
    )
    risk = record.get("risk_score")
    checks.expect(
        "risk.range",
        _is_number(risk) and 0 <= risk <= 1,
        "risk_score is in the closed interval 0..1",
        "risk_score must be a number in 0..1",
    )

    assurance_value = record.get("assurance")
    assurance = assurance_value if isinstance(assurance_value, dict) else None
    attestation_value = record.get("attestation")
    attestation = attestation_value if isinstance(attestation_value, dict) else None
    _nested_type_checks(checks, assurance, attestation)

    if attestation is None:
        checks.skip("identity.guard_version_parity", "attestation is unavailable")
    else:
        checks.expect(
            "identity.guard_version_parity",
            attestation.get("guard_version") == record.get("tool_version"),
            "tool_version matches attestation.guard_version",
            "tool_version contradicts attestation.guard_version",
        )

    _check_lifecycle(checks, record, assurance, attestation)
    _check_verdict_and_counts(checks, record)
    policy = _check_policy(checks, record, attestation)
    _check_evidence_contracts(checks, record, policy, attestation)
    _check_policy_runtime_bindings(checks, record, assurance, attestation, policy)
    _check_receipts(checks, record, assurance, attestation)
    _check_isolation(checks, record, assurance, attestation)
    _check_source_contract(checks, record, assurance, attestation, policy)
    _check_assurance_semantics(checks, record, assurance, policy)
    _check_pack(checks, record, assurance, attestation, policy)
    _check_composite(checks, record, assurance, attestation)
    return checks.report(schema_version)


def verify_record(record: object) -> dict[str, Any]:
    """Total public wrapper: every JSON-like value produces a report."""
    try:
        return _verify_record(record)
    except Exception as exc:  # pragma: no cover - final total-function guard
        checks = _Checks()
        checks.fail(
            "document.semantic_processing",
            f"record could not be processed safely ({type(exc).__name__}: {exc})",
        )
        return checks.report(
            record.get("schema_version") if isinstance(record, dict) else None
        )


def invalid_json_report(message: str) -> dict[str, Any]:
    """Return the same report envelope for an unreadable/non-JSON input."""
    checks = _Checks()
    checks.fail("document.json", message)
    return checks.report()
