# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Deterministic pre-extraction characterization for nested record validation."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evoom_guard import record_verifier
from evoom_guard.verifiers.record_report import RecordChecks

ROOT = Path(__file__).resolve().parents[1]
GOLDEN_RECORD = ROOT / "tests/fixtures/contracts/schema-1.11-golden.json"

ASSURANCE_REQUIRED_FIELDS = (
    "candidate_isolation",
    "execution_phase",
    "execution_state",
    "harness_integrity",
    "overall_profile",
    "report_integrity",
    "runtime_continuity",
    "setup_isolation",
    "suite_isolation",
    "verifier_pack",
)
ATTESTATION_REQUIRED_FIELDS = (
    "candidate_invocations",
    "candidate_launcher_invocation_observed",
    "candidate_sha256",
    "created_utc",
    "delivered_isolation",
    "effective_candidate_isolation",
    "effective_policy",
    "execution_phase",
    "execution_state",
    "guard_version",
    "mode",
    "policy_sha256",
    "test_command_started",
    "verifier_pack_completed",
    "verifier_pack_digest_format",
    "verifier_pack_present",
    "verifier_pack_sha256",
    "verifier_pack_started",
    "verifier_pack_tests_passed",
    "verifier_pack_tests_total",
)


@dataclass(frozen=True, slots=True)
class NestedCase:
    assurance: dict[str, Any] | None
    attestation: dict[str, Any] | None


def _valid_pair() -> tuple[dict[str, Any], dict[str, Any]]:
    record = _valid_record()
    return copy.deepcopy(record["assurance"]), copy.deepcopy(record["attestation"])


def _valid_record(*, schema_version: str = "1.11") -> dict[str, Any]:
    payload = json.loads(GOLDEN_RECORD.read_text(encoding="utf-8"))
    record = copy.deepcopy(payload["records"]["valid_composite"])
    if schema_version == "1.12":
        record["schema_version"] = schema_version
        policy = record["attestation"]["effective_policy"]
        policy["operating_profile"] = "local"
        record["attestation"]["policy_sha256"] = record_verifier._policy_sha256(policy)
    return record


def _case(
    *,
    assurance_updates: dict[str, Any] | None = None,
    attestation_updates: dict[str, Any] | None = None,
) -> NestedCase:
    assurance, attestation = _valid_pair()
    if assurance_updates:
        assurance.update(copy.deepcopy(assurance_updates))
    if attestation_updates:
        attestation.update(copy.deepcopy(attestation_updates))
    return NestedCase(assurance=assurance, attestation=attestation)


def cases() -> dict[str, NestedCase]:
    result = {
        "valid": _case(),
        "assurance_null": NestedCase(None, _valid_pair()[1]),
        "attestation_null": NestedCase(_valid_pair()[0], None),
        "both_null": NestedCase(None, None),
    }

    for field in ASSURANCE_REQUIRED_FIELDS:
        assurance, attestation = _valid_pair()
        del assurance[field]
        result[f"assurance_missing_{field}"] = NestedCase(assurance, attestation)
    for field in ATTESTATION_REQUIRED_FIELDS:
        assurance, attestation = _valid_pair()
        del attestation[field]
        result[f"attestation_missing_{field}"] = NestedCase(assurance, attestation)

    result.update(
        {
            "assurance_wrong_types": _case(
                assurance_updates={
                    "execution_state": 1,
                    "execution_phase": 1,
                    "harness_integrity": 1,
                    "report_integrity": 1,
                    "candidate_isolation": 1,
                    "suite_isolation": 1,
                    "runtime_continuity": 1,
                    "overall_profile": 1,
                    "setup_isolation": [],
                    "verifier_pack": [],
                }
            ),
            "assurance_invalid_shapes": _case(
                assurance_updates={
                    "execution_state": "unknown",
                    "execution_phase": "",
                    "harness_integrity": "unknown",
                    "report_integrity": "unknown",
                    "candidate_isolation": "unknown",
                    "suite_isolation": "unknown",
                    "setup_isolation": "unknown",
                    "overall_profile": "unknown",
                    "repo_native_suite": "unknown",
                }
            ),
            "assurance_invalid_pack_shape": _case(
                assurance_updates={
                    "verifier_pack": {
                        "configured": False,
                        "present": 1,
                        "integrity": "unknown",
                        "identity_verified": 1,
                        "execution_state": "unknown",
                        "secrecy": "unknown",
                        "snapshot_sha256": "A" * 64,
                    }
                }
            ),
            "attestation_wrong_types": _case(
                attestation_updates={
                    "created_utc": [],
                    "guard_version": [],
                    "mode": [],
                    "candidate_sha256": [],
                    "policy_sha256": [],
                    "execution_state": [],
                    "execution_phase": [],
                    "delivered_isolation": [],
                    "effective_candidate_isolation": [],
                    "effective_policy": [],
                    "test_command_started": 1,
                    "candidate_invocations": True,
                    "candidate_launcher_invocation_observed": 1,
                    "verifier_pack_present": 1,
                    "verifier_pack_started": 1,
                    "verifier_pack_completed": 1,
                    "verifier_pack_tests_passed": True,
                    "verifier_pack_tests_total": True,
                    "repo_suite_tests_passed": True,
                    "repo_suite_tests_total": True,
                    "repo_suite_returncode": True,
                    "repo_suite_started": 1,
                    "repo_suite_completed": 1,
                    "repo_suite_passed": 1,
                    "junit_sha256": [],
                    "junit_digest_format": [],
                    "verifier_pack_junit_sha256": [],
                    "verifier_pack_junit_digest_format": [],
                    "repo_suite_state": [],
                    "repo_suite_junit_sha256": [],
                    "repo_suite_junit_digest_format": [],
                    "repo_suite_verdict_source": [],
                    "verifier_pack_sha256": [],
                    "verifier_pack_digest_format": [],
                }
            ),
            "attestation_invalid_shapes": _case(
                attestation_updates={
                    "created_utc": "not-a-timestamp",
                    "guard_version": "",
                    "mode": "unknown",
                    "candidate_sha256": "A" * 64,
                    "policy_sha256": "b" * 63,
                    "execution_state": "unknown",
                    "execution_phase": "",
                    "delivered_isolation": "unknown",
                    "effective_candidate_isolation": "unknown",
                    "candidate_invocations": -1,
                }
            ),
            "top_junit_digest_without_format": _case(
                attestation_updates={"junit_sha256": "c" * 64, "junit_digest_format": None}
            ),
            "pack_junit_format_without_digest": _case(
                attestation_updates={
                    "verifier_pack_junit_sha256": None,
                    "verifier_pack_junit_digest_format": "EVOGUARD_JUNIT_XML_V1",
                }
            ),
            "repo_junit_digest_without_format": _case(
                attestation_updates={
                    "repo_suite_junit_sha256": "d" * 64,
                    "repo_suite_junit_digest_format": None,
                }
            ),
            "preflight_null_effective_valid": _case(
                attestation_updates={
                    "execution_state": "not_started",
                    "test_command_started": False,
                    "delivered_isolation": "not_run",
                    "effective_candidate_isolation": None,
                }
            ),
            "preflight_null_wrong_state": _case(
                attestation_updates={
                    "execution_state": "completed",
                    "test_command_started": False,
                    "delivered_isolation": "not_run",
                    "effective_candidate_isolation": None,
                }
            ),
            "preflight_null_command_started": _case(
                attestation_updates={
                    "execution_state": "not_started",
                    "test_command_started": True,
                    "delivered_isolation": "not_run",
                    "effective_candidate_isolation": None,
                }
            ),
            "preflight_null_wrong_delivery": _case(
                attestation_updates={
                    "execution_state": "not_started",
                    "test_command_started": False,
                    "delivered_isolation": "subprocess",
                    "effective_candidate_isolation": None,
                }
            ),
            "simultaneous_nested_faults": _case(
                assurance_updates={"execution_state": 1, "verifier_pack": None},
                attestation_updates={
                    "created_utc": [],
                    "candidate_sha256": "A" * 64,
                    "candidate_invocations": -1,
                    "junit_sha256": "e" * 64,
                    "junit_digest_format": None,
                },
            ),
        }
    )
    return result


def capture(case: NestedCase) -> list[dict[str, str]]:
    assurance_before = copy.deepcopy(case.assurance)
    attestation_before = copy.deepcopy(case.attestation)
    checks = RecordChecks()
    record_verifier._nested_type_checks(checks, case.assurance, case.attestation)
    assert case.assurance == assurance_before
    assert case.attestation == attestation_before
    return copy.deepcopy(checks.items)


def capture_all() -> dict[str, list[dict[str, str]]]:
    return {name: capture(case) for name, case in cases().items()}


def public_cases() -> dict[str, dict[str, Any]]:
    assurance_non_object = _valid_record()
    assurance_non_object["assurance"] = "not-an-object"
    attestation_non_object = _valid_record()
    attestation_non_object["attestation"] = ["not-an-object"]
    return {
        "valid_schema_1_11": _valid_record(),
        "valid_schema_1_12": _valid_record(schema_version="1.12"),
        "assurance_non_object": assurance_non_object,
        "attestation_non_object": attestation_non_object,
    }


def capture_public(record: dict[str, Any]) -> dict[str, Any]:
    before = copy.deepcopy(record)
    report = record_verifier.verify_record(record)
    assert record == before
    return report


def capture_public_all() -> dict[str, dict[str, Any]]:
    return {name: capture_public(record) for name, record in public_cases().items()}
