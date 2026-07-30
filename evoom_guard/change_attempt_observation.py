# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Bounded advisory observations from authenticated Trusted Finalizer bundles.

The wire object is a deterministic projection of one verified ``.evb``.  It
does not widen Agent Change admission, turn record fields into independent
witnesses, or grant merge/deployment authority.  Local verification time and
projector identity live only in :class:`VerifiedChangeAttemptObservation`.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime, timezone
from typing import Any

from evoom_guard import __version__
from evoom_guard.domain.verdict import (
    EXECUTION_STATES,
    REASON_CODES,
    REASON_CONTRACT,
    VERDICTS,
)
from evoom_guard.evidence_bundle import (
    BUNDLE_FORMAT,
    MAX_ARCHIVE_BYTES,
    EvidenceBundleError,
    canonical_json_bytes,
    load_json_object_bytes,
    read_regular_file_bytes,
    sha256_bytes,
)
from evoom_guard.runtime_identity import (
    RUNTIME_IDENTITY_MAX_ENTRIES,
    RUNTIME_IDENTITY_MAX_LOGICAL_BYTES,
)
from evoom_guard.signing import SigningUnavailableError
from evoom_guard.trusted_finalizer import (
    VerifiedFinalizedBundle,
    verify_finalized_bundle,
)

CHANGE_ATTEMPT_OBSERVATION_FORMAT = "EVOGUARD_CHANGE_ATTEMPT_OBSERVATION_V1"
CHANGE_ATTEMPT_CONSUMER_SCHEMA = "evorise.change-advisory.attempt-observation.v1"
CHANGE_ATTEMPT_EXECUTION_EVIDENCE_FORMAT = "EVOGUARD_CHANGE_ATTEMPT_EXECUTION_EVIDENCE_V1"
CHANGE_ATTEMPT_PROJECTOR_ID = f"evoguard-change-attempt-projector/{__version__}"
MAX_CHANGE_ATTEMPT_OBSERVATION_BYTES = 512 * 1024

_ROOT_KEYS = {
    "format",
    "consumer_schema",
    "source",
    "signed_evidence",
    "outcome",
    "assurance",
    "evidence_channels",
    "authority",
}
_SOURCE_KEYS = {
    "repository",
    "repository_id",
    "pull_request_number",
    "handoff_workflow_run_id",
    "handoff_workflow_run_attempt",
    "context_run_id",
    "context_run_attempt",
    "base_sha",
    "head_sha",
    "base_tree_sha",
    "head_tree_sha",
    "candidate_sha256",
    "effective_policy_sha256",
    "verifier_pack_sha256",
    "guard_artifact_sha256",
}
_SIGNED_EVIDENCE_KEYS = {
    "bundle_format",
    "bundle_sha256",
    "verdict_record_sha256",
    "verdict_record_size",
    "record_schema",
    "record_tool",
    "record_tool_version",
    "signature_algorithm",
    "finalizer_key_id",
    "correlation_group_id",
}
_OUTCOME_KEYS = {
    "decision",
    "verdict",
    "passed",
    "reason_code",
    "execution_state",
    "execution_phase",
    "verdict_source",
}
_ASSURANCE_KEYS = {
    "harness_integrity",
    "report_integrity",
    "candidate_isolation",
    "setup_isolation",
    "repository_suite_isolation",
    "runtime_identity_continuity",
    "overall_profile",
}
_CHANNEL_KEYS = {
    "raw_git_binding",
    "guard_execution",
    "repository_suite",
    "verifier_pack",
    "runtime_identity",
}
_PROVENANCE_KEYS = {
    "origin",
    "receipt_format",
    "receipt_sha256",
    "producer_key_id",
    "correlation_group_id",
    "independently_countable",
}
_RAW_GIT_KEYS = {
    "scope",
    "availability",
    "bound_identity_count",
    "binding_sha256",
    "provenance",
}
_GUARD_KEYS = {
    "scope",
    "availability",
    "test_command_started",
    "candidate_invocation_count",
    "execution_evidence_sha256",
    "provenance",
}
_REPOSITORY_SUITE_KEYS = {
    "scope",
    "availability",
    "started",
    "completed",
    "passed",
    "tests_passed",
    "tests_total",
    "result_sha256",
    "provenance",
}
_VERIFIER_PACK_KEYS = {
    "scope",
    "availability",
    "present",
    "started",
    "completed",
    "tests_passed",
    "tests_total",
    "result_sha256",
    "provenance",
}
_RUNTIME_KEYS = {
    "scope",
    "availability",
    "exported_identity_count",
    "tree_sha256",
    "tree_entries",
    "tree_bytes",
    "provenance",
}
_AUTHORITY_KEYS = {
    "mode",
    "admission",
    "merge",
    "deployment",
    "promotion",
    "external_action",
}

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_KEY_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CORRELATION_ID = re.compile(r"cg:sha256:[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,63}\Z")

_EXECUTION_PHASES = frozenset(
    {
        "pre_gate",
        "preflight",
        "candidate_prepare",
        "setup",
        "blackbox_judge",
        "blackbox_pack",
        "repo_suite",
        "verifier_pack",
        "runtime_verification",
        "complete",
    }
)
_VERDICT_SOURCES = frozenset(
    {
        "junit+exit",
        "exit",
        "blackbox",
        "composite:repo+verifier-pack",
        "composite:blackbox+repo",
    }
)
_REPORT_INTEGRITIES = frozenset(
    {
        "same_process_candidate_writable",
        "external_process_isolated",
        "not_applicable_static_gate",
        "not_applicable_not_run",
    }
)
_ISOLATIONS = frozenset({"not_run", "subprocess", "docker", "gvisor"})
_SETUP_ISOLATIONS = frozenset(
    {"subprocess", "docker", "gvisor", "subprocess_host_opt_in", "unavailable"}
)
_RUNTIME_CONTINUITIES = frozenset(
    {
        "not_applicable",
        "unavailable",
        "incomplete",
        "verification_failed",
        "read_only_enforced",
        "snapshot_boundary_checked",
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
_AVAILABILITIES = frozenset({"AVAILABLE", "UNAVAILABLE", "NOT_APPLICABLE"})


class ChangeAttemptObservationError(ValueError):
    """The observation is malformed, untrusted, mismatched, or unsafe."""


@dataclass(frozen=True)
class InspectedChangeAttemptObservation:
    """Canonical observation bytes passing bounded projection checks.

    Inspection is neither full verdict-record verification nor
    authentication. Use
    :func:`verify_change_attempt_observation` with the original finalizer
    bundle and external trust inputs before relying on the projected facts.
    """

    observation_bytes: bytes

    @property
    def payload(self) -> dict[str, Any]:
        try:
            value = load_json_object_bytes(
                self.observation_bytes,
                "change-attempt observation",
            )
        except EvidenceBundleError as exc:  # pragma: no cover - constructor is internal
            raise ChangeAttemptObservationError(str(exc)) from exc
        return _validate_observation_payload(value)


@dataclass(frozen=True)
class VerifiedChangeAttemptObservation:
    """One observation re-projected from an authenticated finalizer bundle.

    ``verifier_id``, ``verified_at``, and ``observation_sha256`` are local
    wrapper metadata. They are intentionally absent from the deterministic
    wire object and are not facts authenticated by the finalizer signature.
    """

    inspection: InspectedChangeAttemptObservation
    finalized: VerifiedFinalizedBundle = dataclass_field(repr=False)
    verifier_id: str
    verified_at: str
    observation_sha256: str


def _object(value: object, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ChangeAttemptObservationError(f"{label} must be an object")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], *, label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ChangeAttemptObservationError(
            f"{label} keys are not canonical "
            f"(missing={sorted(expected - actual)}, unknown={sorted(actual - expected)})"
        )


def _bounded_string(value: object, *, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ChangeAttemptObservationError(
            f"{label} must be a non-empty string of at most {maximum} characters"
        )
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ChangeAttemptObservationError(
            f"{label} must not contain an unpaired surrogate"
        ) from exc
    if any(ord(character) < 0x20 for character in value):
        raise ChangeAttemptObservationError(f"{label} must not contain control characters")
    return value


def _integer(
    value: object,
    *,
    label: str,
    minimum: int = 0,
    maximum: int = 2_147_483_647,
) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise ChangeAttemptObservationError(
            f"{label} must be an integer from {minimum} through {maximum}"
        )
    return value


def _nullable_integer(
    value: object,
    *,
    label: str,
    maximum: int = 2_147_483_647,
) -> int | None:
    if value is None:
        return None
    return _integer(value, label=label, maximum=maximum)


def _boolean(value: object, *, label: str) -> bool:
    if type(value) is not bool:
        raise ChangeAttemptObservationError(f"{label} must be a boolean")
    return value


def _nullable_boolean(value: object, *, label: str) -> bool | None:
    if value is None:
        return None
    return _boolean(value, label=label)


def _one_of(
    value: object,
    choices: frozenset[str] | set[str],
    *,
    label: str,
    nullable: bool = False,
) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or value not in choices:
        raise ChangeAttemptObservationError(f"{label} is not a supported value")
    return value


def _digest(value: object, *, label: str, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ChangeAttemptObservationError(
            f"{label} must be a lowercase 64-character SHA-256 digest"
        )
    return value


def _git_digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise ChangeAttemptObservationError(
            f"{label} must be a lowercase 40/64-character Git digest"
        )
    return value


def _correlation_group(bundle_sha256: str, key_id: str) -> str:
    digest = hashlib.sha256(
        b"EVOGUARD_CORRELATION_GROUP_V1\0"
        b"SIGNED_FINALIZER_BUNDLE\0"
        b"EVOGUARD_EVIDENCE_BUNDLE_V1\0"
        + bundle_sha256.encode("ascii")
        + b"\0"
        + key_id.encode("ascii")
    ).hexdigest()
    return f"cg:sha256:{digest}"


def _execution_evidence_sha256(
    *,
    verdict_record_sha256: str,
    test_command_started: bool,
    candidate_invocation_count: int | None,
) -> str:
    return sha256_bytes(
        canonical_json_bytes(
            {
                "format": CHANGE_ATTEMPT_EXECUTION_EVIDENCE_FORMAT,
                "verdict_record_sha256": verdict_record_sha256,
                "test_command_started": test_command_started,
                "candidate_invocation_count": candidate_invocation_count,
            }
        )
    )


def _validate_source(value: object) -> dict[str, Any]:
    source = _object(value, label="observation source")
    _exact_keys(source, _SOURCE_KEYS, label="observation source")
    _bounded_string(source["repository"], label="source.repository", maximum=512)
    _bounded_string(source["repository_id"], label="source.repository_id", maximum=256)
    _integer(
        source["pull_request_number"],
        label="source.pull_request_number",
        minimum=1,
    )
    _bounded_string(
        source["handoff_workflow_run_id"],
        label="source.handoff_workflow_run_id",
        maximum=256,
    )
    _integer(
        source["handoff_workflow_run_attempt"],
        label="source.handoff_workflow_run_attempt",
        minimum=1,
    )
    _bounded_string(source["context_run_id"], label="source.context_run_id", maximum=256)
    _integer(
        source["context_run_attempt"],
        label="source.context_run_attempt",
        minimum=1,
    )
    for field in ("base_sha", "head_sha", "base_tree_sha", "head_tree_sha"):
        _git_digest(source[field], label=f"source.{field}")
    for field in (
        "candidate_sha256",
        "effective_policy_sha256",
        "guard_artifact_sha256",
    ):
        _digest(source[field], label=f"source.{field}")
    _digest(
        source["verifier_pack_sha256"],
        label="source.verifier_pack_sha256",
        nullable=True,
    )
    return source


def _validate_signed_evidence(value: object) -> dict[str, Any]:
    evidence = _object(value, label="signed evidence")
    _exact_keys(evidence, _SIGNED_EVIDENCE_KEYS, label="signed evidence")
    if evidence["bundle_format"] != BUNDLE_FORMAT:
        raise ChangeAttemptObservationError("signed_evidence.bundle_format is unsupported")
    _digest(evidence["bundle_sha256"], label="signed_evidence.bundle_sha256")
    _digest(
        evidence["verdict_record_sha256"],
        label="signed_evidence.verdict_record_sha256",
    )
    _integer(
        evidence["verdict_record_size"],
        label="signed_evidence.verdict_record_size",
        minimum=1,
        maximum=8 * 1024 * 1024,
    )
    if evidence["record_schema"] not in {"1.11", "1.12"}:
        raise ChangeAttemptObservationError("signed_evidence.record_schema is unsupported")
    if evidence["record_tool"] != "evoguard":
        raise ChangeAttemptObservationError("signed_evidence.record_tool must be evoguard")
    version = evidence["record_tool_version"]
    if not isinstance(version, str) or _VERSION.fullmatch(version) is None:
        raise ChangeAttemptObservationError("signed_evidence.record_tool_version is not canonical")
    if evidence["signature_algorithm"] != "Ed25519":
        raise ChangeAttemptObservationError("signed_evidence.signature_algorithm must be Ed25519")
    key_id = evidence["finalizer_key_id"]
    if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
        raise ChangeAttemptObservationError("signed_evidence.finalizer_key_id is not canonical")
    correlation = evidence["correlation_group_id"]
    if not isinstance(correlation, str) or _CORRELATION_ID.fullmatch(correlation) is None:
        raise ChangeAttemptObservationError("signed_evidence.correlation_group_id is not canonical")
    expected_correlation = _correlation_group(evidence["bundle_sha256"], key_id)
    if correlation != expected_correlation:
        raise ChangeAttemptObservationError("signed_evidence.correlation_group_id is inconsistent")
    return evidence


def _validate_outcome(value: object) -> dict[str, Any]:
    outcome = _object(value, label="outcome")
    _exact_keys(outcome, _OUTCOME_KEYS, label="outcome")
    if outcome["decision"] not in {"ALLOW", "DENY"}:
        raise ChangeAttemptObservationError("outcome.decision is unsupported")
    verdict = _one_of(outcome["verdict"], set(VERDICTS), label="outcome.verdict")
    passed = _boolean(outcome["passed"], label="outcome.passed")
    reason_code = _one_of(
        outcome["reason_code"],
        set(REASON_CODES),
        label="outcome.reason_code",
    )
    execution_state = _one_of(
        outcome["execution_state"],
        set(EXECUTION_STATES),
        label="outcome.execution_state",
    )
    _one_of(
        outcome["execution_phase"],
        set(_EXECUTION_PHASES),
        label="outcome.execution_phase",
    )
    _one_of(
        outcome["verdict_source"],
        set(_VERDICT_SOURCES),
        label="outcome.verdict_source",
        nullable=True,
    )
    should_allow = verdict == "PASS" and passed is True
    if (outcome["decision"] == "ALLOW") is not should_allow:
        raise ChangeAttemptObservationError(
            "outcome decision is inconsistent with verdict and passed"
        )
    if passed is not (verdict == "PASS"):
        raise ChangeAttemptObservationError(
            "outcome.passed must be true if and only if verdict is PASS"
        )
    if not isinstance(reason_code, str) or not isinstance(execution_state, str):
        raise ChangeAttemptObservationError("outcome lifecycle values are unavailable")
    allowed_verdicts, allowed_states = REASON_CONTRACT[reason_code]
    if verdict not in allowed_verdicts or execution_state not in allowed_states:
        raise ChangeAttemptObservationError(
            "outcome reason, verdict, and execution state are inconsistent"
        )
    return outcome


def _validate_assurance(value: object) -> dict[str, Any]:
    assurance = _object(value, label="assurance")
    _exact_keys(assurance, _ASSURANCE_KEYS, label="assurance")
    if assurance["harness_integrity"] != "pre_gate_enforced":
        raise ChangeAttemptObservationError("assurance.harness_integrity must be pre_gate_enforced")
    _one_of(
        assurance["report_integrity"],
        set(_REPORT_INTEGRITIES),
        label="assurance.report_integrity",
    )
    _one_of(
        assurance["candidate_isolation"],
        set(_ISOLATIONS),
        label="assurance.candidate_isolation",
    )
    _one_of(
        assurance["setup_isolation"],
        set(_SETUP_ISOLATIONS),
        label="assurance.setup_isolation",
        nullable=True,
    )
    _one_of(
        assurance["repository_suite_isolation"],
        set(_ISOLATIONS),
        label="assurance.repository_suite_isolation",
    )
    _one_of(
        assurance["runtime_identity_continuity"],
        set(_RUNTIME_CONTINUITIES),
        label="assurance.runtime_identity_continuity",
    )
    _one_of(
        assurance["overall_profile"],
        set(_OVERALL_PROFILES),
        label="assurance.overall_profile",
    )
    return assurance


def _validate_provenance(
    value: object,
    *,
    label: str,
    signed_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    provenance = _object(value, label=label)
    _exact_keys(provenance, _PROVENANCE_KEYS, label=label)
    if provenance["origin"] != "SIGNED_FINALIZER_BUNDLE":
        raise ChangeAttemptObservationError(f"{label}.origin is unsupported")
    if provenance["receipt_format"] != BUNDLE_FORMAT:
        raise ChangeAttemptObservationError(f"{label}.receipt_format is unsupported")
    if provenance["receipt_sha256"] != signed_evidence["bundle_sha256"]:
        raise ChangeAttemptObservationError(f"{label}.receipt_sha256 is inconsistent")
    if provenance["producer_key_id"] != signed_evidence["finalizer_key_id"]:
        raise ChangeAttemptObservationError(f"{label}.producer_key_id is inconsistent")
    if provenance["correlation_group_id"] != signed_evidence["correlation_group_id"]:
        raise ChangeAttemptObservationError(f"{label}.correlation_group_id is inconsistent")
    if provenance["independently_countable"] is not False:
        raise ChangeAttemptObservationError(f"{label}.independently_countable must be false")
    return provenance


def _validate_availability(value: object, *, label: str) -> str:
    result = _one_of(value, set(_AVAILABILITIES), label=label)
    assert isinstance(result, str)
    return result


def _validate_test_counts(
    passed: object,
    total: object,
    *,
    label: str,
) -> tuple[int | None, int | None]:
    passed_count = _nullable_integer(passed, label=f"{label}.tests_passed")
    total_count = _nullable_integer(total, label=f"{label}.tests_total")
    if (passed_count is None) != (total_count is None):
        raise ChangeAttemptObservationError(
            f"{label} test counts must both be null or both be integers"
        )
    if passed_count is not None and total_count is not None and passed_count > total_count:
        raise ChangeAttemptObservationError(f"{label}.tests_passed must not exceed tests_total")
    return passed_count, total_count


def _validate_raw_git_channel(
    value: object,
    *,
    signed_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    channel = _object(value, label="raw_git_binding channel")
    _exact_keys(channel, _RAW_GIT_KEYS, label="raw_git_binding channel")
    if channel["scope"] != "RAW_GIT_BINDING":
        raise ChangeAttemptObservationError("raw_git_binding.scope must be RAW_GIT_BINDING")
    if channel["availability"] != "UNAVAILABLE":
        raise ChangeAttemptObservationError("raw_git_binding.availability must be UNAVAILABLE")
    if channel["bound_identity_count"] is not None or channel["binding_sha256"] is not None:
        raise ChangeAttemptObservationError("unavailable raw_git_binding fields must be null")
    _validate_provenance(
        channel["provenance"],
        label="raw_git_binding.provenance",
        signed_evidence=signed_evidence,
    )
    return channel


def _validate_guard_channel(
    value: object,
    *,
    signed_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    channel = _object(value, label="guard_execution channel")
    _exact_keys(channel, _GUARD_KEYS, label="guard_execution channel")
    if channel["scope"] != "SIGNED_RECORD_CLAIM":
        raise ChangeAttemptObservationError("guard_execution.scope must be SIGNED_RECORD_CLAIM")
    availability = _validate_availability(
        channel["availability"],
        label="guard_execution.availability",
    )
    if availability == "AVAILABLE":
        started = _boolean(
            channel["test_command_started"],
            label="guard_execution.test_command_started",
        )
        invocations = _nullable_integer(
            channel["candidate_invocation_count"],
            label="guard_execution.candidate_invocation_count",
        )
        expected_digest = _execution_evidence_sha256(
            verdict_record_sha256=str(signed_evidence["verdict_record_sha256"]),
            test_command_started=started,
            candidate_invocation_count=invocations,
        )
        if channel["execution_evidence_sha256"] != expected_digest:
            raise ChangeAttemptObservationError(
                "guard_execution.execution_evidence_sha256 is inconsistent"
            )
    else:
        if any(
            channel[field] is not None
            for field in (
                "test_command_started",
                "candidate_invocation_count",
                "execution_evidence_sha256",
            )
        ):
            raise ChangeAttemptObservationError("unavailable guard_execution fields must be null")
    _validate_provenance(
        channel["provenance"],
        label="guard_execution.provenance",
        signed_evidence=signed_evidence,
    )
    return channel


def _validate_repository_suite_channel(
    value: object,
    *,
    signed_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    channel = _object(value, label="repository_suite channel")
    _exact_keys(channel, _REPOSITORY_SUITE_KEYS, label="repository_suite channel")
    if channel["scope"] != "SIGNED_RECORD_CLAIM":
        raise ChangeAttemptObservationError("repository_suite.scope must be SIGNED_RECORD_CLAIM")
    availability = _validate_availability(
        channel["availability"],
        label="repository_suite.availability",
    )
    if availability == "AVAILABLE":
        started = _boolean(channel["started"], label="repository_suite.started")
        completed = _boolean(channel["completed"], label="repository_suite.completed")
        passed = _nullable_boolean(channel["passed"], label="repository_suite.passed")
        tests_passed, tests_total = _validate_test_counts(
            channel["tests_passed"],
            channel["tests_total"],
            label="repository_suite",
        )
        result_sha256 = _digest(
            channel["result_sha256"],
            label="repository_suite.result_sha256",
            nullable=True,
        )
        if completed and not started:
            raise ChangeAttemptObservationError("repository_suite.completed requires started")
        if passed is not None and not completed:
            raise ChangeAttemptObservationError("repository_suite.passed requires completed")
        if completed and passed is None:
            raise ChangeAttemptObservationError(
                "completed repository_suite requires a boolean passed value"
            )
        if not completed and any(
            item is not None for item in (tests_passed, tests_total, result_sha256)
        ):
            raise ChangeAttemptObservationError(
                "incomplete repository_suite cannot carry result facts"
            )
    else:
        if any(
            channel[field] is not None
            for field in (
                "started",
                "completed",
                "passed",
                "tests_passed",
                "tests_total",
                "result_sha256",
            )
        ):
            raise ChangeAttemptObservationError("unavailable repository_suite fields must be null")
    _validate_provenance(
        channel["provenance"],
        label="repository_suite.provenance",
        signed_evidence=signed_evidence,
    )
    return channel


def _validate_verifier_pack_channel(
    value: object,
    *,
    signed_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    channel = _object(value, label="verifier_pack channel")
    _exact_keys(channel, _VERIFIER_PACK_KEYS, label="verifier_pack channel")
    if channel["scope"] != "SIGNED_RECORD_CLAIM":
        raise ChangeAttemptObservationError("verifier_pack.scope must be SIGNED_RECORD_CLAIM")
    availability = _validate_availability(
        channel["availability"],
        label="verifier_pack.availability",
    )
    if availability == "AVAILABLE":
        present = _boolean(channel["present"], label="verifier_pack.present")
        started = _boolean(channel["started"], label="verifier_pack.started")
        completed = _boolean(channel["completed"], label="verifier_pack.completed")
        tests_passed, tests_total = _validate_test_counts(
            channel["tests_passed"],
            channel["tests_total"],
            label="verifier_pack",
        )
        result_sha256 = _digest(
            channel["result_sha256"],
            label="verifier_pack.result_sha256",
            nullable=True,
        )
        if started and not present:
            raise ChangeAttemptObservationError("verifier_pack.started requires present")
        if completed and not started:
            raise ChangeAttemptObservationError("verifier_pack.completed requires started")
        if not completed and any(
            item is not None for item in (tests_passed, tests_total, result_sha256)
        ):
            raise ChangeAttemptObservationError(
                "incomplete verifier_pack cannot carry result facts"
            )
    else:
        if any(
            channel[field] is not None
            for field in (
                "present",
                "started",
                "completed",
                "tests_passed",
                "tests_total",
                "result_sha256",
            )
        ):
            raise ChangeAttemptObservationError("unavailable verifier_pack fields must be null")
    _validate_provenance(
        channel["provenance"],
        label="verifier_pack.provenance",
        signed_evidence=signed_evidence,
    )
    return channel


def _validate_runtime_channel(
    value: object,
    *,
    signed_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    channel = _object(value, label="runtime_identity channel")
    _exact_keys(channel, _RUNTIME_KEYS, label="runtime_identity channel")
    if channel["scope"] != "SIGNED_RECORD_CLAIM":
        raise ChangeAttemptObservationError("runtime_identity.scope must be SIGNED_RECORD_CLAIM")
    availability = _validate_availability(
        channel["availability"],
        label="runtime_identity.availability",
    )
    if availability == "AVAILABLE":
        if channel["exported_identity_count"] != 1:
            raise ChangeAttemptObservationError(
                "available runtime_identity must export exactly one identity"
            )
        _digest(channel["tree_sha256"], label="runtime_identity.tree_sha256")
        _integer(
            channel["tree_entries"],
            label="runtime_identity.tree_entries",
            maximum=RUNTIME_IDENTITY_MAX_ENTRIES,
        )
        _integer(
            channel["tree_bytes"],
            label="runtime_identity.tree_bytes",
            maximum=RUNTIME_IDENTITY_MAX_LOGICAL_BYTES,
        )
    else:
        if channel["exported_identity_count"] != 0:
            raise ChangeAttemptObservationError(
                "unavailable runtime_identity must export zero identities"
            )
        if any(
            channel[field] is not None for field in ("tree_sha256", "tree_entries", "tree_bytes")
        ):
            raise ChangeAttemptObservationError("unavailable runtime_identity fields must be null")
    _validate_provenance(
        channel["provenance"],
        label="runtime_identity.provenance",
        signed_evidence=signed_evidence,
    )
    return channel


def _validate_channels(
    value: object,
    *,
    source: dict[str, Any],
    signed_evidence: Mapping[str, Any],
    outcome: dict[str, Any],
    assurance: dict[str, Any],
) -> dict[str, Any]:
    channels = _object(value, label="evidence_channels")
    _exact_keys(channels, _CHANNEL_KEYS, label="evidence_channels")
    _validate_raw_git_channel(
        channels["raw_git_binding"],
        signed_evidence=signed_evidence,
    )
    _validate_guard_channel(
        channels["guard_execution"],
        signed_evidence=signed_evidence,
    )
    _validate_repository_suite_channel(
        channels["repository_suite"],
        signed_evidence=signed_evidence,
    )
    _validate_verifier_pack_channel(
        channels["verifier_pack"],
        signed_evidence=signed_evidence,
    )
    _validate_runtime_channel(
        channels["runtime_identity"],
        signed_evidence=signed_evidence,
    )
    pack_availability = channels["verifier_pack"]["availability"]
    pack_is_applicable = source["verifier_pack_sha256"] is not None
    if (pack_availability == "NOT_APPLICABLE") != (not pack_is_applicable):
        raise ChangeAttemptObservationError(
            "verifier_pack availability contradicts its source identity"
        )

    runtime_availability = channels["runtime_identity"]["availability"]
    runtime_is_applicable = assurance["runtime_identity_continuity"] != "not_applicable"
    if (runtime_availability == "NOT_APPLICABLE") != (not runtime_is_applicable):
        raise ChangeAttemptObservationError(
            "runtime_identity availability contradicts assurance continuity"
        )

    repository_availability = channels["repository_suite"]["availability"]
    profile = assurance["overall_profile"]
    required_repository_availability = {
        "black_box_external_judge": "NOT_APPLICABLE",
        "composite_blackbox_repo_native": "AVAILABLE",
        "blackbox_composite_short_circuit": "UNAVAILABLE",
    }.get(profile)
    if (
        required_repository_availability is not None
        and repository_availability != required_repository_availability
    ):
        raise ChangeAttemptObservationError(
            "repository_suite availability contradicts the assurance profile"
        )

    report_integrity = assurance["report_integrity"]
    if report_integrity == "not_applicable_static_gate":
        if (
            profile != "static_gate"
            or outcome["execution_state"] != "static_gate"
            or assurance["candidate_isolation"] != "not_run"
            or assurance["repository_suite_isolation"] != "not_run"
        ):
            raise ChangeAttemptObservationError(
                "static-gate report integrity contradicts outcome or assurance"
            )
    elif profile == "static_gate":
        raise ChangeAttemptObservationError(
            "static_gate profile requires static-gate report integrity"
        )

    if report_integrity == "not_applicable_not_run" and (
        outcome["decision"] == "ALLOW" or outcome["execution_state"] == "completed"
    ):
        raise ChangeAttemptObservationError(
            "not-run report integrity contradicts a completed or allowed outcome"
        )
    if outcome["decision"] == "ALLOW" and report_integrity.startswith("not_applicable_"):
        raise ChangeAttemptObservationError(
            "an allowed outcome requires an applicable report-integrity claim"
        )
    return channels


def _validate_authority(value: object) -> dict[str, Any]:
    authority = _object(value, label="authority")
    _exact_keys(authority, _AUTHORITY_KEYS, label="authority")
    if authority["mode"] != "ADVISORY_ONLY":
        raise ChangeAttemptObservationError("authority.mode must be ADVISORY_ONLY")
    for field in ("admission", "merge", "deployment", "promotion", "external_action"):
        if authority[field] is not False:
            raise ChangeAttemptObservationError(f"authority.{field} must be false")
    return authority


def _validate_observation_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(value)
    _exact_keys(payload, _ROOT_KEYS, label="change-attempt observation")
    if payload["format"] != CHANGE_ATTEMPT_OBSERVATION_FORMAT:
        raise ChangeAttemptObservationError("unsupported change-attempt format")
    if payload["consumer_schema"] != CHANGE_ATTEMPT_CONSUMER_SCHEMA:
        raise ChangeAttemptObservationError("unsupported change-attempt consumer schema")
    source = _validate_source(payload["source"])
    signed_evidence = _validate_signed_evidence(payload["signed_evidence"])
    outcome = _validate_outcome(payload["outcome"])
    assurance = _validate_assurance(payload["assurance"])
    _validate_channels(
        payload["evidence_channels"],
        source=source,
        signed_evidence=signed_evidence,
        outcome=outcome,
        assurance=assurance,
    )
    _validate_authority(payload["authority"])
    return payload


def _common_provenance(
    *,
    bundle_sha256: str,
    finalizer_key_id: str,
    correlation_group_id: str,
) -> dict[str, Any]:
    return {
        "origin": "SIGNED_FINALIZER_BUNDLE",
        "receipt_format": BUNDLE_FORMAT,
        "receipt_sha256": bundle_sha256,
        "producer_key_id": finalizer_key_id,
        "correlation_group_id": correlation_group_id,
        "independently_countable": False,
    }


def _unavailable_channel(
    *,
    scope: str,
    availability: str,
    fields: tuple[str, ...],
    provenance: dict[str, Any],
) -> dict[str, Any]:
    return {
        "scope": scope,
        "availability": availability,
        **{field: None for field in fields},
        "provenance": dict(provenance),
    }


def _project_guard_channel(
    attestation: Mapping[str, Any],
    *,
    verdict_record_sha256: str,
    provenance: dict[str, Any],
) -> dict[str, Any]:
    started = attestation.get("test_command_started")
    invocations = attestation.get("candidate_invocations")
    invocations_valid = invocations is None or (
        type(invocations) is int and 0 <= invocations <= 2_147_483_647
    )
    if type(started) is not bool or not invocations_valid:
        return _unavailable_channel(
            scope="SIGNED_RECORD_CLAIM",
            availability="UNAVAILABLE",
            fields=(
                "test_command_started",
                "candidate_invocation_count",
                "execution_evidence_sha256",
            ),
            provenance=provenance,
        )
    return {
        "scope": "SIGNED_RECORD_CLAIM",
        "availability": "AVAILABLE",
        "test_command_started": started,
        "candidate_invocation_count": invocations,
        "execution_evidence_sha256": _execution_evidence_sha256(
            verdict_record_sha256=verdict_record_sha256,
            test_command_started=started,
            candidate_invocation_count=invocations,
        ),
        "provenance": dict(provenance),
    }


def _project_repository_suite_channel(
    attestation: Mapping[str, Any],
    *,
    provenance: dict[str, Any],
) -> dict[str, Any]:
    started = attestation.get("repo_suite_started")
    completed = attestation.get("repo_suite_completed")
    if attestation.get("repo_suite_state") == "not_required_blackbox_only":
        return _unavailable_channel(
            scope="SIGNED_RECORD_CLAIM",
            availability="NOT_APPLICABLE",
            fields=(
                "started",
                "completed",
                "passed",
                "tests_passed",
                "tests_total",
                "result_sha256",
            ),
            provenance=provenance,
        )
    if type(started) is bool and type(completed) is bool:
        return {
            "scope": "SIGNED_RECORD_CLAIM",
            "availability": "AVAILABLE",
            "started": started,
            "completed": completed,
            "passed": attestation.get("repo_suite_passed"),
            "tests_passed": attestation.get("repo_suite_tests_passed"),
            "tests_total": attestation.get("repo_suite_tests_total"),
            "result_sha256": attestation.get("repo_suite_junit_sha256"),
            "provenance": dict(provenance),
        }
    return _unavailable_channel(
        scope="SIGNED_RECORD_CLAIM",
        availability="UNAVAILABLE",
        fields=(
            "started",
            "completed",
            "passed",
            "tests_passed",
            "tests_total",
            "result_sha256",
        ),
        provenance=provenance,
    )


def _project_verifier_pack_channel(
    attestation: Mapping[str, Any],
    *,
    verifier_pack_sha256: str | None,
    provenance: dict[str, Any],
) -> dict[str, Any]:
    if verifier_pack_sha256 is None:
        return _unavailable_channel(
            scope="SIGNED_RECORD_CLAIM",
            availability="NOT_APPLICABLE",
            fields=(
                "present",
                "started",
                "completed",
                "tests_passed",
                "tests_total",
                "result_sha256",
            ),
            provenance=provenance,
        )
    present = attestation.get("verifier_pack_present")
    started = attestation.get("verifier_pack_started")
    completed = attestation.get("verifier_pack_completed")
    if all(type(item) is bool for item in (present, started, completed)):
        return {
            "scope": "SIGNED_RECORD_CLAIM",
            "availability": "AVAILABLE",
            "present": present,
            "started": started,
            "completed": completed,
            "tests_passed": attestation.get("verifier_pack_tests_passed"),
            "tests_total": attestation.get("verifier_pack_tests_total"),
            "result_sha256": attestation.get("verifier_pack_junit_sha256"),
            "provenance": dict(provenance),
        }
    return _unavailable_channel(
        scope="SIGNED_RECORD_CLAIM",
        availability="UNAVAILABLE",
        fields=(
            "present",
            "started",
            "completed",
            "tests_passed",
            "tests_total",
            "result_sha256",
        ),
        provenance=provenance,
    )


def _project_runtime_channel(
    attestation: Mapping[str, Any],
    *,
    runtime_continuity: str,
    provenance: dict[str, Any],
) -> dict[str, Any]:
    if runtime_continuity == "not_applicable":
        return {
            "scope": "SIGNED_RECORD_CLAIM",
            "availability": "NOT_APPLICABLE",
            "exported_identity_count": 0,
            "tree_sha256": None,
            "tree_entries": None,
            "tree_bytes": None,
            "provenance": dict(provenance),
        }
    tree_sha256 = attestation.get("runtime_tree_sha256")
    tree_entries = attestation.get("runtime_tree_entries")
    tree_bytes = attestation.get("runtime_tree_bytes")
    available = (
        isinstance(tree_sha256, str)
        and _SHA256.fullmatch(tree_sha256) is not None
        and type(tree_entries) is int
        and 0 <= tree_entries <= RUNTIME_IDENTITY_MAX_ENTRIES
        and type(tree_bytes) is int
        and 0 <= tree_bytes <= RUNTIME_IDENTITY_MAX_LOGICAL_BYTES
    )
    if available:
        return {
            "scope": "SIGNED_RECORD_CLAIM",
            "availability": "AVAILABLE",
            "exported_identity_count": 1,
            "tree_sha256": tree_sha256,
            "tree_entries": tree_entries,
            "tree_bytes": tree_bytes,
            "provenance": dict(provenance),
        }
    return {
        "scope": "SIGNED_RECORD_CLAIM",
        "availability": "UNAVAILABLE",
        "exported_identity_count": 0,
        "tree_sha256": None,
        "tree_entries": None,
        "tree_bytes": None,
        "provenance": dict(provenance),
    }


def _project_observation(
    finalized: VerifiedFinalizedBundle,
    *,
    bundle_sha256: str,
) -> dict[str, Any]:
    """Purely project a verified finalizer result into the frozen V1 wire."""

    try:
        manifest = finalized.bundle.manifest
        context = _object(manifest["context"], label="verified bundle context")
        record_descriptor = _object(
            manifest["record"],
            label="verified bundle record descriptor",
        )
        authentication = _object(
            manifest["authentication"],
            label="verified bundle authentication",
        )
        handoff_source = finalized.handoff.source
        verdict = finalized.bundle.verdict
        assurance_record = _object(verdict["assurance"], label="verified assurance")
        attestation = _object(verdict["attestation"], label="verified attestation")
    except KeyError as exc:
        raise ChangeAttemptObservationError(
            "verified finalizer bundle lacks a required projection field"
        ) from exc

    source = {
        "repository": context.get("repository"),
        "repository_id": context.get("repository_id"),
        "pull_request_number": handoff_source.get("pull_request_number"),
        "handoff_workflow_run_id": handoff_source.get("workflow_run_id"),
        "handoff_workflow_run_attempt": handoff_source.get("workflow_run_attempt"),
        "context_run_id": context.get("run_id"),
        "context_run_attempt": context.get("run_attempt"),
        "base_sha": context.get("base_sha"),
        "head_sha": context.get("head_sha"),
        "base_tree_sha": context.get("base_tree_sha"),
        "head_tree_sha": context.get("head_tree_sha"),
        "candidate_sha256": context.get("candidate_sha256"),
        "effective_policy_sha256": context.get("policy_sha256"),
        "verifier_pack_sha256": context.get("verifier_pack_sha256"),
        "guard_artifact_sha256": context.get("guard_artifact_sha256"),
    }
    finalizer_key_id = authentication.get("key_id")
    if not isinstance(finalizer_key_id, str):
        raise ChangeAttemptObservationError("verified bundle finalizer key identity is unavailable")
    correlation_group_id = _correlation_group(bundle_sha256, finalizer_key_id)
    signed_evidence = {
        "bundle_format": manifest.get("format"),
        "bundle_sha256": bundle_sha256,
        "verdict_record_sha256": record_descriptor.get("sha256"),
        "verdict_record_size": record_descriptor.get("size"),
        "record_schema": record_descriptor.get("schema_version"),
        "record_tool": record_descriptor.get("tool"),
        "record_tool_version": record_descriptor.get("tool_version"),
        "signature_algorithm": authentication.get("algorithm"),
        "finalizer_key_id": finalizer_key_id,
        "correlation_group_id": correlation_group_id,
    }
    outcome = {
        "decision": finalized.decision,
        "verdict": verdict.get("verdict"),
        "passed": verdict.get("passed"),
        "reason_code": verdict.get("reason_code"),
        "execution_state": verdict.get("execution_state"),
        "execution_phase": verdict.get("execution_phase"),
        "verdict_source": verdict.get("verdict_source"),
    }
    assurance = {
        "harness_integrity": assurance_record.get("harness_integrity"),
        "report_integrity": assurance_record.get("report_integrity"),
        "candidate_isolation": assurance_record.get("candidate_isolation"),
        "setup_isolation": assurance_record.get("setup_isolation"),
        "repository_suite_isolation": assurance_record.get("suite_isolation"),
        "runtime_identity_continuity": assurance_record.get("runtime_continuity"),
        "overall_profile": assurance_record.get("overall_profile"),
    }
    provenance = _common_provenance(
        bundle_sha256=bundle_sha256,
        finalizer_key_id=finalizer_key_id,
        correlation_group_id=correlation_group_id,
    )
    runtime_continuity = assurance["runtime_identity_continuity"]
    if not isinstance(runtime_continuity, str):
        raise ChangeAttemptObservationError("verified assurance runtime continuity is unavailable")
    evidence_channels = {
        "raw_git_binding": {
            "scope": "RAW_GIT_BINDING",
            "availability": "UNAVAILABLE",
            "bound_identity_count": None,
            "binding_sha256": None,
            "provenance": dict(provenance),
        },
        "guard_execution": _project_guard_channel(
            attestation,
            verdict_record_sha256=str(record_descriptor.get("sha256")),
            provenance=provenance,
        ),
        "repository_suite": _project_repository_suite_channel(
            attestation,
            provenance=provenance,
        ),
        "verifier_pack": _project_verifier_pack_channel(
            attestation,
            verifier_pack_sha256=context.get("verifier_pack_sha256"),
            provenance=provenance,
        ),
        "runtime_identity": _project_runtime_channel(
            attestation,
            runtime_continuity=runtime_continuity,
            provenance=provenance,
        ),
    }
    payload = {
        "format": CHANGE_ATTEMPT_OBSERVATION_FORMAT,
        "consumer_schema": CHANGE_ATTEMPT_CONSUMER_SCHEMA,
        "source": source,
        "signed_evidence": signed_evidence,
        "outcome": outcome,
        "assurance": assurance,
        "evidence_channels": evidence_channels,
        "authority": {
            "mode": "ADVISORY_ONLY",
            "admission": False,
            "merge": False,
            "deployment": False,
            "promotion": False,
            "external_action": False,
        },
    }
    return _validate_observation_payload(payload)


def _materialize_private_snapshot(directory: str, data: bytes) -> str:
    path = os.path.join(directory, "finalized.evb")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o600)
    finally:
        os.close(descriptor)
    return path


def _snapshot_trust_mapping(
    value: Mapping[str, Any],
    *,
    label: str,
) -> dict[str, Any]:
    """Detach one caller-owned trust mapping from later mutation."""

    try:
        snapshot_bytes = canonical_json_bytes(dict(value))
        return load_json_object_bytes(snapshot_bytes, label)
    except (EvidenceBundleError, TypeError, ValueError, RuntimeError):
        raise ChangeAttemptObservationError(
            f"{label} could not be captured as a closed JSON object"
        ) from None


def _reject_output_input_aliases(
    output_path: str,
    *,
    input_paths: tuple[str, ...],
) -> None:
    """Prevent force publication from replacing any security input."""

    try:
        output_absolute = os.path.abspath(output_path)
        output_identities = {
            os.path.normcase(output_absolute),
            os.path.normcase(os.path.realpath(output_absolute)),
        }
        for input_path in input_paths:
            input_absolute = os.path.abspath(input_path)
            input_identities = {
                os.path.normcase(input_absolute),
                os.path.normcase(os.path.realpath(input_absolute)),
            }
            aliases = bool(output_identities & input_identities)
            if not aliases and os.path.exists(output_absolute) and os.path.exists(input_absolute):
                aliases = os.path.samefile(output_absolute, input_absolute)
            if aliases:
                raise ChangeAttemptObservationError(
                    "change-attempt output must not alias a security input"
                )
    except ChangeAttemptObservationError:
        raise
    except (OSError, RuntimeError, ValueError):
        raise ChangeAttemptObservationError(
            "change-attempt output/input alias check failed"
        ) from None


def _verified_bundle_snapshot(
    bundle_path: str,
    *,
    trusted_finalizer_public_key_path: str,
    expected_source: Mapping[str, Any],
    expected_context: Mapping[str, Any],
) -> tuple[VerifiedFinalizedBundle, str]:
    """Read the caller-controlled bundle path once, then verify those same bytes."""

    try:
        snapshot = read_regular_file_bytes(
            bundle_path,
            limit=MAX_ARCHIVE_BYTES,
            label="finalized evidence bundle",
        )
        bundle_sha256 = sha256_bytes(snapshot)
        with tempfile.TemporaryDirectory(prefix=".evoguard-change-attempt-") as directory:
            try:
                os.chmod(directory, 0o700)
            except OSError:
                pass
            snapshot_path = _materialize_private_snapshot(directory, snapshot)
            finalized = verify_finalized_bundle(
                snapshot_path,
                trusted_public_key_path=trusted_finalizer_public_key_path,
                expected_source=expected_source,
                expected_context=expected_context,
            )
    except SigningUnavailableError:
        # Optional signing support being absent is an operational condition,
        # not evidence that the supplied bundle is cryptographically invalid.
        raise
    except (OSError, RuntimeError, ValueError):
        raise ChangeAttemptObservationError(
            "trusted finalizer bundle verification failed"
        ) from None
    return finalized, bundle_sha256


def _published_observation(
    path: str,
    data: bytes,
    *,
    force: bool,
) -> str:
    absolute_output = os.path.abspath(path)
    parent = os.path.dirname(absolute_output) or os.curdir
    if os.path.isdir(absolute_output):
        raise ChangeAttemptObservationError(
            f"change-attempt observation output is a directory: {absolute_output}"
        )
    os.makedirs(parent, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=".evoguard-change-attempt-",
        dir=parent,
    )
    committed = False
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        if force:
            os.replace(temporary, absolute_output)
            committed = True
        else:
            try:
                os.link(temporary, absolute_output, follow_symlinks=False)
            except FileExistsError as exc:
                raise ChangeAttemptObservationError(
                    f"refusing to overwrite existing observation: {absolute_output}"
                ) from exc
            except OSError as exc:
                raise ChangeAttemptObservationError(
                    "cannot publish observation with atomic no-clobber semantics; "
                    "use a filesystem supporting hard links or pass force=True"
                ) from exc
            committed = True
            try:
                os.unlink(temporary)
            except OSError:
                # The requested path is already atomically committed. A
                # same-content temporary hard link is non-sensitive cleanup,
                # and must not turn successful publication into a false
                # failure that invites a conflicting retry.
                pass
    except BaseException:
        if not committed:
            try:
                os.unlink(temporary)
            except OSError:
                pass
        raise
    return absolute_output


def _verified_wrapper(
    inspection: InspectedChangeAttemptObservation,
    finalized: VerifiedFinalizedBundle,
) -> VerifiedChangeAttemptObservation:
    verified_at = datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    return VerifiedChangeAttemptObservation(
        inspection=inspection,
        finalized=finalized,
        verifier_id=CHANGE_ATTEMPT_PROJECTOR_ID,
        verified_at=verified_at,
        observation_sha256=sha256_bytes(inspection.observation_bytes),
    )


def inspect_change_attempt_observation_bytes(
    data: bytes,
) -> InspectedChangeAttemptObservation:
    """Check canonical V1 wire shape without making an authenticity claim."""

    if not isinstance(data, bytes):
        raise ChangeAttemptObservationError("change-attempt observation must be bytes")
    if not data or len(data) > MAX_CHANGE_ATTEMPT_OBSERVATION_BYTES:
        raise ChangeAttemptObservationError(
            "change-attempt observation is empty or exceeds its size limit"
        )
    try:
        payload = load_json_object_bytes(data, "change-attempt observation")
        if canonical_json_bytes(payload) != data:
            raise ChangeAttemptObservationError("change-attempt observation is not canonical JSON")
    except EvidenceBundleError as exc:
        raise ChangeAttemptObservationError(str(exc)) from exc
    _validate_observation_payload(payload)
    return InspectedChangeAttemptObservation(observation_bytes=data)


def inspect_change_attempt_observation(
    path: str,
) -> InspectedChangeAttemptObservation:
    """Read one stable bounded file, then inspect its non-authoritative shape."""

    try:
        data = read_regular_file_bytes(
            path,
            limit=MAX_CHANGE_ATTEMPT_OBSERVATION_BYTES,
            label="change-attempt observation",
        )
    except (OSError, ValueError):
        raise ChangeAttemptObservationError("could not read change-attempt observation") from None
    return inspect_change_attempt_observation_bytes(data)


def produce_change_attempt_observation(
    bundle_path: str,
    output_path: str,
    *,
    trusted_finalizer_public_key_path: str,
    expected_source: Mapping[str, Any],
    expected_context: Mapping[str, Any],
    force: bool = False,
) -> VerifiedChangeAttemptObservation:
    """Authenticate one finalizer bundle and publish its deterministic projection."""

    _reject_output_input_aliases(
        output_path,
        input_paths=(
            bundle_path,
            trusted_finalizer_public_key_path,
        ),
    )
    source_snapshot = _snapshot_trust_mapping(
        expected_source,
        label="expected source",
    )
    context_snapshot = _snapshot_trust_mapping(
        expected_context,
        label="expected context",
    )
    finalized, bundle_sha256 = _verified_bundle_snapshot(
        bundle_path,
        trusted_finalizer_public_key_path=trusted_finalizer_public_key_path,
        expected_source=source_snapshot,
        expected_context=context_snapshot,
    )
    payload = _project_observation(finalized, bundle_sha256=bundle_sha256)
    try:
        observation_bytes = canonical_json_bytes(payload)
    except EvidenceBundleError as exc:  # pragma: no cover - projection is closed
        raise ChangeAttemptObservationError(
            f"could not encode change-attempt observation: {exc}"
        ) from exc
    published_path = _published_observation(
        output_path,
        observation_bytes,
        force=force,
    )
    try:
        published_bytes = read_regular_file_bytes(
            published_path,
            limit=MAX_CHANGE_ATTEMPT_OBSERVATION_BYTES,
            label="published change-attempt observation",
        )
    except (OSError, ValueError):
        raise ChangeAttemptObservationError(
            "could not read back the published change-attempt observation"
        ) from None
    if published_bytes != observation_bytes:
        raise ChangeAttemptObservationError(
            "published change-attempt observation does not match the verified bytes"
        )
    inspection = inspect_change_attempt_observation_bytes(published_bytes)
    return _verified_wrapper(inspection, finalized)


def verify_change_attempt_observation_bytes(
    data: bytes,
    *,
    bundle_path: str,
    trusted_finalizer_public_key_path: str,
    expected_source: Mapping[str, Any],
    expected_context: Mapping[str, Any],
) -> VerifiedChangeAttemptObservation:
    """Re-authenticate and re-project the bundle, then require exact wire bytes."""

    inspection = inspect_change_attempt_observation_bytes(data)
    source_snapshot = _snapshot_trust_mapping(
        expected_source,
        label="expected source",
    )
    context_snapshot = _snapshot_trust_mapping(
        expected_context,
        label="expected context",
    )
    finalized, bundle_sha256 = _verified_bundle_snapshot(
        bundle_path,
        trusted_finalizer_public_key_path=trusted_finalizer_public_key_path,
        expected_source=source_snapshot,
        expected_context=context_snapshot,
    )
    expected_payload = _project_observation(
        finalized,
        bundle_sha256=bundle_sha256,
    )
    try:
        expected_bytes = canonical_json_bytes(expected_payload)
    except EvidenceBundleError as exc:  # pragma: no cover - projection is closed
        raise ChangeAttemptObservationError(
            f"could not encode expected change-attempt observation: {exc}"
        ) from exc
    if inspection.observation_bytes != expected_bytes:
        raise ChangeAttemptObservationError(
            "change-attempt observation does not exactly match the authenticated bundle"
        )
    return _verified_wrapper(inspection, finalized)


def verify_change_attempt_observation(
    observation_path: str,
    *,
    bundle_path: str,
    trusted_finalizer_public_key_path: str,
    expected_source: Mapping[str, Any],
    expected_context: Mapping[str, Any],
) -> VerifiedChangeAttemptObservation:
    """Verify a retained observation against its bundle and external trust roots."""

    try:
        data = read_regular_file_bytes(
            observation_path,
            limit=MAX_CHANGE_ATTEMPT_OBSERVATION_BYTES,
            label="change-attempt observation",
        )
    except (OSError, ValueError):
        raise ChangeAttemptObservationError("could not read change-attempt observation") from None
    return verify_change_attempt_observation_bytes(
        data,
        bundle_path=bundle_path,
        trusted_finalizer_public_key_path=trusted_finalizer_public_key_path,
        expected_source=expected_source,
        expected_context=expected_context,
    )


__all__ = [
    "CHANGE_ATTEMPT_CONSUMER_SCHEMA",
    "CHANGE_ATTEMPT_OBSERVATION_FORMAT",
    "CHANGE_ATTEMPT_PROJECTOR_ID",
    "ChangeAttemptObservationError",
    "InspectedChangeAttemptObservation",
    "MAX_CHANGE_ATTEMPT_OBSERVATION_BYTES",
    "VerifiedChangeAttemptObservation",
    "inspect_change_attempt_observation",
    "inspect_change_attempt_observation_bytes",
    "produce_change_attempt_observation",
    "verify_change_attempt_observation",
    "verify_change_attempt_observation_bytes",
]
