# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Translate repository-verifier artifacts into typed decision evidence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from evoom_guard.domain.evidence import (
    IsolationPayloadEvidence,
    RepositorySuiteEvidence,
    RuntimeIdentityEvidence,
    VerificationEvidence,
    VerifierPackEvidence,
)
from evoom_guard.domain.execution import ExecutionPhaseResult, IsolationObservation

_INCOMPLETE_OUTCOMES = {
    "test_timeout",
    "test_output_limit",
    "setup_timeout",
    "setup_output_limit",
    "runtime_containment_error",
}


def _isolation_observation(
    value: object,
) -> IsolationObservation | None:
    """Read the frozen isolation shape without retaining the source mapping."""

    if not isinstance(value, Mapping):
        return None
    return IsolationObservation(
        requested=str(value.get("requested", "")),
        delivered=str(value.get("delivered", "")),
        image_digest=cast(str | None, value.get("image_digest")),
        network=cast(str | None, value.get("network")),
        runtime=cast(str | None, value.get("runtime")),
        note=cast(str | None, value.get("note")),
    )


def _isolation_wire_payload(
    value: object,
) -> Mapping[str, object] | None:
    """Own an observation's exact key set for wire-compatible projection."""

    return cast(Mapping[str, object], value) if isinstance(value, Mapping) else None


def repo_verification_evidence_from_artifact(
    artifact: Mapping[str, Any],
    *,
    default_isolation: str,
) -> VerificationEvidence:
    """Own and type the artifact facts used by the repository decision layer.

    The lifecycle fallbacks deliberately reproduce Guard's pre-extraction
    compatibility behavior for third-party ``RepoVerifier`` subclasses that
    still return a pre-1.11 artifact.
    """

    outcome = cast(str | None, artifact.get("outcome"))
    verdict_source = cast(str | None, artifact.get("verdict_source"))
    fallback_started = (
        verdict_source is not None
        or outcome in {"test_timeout", "test_output_limit"}
    )
    execution_state = str(
        artifact.get(
            "execution_state",
            "completed"
            if verdict_source
            else "started_incomplete"
            if outcome in _INCOMPLETE_OUTCOMES
            else "not_started",
        )
    )
    execution_phase = str(artifact.get("execution_phase", "repo_suite"))
    test_command_started = bool(
        artifact.get("test_command_started", fallback_started)
    )
    test_command_completed = bool(
        artifact.get(
            "test_command_completed",
            test_command_started and execution_state == "completed",
        )
    )
    recorded_isolation = str(
        artifact.get(
            "delivered_isolation",
            default_isolation if test_command_started else "not_run",
        )
    )
    delivered_isolation = recorded_isolation if test_command_started else "not_run"

    manifest = artifact.get("verifier_pack_manifest")
    pack_manifest = (
        cast(Mapping[str, object], manifest)
        if isinstance(manifest, Mapping)
        else None
    )

    return VerificationEvidence(
        execution=ExecutionPhaseResult(
            execution_state=execution_state,
            execution_phase=execution_phase,
            test_command_started=test_command_started,
            test_command_completed=test_command_completed,
            verifier_pack_started=bool(
                artifact.get("verifier_pack_started", False)
            ),
            verifier_pack_completed=bool(
                artifact.get("verifier_pack_completed", False)
            ),
            delivered_isolation=delivered_isolation,
            setup_isolation_evidence=_isolation_observation(
                artifact.get("setup_isolation_evidence")
            ),
            repo_suite_isolation_evidence=_isolation_observation(
                artifact.get("repo_suite_isolation_evidence")
            ),
            verifier_pack_isolation_evidence=_isolation_observation(
                artifact.get("verifier_pack_isolation_evidence")
            ),
            primary_isolation_evidence=_isolation_observation(
                artifact.get("isolation_evidence")
            ),
        ),
        outcome=outcome,
        tamper=cast(bool | None, artifact.get("tamper")),
        tests_passed=cast(int | None, artifact.get("tests_passed")),
        tests_total=cast(int | None, artifact.get("tests_total")),
        tests_passed_present="tests_passed" in artifact,
        tests_total_present="tests_total" in artifact,
        verdict_source=verdict_source,
        junit_sha256=cast(str | None, artifact.get("junit_sha256")),
        junit_digest_format=cast(
            str | None, artifact.get("junit_digest_format")
        ),
        setup_isolation=cast(str | None, artifact.get("setup_isolation")),
        isolation_payloads=IsolationPayloadEvidence(
            primary=_isolation_wire_payload(
                artifact.get("isolation_evidence")
            ),
            setup=_isolation_wire_payload(
                artifact.get("setup_isolation_evidence")
            ),
            repo_suite=_isolation_wire_payload(
                artifact.get("repo_suite_isolation_evidence")
            ),
            verifier_pack=_isolation_wire_payload(
                artifact.get("verifier_pack_isolation_evidence")
            ),
        ),
        verifier_pack=VerifierPackEvidence(
            present=cast(bool | None, artifact.get("verifier_pack_present")),
            sha256=cast(str | None, artifact.get("verifier_pack_sha256")),
            manifest=pack_manifest,
            tests_passed=cast(
                int | None, artifact.get("verifier_pack_tests_passed")
            ),
            tests_total=cast(
                int | None, artifact.get("verifier_pack_tests_total")
            ),
            junit_sha256=cast(
                str | None, artifact.get("verifier_pack_junit_sha256")
            ),
            junit_digest_format=cast(
                str | None,
                artifact.get("verifier_pack_junit_digest_format"),
            ),
            started=cast(
                bool | None,
                artifact.get("verifier_pack_started"),
            ),
            completed=cast(
                bool | None,
                artifact.get("verifier_pack_completed"),
            ),
        ),
        repo_suite=RepositorySuiteEvidence(
            started=cast(bool | None, artifact.get("repo_suite_started")),
            completed=cast(bool | None, artifact.get("repo_suite_completed")),
            state=cast(str | None, artifact.get("repo_suite_state")),
            passed=cast(bool | None, artifact.get("repo_suite_passed")),
            tests_passed=cast(
                int | None, artifact.get("repo_suite_tests_passed")
            ),
            tests_total=cast(
                int | None, artifact.get("repo_suite_tests_total")
            ),
            verdict_source=cast(
                str | None, artifact.get("repo_suite_verdict_source")
            ),
            returncode=cast(
                int | None, artifact.get("repo_suite_returncode")
            ),
            junit_sha256=cast(
                str | None, artifact.get("repo_suite_junit_sha256")
            ),
            junit_digest_format=cast(
                str | None, artifact.get("repo_suite_junit_digest_format")
            ),
            # Preserve schema-1.11 behavior: RepoVerifier currently records
            # ``image_digest`` but the attestation's historical key is
            # ``repo_suite_image_digest`` and therefore remains null here.
            image_digest=cast(
                str | None, artifact.get("repo_suite_image_digest")
            ),
        ),
        runtime=RuntimeIdentityEvidence(
            tree_sha256=cast(
                str | None, artifact.get("runtime_tree_sha256")
            ),
            tree_digest_format=cast(
                str | None, artifact.get("runtime_tree_digest_format")
            ),
            tree_entries=cast(
                int | None, artifact.get("runtime_tree_entries")
            ),
            tree_bytes=cast(int | None, artifact.get("runtime_tree_bytes")),
            elapsed_ms=cast(
                float | None, artifact.get("runtime_identity_elapsed_ms")
            ),
            continuity=cast(
                str | None, artifact.get("runtime_continuity")
            ),
        ),
    )


def _thaw_wire_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            str(key): _thaw_wire_value(item)
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return [_thaw_wire_value(item) for item in value]
    return value


def _wire_payload(
    payload: Mapping[str, object] | None,
) -> dict[str, object] | None:
    if payload is None:
        return None
    return {
        key: _thaw_wire_value(item)
        for key, item in payload.items()
    }


def repo_attestation_evidence_payload(
    evidence: VerificationEvidence,
) -> dict[str, Any]:
    """Project typed evidence onto the existing schema-1.11 attestation keys."""

    execution = evidence.execution
    isolation = evidence.isolation_payloads
    pack = evidence.verifier_pack
    suite = evidence.repo_suite
    runtime = evidence.runtime
    return {
        "junit_sha256": evidence.junit_sha256,
        "junit_digest_format": evidence.junit_digest_format,
        "verifier_pack_sha256": pack.sha256,
        "verifier_pack_manifest": (
            _wire_payload(pack.manifest)
            if pack.manifest is not None
            else None
        ),
        "verifier_pack_tests_passed": pack.tests_passed,
        "verifier_pack_tests_total": pack.tests_total,
        "verifier_pack_junit_sha256": pack.junit_sha256,
        "verifier_pack_junit_digest_format": pack.junit_digest_format,
        "isolation_evidence": _wire_payload(isolation.primary),
        "setup_isolation_evidence": _wire_payload(isolation.setup),
        "repo_suite_isolation_evidence": _wire_payload(isolation.repo_suite),
        "verifier_pack_isolation_evidence": _wire_payload(
            isolation.verifier_pack
        ),
        "repo_suite_junit_sha256": suite.junit_sha256,
        "repo_suite_junit_digest_format": suite.junit_digest_format,
        "repo_suite_tests_passed": suite.tests_passed,
        "repo_suite_tests_total": suite.tests_total,
        "repo_suite_verdict_source": suite.verdict_source,
        "repo_suite_returncode": suite.returncode,
        "repo_suite_passed": suite.passed,
        "repo_suite_started": suite.started,
        "repo_suite_completed": suite.completed,
        "repo_suite_state": suite.state,
        "repo_suite_image_digest": suite.image_digest,
        "execution_state": execution.execution_state,
        "execution_phase": execution.execution_phase,
        "test_command_started": execution.test_command_started,
        "delivered_isolation": execution.delivered_isolation,
        "verifier_pack_present": pack.present,
        "verifier_pack_started": pack.started,
        "verifier_pack_completed": pack.completed,
        "setup_isolation": evidence.setup_isolation,
        "runtime_tree_sha256": runtime.tree_sha256,
        "runtime_tree_digest_format": runtime.tree_digest_format,
        "runtime_tree_entries": runtime.tree_entries,
        "runtime_tree_bytes": runtime.tree_bytes,
        "runtime_identity_elapsed_ms": runtime.elapsed_ms,
        "runtime_continuity": runtime.continuity,
    }


__all__ = [
    "repo_attestation_evidence_payload",
    "repo_verification_evidence_from_artifact",
]
