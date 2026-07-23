# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Pure assembly of the established Guard attestation payload."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any


def build_attestation(
    candidate: str,
    *,
    safe_deleted: Sequence[str],
    test_command: Sequence[str] | None,
    effective_policy: Mapping[str, Any],
    artifacts: Mapping[str, Any],
    mode: str,
    now: Callable[[], str],
    guard_version: Callable[[], str],
    candidate_digest: Callable[[str], str],
    policy_digest: Callable[[Mapping[str, Any]], str],
    pack_digest_format: Callable[[], str],
) -> dict[str, Any]:
    """Build the exact established 57-key attestation.

    Providers are evaluated in their historical dictionary-literal positions.
    Artifact values and the policy remain reference-compatible; only deleted
    paths and an explicit test command are copied, exactly as before.
    """

    return {
        "created_utc": now(),
        "guard_version": guard_version(),
        "mode": mode,
        "candidate_sha256": candidate_digest(candidate),
        "deleted_paths": list(safe_deleted),
        "test_command": (list(test_command) if test_command else "default:python -m pytest"),
        "effective_policy": effective_policy,
        "policy_sha256": policy_digest(effective_policy),
        "junit_sha256": artifacts.get("junit_sha256"),
        "junit_digest_format": artifacts.get("junit_digest_format"),
        "verifier_pack_sha256": artifacts.get("verifier_pack_sha256"),
        "verifier_pack_manifest": artifacts.get("verifier_pack_manifest"),
        "verifier_pack_tests_passed": artifacts.get("verifier_pack_tests_passed"),
        "verifier_pack_tests_total": artifacts.get("verifier_pack_tests_total"),
        "verifier_pack_junit_sha256": artifacts.get("verifier_pack_junit_sha256"),
        "verifier_pack_junit_digest_format": artifacts.get("verifier_pack_junit_digest_format"),
        "verifier_pack_digest_format": (
            pack_digest_format() if artifacts.get("verifier_pack_sha256") else None
        ),
        "isolation_evidence": artifacts.get("isolation_evidence"),
        "setup_isolation_evidence": artifacts.get("setup_isolation_evidence"),
        "repo_suite_isolation_evidence": artifacts.get("repo_suite_isolation_evidence"),
        "verifier_pack_isolation_evidence": artifacts.get("verifier_pack_isolation_evidence"),
        "blackbox_pack_isolation_evidence": artifacts.get("blackbox_pack_isolation_evidence"),
        "deleted_paths_applied": artifacts.get("deleted_paths_applied"),
        "repo_suite_junit_sha256": artifacts.get("repo_suite_junit_sha256"),
        "repo_suite_junit_digest_format": artifacts.get("repo_suite_junit_digest_format"),
        "repo_suite_tests_passed": artifacts.get("repo_suite_tests_passed"),
        "repo_suite_tests_total": artifacts.get("repo_suite_tests_total"),
        "repo_suite_verdict_source": artifacts.get("repo_suite_verdict_source"),
        "repo_suite_returncode": artifacts.get("repo_suite_returncode"),
        "repo_suite_passed": artifacts.get("repo_suite_passed"),
        "repo_suite_started": artifacts.get("repo_suite_started"),
        "repo_suite_completed": artifacts.get("repo_suite_completed"),
        "repo_suite_state": artifacts.get("repo_suite_state"),
        "repo_suite_image_digest": artifacts.get("repo_suite_image_digest"),
        "base_sha": artifacts.get("base_sha"),
        "head_sha": artifacts.get("head_sha"),
        "base_tree_sha": artifacts.get("base_tree_sha"),
        "head_tree_sha": artifacts.get("head_tree_sha"),
        "policy_id": artifacts.get("policy_id"),
        "policy_version": artifacts.get("policy_version"),
        "execution_state": artifacts.get("execution_state"),
        "execution_phase": artifacts.get("execution_phase"),
        "test_command_started": artifacts.get("test_command_started"),
        "delivered_isolation": artifacts.get("delivered_isolation"),
        "effective_candidate_isolation": artifacts.get("effective_candidate_isolation"),
        "candidate_invocations": artifacts.get("candidate_invocations"),
        "candidate_launcher_invocation_observed": artifacts.get(
            "candidate_launcher_invocation_observed"
        ),
        "verifier_pack_present": artifacts.get("verifier_pack_present"),
        "verifier_pack_started": artifacts.get("verifier_pack_started"),
        "verifier_pack_completed": artifacts.get("verifier_pack_completed"),
        "setup_isolation": artifacts.get("setup_isolation"),
        "runtime_tree_sha256": artifacts.get("runtime_tree_sha256"),
        "runtime_tree_digest_format": artifacts.get("runtime_tree_digest_format"),
        "runtime_tree_entries": artifacts.get("runtime_tree_entries"),
        "runtime_tree_bytes": artifacts.get("runtime_tree_bytes"),
        "runtime_identity_elapsed_ms": artifacts.get("runtime_identity_elapsed_ms"),
        "runtime_continuity": artifacts.get("runtime_continuity"),
    }


__all__ = ["build_attestation"]
