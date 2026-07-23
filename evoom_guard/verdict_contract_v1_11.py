# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Frozen data vocabulary for the EvoGuard verdict-record 1.11 contract.

This compatibility facade has no third-party dependencies and contains no
producer or verifier logic.  It is imported through the installed
``evoom_guard`` package and re-exports the dependency-free domain vocabulary
without changing the frozen schema-1.11 objects.
"""

from __future__ import annotations

from collections.abc import Mapping as Mapping
from types import MappingProxyType as MappingProxyType

from evoom_guard.domain.verdict import (
    ERROR,
    EXECUTION_COMPLETED,
    EXECUTION_NOT_STARTED,
    EXECUTION_STARTED_INCOMPLETE,
    EXECUTION_STATES,
    EXECUTION_STATIC_GATE,
    FAIL,
    PASS,
    REASON_ASSURANCE_REQUIREMENT_NOT_MET,
    REASON_BINARY_PATCH,
    REASON_CANDIDATE_NOT_EXERCISED,
    REASON_CANDIDATE_TREE_CHANGED,
    REASON_CODES,
    REASON_DIFF_COVERAGE_BELOW_THRESHOLD,
    REASON_EMPTY_DIFF,
    REASON_FIX_NOT_DEMONSTRATED,
    REASON_JUNIT_EXIT_MISMATCH,
    REASON_NO_PARSEABLE_EDITS,
    REASON_NO_TEST_VERDICT,
    REASON_NO_VERIFIABLE_CHANGES,
    REASON_PATCH_APPLY_FAILED,
    REASON_POLICY_REQUIREMENT_UNSUPPORTED,
    REASON_PROTECTED_HARNESS_EDIT,
    REASON_REVERSE_APPLY_FAILED,
    REASON_RUNTIME_CLEANUP_FAILED,
    REASON_SETUP_FAILED,
    REASON_SETUP_TIMEOUT,
    REASON_TEST_COMMAND_UNAVAILABLE,
    REASON_TEST_TIMEOUT,
    REASON_TESTS_FAILED,
    REASON_TESTS_PASSED,
    REASON_UNSAFE_PATH,
    REASON_VERIFIER_PACK_IDENTITY_MISMATCH,
    REASON_VERIFIER_PACK_INVALID,
    REASON_VERIFIER_PACK_NOT_FOUND,
    REASON_VERIFIER_PACK_REQUIRED,
    REASON_VERIFIER_PACK_SNAPSHOT_CHANGED,
    REJECTED,
    TAMPERED,
    VERDICTS,
)
from evoom_guard.domain.verdict import (
    REASON_CONTRACT as _REASON_CONTRACT,
)

__all__ = (
    "ALLOWED_POLICY_KEYS",
    "ERROR",
    "EXECUTION_COMPLETED",
    "EXECUTION_NOT_STARTED",
    "EXECUTION_STARTED_INCOMPLETE",
    "EXECUTION_STATES",
    "EXECUTION_STATIC_GATE",
    "FAIL",
    "Mapping",
    "MappingProxyType",
    "OPTIONAL_POLICY_KEYS",
    "PASS",
    "POLICY_KEYS",
    "REASON_ASSURANCE_REQUIREMENT_NOT_MET",
    "REASON_BINARY_PATCH",
    "REASON_CANDIDATE_NOT_EXERCISED",
    "REASON_CANDIDATE_TREE_CHANGED",
    "REASON_CODES",
    "REASON_CONTRACT",
    "REASON_DIFF_COVERAGE_BELOW_THRESHOLD",
    "REASON_EMPTY_DIFF",
    "REASON_FIX_NOT_DEMONSTRATED",
    "REASON_JUNIT_EXIT_MISMATCH",
    "REASON_NO_PARSEABLE_EDITS",
    "REASON_NO_TEST_VERDICT",
    "REASON_NO_VERIFIABLE_CHANGES",
    "REASON_PATCH_APPLY_FAILED",
    "REASON_POLICY_REQUIREMENT_UNSUPPORTED",
    "REASON_PROTECTED_HARNESS_EDIT",
    "REASON_REVERSE_APPLY_FAILED",
    "REASON_RUNTIME_CLEANUP_FAILED",
    "REASON_SETUP_FAILED",
    "REASON_SETUP_TIMEOUT",
    "REASON_TEST_COMMAND_UNAVAILABLE",
    "REASON_TEST_TIMEOUT",
    "REASON_TESTS_FAILED",
    "REASON_TESTS_PASSED",
    "REASON_UNSAFE_PATH",
    "REASON_VERIFIER_PACK_IDENTITY_MISMATCH",
    "REASON_VERIFIER_PACK_INVALID",
    "REASON_VERIFIER_PACK_NOT_FOUND",
    "REASON_VERIFIER_PACK_REQUIRED",
    "REASON_VERIFIER_PACK_SNAPSHOT_CHANGED",
    "REJECTED",
    "REQUIRED_ASSURANCE",
    "REQUIRED_ATTESTATION",
    "REQUIRED_TOP_LEVEL",
    "SCHEMA_VERSION",
    "TAMPERED",
    "VERDICTS",
    "annotations",
)

REASON_CONTRACT: Mapping[
    str, tuple[frozenset[str], frozenset[str]]
] = _REASON_CONTRACT

SCHEMA_VERSION = "1.11"

POLICY_KEYS = frozenset(
    {
        "mode",
        "isolation",
        "docker_image",
        "docker_network",
        "test_command",
        "setup_command",
        "trust_setup_on_host",
        "setup_output_globs",
        "protected",
        "allow",
        "allow_new_tests",
        "timeout",
        "mem_limit_mb",
        "verifier_pack_required",
        "expect_verifier_pack_sha256",
        "blackbox",
        "blackbox_only",
        "require_report_integrity",
        "require_candidate_isolation",
        "min_diff_coverage",
        "baseline_evidence",
        "require_demonstrated_fix",
        "policy_id",
        "policy_version",
    }
)

# Additive policy fields accepted by schema 1.11.  They are deliberately not
# folded into ``POLICY_KEYS``: published 1.11 evidence records were signed over
# the 24-key object above, so making this field required would invalidate their
# historical digest and reject valid records.  An absent value means ``false``;
# new producers state it explicitly and bind it into their policy SHA.
OPTIONAL_POLICY_KEYS = frozenset({"strict_harness"})
ALLOWED_POLICY_KEYS = POLICY_KEYS | OPTIONAL_POLICY_KEYS

REQUIRED_TOP_LEVEL = frozenset(
    {
        "schema_version",
        "tool",
        "tool_version",
        "verdict",
        "passed",
        "exit_code",
        "reason_code",
        "reason",
        "files_changed",
        "protected_violations",
        "risk_level",
        "risk_score",
        "tests_passed",
        "tests_total",
        "test_command_ran",
        "execution_state",
        "execution_phase",
        "verdict_source",
        "isolation",
        "source",
        "base_reconstruction",
        "assurance",
        "diff_coverage",
        "baseline",
        "attestation",
        "diagnostics",
    }
)

REQUIRED_ASSURANCE = frozenset(
    {
        "execution_state",
        "execution_phase",
        "harness_integrity",
        "report_integrity",
        "candidate_isolation",
        "suite_isolation",
        "setup_isolation",
        "runtime_continuity",
        "verifier_pack",
        "overall_profile",
    }
)

REQUIRED_ATTESTATION = frozenset(
    {
        "created_utc",
        "guard_version",
        "mode",
        "candidate_sha256",
        "effective_policy",
        "policy_sha256",
        "execution_state",
        "execution_phase",
        "test_command_started",
        "delivered_isolation",
        "effective_candidate_isolation",
        "candidate_invocations",
        "candidate_launcher_invocation_observed",
        "verifier_pack_sha256",
        "verifier_pack_digest_format",
        "verifier_pack_tests_passed",
        "verifier_pack_tests_total",
        "verifier_pack_present",
        "verifier_pack_started",
        "verifier_pack_completed",
    }
)
