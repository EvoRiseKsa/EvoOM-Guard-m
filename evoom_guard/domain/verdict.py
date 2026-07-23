# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Frozen verdict, execution-lifecycle, and reason semantics.

This dependency-free vocabulary is shared data, not executable producer or
verifier logic. Version-specific policy and wire-record fields remain in their
versioned contract modules.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

EXECUTION_STATIC_GATE = "static_gate"
EXECUTION_NOT_STARTED = "not_started"
EXECUTION_STARTED_INCOMPLETE = "started_incomplete"
EXECUTION_COMPLETED = "completed"

EXECUTION_STATES = frozenset(
    {
        EXECUTION_STATIC_GATE,
        EXECUTION_NOT_STARTED,
        EXECUTION_STARTED_INCOMPLETE,
        EXECUTION_COMPLETED,
    }
)

PASS = "PASS"
REJECTED = "REJECTED"
FAIL = "FAIL"
ERROR = "ERROR"
TAMPERED = "TAMPERED"

VERDICTS = frozenset({PASS, REJECTED, FAIL, ERROR, TAMPERED})

REASON_TESTS_PASSED = "tests_passed"
REASON_PROTECTED_HARNESS_EDIT = "protected_harness_edit"
REASON_TESTS_FAILED = "tests_failed"
REASON_NO_PARSEABLE_EDITS = "no_parseable_edits"
REASON_UNSAFE_PATH = "unsafe_path"
REASON_PATCH_APPLY_FAILED = "patch_apply_failed"
REASON_NO_TEST_VERDICT = "no_test_verdict"
REASON_JUNIT_EXIT_MISMATCH = "junit_exit_mismatch"
REASON_EMPTY_DIFF = "empty_diff"
REASON_BINARY_PATCH = "binary_patch"
REASON_REVERSE_APPLY_FAILED = "reverse_apply_failed"
REASON_NO_VERIFIABLE_CHANGES = "no_verifiable_changes"
REASON_DIFF_COVERAGE_BELOW_THRESHOLD = "diff_coverage_below_threshold"
REASON_TEST_TIMEOUT = "test_timeout"
REASON_SETUP_TIMEOUT = "setup_timeout"
REASON_SETUP_FAILED = "setup_failed"
REASON_ASSURANCE_REQUIREMENT_NOT_MET = "assurance_requirement_not_met"
REASON_FIX_NOT_DEMONSTRATED = "fix_not_demonstrated"
REASON_POLICY_REQUIREMENT_UNSUPPORTED = "policy_requirement_unsupported"
REASON_VERIFIER_PACK_IDENTITY_MISMATCH = "verifier_pack_identity_mismatch"
REASON_VERIFIER_PACK_INVALID = "verifier_pack_invalid"
REASON_VERIFIER_PACK_REQUIRED = "verifier_pack_required"
REASON_VERIFIER_PACK_NOT_FOUND = "verifier_pack_not_found"
REASON_VERIFIER_PACK_SNAPSHOT_CHANGED = "verifier_pack_snapshot_changed"
REASON_CANDIDATE_NOT_EXERCISED = "candidate_not_exercised"
REASON_CANDIDATE_TREE_CHANGED = "candidate_tree_changed_during_run"
REASON_TEST_COMMAND_UNAVAILABLE = "test_command_unavailable"
REASON_RUNTIME_CLEANUP_FAILED = "runtime_cleanup_failed"

REASON_CODES = frozenset(
    {
        REASON_TESTS_PASSED,
        REASON_PROTECTED_HARNESS_EDIT,
        REASON_TESTS_FAILED,
        REASON_NO_PARSEABLE_EDITS,
        REASON_UNSAFE_PATH,
        REASON_PATCH_APPLY_FAILED,
        REASON_NO_TEST_VERDICT,
        REASON_JUNIT_EXIT_MISMATCH,
        REASON_EMPTY_DIFF,
        REASON_BINARY_PATCH,
        REASON_REVERSE_APPLY_FAILED,
        REASON_NO_VERIFIABLE_CHANGES,
        REASON_DIFF_COVERAGE_BELOW_THRESHOLD,
        REASON_TEST_TIMEOUT,
        REASON_SETUP_TIMEOUT,
        REASON_SETUP_FAILED,
        REASON_ASSURANCE_REQUIREMENT_NOT_MET,
        REASON_FIX_NOT_DEMONSTRATED,
        REASON_POLICY_REQUIREMENT_UNSUPPORTED,
        REASON_VERIFIER_PACK_IDENTITY_MISMATCH,
        REASON_VERIFIER_PACK_INVALID,
        REASON_VERIFIER_PACK_REQUIRED,
        REASON_VERIFIER_PACK_NOT_FOUND,
        REASON_VERIFIER_PACK_SNAPSHOT_CHANGED,
        REASON_CANDIDATE_NOT_EXERCISED,
        REASON_CANDIDATE_TREE_CHANGED,
        REASON_TEST_COMMAND_UNAVAILABLE,
        REASON_RUNTIME_CLEANUP_FAILED,
    }
)

# Reason -> (permitted verdicts, permitted execution states). These are frozen
# compatibility values, not executable decision logic.
REASON_CONTRACT: Mapping[
    str, tuple[frozenset[str], frozenset[str]]
] = MappingProxyType(
    {
        REASON_TESTS_PASSED: (
            frozenset({PASS}),
            frozenset({EXECUTION_COMPLETED}),
        ),
        REASON_PROTECTED_HARNESS_EDIT: (
            frozenset({REJECTED}),
            frozenset({EXECUTION_STATIC_GATE}),
        ),
        REASON_TESTS_FAILED: (
            frozenset({FAIL}),
            frozenset({EXECUTION_COMPLETED}),
        ),
        REASON_NO_PARSEABLE_EDITS: (
            frozenset({ERROR}),
            frozenset({EXECUTION_STATIC_GATE}),
        ),
        REASON_UNSAFE_PATH: (
            frozenset({ERROR}),
            frozenset({EXECUTION_STATIC_GATE, EXECUTION_NOT_STARTED}),
        ),
        REASON_PATCH_APPLY_FAILED: (
            frozenset({ERROR}),
            frozenset({EXECUTION_NOT_STARTED}),
        ),
        REASON_NO_TEST_VERDICT: (
            frozenset({ERROR, FAIL}),
            frozenset({EXECUTION_COMPLETED}),
        ),
        REASON_JUNIT_EXIT_MISMATCH: (
            frozenset({TAMPERED}),
            frozenset({EXECUTION_COMPLETED}),
        ),
        REASON_EMPTY_DIFF: (
            frozenset({ERROR}),
            frozenset({EXECUTION_NOT_STARTED}),
        ),
        REASON_BINARY_PATCH: (
            frozenset({ERROR}),
            frozenset({EXECUTION_NOT_STARTED}),
        ),
        REASON_REVERSE_APPLY_FAILED: (
            frozenset({ERROR}),
            frozenset({EXECUTION_NOT_STARTED}),
        ),
        REASON_NO_VERIFIABLE_CHANGES: (
            frozenset({ERROR}),
            frozenset({EXECUTION_NOT_STARTED}),
        ),
        REASON_DIFF_COVERAGE_BELOW_THRESHOLD: (
            frozenset({FAIL}),
            frozenset({EXECUTION_COMPLETED}),
        ),
        REASON_TEST_TIMEOUT: (
            frozenset({FAIL, ERROR}),
            frozenset({EXECUTION_STARTED_INCOMPLETE}),
        ),
        REASON_SETUP_TIMEOUT: (
            frozenset({ERROR}),
            frozenset({EXECUTION_STARTED_INCOMPLETE}),
        ),
        REASON_SETUP_FAILED: (
            frozenset({ERROR}),
            frozenset({EXECUTION_NOT_STARTED, EXECUTION_STARTED_INCOMPLETE}),
        ),
        REASON_ASSURANCE_REQUIREMENT_NOT_MET: (
            frozenset({ERROR}),
            frozenset(
                {
                    EXECUTION_NOT_STARTED,
                    EXECUTION_STARTED_INCOMPLETE,
                    EXECUTION_COMPLETED,
                }
            ),
        ),
        REASON_FIX_NOT_DEMONSTRATED: (
            frozenset({FAIL}),
            frozenset({EXECUTION_COMPLETED}),
        ),
        REASON_POLICY_REQUIREMENT_UNSUPPORTED: (
            frozenset({ERROR}),
            frozenset({EXECUTION_NOT_STARTED}),
        ),
        REASON_VERIFIER_PACK_IDENTITY_MISMATCH: (
            frozenset({ERROR}),
            frozenset({EXECUTION_NOT_STARTED}),
        ),
        REASON_VERIFIER_PACK_INVALID: (
            frozenset({ERROR}),
            frozenset({EXECUTION_NOT_STARTED}),
        ),
        REASON_VERIFIER_PACK_REQUIRED: (
            frozenset({ERROR}),
            frozenset({EXECUTION_NOT_STARTED}),
        ),
        REASON_VERIFIER_PACK_NOT_FOUND: (
            frozenset({ERROR}),
            frozenset({EXECUTION_NOT_STARTED}),
        ),
        REASON_VERIFIER_PACK_SNAPSHOT_CHANGED: (
            frozenset({TAMPERED}),
            frozenset(
                {
                    EXECUTION_NOT_STARTED,
                    EXECUTION_STARTED_INCOMPLETE,
                    EXECUTION_COMPLETED,
                }
            ),
        ),
        REASON_CANDIDATE_NOT_EXERCISED: (
            frozenset({ERROR}),
            frozenset({EXECUTION_COMPLETED}),
        ),
        REASON_CANDIDATE_TREE_CHANGED: (
            frozenset({TAMPERED}),
            frozenset({EXECUTION_STARTED_INCOMPLETE, EXECUTION_COMPLETED}),
        ),
        REASON_TEST_COMMAND_UNAVAILABLE: (
            frozenset({ERROR}),
            frozenset({EXECUTION_NOT_STARTED, EXECUTION_STARTED_INCOMPLETE}),
        ),
        REASON_RUNTIME_CLEANUP_FAILED: (
            frozenset({ERROR}),
            frozenset({EXECUTION_STARTED_INCOMPLETE}),
        ),
    }
)

__all__ = [
    "ERROR",
    "EXECUTION_COMPLETED",
    "EXECUTION_NOT_STARTED",
    "EXECUTION_STARTED_INCOMPLETE",
    "EXECUTION_STATES",
    "EXECUTION_STATIC_GATE",
    "FAIL",
    "PASS",
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
    "TAMPERED",
    "VERDICTS",
]
