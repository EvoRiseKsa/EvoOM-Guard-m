"""Deterministic pre-extraction characterization for Guard attestations.

The harness intentionally calls Guard's historical private seam.  The frozen
vector records the complete 57-key payload plus the less-visible ownership
contract: deleted paths and explicit commands are copied, while policy and
nested artifact evidence remain reference-compatible.
"""

from __future__ import annotations

import copy
import json
from typing import Any
from unittest.mock import patch

import evoom_guard.guard as guard

SCHEMA_VERSION = "attestation-builder-characterization-v1"
FIXED_UTC = "2026-07-23T12:34:56Z"
FIXED_GUARD_VERSION = "4.3.0"
NORMALIZED_FIELDS: tuple[str, ...] = ()

ATTESTATION_KEY_ORDER = (
    "created_utc",
    "guard_version",
    "mode",
    "candidate_sha256",
    "deleted_paths",
    "test_command",
    "effective_policy",
    "policy_sha256",
    "junit_sha256",
    "junit_digest_format",
    "verifier_pack_sha256",
    "verifier_pack_manifest",
    "verifier_pack_tests_passed",
    "verifier_pack_tests_total",
    "verifier_pack_junit_sha256",
    "verifier_pack_junit_digest_format",
    "verifier_pack_digest_format",
    "isolation_evidence",
    "setup_isolation_evidence",
    "repo_suite_isolation_evidence",
    "verifier_pack_isolation_evidence",
    "blackbox_pack_isolation_evidence",
    "deleted_paths_applied",
    "repo_suite_junit_sha256",
    "repo_suite_junit_digest_format",
    "repo_suite_tests_passed",
    "repo_suite_tests_total",
    "repo_suite_verdict_source",
    "repo_suite_returncode",
    "repo_suite_passed",
    "repo_suite_started",
    "repo_suite_completed",
    "repo_suite_state",
    "repo_suite_image_digest",
    "base_sha",
    "head_sha",
    "base_tree_sha",
    "head_tree_sha",
    "policy_id",
    "policy_version",
    "execution_state",
    "execution_phase",
    "test_command_started",
    "delivered_isolation",
    "effective_candidate_isolation",
    "candidate_invocations",
    "candidate_launcher_invocation_observed",
    "verifier_pack_present",
    "verifier_pack_started",
    "verifier_pack_completed",
    "setup_isolation",
    "runtime_tree_sha256",
    "runtime_tree_digest_format",
    "runtime_tree_entries",
    "runtime_tree_bytes",
    "runtime_identity_elapsed_ms",
    "runtime_continuity",
)
ATTESTATION_KEY_COUNT = 57


def _full_artifacts(mode: str) -> dict[str, Any]:
    blackbox = mode == "blackbox"
    return {
        "junit_sha256": "1" * 64,
        "junit_digest_format": "JUNIT_XML_SHA256",
        "verifier_pack_sha256": "2" * 64,
        "verifier_pack_manifest": {"id": f"{mode}-pack", "version": "1"},
        "verifier_pack_tests_passed": 3,
        "verifier_pack_tests_total": 4,
        "verifier_pack_junit_sha256": "3" * 64,
        "verifier_pack_junit_digest_format": "JUNIT_XML_SHA256",
        "isolation_evidence": {
            "delivered": "gvisor" if blackbox else "docker",
            "proved": True,
        },
        "setup_isolation_evidence": {"delivered": "docker", "proved": True},
        "repo_suite_isolation_evidence": {
            "delivered": "docker",
            "proved": True,
        },
        "verifier_pack_isolation_evidence": {
            "delivered": "docker",
            "proved": True,
        },
        "blackbox_pack_isolation_evidence": {
            "delivered": "gvisor",
            "proved": blackbox,
        },
        "deleted_paths_applied": ["obsolete.py"],
        "repo_suite_junit_sha256": "4" * 64,
        "repo_suite_junit_digest_format": "JUNIT_XML_SHA256",
        "repo_suite_tests_passed": 8,
        "repo_suite_tests_total": 9,
        "repo_suite_verdict_source": "junit+exit",
        "repo_suite_returncode": 0,
        "repo_suite_passed": True,
        "repo_suite_started": True,
        "repo_suite_completed": True,
        "repo_suite_state": ("composed_completed" if blackbox else "repo_phase_completed"),
        "repo_suite_image_digest": "sha256:" + "5" * 64,
        "base_sha": "6" * 40,
        "head_sha": "7" * 40,
        "base_tree_sha": "8" * 40,
        "head_tree_sha": "9" * 40,
        "policy_id": "strict",
        "policy_version": "2026.07",
        "execution_state": "completed",
        "execution_phase": "complete",
        "test_command_started": True,
        "delivered_isolation": "gvisor" if blackbox else "docker",
        "effective_candidate_isolation": "gvisor" if blackbox else "docker",
        "candidate_invocations": 1 if blackbox else 0,
        "candidate_launcher_invocation_observed": blackbox,
        "verifier_pack_present": True,
        "verifier_pack_started": True,
        "verifier_pack_completed": True,
        "setup_isolation": "docker",
        "runtime_tree_sha256": "a" * 64,
        "runtime_tree_digest_format": "EVOGUARD_RUNTIME_TREE_V1",
        "runtime_tree_entries": 17,
        "runtime_tree_bytes": 4096,
        "runtime_identity_elapsed_ms": 12,
        "runtime_continuity": "same_runtime",
    }


def _case_inputs(case_name: str) -> dict[str, Any]:
    if case_name == "minimal":
        return {
            "candidate": "",
            "safe_deleted": [],
            "test_command": None,
            "effective_policy": {},
            "art": {},
            "mode": "repo",
        }
    if case_name == "full_repo":
        return {
            "candidate": "print('repo')\n",
            "safe_deleted": ["old.py", "legacy/config.json"],
            "test_command": ["python", "-m", "pytest", "-q"],
            "effective_policy": {
                "mode": "repo",
                "isolation": "docker",
                "protected": ["tests/**"],
            },
            "art": _full_artifacts("repo"),
            "mode": "repo",
        }
    if case_name == "full_blackbox":
        return {
            "candidate": "echo black-box\n",
            "safe_deleted": ["retired.sh"],
            "test_command": ["bash", "verify.sh"],
            "effective_policy": {
                "mode": "blackbox",
                "isolation": "gvisor",
                "blackbox": True,
            },
            "art": _full_artifacts("blackbox"),
            "mode": "blackbox",
        }
    if case_name == "falsey":
        falsey_artifacts: dict[str, Any] = {key: None for key in _full_artifacts("repo")}
        falsey_artifacts.update(
            {
                "verifier_pack_sha256": "",
                "verifier_pack_manifest": {},
                "verifier_pack_tests_passed": 0,
                "verifier_pack_tests_total": 0,
                "isolation_evidence": {},
                "deleted_paths_applied": [],
                "repo_suite_returncode": 0,
                "repo_suite_passed": False,
                "repo_suite_started": False,
                "repo_suite_completed": False,
                "test_command_started": False,
                "candidate_invocations": 0,
                "candidate_launcher_invocation_observed": False,
                "verifier_pack_present": False,
                "verifier_pack_started": False,
                "verifier_pack_completed": False,
                "runtime_tree_entries": 0,
                "runtime_tree_bytes": 0,
                "runtime_identity_elapsed_ms": 0,
            }
        )
        return {
            "candidate": "\x00falsey",
            "safe_deleted": [],
            "test_command": [],
            "effective_policy": {},
            "art": falsey_artifacts,
            "mode": "",
        }
    raise ValueError(f"unknown attestation characterization case: {case_name}")


CASE_NAMES = ("falsey", "full_blackbox", "full_repo", "minimal")


def capture_case(case_name: str) -> dict[str, Any]:
    """Capture one payload and its input ownership/call-count contract."""

    inputs = _case_inputs(case_name)
    safe_deleted = inputs["safe_deleted"]
    test_command = inputs["test_command"]
    effective_policy = inputs["effective_policy"]
    artifacts = inputs["art"]
    clock_calls = 0

    def fixed_clock() -> str:
        nonlocal clock_calls
        clock_calls += 1
        return FIXED_UTC

    with (
        patch.object(guard, "_utc_now", fixed_clock),
        patch.object(guard, "__version__", FIXED_GUARD_VERSION),
    ):
        attestation = guard._build_attestation(
            inputs["candidate"],
            safe_deleted=safe_deleted,
            test_command=test_command,
            effective_policy=effective_policy,
            art=artifacts,
            mode=inputs["mode"],
        )

    frozen_attestation = copy.deepcopy(attestation)
    isolation_source = artifacts.get("isolation_evidence")
    manifest_source = artifacts.get("verifier_pack_manifest")
    ownership = {
        "clock_calls": clock_calls,
        "deleted_paths_is_source": attestation["deleted_paths"] is safe_deleted,
        "test_command_is_source": (
            attestation["test_command"] is test_command if test_command is not None else None
        ),
        "effective_policy_is_source": (attestation["effective_policy"] is effective_policy),
        "isolation_evidence_is_source": (
            attestation["isolation_evidence"] is isolation_source
            if isolation_source is not None
            else None
        ),
        "verifier_pack_manifest_is_source": (
            attestation["verifier_pack_manifest"] is manifest_source
            if manifest_source is not None
            else None
        ),
    }

    safe_deleted.append("__source_mutation__")
    if test_command is not None:
        test_command.append("__source_mutation__")
    effective_policy["__source_mutation__"] = True
    if isinstance(isolation_source, dict):
        isolation_source["__source_mutation__"] = True
    if isinstance(manifest_source, dict):
        manifest_source["__source_mutation__"] = True

    ownership.update(
        {
            "deleted_paths_source_mutation_observed": (
                "__source_mutation__" in attestation["deleted_paths"]
            ),
            "test_command_source_mutation_observed": (
                "__source_mutation__" in attestation["test_command"]
                if isinstance(attestation["test_command"], list)
                else False
            ),
            "effective_policy_source_mutation_observed": (
                attestation["effective_policy"].get("__source_mutation__") is True
            ),
            "isolation_evidence_source_mutation_observed": (
                attestation["isolation_evidence"].get("__source_mutation__") is True
                if isinstance(attestation["isolation_evidence"], dict)
                else None
            ),
            "verifier_pack_manifest_source_mutation_observed": (
                attestation["verifier_pack_manifest"].get("__source_mutation__") is True
                if isinstance(attestation["verifier_pack_manifest"], dict)
                else None
            ),
        }
    )

    return {
        "attestation": frozen_attestation,
        "observed_key_count": len(frozen_attestation),
        "observed_key_order": list(frozen_attestation),
        "ownership": ownership,
    }


def capture_all() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "normalization": list(NORMALIZED_FIELDS),
        "contract": {
            "key_count": ATTESTATION_KEY_COUNT,
            "key_order": list(ATTESTATION_KEY_ORDER),
            "clock_calls_per_build": 1,
        },
        "cases": {name: capture_case(name) for name in CASE_NAMES},
    }


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    print(canonical_json(capture_all()), end="")
