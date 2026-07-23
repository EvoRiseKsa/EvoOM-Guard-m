"""Deterministic pre-extraction characterization for assurance composition.

The harness deliberately exercises Guard's historical private seam.  After the
extraction those names remain compatibility aliases, so the frozen vector
proves that domain modeling did not change the schema-1.11 payload or floor
diagnostics.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from evoom_guard.domain.verdict import (
    EXECUTION_NOT_STARTED,
    EXECUTION_STARTED_INCOMPLETE,
)
from evoom_guard.guard import (
    _assurance_profile,
    _assurance_shortfall,
    _pack_assurance,
    _preflight_assurance_profile,
    _static_assurance_profile,
)

SCHEMA_VERSION = "assurance-characterization-v1"
NORMALIZED_FIELDS: tuple[str, ...] = ()


def _static_cases() -> dict[str, Any]:
    return {
        "without_pack": _static_assurance_profile(None),
        "with_pack": _static_assurance_profile("private-pack"),
    }


def _pack_cases() -> dict[str, Any]:
    cases: dict[str, tuple[str | None, dict[str, Any]]] = {
        "not_configured": (None, {}),
        "configured_without_evidence": ("private-pack", {}),
        "missing": ("private-pack", {"evidence": {"present": False}}),
        "invalid": (
            "private-pack",
            {"evidence": {"present": True, "outcome": "pack_invalid"}},
        ),
        "identity_mismatch": (
            "private-pack",
            {
                "evidence": {
                    "present": True,
                    "snapshot_sha256": "sha256:pack",
                    "outcome": "pack_identity_mismatch",
                }
            },
        ),
        "snapshot_changed": (
            "private-pack",
            {
                "evidence": {
                    "present": True,
                    "snapshot_sha256": "sha256:pack",
                    "outcome": "pack_snapshot_changed",
                }
            },
        ),
        "snapshot_accepted_not_started": (
            "private-pack",
            {
                "evidence": {
                    "present": True,
                    "snapshot_sha256": "sha256:pack",
                }
            },
        ),
        "started_incomplete": (
            "private-pack",
            {
                "evidence": {
                    "present": True,
                    "snapshot_accepted": True,
                    "started": True,
                }
            },
        ),
        "completed_repo_docker": (
            "private-pack",
            {
                "isolation": "docker",
                "evidence": {
                    "present": True,
                    "snapshot_sha256": "sha256:pack",
                    "started": True,
                    "completed": True,
                },
            },
        ),
        "completed_blackbox_gvisor": (
            "private-pack",
            {
                "isolation": "gvisor",
                "blackbox": True,
                "evidence": {
                    "present": True,
                    "snapshot_sha256": "sha256:pack",
                    "started": True,
                    "completed": True,
                },
            },
        ),
        "blackbox_without_candidate_invocation": (
            "private-pack",
            {
                "isolation": "docker",
                "blackbox": True,
                "evidence": {
                    "present": True,
                    "snapshot_sha256": "sha256:pack",
                    "started": True,
                    "candidate_launcher_invocation_observed": False,
                },
            },
        ),
        "blackbox_same_host": (
            "private-pack",
            {
                "isolation": "subprocess",
                "blackbox": True,
                "evidence": {
                    "present": True,
                    "snapshot_sha256": "sha256:pack",
                    "started": True,
                },
            },
        ),
    }
    return {
        name: _pack_assurance(verifier_pack, **arguments)
        for name, (verifier_pack, arguments) in cases.items()
    }


def _preflight_cases() -> dict[str, Any]:
    return {
        "default": _preflight_assurance_profile(None),
        "incomplete_setup": _preflight_assurance_profile(
            "private-pack",
            execution_state=EXECUTION_STARTED_INCOMPLETE,
            execution_phase="setup",
            setup_isolation="subprocess_host_opt_in",
            runtime_continuity="same_runtime",
            pack_evidence={
                "present": True,
                "snapshot_sha256": "sha256:pack",
            },
        ),
    }


def _profile_cases() -> dict[str, Any]:
    cases: dict[str, tuple[str, str | None, dict[str, Any]]] = {
        "repo_subprocess": ("subprocess", None, {}),
        "repo_docker": ("docker", "private-pack", {}),
        "repo_host_setup": (
            "docker",
            None,
            {
                "setup_isolation": "subprocess_host_opt_in",
                "runtime_continuity": "same_runtime",
            },
        ),
        "not_started": (
            "docker",
            "private-pack",
            {
                "execution_state": EXECUTION_NOT_STARTED,
                "execution_phase": "candidate_prepare",
            },
        ),
        "test_command_not_started": (
            "docker",
            "private-pack",
            {
                "execution_state": EXECUTION_STARTED_INCOMPLETE,
                "execution_phase": "setup",
                "test_command_started": False,
            },
        ),
        "blackbox_subprocess": (
            "subprocess",
            "private-pack",
            {"blackbox": True},
        ),
        "blackbox_docker_observed": (
            "docker",
            "private-pack",
            {
                "blackbox": True,
                "candidate_isolation": "docker",
            },
        ),
        "blackbox_composed": (
            "docker",
            "private-pack",
            {
                "blackbox": True,
                "composed_repo_suite": True,
                "repo_suite_required": True,
                "repo_suite_state": "composed_completed",
                "candidate_isolation": "docker",
            },
        ),
        "blackbox_required_short_circuit": (
            "gvisor",
            "private-pack",
            {
                "blackbox": True,
                "repo_suite_required": True,
                "repo_suite_state": "required_not_run_pack_failure",
                "candidate_isolation": "gvisor",
            },
        ),
        "blackbox_incomplete": (
            "docker",
            "private-pack",
            {
                "blackbox": True,
                "candidate_isolation": "docker",
                "execution_state": EXECUTION_STARTED_INCOMPLETE,
                "execution_phase": "blackbox_judge",
                "pack_evidence": {
                    "present": True,
                    "snapshot_sha256": "sha256:pack",
                    "started": True,
                },
            },
        ),
    }
    return {
        name: _assurance_profile(isolation, verifier_pack, **arguments)
        for name, (isolation, verifier_pack, arguments) in cases.items()
    }


def _shortfall_cases() -> dict[str, Any]:
    repo_profile = _assurance_profile("subprocess", None)
    blackbox_profile = _assurance_profile(
        "docker",
        "private-pack",
        blackbox=True,
        candidate_isolation="docker",
    )
    cases: dict[str, tuple[dict[str, Any], dict[str, str | None]]] = {
        "none_required": (
            repo_profile,
            {
                "require_report_integrity": None,
                "require_candidate_isolation": None,
            },
        ),
        "unknown_report": (
            repo_profile,
            {
                "require_report_integrity": "unknown",
                "require_candidate_isolation": None,
            },
        ),
        "report_below_floor": (
            repo_profile,
            {
                "require_report_integrity": "external_process_isolated",
                "require_candidate_isolation": None,
            },
        ),
        "unknown_isolation": (
            repo_profile,
            {
                "require_report_integrity": None,
                "require_candidate_isolation": "unknown",
            },
        ),
        "isolation_below_floor": (
            repo_profile,
            {
                "require_report_integrity": None,
                "require_candidate_isolation": "docker",
            },
        ),
        "blackbox_meets_floors": (
            blackbox_profile,
            {
                "require_report_integrity": "external_process_isolated",
                "require_candidate_isolation": "docker",
            },
        ),
    }
    return {
        name: _assurance_shortfall(profile, **arguments)
        for name, (profile, arguments) in cases.items()
    }


CASE_BUILDERS: dict[str, Callable[[], dict[str, Any]]] = {
    "pack": _pack_cases,
    "preflight": _preflight_cases,
    "profile": _profile_cases,
    "shortfall": _shortfall_cases,
    "static": _static_cases,
}
CASE_NAMES = tuple(CASE_BUILDERS)


def capture_case(case_name: str) -> dict[str, Any]:
    if case_name not in CASE_BUILDERS:
        raise ValueError(f"unknown assurance characterization case: {case_name}")
    return CASE_BUILDERS[case_name]()


def capture_all() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "normalization": list(NORMALIZED_FIELDS),
        "cases": {name: capture_case(name) for name in CASE_NAMES},
    }


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    print(canonical_json(capture_all()), end="")
