"""Deterministic characterization of repository pack-snapshot continuity."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from repo_pack_characterization_harness import capture_case as capture_pack_case

SCHEMA_VERSION = "repo-pack-continuity-characterization-v1"
CASE_NAMES = (
    "complete",
    "post_execution_drift",
    "pre_execution_drift",
)

_PACK_CASE = {
    "complete": "host_pass_strict",
    "post_execution_drift": "pack_drift_after_execution",
    "pre_execution_drift": "pack_drift_before_execution",
}

_PACK_KEYS = (
    "outcome",
    "runtime_continuity",
    "tamper",
    "verifier_pack_manifest",
    "verifier_pack_sha256",
)


def canonical_json(value: Any) -> str:
    """Return stable, human-reviewable JSON."""

    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def capture_case(case_name: str, workspace: Path) -> dict[str, Any]:
    """Capture only the accepted-pack continuity slice of one pack case."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown repository pack-continuity case: {case_name}")

    observed = capture_pack_case(_PACK_CASE[case_name], workspace)
    artifact = observed["result"]["artifact"]
    continuity_events = [
        event
        for event in observed["events"]
        if event["op"]
        in {
            "host-run",
            "read-pack-report",
            "verify-pack",
        }
    ]
    return {
        "diagnostics": observed["result"]["diagnostics"],
        "events": continuity_events,
        "pack_artifact": {
            key: artifact[key]
            for key in _PACK_KEYS
            if key in artifact
        },
    }


def capture_all(workspace: Path) -> dict[str, Any]:
    """Capture every reviewed pack-continuity case."""

    return {
        "cases": {
            name: capture_case(name, workspace)
            for name in CASE_NAMES
        },
        "schema_version": SCHEMA_VERSION,
    }
