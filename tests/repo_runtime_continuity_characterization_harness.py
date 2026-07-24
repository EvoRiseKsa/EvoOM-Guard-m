"""Deterministic characterization of repository runtime continuity."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from repo_pack_characterization_harness import capture_case as capture_pack_case

SCHEMA_VERSION = "repo-runtime-continuity-characterization-v1"
CASE_NAMES = (
    "host_complete",
    "pack_drift",
    "read_only_complete",
)

_PACK_CASE = {
    "host_complete": "host_pass_strict",
    "pack_drift": "runtime_drift_after_execution",
    "read_only_complete": "docker_pass",
}

_RUNTIME_KEYS = (
    "candidate_fidelity_changes",
    "outcome",
    "runtime_continuity",
    "runtime_tree_bytes",
    "runtime_tree_digest_format",
    "runtime_tree_entries",
    "runtime_tree_sha256",
    "tamper",
)


def canonical_json(value: Any) -> str:
    """Return stable, human-reviewable JSON."""

    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def capture_case(case_name: str, workspace: Path) -> dict[str, Any]:
    """Capture only the runtime-continuity slice of one frozen pack case."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown repository runtime case: {case_name}")

    observed = capture_pack_case(_PACK_CASE[case_name], workspace)
    artifact = observed["result"]["artifact"]
    runtime_events = [
        event
        for event in observed["events"]
        if event["op"] in {"runtime-capture", "verify-runtime"}
    ]
    return {
        "diagnostics": observed["result"]["diagnostics"],
        "events": runtime_events,
        "runtime_artifact": {
            key: artifact[key]
            for key in _RUNTIME_KEYS
            if key in artifact
        },
    }


def capture_all(workspace: Path) -> dict[str, Any]:
    """Capture every reviewed runtime-continuity case."""

    return {
        "cases": {
            name: capture_case(name, workspace)
            for name in CASE_NAMES
        },
        "schema_version": SCHEMA_VERSION,
    }
