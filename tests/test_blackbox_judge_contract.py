"""Frozen contract for moving black-box judge process mechanics safely."""

from __future__ import annotations

import difflib
import json
from pathlib import Path

import pytest
from blackbox_judge_contract_harness import (
    SCHEMA_VERSION,
    canonical_json,
    capture_contract,
)

VECTOR = (
    Path(__file__).parent
    / "fixtures"
    / "refactor-safety"
    / "blackbox-judge-process-contract-v1.json"
)


def _frozen() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_blackbox_judge_process_contract_is_exact() -> None:
    expected = _frozen()
    actual = capture_contract()
    if actual == expected:
        return
    diff = "".join(
        difflib.unified_diff(
            canonical_json(expected).splitlines(keepends=True),
            canonical_json(actual).splitlines(keepends=True),
            fromfile="frozen/blackbox-judge-process-contract-v1.json",
            tofile="current/blackbox-judge-process-contract-v1.json",
        )
    )
    pytest.fail(f"black-box judge process contract drifted:\n{diff}")


def test_snapshot_exposes_the_security_critical_transfer_seams() -> None:
    snapshot = _frozen()
    assert snapshot["schema_version"] == SCHEMA_VERSION
    assert all(snapshot["static"]["patch_seam_presence"].values())
    assert snapshot["completed_run"]["popen"] == {
        "command": ["judge-python", "-m", "pytest"],
        "command_identity": True,
        "cwd": "/judge",
        "env": {"SAFE": "1"},
        "env_identity": True,
        "keyword_names": [
            "cwd",
            "env",
            "start_new_session",
            "stderr",
            "stdin",
            "stdout",
        ],
        "start_new_session": True,
        "stderr_is_pipe": True,
        "stdin_is_devnull": True,
        "stdout_is_pipe": True,
    }
    assert snapshot["completed_run"]["completed_process"]["args_identity"] is True
    assert snapshot["completed_run"]["reader_factory"]["targets_use_drain_patch"] == [
        True,
        True,
    ]
    assert snapshot["completed_run"]["runtime_seams"] == {
        "join_calls": [
            {
                "reader_count": 2,
                "readers_match_created": True,
                "stream_labels": ["stdout", "stderr"],
            },
            {
                "reader_count": 2,
                "readers_match_created": True,
                "stream_labels": ["stdout", "stderr"],
            },
        ],
        "monotonic_calls": [100.0, 100.0],
        "output_limits": [321],
        "poll_calls": 2,
        "sleep_calls": [0.125],
        "terminate_process_identity": [True],
    }
    assert snapshot["termination"]["signals"] == [
        [4321, snapshot["termination"]["sigterm"]],
        [4321, 99],
    ]
    assert snapshot["termination"]["event_trace"] == [
        "probe",
        "signal-term",
        "wait",
        "signal-kill",
        "wait",
        "reap",
    ]
    assert snapshot["join"]["live"]["result"] is False
    assert snapshot["join"]["live"]["close_calls"] == 0
    assert snapshot["join"]["join_error"] == {
        "close_calls": 0,
        "exception_type": "RuntimeError",
        "message": "join sentinel",
    }
