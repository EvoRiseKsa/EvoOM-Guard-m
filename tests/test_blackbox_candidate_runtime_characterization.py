"""Frozen R2 boundary for black-box candidate evidence and cleanup."""

from __future__ import annotations

import difflib
import json
from pathlib import Path
from typing import Any

import pytest

from tests.blackbox_candidate_runtime_characterization_harness import (
    CASE_NAMES,
    SCHEMA_VERSION,
    canonical_json,
    capture_case,
)

VECTOR = (
    Path(__file__).parent
    / "fixtures"
    / "refactor-safety"
    / "blackbox-candidate-runtime-v1.json"
)


def _frozen() -> dict[str, Any]:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_blackbox_candidate_runtime_vector_metadata_is_exact() -> None:
    frozen = _frozen()

    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_blackbox_candidate_runtime_matches_pre_extraction_vector(
    case_name: str,
) -> None:
    expected = _frozen()["cases"][case_name]
    actual = capture_case(case_name)
    if actual != expected:
        diff = "".join(
            difflib.unified_diff(
                canonical_json(expected).splitlines(keepends=True),
                canonical_json(actual).splitlines(keepends=True),
                fromfile=f"frozen/{case_name}",
                tofile=f"current/{case_name}",
            )
        )
        pytest.fail(
            "black-box candidate runtime behavior drifted:\n" + diff
        )


def test_retry_observes_live_providers_and_updates_cids_before_sorting() -> None:
    case = capture_case("evidence_live_retry_rebinding")
    operations = [event["op"] for event in case["events"]]

    assert operations == [
        "drain-initial",
        "scan-after-drain",
        "observed-update",
        "observed-updated",
        "observed-iterate",
        "sleep-late",
        "drain-late",
        "scan-late",
        "observed-update",
        "observed-updated",
        "observed-iterate",
    ]
    assert case["returned"]["candidate_invocations"] == 2
    assert case["observed_container_ids"] == [
        "a" * 64,
        "b" * 64,
    ]


def test_interrupted_observation_keeps_immediate_cid_mutation() -> None:
    case = capture_case("evidence_observation_interrupt_identity")

    assert case["exception"]["type"] == "KeyboardInterrupt"
    assert case["exception"]["same_object"] is True
    assert case["observed_container_ids"] == ["a" * 64]


@pytest.mark.parametrize(
    "case_name",
    (
        "evidence_drain_interrupt_identity",
        "evidence_scan_interrupt_identity",
        "evidence_sleep_interrupt_identity",
        "cleanup_kernel_interrupt_identity",
        "cleanup_scan_interrupt_identity",
        "cleanup_control_interrupt_identity",
        "cleanup_sleep_interrupt_identity",
    ),
)
def test_provider_interrupts_preserve_the_exact_exception_object(
    case_name: str,
) -> None:
    case = capture_case(case_name)

    assert case["exception"]["type"] == "KeyboardInterrupt"
    assert case["exception"]["same_object"] is True
    assert case["exception"]["cause_type"] is None


def test_cleanup_strictness_adapts_only_the_established_scan_failure() -> None:
    strict = capture_case("cleanup_strict_scan_failure")
    non_strict = capture_case("cleanup_non_strict_scan_failure")

    assert strict["events"][1]["strict"] is True
    assert strict["exception"] == {
        "cause_type": None,
        "context_type": None,
        "message": (
            "candidate container cleanup could not prove absence: "
            "controlled scan evidence failure"
        ),
        "same_object": False,
        "type": "CandidateContainerCleanupError",
    }
    assert non_strict["events"][1]["strict"] is False
    assert non_strict["exception"] is None
    assert non_strict["returned"] is None
