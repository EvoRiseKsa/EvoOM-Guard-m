"""Frozen public characterization for repo-native Guard finalization."""

from __future__ import annotations

import difflib
import json
from pathlib import Path
from typing import Any, cast

import pytest
from repo_finalization_characterization_harness import (
    CASE_NAMES,
    NORMALIZED_FIELDS,
    SCHEMA_VERSION,
    canonical_json,
    capture_case,
)

VECTOR = (
    Path(__file__).parent
    / "fixtures"
    / "refactor-safety"
    / "repo-finalization-v1.json"
)


def _frozen() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(VECTOR.read_text(encoding="utf-8")))


def test_repo_finalization_characterization_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert frozen["normalization"] == list(NORMALIZED_FIELDS)
    assert tuple(frozen["cases"]) == CASE_NAMES


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_repo_finalization_matches_frozen_public_behavior(
    case_name: str,
    tmp_path: Path,
) -> None:
    expected = _frozen()["cases"][case_name]
    actual = capture_case(case_name, tmp_path)
    if actual != expected:
        diff = "".join(
            difflib.unified_diff(
                canonical_json(expected).splitlines(keepends=True),
                canonical_json(actual).splitlines(keepends=True),
                fromfile=f"frozen/{case_name}",
                tofile=f"current/{case_name}",
            )
        )
        pytest.fail("repo-native finalization contract drifted:\n" + diff)


def test_effect_and_exception_order_is_frozen(tmp_path: Path) -> None:
    complete = capture_case("repo_completed_pass_full_pipeline", tmp_path)
    coverage_error = capture_case("coverage_exception_stops_baseline", tmp_path)
    baseline_error = capture_case("baseline_exception_stops_attestation", tmp_path)
    attestation_error = capture_case("attestation_exception_stops_profile", tmp_path)
    profile_error = capture_case("profile_exception_follows_attestation", tmp_path)
    shortfall_error = capture_case("shortfall_exception_follows_profile", tmp_path)

    assert complete["timeline"] == [
        "verifier:init",
        "verifier:verify",
        "coverage:collect",
        "baseline:early",
        "attestation:build",
        "profile:runtime",
        "shortfall:call",
    ]
    assert coverage_error["timeline"][-1] == "coverage:collect"
    assert baseline_error["timeline"][-1] == "baseline:early"
    assert attestation_error["timeline"][-1] == "attestation:build"
    assert profile_error["timeline"][-2:] == [
        "attestation:build",
        "profile:runtime",
    ]
    assert shortfall_error["timeline"][-3:] == [
        "attestation:build",
        "profile:runtime",
        "shortfall:call",
    ]


def test_coverage_demotion_does_not_skip_baseline(tmp_path: Path) -> None:
    case = capture_case("coverage_demotion_keeps_baseline_effect", tmp_path)

    assert case["decision"]["reason_code"] == "diff_coverage_below_threshold"
    assert case["timeline"][-3:] == [
        "baseline:early",
        "attestation:build",
        "profile:runtime",
    ]
    assert "shortfall:call" not in case["timeline"]
    assert case["baseline_snapshot"]["repair_effect"] == "demonstrated"


def test_repo_finalization_preserves_live_provider_lookup(tmp_path: Path) -> None:
    case = capture_case("live_provider_rebinding", tmp_path)

    assert case["timeline"][-4:] == [
        "baseline:late",
        "attestation:late",
        "profile:late",
        "shortfall:late",
    ]
    assert case["result_identities"] == {
        "coverage": True,
        "baseline": True,
        "attestation": True,
        "assurance": True,
    }


def test_trusted_context_overrides_raw_artifact_values(tmp_path: Path) -> None:
    case = capture_case("repo_completed_pass_full_pipeline", tmp_path)
    attestation_call = next(
        call for call in case["provider_calls"] if call["provider"] == "attestation"
    )

    assert attestation_call["trusted_bindings"] == {
        "base_sha": "trusted-base",
        "head_sha": "trusted-head",
        "policy_id": "trusted-policy",
        "execution_state": "completed",
        "repo_suite_passed": True,
        "raw_marker": "preserved",
    }


def test_static_and_incomplete_paths_skip_optional_effects(tmp_path: Path) -> None:
    static = capture_case("static_rejection_uses_static_profile", tmp_path)
    incomplete = capture_case("incomplete_error_skips_optional_effects", tmp_path)

    assert static["timeline"] == ["attestation:build", "profile:static"]
    assert static["decision"]["execution_state"] == "static_gate"
    assert incomplete["timeline"] == [
        "verifier:init",
        "verifier:verify",
        "attestation:build",
        "profile:runtime",
    ]
    assert incomplete["decision"]["reason_code"] == "setup_failed"


def test_pack_presence_probe_precedes_attestation(tmp_path: Path) -> None:
    case = capture_case("pack_presence_inference_precedes_attestation", tmp_path)

    assert case["pack_isdir_calls"] == [True]
    assert case["timeline"][-3:] == [
        "pack:isdir",
        "attestation:build",
        "profile:runtime",
    ]
