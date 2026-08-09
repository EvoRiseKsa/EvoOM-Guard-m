# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Focused contracts for the pure nested record-validation owner."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from record_nested_characterization_harness import capture, cases

from evoom_guard.verifiers.record_nested import project_nested_validation


def _check(case_name: str, check_id: str) -> dict[str, str]:
    return next(item for item in capture(cases()[case_name]) if item["id"] == check_id)


def test_nested_projection_is_frozen_and_does_not_mutate_inputs() -> None:
    case = cases()["valid"]
    projection = project_nested_validation(case.assurance, case.attestation)

    assert projection.assurance is not None
    assert projection.attestation is not None
    assert projection.assurance.missing_fields == ()
    assert projection.attestation.shape_errors == ()
    with pytest.raises(FrozenInstanceError):
        projection.assurance = None  # type: ignore[misc]


def test_required_nested_fields_cannot_be_bypassed() -> None:
    assert _check(
        "assurance_missing_execution_state", "assurance.required_fields"
    ) == {
        "id": "assurance.required_fields",
        "status": "fail",
        "message": "missing assurance fields: execution_state",
    }
    assert _check(
        "attestation_missing_candidate_sha256", "attestation.required_fields"
    ) == {
        "id": "attestation.required_fields",
        "status": "fail",
        "message": "missing attestation fields: candidate_sha256",
    }


def test_preflight_null_isolation_requires_the_complete_truth_table() -> None:
    assert _check(
        "preflight_null_effective_valid", "attestation.shape"
    )["status"] == "pass"
    for name in (
        "preflight_null_wrong_state",
        "preflight_null_command_started",
        "preflight_null_wrong_delivery",
    ):
        assert _check(name, "attestation.types")["status"] == "fail"
        assert "effective_candidate_isolation is invalid" in _check(
            name, "attestation.shape"
        )["message"]


def test_sha256_shape_requires_exact_lowercase_hex() -> None:
    message = _check("attestation_invalid_shapes", "attestation.shape")["message"]

    assert "candidate_sha256 must be a lowercase SHA-256" in message
    assert "policy_sha256 must be a lowercase SHA-256" in message


@pytest.mark.parametrize(
    ("name", "message"),
    [
        (
            "top_junit_digest_without_format",
            "junit digest and format must form a recognized SHA-256 pair",
        ),
        (
            "pack_junit_format_without_digest",
            "verifier-pack JUnit digest and format must form a recognized SHA-256 pair",
        ),
        (
            "repo_junit_digest_without_format",
            "repo-suite JUnit digest and format must form a recognized SHA-256 pair",
        ),
    ],
)
def test_junit_digest_and_format_remain_coupled(name: str, message: str) -> None:
    assert message in _check(name, "attestation.shape")["message"]


def test_nested_pack_shape_cannot_be_bypassed() -> None:
    message = _check("assurance_invalid_pack_shape", "assurance.shape")["message"]

    assert "configured must be true" in message
    assert "snapshot_sha256 must be a lowercase SHA-256 or null" in message


def test_candidate_invocations_cannot_be_negative() -> None:
    assert "candidate_invocations must be non-negative" in _check(
        "attestation_invalid_shapes", "attestation.shape"
    )["message"]


def test_null_skip_order_and_early_return_are_exact() -> None:
    trace = capture(cases()["both_null"])

    assert [item["id"] for item in trace] == [
        "assurance.required_fields",
        "assurance.types",
        "assurance.shape",
        "attestation.required_fields",
        "attestation.types",
        "attestation.shape",
    ]
    assert all(item["status"] == "skip" for item in trace)
