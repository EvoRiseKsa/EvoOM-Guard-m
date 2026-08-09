# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Focused contracts for the pure record-policy type projection."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from record_policy_types_characterization_harness import capture, cases

from evoom_guard import record_verifier
from evoom_guard.verifiers.record_policy_types import project_policy_type_validation


def _errors(case_name: str) -> list[str]:
    return capture(cases()[case_name])


def test_policy_projection_is_frozen_and_does_not_mutate_inputs() -> None:
    case = cases()["valid_schema_1_12"]
    projection = project_policy_type_validation(
        case.policy,
        case.schema_version,
        policy_keys=record_verifier._contract_v1_12.POLICY_KEYS,
        allowed_policy_keys=record_verifier._contract_v1_12.ALLOWED_POLICY_KEYS,
        harness_input_validator=record_verifier._is_canonical_harness_input_list,
        setup_conflict_predicate=record_verifier._setup_output_hides_harness_input,
    )

    assert projection.errors == ()
    assert projection.operating_profile == "local"
    with pytest.raises(FrozenInstanceError):
        projection.operating_profile = None  # type: ignore[misc]


def test_required_policy_fields_and_error_order_cannot_be_bypassed() -> None:
    assert _errors("missing_sorted") == [
        "missing keys: allow, mode, timeout",
        "mode must be repo or blackbox",
        "allow must be an array of strings",
        "timeout must be a positive integer",
    ]


def test_schema_specific_extra_keys_cannot_be_bypassed() -> None:
    assert _errors("extra_sorted") == [
        "unexpected schema-1.11 keys: alpha, zeta"
    ]
    assert _errors("valid_schema_1_12") == []


def test_harness_inputs_remain_canonical_and_visible_to_setup_conflicts() -> None:
    assert _errors("harness_inputs_invalid")[-1].startswith(
        "harness_inputs must be a non-empty sorted unique array"
    )
    assert _errors("harness_input_conflict")[-1] == (
        "setup_output_globs cannot exclude harness_inputs: ci/judge.py"
    )


def test_timeout_rejects_bool_zero_and_negative_values() -> None:
    assert "timeout must be a positive integer" in _errors("numeric_fields_invalid")
    assert _errors("timeout_zero") == ["timeout must be a positive integer"]
    assert _errors("timeout_negative") == ["timeout must be a positive integer"]


def test_pack_digest_remains_lowercase_and_requires_the_pack() -> None:
    assert _errors("pack_digest_invalid") == [
        "expect_verifier_pack_sha256 must be a lowercase SHA-256 or null"
    ]
    assert _errors("pack_digest_requires_pack") == [
        "an expected pack digest requires verifier_pack_required"
    ]


def test_valid_hostile_profile_cannot_skip_semantic_reverification() -> None:
    errors = _errors("operating_profile_hostile_violations")

    assert "operating_profile 'hostile' requires blackbox_only=true" in errors
    assert "operating_profile 'hostile' requires isolation='gvisor'" in errors
    assert "operating_profile 'hostile' requires docker_image" in errors
