# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Focused contracts for the pure record-envelope type projection."""

from __future__ import annotations

import copy

from record_envelope_types_characterization_harness import (
    capture,
    cases,
    legacy_top_level_type_errors,
    valid_envelope,
)

from evoom_guard import record_verifier
from evoom_guard.verifiers.record_envelope_types import (
    project_envelope_type_errors,
)


def test_projection_is_immutable_and_does_not_mutate_envelope() -> None:
    record = valid_envelope()
    before = copy.deepcopy(record)

    result = project_envelope_type_errors(record)

    assert result == ()
    assert isinstance(result, tuple)
    assert record == before


def test_facade_retains_historical_mutable_list_projection() -> None:
    record = cases()["ordered_multiple_faults"]

    projected = project_envelope_type_errors(record)
    facade = record_verifier._top_level_type_errors(record)

    assert isinstance(projected, tuple)
    assert isinstance(facade, list)
    assert facade == list(projected) == legacy_top_level_type_errors(record)


def test_string_and_boolean_field_families_preserve_order() -> None:
    selected = {
        name: value
        for name, value in cases().items()
        if name.endswith("_not_string") or name.endswith("_not_boolean")
    }
    for value in selected.values():
        assert capture(value) == legacy_top_level_type_errors(value)


def test_integer_and_number_types_reject_boolean_and_non_finite_values() -> None:
    for name in (
        "exit_code_boolean",
        "exit_code_float",
        "risk_score_boolean",
        "risk_score_string",
        "risk_score_nan",
        "risk_score_positive_infinity",
        "risk_score_negative_infinity",
        "tests_passed_boolean",
        "tests_total_float",
    ):
        assert capture(cases()[name]) == legacy_top_level_type_errors(cases()[name])


def test_string_arrays_require_real_lists_with_only_strings() -> None:
    for name in (
        "files_changed_tuple",
        "files_changed_mixed",
        "protected_violations_object",
    ):
        assert capture(cases()[name]) == legacy_top_level_type_errors(cases()[name])


def test_nullable_strings_and_objects_keep_exact_dict_semantics() -> None:
    for name in (
        "valid_nullable_fields",
        "valid_dict_subclasses",
        "verdict_source_object",
        "source_integer",
        "base_reconstruction_boolean",
        "diff_coverage_array",
        "baseline_mapping_not_dict",
        "assurance_null",
        "assurance_array",
        "attestation_array",
    ):
        assert capture(cases()[name]) == legacy_top_level_type_errors(cases()[name])
