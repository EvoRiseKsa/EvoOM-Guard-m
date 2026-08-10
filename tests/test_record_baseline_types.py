# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Focused contracts for the pure baseline type projection."""

from __future__ import annotations

import copy

from record_baseline_types_characterization_harness import (
    capture,
    cases,
    valid_fail,
)

from evoom_guard.verifiers.record_baseline_types import (
    project_baseline_type_errors,
)


def test_projection_is_immutable_and_does_not_mutate_baseline() -> None:
    baseline = valid_fail()
    before = copy.deepcopy(baseline)

    result = project_baseline_type_errors(baseline)

    assert result == ()
    assert isinstance(result, tuple)
    assert baseline == before
    assert capture(baseline) == []


def test_required_and_unknown_producer_keys_cannot_be_bypassed() -> None:
    assert capture(cases()["missing_and_unknown_keys"])[:2] == [
        "baseline has missing or unknown producer keys",
        "baseline.note must be a non-empty string",
    ]


def test_non_string_keys_fail_closed_before_value_validation() -> None:
    assert capture(cases()["non_string_key"]) == [
        "all baseline keys must be strings"
    ]


def test_unsupported_mode_requires_exact_keys_and_null_evidence() -> None:
    assert capture(cases()["unsupported_with_setup"]) == [
        "unsupported-mode baseline cannot contain setup fields"
    ]
    assert capture(cases()["unsupported_non_null_evidence"]) == [
        "unsupported-mode baseline must contain only null evidence"
    ]


def test_counts_reject_boolean_negative_and_out_of_order_values() -> None:
    assert capture(cases()["boolean_counts"])[:2] == [
        "baseline counts must be a null or ordered integer pair",
        "clean baseline verdicts require integer counts",
    ]
    assert capture(cases()["out_of_order_pass_counts"])[0] == (
        "baseline counts must be a null or ordered integer pair"
    )


def test_clean_verdict_count_truth_tables_cannot_be_bypassed() -> None:
    assert capture(cases()["partial_pass_counts"]) == [
        "a PASS baseline must have all-passing counts"
    ]
    assert capture(cases()["all_passing_fail_counts"]) == [
        "a FAIL baseline must have zero exit-only counts or a failed test"
    ]


def test_repair_effect_remains_bound_to_cleanliness() -> None:
    assert capture(cases()["no_clean_measured_effect"]) == [
        "NO_CLEAN_VERDICT requires an unmeasured repair effect"
    ]
    assert capture(cases()["clean_unmeasured_effect"]) == [
        "clean baseline verdict requires a measured repair effect"
    ]


def test_setup_fidelity_requires_an_unclean_unmeasured_baseline() -> None:
    assert capture(cases()["invalid_setup_fidelity"]) == [
        "setup_fidelity is invalid"
    ]
    assert capture(cases()["setup_failure_with_clean_verdict"]) == [
        "setup fidelity failures require an unclean baseline"
    ]


def test_changed_tree_paths_are_nonempty_sorted_unique_strings() -> None:
    for name in (
        "changed_tree_empty_paths",
        "changed_tree_unsorted_duplicate_paths",
        "changed_tree_non_string_paths",
    ):
        assert capture(cases()[name]) == [
            "changed judged tree requires sorted unique changed paths"
        ]
    assert capture(cases()["changes_without_changed_tree"]) == [
        "setup_fidelity_changes requires changed_judged_tree"
    ]
