# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Focused contracts for the pure diff-coverage type projection."""

from __future__ import annotations

import copy

from record_coverage_types_characterization_harness import (
    capture,
    cases,
    valid_measured,
)

from evoom_guard.verifiers.record_coverage_types import (
    project_diff_coverage_type_errors,
)


def test_projection_is_immutable_and_does_not_mutate_coverage() -> None:
    coverage = valid_measured()
    before = copy.deepcopy(coverage)

    result = project_diff_coverage_type_errors(coverage)

    assert result == ()
    assert isinstance(result, tuple)
    assert coverage == before


def test_python_coverage_paths_remain_safe_and_repo_relative() -> None:
    assert (
        capture(cases()["unsafe_python_paths"])[:4]
        == [
            "files keys must be safe repo-relative .py paths",
        ]
        * 4
    )


def test_line_arrays_require_sorted_unique_positive_non_boolean_lines() -> None:
    coverage = valid_measured()
    coverage.update(
        {
            "percent": 100.0,
            "executed": 1,
            "total": 1,
            "files": {"src/a.py": {"executed": [0], "missed": []}},
        }
    )

    assert project_diff_coverage_type_errors(coverage)[0] == (
        "files['src/a.py'] executed/missed must be sorted unique positive lines"
    )


def test_executed_and_missed_lines_cannot_overlap() -> None:
    assert capture(cases()["line_arrays_overlap"])[0] == (
        "files['src/a.py'] executed and missed lines overlap"
    )


def test_top_level_counts_remain_bound_to_per_file_totals() -> None:
    assert capture(cases()["executed_total_mismatch"])[:2] == [
        "executed does not equal the per-file executed-line total",
        "total does not equal the per-file measurable-line total",
    ]


def test_percentage_remains_bound_to_the_exact_producer_calculation() -> None:
    assert capture(cases()["percent_mismatch"]) == [
        "percent must equal the producer calculation 66.7"
    ]


def test_unmeasured_paths_cannot_claim_python_files_as_out_of_scope() -> None:
    assert capture(cases()["unsafe_unmeasured_paths"]) == [
        "unmeasured_files must be sorted unique safe non-Python paths"
    ]
