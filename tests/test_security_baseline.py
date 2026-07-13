# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Smoke tests for the reproducible security microbenchmark harness."""

from benchmarks.security_baseline import run_baseline
from evoom_guard import __version__


def test_security_baseline_records_scope_and_environment(tmp_path) -> None:
    result = run_baseline(tmp_path, files=8, bytes_per_file=32, rounds=2)

    assert result["files"] == 8
    assert result["payload_bytes"] == 256
    assert result["snapshot_entries"] >= 8
    assert result["rounds"] == 2
    assert result["engine_version"] == __version__
    assert result["median_seconds"] >= 0
    assert "equivalent environments" in result["scope"]


def test_security_baseline_rejects_non_positive_dimensions(tmp_path) -> None:
    for kwargs in (
        {"files": 0},
        {"bytes_per_file": 0},
        {"rounds": 0},
    ):
        try:
            run_baseline(tmp_path, **kwargs)
        except ValueError as exc:
            assert "positive" in str(exc)
        else:  # pragma: no cover - defensive assertion branch
            raise AssertionError(f"invalid baseline dimensions accepted: {kwargs}")
