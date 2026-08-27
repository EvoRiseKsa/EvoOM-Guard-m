# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""The blind independent-evaluation demo composes all three protocol phases.

Pins that ``tools/evaluation/blind_eval_demo.py`` drives the real
commit/freeze/score protocol end to end and emits a signed, scored report, so the
worked example an external evaluator adapts can never silently rot.
"""

from __future__ import annotations

import json
from pathlib import Path

from tools.evaluation.blind_eval_demo import main


def test_demo_runs_all_three_phases_and_emits_a_scored_report(tmp_path: Path) -> None:
    out = tmp_path / "run"
    assert main(["--out-dir", str(out)]) == 0

    # All phase artifacts exist; the score report is the signed outcome.
    for name in (
        "public-label-commitment.json",
        "public-label-commitment.json.sig",
        "frozen-predictions.json",
        "frozen-predictions.json.sig",
        "score-report.json",
    ):
        assert (out / name).is_file(), name

    report = json.loads((out / "score-report.json").read_text(encoding="utf-8"))
    assert report["schema_version"] == "evoguard-blind-score-report-v2"
    # The illustrative corpus populates every confusion cell for the gate, and the
    # ordinary-CI baseline classifies its four cases exactly (one abstention each).
    guard = report["guard_metrics"]
    assert (guard["tp"], guard["fn"], guard["tn"], guard["fp"]) == (1, 1, 1, 1)
    assert guard["abstain"] == 1
    baseline = report["baseline_metrics"]
    assert (baseline["tp"], baseline["fn"], baseline["tn"], baseline["fp"]) == (2, 0, 2, 0)

    # Status strings are what the tool verifies (byte/relation integrity), not
    # claims about the parties' independence.
    assert report["independence_status"] == "externally_declared_not_verified_by_tool"
    assert report["key_separation_status"].startswith("distinct_keys_verified")


def test_demo_refuses_a_non_empty_output_dir(tmp_path: Path) -> None:
    out = tmp_path / "used"
    out.mkdir()
    (out / "leftover").write_text("x", encoding="utf-8")
    # The protocol outputs are create-only; the demo refuses a dirty directory.
    assert main(["--out-dir", str(out)]) == 2
