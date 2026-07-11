# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""SARIF 2.1.0 output (`--sarif`) for GitHub code-scanning.

A clean PASS emits no results (no alert); any non-PASS verdict emits one
``error``-level result keyed on the stable ``reason_code`` with the offending
files as locations. SARIF is only a view — the decision stays the verdict + exit
code.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard.cli import main as cli_main
from evoom_guard.guard import FAIL, PASS, REJECTED, GuardResult, to_sarif


def _result(verdict: str, **kw) -> GuardResult:
    base = dict(
        verdict=verdict,
        passed=(verdict == PASS),
        reason="because",
        files_changed=["src/a.py"],
        protected_violations=[],
        risk_level="low",
        risk_score=0.1,
    )
    base.update(kw)
    return GuardResult(**base)


def test_sarif_envelope_is_valid_2_1_0():
    doc = to_sarif(_result(PASS))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "EvoGuard"
    assert driver["version"]  # the running version, non-empty


def test_sarif_pass_has_no_results():
    assert to_sarif(_result(PASS))["runs"][0]["results"] == []


def test_sarif_rejected_is_error_with_location_and_rule():
    r = _result(
        REJECTED, reason_code="protected_harness_edit",
        protected_violations=["tests/test_x.py"], reason="edited a test",
    )
    doc = to_sarif(r)
    (res,) = doc["runs"][0]["results"]
    assert res["level"] == "error"
    assert res["ruleId"] == "protected_harness_edit"
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "tests/test_x.py"
    assert res["properties"]["verdict"] == REJECTED
    assert doc["runs"][0]["tool"]["driver"]["rules"][0]["id"] == "protected_harness_edit"


def test_sarif_fail_locations_fall_back_to_changed_files():
    (res,) = to_sarif(_result(FAIL, files_changed=["src/a.py"]))["runs"][0]["results"]
    assert res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/a.py"


def test_cli_writes_sarif_for_a_rejected_patch(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "m.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (repo / "test_m.py").write_text(
        "from m import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n", encoding="utf-8"
    )
    patch = tmp_path / "c.patch"
    patch.write_text(  # a reward-hack: edit the test → REJECTED (no suite run needed)
        "<<<FILE: test_m.py>>>\ndef test_add():\n    assert True\n<<<END FILE>>>", encoding="utf-8"
    )
    out = tmp_path / "r.sarif"
    rc = cli_main(["guard", str(repo), "--patch", str(patch), "--sarif", str(out)])
    assert rc == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    (res,) = doc["runs"][0]["results"]
    assert res["level"] == "error"
    assert "test_m.py" in res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
