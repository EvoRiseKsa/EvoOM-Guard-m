# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Baseline differential evidence — the before/after counterfactual (schema 1.6).

"All tests pass on head" never showed the change FIXED anything: the base may
already have been green (a docs-only patch, dead code, an unrelated edit). The
opt-in baseline run makes the counterfactual measurable:

    baseline FAIL  →  candidate PASS,  same judge/policy/env
        ⇒ repair_effect: "demonstrated"

and ``--require-demonstrated-fix`` turns that evidence into a gate: a PASS whose
repair effect is not demonstrated becomes FAIL (``fix_not_demonstrated``).
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

from evoom_guard.guard import FAIL, PASS, REJECTED, guard

HAS_PYTEST = True
try:
    import pytest as _pytest  # noqa: F401
except ImportError:  # pragma: no cover
    HAS_PYTEST = False

TEST_CMD = [sys.executable, "-m", "pytest", "-q", "--color=no", "-p", "no:cacheprovider"]
BUGGY = "def dbl(x):\n    return x + x + 1\n"
FIXED = "def dbl(x):\n    return x + x\n"
FIX_BLOCK = f"<<<FILE: pkg/m.py>>>\n{FIXED}<<<END FILE>>>"


def _make_repo(root: str, *, buggy: bool) -> None:
    os.makedirs(os.path.join(root, "pkg"))
    os.makedirs(os.path.join(root, "tests"))
    open(os.path.join(root, "pkg", "__init__.py"), "w").close()
    with open(os.path.join(root, "pkg", "m.py"), "w", encoding="utf-8") as f:
        f.write(BUGGY if buggy else FIXED)
    with open(os.path.join(root, "tests", "test_m.py"), "w", encoding="utf-8") as f:
        f.write(
            "import sys, os\n"
            "sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))\n"
            "from pkg.m import dbl\n\n"
            "def test_dbl():\n    assert dbl(3) == 6\n"
        )


@unittest.skipUnless(HAS_PYTEST, "pytest needed to run the suites")
class BaselineEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="evo_baseline_t_")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_demonstrated_fix(self) -> None:
        # Base fails, candidate passes → PASS with repair_effect demonstrated.
        _make_repo(self.root, buggy=True)
        r = guard(self.root, FIX_BLOCK, test_command=TEST_CMD,
                  timeout=120, baseline_evidence=True)
        self.assertEqual(r.verdict, PASS, r.reason)
        assert r.baseline is not None
        self.assertEqual(r.baseline["verdict"], "FAIL")
        self.assertEqual(r.baseline["repair_effect"], "demonstrated")
        # The evidence lands in the machine contract too.
        self.assertEqual(r.to_dict()["baseline"]["repair_effect"], "demonstrated")

    def test_not_demonstrated_on_green_base(self) -> None:
        # Base already passes → the same candidate PASS is NOT a demonstrated fix.
        _make_repo(self.root, buggy=False)
        r = guard(self.root, FIX_BLOCK, test_command=TEST_CMD,
                  timeout=120, baseline_evidence=True)
        self.assertEqual(r.verdict, PASS, r.reason)
        assert r.baseline is not None
        self.assertEqual(r.baseline["verdict"], "PASS")
        self.assertEqual(r.baseline["repair_effect"], "not_demonstrated")

    def test_evidence_only_never_changes_the_verdict(self) -> None:
        _make_repo(self.root, buggy=False)
        plain = guard(self.root, FIX_BLOCK, test_command=TEST_CMD, timeout=120)
        with_ev = guard(self.root, FIX_BLOCK, test_command=TEST_CMD,
                        timeout=120, baseline_evidence=True)
        self.assertEqual(plain.verdict, with_ev.verdict)

    def test_require_demonstrated_fix_demotes_undemonstrated_pass(self) -> None:
        # The opt-in gate: green base + green candidate → FAIL fix_not_demonstrated.
        _make_repo(self.root, buggy=False)
        r = guard(self.root, FIX_BLOCK, test_command=TEST_CMD,
                  timeout=120, require_demonstrated_fix=True)
        self.assertEqual(r.verdict, FAIL)
        self.assertEqual(r.reason_code, "fix_not_demonstrated")
        self.assertIn("already passes", r.reason)

    def test_require_demonstrated_fix_keeps_a_real_fix_green(self) -> None:
        _make_repo(self.root, buggy=True)
        r = guard(self.root, FIX_BLOCK, test_command=TEST_CMD,
                  timeout=120, require_demonstrated_fix=True)
        self.assertEqual(r.verdict, PASS, r.reason)
        assert r.baseline is not None
        self.assertEqual(r.baseline["repair_effect"], "demonstrated")

    def test_rejected_runs_no_baseline(self) -> None:
        # A pre-gated rejection judges nothing — no baseline suite may run.
        _make_repo(self.root, buggy=True)
        cheat = "<<<FILE: tests/test_m.py>>>\ndef test_x():\n    assert True\n<<<END FILE>>>"
        r = guard(self.root, cheat, test_command=TEST_CMD,
                  timeout=120, baseline_evidence=True)
        self.assertEqual(r.verdict, REJECTED)
        self.assertIsNone(r.baseline)

    def test_baseline_appears_in_the_report(self) -> None:
        from evoom_guard.guard import render_report

        _make_repo(self.root, buggy=True)
        r = guard(self.root, FIX_BLOCK, test_command=TEST_CMD,
                  timeout=120, baseline_evidence=True)
        report = render_report(r)
        self.assertIn("Baseline (pristine base)", report)
        self.assertIn("demonstrated", report)


if __name__ == "__main__":
    unittest.main()
