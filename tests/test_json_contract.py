# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Sole owner & author: Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""The machine-readable JSON contract — the stable surface every adapter (IDE
extension, Claude Code hook, GitHub Action) keys off.

These pin the contract so it cannot drift silently: the verdict names, the
``reason_code`` vocabulary, the presence of ``schema_version`` / ``exit_code`` /
``test_command_ran``, and the new ``TAMPERED`` verdict + ``doctor`` report. The
pure-function and pre-subprocess paths run without pytest; the end-to-end PASS /
FAIL / TAMPERED paths are skipped when pytest is absent.
"""

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard import __version__
from evoom_guard.cli import cmd_doctor, doctor_report
from evoom_guard.cli import main as cli_main
from evoom_guard.guard import (
    ERROR,
    FAIL,
    PASS,
    REASON_BINARY_PATCH,
    REASON_EMPTY_DIFF,
    REASON_JUNIT_EXIT_MISMATCH,
    REASON_NO_PARSEABLE_EDITS,
    REASON_PROTECTED_HARNESS_EDIT,
    REASON_REVERSE_APPLY_FAILED,
    REASON_TESTS_FAILED,
    REASON_TESTS_PASSED,
    REASON_UNSAFE_PATH,
    REJECTED,
    SCHEMA_VERSION,
    TAMPERED,
    guard,
    guard_from_diff,
)
from evoom_guard.verifiers.repo_verifier import detect_tamper, parse_junit_xml

HAS_PYTEST = importlib.util.find_spec("pytest") is not None

# The frozen vocabulary adapters are allowed to see. Adding a code is a
# SCHEMA_VERSION-compatible change; renaming/removing one is breaking.
KNOWN_REASON_CODES = {
    REASON_TESTS_PASSED, REASON_PROTECTED_HARNESS_EDIT, REASON_TESTS_FAILED,
    REASON_NO_PARSEABLE_EDITS, REASON_UNSAFE_PATH, "patch_apply_failed",
    "no_test_verdict", REASON_JUNIT_EXIT_MISMATCH, REASON_EMPTY_DIFF,
    REASON_BINARY_PATCH, REASON_REVERSE_APPLY_FAILED, "no_verifiable_changes",
}
KNOWN_VERDICTS = {PASS, REJECTED, FAIL, ERROR, TAMPERED}

REQUIRED_KEYS = {
    "schema_version", "tool", "tool_version", "verdict", "passed", "exit_code",
    "reason_code", "reason", "files_changed", "protected_violations", "risk_level",
    "risk_score", "tests_passed", "tests_total", "test_command_ran",
    "verdict_source", "source", "base_reconstruction", "diagnostics",
}


def _block(path: str, body: str) -> str:
    return f"<<<FILE: {path}>>>\n{body}\n<<<END FILE>>>"


def _make_repo(root: str) -> None:
    os.makedirs(os.path.join(root, "tests"))
    with open(os.path.join(root, "calc.py"), "w", encoding="utf-8") as f:
        f.write("def add(a, b):\n    return a - b\n")  # bug
    with open(os.path.join(root, "tests", "test_calc.py"), "w", encoding="utf-8") as f:
        f.write("from calc import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n")


def _assert_envelope(tc: unittest.TestCase, payload: dict) -> None:
    """Every verdict JSON must carry the full, stable envelope."""
    tc.assertEqual(REQUIRED_KEYS - set(payload), set(), "missing contract keys")
    tc.assertEqual(payload["schema_version"], SCHEMA_VERSION)
    tc.assertEqual(payload["tool"], "evoguard")
    tc.assertEqual(payload["tool_version"], __version__)
    tc.assertIn(payload["verdict"], KNOWN_VERDICTS)
    tc.assertIn(payload["reason_code"], KNOWN_REASON_CODES)
    # exit_code is 0 iff PASS; non-PASS is always 1.
    tc.assertEqual(payload["exit_code"], 0 if payload["verdict"] == PASS else 1)
    tc.assertEqual(payload["passed"], payload["verdict"] == PASS)


class DetectTamperTests(unittest.TestCase):
    """The pure tamper oracle: exit code ⟷ JUnit report (dis)agreement."""

    def _j(self, **kw):
        return parse_junit_xml(
            '<testsuite tests="{tests}" failures="{failures}" errors="{errors}" '
            'skipped="0"/>'.format(**kw)
        )

    def test_allpass_report_nonzero_exit_is_tamper(self) -> None:
        self.assertTrue(detect_tamper(3, self._j(tests=2, failures=0, errors=0), report_expected=True))

    def test_failing_report_zero_exit_is_tamper(self) -> None:
        self.assertTrue(detect_tamper(0, self._j(tests=2, failures=1, errors=0), report_expected=True))
        self.assertTrue(detect_tamper(0, self._j(tests=2, failures=0, errors=1), report_expected=True))

    def test_agreement_is_not_tamper(self) -> None:
        # clean pass + exit 0, and real failure + exit 1 — the signals agree.
        self.assertFalse(detect_tamper(0, self._j(tests=2, failures=0, errors=0), report_expected=True))
        self.assertFalse(detect_tamper(1, self._j(tests=2, failures=1, errors=0), report_expected=True))

    def test_no_report_is_not_tamper(self) -> None:
        # A collection error (nonzero exit, no/garbled report) is not a desync.
        self.assertFalse(detect_tamper(2, None, report_expected=True))
        self.assertFalse(detect_tamper(0, None, report_expected=False))


class DoctorTests(unittest.TestCase):
    def test_report_has_required_keys_and_types(self) -> None:
        info = doctor_report()
        for key in ("tool", "version", "platform", "python", "git", "patch", "supported"):
            self.assertIn(key, info)
        self.assertEqual(info["tool"], "evoguard")
        self.assertEqual(info["version"], __version__)
        self.assertIsInstance(info["git"], bool)
        self.assertIsInstance(info["supported"], bool)
        self.assertEqual(info["supported"], info["git"] or info["patch"])

    def test_cli_doctor_json_is_valid_and_exit_reflects_support(self) -> None:
        captured: list[str] = []
        rc = cli_main(["doctor", "--json"])  # prints to real stdout; also check rc
        self.assertIn(rc, (0, 1))
        # exercise the printer path directly for JSON validity
        import argparse
        cmd_doctor(argparse.Namespace(doctor_json=True), out=captured.append)
        payload = json.loads("\n".join(captured))
        self.assertEqual(payload["tool"], "evoguard")


class JsonContractTests(unittest.TestCase):
    """Pre-subprocess paths — valid envelope without pytest installed."""

    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="evo_contract_")
        _make_repo(self.root)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_rejected_envelope(self) -> None:
        r = guard(self.root, _block("tests/test_calc.py", "def test_add():\n    assert True\n"))
        _assert_envelope(self, r.to_dict())
        self.assertEqual(r.verdict, REJECTED)
        self.assertEqual(r.reason_code, REASON_PROTECTED_HARNESS_EDIT)
        self.assertFalse(r.to_dict()["test_command_ran"])  # rejected before running

    def test_no_blocks_envelope(self) -> None:
        r = guard(self.root, "just prose")
        _assert_envelope(self, r.to_dict())
        self.assertEqual(r.reason_code, REASON_NO_PARSEABLE_EDITS)

    def test_unsafe_edit_block_path_is_named_correctly(self) -> None:
        # Regression: an unsafe FILE path used to be mislabeled "PATCH anchor did
        # not match". It must now carry reason_code=unsafe_path and say so.
        r = guard(self.root, _block("../escape.py", "x = 1"))
        _assert_envelope(self, r.to_dict())
        self.assertEqual(r.verdict, ERROR)
        self.assertEqual(r.reason_code, REASON_UNSAFE_PATH)
        self.assertIn("unsafe", r.reason.lower())

    def test_diff_error_reason_codes(self) -> None:
        cases = {
            "": REASON_EMPTY_DIFF,
            "diff --git a/x b/x\nBinary files a/x and b/x differ\n": REASON_BINARY_PATCH,
            "--- a/calc.py\n+++ /etc/passwd\n@@ -1 +1 @@\n-x\n+y\n": REASON_UNSAFE_PATH,
            "--- a/calc.py\n+++ b/calc.py\n@@ -1 +1 @@\n-nope\n+also-nope\n":
                REASON_REVERSE_APPLY_FAILED,
        }
        for diff, expected in cases.items():
            result, _ = guard_from_diff(self.root, diff)
            _assert_envelope(self, result.to_dict())
            self.assertEqual(result.verdict, ERROR)
            self.assertEqual(result.reason_code, expected, repr(diff[:20]))

    def test_cli_invalid_usage_exits_2(self) -> None:
        self.assertEqual(cli_main(["guard", self.root]), 2)


@unittest.skipUnless(HAS_PYTEST, "needs pytest to run the suite")
class JsonContractRunningTests(unittest.TestCase):
    """End-to-end paths that actually run the suite."""

    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="evo_contract_run_")
        _make_repo(self.root)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_pass_envelope(self) -> None:
        r = guard(self.root, _block("calc.py", "def add(a, b):\n    return a + b\n"))
        _assert_envelope(self, r.to_dict())
        self.assertEqual(r.verdict, PASS)
        self.assertEqual(r.reason_code, REASON_TESTS_PASSED)
        self.assertTrue(r.to_dict()["test_command_ran"])

    def test_fail_envelope(self) -> None:
        r = guard(self.root, _block("calc.py", "def add(a, b):\n    return a + b + 1\n"))
        _assert_envelope(self, r.to_dict())
        self.assertEqual(r.verdict, FAIL)
        self.assertEqual(r.reason_code, REASON_TESTS_FAILED)

    def test_tampered_verdict_end_to_end(self) -> None:
        # Tests pass (2 made to pass) but an atexit hook forces a non-zero exit
        # AFTER pytest writes its all-pass report — a genuine exit/JUnit desync.
        forged = (
            "import atexit, os\n"
            "def add(a, b):\n    return a + b\n"
            "atexit.register(lambda: os._exit(7))\n"
        )
        r = guard(self.root, _block("calc.py", forged))
        _assert_envelope(self, r.to_dict())
        self.assertEqual(r.verdict, TAMPERED)
        self.assertEqual(r.reason_code, REASON_JUNIT_EXIT_MISMATCH)
        self.assertFalse(r.passed)
        self.assertEqual(r.exit_code, 1)


if __name__ == "__main__":
    unittest.main()
