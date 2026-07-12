# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
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
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard import __version__
from evoom_guard.cli import cmd_doctor, doctor_report
from evoom_guard.cli import main as cli_main
from evoom_guard.guard import (
    ERROR,
    FAIL,
    PASS,
    REASON_ASSURANCE_REQUIREMENT_NOT_MET,
    REASON_BINARY_PATCH,
    REASON_CANDIDATE_TREE_CHANGED,
    REASON_DIFF_COVERAGE_BELOW_THRESHOLD,
    REASON_EMPTY_DIFF,
    REASON_FIX_NOT_DEMONSTRATED,
    REASON_JUNIT_EXIT_MISMATCH,
    REASON_NO_PARSEABLE_EDITS,
    REASON_NO_TEST_VERDICT,
    REASON_NO_VERIFIABLE_CHANGES,
    REASON_PATCH_APPLY_FAILED,
    REASON_POLICY_REQUIREMENT_UNSUPPORTED,
    REASON_PROTECTED_HARNESS_EDIT,
    REASON_REVERSE_APPLY_FAILED,
    REASON_SETUP_FAILED,
    REASON_SETUP_TIMEOUT,
    REASON_TEST_COMMAND_UNAVAILABLE,
    REASON_TEST_TIMEOUT,
    REASON_TESTS_FAILED,
    REASON_TESTS_PASSED,
    REASON_UNSAFE_PATH,
    REASON_VERIFIER_PACK_IDENTITY_MISMATCH,
    REASON_VERIFIER_PACK_INVALID,
    REASON_VERIFIER_PACK_SNAPSHOT_CHANGED,
    REJECTED,
    SCHEMA_VERSION,
    TAMPERED,
    guard,
    guard_from_diff,
)
from evoom_guard.pack_manifest import PACK_DIGEST_FORMAT, pack_digest
from evoom_guard.verifiers.repo_verifier import detect_tamper, parse_junit_xml

HAS_PYTEST = importlib.util.find_spec("pytest") is not None

# The frozen vocabulary adapters are allowed to see. Adding a code is a
# SCHEMA_VERSION-compatible change; renaming/removing one is breaking.
KNOWN_REASON_CODES = {
    REASON_TESTS_PASSED, REASON_PROTECTED_HARNESS_EDIT, REASON_TESTS_FAILED,
    REASON_NO_PARSEABLE_EDITS, REASON_UNSAFE_PATH, REASON_PATCH_APPLY_FAILED,
    REASON_NO_TEST_VERDICT, REASON_JUNIT_EXIT_MISMATCH, REASON_EMPTY_DIFF,
    REASON_BINARY_PATCH, REASON_REVERSE_APPLY_FAILED,
    REASON_NO_VERIFIABLE_CHANGES, REASON_DIFF_COVERAGE_BELOW_THRESHOLD,
    REASON_TEST_TIMEOUT, REASON_SETUP_TIMEOUT, REASON_SETUP_FAILED,
    REASON_ASSURANCE_REQUIREMENT_NOT_MET, REASON_FIX_NOT_DEMONSTRATED,
    REASON_POLICY_REQUIREMENT_UNSUPPORTED, REASON_VERIFIER_PACK_IDENTITY_MISMATCH,
    REASON_VERIFIER_PACK_INVALID, REASON_VERIFIER_PACK_SNAPSHOT_CHANGED,
    REASON_CANDIDATE_TREE_CHANGED, REASON_TEST_COMMAND_UNAVAILABLE,
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


def _make_pack(root: str, *, manifest: str | None = None) -> str:
    pack = os.path.join(root, "pack")
    os.makedirs(pack)
    with open(os.path.join(pack, "test_contract.py"), "w", encoding="utf-8") as f:
        f.write(
            "from calc import add\n\n"
            "def test_pack_contract():\n"
            "    assert add(10, 20) == 30\n"
        )
    if manifest is not None:
        with open(os.path.join(pack, "pack.json"), "w", encoding="utf-8") as f:
            f.write(manifest)
    return pack


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

    def test_frozen_reason_code_vocabulary_covers_every_exported_code(self) -> None:
        # Adapters switch on values, not constant names. A new reason may be
        # additive, but it must be added to this frozen vocabulary deliberately.
        import evoom_guard.guard as guard_module

        exported = {
            value
            for name, value in vars(guard_module).items()
            if name.startswith("REASON_") and isinstance(value, str)
        }
        self.assertEqual(exported, KNOWN_REASON_CODES)
        exported_names = [
            name for name in vars(guard_module) if name.startswith("REASON_")
        ]
        self.assertEqual(len(exported_names), len(exported), "duplicate reason-code value")

    def test_missing_test_command_has_a_stable_fail_closed_reason(self) -> None:
        r = guard(
            self.root,
            _block("calc.py", "def add(a, b):\n    return a + b"),
            test_command=["__evoguard_command_that_must_not_exist__"],
        )
        _assert_envelope(self, r.to_dict())
        self.assertEqual(r.verdict, ERROR)
        self.assertEqual(r.reason_code, REASON_TEST_COMMAND_UNAVAILABLE)
        self.assertFalse(r.to_dict()["test_command_ran"])

    def test_invalid_pack_has_a_stable_fail_closed_reason(self) -> None:
        pack = _make_pack(self.root, manifest="{broken")
        r = guard(
            self.root,
            _block("calc.py", "def add(a, b):\n    return a + b"),
            verifier_pack=pack,
        )
        _assert_envelope(self, r.to_dict())
        self.assertEqual(r.verdict, ERROR)
        self.assertEqual(r.reason_code, REASON_VERIFIER_PACK_INVALID)
        self.assertFalse(r.to_dict()["test_command_ran"])

    def test_pack_identity_mismatch_reason_is_consistent_across_judges(self) -> None:
        pack = _make_pack(self.root)
        wrong = "0" * 64
        common = {
            "verifier_pack": pack,
            "expect_verifier_pack_sha256": wrong,
        }
        repo_result = guard(
            self.root,
            _block("calc.py", "def add(a, b):\n    return a + b"),
            **common,
        )
        blackbox_result = guard(
            self.root,
            _block("calc.py", "def add(a, b):\n    return a + b"),
            blackbox=True,
            blackbox_only=True,
            **common,
        )
        for result in (repo_result, blackbox_result):
            with self.subTest(mode=(result.attestation or {}).get("mode")):
                _assert_envelope(self, result.to_dict())
                self.assertEqual(result.verdict, ERROR)
                self.assertEqual(
                    result.reason_code, REASON_VERIFIER_PACK_IDENTITY_MISMATCH
                )
                self.assertFalse(result.to_dict()["test_command_ran"])
                assert result.attestation is not None
                self.assertEqual(
                    result.attestation["effective_policy"][
                        "expect_verifier_pack_sha256"
                    ],
                    wrong,
                )

    def test_windows_blackbox_subprocess_refusal_is_a_structured_error(self) -> None:
        pack = _make_pack(self.root)
        with mock.patch("evoom_guard.candidate_runner.os.name", "nt"):
            result = guard(
                self.root,
                _block("calc.py", "def add(a, b):\n    return a + b"),
                verifier_pack=pack,
                blackbox=True,
                blackbox_only=True,
            )
        _assert_envelope(self, result.to_dict())
        self.assertEqual(result.verdict, ERROR)
        self.assertEqual(
            result.reason_code, REASON_ASSURANCE_REQUIREMENT_NOT_MET
        )
        self.assertIn("WSL on Windows", result.reason)
        self.assertEqual(result.isolation, "unavailable")
        self.assertFalse(result.to_dict()["test_command_ran"])


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

    def test_matching_pack_pin_is_normalized_and_bound_to_the_attestation(self) -> None:
        pack = _make_pack(self.root)
        expected = pack_digest(pack)
        r = guard(
            self.root,
            _block("calc.py", "def add(a, b):\n    return a + b"),
            verifier_pack=pack,
            expect_verifier_pack_sha256=expected.upper(),
        )
        _assert_envelope(self, r.to_dict())
        self.assertEqual(r.verdict, PASS, r.reason)
        assert r.attestation is not None
        self.assertEqual(r.attestation["verifier_pack_sha256"], expected)
        self.assertEqual(
            r.attestation["verifier_pack_digest_format"], PACK_DIGEST_FORMAT
        )
        self.assertEqual(
            r.attestation["effective_policy"]["expect_verifier_pack_sha256"],
            expected,
        )


if __name__ == "__main__":
    unittest.main()
