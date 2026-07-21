# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""EvoOM Guard tests — the AI patch verification gate.

Offline and model-free. The reward-hack rejection and the diff/report layers run
without pytest; the end-to-end PASS/FAIL paths (which run the repo's suite) are
skipped when pytest is absent.
"""

import difflib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard.cli import main as cli_main
from evoom_guard.guard import (
    ERROR,
    FAIL,
    PASS,
    REASON_NO_VERIFIABLE_CHANGES,
    REASON_VERIFIER_PACK_INVALID,
    REJECTED,
    _UnverifiableChangedPathsError,
    blocks_from_dirs,
    candidate_from_dirs,
    guard,
    guard_from_diff,
    render_report,
)


def _udiff(rel: str, old: str, new: str) -> str:
    """A git-style unified diff (the format `git diff` emits)."""
    return "".join(
        difflib.unified_diff(
            old.splitlines(True), new.splitlines(True),
            fromfile=f"a/{rel}", tofile=f"b/{rel}",
        )
    )

HAS_PYTEST = importlib.util.find_spec("pytest") is not None


def _block(path: str, body: str) -> str:
    return f"<<<FILE: {path}>>>\n{body}\n<<<END FILE>>>"


def _make_repo(root: str) -> None:
    """A tiny multi-file repo: pkg.m.dbl is buggy; the visible test wants dbl(3)==6."""
    os.makedirs(os.path.join(root, "pkg"))
    os.makedirs(os.path.join(root, "tests"))
    open(os.path.join(root, "pkg", "__init__.py"), "w").close()
    with open(os.path.join(root, "pkg", "m.py"), "w", encoding="utf-8") as f:
        f.write("def dbl(x):\n    return x + x + 1\n")  # bug
    with open(os.path.join(root, "tests", "test_m.py"), "w", encoding="utf-8") as f:
        f.write("from pkg.m import dbl\n\n\ndef test_dbl():\n    assert dbl(3) == 6\n")


FIX = _block("pkg/m.py", "def dbl(x):\n    return x * 2\n")
WRONG = _block("pkg/m.py", "def dbl(x):\n    return x * 3\n")


class GuardGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="evo_guard_")
        _make_repo(self.root)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_editing_a_test_is_rejected(self) -> None:
        cheat = _block("tests/test_m.py", "def test_dbl():\n    assert True\n")
        r = guard(self.root, cheat)
        self.assertEqual(r.verdict, REJECTED)
        self.assertFalse(r.passed)
        self.assertIn("tests/test_m.py", r.protected_violations)
        self.assertEqual(r.exit_code, 1)

    def test_editing_the_config_is_rejected(self) -> None:
        cheat = _block("pyproject.toml", '[tool.pytest.ini_options]\naddopts = "-k nope"\n')
        r = guard(self.root, cheat)
        self.assertEqual(r.verdict, REJECTED)
        self.assertIn("pyproject.toml", r.protected_violations)

    def test_creating_an_autoexec_file_is_rejected(self) -> None:
        cheat = _block("sitecustomize.py", "import os\nos._exit(0)\n")
        r = guard(self.root, cheat)
        self.assertEqual(r.verdict, REJECTED)
        self.assertIn("sitecustomize.py", r.protected_violations)

    def test_static_gate_rejects_a_helper_in_a_referenced_local_action(self) -> None:
        """The cheap preflight must see Action helpers before any suite runs."""
        action_dir = os.path.join(self.root, ".ci", "guard")
        os.makedirs(os.path.join(self.root, ".github", "workflows"))
        os.makedirs(action_dir)
        with open(os.path.join(action_dir, "action.yml"), "w", encoding="utf-8") as f:
            f.write("runs:\n  using: composite\n")
        with open(os.path.join(action_dir, "check.py"), "w", encoding="utf-8") as f:
            f.write("raise SystemExit(0)\n")
        with open(
            os.path.join(self.root, ".github", "workflows", "guard.yml"),
            "w", encoding="utf-8",
        ) as f:
            f.write("jobs:\n  guard:\n    steps:\n      - uses: ./.ci/guard\n")

        r = guard(self.root, _block(".ci/guard/check.py", "raise SystemExit(0)\n"))

        self.assertEqual(r.verdict, REJECTED)
        self.assertIn(".ci/guard/check.py", r.protected_violations)
        self.assertFalse(r.test_command_ran)

    def test_editing_pom_xml_is_rejected(self) -> None:
        # a Maven Surefire <excludes> in pom.xml can deselect failing tests.
        cheat = _block("pom.xml", "<project><!-- surefire excludes --></project>\n")
        r = guard(self.root, cheat)
        self.assertEqual(r.verdict, REJECTED)
        self.assertIn("pom.xml", r.protected_violations)

    def test_pom_xml_cannot_be_allowlisted(self) -> None:
        # Build/test configuration controls the judge and remains immutable.
        cheat = _block("pom.xml", "<project><!-- deps --></project>\n")
        r = guard(self.root, cheat, allow=("pom.xml",))
        self.assertEqual(r.verdict, REJECTED)

    def test_no_blocks_is_an_error(self) -> None:
        r = guard(self.root, "just some prose, no edits")
        self.assertEqual(r.verdict, ERROR)
        self.assertFalse(r.passed)

    def test_report_renders_the_verdict_and_reason(self) -> None:
        cheat = _block("tests/test_m.py", "def test_dbl():\n    assert True\n")
        report = render_report(guard(self.root, cheat))
        self.assertIn("REJECTED", report)
        self.assertIn("Reward-hack", report)
        self.assertIn("tests/test_m.py", report)

    def test_static_report_footer_does_not_claim_a_judge_ran(self) -> None:
        # A protected edit is rejected before execution.  The report must not
        # turn the requested/default policy into a claim that a subprocess or
        # container boundary was delivered (regression guard for issue #8 and
        # the static-assurance contract).
        cheat = _block("tests/test_m.py", "def test_dbl():\n    assert True\n")
        report = render_report(guard(self.root, cheat))
        self.assertIn("suite was not started", report)
        self.assertIn("no test command, JUnit report, or runtime isolation was delivered", report)
        self.assertIn("isolation `not_run`", report)
        self.assertNotIn("runs in a subprocess", report)
        self.assertNotIn("container judge", report)

    @unittest.skipUnless(HAS_PYTEST, "needs pytest to run the suite")
    def test_executed_pass_report_still_describes_the_real_judge(self) -> None:
        report = render_report(guard(self.root, FIX))
        self.assertIn("judge-owned JUnit report", report)
        self.assertIn("judge runs the suite in a subprocess", report)
        self.assertNotIn("suite was not started", report)
        self.assertNotIn("isolation `not_run`", report)

    @unittest.skipUnless(HAS_PYTEST, "needs pytest to run the suite")
    def test_correct_source_fix_passes(self) -> None:
        r = guard(self.root, FIX)
        self.assertEqual(r.verdict, PASS)
        self.assertTrue(r.passed)
        self.assertEqual((r.tests_passed, r.tests_total), (1, 1))
        self.assertEqual(r.verdict_source, "junit+exit")
        self.assertEqual(r.exit_code, 0)

    @unittest.skipUnless(HAS_PYTEST, "needs pytest to run the suite")
    def test_wrong_source_fix_fails(self) -> None:
        r = guard(self.root, WRONG)
        self.assertEqual(r.verdict, FAIL)
        self.assertFalse(r.passed)
        self.assertEqual(r.tests_total, 1)
        self.assertEqual(r.exit_code, 1)

    @unittest.skipUnless(HAS_PYTEST, "needs pytest to run the suite")
    def test_forged_stdout_cannot_fake_a_pass(self) -> None:
        # The patch fixes nothing and prints a fake pass summary to the runner's
        # stdout — Guard reads the JUnit oracle, so it cannot be fooled.
        forge = _block(
            "pkg/m.py",
            "import os\n"
            "os.write(1, b'\\n9999 passed in 0.01s\\n')\n"
            "def dbl(x):\n    return x + x + 1\n",
        )
        r = guard(self.root, forge)
        self.assertEqual(r.verdict, FAIL)
        self.assertFalse(r.passed)

    def test_runner_output_outside_the_locale_codec_still_yields_a_verdict(self) -> None:
        # Node-based runners (Vitest banners include "❯") write raw UTF-8 to
        # their pipes regardless of the Windows code page. The judge must read
        # runner pipes as UTF-8: under cp1252 the banner bytes are undecodable
        # (the run died in the reader thread instead of failing the tests) and
        # under other locale codecs they decode as mojibake.
        runner = (
            b"import os, sys\n"
            b"os.write(1, b'\\xe2\\x9d\\xaf 1 test failed\\n')\n"  # "❯" raw UTF-8
            b"sys.exit(1)\n"
        )
        with open(os.path.join(self.root, "run_tests.py"), "wb") as f:
            f.write(runner)
        r = guard(self.root, WRONG, test_command=[sys.executable, "run_tests.py"])
        self.assertEqual(r.verdict, FAIL)
        self.assertFalse(r.passed)
        self.assertIn("❯", r.diagnostics)


class GuardDiffTests(unittest.TestCase):
    def test_candidate_from_dirs_picks_added_and_modified(self) -> None:
        base = tempfile.mkdtemp()
        head = tempfile.mkdtemp()
        try:
            for root in (base, head):
                with open(os.path.join(root, "keep.py"), "w", encoding="utf-8") as f:
                    f.write("X = 1\n")
            # modify one file, add another, delete a third (present only in base)
            with open(os.path.join(base, "old.py"), "w", encoding="utf-8") as f:
                f.write("gone = True\n")
            with open(os.path.join(head, "keep.py"), "w", encoding="utf-8") as f:
                f.write("X = 2\n")  # modified
            with open(os.path.join(head, "new.py"), "w", encoding="utf-8") as f:
                f.write("Y = 3\n")  # added
            candidate, deleted = candidate_from_dirs(base, head)
            self.assertIn("<<<FILE: keep.py>>>", candidate)   # modified -> included
            self.assertIn("<<<FILE: new.py>>>", candidate)    # added -> included
            self.assertIn("X = 2", candidate)
            self.assertEqual(deleted, ["old.py"])              # deletion surfaced
        finally:
            shutil.rmtree(base, ignore_errors=True)
            shutil.rmtree(head, ignore_errors=True)

    def test_blocks_from_dirs_fails_closed_for_changed_oversized_text(self) -> None:
        """A changed >1 MB test must not disappear before the static gate."""
        base = tempfile.mkdtemp()
        head = tempfile.mkdtemp()
        try:
            for root in (base, head):
                os.makedirs(os.path.join(root, "tests"))
            small = "def test_still_valid():\n    assert True\n"
            large = small + "#" + ("x" * 1_000_001) + "\n"
            with open(os.path.join(base, "tests", "test_big.py"), "w", encoding="utf-8") as f:
                f.write(small)
            with open(os.path.join(head, "tests", "test_big.py"), "w", encoding="utf-8") as f:
                f.write(large)

            with self.assertRaisesRegex(ValueError, r"tests/test_big\.py"):
                blocks_from_dirs(base, head)
        finally:
            shutil.rmtree(base, ignore_errors=True)
            shutil.rmtree(head, ignore_errors=True)

    def test_blocks_from_dirs_refuses_a_new_empty_directory(self) -> None:
        """An empty directory is otherwise absent from FILE-block input."""
        base = tempfile.mkdtemp()
        head = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(head, "tests", "new-empty"))

            with self.assertRaises(_UnverifiableChangedPathsError) as raised:
                blocks_from_dirs(base, head)

            self.assertIn("new empty directory", str(raised.exception))
            self.assertIn("tests/new-empty", str(raised.exception))
        finally:
            shutil.rmtree(base, ignore_errors=True)
            shutil.rmtree(head, ignore_errors=True)

    def test_blocks_from_dirs_allows_a_new_directory_implied_by_a_file_block(self) -> None:
        base = tempfile.mkdtemp()
        head = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(head, "new_package"))
            with open(os.path.join(head, "new_package", "module.py"), "wb") as f:
                f.write(b"VALUE = 1\n")

            blocks, deleted = blocks_from_dirs(base, head)

            self.assertEqual(blocks, {"new_package/module.py": "VALUE = 1\n"})
            self.assertEqual(deleted, [])
        finally:
            shutil.rmtree(base, ignore_errors=True)
            shutil.rmtree(head, ignore_errors=True)

    def test_blocks_from_dirs_surfaces_deleted_empty_directories(self) -> None:
        """Directory deletion is applied by the safe recursive deletion path."""
        base = tempfile.mkdtemp()
        head = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(base, "obsolete"))

            blocks, deleted = blocks_from_dirs(base, head)

            self.assertEqual(blocks, {})
            self.assertEqual(deleted, ["obsolete"])
        finally:
            shutil.rmtree(base, ignore_errors=True)
            shutil.rmtree(head, ignore_errors=True)

    def test_blocks_from_dirs_surfaces_deleted_oversized_path(self) -> None:
        """Deletion needs no text payload, so it must remain visible to the gate."""
        base = tempfile.mkdtemp()
        head = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(base, "tests"))
            with open(os.path.join(base, "tests", "test_big.py"), "w", encoding="utf-8") as f:
                f.write("#" + ("x" * 1_000_001) + "\n")

            blocks, deleted = blocks_from_dirs(base, head)
            self.assertEqual(blocks, {})
            self.assertEqual(deleted, ["tests", "tests/test_big.py"])
        finally:
            shutil.rmtree(base, ignore_errors=True)
            shutil.rmtree(head, ignore_errors=True)


class GuardDeletionTests(unittest.TestCase):
    """Deletions are gated (schema 1.1): a deleted harness file is REJECTED, and a
    deleted source file is applied to the verified tree so the verdict matches the
    merge."""

    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="evo_guard_del_")
        _make_repo(self.root)
        # a second, unrelated source module the visible test does NOT import
        with open(os.path.join(self.root, "pkg", "extra.py"), "w", encoding="utf-8") as f:
            f.write("VALUE = 1\n")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_deleting_a_test_file_is_rejected(self) -> None:
        # Removing a check is a reward-hack as direct as editing it.
        r = guard(self.root, FIX, deleted=("tests/test_m.py",))
        self.assertEqual(r.verdict, REJECTED)
        self.assertIn("tests/test_m.py", r.protected_violations)

    def test_deletion_only_violation_is_pre_gated_suite_never_runs(self) -> None:
        # The docs promise every REJECTED is decided BEFORE the suite runs
        # (`test_command_ran: false`). A candidate whose only violation is a
        # protected *deletion* used to slip past that: its added/modified paths
        # were clean, so the suite ran once before the verdict flipped. Pin the
        # fixed contract on the JSON the adopters see.
        r = guard(self.root, FIX, deleted=("tests/test_m.py",))
        self.assertEqual(r.verdict, REJECTED)
        self.assertIsNone(r.verdict_source)              # no suite ran
        self.assertFalse(r.to_dict()["test_command_ran"])  # the public contract

    def test_deleting_config_is_rejected_even_delete_only(self) -> None:
        # A delete-only change that removes the harness config is still REJECTED
        # (not a vague ERROR).
        r = guard(self.root, "", deleted=("pyproject.toml",))
        self.assertEqual(r.verdict, REJECTED)
        self.assertIn("pyproject.toml", r.protected_violations)

    def test_deleting_unsafe_path_is_error(self) -> None:
        r = guard(self.root, FIX, deleted=("../escape.py",))
        self.assertEqual(r.verdict, ERROR)

    @unittest.skipUnless(HAS_PYTEST, "needs pytest to run the suite")
    def test_deleting_an_unused_source_file_still_passes(self) -> None:
        # extra.py is unused by the visible test; deleting it alongside the real fix
        # leaves a green suite.
        r = guard(self.root, FIX, deleted=("pkg/extra.py",))
        self.assertEqual(r.verdict, PASS)

    @unittest.skipUnless(HAS_PYTEST, "needs pytest to run the suite")
    def test_deleting_a_needed_source_file_breaks_the_suite(self) -> None:
        # Proof the deletion is actually applied: removing the module the test
        # imports makes the reconstructed-merge suite fail (it cannot import it).
        r = guard(self.root, "", deleted=("pkg/m.py",))
        self.assertEqual(r.verdict, FAIL)
        self.assertFalse(r.passed)


_BUGGY_M = "def dbl(x):\n    return x + x + 1\n"
_FIXED_M = "def dbl(x):\n    return x * 2\n"


class GuardDiffModeTests(unittest.TestCase):
    """`evo guard --diff`: a base...HEAD diff reverse-applied against the head tree."""

    def setUp(self) -> None:
        # the head working tree (the current checkout — the fix is already in place).
        self.head = tempfile.mkdtemp(prefix="evo_guard_diffmode_")
        _make_repo(self.head)
        with open(os.path.join(self.head, "pkg", "m.py"), "w", encoding="utf-8") as f:
            f.write(_FIXED_M)  # head = fixed

    def tearDown(self) -> None:
        shutil.rmtree(self.head, ignore_errors=True)

    @unittest.skipUnless(HAS_PYTEST, "needs pytest to run the suite")
    def test_valid_diff_passes(self) -> None:
        diff = _udiff("pkg/m.py", _BUGGY_M, _FIXED_M)  # base buggy -> head fixed
        result, _ = guard_from_diff(self.head, diff)
        self.assertEqual(result.verdict, PASS)
        self.assertEqual((result.tests_passed, result.tests_total), (1, 1))

    @unittest.skipUnless(HAS_PYTEST, "needs pytest to run the suite")
    def test_failing_diff_fails(self) -> None:
        # head is a WRONG fix; the diff goes base(buggy) -> head(wrong).
        with open(os.path.join(self.head, "pkg", "m.py"), "w", encoding="utf-8") as f:
            f.write("def dbl(x):\n    return x * 3\n")
        diff = _udiff("pkg/m.py", _BUGGY_M, "def dbl(x):\n    return x * 3\n")
        result, _ = guard_from_diff(self.head, diff)
        self.assertEqual(result.verdict, FAIL)
        self.assertFalse(result.passed)

    def test_diff_editing_a_test_is_rejected(self) -> None:
        # head edits the judging test; the diff carries that test change.
        with open(os.path.join(self.head, "tests", "test_m.py"), "w", encoding="utf-8") as f:
            f.write("from pkg.m import dbl\n\n\ndef test_dbl():\n    assert True\n")
        diff = _udiff(
            "tests/test_m.py",
            "from pkg.m import dbl\n\n\ndef test_dbl():\n    assert dbl(3) == 6\n",
            "from pkg.m import dbl\n\n\ndef test_dbl():\n    assert True\n",
        )
        result, _ = guard_from_diff(self.head, diff)
        self.assertEqual(result.verdict, REJECTED)
        self.assertIn("tests/test_m.py", result.protected_violations)

    def test_large_test_edit_is_error_not_a_pass(self) -> None:
        """Regression for a >1 MB test edit silently vanishing from --diff."""
        original_test = (
            "from pkg.m import dbl\n\n\n"
            "def test_dbl():\n"
            "    assert dbl(3) == 6\n"
        )
        large_test = original_test + "#" + ("x" * 1_000_001) + "\n"
        with open(os.path.join(self.head, "tests", "test_m.py"), "w", encoding="utf-8") as f:
            f.write(large_test)
        diff = (
            _udiff("pkg/m.py", _BUGGY_M, _FIXED_M)
            + _udiff("tests/test_m.py", original_test, large_test)
        )

        result, _ = guard_from_diff(self.head, diff)

        self.assertEqual(result.verdict, ERROR)
        self.assertEqual(result.reason_code, REASON_NO_VERIFIABLE_CHANGES)
        self.assertIn("tests/test_m.py", result.reason)
        self.assertFalse(result.to_dict()["test_command_ran"])

    def test_diff_verifier_pack_requires_an_identity_pin(self) -> None:
        """An external-looking but unpinned pack is not a trusted diff oracle."""
        pack = tempfile.mkdtemp(prefix="evo_guard_external_pack_")
        try:
            with open(os.path.join(pack, "test_invariant.py"), "w", encoding="utf-8") as f:
                f.write("def test_invariant():\n    assert True\n")
            diff = _udiff("pkg/m.py", _BUGGY_M, _FIXED_M)

            result, _ = guard_from_diff(self.head, diff, verifier_pack=pack)

            self.assertEqual(result.verdict, ERROR)
            self.assertEqual(result.reason_code, REASON_VERIFIER_PACK_INVALID)
            self.assertIn("SHA-256 pin", result.reason)
            self.assertFalse(result.test_command_ran)
        finally:
            shutil.rmtree(pack, ignore_errors=True)

    def test_diff_rejects_a_pinned_pack_nested_in_the_candidate_checkout(self) -> None:
        """A SHA cannot make candidate-selected verifier bytes judge-owned."""
        pack = os.path.join(self.head, "judge-pack")
        os.makedirs(pack)
        with open(os.path.join(pack, "test_invariant.py"), "w", encoding="utf-8") as f:
            f.write("def test_invariant():\n    assert True\n")
        diff = _udiff("pkg/m.py", _BUGGY_M, _FIXED_M)

        result, _ = guard_from_diff(
            self.head,
            diff,
            verifier_pack=pack,
            expect_verifier_pack_sha256="0" * 64,
        )

        self.assertEqual(result.verdict, ERROR)
        self.assertEqual(result.reason_code, REASON_VERIFIER_PACK_INVALID)
        self.assertIn("inside the candidate checkout", result.reason)
        self.assertFalse(result.test_command_ran)

    @unittest.skipUnless(HAS_PYTEST, "needs pytest to run the suite")
    def test_diff_forging_stdout_cannot_fake_a_pass(self) -> None:
        # head fixes nothing but prints a fake pass summary; the diff carries it.
        forged = (
            "import os\n"
            "os.write(1, b'\\n9999 passed in 0.01s\\n')\n" + _BUGGY_M
        )
        with open(os.path.join(self.head, "pkg", "m.py"), "w", encoding="utf-8") as f:
            f.write(forged)
        diff = _udiff("pkg/m.py", _BUGGY_M, forged)
        result, _ = guard_from_diff(self.head, diff)
        self.assertEqual(result.verdict, FAIL)
        self.assertFalse(result.passed)

    def test_empty_diff_is_an_error(self) -> None:
        result, _ = guard_from_diff(self.head, "")
        self.assertEqual(result.verdict, ERROR)

    # ---- hardening for untrusted diffs ---------------------------------- #
    @staticmethod
    def _snapshot(root: str) -> dict:
        snap = {}
        for dp, _dn, fns in os.walk(root):
            for fn in fns:
                p = os.path.join(dp, fn)
                with open(p, "rb") as f:
                    snap[os.path.relpath(p, root)] = f.read()
        return snap

    def test_working_tree_is_never_modified(self) -> None:
        # A REJECTED test-edit diff exercises copy + reverse-apply + candidate build
        # without needing pytest; the real working tree must be byte-for-byte intact.
        with open(os.path.join(self.head, "tests", "test_m.py"), "w", encoding="utf-8") as f:
            f.write("from pkg.m import dbl\n\n\ndef test_dbl():\n    assert True\n")
        diff = _udiff(
            "tests/test_m.py",
            "from pkg.m import dbl\n\n\ndef test_dbl():\n    assert dbl(3) == 6\n",
            "from pkg.m import dbl\n\n\ndef test_dbl():\n    assert True\n",
        )
        before = self._snapshot(self.head)
        guard_from_diff(self.head, diff)
        self.assertEqual(self._snapshot(self.head), before)

    def test_reverse_apply_failure_is_a_clear_error(self) -> None:
        # The diff's "new" side does not match the head tree, so reverse-apply fails.
        diff = _udiff("pkg/m.py", _BUGGY_M, "def dbl(x):\n    return 999\n")
        result, _ = guard_from_diff(self.head, diff)
        self.assertEqual(result.verdict, ERROR)
        self.assertIn("reverse-apply", result.reason)
        self.assertEqual(result.base_reconstruction, "failed")

    def test_absolute_path_in_diff_is_refused(self) -> None:
        diff = "--- a/pkg/m.py\n+++ b//etc/passwd\n@@ -1 +1 @@\n-x\n+y\n"
        before = self._snapshot(self.head)
        result, _ = guard_from_diff(self.head, diff)
        self.assertEqual(result.verdict, ERROR)
        self.assertIn("unsafe", result.reason)
        self.assertEqual(self._snapshot(self.head), before)  # nothing applied

    def test_parent_escape_path_in_diff_is_refused(self) -> None:
        diff = "--- a/pkg/m.py\n+++ b/../../etc/passwd\n@@ -1 +1 @@\n-x\n+y\n"
        result, _ = guard_from_diff(self.head, diff)
        self.assertEqual(result.verdict, ERROR)
        self.assertIn("unsafe", result.reason)

    def test_binary_patch_is_refused(self) -> None:
        diff = (
            "diff --git a/img.png b/img.png\n"
            "Binary files a/img.png and b/img.png differ\n"
        )
        result, _ = guard_from_diff(self.head, diff)
        self.assertEqual(result.verdict, ERROR)
        self.assertIn("binary", result.reason.lower())

    def test_report_shows_source_and_base_reconstruction(self) -> None:
        diff = _udiff(
            "tests/test_m.py",
            "from pkg.m import dbl\n\n\ndef test_dbl():\n    assert dbl(3) == 6\n",
            "from pkg.m import dbl\n\n\ndef test_dbl():\n    assert True\n",
        )
        with open(os.path.join(self.head, "tests", "test_m.py"), "w", encoding="utf-8") as f:
            f.write("from pkg.m import dbl\n\n\ndef test_dbl():\n    assert True\n")
        result, _ = guard_from_diff(self.head, diff)
        report = render_report(result)
        self.assertIn("| Input | diff |", report)
        self.assertIn("| Base reconstruction | ok |", report)


class GuardCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="evo_guard_cli_")
        _make_repo(self.root)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_cli_rejects_a_test_edit_with_exit_1(self) -> None:
        fd, patch = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(_block("tests/test_m.py", "def test_dbl():\n    assert True\n"))
        try:
            rc = cli_main(["guard", self.root, "--patch", patch])
            self.assertEqual(rc, 1)
        finally:
            os.unlink(patch)

    def test_cli_usage_without_inputs(self) -> None:
        rc = cli_main(["guard", self.root])
        self.assertEqual(rc, 2)

    def test_cli_diff_mode_rejects_a_test_edit(self) -> None:
        # head edits the judging test; a --diff file carrying that change is rejected.
        with open(os.path.join(self.root, "tests", "test_m.py"), "w", encoding="utf-8") as f:
            f.write("from pkg.m import dbl\n\n\ndef test_dbl():\n    assert True\n")
        diff = _udiff(
            "tests/test_m.py",
            "from pkg.m import dbl\n\n\ndef test_dbl():\n    assert dbl(3) == 6\n",
            "from pkg.m import dbl\n\n\ndef test_dbl():\n    assert True\n",
        )
        fd, path = tempfile.mkstemp(suffix=".diff")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(diff)
        try:
            rc = cli_main(["guard", self.root, "--diff", path, "--no-config"])
            self.assertEqual(rc, 1)  # REJECTED -> non-zero
        finally:
            os.unlink(path)

    def test_cli_base_head_large_test_edit_fails_closed(self) -> None:
        """The --base/--head route must report ERROR, not crash or pass."""
        base = tempfile.mkdtemp(prefix="evo_guard_cli_base_")
        head = tempfile.mkdtemp(prefix="evo_guard_cli_head_")
        json_out = os.path.join(head, "guard.json")
        try:
            _make_repo(base)
            shutil.copytree(base, head, dirs_exist_ok=True)
            with open(os.path.join(head, "pkg", "m.py"), "w", encoding="utf-8") as f:
                f.write(_FIXED_M)
            with open(os.path.join(head, "tests", "test_m.py"), "a", encoding="utf-8") as f:
                f.write("#" + ("x" * 1_000_001) + "\n")

            rc = cli_main([
                "guard", "--base", base, "--head", head, "--no-config", "--json", json_out,
            ])

            self.assertEqual(rc, 1)
            with open(json_out, encoding="utf-8") as f:
                payload = json.load(f)
            self.assertEqual(payload["verdict"], ERROR)
            self.assertEqual(payload["reason_code"], REASON_NO_VERIFIABLE_CHANGES)
            self.assertEqual(payload["source"], "base/head")
            self.assertIn("tests/test_m.py", payload["reason"])
            self.assertFalse(payload["test_command_ran"])
        finally:
            shutil.rmtree(base, ignore_errors=True)
            shutil.rmtree(head, ignore_errors=True)


class MemLimitOptionTests(unittest.TestCase):
    """The ``--mem-limit`` CLI option threads the address-space cap to the judge.

    Default behaviour is unchanged (1024 MB); ``0`` disables the cap, which is
    required for Node/V8 suites that reserve far more virtual memory than any sane
    ``RLIMIT_AS`` (the default cap would SIGABRT them).
    """

    def test_parser_default_and_override(self) -> None:
        from evoom_guard.cli import build_parser

        p = build_parser()
        # The CLI defaults are now sentinels (None) so .evoguard.json can supply a
        # value; the effective 1024 MB / 120 s are applied in cmd_guard (see the
        # effective-default test below). Explicit values still parse.
        self.assertIsNone(p.parse_args(["guard", "."]).mem_limit)
        self.assertEqual(p.parse_args(["guard", ".", "--mem-limit", "0"]).mem_limit, 0)
        self.assertIsNone(p.parse_args(["guard", "."]).timeout)
        self.assertEqual(p.parse_args(["guard", ".", "--timeout", "5"]).timeout, 5)

    def test_cmd_guard_applies_effective_defaults(self) -> None:
        # With no flag and no config, cmd_guard resolves the built-in 1024 MB / 120 s
        # and threads them to the judge. The spy's stubbed verify() keeps this
        # hermetic — no suite ever runs. (A protected-path patch no longer works
        # here: since the deletion-pre-gate fix, guard() never even CONSTRUCTS the
        # verifier for a pre-gated rejection.)
        import evoom_guard.guard as guard_mod
        from evoom_guard.contracts import VerdictResult

        seen: dict[str, int] = {}
        real = guard_mod.RepoVerifier

        class _Spy(real):  # type: ignore[misc, valid-type]
            def __init__(self, *a, **kw):
                seen["timeout"] = kw.get("timeout")
                seen["mem_limit_mb"] = kw.get("mem_limit_mb")
                super().__init__(*a, **kw)

            def verify(self, hypothesis, problem):  # never run a real suite
                return VerdictResult(
                    passed=True, score=1.0, diagnostics="",
                    artifact={"tests_passed": 1, "tests_total": 1,
                              "verdict_source": "junit+exit"},
                )

        guard_mod.RepoVerifier = _Spy  # type: ignore[misc]
        pf = os.path.join(self.root, "cand.patch")
        with open(pf, "w", encoding="utf-8") as f:
            f.write("<<<FILE: pkg/m.py>>>\n# a safe source edit\n<<<END FILE>>>")
        try:
            cli_main(["guard", self.root, "--patch", pf, "--no-config"])
        finally:
            guard_mod.RepoVerifier = real  # type: ignore[misc]
        self.assertEqual(seen.get("timeout"), 120)
        self.assertEqual(seen.get("mem_limit_mb"), 1024)

    def test_invalid_mem_limit_is_rejected_safely(self) -> None:
        # A non-integer value is refused by argparse (exit 2), never silently ignored.
        from evoom_guard.cli import build_parser

        with self.assertRaises(SystemExit):
            build_parser().parse_args(["guard", ".", "--mem-limit", "notanumber"])

    def test_guard_api_rejects_values_that_cannot_form_a_valid_policy(self) -> None:
        import evoom_guard.guard as guard_mod

        candidate = "<<<FILE: pkg/m.py>>>\n\n<<<END FILE>>>"
        for timeout in (0, -1, True, 1.0):
            with self.subTest(timeout=timeout), self.assertRaisesRegex(
                ValueError, "timeout must be a positive integer"
            ):
                guard_mod.guard(self.root, candidate, timeout=timeout)  # type: ignore[arg-type]
        for mem_limit in (-1, True, 1.0):
            with self.subTest(mem_limit=mem_limit), self.assertRaisesRegex(
                ValueError, "mem_limit_mb must be a non-negative integer"
            ):
                guard_mod.guard(self.root, candidate, mem_limit_mb=mem_limit)  # type: ignore[arg-type]
        for coverage_floor in (
            -1.0,
            100.1,
            float("nan"),
            float("inf"),
            True,
            "80",
            10**10000,
        ):
            with self.subTest(coverage_floor=coverage_floor), self.assertRaisesRegex(
                ValueError, "min_diff_coverage must be a finite number between 0 and 100"
            ):
                guard_mod.guard(  # type: ignore[arg-type]
                    self.root, candidate, min_diff_coverage=coverage_floor
                )

    def test_guard_threads_mem_limit_to_verifier(self) -> None:
        import evoom_guard.guard as guard_mod

        seen: dict[str, int] = {}
        real = guard_mod.RepoVerifier

        class _Spy(real):  # type: ignore[misc, valid-type]
            def __init__(self, *a, **kw):
                seen["mem_limit_mb"] = kw.get("mem_limit_mb")
                super().__init__(*a, **kw)

        guard_mod.RepoVerifier = _Spy  # type: ignore[misc]
        try:
            guard_mod.guard(self.root, "<<<FILE: pkg/m.py>>>\n\n<<<END FILE>>>", mem_limit_mb=0)
        finally:
            guard_mod.RepoVerifier = real  # type: ignore[misc]
        self.assertEqual(seen.get("mem_limit_mb"), 0)

    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="evo_memlimit_")
        os.makedirs(os.path.join(self.root, "pkg"))
        with open(os.path.join(self.root, "pkg", "m.py"), "w", encoding="utf-8") as f:
            f.write("def dbl(x):\n    return x * 2\n")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


class RuntimeContainmentOutcomeTests(unittest.TestCase):
    """Runner containment failures must preserve a truthful public verdict."""

    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="evo_runtime_outcome_")
        _make_repo(self.root)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_output_cap_is_an_incomplete_error_not_a_pass_or_apply_failure(self) -> None:
        import evoom_guard.guard as guard_mod
        from evoom_guard.contracts import VerdictResult

        real = guard_mod.RepoVerifier

        class _FloodedRunner(real):  # type: ignore[misc, valid-type]
            def verify(self, hypothesis, problem):
                return VerdictResult(
                    passed=False,
                    score=0.0,
                    diagnostics="test suite output was rejected: capture limit exceeded",
                    artifact={"outcome": "test_output_limit", "files_changed": ["pkg/m.py"]},
                )

        guard_mod.RepoVerifier = _FloodedRunner  # type: ignore[misc]
        try:
            result = guard_mod.guard(self.root, FIX)
        finally:
            guard_mod.RepoVerifier = real  # type: ignore[misc]

        self.assertEqual(result.verdict, ERROR)
        self.assertEqual(result.reason_code, "test_timeout")
        self.assertEqual(result.execution_state, "started_incomplete")
        self.assertTrue(result.test_command_ran)

    def test_unproven_process_tree_cleanup_is_a_distinct_runtime_error(self) -> None:
        import evoom_guard.guard as guard_mod
        from evoom_guard.contracts import VerdictResult

        real = guard_mod.RepoVerifier

        class _UncontainedRunner(real):  # type: ignore[misc, valid-type]
            def verify(self, hypothesis, problem):
                return VerdictResult(
                    passed=False,
                    score=0.0,
                    diagnostics="test suite containment failed",
                    artifact={"outcome": "runtime_containment_error", "files_changed": ["pkg/m.py"]},
                )

        guard_mod.RepoVerifier = _UncontainedRunner  # type: ignore[misc]
        try:
            result = guard_mod.guard(self.root, FIX)
        finally:
            guard_mod.RepoVerifier = real  # type: ignore[misc]

        self.assertEqual(result.verdict, ERROR)
        self.assertEqual(result.reason_code, "runtime_cleanup_failed")
        self.assertEqual(result.execution_state, "started_incomplete")
        self.assertFalse(result.test_command_ran)


if __name__ == "__main__":
    unittest.main()
