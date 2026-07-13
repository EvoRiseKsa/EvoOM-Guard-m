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
    REJECTED,
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

    def test_editing_pom_xml_is_rejected(self) -> None:
        # a Maven Surefire <excludes> in pom.xml can deselect failing tests.
        cheat = _block("pom.xml", "<project><!-- surefire excludes --></project>\n")
        r = guard(self.root, cheat)
        self.assertEqual(r.verdict, REJECTED)
        self.assertIn("pom.xml", r.protected_violations)

    def test_pom_xml_can_be_allowlisted(self) -> None:
        # an adopter who needs dependency edits can exempt pom.xml via --allow.
        cheat = _block("pom.xml", "<project><!-- deps --></project>\n")
        r = guard(self.root, cheat, allow=("pom.xml",))
        self.assertNotEqual(r.verdict, REJECTED)

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
            rc = cli_main(["guard", self.root, "--diff", path])
            self.assertEqual(rc, 1)  # REJECTED -> non-zero
        finally:
            os.unlink(path)


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
            cli_main(["guard", self.root, "--patch", pf,
                      "--config", os.path.join(self.root, "no-such-config.json")])
        finally:
            guard_mod.RepoVerifier = real  # type: ignore[misc]
        self.assertEqual(seen.get("timeout"), 120)
        self.assertEqual(seen.get("mem_limit_mb"), 1024)

    def test_invalid_mem_limit_is_rejected_safely(self) -> None:
        # A non-integer value is refused by argparse (exit 2), never silently ignored.
        from evoom_guard.cli import build_parser

        with self.assertRaises(SystemExit):
            build_parser().parse_args(["guard", ".", "--mem-limit", "notanumber"])

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


if __name__ == "__main__":
    unittest.main()
