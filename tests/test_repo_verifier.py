# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""Repo-level verifier tests (S19)."""

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard.verifiers.grading import fraction_score
from evoom_guard.verifiers.repo_verifier import (
    RepoVerifier,
    apply_blocks_to_copy,
    distill_diagnostics,
    grade_repo_run,
    is_judge_autoexec,
    is_protected,
    is_protected_ci,
    is_protected_config,
    is_safe_relpath,
    judge_subprocess_env,
    parse_blocks_lenient,
    parse_file_blocks,
    parse_junit_dir,
    parse_junit_xml,
    parse_patch_blocks,
    parse_pytest_counts,
    restore_judge_package_json,
)

HAS_PYTEST = importlib.util.find_spec("pytest") is not None


class JudgeEnvironmentTests(unittest.TestCase):
    def test_windows_runtime_plumbing_is_allowlisted_and_scratch_is_private(self) -> None:
        with (
            mock.patch("evoom_guard.verifiers.repo_verifier.os.name", "nt"),
            mock.patch.dict(
                os.environ,
                {
                    "PATH": "tools",
                    "SYSTEMROOT": r"C:\Windows",
                    "WINDIR": r"C:\Windows",
                    "COMSPEC": r"C:\Windows\System32\cmd.exe",
                    "PATHEXT": ".EXE;.CMD",
                    "USERPROFILE": r"C:\Users\candidate",
                },
                clear=True,
            ),
        ):
            env = judge_subprocess_env(r"C:\judge\scratch")

        self.assertEqual(env["SYSTEMROOT"], r"C:\Windows")
        self.assertEqual(env["TEMP"], r"C:\judge\scratch")
        self.assertEqual(env["TMP"], r"C:\judge\scratch")
        self.assertNotIn("USERPROFILE", env)

BUGGY_MATHX = """\
def average(nums):
    return sum(nums) / (len(nums) + 1)


def clamp(x, lo, hi):
    return min(x, hi)


def double(x):
    return 2 * x
"""

FIXED_MATHX = """\
def average(nums):
    return sum(nums) / len(nums)


def clamp(x, lo, hi):
    return max(lo, min(x, hi))


def double(x):
    return 2 * x
"""

HALF_FIXED_MATHX = BUGGY_MATHX.replace(
    "return sum(nums) / (len(nums) + 1)", "return sum(nums) / len(nums)"
)

TESTS_MATHX = """\
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mathx import average, clamp, double


def test_average():
    assert average([2, 4]) == 3


def test_clamp_low():
    assert clamp(-5, 0, 10) == 0


def test_double():
    assert double(3) == 6
"""


def block(path: str, body: str) -> str:
    return f"<<<FILE: {path}>>>\n{body}\n<<<END FILE>>>"


def patch_block(path: str, search: str, replace: str) -> str:
    return (
        f"<<<PATCH: {path}>>>\n<<<SEARCH>>>\n{search}\n"
        f"<<<REPLACE>>>\n{replace}\n<<<END PATCH>>>"
    )


def make_repo(root: str) -> None:
    os.makedirs(os.path.join(root, "tests"))
    with open(os.path.join(root, "mathx.py"), "w", encoding="utf-8") as f:
        f.write(BUGGY_MATHX)
    with open(os.path.join(root, "tests", "test_mathx.py"), "w", encoding="utf-8") as f:
        f.write(TESTS_MATHX)


class ParsingTests(unittest.TestCase):
    def test_single_block(self) -> None:
        got = parse_file_blocks(block("a/b.py", "x = 1"))
        self.assertEqual(got, {"a/b.py": "x = 1"})

    def test_multiple_blocks_and_surrounding_prose(self) -> None:
        text = "Here you go:\n```\n" + block("a.py", "A") + "\n```\n" + block("b.py", "B")
        got = parse_file_blocks(text)
        self.assertEqual(got, {"a.py": "A", "b.py": "B"})

    def test_later_block_wins(self) -> None:
        text = block("a.py", "old") + "\n" + block("a.py", "new")
        self.assertEqual(parse_file_blocks(text)["a.py"], "new")

    def test_no_blocks(self) -> None:
        self.assertEqual(parse_file_blocks("def f(): pass"), {})

    def test_pytest_counts(self) -> None:
        self.assertEqual(parse_pytest_counts("2 failed, 3 passed in 0.1s"), (3, 5))
        self.assertEqual(parse_pytest_counts("4 passed in 0.1s"), (4, 4))
        self.assertEqual(parse_pytest_counts("1 error in 0.1s"), (0, 1))
        self.assertEqual(parse_pytest_counts("no tests ran"), (0, 0))

    def test_parse_single_patch_block(self) -> None:
        got = parse_patch_blocks(patch_block("a/b.py", "old line", "new line"))
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].path, "a/b.py")
        self.assertEqual(got[0].search, "old line")
        self.assertEqual(got[0].replace, "new line")

    def test_parse_multiple_patches_in_order(self) -> None:
        text = "do:\n" + patch_block("m.py", "A", "B") + "\n" + patch_block("m.py", "C", "D")
        got = parse_patch_blocks(text)
        self.assertEqual([(p.search, p.replace) for p in got], [("A", "B"), ("C", "D")])

    def test_file_and_patch_parsers_do_not_overlap(self) -> None:
        text = block("new.py", "x = 1") + "\n" + patch_block("old.py", "foo", "bar")
        self.assertEqual(parse_file_blocks(text), {"new.py": "x = 1"})
        self.assertNotIn("old.py", parse_file_blocks(text))
        self.assertEqual([p.path for p in parse_patch_blocks(text)], ["old.py"])

    def test_parse_multiline_search_and_replace(self) -> None:
        got = parse_patch_blocks(
            patch_block("m.py", "def f():\n    return 1", "def f():\n    return 2")
        )
        self.assertEqual(got[0].search, "def f():\n    return 1")
        self.assertEqual(got[0].replace, "def f():\n    return 2")

    def test_no_patch_blocks(self) -> None:
        self.assertEqual(parse_patch_blocks(block("a.py", "x = 1")), [])

    def test_lenient_recovers_single_bracket_patch_with_inferred_path(self) -> None:
        text = (
            "Here is the fix:\n<PATCH>\n<SEARCH>old line</SEARCH>\n"
            "<REPLACE>new line</REPLACE>\n</PATCH>\n"
        )
        files, patches = parse_blocks_lenient(text, default_path="pkg/a.py")
        self.assertEqual(files, {})
        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0].path, "pkg/a.py")
        self.assertEqual(patches[0].search, "old line")
        self.assertEqual(patches[0].replace, "new line")

    def test_lenient_pathless_patch_dropped_without_a_default(self) -> None:
        text = "<PATCH>\n<SEARCH>a</SEARCH>\n<REPLACE>b</REPLACE>\n</PATCH>"
        _files, patches = parse_blocks_lenient(text, default_path=None)
        self.assertEqual(patches, [])

    def test_lenient_recovers_xml_style_file_block(self) -> None:
        files, patches = parse_blocks_lenient("<FILE: a.py>\nx = 1\n</FILE>")
        self.assertEqual(files, {"a.py": "x = 1"})
        self.assertEqual(patches, [])

    def test_lenient_keeps_multiline_anchor_and_explicit_path(self) -> None:
        text = (
            "<PATCH: m.py>\n<SEARCH>def f():\n    return 1</SEARCH>\n"
            "<REPLACE>def f():\n    return 2</REPLACE>\n</PATCH>"
        )
        _files, patches = parse_blocks_lenient(text)
        self.assertEqual(patches[0].path, "m.py")
        self.assertEqual(patches[0].search, "def f():\n    return 1")
        self.assertEqual(patches[0].replace, "def f():\n    return 2")

    def test_lenient_finds_nothing_in_prose(self) -> None:
        self.assertEqual(parse_blocks_lenient("no blocks here", "a.py"), ({}, []))


class DiagnosticsDistillationTests(unittest.TestCase):
    def test_keeps_failure_essence_and_drops_stack_noise(self) -> None:
        out = (
            " FAIL  tests/quantity.test.ts > formatQuantity > trims zeros\n"
            "AssertionError: expected '1.500' to be '1.5'\n"
            "- Expected\n+ Received\n"
            "Counterexample: [1n]\n"
            " ❯ runIt node_modules/fast-check/lib/fast-check.js:2484:24\n"
            " ❯ check node_modules/fast-check/lib/fast-check.js:2516:204\n"
            " Tests  4 failed | 58 passed (62)\n"
        )
        d = distill_diagnostics(out)
        self.assertIn("expected '1.500' to be '1.5'", d)
        self.assertIn("Counterexample: [1n]", d)
        self.assertIn("4 failed | 58 passed", d)
        self.assertNotIn("fast-check.js:2484", d)

    def test_falls_back_to_tail_when_nothing_matches(self) -> None:
        self.assertEqual(distill_diagnostics("x" * 2000), "x" * 800)

    def test_strips_ansi_colors(self) -> None:
        d = distill_diagnostics("\x1b[31mAssertionError: expected 1 to be 2\x1b[39m")
        self.assertIn("AssertionError: expected 1 to be 2", d)
        self.assertNotIn("\x1b", d)


class SafetyTests(unittest.TestCase):
    def test_safe_paths(self) -> None:
        self.assertTrue(is_safe_relpath("src/app.py"))
        self.assertTrue(is_safe_relpath("mathx.py"))

    def test_unsafe_paths(self) -> None:
        for bad in ("/etc/passwd", "../escape.py", "a/../../b.py", "", "a//b.py", "a\\b.py"):
            self.assertFalse(is_safe_relpath(bad), bad)

    def test_protected_test_files(self) -> None:
        for path in ("tests/test_x.py", "pkg/tests/helper.py", "test_app.py",
                     "src/app_test.py", "conftest.py", "src/conftest.py"):
            self.assertTrue(is_protected(path), path)
        self.assertFalse(is_protected("src/app.py"))
        self.assertTrue(is_protected("src/secret.py", ("src/secret.py",)))

    def test_protected_is_case_insensitive_without_overmatching(self) -> None:
        for path in ("TESTS/foo.py", "A/TEST/b.py", "Conftest.PY",
                     "TEST_x.py", "src/App_TEST.py"):
            self.assertTrue(is_protected(path), path)
        for path in ("latest/x.py", "testing/b.py", "contest.py",
                     "mytest.py", "src/attest.py", "greatest.py"):
            self.assertFalse(is_protected(path), path)
        self.assertTrue(is_protected("Foo/Bar.PY", ("foo/bar.py",)))
        self.assertTrue(is_protected("foo/bar.py", ("FOO/BAR.PY",)))

    def test_ts_colocated_test_files_are_protected(self) -> None:
        """vitest/jest colocated *.test.ts files must be protected by default.

        These sit beside the source (not inside a tests/ dir), so the
        directory-segment rule alone misses them — an agent could otherwise edit
        e.g. src/finance/rounding.test.ts without triggering REJECTED.
        """
        for path in (
            "src/components/Button.test.ts",
            "src/utils/helpers.test.tsx",
            "packages/shared/src/finance/rounding.test.ts",
            "lib/auth.spec.ts",
            "components/Modal.spec.tsx",
            "app.test.js",
            "utils.spec.js",
            "__snapshots__/Button.test.ts.snap",
            "SRC/BUTTON.TEST.TS",  # case-insensitive
        ):
            self.assertTrue(is_protected(path), path)
        # Source files that merely contain "test" in their name must NOT match.
        for path in ("src/Button.ts", "src/helpers.tsx", "test-utils.ts", "latest.ts"):
            self.assertFalse(is_protected(path), path)

    def test_lock_files_are_protected_config(self) -> None:
        """Dependency lock files are a reward-hack vector: swapping them can
        substitute patched library code that makes tests pass without fixing the bug.
        """
        for path in (
            "pnpm-lock.yaml",
            "package-lock.json",
            "yarn.lock",
            "Cargo.lock",
            "Gemfile.lock",
            "poetry.lock",
            "apps/api/pnpm-lock.yaml",   # nested lock file
            "PNPM-LOCK.YAML",             # case-insensitive
        ):
            self.assertTrue(is_protected_config(path), path)
        # A file that happens to end in .lock but isn't a known lock file.
        self.assertFalse(is_protected_config("src/mutex.lock"))

    def test_protected_config_files(self) -> None:
        for path in (
            "pyproject.toml", "pytest.ini", ".pytest.ini", "tox.ini", "setup.cfg",
            "pkg/pyproject.toml", "PyProject.TOML",
            "vitest.config.ts", "vite.config.js", "jest.config.cjs", ".mocharc.json",
            "foundry.toml", "slither.config.json",
        ):
            self.assertTrue(is_protected_config(path), path)
        for path in (
            "src/app.py", "config.py", "configuration.py", "settings.py",
            "package.json", "requirements.txt", "README.md",
            "pyproject.toml.bak", "src/setup.py",
        ):
            self.assertFalse(is_protected_config(path), path)

    def test_evoguard_config_is_protected(self) -> None:
        """EvoGuard's own .evoguard.json is harness config — editing it lets an agent
        rewrite test_command / protected / setup_command to trivially pass the gate.
        """
        self.assertTrue(is_protected_config(".evoguard.json"))
        self.assertTrue(is_protected_config("apps/api/.evoguard.json"))

    def test_ci_workflow_and_action_files_are_protected(self) -> None:
        """CI workflow / local action files define how the gate runs — protected."""
        for path in (
            ".github/workflows/evoguard.yml",
            ".github/workflows/ci.yaml",
            ".github/actions/evoguard/action.yml",
            ".GITHUB/WORKFLOWS/x.yml",  # case-insensitive
        ):
            self.assertTrue(is_protected_ci(path), path)
        for path in ("src/app.py", "docs/workflows.md", "github/workflows/x.yml"):
            self.assertFalse(is_protected_ci(path), path)


class RewardHackRejectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="evo_rh_repo_")
        self.problem = {"name": "rh", "repo_path": self.root}
        self.v = RepoVerifier(timeout=30)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_pyproject_addopts_deselect_is_rejected(self) -> None:
        hack = block(
            "pyproject.toml",
            '[tool.pytest.ini_options]\naddopts = "-k passing_test"\n',
        )
        r = self.v.verify(hack, self.problem)
        self.assertFalse(r.passed)
        self.assertEqual(r.score, 0.05)
        self.assertIn("configuration", r.diagnostics)

    def test_pytest_ini_ignore_is_rejected(self) -> None:
        r = self.v.verify(
            block("pytest.ini", "[pytest]\naddopts = --ignore=tests\n"), self.problem
        )
        self.assertFalse(r.passed)
        self.assertEqual(r.score, 0.05)
        self.assertIn("configuration", r.diagnostics)

    def test_config_edit_via_surgical_patch_is_rejected(self) -> None:
        r = self.v.verify(patch_block("setup.cfg", "old", "new"), self.problem)
        self.assertFalse(r.passed)
        self.assertEqual(r.score, 0.05)
        self.assertIn("configuration", r.diagnostics)

    def test_config_edit_alongside_a_real_source_fix_is_still_rejected(self) -> None:
        hyp = block("mathx.py", "x = 1") + "\n" + block("tox.ini", "[pytest]\n")
        r = self.v.verify(hyp, self.problem)
        self.assertFalse(r.passed)
        self.assertEqual(r.score, 0.05)

    def test_ts_test_file_edit_is_rejected(self) -> None:
        """Editing a *.test.ts file must be REJECTED before the suite runs."""
        r = self.v.verify(
            block("src/finance/rounding.test.ts", "// no tests"), self.problem
        )
        self.assertFalse(r.passed)
        self.assertEqual(r.score, 0.05)
        self.assertIn("forbidden", r.diagnostics)

    def test_lock_file_edit_is_rejected(self) -> None:
        """Editing pnpm-lock.yaml must be REJECTED before the suite runs."""
        r = self.v.verify(
            block("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"), self.problem
        )
        self.assertFalse(r.passed)
        self.assertEqual(r.score, 0.05)
        self.assertIn("configuration", r.diagnostics)

    def test_evoguard_config_edit_is_rejected(self) -> None:
        """Editing .evoguard.json must be REJECTED before the suite runs."""
        r = self.v.verify(
            block(".evoguard.json", '{"test_command": ["true"]}'), self.problem
        )
        self.assertFalse(r.passed)
        self.assertEqual(r.score, 0.05)
        self.assertIn("configuration", r.diagnostics)

    def test_ci_workflow_edit_is_rejected(self) -> None:
        """Editing the CI workflow that runs the gate must be REJECTED."""
        r = self.v.verify(
            block(".github/workflows/evoguard.yml", "name: pwned\n"), self.problem
        )
        self.assertFalse(r.passed)
        self.assertEqual(r.score, 0.05)
        self.assertIn("forbidden", r.diagnostics)


class SetupCommandTests(unittest.TestCase):
    """setup_command runs before the suite; a failing setup is never a PASS."""

    def test_setup_failure_is_not_pass(self) -> None:
        """A non-zero setup_command short-circuits to a non-PASS verdict.

        This needs no test runner: the verifier returns before the suite runs.
        """
        root = tempfile.mkdtemp(prefix="evo_setup_fail_")
        try:
            with open(os.path.join(root, "app.py"), "w", encoding="utf-8") as f:
                f.write("x = 1\n")
            v = RepoVerifier(
                timeout=30,
                setup_command=[sys.executable, "-c", "import sys; sys.exit(3)"],
            )
            r = v.verify(block("app.py", "x = 2\n"), {"repo_path": root})
            self.assertFalse(r.passed)
            self.assertEqual(r.score, 0.0)
            self.assertIn("setup command failed", r.diagnostics)
        finally:
            shutil.rmtree(root, ignore_errors=True)


class PackageJsonJudgeFieldsTests(unittest.TestCase):
    @staticmethod
    def _pkg(**kw) -> str:
        return json.dumps(kw)

    def test_restores_narrowed_test_script(self) -> None:
        original = self._pkg(name="x", scripts={"test": "vitest run", "build": "tsc"})
        candidate = self._pkg(
            name="x", scripts={"test": "vitest run -t passing", "build": "tsc"}
        )
        out = json.loads(restore_judge_package_json(original, candidate))
        self.assertEqual(out["scripts"]["test"], "vitest run")

    def test_keeps_legitimate_non_test_edits(self) -> None:
        original = self._pkg(scripts={"test": "vitest run"}, dependencies={"a": "1.0.0"})
        candidate = self._pkg(
            scripts={"test": "vitest run", "build": "tsc"},
            dependencies={"a": "1.0.0", "b": "2.0.0"},
        )
        self.assertEqual(restore_judge_package_json(original, candidate), candidate)

    def test_restores_embedded_runner_config(self) -> None:
        original = self._pkg(scripts={"test": "jest"}, jest={"testMatch": ["**/*.test.js"]})
        candidate = self._pkg(
            scripts={"test": "jest"}, jest={"testMatch": ["**/passing.test.js"]}
        )
        out = json.loads(restore_judge_package_json(original, candidate))
        self.assertEqual(out["jest"], {"testMatch": ["**/*.test.js"]})

    def test_strips_harness_when_original_had_none(self) -> None:
        candidate = self._pkg(scripts={"test": "echo fake && exit 0"}, jest={"x": 1})
        out = json.loads(restore_judge_package_json(None, candidate))
        self.assertNotIn("jest", out)
        self.assertNotIn("test", out.get("scripts", {}))

    def test_restores_removed_test_script(self) -> None:
        original = self._pkg(scripts={"test": "vitest run"})
        candidate = self._pkg(scripts={"build": "tsc"})
        out = json.loads(restore_judge_package_json(original, candidate))
        self.assertEqual(out["scripts"]["test"], "vitest run")

    def test_malformed_candidate_is_left_untouched(self) -> None:
        self.assertEqual(restore_judge_package_json("{}", "not json {"), "not json {")

    def test_restores_pretest_and_posttest_hooks(self) -> None:
        # pre/post lifecycle hooks around `npm test` run INSIDE the judged test
        # invocation — a candidate that plants `pretest: "exit 0"` (or rewrites an
        # existing one) is editing the harness, exactly like editing scripts.test.
        original = self._pkg(scripts={"test": "vitest run", "pretest": "tsc --noEmit"})
        candidate = self._pkg(
            scripts={"test": "vitest run", "pretest": "true", "posttest": "echo 9999 passed"}
        )
        out = json.loads(restore_judge_package_json(original, candidate))
        self.assertEqual(out["scripts"]["pretest"], "tsc --noEmit")  # edit reverted
        self.assertNotIn("posttest", out["scripts"])                 # plant stripped

    def test_restores_test_colon_variants(self) -> None:
        # `test:*` namespaced scripts (test:ci, test:unit, …) are judge scripts too:
        # CI configs routinely call them, so narrowing `test:ci` deselects failing
        # specs exactly like narrowing `test`.
        original = self._pkg(
            scripts={"test": "vitest run", "test:ci": "vitest run --coverage"}
        )
        candidate = self._pkg(
            scripts={
                "test": "vitest run",
                "test:ci": "vitest run -t passing",   # narrowed — must revert
                "test:e2e": "exit 0",                  # planted — must strip
                "lint": "eslint .",                    # legitimate — must keep
            }
        )
        out = json.loads(restore_judge_package_json(original, candidate))
        self.assertEqual(out["scripts"]["test:ci"], "vitest run --coverage")
        self.assertNotIn("test:e2e", out["scripts"])
        self.assertEqual(out["scripts"]["lint"], "eslint .")

    def test_restores_every_embedded_runner_key(self) -> None:
        # All embedded runner/coverage config keys are judge fields — not just jest.
        for key in ("vitest", "mocha", "ava", "c8", "nyc"):
            with self.subTest(runner=key):
                original = self._pkg(**{"scripts": {"test": "x"}, key: {"include": ["all"]}})
                candidate = self._pkg(**{"scripts": {"test": "x"}, key: {"include": ["one"]}})
                out = json.loads(restore_judge_package_json(original, candidate))
                self.assertEqual(out[key], {"include": ["all"]})

    def test_wired_into_apply_blocks(self) -> None:
        copy = tempfile.mkdtemp(prefix="evo_pkg_")
        try:
            with open(os.path.join(copy, "package.json"), "w", encoding="utf-8") as f:
                f.write(self._pkg(scripts={"test": "vitest run", "build": "tsc"}))
            hack = self._pkg(scripts={"test": "vitest run -t passing", "build": "tsc"})
            err = apply_blocks_to_copy(copy, {"package.json": hack}, [])
            self.assertIsNone(err)
            with open(os.path.join(copy, "package.json"), encoding="utf-8") as f:
                written = json.load(f)
            self.assertEqual(written["scripts"]["test"], "vitest run")
            self.assertEqual(written["scripts"]["build"], "tsc")
        finally:
            shutil.rmtree(copy, ignore_errors=True)


@unittest.skipUnless(HAS_PYTEST, "pytest not installed")
class RepoVerifierEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="evo_test_repo_")
        make_repo(self.root)
        self.problem = {"name": "fix_mathx", "repo_path": self.root}
        self.v = RepoVerifier(timeout=60)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_full_fix_passes(self) -> None:
        r = self.v.verify(block("mathx.py", FIXED_MATHX), self.problem)
        self.assertTrue(r.passed)
        self.assertEqual(r.score, 1.0)
        self.assertEqual(r.artifact["tests_passed"], r.artifact["tests_total"])

    def test_partial_fix_scores_between(self) -> None:
        r = self.v.verify(block("mathx.py", HALF_FIXED_MATHX), self.problem)
        self.assertFalse(r.passed)
        self.assertGreater(r.score, 0.25)
        self.assertLess(r.score, 1.0)
        self.assertEqual(r.artifact["tests_passed"], 2)

    def test_gradient_orders_candidates(self) -> None:
        full = self.v.verify(block("mathx.py", FIXED_MATHX), self.problem).score
        half = self.v.verify(block("mathx.py", HALF_FIXED_MATHX), self.problem).score
        broken = self.v.verify(block("mathx.py", "syntax error ((("), self.problem).score
        none = self.v.verify("no blocks here", self.problem).score
        self.assertGreater(full, half)
        self.assertGreater(half, broken)
        self.assertGreater(broken, none)

    def test_source_repo_never_modified(self) -> None:
        before = open(os.path.join(self.root, "mathx.py"), encoding="utf-8").read()
        self.v.verify(block("mathx.py", FIXED_MATHX), self.problem)
        after = open(os.path.join(self.root, "mathx.py"), encoding="utf-8").read()
        self.assertEqual(before, after)

    def test_cannot_edit_the_judge(self) -> None:
        cheat = block("tests/test_mathx.py", "def test_nothing(): pass")
        r = self.v.verify(cheat, self.problem)
        self.assertFalse(r.passed)
        self.assertEqual(r.score, 0.05)
        self.assertIn("forbidden", r.diagnostics)

    def test_path_escape_rejected(self) -> None:
        r = self.v.verify(block("../outside.py", "x = 1"), self.problem)
        self.assertFalse(r.passed)
        self.assertEqual(r.score, 0.05)

    def test_new_file_can_be_created(self) -> None:
        hyp = block("mathx.py", FIXED_MATHX) + "\n" + block("helpers/extra.py", "Y = 2")
        r = self.v.verify(hyp, self.problem)
        self.assertTrue(r.passed)
        self.assertIn("helpers/extra.py", r.artifact["files_changed"])

    def test_collection_error_scores_low_but_above_rejection(self) -> None:
        r = self.v.verify(block("mathx.py", "raise RuntimeError('boom')"), self.problem)
        self.assertFalse(r.passed)
        self.assertLessEqual(r.score, 0.10)
        self.assertGreater(r.score, 0.05)

    def test_missing_repo_path_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.v.verify(block("a.py", "x"), {"name": "x", "repo_path": "/nonexistent_xyz"})

    def _full_fix_patches(self) -> str:
        return (
            patch_block(
                "mathx.py",
                "return sum(nums) / (len(nums) + 1)",
                "return sum(nums) / len(nums)",
            )
            + "\n"
            + patch_block("mathx.py", "return min(x, hi)", "return max(lo, min(x, hi))")
        )

    def test_patch_fix_passes(self) -> None:
        r = self.v.verify(self._full_fix_patches(), self.problem)
        self.assertTrue(r.passed)
        self.assertEqual(r.score, 1.0)
        self.assertIn("mathx.py", r.artifact["files_changed"])

    def test_mixed_file_and_patch_blocks(self) -> None:
        hyp = self._full_fix_patches() + "\n" + block("helpers/extra.py", "Y = 2")
        r = self.v.verify(hyp, self.problem)
        self.assertTrue(r.passed)
        self.assertIn("helpers/extra.py", r.artifact["files_changed"])
        self.assertIn("mathx.py", r.artifact["files_changed"])

    def test_patch_keeps_source_repo_unmodified(self) -> None:
        before = open(os.path.join(self.root, "mathx.py"), encoding="utf-8").read()
        self.v.verify(self._full_fix_patches(), self.problem)
        after = open(os.path.join(self.root, "mathx.py"), encoding="utf-8").read()
        self.assertEqual(before, after)

    def test_patch_cannot_edit_the_judge(self) -> None:
        cheat = patch_block("tests/test_mathx.py", "assert average([2, 4]) == 3", "assert True")
        r = self.v.verify(cheat, self.problem)
        self.assertFalse(r.passed)
        self.assertEqual(r.score, 0.05)
        self.assertIn("forbidden", r.diagnostics)

    def test_patch_no_match_yields_diagnostic(self) -> None:
        r = self.v.verify(patch_block("mathx.py", "anchor not present", "x"), self.problem)
        self.assertFalse(r.passed)
        self.assertEqual(r.score, 0.08)
        self.assertIn("NoMatchError", r.diagnostics)

    def test_patch_ambiguous_anchor_yields_diagnostic(self) -> None:
        r = self.v.verify(patch_block("mathx.py", "    return", "    return  # x"), self.problem)
        self.assertFalse(r.passed)
        self.assertEqual(r.score, 0.08)
        self.assertIn("AmbiguousMatchError", r.diagnostics)

    def test_patch_missing_target_yields_diagnostic(self) -> None:
        r = self.v.verify(patch_block("nope.py", "x", "y"), self.problem)
        self.assertFalse(r.passed)
        self.assertEqual(r.score, 0.08)
        self.assertIn("not found", r.diagnostics)

    def test_lenient_format_is_recovered_end_to_end(self) -> None:
        hyp = (
            "Here is the fix:\n"
            "<PATCH>\n<SEARCH>def average(nums):\n"
            "    return sum(nums) / (len(nums) + 1)</SEARCH>\n"
            "<REPLACE>def average(nums):\n    return sum(nums) / len(nums)</REPLACE>\n"
            "</PATCH>\n"
            "<PATCH>\n<SEARCH>    return min(x, hi)</SEARCH>\n"
            "<REPLACE>    return max(lo, min(x, hi))</REPLACE>\n</PATCH>\n"
        )
        r = self.v.verify(hyp, {**self.problem, "target_files": ["mathx.py"]})
        self.assertTrue(r.passed)
        self.assertEqual(r.score, 1.0)
        self.assertIn("mathx.py", r.artifact["files_changed"])

    def test_unparseable_output_still_scores_floor(self) -> None:
        r = self.v.verify("just some prose, no edits", self.problem)
        self.assertFalse(r.passed)
        self.assertEqual(r.score, 0.02)

    def test_setup_command_runs_before_suite(self) -> None:
        """setup_command should execute inside the copy before test_command.

        This is a pure-filesystem smoke test: setup_command writes a marker file
        that test_command (a custom pytest) reads. If setup ran, the test passes;
        if not, the test errors out.
        """
        # Create a repo whose test requires a file written by a setup step.
        root = tempfile.mkdtemp(prefix="evo_setup_repo_")
        try:
            # The source is fine; the test checks that setup wrote a marker.
            with open(os.path.join(root, "app.py"), "w", encoding="utf-8") as f:
                f.write("x = 1\n")
            with open(os.path.join(root, "test_setup.py"), "w", encoding="utf-8") as f:
                f.write(
                    "import os\n\n"
                    "def test_setup_ran():\n"
                    "    assert os.path.exists('setup_ran.marker'), "
                    "'setup_command did not run'\n"
                )
            v = RepoVerifier(
                timeout=30,
                setup_command=[sys.executable, "-c",
                               "open('setup_ran.marker', 'w').close()"],
                setup_output_globs=("setup_ran.marker",),
            )
            r = v.verify(block("app.py", "x = 1\n"), {"repo_path": root})
            self.assertTrue(r.passed, f"expected PASS, got: {r.diagnostics}")
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_setup_command_stdout_does_not_affect_verdict(self) -> None:
        """A forged pass summary printed by setup must not influence the verdict.

        The verdict comes from the judge-owned JUnit report + the test command's
        exit code, never from setup's stdout — so setup printing
        '=== 9999 passed ===' cannot inflate the real test counts.
        """
        root = tempfile.mkdtemp(prefix="evo_setup_stdout_")
        try:
            with open(os.path.join(root, "app.py"), "w", encoding="utf-8") as f:
                f.write("x = 1\n")
            with open(os.path.join(root, "test_app.py"), "w", encoding="utf-8") as f:
                f.write("from app import x\n\n\ndef test_x():\n    assert x == 1\n")
            v = RepoVerifier(
                timeout=30,
                setup_command=[
                    sys.executable, "-c",
                    "print('=========== 9999 passed in 0.01s ===========')",
                ],
            )
            r = v.verify(block("app.py", "x = 1\n"), {"repo_path": root})
            self.assertTrue(r.passed, f"expected PASS, got: {r.diagnostics}")
            # Real count from the JUnit report — not the forged 9999 from setup stdout.
            self.assertEqual(r.artifact["tests_total"], 1)
            self.assertEqual(r.artifact["tests_passed"], 1)
            self.assertEqual(r.artifact["verdict_source"], "junit+exit")
        finally:
            shutil.rmtree(root, ignore_errors=True)


class JUnitDirOracleTests(unittest.TestCase):
    """Directory-of-reports merge (Maven Surefire writes one file per class)."""

    def _dir(self) -> str:
        return tempfile.mkdtemp(prefix="evo_junitdir_")

    def test_merges_counts_across_files(self) -> None:
        d = self._dir()
        try:
            with open(os.path.join(d, "TEST-A.xml"), "w", encoding="utf-8") as f:
                f.write('<testsuite tests="3" failures="0" errors="0" skipped="0"/>')
            with open(os.path.join(d, "TEST-B.xml"), "w", encoding="utf-8") as f:
                f.write('<testsuite tests="2" failures="1" errors="0" skipped="0"/>')
            j = parse_junit_dir(d)
            assert j is not None
            self.assertEqual((j.passed, j.total, j.failures, j.errors), (4, 5, 1, 0))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_missing_dir_yields_none(self) -> None:
        self.assertIsNone(parse_junit_dir("/no/such/dir"))

    def test_empty_or_non_report_dir_yields_none(self) -> None:
        d = self._dir()
        try:
            with open(os.path.join(d, "notes.txt"), "w", encoding="utf-8") as f:
                f.write("not a report")
            self.assertIsNone(parse_junit_dir(d))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_hostile_dtd_file_is_skipped_not_counted(self) -> None:
        # The per-file hardening (DTD/ENTITY refusal) still applies in the dir merge.
        d = self._dir()
        try:
            with open(os.path.join(d, "TEST-evil.xml"), "w", encoding="utf-8") as f:
                f.write('<!DOCTYPE x [<!ENTITY a "boom">]>\n<testsuite tests="9"/>')
            with open(os.path.join(d, "TEST-ok.xml"), "w", encoding="utf-8") as f:
                f.write('<testsuite tests="2" failures="0" errors="0" skipped="0"/>')
            j = parse_junit_dir(d)
            assert j is not None
            # only the clean file is counted; the DTD file is refused
            self.assertEqual((j.passed, j.total), (2, 2))
        finally:
            shutil.rmtree(d, ignore_errors=True)


class JUnitOracleTests(unittest.TestCase):
    def test_counts_come_from_structured_xml(self) -> None:
        j = parse_junit_xml(
            '<testsuites><testsuite tests="5" failures="1" errors="1" skipped="1"/></testsuites>'
        )
        assert j is not None
        self.assertEqual((j.passed, j.total, j.failures, j.errors), (2, 4, 1, 1))

    def test_a_forged_stdout_summary_yields_no_counts(self) -> None:
        self.assertIsNone(parse_junit_xml("\n====== 9999 passed in 0.01s ======\n"))
        self.assertIsNone(parse_junit_xml(""))
        self.assertIsNone(parse_junit_xml("<not-valid-xml"))

    def test_full_pass_requires_exit0_and_a_clean_report(self) -> None:
        j = parse_junit_xml('<testsuite tests="3" failures="0" errors="0" skipped="0"/>')
        self.assertEqual(grade_repo_run(0, j, report_expected=True), (True, 1.0, 3, 3))

    def test_partial_score_uses_the_report_fraction(self) -> None:
        j = parse_junit_xml('<testsuite tests="3" failures="1" errors="0" skipped="0"/>')
        passed, score, p, t = grade_repo_run(1, j, report_expected=True)
        self.assertFalse(passed)
        self.assertEqual((p, t), (2, 3))
        self.assertAlmostEqual(score, fraction_score(2, 3))

    def test_exit0_with_a_failing_report_is_rejected_as_tamper(self) -> None:
        j = parse_junit_xml('<testsuite tests="3" failures="2" errors="0" skipped="0"/>')
        self.assertEqual(grade_repo_run(0, j, report_expected=True), (False, 0.10, 1, 3))

    def test_allpass_report_with_nonzero_exit_is_rejected_as_tamper(self) -> None:
        j = parse_junit_xml('<testsuite tests="3" failures="0" errors="0" skipped="0"/>')
        passed, score, _, _ = grade_repo_run(1, j, report_expected=True)
        self.assertFalse(passed)
        self.assertEqual(score, 0.10)

    def test_pytest_without_a_report_is_no_verdict(self) -> None:
        self.assertEqual(grade_repo_run(0, None, report_expected=True), (False, 0.10, 0, 0))

    def test_custom_runner_falls_back_to_exit_code(self) -> None:
        self.assertEqual(grade_repo_run(0, None, report_expected=False), (True, 1.0, 0, 0))
        self.assertFalse(grade_repo_run(1, None, report_expected=False)[0])
        self.assertEqual(grade_repo_run(2, None, report_expected=False), (False, 0.10, 0, 0))


_STDOUT_FORGERY = (
    "\n\nimport os as _os\n"
    "for _fd in (1, 2):\n"
    "    try:\n"
    "        _os.write(_fd, b'\\n=========== 9999 passed in 0.01s ===========\\n')\n"
    "    except OSError:\n"
    "        pass\n"
)


class JudgeOracleRedTeamTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="evo_redteam_repo_")
        make_repo(self.root)
        self.problem = {"name": "redteam", "repo_path": self.root}
        self.v = RepoVerifier(timeout=60)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_autoexec_and_runner_files_are_rejected_at_the_gate(self) -> None:
        for path in (
            "sitecustomize.py", "usercustomize.py", "evil.pth", "pkg/sub/x.pth",
            "Makefile", "GNUmakefile", "noxfile.py",
        ):
            r = self.v.verify(block(path, "import os; os._exit(0)"), self.problem)
            self.assertFalse(r.passed, path)
            self.assertEqual(r.score, 0.05, path)
        self.assertTrue(is_judge_autoexec("SiteCustomize.PY"))
        self.assertTrue(is_judge_autoexec("a/b/plugin.pth"))
        self.assertFalse(is_judge_autoexec("customize.py"))
        self.assertFalse(is_judge_autoexec("path.py"))

    @unittest.skipUnless(HAS_PYTEST, "needs pytest to run the suite")
    def test_stdout_injection_cannot_inflate_the_partial_score(self) -> None:
        candidate = block("mathx.py", HALF_FIXED_MATHX + _STDOUT_FORGERY)
        r = self.v.verify(candidate, self.problem)
        self.assertFalse(r.passed)
        self.assertEqual((r.artifact["tests_passed"], r.artifact["tests_total"]), (2, 3))
        self.assertAlmostEqual(r.score, fraction_score(2, 3))
        self.assertLess(r.score, 0.9)
        self.assertEqual(r.artifact["verdict_source"], "junit+exit")

    @unittest.skipUnless(HAS_PYTEST, "needs pytest to run the suite")
    def test_stdout_injection_cannot_forge_a_full_pass(self) -> None:
        candidate = block("mathx.py", BUGGY_MATHX + _STDOUT_FORGERY)
        r = self.v.verify(candidate, self.problem)
        self.assertFalse(r.passed)
        self.assertLess(r.score, 1.0)
        self.assertEqual(r.artifact["tests_passed"], 1)

    @unittest.skipUnless(HAS_PYTEST, "needs pytest to run the suite")
    def test_candidate_cannot_plant_a_fake_junit_report(self) -> None:
        fake = (
            '<?xml version="1.0"?><testsuites><testsuite name="x" '
            'tests="3" failures="0" errors="0" skipped="0"/></testsuites>'
        )
        hyp = block("mathx.py", BUGGY_MATHX) + "\n" + block("judge-result.xml", fake)
        r = self.v.verify(hyp, self.problem)
        self.assertFalse(r.passed)
        self.assertLess(r.score, 1.0)
        self.assertEqual(r.artifact["tests_passed"], 1)

    @unittest.skipUnless(HAS_PYTEST, "needs pytest to run the suite")
    def test_an_honest_full_fix_still_passes(self) -> None:
        r = self.v.verify(block("mathx.py", FIXED_MATHX), self.problem)
        self.assertTrue(r.passed)
        self.assertEqual(r.score, 1.0)
        self.assertEqual(r.artifact["verdict_source"], "junit+exit")


if __name__ == "__main__":
    unittest.main()
