"""Real Jest 30.5.1 plus jest-junit 17.0.0 live-runner evidence."""

from __future__ import annotations

import shutil
from pathlib import Path

from evoom_guard.verifiers.repo_verifier import parse_junit_xml
from tests.live_runner_extended_helpers import (
    FAIL,
    PASS,
    TOOLS,
    assert_guard_counts,
    candidate,
    live_extended_mark,
    require_env,
    require_executable,
    run_guard,
    write_text,
)

pytestmark = live_extended_mark()

JEST_XML = """<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="2" failures="1" errors="0">
  <testsuite name="calc" tests="2" failures="1" errors="0">
    <testcase classname="calc" name="doubles three" />
    <testcase classname="calc" name="doubles five"><failure>mismatch</failure></testcase>
  </testsuite>
</testsuites>
"""


def _repo(root: Path) -> None:
    root.mkdir()
    shutil.copy2(TOOLS / "node" / "package.json", root / "package.json")
    shutil.copy2(TOOLS / "node" / "package-lock.json", root / "package-lock.json")
    write_text(root / "calc.js", "module.exports.twice = (value) => value * 2 + 1;\n")
    write_text(
        root / "calc.test.js",
        "const { twice } = require('./calc');\n"
        "test('doubles three', () => expect(twice(3)).toBe(6));\n"
        "test('doubles five', () => expect(twice(5)).toBe(10));\n",
    )


def _run(root: Path, body: str) -> object:
    require_executable("npm")
    cache = require_env("EVOGUARD_EXTENDED_NPM_CACHE")
    return run_guard(
        root,
        candidate("calc.js", body),
        ["npm", "exec", "--offline", "--", "jest", "--runInBand"],
        setup_command=[
            "npm",
            "ci",
            "--ignore-scripts",
            "--offline",
            "--cache",
            cache,
        ],
        setup_output_globs=("node_modules/**",),
    )


def test_extended_parse_jest_junit_counts() -> None:
    parsed = parse_junit_xml(JEST_XML)
    assert parsed is not None
    assert (parsed.passed, parsed.total, parsed.failures, parsed.errors) == (1, 2, 1, 0)


def test_extended_jest_honest_fix_is_pass(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _repo(repo)
    result = _run(repo, "module.exports.twice = (value) => value * 2;\n")
    assert_guard_counts(result, PASS, 2, 2)


def test_extended_jest_broken_fix_is_fail(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _repo(repo)
    result = _run(repo, "module.exports.twice = (value) => value * 2 + 99;\n")
    assert_guard_counts(result, FAIL, 0, 2)


def test_extended_jest_protected_test_rewrite_is_rejected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _repo(repo)
    result = run_guard(
        repo,
        candidate(
            "calc.test.js",
            "test('replacement', () => expect(1).toBe(1));\n",
        ),
        ["npm", "exec", "--offline", "--", "jest", "--runInBand"],
    )
    assert result.verdict == "REJECTED"
    assert result.test_command_ran is False
