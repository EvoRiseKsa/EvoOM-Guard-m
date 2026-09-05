"""Real Mocha 12.0.0 built-in xUnit live-runner evidence."""

from __future__ import annotations

from pathlib import Path

from evoom_guard.verifiers.repo_verifier import parse_junit_xml
from tests.live_runner_extended_helpers import (
    FAIL,
    PASS,
    assert_guard_counts,
    candidate,
    live_extended_mark,
    require_env,
    run_guard,
    write_text,
)

pytestmark = live_extended_mark()

MOCHA_XML = """<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="Mocha Tests" tests="2" failures="1" errors="0">
  <testcase classname="calc" name="doubles three" />
  <testcase classname="calc" name="doubles five"><failure>mismatch</failure></testcase>
</testsuite>
"""


def _repo(root: Path) -> None:
    root.mkdir()
    write_text(root / "calc.cjs", "exports.twice = (value) => value * 2 + 1;\n")
    write_text(
        root / "test" / "calc.test.cjs",
        "const assert = require('node:assert/strict');\n"
        "const { twice } = require('../calc.cjs');\n"
        "describe('twice', () => {\n"
        "  it('doubles three', () => assert.equal(twice(3), 6));\n"
        "  it('doubles five', () => assert.equal(twice(5), 10));\n"
        "});\n",
    )


def _run(root: Path, expression: str) -> object:
    mocha = require_env("EVOGUARD_EXTENDED_MOCHA")
    assert Path(mocha).is_file(), "the exact Mocha executable is absent"
    return run_guard(
        root,
        candidate("calc.cjs", f"exports.twice = (value) => {expression};\n"),
        [mocha, "test/calc.test.cjs"],
    )


def test_extended_parse_mocha_junit_counts() -> None:
    parsed = parse_junit_xml(MOCHA_XML)
    assert parsed is not None
    assert (parsed.passed, parsed.total, parsed.failures, parsed.errors) == (1, 2, 1, 0)


def test_extended_mocha_honest_fix_is_pass(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _repo(repo)
    assert_guard_counts(_run(repo, "value * 2"), PASS, 2, 2)


def test_extended_mocha_broken_fix_is_fail(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _repo(repo)
    assert_guard_counts(_run(repo, "value * 2 + 99"), FAIL, 0, 2)
