"""Real Ruby 3.4.10, RSpec 3.13.2, and JUnit formatter evidence."""

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

RSPEC_XML = """<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="rspec" tests="2" failures="1" errors="0">
  <testcase classname="Calc" name="doubles three" />
  <testcase classname="Calc" name="doubles five"><failure>mismatch</failure></testcase>
</testsuite>
"""


def _repo(root: Path) -> None:
    root.mkdir()
    shutil.copy2(TOOLS / "ruby" / "Gemfile", root / "Gemfile")
    shutil.copy2(TOOLS / "ruby" / "Gemfile.lock", root / "Gemfile.lock")
    bundle_path = require_env("EVOGUARD_EXTENDED_BUNDLE_PATH").replace("\\", "/")
    write_text(root / ".bundle" / "config", f"---\nBUNDLE_PATH: \"{bundle_path}\"\nBUNDLE_FROZEN: \"true\"\n")
    write_text(root / "calc.rb", "def twice(value) = value * 2 + 1\n")
    write_text(
        root / "spec" / "calc_spec.rb",
        "require_relative '../calc'\n\n"
        "RSpec.describe 'twice' do\n"
        "  it('doubles three') { expect(twice(3)).to eq(6) }\n"
        "  it('doubles five') { expect(twice(5)).to eq(10) }\n"
        "end\n",
    )


def _run(root: Path, expression: str) -> object:
    require_executable("bundle")
    return run_guard(
        root,
        candidate("calc.rb", f"def twice(value) = {expression}\n"),
        ["bundle", "exec", "rspec"],
    )


def test_extended_parse_rspec_junit_counts() -> None:
    parsed = parse_junit_xml(RSPEC_XML)
    assert parsed is not None
    assert (parsed.passed, parsed.total, parsed.failures, parsed.errors) == (1, 2, 1, 0)


def test_extended_rspec_honest_fix_is_pass(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _repo(repo)
    assert_guard_counts(_run(repo, "value * 2"), PASS, 2, 2)


def test_extended_rspec_broken_fix_is_fail(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _repo(repo)
    assert_guard_counts(_run(repo, "value * 2 + 99"), FAIL, 0, 2)
