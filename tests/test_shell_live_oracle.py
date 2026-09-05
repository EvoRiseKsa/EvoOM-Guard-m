"""Exact Bash wrapping Node 22 test runner live evidence."""

from __future__ import annotations

from pathlib import Path

from tests.live_runner_extended_helpers import (
    FAIL,
    PASS,
    assert_guard_counts,
    candidate,
    live_extended_mark,
    require_env,
    require_executable,
    run_guard,
    write_text,
)

pytestmark = live_extended_mark()


def _repo(root: Path) -> None:
    root.mkdir()
    write_text(root / "calc.mjs", "export const twice = (value) => value * 2 + 1;\n")
    write_text(
        root / "test" / "calc.test.mjs",
        "import assert from 'node:assert/strict';\n"
        "import test from 'node:test';\n"
        "import { twice } from '../calc.mjs';\n"
        "test('doubles three', () => assert.equal(twice(3), 6));\n"
        "test('doubles five', () => assert.equal(twice(5), 10));\n",
    )


def _run(root: Path, expression: str) -> object:
    require_executable("node")
    bash = require_env("EVOGUARD_EXTENDED_BASH")
    assert Path(bash).is_file(), "the exact Bash executable is absent"
    return run_guard(
        root,
        candidate("calc.mjs", f"export const twice = (value) => {expression};\n"),
        [bash, "-c", "node --test test/calc.test.mjs"],
    )


def test_extended_shell_honest_fix_is_pass(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _repo(repo)
    assert_guard_counts(_run(repo, "value * 2"), PASS, 2, 2)


def test_extended_shell_broken_fix_is_fail(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _repo(repo)
    assert_guard_counts(_run(repo, "value * 2 + 99"), FAIL, 0, 2)
