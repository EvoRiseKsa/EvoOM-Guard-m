# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Live structured-verdict oracle for the pytest adapter."""

from __future__ import annotations

import sys
from pathlib import Path

from evoom_guard.guard import FAIL, PASS, REJECTED, guard


def _pytest_repo(root: Path) -> None:
    (root / "impl.py").write_text(
        "def dbl(value: int) -> int:\n    return value + value + 1\n",
        encoding="utf-8",
    )
    tests = root / "tests"
    tests.mkdir()
    (tests / "test_impl.py").write_text(
        "from impl import dbl\n\n"
        "def test_dbl() -> None:\n"
        "    assert dbl(3) == 6\n",
        encoding="utf-8",
    )


def _pytest_command() -> list[str]:
    return [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
    ]


def test_pytest_honest_fix_is_pass_with_junit_source(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _pytest_repo(repo)
    candidate = (
        "<<<FILE: impl.py>>>\n"
        "def dbl(value: int) -> int:\n"
        "    return value + value\n"
        "<<<END FILE>>>"
    )

    result = guard(
        str(repo),
        candidate,
        test_command=_pytest_command(),
        mem_limit_mb=0,
    )

    assert result.verdict == PASS
    assert result.verdict_source == "junit+exit"
    assert (result.tests_passed, result.tests_total) == (1, 1)


def test_pytest_broken_fix_is_fail_with_real_counts(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _pytest_repo(repo)
    candidate = (
        "<<<FILE: impl.py>>>\n"
        "def dbl(value: int) -> int:\n"
        "    return value + value + 99\n"
        "<<<END FILE>>>"
    )

    result = guard(
        str(repo),
        candidate,
        test_command=_pytest_command(),
        mem_limit_mb=0,
    )

    assert result.verdict == FAIL
    assert result.verdict_source == "junit+exit"
    assert (result.tests_passed, result.tests_total) == (0, 1)


def test_pytest_protected_test_rewrite_is_rejected_before_execution(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _pytest_repo(repo)
    candidate = (
        "<<<FILE: tests/test_impl.py>>>\n"
        "def test_noop() -> None:\n"
        "    assert True\n"
        "<<<END FILE>>>"
    )

    result = guard(
        str(repo),
        candidate,
        test_command=_pytest_command(),
        mem_limit_mb=0,
    )

    assert result.verdict == REJECTED
    assert result.test_command_ran is False
