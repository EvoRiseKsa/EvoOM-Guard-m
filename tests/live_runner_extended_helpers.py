"""Shared fixtures for the opt-in extended live-runner matrix."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from evoom_guard.guard import FAIL, PASS, guard

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools" / "ci-live-runners"
LIVE_ENV = "EVOGUARD_LIVE_EXTENDED"


def live_extended_mark() -> pytest.MarkDecorator:
    """Skip outside the dedicated job; inside it, missing tools are failures."""

    return pytest.mark.skipif(
        os.environ.get(LIVE_ENV) != "1",
        reason="extended live-runner evidence is exercised only by its dedicated job",
    )


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    assert value, f"required extended live-runner environment value is absent: {name}"
    return value


def require_executable(name: str) -> str:
    resolved = shutil.which(name)
    assert resolved is not None, f"required extended live-runner tool is absent: {name}"
    return resolved


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def candidate(path: str, body: str) -> str:
    return f"<<<FILE: {path}>>>\n{body}<<<END FILE>>>"


def assert_guard_counts(result: object, verdict: str, passed: int, total: int) -> None:
    assert result.verdict == verdict
    assert result.verdict_source == "junit+exit"
    assert (result.tests_passed, result.tests_total) == (
        passed,
        total,
    )


def run_guard(
    repo: Path,
    patch: str,
    command: list[str],
    *,
    setup_command: list[str] | None = None,
    setup_output_globs: tuple[str, ...] = (),
    baseline_evidence: bool = False,
) -> object:
    return guard(
        str(repo),
        patch,
        test_command=command,
        setup_command=setup_command,
        trust_setup_on_host=setup_command is not None,
        setup_output_globs=setup_output_globs,
        baseline_evidence=baseline_evidence,
        timeout=300,
        mem_limit_mb=0,
    )


__all__ = [
    "FAIL",
    "PASS",
    "TOOLS",
    "assert_guard_counts",
    "candidate",
    "live_extended_mark",
    "require_env",
    "require_executable",
    "run_guard",
    "write_text",
]
