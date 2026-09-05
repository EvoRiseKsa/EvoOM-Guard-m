"""Real Go 1.27.1 and gotestsum 1.13.0 live-runner evidence."""

from __future__ import annotations

from pathlib import Path

from evoom_guard.verifiers.repo_verifier import parse_junit_xml
from tests.live_runner_extended_helpers import (
    FAIL,
    PASS,
    assert_guard_counts,
    candidate,
    live_extended_mark,
    require_executable,
    run_guard,
    write_text,
)

pytestmark = live_extended_mark()

GOTESTSUM_XML = """<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="2" failures="1" errors="0">
  <testsuite name="example.com/live" tests="2" failures="1" errors="0">
    <testcase classname="live" name="TestTwiceThree" />
    <testcase classname="live" name="TestTwiceFive"><failure>mismatch</failure></testcase>
  </testsuite>
</testsuites>
"""


def _repo(root: Path) -> None:
    root.mkdir()
    write_text(root / "go.mod", "module example.com/evoguard-live\n\ngo 1.27.1\n")
    write_text(root / "calc.go", "package live\n\nfunc Twice(v int) int { return v*2 + 1 }\n")
    write_text(
        root / "calc_test.go",
        "package live\n\nimport \"testing\"\n\n"
        "func TestTwiceThree(t *testing.T) { if Twice(3) != 6 { t.Fail() } }\n"
        "func TestTwiceFive(t *testing.T) { if Twice(5) != 10 { t.Fail() } }\n",
    )


def _run(
    root: Path,
    expression: str,
    *,
    baseline_evidence: bool = False,
) -> object:
    require_executable("go")
    require_executable("gotestsum")
    return run_guard(
        root,
        candidate("calc.go", f"package live\n\nfunc Twice(v int) int {{ return {expression} }}\n"),
        ["gotestsum", "--", "./..."],
        baseline_evidence=baseline_evidence,
    )


def test_extended_parse_gotestsum_junit_counts() -> None:
    parsed = parse_junit_xml(GOTESTSUM_XML)
    assert parsed is not None
    assert (parsed.passed, parsed.total, parsed.failures, parsed.errors) == (1, 2, 1, 0)


def test_extended_gotestsum_honest_fix_is_pass(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _repo(repo)
    assert_guard_counts(_run(repo, "v*2"), PASS, 2, 2)


def test_extended_gotestsum_broken_fix_is_fail(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _repo(repo)
    assert_guard_counts(_run(repo, "v*2 + 99"), FAIL, 0, 2)


def test_extended_gotestsum_green_baseline_remains_green_with_private_cache(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    _repo(repo)
    write_text(
        repo / "calc.go",
        "package live\n\nfunc Twice(v int) int { return v*2 }\n",
    )

    result = _run(repo, "2*v", baseline_evidence=True)

    assert_guard_counts(result, PASS, 2, 2)
    assert result.baseline is not None
    assert result.baseline["verdict"] == "PASS"
    assert result.baseline["repair_effect"] == "not_demonstrated"
