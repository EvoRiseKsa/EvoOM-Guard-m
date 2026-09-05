"""Real Java 21 and Maven 3.9.16 Surefire live-runner evidence."""

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

MAVEN_XML = """<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="CalcTest" tests="2" failures="1" errors="0">
  <testcase classname="CalcTest" name="doublesThree" />
  <testcase classname="CalcTest" name="doublesFive"><failure>mismatch</failure></testcase>
</testsuite>
"""

SOURCE = "src/main/java/io/github/evoriseksa/Calc.java"


def _repo(root: Path) -> None:
    root.mkdir()
    shutil.copy2(TOOLS / "maven" / "pom.xml", root / "pom.xml")
    write_text(
        root / SOURCE,
        "package io.github.evoriseksa;\n\n"
        "public final class Calc {\n"
        "    private Calc() {}\n"
        "    public static int twice(int value) { return value * 2 + 1; }\n"
        "}\n",
    )
    test_target = root / "src" / "test" / "java" / "io" / "github" / "evoriseksa" / "CalcTest.java"
    test_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(
        TOOLS / "maven" / "src" / "test" / "java" / "io" / "github" / "evoriseksa" / "CalcTest.java",
        test_target,
    )


def _run(root: Path, expression: str) -> object:
    require_executable("mvn")
    repository = require_env("EVOGUARD_EXTENDED_MAVEN_REPO")
    body = (
        "package io.github.evoriseksa;\n\n"
        "public final class Calc {\n"
        "    private Calc() {}\n"
        f"    public static int twice(int value) {{ return {expression}; }}\n"
        "}\n"
    )
    return run_guard(
        root,
        candidate(SOURCE, body),
        ["mvn", "-q", "-o", f"-Dmaven.repo.local={repository}", "test"],
    )


def test_extended_parse_maven_junit_counts() -> None:
    parsed = parse_junit_xml(MAVEN_XML)
    assert parsed is not None
    assert (parsed.passed, parsed.total, parsed.failures, parsed.errors) == (1, 2, 1, 0)


def test_extended_maven_honest_fix_is_pass(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _repo(repo)
    assert_guard_counts(_run(repo, "value * 2"), PASS, 2, 2)


def test_extended_maven_broken_fix_is_fail(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _repo(repo)
    assert_guard_counts(_run(repo, "value * 2 + 99"), FAIL, 0, 2)
