# -----------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Judge-owned JUnit parsing, grading, and report-integrity checks."""

from __future__ import annotations

import os
import re
import stat
import xml.etree.ElementTree as ET
from typing import NamedTuple

from evoom_guard.verifiers.grading import fraction_score

# pytest's summary line, e.g. "2 failed, 3 passed in 0.12s" / "1 error in 0.05s".
_PASSED_RE = re.compile(r"(\d+) passed")
_FAILED_RE = re.compile(r"(\d+) failed")
_ERROR_RE = re.compile(r"(\d+) errors?")


def parse_pytest_counts(output: str) -> tuple[int, int]:
    """Read ``(passed, total)`` from a pytest/vitest run's *human* output.

    NOTE — this scrapes the runner's stdout/stderr and is therefore **forgeable**.
    Retained only to enrich diagnostic text; never used for the verdict.
    """
    lines = [ln for ln in (output or "").splitlines() if "Test Files" not in ln]
    text = "\n".join(lines)
    passed = sum(int(n) for n in _PASSED_RE.findall(text))
    failed = sum(int(n) for n in _FAILED_RE.findall(text))
    errors = sum(int(n) for n in _ERROR_RE.findall(text))
    return passed, passed + failed + errors


class JUnitCounts(NamedTuple):
    """Authoritative test counts read from a pytest JUnit-XML report."""

    passed: int
    total: int
    failures: int
    errors: int


def _count_testcases(root: ET.Element) -> JUnitCounts | None:
    """Count ``<testcase>`` elements directly — the unit every dialect emits."""
    cases = list(root.iter("testcase"))
    if not cases:
        return None
    failures = errors = skipped = 0
    for tc in cases:
        if tc.find("skipped") is not None:
            skipped += 1
        elif tc.find("error") is not None:
            errors += 1
        elif tc.find("failure") is not None:
            failures += 1
    total = len(cases)
    effective_total = max(0, total - skipped)
    passed = max(0, effective_total - failures - errors)
    return JUnitCounts(
        passed=passed,
        total=effective_total,
        failures=failures,
        errors=errors,
    )


# A JUnit report is small (a few KB even for thousands of cases); anything much
# larger is pathological. Cap the input so a runaway/hostile report cannot exhaust
# memory or parse time.
_MAX_REPORT_CHARS = 8 * 1024 * 1024


def parse_junit_xml(xml_text: str) -> JUnitCounts | None:
    """Read authoritative test counts from a JUnit-XML report.

    **Hardened** against a hostile report — the candidate's *test process* can write
    to the report path, so this input is only semi-trusted. The input is
    **size-capped**, and any **DTD / ``DOCTYPE`` / ``ENTITY`` is refused**, which
    eliminates entity-expansion ("billion laughs") and external-entity vectors
    regardless of the host's ``expat`` version. A rejected report yields no counts —
    the run then grades as "no clean verdict" (``FAIL``) — never a parser hang.
    """
    if not xml_text or not xml_text.strip():
        return None
    if len(xml_text) > _MAX_REPORT_CHARS:
        return None
    # A JUnit report never legitimately needs a DTD; refuse it before expat parses.
    if "<!DOCTYPE" in xml_text or "<!ENTITY" in xml_text:
        return None
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    by_case = _count_testcases(root)
    if by_case is not None:
        return by_case
    total = failures = errors = skipped = 0
    seen = False
    for suite in root.iter("testsuite"):
        seen = True
        try:
            total += int(suite.get("tests", 0))
            failures += int(suite.get("failures", 0))
            errors += int(suite.get("errors", 0))
            skipped += int(suite.get("skipped", 0))
        except (TypeError, ValueError):  # pragma: no cover - defensive
            return None
    if not seen:
        return None
    effective_total = max(0, total - skipped)
    passed = max(0, effective_total - failures - errors)
    return JUnitCounts(
        passed=passed,
        total=effective_total,
        failures=failures,
        errors=errors,
    )


def _read_text_or_none(path: str) -> str | None:
    """Read UTF-8 text, returning ``None`` if it cannot be read."""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


def parse_junit_dir(dirpath: str) -> JUnitCounts | None:
    """Merge every ``*.xml`` JUnit report in a directory into one count.

    For runners (Maven Surefire, …) that emit **one report file per test class**
    into a judge-owned *directory* rather than a single file. Each file is read
    through the hardened :func:`parse_junit_xml` (size-cap + DTD/``ENTITY`` refusal),
    and the per-file counts are summed. The directory is one report set: if any
    ``*.xml`` entry is a symlink/special file, unreadable, or invalid, the entire
    set is rejected instead of silently dropping evidence. Returns ``None`` when
    the directory is absent, has no XML reports, or is invalid, so the run grades
    as "no clean verdict" rather than a partial false pass.
    """
    if not dirpath or not os.path.isdir(dirpath):
        return None
    passed = total = failures = errors = 0
    seen = False
    try:
        entries = sorted(os.listdir(dirpath))
    except OSError:
        return None
    for fn in entries:
        if not fn.lower().endswith(".xml"):
            continue
        path = os.path.join(dirpath, fn)
        try:
            mode = os.lstat(path).st_mode
        except OSError:
            return None
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            return None
        text = _read_text_or_none(path)
        if text is None:
            return None
        counts = parse_junit_xml(text)
        if counts is None:
            return None
        seen = True
        passed += counts.passed
        total += counts.total
        failures += counts.failures
        errors += counts.errors
    if not seen:
        return None
    return JUnitCounts(
        passed=passed,
        total=total,
        failures=failures,
        errors=errors,
    )


def grade_repo_run(
    returncode: int, junit: JUnitCounts | None, *, report_expected: bool
) -> tuple[bool, float, int, int]:
    """Turn a finished run into ``(passed, score, tests_passed, tests_total)``."""
    if junit is not None:
        if returncode == 0 and junit.total > 0 and junit.failures == 0 and junit.errors == 0:
            return True, 1.0, junit.passed, junit.total
        if returncode == 1 and junit.total > 0 and (junit.failures > 0 or junit.errors > 0):
            return (
                False,
                fraction_score(junit.passed, junit.total),
                junit.passed,
                junit.total,
            )
        return False, 0.10, junit.passed, junit.total
    if report_expected:
        return False, 0.10, 0, 0
    if returncode == 0:
        return True, 1.0, 0, 0
    if returncode == 1:
        return False, 0.25, 0, 0
    return False, 0.10, 0, 0


def detect_tamper(
    returncode: int, junit: JUnitCounts | None, *, report_expected: bool
) -> bool:
    """Is the exit code inconsistent with its judge-owned JUnit report?"""
    if junit is None:
        return False
    all_pass = junit.total > 0 and junit.failures == 0 and junit.errors == 0
    has_failures = junit.failures > 0 or junit.errors > 0
    if all_pass and returncode != 0:
        return True
    if has_failures and returncode == 0:
        return True
    return False


__all__ = [
    "JUnitCounts",
    "detect_tamper",
    "grade_repo_run",
    "parse_junit_dir",
    "parse_junit_xml",
    "parse_pytest_counts",
]
