# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Judge-owned JUnit parsing, grading, and report-integrity checks."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import struct
import xml.etree.ElementTree as ET

from evoom_guard.domain.verification import JUnitCounts
from evoom_guard.verifiers.grading import fraction_score

# pytest's summary line, e.g. "2 failed, 3 passed in 0.12s" / "1 error in 0.05s".
_PASSED_RE = re.compile(r"(\d+) passed")
_FAILED_RE = re.compile(r"(\d+) failed")
_ERROR_RE = re.compile(r"(\d+) errors?")

_JUNIT_COUNTERS = ("tests", "failures", "errors", "skipped")
_TERMINAL_CASE_STATES = frozenset(("failure", "error", "skipped"))
_MAX_JUNIT_COUNTER = 10**12
_MAX_JUNIT_COUNTER_DIGITS = len(str(_MAX_JUNIT_COUNTER))
_MAX_JUNIT_NESTING = 128


class _InvalidJUnit(ValueError):
    """Internal fail-closed signal for contradictory JUnit semantics."""


def _local_name(element: ET.Element) -> str:
    """Return an XML element's local name, independent of its namespace."""

    tag = element.tag
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1]


def _declared_counts(element: ET.Element) -> dict[str, int]:
    """Read present aggregate counters, rejecting negative/impossible values."""

    declared: dict[str, int] = {}
    for name in _JUNIT_COUNTERS:
        raw = element.get(name)
        if raw is None:
            continue
        # Bound the lexical form before ``int``. Python 3.10 has no built-in
        # integer-string digit limit, so converting an attacker-supplied
        # multi-million-digit counter would otherwise consume unbounded CPU.
        if (
            not raw
            or len(raw) > _MAX_JUNIT_COUNTER_DIGITS
            or any(char < "0" or char > "9" for char in raw)
        ):
            raise _InvalidJUnit
        value = int(raw)
        if value > _MAX_JUNIT_COUNTER:
            raise _InvalidJUnit
        declared[name] = value

    tests = declared.get("tests")
    if tests is not None:
        terminal = sum(declared.get(name, 0) for name in ("failures", "errors", "skipped"))
        if terminal > tests:
            raise _InvalidJUnit
    return declared


def _add_raw_counts(
    left: tuple[int, int, int, int],
    right: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    """Add raw ``(tests, failures, errors, skipped)`` counters."""

    tests, failures, errors, skipped = (left[index] + right[index] for index in range(4))
    return tests, failures, errors, skipped


def _testcase_counts(testcase: ET.Element) -> tuple[int, int, int, int]:
    """Return one testcase's state, rejecting mutually exclusive outcomes."""

    states = {
        _local_name(child) for child in testcase if _local_name(child) in _TERMINAL_CASE_STATES
    }
    if len(states) > 1:
        # A testcase cannot simultaneously be skipped and failed (or errored).
        # Picking the first child would let document order decide the verdict.
        raise _InvalidJUnit
    state = next(iter(states), "")
    return (
        1,
        int(state == "failure"),
        int(state == "error"),
        int(state == "skipped"),
    )


def _validate_declared_counts(
    declared: dict[str, int],
    actual: tuple[int, int, int, int],
) -> None:
    """Require supplied aggregate fields to agree with explicit child evidence.

    Pytest 9 counts successful ``unittest``/builtin subtests in a suite's
    ``tests`` attribute without emitting a separate ``testcase`` element for
    them.  Permit only that passed-only surplus when all three terminal counters
    are present and exactly match the explicit testcase evidence.  The caller
    deliberately retains ``actual`` rather than trusting the larger declaration,
    so the compatibility case cannot inflate a candidate's score.
    """

    actual_by_name = dict(zip(_JUNIT_COUNTERS, actual, strict=True))
    declared_tests = declared.get("tests")
    if declared_tests is not None and declared_tests != actual_by_name["tests"]:
        terminal_names = ("failures", "errors", "skipped")
        passed_only_surplus = (
            declared_tests > actual_by_name["tests"]
            and all(name in declared for name in terminal_names)
            and all(
                declared[name] == actual_by_name[name]
                for name in terminal_names
            )
        )
        if not passed_only_surplus:
            raise _InvalidJUnit

    if any(
        actual_by_name[name] != value
        for name, value in declared.items()
        if name != "tests"
    ):
        raise _InvalidJUnit


def _element_counts(
    element: ET.Element,
    *,
    depth: int = 0,
) -> tuple[tuple[int, int, int, int], bool]:
    """Derive counts recursively without double-counting nested suites.

    Parent aggregate counters are validation claims over their descendants, not
    extra tests to sum. A leaf ``testsuite`` without testcase elements is the one
    compatibility case where its aggregate counters are the evidence.
    """

    if depth > _MAX_JUNIT_NESTING:
        raise _InvalidJUnit

    local_name = _local_name(element)
    declared = _declared_counts(element) if local_name in {"testsuite", "testsuites"} else {}
    counts = (0, 0, 0, 0)
    seen = False

    for child in element:
        child_name = _local_name(child)
        if child_name == "testcase":
            counts = _add_raw_counts(counts, _testcase_counts(child))
            seen = True
        elif child_name in {"testsuite", "testsuites"}:
            child_counts, child_seen = _element_counts(child, depth=depth + 1)
            if child_seen:
                counts = _add_raw_counts(counts, child_counts)
                seen = True
        elif list(child):
            # Tolerate dialect-specific grouping wrappers while retaining the same
            # testcase and testsuite validation rules.
            child_counts, child_seen = _element_counts(child, depth=depth + 1)
            if child_seen:
                counts = _add_raw_counts(counts, child_counts)
                seen = True

    if seen:
        _validate_declared_counts(declared, counts)
        return counts, True

    if local_name == "testsuite":
        aggregate = tuple(declared.get(name, 0) for name in _JUNIT_COUNTERS)
        return aggregate, True  # type: ignore[return-value]

    return counts, False


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


def _count_testcases(root: ET.Element) -> JUnitCounts | None:
    """Derive namespace-aware, semantically consistent JUnit counts."""

    if _local_name(root) not in {"testsuite", "testsuites"}:
        return None
    try:
        raw, seen = _element_counts(root)
    except _InvalidJUnit:
        return None
    if not seen:
        return None
    total, failures, errors, skipped = raw
    effective_total = total - skipped
    passed = effective_total - failures - errors
    if effective_total < 0 or passed < 0:
        return None
    return JUnitCounts(
        passed=passed,
        total=effective_total,
        failures=failures,
        errors=errors,
    )


# A JUnit report is small (a few KB even for thousands of cases); anything much
# larger is pathological.  Keep the historical character-name as a compatibility
# alias, but enforce the limit *in bytes before decoding a file*.  Checking only
# after ``open(...).read()`` has already let a candidate force an unbounded host
# allocation.
_MAX_REPORT_BYTES = 8 * 1024 * 1024
_MAX_REPORT_CHARS = _MAX_REPORT_BYTES
_MAX_REPORT_SET_BYTES = 16 * 1024 * 1024
_MAX_REPORT_FILES = 2_048

JUNIT_XML_DIGEST_FORMAT = "JUNIT_XML_SHA256"
JUNIT_REPORT_SET_DIGEST_FORMAT = "EVOGUARD_JUNIT_REPORT_SET_V1"
JUNIT_COMPOSITE_DIGEST_FORMAT = "EVOGUARD_JUNIT_COMPOSITE_V2"


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
    return _count_testcases(root)


def _read_text_or_none(path: str) -> str | None:
    """Read one JUnit report without ever allocating beyond its byte cap.

    The report is candidate-influenced even though the pathname is judge-owned.
    Both the metadata check and the bounded read are required: metadata can race
    with a writer, while a bounded read alone avoids trusting stale metadata.
    """
    try:
        if os.stat(path).st_size > _MAX_REPORT_BYTES:
            return None
        with open(path, "rb") as f:
            raw = f.read(_MAX_REPORT_BYTES + 1)
    except OSError:
        return None
    if len(raw) > _MAX_REPORT_BYTES:
        return None
    return raw.decode("utf-8", errors="replace")


def read_junit_xml(path: str) -> str | None:
    """Read one bounded JUnit XML document from a judge-owned path.

    This public helper gives runners a safe alternative to ``open(...).read()``
    and deliberately shares the parser's input cap.
    """
    return _read_text_or_none(path)


def parse_junit_dir_with_digest(
    dirpath: str,
) -> tuple[JUnitCounts, str] | None:
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
    digest = hashlib.sha256()
    digest.update((JUNIT_REPORT_SET_DIGEST_FORMAT + "\0").encode("ascii"))
    report_bytes = 0
    report_files = 0
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
            entry = os.lstat(path)
        except OSError:
            return None
        if stat.S_ISLNK(entry.st_mode) or not stat.S_ISREG(entry.st_mode):
            return None
        report_files += 1
        report_bytes += entry.st_size
        if (
            report_files > _MAX_REPORT_FILES
            or entry.st_size > _MAX_REPORT_BYTES
            or report_bytes > _MAX_REPORT_SET_BYTES
        ):
            return None
        text = _read_text_or_none(path)
        if text is None:
            return None
        counts = parse_junit_xml(text)
        if counts is None:
            return None
        try:
            name_bytes = fn.encode("utf-8")
        except UnicodeEncodeError:
            # The digest contract is portable UTF-8, not an opaque host
            # filesystem byte sequence. Refuse an unrepresentable filename
            # instead of aborting the verdict process.
            return None
        text_bytes = text.encode("utf-8")
        digest.update(struct.pack(">Q", len(name_bytes)))
        digest.update(name_bytes)
        digest.update(struct.pack(">Q", len(text_bytes)))
        digest.update(text_bytes)
        seen = True
        passed += counts.passed
        total += counts.total
        failures += counts.failures
        errors += counts.errors
    if not seen:
        return None
    return (
        JUnitCounts(
            passed=passed,
            total=total,
            failures=failures,
            errors=errors,
        ),
        digest.hexdigest(),
    )


def parse_junit_dir(dirpath: str) -> JUnitCounts | None:
    """Compatibility wrapper returning only counts for a JUnit report set."""
    result = parse_junit_dir_with_digest(dirpath)
    return result[0] if result is not None else None


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
    "JUNIT_COMPOSITE_DIGEST_FORMAT",
    "JUNIT_REPORT_SET_DIGEST_FORMAT",
    "JUNIT_XML_DIGEST_FORMAT",
    "JUnitCounts",
    "detect_tamper",
    "grade_repo_run",
    "parse_junit_dir",
    "parse_junit_dir_with_digest",
    "parse_junit_xml",
    "parse_pytest_counts",
    "read_junit_xml",
]
