# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""Phase 1 — native JUnit verdicting for the vitest runner.

vitest writes standard JUnit XML to a judge-owned ``--outputFile`` (so the verdict
stays off candidate-influenceable stdout), which the dialect-agnostic
``parse_junit_xml`` reads. The pure parse test always runs; the end-to-end ``guard``
run is skipped unless the ``vitest`` CLI is resolvable on PATH (it is not on the
stock CI runner, so the suite stays green there). The command-detection /
report-injection wiring is tested in ``test_adapters.py``.
"""

import os
import shutil
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard.guard import FAIL, PASS, guard
from evoom_guard.verifiers.repo_verifier import parse_junit_xml

needs_vitest = pytest.mark.skipif(
    shutil.which("vitest") is None, reason="needs the vitest CLI on PATH"
)

# The shape vitest's junit reporter emits (captured live): suite attributes *and*
# <testcase> elements with <failure> children — the case-counting path reads it.
VITEST_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<testsuites name="vitest tests" tests="2" failures="1" errors="0">\n'
    '  <testsuite name="impl.test.mjs" tests="2" failures="1" errors="0" skipped="0">\n'
    '    <testcase classname="impl.test.mjs" name="dbl doubles"/>\n'
    '    <testcase classname="impl.test.mjs" name="dbl of 5">\n'
    '      <failure message="expected 11 to be 10" type="AssertionError"></failure>\n'
    "    </testcase>\n  </testsuite>\n</testsuites>\n"
)


def test_parse_vitest_junit_counts():
    j = parse_junit_xml(VITEST_XML)
    assert j is not None
    assert (j.passed, j.total, j.failures, j.errors) == (1, 2, 1, 0)


# ───────────────────────────── integration (vitest) ─────────────────────────
def _vitest_repo(root):
    (root / "impl.mjs").write_text("export const dbl = (x) => x + x + 1;\n", encoding="utf-8")  # bug
    (root / "impl.test.mjs").write_text(
        "import { test, expect } from 'vitest';\n"
        "import { dbl } from './impl.mjs';\n"
        "test('dbl doubles', () => expect(dbl(3)).toBe(6));\n"
        "test('dbl of 5', () => expect(dbl(5)).toBe(10));\n",
        encoding="utf-8",
    )


@needs_vitest
def test_vitest_honest_fix_is_pass_with_junit_source(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _vitest_repo(repo)
    cand = "<<<FILE: impl.mjs>>>\nexport const dbl = (x) => x + x;\n<<<END FILE>>>"
    res = guard(str(repo), cand, test_command=["vitest", "run"], mem_limit_mb=0)
    assert res.verdict == PASS
    assert res.verdict_source == "junit+exit"        # was "exit" (custom runner) before
    assert (res.tests_passed, res.tests_total) == (2, 2)


@needs_vitest
def test_vitest_broken_fix_is_fail_with_real_counts(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _vitest_repo(repo)
    cand = "<<<FILE: impl.mjs>>>\nexport const dbl = (x) => x + x + 99;\n<<<END FILE>>>"  # still wrong
    res = guard(str(repo), cand, test_command=["vitest", "run"], mem_limit_mb=0)
    assert res.verdict == FAIL
    assert res.verdict_source == "junit+exit"
    assert (res.tests_passed, res.tests_total) == (0, 2)
