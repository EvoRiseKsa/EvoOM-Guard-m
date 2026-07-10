# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Sole owner & author: Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""Phase 1 — native JUnit verdicting for the jest runner.

jest cannot take a per-reporter option on the CLI, so the judge-owned output path
is handed to ``jest-junit`` via the ``JEST_JUNIT_OUTPUT_FILE`` environment variable
(see ``JestAdapter`` / ``instrument_command`` / ``RepoVerifier``); the report file
itself still lives *outside* the repo copy, so the verdict stays off
candidate-influenceable stdout. The pure parse test always runs; the end-to-end
``guard`` run is skipped unless both ``jest`` is on PATH and ``jest-junit`` is
resolvable (neither is on the stock CI runner, so the suite stays green there).
The command-detection / env wiring is covered offline in ``test_adapters.py``.
"""

import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard.guard import FAIL, PASS, guard
from evoom_guard.verifiers.repo_verifier import parse_junit_xml


def _jest_ready() -> bool:
    if shutil.which("jest") is None or shutil.which("node") is None:
        return False
    try:  # jest-junit must be resolvable, else no judge-owned report is written
        return subprocess.run(
            ["node", "-e", "require.resolve('jest-junit')"],
            capture_output=True, timeout=20,
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


needs_jest = pytest.mark.skipif(
    not _jest_ready(), reason="needs the jest CLI and a resolvable jest-junit"
)

# The shape jest-junit emits (captured form): <testsuites> with <testcase>
# elements, a failing case carrying a <failure> child — the case-counting path
# reads it the same way it reads pytest/node/vitest reports.
JEST_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<testsuites name="jest tests" tests="2" failures="1" errors="0" time="0.42">\n'
    '  <testsuite name="impl.test.js" errors="0" failures="1" skipped="0" tests="2" time="0.4">\n'
    '    <testcase classname="dbl doubles" name="dbl doubles" time="0.001"/>\n'
    '    <testcase classname="dbl of 5" name="dbl of 5" time="0.001">\n'
    '      <failure>Error: expect(received).toBe(expected)\n\nExpected: 10\nReceived: 11</failure>\n'
    "    </testcase>\n  </testsuite>\n</testsuites>\n"
)


def test_parse_jest_junit_counts():
    j = parse_junit_xml(JEST_XML)
    assert j is not None
    assert (j.passed, j.total, j.failures, j.errors) == (1, 2, 1, 0)


# ───────────────────────────── integration (jest) ───────────────────────────
def _jest_repo(root):
    (root / "impl.js").write_text("module.exports.dbl = (x) => x + x + 1;\n", encoding="utf-8")  # bug
    (root / "impl.test.js").write_text(
        "const { dbl } = require('./impl');\n"
        "test('dbl doubles', () => expect(dbl(3)).toBe(6));\n"
        "test('dbl of 5', () => expect(dbl(5)).toBe(10));\n",
        encoding="utf-8",
    )


@needs_jest
def test_jest_honest_fix_is_pass_with_junit_source(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _jest_repo(repo)
    cand = "<<<FILE: impl.js>>>\nmodule.exports.dbl = (x) => x + x;\n<<<END FILE>>>"
    res = guard(str(repo), cand, test_command=["jest"], mem_limit_mb=0)
    assert res.verdict == PASS
    assert res.verdict_source == "junit+exit"        # was "exit" (custom runner) before
    assert (res.tests_passed, res.tests_total) == (2, 2)


@needs_jest
def test_jest_broken_fix_is_fail_with_real_counts(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _jest_repo(repo)
    cand = "<<<FILE: impl.js>>>\nmodule.exports.dbl = (x) => x + x + 99;\n<<<END FILE>>>"  # still wrong
    res = guard(str(repo), cand, test_command=["jest"], mem_limit_mb=0)
    assert res.verdict == FAIL
    assert res.verdict_source == "junit+exit"
    assert (res.tests_passed, res.tests_total) == (0, 2)


@needs_jest
def test_jest_rejects_protected_test_edit(tmp_path):
    # The reward-hack pre-gate fires before the suite runs — even for jest.
    repo = tmp_path / "repo"
    repo.mkdir()
    _jest_repo(repo)
    cand = "<<<FILE: impl.test.js>>>\ntest('noop', () => expect(1).toBe(1));\n<<<END FILE>>>"
    res = guard(str(repo), cand, test_command=["jest"], mem_limit_mb=0)
    assert res.verdict == "REJECTED"
