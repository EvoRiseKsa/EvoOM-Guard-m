# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Sole owner & author: Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""Phase 1 — native JUnit verdicting for node's built-in test runner.

* **Pure** — the dialect-agnostic ``parse_junit_xml`` over the shapes node emits
  (top-level cases straight under ``<testsuites>`` with no ``<testsuite>`` wrapper
  and no aggregate counts). Always runs.
* **Integration** — ``node --test`` driven end-to-end through ``guard``; skipped
  unless Node ≥ 22 is on PATH. Proves a Node run yields ``verdict_source:
  junit+exit`` with real counts (previously exit-code-only).

The command-detection / report-injection wiring is tested in ``test_adapters.py``.
"""

import os
import re
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard.guard import FAIL, PASS, guard
from evoom_guard.verifiers.repo_verifier import parse_junit_xml


def _node_ge_22() -> bool:
    exe = shutil.which("node")
    if not exe:
        return False
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    m = re.match(r"v(\d+)", out.strip())
    return bool(m) and int(m.group(1)) >= 22


HAS_NODE22 = _node_ge_22()
needs_node = pytest.mark.skipif(not HAS_NODE22, reason="needs Node >= 22 on PATH")

# The exact shapes node's built-in junit reporter emits (captured live).
NODE_TOPLEVEL = (
    '<?xml version="1.0" encoding="utf-8"?>\n<testsuites>\n'
    '  <testcase name="passes one" classname="test"/>\n'
    '  <testcase name="passes two" classname="test"/>\n'
    '  <testcase name="fails here" classname="test" failure="boom">\n'
    '    <failure type="testCodeFailure" message="boom">trace</failure>\n'
    "  </testcase>\n</testsuites>\n"
)
NODE_MIXED = (
    "<testsuites>\n"
    '  <testsuite name="group" tests="2" failures="0" errors="0" skipped="0">\n'
    '    <testcase name="a"/>\n    <testcase name="b"/>\n  </testsuite>\n'
    '  <testcase name="toplevel"/>\n</testsuites>\n'
)
NODE_SKIP = (
    "<testsuites>\n"
    '  <testcase name="run"/>\n'
    '  <testcase name="todo"><skipped/></testcase>\n</testsuites>\n'
)


# ───────────────────────────── parse_junit_xml (node dialect) ────────────────
def test_parse_node_toplevel_cases_no_suite_wrapper():
    # No <testsuite> element and no aggregate counts — the case-counting path.
    j = parse_junit_xml(NODE_TOPLEVEL)
    assert j is not None
    assert (j.passed, j.total, j.failures, j.errors) == (2, 3, 1, 0)


def test_parse_node_mixed_suite_and_toplevel_counts_all_cases():
    j = parse_junit_xml(NODE_MIXED)
    assert j is not None
    assert (j.passed, j.total) == (3, 3)  # the loose top-level case is not lost


def test_parse_node_skipped_excluded_from_total():
    j = parse_junit_xml(NODE_SKIP)
    assert j is not None
    assert (j.passed, j.total) == (1, 1)  # total excludes the skipped case


def test_pytest_suite_attribute_fallback_still_works():
    # No <testcase> elements → the aggregate <testsuite> attributes are read.
    j = parse_junit_xml('<testsuite tests="5" failures="1" errors="1" skipped="1"/>')
    assert j is not None
    assert (j.passed, j.total, j.failures, j.errors) == (2, 4, 1, 1)


# ───────────────────────────── integration (node --test) ────────────────────
def _node_repo(root):
    (root / "impl.mjs").write_text("export const dbl = (x) => x + x + 1;\n", encoding="utf-8")  # bug
    (root / "impl.test.mjs").write_text(
        "import { test } from 'node:test';\n"
        "import assert from 'node:assert';\n"
        "import { dbl } from './impl.mjs';\n"
        "test('dbl doubles', () => assert.strictEqual(dbl(3), 6));\n",
        encoding="utf-8",
    )


@needs_node
def test_node_test_honest_fix_is_pass_with_junit_source(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _node_repo(repo)
    cand = "<<<FILE: impl.mjs>>>\nexport const dbl = (x) => x + x;\n<<<END FILE>>>"
    res = guard(str(repo), cand, test_command=["node", "--test", "impl.test.mjs"], mem_limit_mb=0)
    assert res.verdict == PASS
    assert res.verdict_source == "junit+exit"     # was "exit" before Phase 1
    assert (res.tests_passed, res.tests_total) == (1, 1)  # real structured counts


@needs_node
def test_node_test_broken_fix_is_fail_with_real_counts(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _node_repo(repo)
    cand = "<<<FILE: impl.mjs>>>\nexport const dbl = (x) => x + x + 99;\n<<<END FILE>>>"  # still wrong
    res = guard(str(repo), cand, test_command=["node", "--test", "impl.test.mjs"], mem_limit_mb=0)
    assert res.verdict == FAIL
    assert res.verdict_source == "junit+exit"
    assert (res.tests_passed, res.tests_total) == (0, 1)
