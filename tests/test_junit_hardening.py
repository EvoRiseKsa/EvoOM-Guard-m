# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""`parse_junit_xml` hardening — the report is semi-trusted.

The candidate's test process can write the report path, so a hostile report must
not be able to hang or OOM the judge. The parser refuses any DTD/DOCTYPE/ENTITY
(killing entity-expansion / external-entity vectors) and caps the input size; a
rejected report yields *no counts* (the run grades as FAIL), never a hang.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard.verifiers.repo_verifier import parse_junit_xml

# A classic "billion laughs": nested entity defs that, if expanded, blow up memory.
_BILLION_LAUGHS = (
    '<?xml version="1.0"?>\n'
    "<!DOCTYPE lolz [\n"
    ' <!ENTITY lol "lol">\n'
    ' <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n'
    ' <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">\n'
    "]>\n"
    '<testsuites><testsuite tests="1"><testcase name="&lol3;"/></testsuite></testsuites>\n'
)

_NORMAL = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<testsuites tests="2" failures="1">\n'
    '  <testsuite name="s" tests="2" failures="1">\n'
    '    <testcase name="ok"/>\n'
    '    <testcase name="bad"><failure message="x"/></testcase>\n'
    "  </testsuite>\n</testsuites>\n"
)


def test_rejects_doctype_billion_laughs_without_expanding():
    # Returns None instantly — the DOCTYPE is refused before expat expands anything.
    assert parse_junit_xml(_BILLION_LAUGHS) is None


def test_rejects_bare_entity_declaration():
    assert parse_junit_xml('<!ENTITY x "y">\n<testsuites/>') is None


def test_rejects_oversized_report():
    big = "<testsuites>" + ("x" * (9 * 1024 * 1024)) + "</testsuites>"
    assert parse_junit_xml(big) is None


def test_normal_report_still_counts():
    j = parse_junit_xml(_NORMAL)
    assert j is not None
    assert (j.passed, j.total, j.failures, j.errors) == (1, 2, 1, 0)
