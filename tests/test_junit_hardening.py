# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
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

from evoom_guard.verifiers.junit_oracle import canary_case_failed
from evoom_guard.verifiers.repo_verifier import parse_junit_xml

_CANARY = "test_evoguard_assertion_liveness"

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


def test_namespaced_junit_elements_are_counted():
    report = (
        '<testsuites xmlns="urn:junit" tests="3" failures="1" errors="0" skipped="1">'
        '<testsuite tests="3" failures="1" errors="0" skipped="1">'
        '<testcase name="pass"/>'
        '<testcase name="fail"><failure message="broken"/></testcase>'
        '<testcase name="skip"><skipped/></testcase>'
        "</testsuite>"
        "</testsuites>"
    )

    counts = parse_junit_xml(report)

    assert counts is not None
    assert (counts.passed, counts.total, counts.failures, counts.errors) == (1, 2, 1, 0)


def test_rejects_negative_or_impossible_aggregate_counters():
    reports = (
        '<testsuite tests="-1" failures="0" errors="0" skipped="0"/>',
        '<testsuite tests="1" failures="-1" errors="0" skipped="0"/>',
        '<testsuite tests="1" failures="1" errors="1" skipped="0"/>',
        '<testsuite tests="1" failures="0" errors="0" skipped="2"/>',
    )

    for report in reports:
        assert parse_junit_xml(report) is None


def test_rejects_huge_or_non_ascii_counter_before_integer_conversion():
    huge = "9" * 100_000

    assert parse_junit_xml(f'<testsuite tests="{huge}"/>') is None
    assert parse_junit_xml('<testsuite tests="١"/>') is None


def test_rejects_excessively_deep_suite_nesting_without_recursion_error():
    depth = 140
    report = "<testsuites>" + ('<testsuite tests="1">' * depth)
    report += '<testcase name="pass"/>'
    report += "</testsuite>" * depth + "</testsuites>"

    assert parse_junit_xml(report) is None


def test_rejects_testcase_with_contradictory_terminal_states():
    report = (
        '<testsuite tests="2" failures="1" errors="0" skipped="1">'
        '<testcase name="honest-pass"/>'
        '<testcase name="ambiguous"><skipped/><failure message="hidden"/></testcase>'
        "</testsuite>"
    )

    assert parse_junit_xml(report) is None


def test_nested_suite_aggregates_are_validated_not_double_counted():
    report = (
        '<testsuites tests="2" failures="1" errors="0" skipped="0">'
        '<testsuite name="parent" tests="2" failures="1" errors="0" skipped="0">'
        '<testsuite name="passing" tests="1" failures="0" errors="0" skipped="0">'
        '<testcase name="pass"/>'
        "</testsuite>"
        '<testsuite name="failing" tests="1" failures="1" errors="0" skipped="0">'
        '<testcase name="fail"><failure/></testcase>'
        "</testsuite>"
        "</testsuite>"
        "</testsuites>"
    )

    counts = parse_junit_xml(report)

    assert counts is not None
    assert (counts.passed, counts.total, counts.failures, counts.errors) == (1, 2, 1, 0)


def test_pytest_passed_subtests_may_exceed_emitted_testcases_without_inflating_counts():
    # Captures pytest 9's JUnit shape for successful unittest/builtin subtests:
    # the suite counter includes them, but the XML writer reuses the parent
    # node reporter and emits no separate testcase elements.
    report = (
        '<testsuites name="pytest tests">'
        '<testsuite name="pytest" tests="3" failures="0" errors="0" skipped="0">'
        '<testcase classname="tests.test_example" name="test_with_subtests"/>'
        '<testcase classname="tests.test_example" name="test_plain"/>'
        "</testsuite>"
        "</testsuites>"
    )

    counts = parse_junit_xml(report)

    assert counts is not None
    # Trust only explicit testcase evidence, not the larger aggregate claim.
    assert (counts.passed, counts.total, counts.failures, counts.errors) == (2, 2, 0, 0)


def test_rejects_test_surplus_without_complete_matching_terminal_counters():
    missing_terminal_claims = (
        '<testsuite tests="2"><testcase name="only-explicit-case"/></testsuite>'
    )
    contradictory_terminal_claim = (
        '<testsuite tests="3" failures="1" errors="0" skipped="0">'
        '<testcase name="explicit-pass-one"/>'
        '<testcase name="explicit-pass-two"/>'
        "</testsuite>"
    )

    assert parse_junit_xml(missing_terminal_claims) is None
    assert parse_junit_xml(contradictory_terminal_claim) is None


def test_rejects_aggregate_claim_that_disagrees_with_testcases():
    hidden_failure = (
        '<testsuite tests="1" failures="0" errors="0" skipped="0">'
        '<testcase name="failed"><failure/></testcase>'
        "</testsuite>"
    )
    invented_failure = (
        '<testsuite tests="1" failures="1" errors="0" skipped="0">'
        '<testcase name="passed"/>'
        "</testsuite>"
    )

    assert parse_junit_xml(hidden_failure) is None
    assert parse_junit_xml(invented_failure) is None


def test_mocha_xunit_error_alias_retains_explicit_failures():
    report = (
        '<testsuite name="Mocha Tests" tests="2" failures="0" errors="1" skipped="0">'
        '<testcase name="passed"/>'
        '<testcase name="failed"><failure message="assertion failed"/></testcase>'
        "</testsuite>"
    )

    counts = parse_junit_xml(report)

    assert counts is not None
    assert (counts.passed, counts.total, counts.failures, counts.errors) == (1, 2, 1, 0)


def test_mocha_xunit_compatibility_rejects_non_equivalent_counter_claims():
    invented_extra_error = (
        '<testsuite tests="2" failures="0" errors="2" skipped="0">'
        '<testcase name="passed"/>'
        '<testcase name="failed"><failure/></testcase>'
        "</testsuite>"
    )
    mixed_child_states = (
        '<testsuite tests="2" failures="0" errors="2" skipped="0">'
        '<testcase name="failed"><failure/></testcase>'
        '<testcase name="errored"><error/></testcase>'
        "</testsuite>"
    )
    reverse_alias = (
        '<testsuite tests="1" failures="1" errors="0" skipped="0">'
        '<testcase name="errored"><error/></testcase>'
        "</testsuite>"
    )

    assert parse_junit_xml(invented_extra_error) is None
    assert parse_junit_xml(mixed_child_states) is None
    assert parse_junit_xml(reverse_alias) is None


def test_canary_case_failed_detects_the_named_failing_node():
    # The canary node failed (or errored) -> True; a passing canary or an absent
    # canary -> False. This is what upgrades a neutered run from FAIL to TAMPERED.
    failed = (
        '<testsuite tests="2" failures="1">'
        '<testcase classname="tests.test_m" name="test_value"/>'
        f'<testcase classname=".evoguard.assert_liveness_canary" name="{_CANARY}">'
        "<failure>assertion machinery neutered</failure></testcase>"
        "</testsuite>"
    )
    errored = failed.replace("<failure>assertion machinery neutered</failure>", "<error/>")
    passed = (
        '<testsuite tests="2">'
        '<testcase name="test_value"/>'
        f'<testcase name="{_CANARY}"/>'
        "</testsuite>"
    )
    absent = '<testsuite tests="1"><testcase name="test_value"><failure/></testcase></testsuite>'

    assert canary_case_failed(failed, _CANARY) is True
    assert canary_case_failed(errored, _CANARY) is True
    assert canary_case_failed(passed, _CANARY) is False
    assert canary_case_failed(absent, _CANARY) is False


def test_canary_case_failed_is_fail_open_on_hostile_or_empty_reports():
    # Fail-open is safe: the ordinary grader still counts the canary's failure, so a
    # missed detection degrades TAMPERED to a plain FAIL, never to a PASS.
    assert canary_case_failed("", _CANARY) is False
    assert canary_case_failed("not xml at all", _CANARY) is False
    # A namespaced testcase is still matched by local name.
    namespaced = (
        f'<ns:testsuite xmlns:ns="urn:x"><ns:testcase name="{_CANARY}">'
        "<ns:failure/></ns:testcase></ns:testsuite>"
    )
    assert canary_case_failed(namespaced, _CANARY) is True
    # DTD/ENTITY reports are refused before parsing (shared parser hardening).
    dtd = (
        '<?xml version="1.0"?><!DOCTYPE t [<!ENTITY x "y">]>'
        f'<testsuite><testcase name="{_CANARY}"><failure/></testcase></testsuite>'
    )
    assert canary_case_failed(dtd, _CANARY) is False
