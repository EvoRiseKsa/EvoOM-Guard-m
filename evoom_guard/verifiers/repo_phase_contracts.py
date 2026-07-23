# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Pure interpretation contracts for completed repository judge phases.

This module deliberately owns no filesystem, process, container, or trace
mutation. ``RepoVerifier`` gathers the evidence; these functions interpret and
compose it so phase semantics can be tested independently of execution effects.
"""

from __future__ import annotations

import hashlib

from evoom_guard.domain.verification import (
    CompletedRunEvidence,
    CompositePhaseResult,
    JUnitCounts,
    PackPhaseResult,
    RepoPhaseResult,
)
from evoom_guard.verifiers.junit_oracle import (
    JUNIT_COMPOSITE_DIGEST_FORMAT,
    JUNIT_REPORT_SET_DIGEST_FORMAT,
    JUNIT_XML_DIGEST_FORMAT,
    detect_tamper,
    grade_repo_run,
)


def clean_verdict_source(
    returncode: int,
    junit: JUnitCounts | None,
    *,
    report_expected: bool,
) -> str | None:
    """Name a source only for a cleanly gradeable pass/fail evidence pair."""

    if junit is not None:
        return "junit+exit" if junit.total > 0 and returncode in (0, 1) else None
    if not report_expected and returncode in (0, 1):
        return "exit"
    return None


def evaluate_repo_phase(
    evidence: CompletedRunEvidence,
    *,
    strict_harness: bool,
) -> RepoPhaseResult:
    """Interpret one completed repository suite without performing effects."""

    passed, score, tests_passed, tests_total = grade_repo_run(
        evidence.returncode,
        evidence.junit,
        report_expected=evidence.report_expected,
    )
    tampered = detect_tamper(
        evidence.returncode,
        evidence.junit,
        report_expected=evidence.report_expected,
    )
    output = evidence.stdout + "\n" + evidence.stderr
    verdict_source = clean_verdict_source(
        evidence.returncode,
        evidence.junit,
        report_expected=evidence.report_expected,
    )
    if strict_harness and (evidence.junit is None or evidence.junit.total <= 0):
        passed = False
        score = 0.0
        verdict_source = None
        output += (
            "\nstrict_harness requires a non-empty structured JUnit "
            "test verdict; exit-only/zero-test success was rejected"
        )
    return RepoPhaseResult(
        passed=passed,
        score=score,
        tests_passed=tests_passed,
        tests_total=tests_total,
        tampered=tampered,
        output=output,
        verdict_source=verdict_source,
        outcome=None if verdict_source is not None else "no_test_verdict",
        returncode=evidence.returncode,
        junit_text=evidence.junit_text,
        junit_sha256=evidence.junit_sha256,
        junit_digest_format=evidence.junit_digest_format,
    )


def evaluate_pack_phase(evidence: CompletedRunEvidence) -> PackPhaseResult:
    """Interpret a completed mandatory verifier pack without composing it."""

    passed, score, tests_passed, tests_total = grade_repo_run(
        evidence.returncode,
        evidence.junit,
        report_expected=evidence.report_expected,
    )
    verdict_source = clean_verdict_source(
        evidence.returncode,
        evidence.junit,
        report_expected=evidence.report_expected,
    )
    outcome: str | None = None
    diagnostic = ""
    if not tests_total:
        passed = False
        score = 0.0
        if evidence.junit is not None:
            outcome = "pack_no_tests"
            diagnostic = "\nverifier pack collected zero tests"
        else:
            outcome = "pack_no_verdict"
            diagnostic = "\nverifier pack produced no valid JUnit verdict"
    elif verdict_source is None:
        passed = False
        score = 0.0
        outcome = "pack_no_verdict"
        diagnostic = "\nverifier pack produced no clean pass/fail verdict"
    return PackPhaseResult(
        passed=passed,
        score=score,
        tests_passed=tests_passed,
        tests_total=tests_total,
        tampered=detect_tamper(
            evidence.returncode,
            evidence.junit,
            report_expected=evidence.report_expected,
        ),
        output_suffix=diagnostic + "\n" + evidence.stdout + "\n" + evidence.stderr,
        verdict_source=verdict_source,
        outcome=outcome,
        junit_text=evidence.junit_text,
        junit_sha256=evidence.junit_sha256,
        junit_digest_format=evidence.junit_digest_format,
    )


def compose_repo_and_pack(
    repo: RepoPhaseResult,
    pack: PackPhaseResult,
) -> CompositePhaseResult:
    """Compose repository and mandatory pack results using the frozen framing."""

    if repo.junit_digest_format in (
        JUNIT_XML_DIGEST_FORMAT,
        JUNIT_REPORT_SET_DIGEST_FORMAT,
    ):
        if repo.junit_sha256 is not None and pack.junit_sha256 is not None:
            identity = (
                JUNIT_COMPOSITE_DIGEST_FORMAT
                + "\0repo\0"
                + repo.junit_digest_format
                + "\0"
                + repo.junit_sha256
                + "\0verifier-pack\0"
                + JUNIT_XML_DIGEST_FORMAT
                + "\0"
                + pack.junit_sha256
            )
            junit_sha256 = hashlib.sha256(identity.encode("utf-8")).hexdigest()
            junit_digest_format: str | None = JUNIT_COMPOSITE_DIGEST_FORMAT
        else:
            junit_sha256 = None
            junit_digest_format = None
    else:
        combined_junit = (
            "repo\0"
            + repo.junit_text
            + "\0verifier-pack\0"
            + pack.junit_text
        )
        junit_sha256 = hashlib.sha256(combined_junit.encode("utf-8")).hexdigest()
        junit_digest_format = "EVOGUARD_JUNIT_COMPOSITE_V1"

    return CompositePhaseResult(
        passed=repo.passed and pack.passed,
        score=min(repo.score, pack.score),
        tests_passed=repo.tests_passed + pack.tests_passed,
        tests_total=repo.tests_total + pack.tests_total,
        tampered=repo.tampered or pack.tampered,
        output=repo.output + pack.output_suffix,
        verdict_source=(
            "composite:repo+verifier-pack"
            if repo.verdict_source is not None and pack.verdict_source is not None
            else None
        ),
        outcome=pack.outcome if pack.outcome is not None else repo.outcome,
        returncode=repo.returncode,
        junit_sha256=junit_sha256,
        junit_digest_format=junit_digest_format,
    )


__all__ = [
    "CompletedRunEvidence",
    "CompositePhaseResult",
    "PackPhaseResult",
    "RepoPhaseResult",
    "clean_verdict_source",
    "compose_repo_and_pack",
    "evaluate_pack_phase",
    "evaluate_repo_phase",
]
