# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Dependency-free verification evidence and phase-result contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import NamedTuple


class JUnitCounts(NamedTuple):
    """Authoritative test counts read from a judge-owned JUnit report."""

    passed: int
    total: int
    failures: int
    errors: int


@dataclass(frozen=True, slots=True)
class CompletedRunEvidence:
    """Evidence already collected for one completed judge command."""

    returncode: int
    junit: JUnitCounts | None
    report_expected: bool
    stdout: str
    stderr: str
    junit_text: str
    junit_sha256: str | None
    junit_digest_format: str | None


@dataclass(frozen=True, slots=True)
class RepoPhaseResult:
    """Interpreted repository-suite result before optional pack composition."""

    passed: bool
    score: float
    tests_passed: int
    tests_total: int
    tampered: bool
    output: str
    verdict_source: str | None
    outcome: str | None
    returncode: int
    junit_text: str
    junit_sha256: str | None
    junit_digest_format: str | None


@dataclass(frozen=True, slots=True)
class PackPhaseResult:
    """Interpreted mandatory verifier-pack result and output contribution."""

    passed: bool
    score: float
    tests_passed: int
    tests_total: int
    tampered: bool
    output_suffix: str
    verdict_source: str | None
    outcome: str | None
    junit_text: str
    junit_sha256: str | None
    junit_digest_format: str | None


@dataclass(frozen=True, slots=True)
class CompositePhaseResult:
    """Repository-plus-pack result with its composite evidence identity."""

    passed: bool
    score: float
    tests_passed: int
    tests_total: int
    tampered: bool
    output: str
    verdict_source: str | None
    outcome: str | None
    returncode: int
    junit_sha256: str | None
    junit_digest_format: str | None


__all__ = [
    "CompletedRunEvidence",
    "CompositePhaseResult",
    "JUnitCounts",
    "PackPhaseResult",
    "RepoPhaseResult",
]
