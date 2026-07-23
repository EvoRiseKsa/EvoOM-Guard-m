# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Contracts for the first dependency-free verification domain slice."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import FrozenInstanceError, fields
from pathlib import Path

import pytest

from evoom_guard import domain
from evoom_guard.domain import verification
from evoom_guard.verifiers import junit_oracle, repo_phase_contracts

ROOT = Path(__file__).resolve().parents[1]


def test_legacy_verifier_paths_are_exact_domain_aliases() -> None:
    assert (
        junit_oracle.JUnitCounts
        is repo_phase_contracts.JUnitCounts
        is domain.JUnitCounts
        is verification.JUnitCounts
    )
    for name in (
        "CompletedRunEvidence",
        "RepoPhaseResult",
        "PackPhaseResult",
        "CompositePhaseResult",
    ):
        assert getattr(repo_phase_contracts, name) is getattr(domain, name)
        assert getattr(domain, name) is getattr(verification, name)


def test_junit_counts_field_order_is_frozen() -> None:
    assert verification.JUnitCounts._fields == (
        "passed",
        "total",
        "failures",
        "errors",
    )
    assert verification.JUnitCounts(1, 2, 1, 0) == (1, 2, 1, 0)


@pytest.mark.parametrize(
    ("model", "expected_fields"),
    (
        (
            verification.CompletedRunEvidence,
            (
                "returncode",
                "junit",
                "report_expected",
                "stdout",
                "stderr",
                "junit_text",
                "junit_sha256",
                "junit_digest_format",
            ),
        ),
        (
            verification.RepoPhaseResult,
            (
                "passed",
                "score",
                "tests_passed",
                "tests_total",
                "tampered",
                "output",
                "verdict_source",
                "outcome",
                "returncode",
                "junit_text",
                "junit_sha256",
                "junit_digest_format",
            ),
        ),
        (
            verification.PackPhaseResult,
            (
                "passed",
                "score",
                "tests_passed",
                "tests_total",
                "tampered",
                "output_suffix",
                "verdict_source",
                "outcome",
                "junit_text",
                "junit_sha256",
                "junit_digest_format",
            ),
        ),
        (
            verification.CompositePhaseResult,
            (
                "passed",
                "score",
                "tests_passed",
                "tests_total",
                "tampered",
                "output",
                "verdict_source",
                "outcome",
                "returncode",
                "junit_sha256",
                "junit_digest_format",
            ),
        ),
    ),
)
def test_phase_model_field_order_and_storage_are_frozen(
    model: type[object],
    expected_fields: tuple[str, ...],
) -> None:
    assert tuple(field.name for field in fields(model)) == expected_fields
    assert "__slots__" in model.__dict__
    assert "__dict__" not in model.__dict__


def test_phase_models_remain_immutable() -> None:
    evidence = verification.CompletedRunEvidence(
        returncode=0,
        junit=None,
        report_expected=False,
        stdout="",
        stderr="",
        junit_text="",
        junit_sha256=None,
        junit_digest_format=None,
    )
    with pytest.raises(FrozenInstanceError):
        evidence.returncode = 1  # type: ignore[misc]


def test_domain_import_does_not_initialize_higher_layers() -> None:
    code = """
import sys
sys.path.insert(0, sys.argv[1])
import evoom_guard.domain

forbidden = (
    "evoom_guard.verifiers",
    "evoom_guard.guard",
    "evoom_guard.evidence",
    "evoom_guard.application",
)
loaded = sorted(
    name
    for name in sys.modules
    if any(name == root or name.startswith(root + ".") for root in forbidden)
)
assert loaded == [], loaded
"""
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code, str(ROOT)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
