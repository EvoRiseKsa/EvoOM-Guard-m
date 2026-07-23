# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Dependency-free effective-policy domain contract."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EffectivePolicy:
    """Immutable policy values that shape one Guard judgment.

    This is a domain value only. Canonical wire representation, hashing, and
    trusted-input validation belong to the policy and schema layers.
    """

    mode: str
    isolation: str
    docker_image: str | None
    docker_network: str
    test_command: tuple[str, ...] | None
    setup_command: tuple[str, ...] | None
    trust_setup_on_host: bool
    setup_output_globs: tuple[str, ...]
    protected: tuple[str, ...]
    allow: tuple[str, ...]
    allow_new_tests: bool
    timeout: int
    mem_limit_mb: int
    verifier_pack_required: bool
    expect_verifier_pack_sha256: str | None
    blackbox: bool
    blackbox_only: bool
    require_report_integrity: str | None
    require_candidate_isolation: str | None
    min_diff_coverage: float | None
    baseline_evidence: bool
    require_demonstrated_fix: bool
    strict_harness: bool
    policy_id: str | None
    policy_version: str | None
