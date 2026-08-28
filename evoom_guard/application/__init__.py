# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ─────────────────────────────────────────────────────────────────────────────
"""Application services that compose domain values into Guard decisions."""

from evoom_guard.application.assurance import (
    assurance_profile,
    assurance_shortfall,
)
from evoom_guard.application.attestation import build_attestation
from evoom_guard.application.blackbox_finalization import (
    BlackboxFinalizationInput,
    BlackboxFinalizationOutcome,
    BlackboxFinalizationServices,
    finalize_blackbox_verification,
)
from evoom_guard.application.decision_gates import (
    AssuranceShortfallEvaluator,
    apply_assurance_gate,
    apply_demonstrated_fix_gate,
    apply_diff_coverage_gate,
)
from evoom_guard.application.diff_verification import (
    DiffVerificationOptions,
    DiffVerificationOutcome,
    DiffVerificationRequest,
    DiffVerificationServices,
    verify_diff,
)
from evoom_guard.application.pipeline import VerificationPipeline
from evoom_guard.application.repo_decision import compose_repo_decision
from evoom_guard.application.repo_finalization import (
    RepoFinalizationInput,
    RepoFinalizationOutcome,
    RepoFinalizationServices,
    finalize_repo_verification,
)
from evoom_guard.application.repo_judgment import (
    RepoJudgmentInput,
    RepoJudgmentOutcome,
    RepoJudgmentServices,
    build_repo_judgment,
)

__all__ = [
    "assurance_profile",
    "assurance_shortfall",
    "AssuranceShortfallEvaluator",
    "apply_assurance_gate",
    "apply_demonstrated_fix_gate",
    "apply_diff_coverage_gate",
    "build_attestation",
    "BlackboxFinalizationInput",
    "BlackboxFinalizationOutcome",
    "BlackboxFinalizationServices",
    "compose_repo_decision",
    "DiffVerificationOptions",
    "DiffVerificationOutcome",
    "DiffVerificationRequest",
    "DiffVerificationServices",
    "finalize_blackbox_verification",
    "finalize_repo_verification",
    "build_repo_judgment",
    "RepoFinalizationInput",
    "RepoFinalizationOutcome",
    "RepoFinalizationServices",
    "RepoJudgmentInput",
    "RepoJudgmentOutcome",
    "RepoJudgmentServices",
    "VerificationPipeline",
    "verify_diff",
]
