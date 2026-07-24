"""Application services that compose domain values into Guard decisions."""

from evoom_guard.application.assurance import (
    assurance_profile,
    assurance_shortfall,
)
from evoom_guard.application.attestation import build_attestation
from evoom_guard.application.decision_gates import (
    AssuranceShortfallEvaluator,
    apply_assurance_gate,
    apply_demonstrated_fix_gate,
    apply_diff_coverage_gate,
)
from evoom_guard.application.pipeline import VerificationPipeline
from evoom_guard.application.repo_decision import compose_repo_decision
from evoom_guard.application.repo_finalization import (
    RepoFinalizationInput,
    RepoFinalizationOutcome,
    RepoFinalizationServices,
    finalize_repo_verification,
)

__all__ = [
    "assurance_profile",
    "assurance_shortfall",
    "AssuranceShortfallEvaluator",
    "apply_assurance_gate",
    "apply_demonstrated_fix_gate",
    "apply_diff_coverage_gate",
    "build_attestation",
    "compose_repo_decision",
    "finalize_repo_verification",
    "RepoFinalizationInput",
    "RepoFinalizationOutcome",
    "RepoFinalizationServices",
    "VerificationPipeline",
]
