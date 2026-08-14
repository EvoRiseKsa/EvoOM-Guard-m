"""Public dependency-free domain contracts."""

from evoom_guard.domain.assurance import AssuranceProfile, VerifierPackAssurance
from evoom_guard.domain.blast_radius import (
    BLAST_RADIUS_V2_FORMAT,
    BLAST_RADIUS_V2_SCORE_FORMAT,
    BlastRadiusScoreV2,
    BlastRadiusV2ContractError,
    MaterializedChangeSetV2,
    MaterializedChangeV2,
    MaterializedOperationV2,
    blast_radius_score_v2,
    canonical_materialized_change_v2_bytes,
    materialized_change_set_v2,
)
from evoom_guard.domain.decision import GuardDecision
from evoom_guard.domain.evidence import (
    IsolationPayloadEvidence,
    RepositorySuiteEvidence,
    RuntimeIdentityEvidence,
    VerificationEvidence,
    VerifierPackEvidence,
)
from evoom_guard.domain.execution import ExecutionPhaseResult, IsolationObservation
from evoom_guard.domain.harness import (
    HarnessInputPolicyError,
    harness_input_path_conflicts,
    is_harness_input_path,
    is_portable_repo_path,
    is_windows_ambiguous_path_segment,
    normalize_harness_inputs,
    setup_output_harness_conflicts,
)
from evoom_guard.domain.isolation import (
    SUPPORTED_ISOLATION_MODES,
    validate_isolation_mode,
)
from evoom_guard.domain.policy import (
    OPERATING_PROFILES,
    EffectivePolicy,
    is_verifier_pack_sha256,
    operating_profile_violations,
    unsupported_policy_requirements,
)
from evoom_guard.domain.request import (
    CandidateInput,
    GuardRequest,
    RepositoryInput,
    SourceIdentity,
)
from evoom_guard.domain.verification import (
    CompletedRunEvidence,
    CompositePhaseResult,
    JUnitCounts,
    PackPhaseResult,
    RepoPhaseResult,
)

__all__ = [
    "AssuranceProfile",
    "BLAST_RADIUS_V2_FORMAT",
    "BLAST_RADIUS_V2_SCORE_FORMAT",
    "BlastRadiusScoreV2",
    "BlastRadiusV2ContractError",
    "CompletedRunEvidence",
    "CompositePhaseResult",
    "CandidateInput",
    "EffectivePolicy",
    "ExecutionPhaseResult",
    "GuardRequest",
    "GuardDecision",
    "HarnessInputPolicyError",
    "harness_input_path_conflicts",
    "IsolationObservation",
    "IsolationPayloadEvidence",
    "JUnitCounts",
    "MaterializedChangeSetV2",
    "MaterializedChangeV2",
    "MaterializedOperationV2",
    "OPERATING_PROFILES",
    "is_harness_input_path",
    "is_portable_repo_path",
    "is_verifier_pack_sha256",
    "is_windows_ambiguous_path_segment",
    "normalize_harness_inputs",
    "blast_radius_score_v2",
    "canonical_materialized_change_v2_bytes",
    "materialized_change_set_v2",
    "operating_profile_violations",
    "unsupported_policy_requirements",
    "PackPhaseResult",
    "RepositoryInput",
    "RepositorySuiteEvidence",
    "RepoPhaseResult",
    "RuntimeIdentityEvidence",
    "SourceIdentity",
    "SUPPORTED_ISOLATION_MODES",
    "setup_output_harness_conflicts",
    "VerificationEvidence",
    "VerifierPackAssurance",
    "VerifierPackEvidence",
    "validate_isolation_mode",
]
