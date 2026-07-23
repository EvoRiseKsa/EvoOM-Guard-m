"""Public dependency-free domain contracts."""

from evoom_guard.domain.decision import GuardDecision
from evoom_guard.domain.evidence import (
    IsolationPayloadEvidence,
    RepositorySuiteEvidence,
    RuntimeIdentityEvidence,
    VerificationEvidence,
    VerifierPackEvidence,
)
from evoom_guard.domain.execution import ExecutionPhaseResult, IsolationObservation
from evoom_guard.domain.policy import EffectivePolicy
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
    "CompletedRunEvidence",
    "CompositePhaseResult",
    "CandidateInput",
    "EffectivePolicy",
    "ExecutionPhaseResult",
    "GuardRequest",
    "GuardDecision",
    "IsolationObservation",
    "IsolationPayloadEvidence",
    "JUnitCounts",
    "PackPhaseResult",
    "RepositoryInput",
    "RepositorySuiteEvidence",
    "RepoPhaseResult",
    "RuntimeIdentityEvidence",
    "SourceIdentity",
    "VerificationEvidence",
    "VerifierPackEvidence",
]
