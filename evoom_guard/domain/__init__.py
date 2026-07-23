"""Public dependency-free domain contracts."""

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
    "GuardRequest",
    "JUnitCounts",
    "PackPhaseResult",
    "RepositoryInput",
    "RepoPhaseResult",
    "SourceIdentity",
]
