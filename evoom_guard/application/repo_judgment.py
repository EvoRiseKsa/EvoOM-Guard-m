# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Repo-native pre-finalization judgment through injected live providers.

This owner starts only after candidate preflight and shared problem
construction.  It stops before repo finalization and public ``GuardResult``
construction.  It intentionally imports no EvoOM runtime module.
"""

from __future__ import annotations

from collections.abc import Callable, MutableMapping, Sequence
from dataclasses import dataclass
from typing import Generic, Protocol, TypeVar

RiskMap = MutableMapping[str, tuple[int, int]]


class RepoVerifierResult(Protocol):
    """The exact verifier fields read by this judgment stage."""

    @property
    def artifact(self) -> dict[str, object] | None: ...

    @property
    def diagnostics(self) -> str | None: ...

    @property
    def passed(self) -> bool: ...

    @property
    def score(self) -> float: ...


class _RepoVerifier(Protocol):
    def verify(
        self,
        candidate: str,
        problem: dict[str, object],
        /,
    ) -> RepoVerifierResult: ...


class _RepoVerifierFactory(Protocol):
    def __call__(
        self,
        *,
        timeout: int,
        mem_limit_mb: int,
        isolation: str,
        docker_image: str | None,
        docker_network: str,
        trust_setup_on_host: bool,
        setup_output_globs: tuple[str, ...],
        strict_harness: bool,
        require_suite_continuity: bool,
        require_assert_liveness: bool,
    ) -> _RepoVerifier: ...


_EvidenceT = TypeVar("_EvidenceT")
_EvidenceT_co = TypeVar("_EvidenceT_co", covariant=True)
_EvidenceT_contra = TypeVar("_EvidenceT_contra", contravariant=True)
_RiskT = TypeVar("_RiskT")
_RiskT_co = TypeVar("_RiskT_co", covariant=True)
_PipelineT = TypeVar("_PipelineT")
_PipelineT_co = TypeVar("_PipelineT_co", covariant=True)


class _EvidenceProjector(Protocol[_EvidenceT_co]):
    def __call__(
        self,
        artifact: dict[str, object],
        /,
        *,
        default_isolation: str,
    ) -> _EvidenceT_co: ...


class _RiskMapBuilder(Protocol):
    def __call__(
        self,
        repository_path: str,
        candidate_text: str,
        file_blocks: dict[str, str] | None,
        /,
    ) -> RiskMap: ...


class _RiskScorer(Protocol[_RiskT_co]):
    def __call__(
        self,
        risk_map: RiskMap,
        /,
        *,
        protected: tuple[str, ...],
    ) -> _RiskT_co: ...


class _VerificationPipelineFactory(
    Protocol[_EvidenceT_contra, _PipelineT_co]
):
    def from_repo_facts(
        self,
        *,
        has_changes: bool,
        unsafe_paths: Sequence[str],
        protected_violations: Sequence[str],
        verifier_present: bool,
        verifier_passed: bool | None,
        verifier_score: float | None,
        diagnostics: str,
        evidence: _EvidenceT_contra | None,
    ) -> _PipelineT_co: ...


@dataclass(frozen=True, slots=True)
class RepoJudgmentInput:
    """Values already owned by Guard at the post-preflight boundary.

    Containers are retained by reference.  In particular, ``problem`` and
    ``all_touched_paths`` must not be copied before verifier/risk effects.
    """

    run_suite: bool
    repository_path: str
    candidate_text: str
    problem: dict[str, object]
    all_touched_paths: list[str]
    unsafe_paths: list[str]
    protected_violations: list[str]
    deleted_paths: Sequence[str]
    protected_patterns: Sequence[str]
    file_blocks: dict[str, str] | None
    timeout: int
    mem_limit_mb: int
    isolation: str
    docker_image: str | None
    docker_network: str
    trust_setup_on_host: bool
    setup_output_globs: tuple[str, ...]
    strict_harness: bool
    require_suite_continuity: bool = False
    require_assert_liveness: bool = False


@dataclass(frozen=True, slots=True)
class RepoJudgmentServices(Generic[_EvidenceT, _RiskT, _PipelineT]):
    """Providers resolved only at their historical operation positions."""

    repo_verifier_provider: Callable[[], _RepoVerifierFactory]
    evidence_projector_provider: Callable[[], _EvidenceProjector[_EvidenceT]]
    risk_map_provider: Callable[[], _RiskMapBuilder]
    repo_file_reader_provider: Callable[[], Callable[[str, str], str]]
    risk_scorer_provider: Callable[[], _RiskScorer[_RiskT]]
    protected_globs_provider: Callable[[], tuple[str, ...]]
    verification_pipeline_provider: Callable[
        [], _VerificationPipelineFactory[_EvidenceT, _PipelineT]
    ]


@dataclass(frozen=True, slots=True)
class RepoJudgmentOutcome(Generic[_EvidenceT, _RiskT, _PipelineT]):
    """Exact objects delivered to finalization and the public result adapter."""

    run_suite: bool
    verifier_result: RepoVerifierResult | None
    raw_artifact: dict[str, object]
    verification_evidence: _EvidenceT | None
    diagnostics: str
    risk: _RiskT
    pipeline: _PipelineT
    all_touched_paths: list[str]


def build_repo_judgment(
    request: RepoJudgmentInput,
    *,
    services: RepoJudgmentServices[_EvidenceT, _RiskT, _PipelineT],
) -> RepoJudgmentOutcome[_EvidenceT, _RiskT, _PipelineT]:
    """Build the initial repo-native judgment without finalizing evidence.

    Operation and lookup order are compatibility constraints: verifier,
    artifact, evidence, diagnostics, risk map, per-deletion reads, risk score,
    pipeline method resolution, and only then the verifier's live
    ``passed``/``score`` fields.
    """

    run_suite = request.run_suite
    verifier_result: RepoVerifierResult | None
    raw_artifact: dict[str, object]
    verification_evidence: _EvidenceT | None
    diagnostics: str

    if run_suite:
        verifier_factory = services.repo_verifier_provider()
        verifier_result = verifier_factory(
            timeout=request.timeout,
            mem_limit_mb=request.mem_limit_mb,
            isolation=request.isolation,
            docker_image=request.docker_image,
            docker_network=request.docker_network,
            trust_setup_on_host=request.trust_setup_on_host,
            setup_output_globs=request.setup_output_globs,
            strict_harness=request.strict_harness,
            require_suite_continuity=request.require_suite_continuity,
            require_assert_liveness=request.require_assert_liveness,
        ).verify(request.candidate_text, request.problem)
        raw_artifact = verifier_result.artifact or {}
        verification_evidence = services.evidence_projector_provider()(
            raw_artifact,
            default_isolation=request.isolation,
        )
        diagnostics = verifier_result.diagnostics or ""
    else:
        verifier_result = None
        raw_artifact = {}
        verification_evidence = None
        diagnostics = ""

    risk_map = services.risk_map_provider()(
        request.repository_path,
        request.candidate_text,
        request.file_blocks,
    )
    for path in request.all_touched_paths:
        if path in request.deleted_paths and path not in risk_map:
            base = services.repo_file_reader_provider()(
                request.repository_path,
                path,
            )
            risk_map[path] = (0, len(base.splitlines()))

    risk_scorer = services.risk_scorer_provider()
    risk = risk_scorer(
        risk_map,
        protected=(
            services.protected_globs_provider()
            + tuple(request.protected_patterns)
        ),
    )

    pipeline_factory = services.verification_pipeline_provider()
    pipeline_builder = pipeline_factory.from_repo_facts
    pipeline = pipeline_builder(
        has_changes=bool(request.all_touched_paths),
        unsafe_paths=request.unsafe_paths,
        protected_violations=request.protected_violations,
        verifier_present=verifier_result is not None,
        verifier_passed=(
            verifier_result.passed
            if verifier_result is not None
            else None
        ),
        verifier_score=(
            verifier_result.score
            if verifier_result is not None
            else None
        ),
        diagnostics=diagnostics,
        evidence=verification_evidence,
    )

    return RepoJudgmentOutcome(
        run_suite=run_suite,
        verifier_result=verifier_result,
        raw_artifact=raw_artifact,
        verification_evidence=verification_evidence,
        diagnostics=diagnostics,
        risk=risk,
        pipeline=pipeline,
        all_touched_paths=request.all_touched_paths,
    )


__all__ = [
    "build_repo_judgment",
    "RepoJudgmentInput",
    "RepoJudgmentOutcome",
    "RepoJudgmentServices",
    "RepoVerifierResult",
    "RiskMap",
]
