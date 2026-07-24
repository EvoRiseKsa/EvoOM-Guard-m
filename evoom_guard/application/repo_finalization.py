# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Ordered repo-native evidence finalization behind the public Guard facade.

This module owns only the established sequence after the repository verifier
has produced its initial decision.  Runtime effects and compatibility helpers
remain in their existing modules and are resolved through providers at their
historical call positions.  Black-box orchestration and ``GuardResult`` remain
outside this boundary.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass
from typing import Protocol

from evoom_guard.application.pipeline import VerificationPipeline
from evoom_guard.domain.decision import GuardDecision
from evoom_guard.domain.evidence import VerificationEvidence
from evoom_guard.domain.verdict import (
    EXECUTION_STATIC_GATE,
    FAIL,
    PASS,
)

EvidenceMapping = Mapping[str, object]
MutableEvidenceMapping = MutableMapping[str, object]


class RepoCoverageCollector(Protocol):
    """Effectful changed-line coverage collector supplied by Guard."""

    def __call__(
        self,
        repo_path: str,
        candidate: str,
        *,
        deleted: tuple[str, ...],
        test_command: list[str] | None,
        setup_command: list[str] | None,
        setup_output_globs: tuple[str, ...],
        timeout: int,
        mem_limit_mb: int,
        file_blocks: dict[str, str] | None,
        require_passing_suite: bool,
    ) -> EvidenceMapping: ...


class RepoBaselineRunner(Protocol):
    """Effectful pristine-suite runner supplied by the Guard facade."""

    def __call__(
        self,
        repo_path: str,
        *,
        test_command: list[str] | None,
        setup_command: list[str] | None,
        setup_output_globs: tuple[str, ...],
        timeout: int,
        mem_limit_mb: int,
        strict_harness: bool,
    ) -> MutableEvidenceMapping: ...


class RepoAttestationBuilder(Protocol):
    """Compatibility attestation facade resolved immediately before use."""

    def __call__(
        self,
        candidate: str,
        *,
        safe_deleted: list[str],
        test_command: list[str] | None,
        effective_policy: dict[str, object],
        art: dict[str, object],
        mode: str,
    ) -> EvidenceMapping: ...


class RuntimeAssuranceBuilder(Protocol):
    """Construct the delivered runtime assurance mapping."""

    def __call__(
        self,
        isolation: str,
        verifier_pack: str | None,
        *,
        setup_isolation: str | None,
        runtime_continuity: str | None,
        execution_state: str,
        execution_phase: str,
        test_command_started: bool,
        pack_evidence: dict[str, object] | None,
    ) -> EvidenceMapping: ...


class StaticAssuranceBuilder(Protocol):
    """Construct assurance for a static pre-execution decision."""

    def __call__(self, verifier_pack: str | None) -> EvidenceMapping: ...


class AssuranceShortfallEvaluator(Protocol):
    """Evaluate the delivered assurance against configured minimums."""

    def __call__(
        self,
        assurance: EvidenceMapping,
        *,
        require_report_integrity: str | None,
        require_candidate_isolation: str | None,
    ) -> str | None: ...


class RepoAttestationEvidenceProjector(Protocol):
    """Project typed repository evidence to the established wire fields."""

    def __call__(
        self,
        evidence: VerificationEvidence,
    ) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class RepoFinalizationInput:
    """Exact values present at Guard's post-core-decision boundary.

    Containers are intentionally retained by reference.  The aggregate is
    shallow-frozen so the compatibility facade cannot rebind fields while the
    evidence objects preserve their established identity in ``GuardResult``.
    """

    pipeline: VerificationPipeline
    verification_evidence: VerificationEvidence | None
    raw_artifact: Mapping[str, object]
    run_suite: bool
    repository_path: str
    candidate_text: str
    safe_deleted_paths: list[str]
    test_command: list[str] | None
    setup_command: list[str] | None
    setup_output_globs: tuple[str, ...]
    file_blocks: dict[str, str] | None
    timeout: int
    mem_limit_mb: int
    strict_harness: bool
    isolation: str
    judgment_mode: str
    verifier_pack_path: str | None
    collect_diff_coverage: bool
    min_diff_coverage: int | float | None
    collect_baseline_evidence: bool
    require_demonstrated_fix: bool
    require_report_integrity: str | None
    require_candidate_isolation: str | None
    effective_policy: dict[str, object]
    base_sha: str | None
    head_sha: str | None
    base_tree_sha: str | None
    head_tree_sha: str | None
    policy_id: str | None
    policy_version: str | None


@dataclass(frozen=True, slots=True)
class RepoFinalizationServices:
    """Late resolvers and effects evaluated only at their historical positions."""

    coverage_collector_provider: Callable[[], RepoCoverageCollector]
    baseline_runner_provider: Callable[[], RepoBaselineRunner]
    attestation_builder_provider: Callable[[], RepoAttestationBuilder]
    runtime_assurance_builder_provider: Callable[[], RuntimeAssuranceBuilder]
    static_assurance_builder_provider: Callable[[], StaticAssuranceBuilder]
    assurance_shortfall_provider: Callable[[], AssuranceShortfallEvaluator]
    attestation_evidence_projector_provider: Callable[
        [], RepoAttestationEvidenceProjector
    ]
    pack_directory_predicate: Callable[[str], bool]


@dataclass(frozen=True, slots=True)
class RepoFinalizationOutcome:
    """Final decision plus exact evidence objects projected by ``GuardResult``."""

    decision: GuardDecision
    execution_state: str
    execution_phase: str
    test_command_started: bool
    effective_candidate_isolation: str
    diff_coverage: EvidenceMapping | None
    baseline: MutableEvidenceMapping | None
    attestation: EvidenceMapping
    assurance: EvidenceMapping


def finalize_repo_verification(
    request: RepoFinalizationInput,
    *,
    services: RepoFinalizationServices,
) -> RepoFinalizationOutcome:
    """Run the frozen repo-native post-decision sequence.

    Coverage collection, baseline execution, evidence mutation, attestation,
    profile construction, and lazy assurance evaluation deliberately retain
    their historical order and fail-loud exception boundaries.
    """

    decision_pipeline = request.pipeline
    initial_decision = decision_pipeline.decision
    current_decision = initial_decision
    verdict = current_decision.verdict

    # Preserve both layers before later evidence gates can demote the top-level
    # verdict. Baseline compares only the repository phase when one is present.
    core_verdict_completed = verdict in (PASS, FAIL)
    core_verdict_passed = verdict == PASS
    repo_suite_pass_value = (
        request.verification_evidence.repo_suite.passed
        if request.verification_evidence is not None
        else None
    )
    repo_suite_completed = (
        request.verification_evidence is not None
        and request.verification_evidence.repo_suite.started is True
        and request.verification_evidence.repo_suite.completed is True
        and isinstance(repo_suite_pass_value, bool)
    )
    candidate_suite_completed = repo_suite_completed or core_verdict_completed
    candidate_suite_passed = (
        repo_suite_pass_value is True
        if repo_suite_completed
        else core_verdict_passed
    )

    # Changed-line coverage is an effect only for a completed core verdict in
    # subprocess mode. Unsupported evidence-only requests remain explicit.
    coverage_evidence: EvidenceMapping | None = None
    if request.collect_diff_coverage and request.isolation != "subprocess":
        coverage_evidence = {
            "measured": False,
            "note": (
                "changed-line coverage runs under the subprocess judge "
                f"only; isolation {request.isolation!r} did not measure it"
            ),
        }
    if (
        request.collect_diff_coverage
        and core_verdict_completed
        and request.isolation == "subprocess"
    ):
        coverage_evidence = services.coverage_collector_provider()(
            request.repository_path,
            request.candidate_text,
            deleted=tuple(request.safe_deleted_paths),
            test_command=request.test_command,
            setup_command=request.setup_command,
            setup_output_globs=request.setup_output_globs,
            timeout=request.timeout,
            mem_limit_mb=request.mem_limit_mb,
            file_blocks=request.file_blocks,
            require_passing_suite=(
                core_verdict_passed and request.min_diff_coverage is not None
            ),
        )
        decision_pipeline = decision_pipeline.apply_diff_coverage(
            coverage_evidence=coverage_evidence,
            min_diff_coverage=request.min_diff_coverage,
        )
        current_decision = decision_pipeline.decision
        verdict = current_decision.verdict

    # Baseline remains after coverage even when coverage has already demoted the
    # decision. Its repair effect is based on the pre-demotion repo-suite facts.
    baseline_info: MutableEvidenceMapping | None = None
    if request.collect_baseline_evidence and request.isolation != "subprocess":
        baseline_info = {
            "verdict": None,
            "tests_passed": None,
            "tests_total": None,
            "repair_effect": "unmeasured",
            "scope": "unsupported_mode",
            "note": (
                "baseline differential evidence runs under the subprocess "
                f"judge only; isolation {request.isolation!r} did not measure it"
            ),
        }
    if (
        (
            request.collect_baseline_evidence
            or request.require_demonstrated_fix
        )
        and candidate_suite_completed
        and request.isolation == "subprocess"
    ):
        baseline_info = services.baseline_runner_provider()(
            request.repository_path,
            test_command=request.test_command,
            setup_command=request.setup_command,
            setup_output_globs=request.setup_output_globs,
            timeout=request.timeout,
            mem_limit_mb=request.mem_limit_mb,
            strict_harness=request.strict_harness,
        )
        if baseline_info.get("verdict") == "NO_CLEAN_VERDICT":
            baseline_info["repair_effect"] = "unmeasured"
        elif (
            baseline_info.get("verdict") == "FAIL"
            and candidate_suite_passed
        ):
            baseline_info["repair_effect"] = "demonstrated"
        else:
            baseline_info["repair_effect"] = "not_demonstrated"
        baseline_info["scope"] = "repo_suite_only"
        baseline_info["note"] = (
            "counterfactual suite-transition evidence, not a causal proof: the "
            "same judge and environment ran the REPO suite on the pristine base "
            "and on the candidate; 'demonstrated' means the base failed and the "
            "candidate passed. A verifier pack (if any) is exercised only on "
            "the candidate run — see scope."
        )
        decision_pipeline = decision_pipeline.apply_demonstrated_fix(
            baseline_evidence=baseline_info,
            require_demonstrated_fix=request.require_demonstrated_fix,
        )
        current_decision = decision_pipeline.decision
        verdict = current_decision.verdict

    if request.run_suite:
        assert request.verification_evidence is not None
        execution_state = (
            request.verification_evidence.execution.execution_state
        )
        execution_phase = (
            request.verification_evidence.execution.execution_phase
        )
        test_command_started = (
            request.verification_evidence.execution.test_command_started
        )
        delivered_isolation = (
            request.verification_evidence.execution.delivered_isolation
        )
    else:
        execution_state = EXECUTION_STATIC_GATE
        execution_phase = "pre_gate"
        test_command_started = False
        delivered_isolation = "not_run"

    effective_candidate_isolation = (
        "subprocess"
        if (
            request.verification_evidence is not None
            and request.verification_evidence.setup_isolation
            == "subprocess_host_opt_in"
        )
        else delivered_isolation
    )

    pack_evidence: dict[str, object] | None = None
    if request.verifier_pack_path:
        if request.verification_evidence is None:
            pack_evidence = {
                "present": None,
                "snapshot_sha256": None,
                "started": False,
                "completed": False,
                "outcome": None,
            }
        else:
            present = request.verification_evidence.verifier_pack.present
            if (
                present is None
                and request.verification_evidence.verifier_pack.sha256
            ):
                present = True
            if (
                present is None
                and request.verification_evidence.outcome == "pack_invalid"
            ):
                present = services.pack_directory_predicate(
                    request.verifier_pack_path
                )
            pack_evidence = {
                "present": present,
                "snapshot_sha256": (
                    request.verification_evidence.verifier_pack.sha256
                ),
                "started": (
                    request.verification_evidence.execution.verifier_pack_started
                ),
                "completed": (
                    request.verification_evidence.execution.verifier_pack_completed
                ),
                "outcome": request.verification_evidence.outcome,
            }

    attestation_art = dict(request.raw_artifact)
    if request.verification_evidence is not None:
        attestation_art.update(
            services.attestation_evidence_projector_provider()(
                request.verification_evidence
            )
        )
    attestation_art.update(
        {
            "execution_state": execution_state,
            "execution_phase": execution_phase,
            "test_command_started": test_command_started,
            "delivered_isolation": delivered_isolation,
            "effective_candidate_isolation": effective_candidate_isolation,
            "base_sha": request.base_sha,
            "head_sha": request.head_sha,
            "base_tree_sha": request.base_tree_sha,
            "head_tree_sha": request.head_tree_sha,
            "policy_id": request.policy_id,
            "policy_version": request.policy_version,
        }
    )
    attestation = services.attestation_builder_provider()(
        request.candidate_text,
        safe_deleted=request.safe_deleted_paths,
        test_command=request.test_command,
        effective_policy=request.effective_policy,
        art=attestation_art,
        mode=request.judgment_mode,
    )

    assurance = (
        services.runtime_assurance_builder_provider()(
            delivered_isolation,
            request.verifier_pack_path,
            setup_isolation=(
                request.verification_evidence.setup_isolation
                if request.verification_evidence is not None
                else None
            ),
            runtime_continuity=(
                request.verification_evidence.runtime.continuity
                if request.verification_evidence is not None
                else None
            ),
            execution_state=execution_state,
            execution_phase=execution_phase,
            test_command_started=test_command_started,
            pack_evidence=pack_evidence,
        )
        if request.run_suite
        else services.static_assurance_builder_provider()(
            request.verifier_pack_path
        )
    )
    decision_pipeline = decision_pipeline.apply_assurance(
        assurance=assurance,
        execution_state=execution_state,
        execution_requested=request.run_suite,
        require_report_integrity=request.require_report_integrity,
        require_candidate_isolation=request.require_candidate_isolation,
        shortfall_evaluator=services.assurance_shortfall_provider(),
        eager_shortfall=False,
    )
    current_decision = decision_pipeline.decision

    return RepoFinalizationOutcome(
        decision=current_decision,
        execution_state=execution_state,
        execution_phase=execution_phase,
        test_command_started=test_command_started,
        effective_candidate_isolation=effective_candidate_isolation,
        diff_coverage=coverage_evidence,
        baseline=baseline_info,
        attestation=attestation,
        assurance=assurance,
    )


__all__ = [
    "RepoFinalizationInput",
    "RepoFinalizationOutcome",
    "RepoFinalizationServices",
    "finalize_repo_verification",
]
