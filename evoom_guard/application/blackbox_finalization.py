# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Ordered post-judge finalization for Guard's black-box path.

The external judge and its cleanup remain runtime responsibilities.  This
module starts only after that boundary returns successfully and owns the
established interpretation, optional repo-native composition, evidence
projection, eager assurance gate, and attestation order.  All effects and
compatibility facades are injected through live providers.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from evoom_guard.application.pipeline import VerificationPipeline
from evoom_guard.domain.decision import GuardDecision

EvidenceMapping = Mapping[str, object]
DecisionSymbolProviders = Mapping[str, Callable[[], str]]
OutcomeReasonPolicy = Mapping[str, tuple[str, str]]


class BlackboxRuntimeResult(Protocol):
    """Read-only result returned after the external judge has cleaned up."""

    @property
    def passed(self) -> bool: ...

    @property
    def tests_passed(self) -> int: ...

    @property
    def tests_total(self) -> int: ...

    @property
    def diagnostics(self) -> str: ...

    @property
    def ran(self) -> bool: ...

    @property
    def error(self) -> str | None: ...

    @property
    def pack_sha256(self) -> str | None: ...

    @property
    def pack_manifest(self) -> dict[str, object] | None: ...

    @property
    def junit_sha256(self) -> str | None: ...

    @property
    def isolation(self) -> dict[str, object] | None: ...

    @property
    def deleted_applied(self) -> list[str] | None: ...

    @property
    def started(self) -> bool: ...

    @property
    def completed(self) -> bool: ...

    @property
    def execution_state(self) -> str: ...

    @property
    def execution_phase(self) -> str: ...

    @property
    def pack_present(self) -> bool | None: ...

    @property
    def candidate_invocations(self) -> int: ...

    @property
    def candidate_launcher_invocation_observed(self) -> bool: ...


class RepoVerdictResult(Protocol):
    """The optional repo-native phase result supplied by the Guard facade."""

    @property
    def passed(self) -> bool: ...

    @property
    def score(self) -> float: ...

    @property
    def diagnostics(self) -> str: ...

    @property
    def artifact(self) -> Mapping[str, object]: ...


class RiskAssessment(Protocol):
    """Risk projection computed through Guard's existing effect facade."""

    @property
    def level(self) -> str: ...

    @property
    def score(self) -> float: ...


class BlackboxRiskAssessor(Protocol):
    def __call__(self) -> RiskAssessment: ...


class ComposedRepoVerifier(Protocol):
    def __call__(self) -> RepoVerdictResult: ...


class BlackboxAssuranceBuilder(Protocol):
    def __call__(
        self,
        isolation: str,
        verifier_pack: str | None,
        *,
        blackbox: bool,
        composed_repo_suite: bool,
        repo_suite_required: bool,
        repo_suite_state: str,
        candidate_isolation: str,
        setup_isolation: str | None,
        runtime_continuity: str | None,
        execution_state: str,
        execution_phase: str,
        test_command_started: bool,
        pack_evidence: dict[str, object],
    ) -> EvidenceMapping: ...


class AssuranceShortfallEvaluator(Protocol):
    def __call__(
        self,
        assurance: EvidenceMapping,
        *,
        require_report_integrity: str | None,
        require_candidate_isolation: str | None,
    ) -> str | None: ...


class BlackboxAttestationBuilder(Protocol):
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


@dataclass(frozen=True, slots=True)
class BlackboxFinalizationInput:
    """Values present immediately after the black-box runtime returns."""

    runtime_result: BlackboxRuntimeResult
    blackbox_only: bool
    verifier_pack_path: str
    candidate_text: str
    safe_deleted_paths: list[str]
    test_command: list[str] | None
    effective_policy: dict[str, object]
    collect_baseline_evidence: bool
    collect_diff_coverage: bool
    require_report_integrity: str | None
    require_candidate_isolation: str | None
    base_sha: str | None
    head_sha: str | None
    base_tree_sha: str | None
    head_tree_sha: str | None
    policy_id: str | None
    policy_version: str | None


@dataclass(frozen=True, slots=True)
class BlackboxFinalizationServices:
    """Live effects and compatibility providers at historical call positions."""

    risk_assessor_provider: Callable[[], BlackboxRiskAssessor]
    composed_repo_verifier_provider: Callable[[], ComposedRepoVerifier]
    assurance_builder_provider: Callable[[], BlackboxAssuranceBuilder]
    assurance_shortfall_provider: Callable[[], AssuranceShortfallEvaluator]
    attestation_builder_provider: Callable[[], BlackboxAttestationBuilder]
    decision_symbol_providers: DecisionSymbolProviders
    outcome_reason_policy_provider: Callable[[], OutcomeReasonPolicy]
    tamper_outcome_reason_policy_provider: Callable[[], OutcomeReasonPolicy]


@dataclass(frozen=True, slots=True)
class BlackboxFinalizationOutcome:
    """Final decision and exact wire evidence consumed by ``GuardResult``."""

    decision: GuardDecision
    passed: bool
    risk_level: str
    risk_score: float
    tests_passed: int | None
    tests_total: int | None
    test_command_started: bool
    execution_state: str
    execution_phase: str
    verdict_source: str | None
    diagnostics: str
    effective_candidate_isolation: str
    baseline: EvidenceMapping | None
    diff_coverage: EvidenceMapping | None
    attestation: EvidenceMapping
    assurance: EvidenceMapping


def finalize_blackbox_verification(
    request: BlackboxFinalizationInput,
    *,
    services: BlackboxFinalizationServices,
) -> BlackboxFinalizationOutcome:
    """Run the frozen post-cleanup black-box sequence without owning effects."""

    result = request.runtime_result

    def decision_symbol(name: str) -> str:
        """Resolve Guard's compatibility vocabulary at the historical use site."""

        return services.decision_symbol_providers[name]()

    # ``ran`` means gradeable; start/completion and candidate invocation remain
    # independent facts.  Keep compatibility fallbacks for historical result
    # objects supplied by integrations.
    started = bool(getattr(result, "started", result.ran))
    completed = bool(getattr(result, "completed", result.ran))
    execution_state = str(
        getattr(
            result,
            "execution_state",
            (
                decision_symbol("EXECUTION_COMPLETED")
                if result.ran
                else decision_symbol("EXECUTION_NOT_STARTED")
            ),
        )
    )
    execution_phase = str(
        getattr(result, "execution_phase", "blackbox_pack")
    )
    delivered_isolation = (
        (result.isolation or {}).get("delivered", "subprocess")
        if started
        else "not_run"
    )
    invocation_observed = bool(
        getattr(result, "candidate_launcher_invocation_observed", False)
    )
    candidate_invocations = int(
        getattr(result, "candidate_invocations", 0)
    )
    candidate_isolation = (
        str(delivered_isolation) if invocation_observed else "not_run"
    )
    gradeable = bool(result.ran and invocation_observed)

    isolation_evidence = result.isolation
    if (
        not started
        and isolation_evidence
        and isolation_evidence.get("delivered") != "unavailable"
    ):
        prepared = isolation_evidence.get(
            "prepared", isolation_evidence.get("delivered")
        )
        isolation_evidence = {
            **isolation_evidence,
            "delivered": "not_run",
            "prepared": prepared,
            "note": (
                "the launcher/boundary was prepared but the black-box judge "
                "did not start, so candidate isolation was not exercised"
            ),
        }
    elif (
        started
        and not invocation_observed
        and isolation_evidence
        and isolation_evidence.get("delivered") != "unavailable"
    ):
        prepared = isolation_evidence.get(
            "prepared", isolation_evidence.get("delivered")
        )
        isolation_evidence = {
            **isolation_evidence,
            "delivered": "not_run",
            "prepared": prepared,
            "note": (
                "the judge ran, but no candidate launcher invocation was "
                "observed; the prepared boundary is not delivery evidence"
            ),
        }

    risk = services.risk_assessor_provider()()

    # A successful external pack is additive.  The repo-native suite remains
    # required unless the caller explicitly selected blackbox-only.
    repo_verdict: RepoVerdictResult | None = None
    if not request.blackbox_only and gradeable and result.passed:
        repo_verdict = services.composed_repo_verifier_provider()()

    repo_art = repo_verdict.artifact if repo_verdict is not None else {}
    repo_started = bool(repo_art.get("test_command_started"))
    repo_completed = bool(
        repo_started
        and repo_art.get("execution_state")
        == decision_symbol("EXECUTION_COMPLETED")
    )
    repo_clean_source = bool(repo_art.get("verdict_source"))
    repo_suite_state = (
        "not_required_blackbox_only"
        if request.blackbox_only
        else "required_not_run_short_circuit"
        if repo_verdict is None
        else "required_not_started"
        if not repo_started
        else "required_started_incomplete"
        if not repo_completed
        else "composed_completed"
    )

    if result.ran and not invocation_observed:
        verdict, reason_code = (
            decision_symbol("ERROR"),
            decision_symbol("REASON_CANDIDATE_NOT_EXERCISED"),
        )
        reason = (
            "the black-box pack completed without an observed "
            "$EVOGUARD_EXEC invocation, so it did not prove that it exercised "
            "the candidate; direct EVOGUARD_TARGET access and constant tests "
            "cannot produce a gradeable black-box verdict"
        )
    elif not result.ran:
        if result.error == "timeout":
            verdict, reason_code = (
                decision_symbol("ERROR"),
                decision_symbol("REASON_TEST_TIMEOUT"),
            )
        elif result.error == "verifier pack identity mismatch":
            verdict, reason_code = (
                decision_symbol("ERROR"),
                decision_symbol(
                    "REASON_VERIFIER_PACK_IDENTITY_MISMATCH"
                ),
            )
        elif result.error == "verifier pack invalid":
            verdict, reason_code = (
                decision_symbol("ERROR"),
                decision_symbol("REASON_VERIFIER_PACK_INVALID"),
            )
        elif (result.error or "").startswith("verifier pack not found:"):
            verdict, reason_code = (
                decision_symbol("ERROR"),
                decision_symbol("REASON_VERIFIER_PACK_NOT_FOUND"),
            )
        elif result.error == "patch did not apply":
            verdict, reason_code = (
                decision_symbol("ERROR"),
                decision_symbol("REASON_PATCH_APPLY_FAILED"),
            )
        elif result.error == "unsafe deletion path":
            verdict, reason_code = (
                decision_symbol("ERROR"),
                decision_symbol("REASON_UNSAFE_PATH"),
            )
        elif result.error == "isolation unavailable":
            verdict, reason_code = (
                decision_symbol("ERROR"),
                decision_symbol(
                    "REASON_ASSURANCE_REQUIREMENT_NOT_MET"
                ),
            )
        elif result.error in (
            "verifier pack snapshot changed",
            "verifier pack changed while executing",
        ):
            verdict, reason_code = (
                decision_symbol("TAMPERED"),
                decision_symbol(
                    "REASON_VERIFIER_PACK_SNAPSHOT_CHANGED"
                ),
            )
        elif result.error == "black-box JUnit/exit mismatch":
            verdict, reason_code = (
                decision_symbol("TAMPERED"),
                decision_symbol("REASON_JUNIT_EXIT_MISMATCH"),
            )
        elif result.error in (
            "candidate container cleanup failed",
            "judge process cleanup failed",
        ):
            verdict, reason_code = (
                decision_symbol("ERROR"),
                decision_symbol("REASON_RUNTIME_CLEANUP_FAILED"),
            )
        else:
            verdict, reason_code = (
                decision_symbol("ERROR"),
                decision_symbol("REASON_NO_TEST_VERDICT"),
            )
        reason = (
            result.diagnostics
            or result.error
            or "the black-box pack produced no verdict"
        )
    elif not result.passed:
        verdict, reason_code, reason = (
            decision_symbol("FAIL"),
            decision_symbol("REASON_TESTS_FAILED"),
            (
                "the black-box pack failed "
                f"({result.tests_passed}/{result.tests_total})"
            ),
        )
    elif repo_verdict is not None and not repo_verdict.passed:
        repo_outcome = repo_art.get("outcome")
        if repo_outcome in services.tamper_outcome_reason_policy_provider():
            reason_code, summary = (
                services.tamper_outcome_reason_policy_provider()[
                    cast(str, repo_outcome)
                ]
            )
            verdict, repo_cause = decision_symbol("TAMPERED"), summary
        elif repo_art.get("tamper"):
            verdict, reason_code = (
                decision_symbol("TAMPERED"),
                decision_symbol("REASON_JUNIT_EXIT_MISMATCH"),
            )
            repo_cause = (
                "the repo suite's exit code and JUnit report disagree"
            )
        elif repo_outcome in services.outcome_reason_policy_provider():
            verdict, reason_code = services.outcome_reason_policy_provider()[
                cast(str, repo_outcome)
            ]
            repo_cause = repo_verdict.diagnostics or str(repo_outcome)
        elif repo_art.get("tests_total") is not None:
            verdict, reason_code = (
                decision_symbol("FAIL"),
                decision_symbol("REASON_TESTS_FAILED"),
            )
            repo_cause = (
                "the repo suite failed "
                f"({repo_art.get('tests_passed', 0)}/"
                f"{repo_art.get('tests_total')} passed)"
            )
        elif repo_verdict.score <= 0.08:
            verdict, reason_code = (
                decision_symbol("ERROR"),
                decision_symbol("REASON_PATCH_APPLY_FAILED"),
            )
            repo_cause = (
                repo_verdict.diagnostics or "the patch did not apply"
            )
        else:
            verdict, reason_code = (
                decision_symbol("FAIL"),
                decision_symbol("REASON_NO_TEST_VERDICT"),
            )
            repo_cause = (
                repo_verdict.diagnostics or "no clean repo-suite verdict"
            )
        reason = (
            "the black-box pack passed, but the repo's own test suite "
            "(the required repo-native phase) "
            f"did not: {repo_cause} — a green pack must not mask a repo failure"
        )
    else:
        extra = (
            "" if repo_verdict is None else " and the repo's own suite passed"
        )
        verdict, reason_code, reason = (
            decision_symbol("PASS"),
            decision_symbol("REASON_TESTS_PASSED"),
            (
                "the black-box pack passed "
                f"({result.tests_passed}/{result.tests_total}){extra} — "
                "the candidate satisfied the judge-owned protocol tests, "
                "judged from outside its own process"
            ),
        )

    repo_state = repo_art.get("execution_state") if repo_art else None
    final_execution_state = (
        decision_symbol("EXECUTION_COMPLETED")
        if repo_verdict is not None
        and repo_state == decision_symbol("EXECUTION_COMPLETED")
        and execution_state == decision_symbol("EXECUTION_COMPLETED")
        else decision_symbol("EXECUTION_STARTED_INCOMPLETE")
        if repo_verdict is not None
        else execution_state
    )
    final_execution_phase = (
        str(repo_art.get("execution_phase", "repo_suite"))
        if repo_verdict is not None
        else execution_phase
    )
    test_command_started = started or bool(
        repo_art.get("test_command_started")
    )
    verdict_source = (
        "composite:blackbox+repo"
        if (
            repo_verdict is not None
            and repo_art.get("verdict_source")
            and gradeable
        )
        else None
        if repo_verdict is not None
        else "blackbox"
        if gradeable
        else None
    )

    tests_passed: int | None
    tests_total: int | None
    if repo_verdict is not None:
        if final_execution_state == decision_symbol(
            "EXECUTION_COMPLETED"
        ):
            repo_passed_count = repo_art.get("tests_passed")
            repo_total_count = repo_art.get("tests_total")
            if (
                repo_passed_count is not None
                and repo_total_count is not None
            ):
                tests_passed = result.tests_passed + int(
                    cast(int, repo_passed_count)
                )
                tests_total = result.tests_total + int(
                    cast(int, repo_total_count)
                )
            else:
                tests_passed = tests_total = None
        else:
            tests_passed = tests_total = None
    else:
        tests_passed = result.tests_passed if completed else None
        tests_total = result.tests_total if completed else None

    pack_outcome = None
    if result.error == "verifier pack invalid":
        pack_outcome = "pack_invalid"
    elif result.error == "verifier pack identity mismatch":
        pack_outcome = "pack_identity_mismatch"
    elif result.error in (
        "verifier pack snapshot changed",
        "verifier pack changed while executing",
    ):
        pack_outcome = "pack_snapshot_changed"
    pack_evidence: dict[str, object] = {
        "present": getattr(
            result,
            "pack_present",
            True
            if result.pack_sha256
            else False
            if "not found" in (result.error or "")
            else None,
        ),
        "snapshot_sha256": result.pack_sha256,
        "started": started,
        "completed": completed,
        "outcome": pack_outcome,
        "candidate_launcher_invocation_observed": invocation_observed,
    }

    assurance = services.assurance_builder_provider()(
        candidate_isolation,
        request.verifier_pack_path,
        blackbox=True,
        composed_repo_suite=repo_started,
        repo_suite_required=not request.blackbox_only,
        repo_suite_state=repo_suite_state,
        candidate_isolation=candidate_isolation,
        setup_isolation=cast(
            str | None,
            repo_art.get("setup_isolation") if repo_art else None,
        ),
        runtime_continuity=cast(
            str | None,
            repo_art.get("runtime_continuity") if repo_art else None,
        ),
        execution_state=final_execution_state,
        execution_phase=final_execution_phase,
        test_command_started=test_command_started,
        pack_evidence=pack_evidence,
    )
    decision_pipeline = VerificationPipeline.from_decision(
        GuardDecision(
            verdict=verdict,
            reason_code=reason_code,
            reason=reason,
        )
    ).apply_assurance(
        assurance=assurance,
        execution_state=final_execution_state,
        execution_requested=True,
        require_report_integrity=request.require_report_integrity,
        require_candidate_isolation=request.require_candidate_isolation,
        shortfall_evaluator=services.assurance_shortfall_provider(),
        eager_shortfall=True,
    )
    decision = decision_pipeline.decision

    baseline = None
    if request.collect_baseline_evidence:
        baseline = {
            "verdict": None,
            "tests_passed": None,
            "tests_total": None,
            "repair_effect": "unmeasured",
            "scope": "unsupported_mode",
            "note": (
                "baseline differential evidence runs under the subprocess "
                "repo judge only; the black-box judge did not measure it"
            ),
        }
    diff_coverage = None
    if request.collect_diff_coverage:
        diff_coverage = {
            "measured": False,
            "note": (
                "changed-line coverage runs under the subprocess repo judge "
                "only; the black-box judge did not measure it"
            ),
        }

    # Historical Guard evaluated ``passed=(verdict == PASS)`` immediately
    # before reading the final risk/diagnostic properties and building the
    # attestation. Keep both the live symbol lookup and that access order.
    passed = decision.verdict == decision_symbol("PASS")

    # GuardResult historically read these properties immediately before the
    # final attestation call.  Keep that exception/access order even though the
    # public wire object is now assembled by the facade after this coordinator.
    risk_level = risk.level
    risk_score = risk.score
    diagnostics = result.diagnostics
    attestation = services.attestation_builder_provider()(
        request.candidate_text,
        safe_deleted=request.safe_deleted_paths,
        test_command=request.test_command,
        effective_policy=request.effective_policy,
        art={
            "verifier_pack_sha256": result.pack_sha256,
            "verifier_pack_manifest": result.pack_manifest,
            "verifier_pack_present": pack_evidence["present"],
            "verifier_pack_started": started,
            "verifier_pack_completed": completed,
            "verifier_pack_tests_passed": (
                result.tests_passed if completed else None
            ),
            "verifier_pack_tests_total": (
                result.tests_total if completed else None
            ),
            "verifier_pack_junit_sha256": result.junit_sha256,
            "verifier_pack_junit_digest_format": (
                "JUNIT_XML_SHA256" if result.junit_sha256 else None
            ),
            "junit_sha256": result.junit_sha256,
            "junit_digest_format": (
                "JUNIT_XML_SHA256" if result.junit_sha256 else None
            ),
            "isolation_evidence": isolation_evidence,
            "blackbox_pack_isolation_evidence": isolation_evidence,
            "setup_isolation_evidence": repo_art.get(
                "setup_isolation_evidence"
            ),
            "repo_suite_isolation_evidence": repo_art.get(
                "repo_suite_isolation_evidence"
            ),
            "verifier_pack_isolation_evidence": repo_art.get(
                "verifier_pack_isolation_evidence"
            ),
            "deleted_paths_applied": result.deleted_applied,
            "repo_suite_junit_sha256": (
                repo_art.get("junit_sha256") if repo_art else None
            ),
            "repo_suite_junit_digest_format": (
                repo_art.get("junit_digest_format") if repo_art else None
            ),
            "repo_suite_passed": (
                repo_verdict.passed
                if repo_verdict is not None and repo_clean_source
                else None
            ),
            "repo_suite_started": repo_started,
            "repo_suite_completed": repo_completed,
            "repo_suite_state": repo_suite_state,
            "repo_suite_image_digest": (
                repo_art.get("image_digest") if repo_art else None
            ),
            "base_sha": request.base_sha,
            "head_sha": request.head_sha,
            "base_tree_sha": request.base_tree_sha,
            "head_tree_sha": request.head_tree_sha,
            "policy_id": request.policy_id,
            "policy_version": request.policy_version,
            "setup_isolation": repo_art.get("setup_isolation"),
            "execution_state": final_execution_state,
            "execution_phase": final_execution_phase,
            "test_command_started": test_command_started,
            "candidate_invocations": candidate_invocations,
            "candidate_launcher_invocation_observed": invocation_observed,
            "delivered_isolation": candidate_isolation,
            "effective_candidate_isolation": candidate_isolation,
        },
        mode="blackbox",
    )

    return BlackboxFinalizationOutcome(
        decision=decision,
        passed=passed,
        risk_level=risk_level,
        risk_score=risk_score,
        tests_passed=tests_passed,
        tests_total=tests_total,
        test_command_started=test_command_started,
        execution_state=final_execution_state,
        execution_phase=final_execution_phase,
        verdict_source=verdict_source,
        diagnostics=diagnostics,
        effective_candidate_isolation=candidate_isolation,
        baseline=baseline,
        diff_coverage=diff_coverage,
        attestation=attestation,
        assurance=assurance,
    )


__all__ = [
    "BlackboxFinalizationInput",
    "BlackboxFinalizationOutcome",
    "BlackboxFinalizationServices",
    "finalize_blackbox_verification",
]
