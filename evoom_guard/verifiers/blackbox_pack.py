# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Typed execution and interpretation of one accepted black-box verifier pack.

This module owns only the already-established pack-phase effect sequence.  The
public black-box facade retains pack intake, candidate materialization,
candidate-boundary preparation, invocation/CID evidence, cleanup precedence,
workspace lifetime, and the ``BlackboxResult`` compatibility ABI.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from evoom_guard.execution import JudgeOutputLimitError, JudgeProcessCleanupError
from evoom_guard.pack_manifest import PackManifestError

ExecutionState = Literal["not_started", "started_incomplete", "completed"]
ExecutionPhase = Literal["preflight", "blackbox_pack"]
PackIdentity = tuple[str, dict[str, Any] | None]


class CompletedJudgeProcess(Protocol):
    """Minimal completed-process facts consumed by black-box interpretation."""

    returncode: int
    stdout: str
    stderr: str


class JUnitObservation(Protocol):
    """JUnit counts required by the established exit/report coherence policy."""

    passed: int
    total: int
    failures: int
    errors: int


class VerifyPackSnapshot(Protocol):
    """Verify that the accepted pack snapshot still has one exact identity."""

    def __call__(self, path: str, identity: PackIdentity) -> None: ...


class BuildJudgeCommand(Protocol):
    """Build the judge command for one accepted snapshot and owned report."""

    def __call__(self, pack_dir: str, xml_path: str) -> list[str]: ...


class RunJudgeProcess(Protocol):
    """Run the established bounded judge-process compatibility facade."""

    def __call__(
        self,
        command: list[str],
        *,
        cwd: str,
        env: dict[str, str],
        timeout: int,
    ) -> CompletedJudgeProcess: ...


class ReadJUnitReport(Protocol):
    """Read one bounded judge-owned JUnit report."""

    def __call__(self, path: str) -> str | None: ...


class ParseJUnitReport(Protocol):
    """Parse the exact JUnit text observed from the judge-owned report."""

    def __call__(self, text: str) -> JUnitObservation | None: ...


class DistillDiagnostics(Protocol):
    """Bound process diagnostics without changing their established ordering."""

    def __call__(self, output: str) -> str: ...


@dataclass(slots=True)
class BlackboxPackLifecycle:
    """Mutable cleanup state shared with the outer resource owner.

    The state is deliberately set before command construction.  If command
    construction or process launch raises an unhandled ``BaseException``, the
    facade's ``finally`` block must still perform late, non-strict cleanup just
    as the historical implementation did.
    """

    active: bool = False
    started: bool = False


@dataclass(frozen=True, slots=True)
class BlackboxPackExecutionRequest:
    """Immutable values present immediately before black-box pack execution."""

    pack_snapshot: str
    pack_identity: PackIdentity
    xml_path: str
    environment: dict[str, str]
    timeout: int


@dataclass(frozen=True, slots=True)
class BlackboxPackExecutionServices:
    """Live effect providers resolved at their historical operation sites."""

    verify_snapshot: Callable[[], VerifyPackSnapshot]
    build_command: Callable[[], BuildJudgeCommand]
    run_judge: Callable[[], RunJudgeProcess]
    perf_counter: Callable[[], float]


@dataclass(frozen=True, slots=True)
class BlackboxPackVerdictFacts:
    """Internal facts projected by the facade onto ``BlackboxResult``."""

    passed: bool
    tests_passed: int
    tests_total: int
    diagnostics: str
    ran: bool
    error: str | None
    junit_sha256: str | None = None
    started: bool = False
    completed: bool = False
    execution_state: ExecutionState = "not_started"
    execution_phase: ExecutionPhase = "preflight"
    attach_candidate_evidence: bool = False
    wait_for_late_container_evidence: bool = False


@dataclass(frozen=True, slots=True)
class BlackboxPackCompleted:
    """Completed process evidence awaiting immediate JUnit interpretation."""

    process: CompletedJudgeProcess
    xml_path: str
    started_at: float


@dataclass(frozen=True, slots=True)
class BlackboxPackExecutionOutcome:
    """Exactly one terminal verdict or one completed process observation."""

    terminal: BlackboxPackVerdictFacts | None = None
    completed: BlackboxPackCompleted | None = None

    def __post_init__(self) -> None:
        if (self.terminal is None) == (self.completed is None):
            raise ValueError(
                "black-box pack outcome requires exactly one terminal or completed value"
            )


@dataclass(frozen=True, slots=True)
class BlackboxPackInterpretationRequest:
    """One completed judge process ready for immediate report interpretation."""

    completed: BlackboxPackCompleted


@dataclass(frozen=True, slots=True)
class BlackboxPackInterpretationServices:
    """Live report, hashing, diagnostics, and clock providers."""

    read_report: Callable[[], ReadJUnitReport]
    parse_report: Callable[[], ParseJUnitReport]
    digest_text: Callable[[str], str]
    distill_diagnostics: Callable[[], DistillDiagnostics]
    perf_counter: Callable[[], float]


def _incomplete(
    *,
    diagnostics: str,
    error: str,
) -> BlackboxPackExecutionOutcome:
    return BlackboxPackExecutionOutcome(
        terminal=BlackboxPackVerdictFacts(
            passed=False,
            tests_passed=0,
            tests_total=0,
            diagnostics=diagnostics,
            ran=False,
            error=error,
            started=True,
            completed=False,
            execution_state="started_incomplete",
            execution_phase="blackbox_pack",
            attach_candidate_evidence=True,
            wait_for_late_container_evidence=True,
        )
    )


def execute_blackbox_pack(
    request: BlackboxPackExecutionRequest,
    *,
    lifecycle: BlackboxPackLifecycle,
    services: BlackboxPackExecutionServices,
) -> BlackboxPackExecutionOutcome:
    """Verify, execute, and re-verify one accepted black-box pack snapshot."""

    started_at = services.perf_counter()
    try:
        services.verify_snapshot()(request.pack_snapshot, request.pack_identity)
        lifecycle.active = True
        lifecycle.started = True
        # Python historically resolved ``_run_judge_process`` before evaluating
        # the nested ``_judge_command(...)`` argument. Preserve that lookup
        # timing so a command-builder monkeypatch cannot replace the runner for
        # the in-flight call.
        run_judge = services.run_judge()
        command = services.build_command()(request.pack_snapshot, request.xml_path)
        process = run_judge(
            command,
            cwd=request.pack_snapshot,
            timeout=request.timeout,
            env=request.environment,
        )
        lifecycle.active = False
    except subprocess.TimeoutExpired:
        return _incomplete(
            diagnostics=f"black-box pack timed out after {request.timeout}s",
            error="timeout",
        )
    except JudgeOutputLimitError as exc:
        return _incomplete(
            diagnostics=str(exc),
            error="black-box output limit",
        )
    except JudgeProcessCleanupError as exc:
        return _incomplete(
            diagnostics=str(exc),
            error="judge process cleanup failed",
        )
    except PackManifestError as exc:
        return BlackboxPackExecutionOutcome(
            terminal=BlackboxPackVerdictFacts(
                passed=False,
                tests_passed=0,
                tests_total=0,
                diagnostics=str(exc),
                ran=False,
                error="verifier pack snapshot changed",
            )
        )

    try:
        services.verify_snapshot()(request.pack_snapshot, request.pack_identity)
    except PackManifestError as exc:
        return BlackboxPackExecutionOutcome(
            terminal=BlackboxPackVerdictFacts(
                passed=False,
                tests_passed=0,
                tests_total=0,
                diagnostics=str(exc),
                ran=False,
                error="verifier pack changed while executing",
                started=True,
                completed=True,
                execution_state="completed",
                execution_phase="blackbox_pack",
                attach_candidate_evidence=True,
            )
        )

    return BlackboxPackExecutionOutcome(
        completed=BlackboxPackCompleted(
            process=process,
            xml_path=request.xml_path,
            started_at=started_at,
        )
    )


def interpret_blackbox_pack(
    request: BlackboxPackInterpretationRequest,
    *,
    services: BlackboxPackInterpretationServices,
) -> BlackboxPackVerdictFacts:
    """Read and classify one completed pack under the established exit policy."""

    completed = request.completed
    junit = None
    junit_sha256 = None
    xml_text = services.read_report()(completed.xml_path)
    if xml_text is not None:
        junit = services.parse_report()(xml_text)
        junit_sha256 = services.digest_text(xml_text)
    _elapsed_seconds = services.perf_counter() - completed.started_at
    diagnostics = services.distill_diagnostics()(
        completed.process.stdout + "\n" + completed.process.stderr
    )

    if junit is None or junit.total <= 0:
        return BlackboxPackVerdictFacts(
            passed=False,
            tests_passed=0,
            tests_total=0,
            diagnostics=diagnostics,
            ran=False,
            error="black-box pack produced no judge-owned test results",
            junit_sha256=junit_sha256,
            started=True,
            completed=True,
            execution_state="completed",
            execution_phase="blackbox_pack",
            attach_candidate_evidence=True,
        )

    tests_passed, tests_total = junit.passed, junit.total
    junit_all_passed = junit.failures == 0 and junit.errors == 0 and tests_passed == tests_total
    if (completed.process.returncode == 0 and not junit_all_passed) or (
        completed.process.returncode == 1 and junit_all_passed
    ):
        return BlackboxPackVerdictFacts(
            passed=False,
            tests_passed=tests_passed,
            tests_total=tests_total,
            diagnostics=diagnostics,
            ran=False,
            error="black-box JUnit/exit mismatch",
            junit_sha256=junit_sha256,
            started=True,
            completed=True,
            execution_state="completed",
            execution_phase="blackbox_pack",
            attach_candidate_evidence=True,
        )
    if completed.process.returncode == 0:
        return BlackboxPackVerdictFacts(
            passed=True,
            tests_passed=tests_passed,
            tests_total=tests_total,
            diagnostics=diagnostics,
            ran=True,
            error=None,
            junit_sha256=junit_sha256,
            started=True,
            completed=True,
            execution_state="completed",
            execution_phase="blackbox_pack",
            attach_candidate_evidence=True,
        )
    if completed.process.returncode == 1:
        return BlackboxPackVerdictFacts(
            passed=False,
            tests_passed=tests_passed,
            tests_total=tests_total,
            diagnostics=diagnostics,
            ran=True,
            error=None,
            junit_sha256=junit_sha256,
            started=True,
            completed=True,
            execution_state="completed",
            execution_phase="blackbox_pack",
            attach_candidate_evidence=True,
        )
    return BlackboxPackVerdictFacts(
        passed=False,
        tests_passed=tests_passed,
        tests_total=tests_total,
        diagnostics=diagnostics,
        ran=False,
        error=(f"black-box pack did not run cleanly (pytest exit {completed.process.returncode})"),
        junit_sha256=junit_sha256,
        started=True,
        completed=True,
        execution_state="completed",
        execution_phase="blackbox_pack",
        attach_candidate_evidence=True,
    )


__all__ = [
    "BlackboxPackCompleted",
    "BlackboxPackExecutionOutcome",
    "BlackboxPackExecutionRequest",
    "BlackboxPackExecutionServices",
    "BlackboxPackInterpretationRequest",
    "BlackboxPackInterpretationServices",
    "BlackboxPackLifecycle",
    "BlackboxPackVerdictFacts",
    "execute_blackbox_pack",
    "interpret_blackbox_pack",
]
