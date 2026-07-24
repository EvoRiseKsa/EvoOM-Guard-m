# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Typed repository-suite execution and interpretation.

The two public operations are deliberately separate. ``RepoVerifier`` retains
runtime-tree continuity verification between completed suite execution and
JUnit interpretation, and it retains all verifier-pack execution afterward.
Effects are resolved through live providers at their historical call sites.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from evoom_guard.contracts import VerdictResult
from evoom_guard.domain.execution import IsolationObservation
from evoom_guard.domain.verification import (
    CompletedRunEvidence,
    JUnitCounts,
    RepoPhaseResult,
)
from evoom_guard.execution import (
    ProcessContainmentError,
    ProcessOutputLimitExceeded,
)
from evoom_guard.isolation import (
    DockerRunContainmentError,
    DockerRunOutputLimit,
    DockerRunTimeout,
)


class RepoSuiteTrace(Protocol):
    """Trace fields the repository-suite phase may mutate."""

    execution_state: str
    execution_phase: str
    test_command_started: bool
    test_command_completed: bool
    delivered_isolation: str
    repo_suite_isolation_evidence: IsolationObservation | None
    primary_isolation_evidence: IsolationObservation | None


class CompletedSuiteProcess(Protocol):
    """Minimal completed-process evidence required by suite policy."""

    returncode: int
    stdout: str
    stderr: str


class InstrumentSuiteCommand(Protocol):
    """Bind a command to a judge-owned structured-report path."""

    def __call__(
        self,
        command: list[str],
        report_path: str,
    ) -> tuple[list[str], bool, dict[str, str]]: ...


class ResolveHostSuiteCommand(Protocol):
    """Resolve one host command at the historical operation site."""

    def __call__(
        self,
        command: list[str],
        *,
        cwd: str,
        env: Mapping[str, str],
    ) -> list[str]: ...


class RunHostSuite(Protocol):
    """Execute one bounded repository suite on the host."""

    def __call__(
        self,
        command: list[str],
        *,
        cwd: str | None,
        env: Mapping[str, str],
        timeout: int,
        preexec_fn: Any,
        require_process_group_cleanup_proof: bool,
    ) -> CompletedSuiteProcess: ...


class RunDockerSuite(Protocol):
    """Execute one repository suite through the existing container facade."""

    def __call__(
        self,
        base_command: list[str],
        candidate_copy: str,
        workdir: str,
    ) -> tuple[str, CompletedSuiteProcess, bool]: ...


class BuildIsolationEvidence(Protocol):
    """Build one repository-suite isolation observation."""

    def __call__(
        self,
        delivered: str,
        image_digest: str | None,
        *,
        note: str | None = None,
    ) -> IsolationObservation: ...


class ProjectIsolationEvidence(Protocol):
    """Project one typed isolation observation to its wire mapping."""

    def __call__(
        self,
        observation: IsolationObservation,
    ) -> dict[str, object]: ...


class ReadJUnitReport(Protocol):
    """Read one bounded judge-owned JUnit file."""

    def __call__(self, path: str) -> str | None: ...


class ParseJUnitReport(Protocol):
    """Parse one JUnit XML document."""

    def __call__(self, text: str) -> JUnitCounts | None: ...


class ParseJUnitReportDirectory(Protocol):
    """Parse one judge-owned JUnit report directory."""

    def __call__(
        self,
        path: str,
    ) -> tuple[JUnitCounts, str] | None: ...


class EvaluateRepoPhase(Protocol):
    """Interpret completed suite evidence through the pure phase contract."""

    def __call__(
        self,
        evidence: CompletedRunEvidence,
        *,
        strict_harness: bool,
    ) -> RepoPhaseResult: ...


@dataclass(frozen=True, slots=True)
class RepoSuiteExecutionRequest:
    """Immutable values present immediately before repository-suite launch."""

    candidate_copy: str
    workdir: str
    files_changed: tuple[str, ...]
    environment: Mapping[str, str]
    container_mode: bool
    resolved_image: str | None
    pack_configured: bool
    setup_isolation: str | None
    strict_harness: bool


@dataclass(frozen=True, slots=True)
class RepoSuiteExecutionServices:
    """Live judge-owned operations required by suite execution."""

    trace: RepoSuiteTrace
    command: Callable[[], list[str]]
    requested_isolation: Callable[[], str]
    timeout: Callable[[], int]
    instrument_command: Callable[[], InstrumentSuiteCommand]
    resolve_host_command: Callable[[], ResolveHostSuiteCommand]
    run_host_suite: Callable[[], RunHostSuite]
    run_docker_suite: Callable[[], RunDockerSuite]
    limits: Callable[[], Any]
    phase_isolation_evidence: Callable[[], BuildIsolationEvidence]
    runtime_evidence: Callable[[], Mapping[str, object]]
    isolation_payload: Callable[[], ProjectIsolationEvidence]
    distill_diagnostics: Callable[[], Callable[[str], str]]
    perf_counter: Callable[[], float]


@dataclass(frozen=True, slots=True)
class RepoSuiteCompleted:
    """Completed process evidence awaiting runtime continuity verification."""

    report_path: str
    returncode: int
    stdout: str
    stderr: str
    report_expected: bool
    elapsed_seconds: float


@dataclass(frozen=True, slots=True)
class RepoSuiteExecutionOutcome:
    """Exactly one terminal result or one completed-suite observation."""

    terminal_result: VerdictResult | None = None
    completed: RepoSuiteCompleted | None = None


@dataclass(frozen=True, slots=True)
class RepoSuiteInterpretationRequest:
    """Completed suite evidence and its effective strict policy."""

    completed: RepoSuiteCompleted
    strict_harness: bool


@dataclass(frozen=True, slots=True)
class RepoSuiteInterpretationServices:
    """Live report and pure interpretation providers."""

    read_report: Callable[[], ReadJUnitReport]
    parse_xml: Callable[[], ParseJUnitReport]
    parse_directory: Callable[[], ParseJUnitReportDirectory]
    evaluate_phase: Callable[[], EvaluateRepoPhase]
    junit_xml_digest_format: Callable[[], str]
    junit_report_set_digest_format: Callable[[], str]


def _terminal(
    *,
    diagnostics: str,
    artifact: dict[str, object],
) -> RepoSuiteExecutionOutcome:
    return RepoSuiteExecutionOutcome(
        terminal_result=VerdictResult(
            passed=False,
            score=0.0,
            diagnostics=diagnostics,
            artifact=artifact,
        )
    )


def execute_repo_suite(
    request: RepoSuiteExecutionRequest,
    *,
    services: RepoSuiteExecutionServices,
) -> RepoSuiteExecutionOutcome:
    """Execute one repository suite and freeze its process observation."""

    trace = services.trace
    trace.execution_phase = "repo_suite"
    base_command = services.command()
    started_at = services.perf_counter()
    try:
        if request.container_mode:
            report_path, process, report_expected = (
                services.run_docker_suite()(
                    base_command,
                    request.candidate_copy,
                    request.workdir,
                )
            )
        else:
            report_path = os.path.join(
                request.workdir,
                "judge-result.xml",
            )
            command, report_expected, report_env = (
                services.instrument_command()(
                    base_command,
                    report_path,
                )
            )
            run_environment = {
                **request.environment,
                **report_env,
            }
            command = services.resolve_host_command()(
                command,
                cwd=request.candidate_copy,
                env=run_environment,
            )
            process = services.run_host_suite()(
                command,
                cwd=request.candidate_copy,
                env=run_environment,
                timeout=services.timeout(),
                preexec_fn=(
                    services.limits()
                    if os.name == "posix"
                    else None
                ),
                require_process_group_cleanup_proof=(
                    request.strict_harness
                ),
            )
    except DockerRunTimeout as exc:
        delivered = (
            services.requested_isolation()
            if exc.container_started
            else "not_run"
        )
        isolation_evidence = services.phase_isolation_evidence()(
            delivered,
            request.resolved_image,
            note=(
                None
                if exc.container_started
                else (
                    "docker client timed out before container start "
                    "was proven"
                )
            ),
        )
        trace.repo_suite_isolation_evidence = isolation_evidence
        if exc.container_started:
            trace.execution_state = "started_incomplete"
            trace.test_command_started = True
            trace.delivered_isolation = services.requested_isolation()
        return _terminal(
            diagnostics=(
                f"test suite timed out after {services.timeout()}s"
            ),
            artifact={
                "elapsed": services.timeout(),
                "files_changed": list(request.files_changed),
                "outcome": "test_timeout",
                "isolation_evidence": services.isolation_payload()(
                    isolation_evidence
                ),
                **services.runtime_evidence(),
            },
        )
    except ProcessOutputLimitExceeded as exc:
        docker_failure = isinstance(exc, DockerRunOutputLimit)
        container_started = bool(
            getattr(exc, "container_started", True)
        )
        delivered = (
            services.requested_isolation()
            if docker_failure and container_started
            else (
                "not_run"
                if docker_failure
                else "subprocess"
            )
        )
        if container_started:
            trace.execution_state = "started_incomplete"
            trace.test_command_started = True
            trace.delivered_isolation = delivered
        trace.repo_suite_isolation_evidence = (
            services.phase_isolation_evidence()(
                delivered,
                request.resolved_image,
                note=(
                    None
                    if container_started
                    else (
                        "docker client output limit was reached before "
                        "container start was proven"
                    )
                ),
            )
        )
        return _terminal(
            diagnostics=f"test suite output was rejected: {exc}",
            artifact={
                "files_changed": list(request.files_changed),
                "outcome": "test_output_limit",
                "setup_isolation": request.setup_isolation,
                **services.runtime_evidence(),
            },
        )
    except ProcessContainmentError as exc:
        docker_failure = isinstance(exc, DockerRunContainmentError)
        container_started = bool(
            getattr(exc, "container_started", True)
        )
        delivered = (
            services.requested_isolation()
            if docker_failure and container_started
            else (
                "not_run"
                if docker_failure
                else "subprocess"
            )
        )
        if container_started:
            trace.execution_state = "started_incomplete"
            trace.test_command_started = True
            trace.delivered_isolation = delivered
        trace.repo_suite_isolation_evidence = (
            services.phase_isolation_evidence()(
                delivered,
                request.resolved_image,
                note=(
                    "docker container cleanup was not proven"
                    if docker_failure
                    else "subprocess cleanup was not proven"
                ),
            )
        )
        return _terminal(
            diagnostics=f"test suite containment failed: {exc}",
            artifact={
                "files_changed": list(request.files_changed),
                "outcome": "runtime_containment_error",
                "setup_isolation": request.setup_isolation,
                **services.runtime_evidence(),
            },
        )
    except subprocess.TimeoutExpired:
        trace.execution_state = "started_incomplete"
        trace.test_command_started = True
        trace.delivered_isolation = "subprocess"
        trace.repo_suite_isolation_evidence = (
            services.phase_isolation_evidence()(
                "subprocess",
                request.resolved_image,
            )
        )
        return _terminal(
            diagnostics=(
                f"test suite timed out after {services.timeout()}s"
            ),
            artifact={
                "elapsed": services.timeout(),
                "files_changed": list(request.files_changed),
                "outcome": "test_timeout",
                **services.runtime_evidence(),
            },
        )
    except FileNotFoundError:
        unavailable_evidence = services.phase_isolation_evidence()(
            (
                "unavailable"
                if request.container_mode
                else "not_run"
            ),
            request.resolved_image,
        )
        trace.repo_suite_isolation_evidence = unavailable_evidence
        return _terminal(
            diagnostics=(
                f"{services.requested_isolation()} isolation requested "
                "but the docker CLI was not found"
                if request.container_mode
                else f"test command not found: {base_command[0]!r}"
            ),
            artifact={
                "files_changed": list(request.files_changed),
                "outcome": (
                    "isolation_unavailable"
                    if request.container_mode
                    else "test_command_unavailable"
                ),
                "setup_isolation": request.setup_isolation,
                "isolation_evidence": (
                    services.isolation_payload()(
                        unavailable_evidence
                    )
                    if request.container_mode
                    else None
                ),
                **services.runtime_evidence(),
            },
        )

    elapsed = services.perf_counter() - started_at
    if request.container_mode and process.returncode == 125:
        unavailable_evidence = services.phase_isolation_evidence()(
            "unavailable",
            request.resolved_image,
        )
        trace.repo_suite_isolation_evidence = unavailable_evidence
        return _terminal(
            diagnostics=(
                f"the {services.requested_isolation()} suite container "
                "could not be started (docker exit 125): "
                + services.distill_diagnostics()(
                    process.stdout + "\n" + process.stderr
                )
            ),
            artifact={
                "files_changed": list(request.files_changed),
                "outcome": "isolation_unavailable",
                "setup_isolation": request.setup_isolation,
                "isolation_evidence": services.isolation_payload()(
                    unavailable_evidence
                ),
                **services.runtime_evidence(),
            },
        )

    isolation_evidence = services.phase_isolation_evidence()(
        (
            services.requested_isolation()
            if request.container_mode
            else "subprocess"
        ),
        request.resolved_image,
    )
    trace.repo_suite_isolation_evidence = isolation_evidence
    if request.container_mode:
        trace.primary_isolation_evidence = isolation_evidence
    trace.execution_state = (
        "started_incomplete"
        if request.pack_configured
        else "completed"
    )
    trace.test_command_started = True
    trace.test_command_completed = True
    trace.delivered_isolation = (
        services.requested_isolation()
        if request.container_mode
        else "subprocess"
    )
    return RepoSuiteExecutionOutcome(
        completed=RepoSuiteCompleted(
            report_path=report_path,
            returncode=process.returncode,
            stdout=process.stdout,
            stderr=process.stderr,
            report_expected=report_expected,
            elapsed_seconds=elapsed,
        )
    )


def interpret_repo_suite(
    request: RepoSuiteInterpretationRequest,
    *,
    services: RepoSuiteInterpretationServices,
) -> RepoPhaseResult:
    """Read and interpret a completed suite after continuity verification."""

    completed = request.completed
    junit_text = services.read_report()(completed.report_path) or ""
    junit = services.parse_xml()(junit_text)
    junit_sha256 = (
        hashlib.sha256(junit_text.encode("utf-8")).hexdigest()
        if junit is not None and junit_text
        else None
    )
    junit_digest_format = (
        services.junit_xml_digest_format()
        if junit_sha256 is not None
        else None
    )
    if junit is None:
        report_set = services.parse_directory()(
            completed.report_path + ".d"
        )
        if report_set is not None:
            junit, junit_sha256 = report_set
            junit_digest_format = (
                services.junit_report_set_digest_format()
            )
    return services.evaluate_phase()(
        CompletedRunEvidence(
            returncode=completed.returncode,
            junit=junit,
            report_expected=completed.report_expected,
            stdout=completed.stdout,
            stderr=completed.stderr,
            junit_text=junit_text,
            junit_sha256=junit_sha256,
            junit_digest_format=junit_digest_format,
        ),
        strict_harness=request.strict_harness,
    )


__all__ = [
    "RepoSuiteCompleted",
    "RepoSuiteExecutionOutcome",
    "RepoSuiteExecutionRequest",
    "RepoSuiteExecutionServices",
    "RepoSuiteInterpretationRequest",
    "RepoSuiteInterpretationServices",
    "execute_repo_suite",
    "interpret_repo_suite",
]
