# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Typed verifier-pack execution and interpretation.

The two public operations are deliberately separate. ``RepoVerifier`` retains
pack-snapshot checks before and after execution, candidate runtime-continuity
checks, sticky repository-suite evidence, final verdict projection, and
workspace cleanup. Effects are resolved through live providers at their
historical call sites.
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
    PackPhaseResult,
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


class RepoPackTrace(Protocol):
    """Trace fields the verifier-pack execution phase may mutate."""

    execution_state: str
    execution_phase: str
    verifier_pack_started: bool
    verifier_pack_completed: bool
    verifier_pack_isolation_evidence: IsolationObservation | None


class CompletedPackProcess(Protocol):
    """Minimal completed-process evidence required by pack policy."""

    returncode: int
    stdout: str
    stderr: str


class InstrumentPackCommand(Protocol):
    """Bind a pack command to a judge-owned structured-report path."""

    def __call__(
        self,
        command: list[str],
        report_path: str,
    ) -> tuple[list[str], bool, dict[str, str]]: ...


class ResolveHostPackCommand(Protocol):
    """Resolve one host command at the historical operation site."""

    def __call__(
        self,
        command: list[str],
        *,
        cwd: str,
        env: Mapping[str, str],
    ) -> list[str]: ...


class RunHostPack(Protocol):
    """Execute one bounded verifier pack on the host."""

    def __call__(
        self,
        command: list[str],
        *,
        cwd: str | None,
        env: Mapping[str, str],
        timeout: int,
        preexec_fn: Any,
        require_process_group_cleanup_proof: bool,
    ) -> CompletedPackProcess: ...


class RunDockerPack(Protocol):
    """Execute one verifier pack through the existing container facade."""

    def __call__(
        self,
        command: list[str],
        candidate_copy: str,
        workdir: str,
        *,
        pack_dir: str | None = None,
    ) -> tuple[str, CompletedPackProcess, bool]: ...


class BuildIsolationEvidence(Protocol):
    """Build one verifier-pack isolation observation."""

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


class ReadPackReport(Protocol):
    """Read one bounded judge-owned verifier-pack JUnit file."""

    def __call__(self, path: str) -> str | None: ...


class ParsePackReport(Protocol):
    """Parse one verifier-pack JUnit XML document."""

    def __call__(self, text: str) -> JUnitCounts | None: ...


class EvaluatePackPhase(Protocol):
    """Interpret completed verifier-pack evidence."""

    def __call__(
        self,
        evidence: CompletedRunEvidence,
    ) -> PackPhaseResult: ...


@dataclass(frozen=True, slots=True)
class RepoPackExecutionRequest:
    """Immutable values present immediately before verifier-pack launch."""

    candidate_copy: str
    workdir: str
    pack_snapshot: str
    files_changed: tuple[str, ...]
    environment: Mapping[str, str]
    container_mode: bool
    resolved_image: str | None
    setup_isolation: str | None
    suite_isolation_evidence: IsolationObservation
    strict_harness: bool


@dataclass(frozen=True, slots=True)
class RepoPackExecutionServices:
    """Live judge-owned operations required by verifier-pack execution."""

    trace: RepoPackTrace
    requested_isolation: Callable[[], str]
    timeout: Callable[[], int]
    python_executable: Callable[[], str]
    instrument_command: Callable[[], InstrumentPackCommand]
    resolve_host_command: Callable[[], ResolveHostPackCommand]
    run_host_pack: Callable[[], RunHostPack]
    run_docker_pack: Callable[[], RunDockerPack]
    limits: Callable[[], Any]
    phase_isolation_evidence: Callable[[], BuildIsolationEvidence]
    runtime_evidence: Callable[[], Mapping[str, object]]
    isolation_payload: Callable[[], ProjectIsolationEvidence]
    distill_diagnostics: Callable[[], Callable[[str], str]]


@dataclass(frozen=True, slots=True)
class RepoPackCompleted:
    """Completed pack-process evidence awaiting continuity verification."""

    report_path: str
    returncode: int
    stdout: str
    stderr: str
    report_expected: bool


@dataclass(frozen=True, slots=True)
class RepoPackExecutionOutcome:
    """Exactly one terminal result or one completed-pack observation."""

    terminal_result: VerdictResult | None = None
    completed: RepoPackCompleted | None = None

    def __post_init__(self) -> None:
        if (self.terminal_result is None) == (self.completed is None):
            raise ValueError(
                "repository pack outcome requires exactly one terminal or completed value"
            )


@dataclass(frozen=True, slots=True)
class RepoPackInterpretationRequest:
    """Completed verifier-pack process evidence."""

    completed: RepoPackCompleted


@dataclass(frozen=True, slots=True)
class RepoPackInterpretationServices:
    """Live judge-owned operations required by pack interpretation."""

    read_report: Callable[[], ReadPackReport]
    parse_xml: Callable[[], ParsePackReport]
    evaluate_phase: Callable[[], EvaluatePackPhase]
    junit_xml_digest_format: Callable[[], str]


def _terminal(
    *,
    diagnostics: str,
    artifact: dict[str, Any],
) -> RepoPackExecutionOutcome:
    return RepoPackExecutionOutcome(
        terminal_result=VerdictResult(
            passed=False,
            score=0.0,
            diagnostics=diagnostics,
            artifact=artifact,
        )
    )


def _suite_isolation_payload(
    request: RepoPackExecutionRequest,
    services: RepoPackExecutionServices,
) -> dict[str, object]:
    return services.isolation_payload()(request.suite_isolation_evidence)


def execute_repo_pack(
    request: RepoPackExecutionRequest,
    *,
    services: RepoPackExecutionServices,
) -> RepoPackExecutionOutcome:
    """Execute one accepted verifier pack and freeze its process observation."""

    trace = services.trace
    trace.execution_phase = "verifier_pack"
    pack_phase = os.path.join(request.workdir, "pack-phase")
    os.makedirs(pack_phase, exist_ok=True)
    pack_test_root = "/verifier-pack" if request.container_mode else request.pack_snapshot
    command = [
        "python" if request.container_mode else services.python_executable(),
        "-m",
        "pytest",
        "-q",
        "--color=no",
        "-p",
        "no:cacheprovider",
        # The pack snapshot is intentionally outside ``cwd=candidate_copy``.
        # This explicit boundary prevents pytest from walking volatile sibling
        # workspaces under their common temporary ancestor.
        f"--confcutdir={pack_test_root}",
        pack_test_root,
    ]
    try:
        if request.container_mode:
            report_path, process, report_expected = services.run_docker_pack()(
                command,
                request.candidate_copy,
                pack_phase,
                pack_dir=request.pack_snapshot,
            )
        else:
            report_path = os.path.join(
                pack_phase,
                "judge-result.xml",
            )
            instrumented, report_expected, report_environment = services.instrument_command()(
                command,
                report_path,
            )
            environment = {
                **request.environment,
                **report_environment,
            }
            instrumented = services.resolve_host_command()(
                instrumented,
                cwd=request.candidate_copy,
                env=environment,
            )
            process = services.run_host_pack()(
                instrumented,
                cwd=request.candidate_copy,
                env=environment,
                timeout=services.timeout(),
                preexec_fn=(services.limits() if os.name == "posix" else None),
                require_process_group_cleanup_proof=(request.strict_harness),
            )
    except DockerRunTimeout as exc:
        delivered = services.requested_isolation() if exc.container_started else "not_run"
        trace.verifier_pack_isolation_evidence = services.phase_isolation_evidence()(
            delivered,
            request.resolved_image,
            note=(
                None
                if exc.container_started
                else ("docker client timed out before container start was proven")
            ),
        )
        if exc.container_started:
            trace.execution_state = "started_incomplete"
            trace.verifier_pack_started = True
        return _terminal(
            diagnostics=(f"verifier pack timed out after {services.timeout()}s"),
            artifact={
                "files_changed": list(request.files_changed),
                "outcome": "test_timeout",
                "setup_isolation": request.setup_isolation,
                "isolation_evidence": _suite_isolation_payload(
                    request,
                    services,
                ),
                **services.runtime_evidence(),
            },
        )
    except ProcessOutputLimitExceeded as exc:
        docker_failure = isinstance(exc, DockerRunOutputLimit)
        container_started = bool(getattr(exc, "container_started", True))
        delivered = (
            services.requested_isolation()
            if docker_failure and container_started
            else ("not_run" if docker_failure else "subprocess")
        )
        if container_started:
            trace.execution_state = "started_incomplete"
            trace.verifier_pack_started = True
        trace.verifier_pack_isolation_evidence = services.phase_isolation_evidence()(
            delivered,
            request.resolved_image,
            note=(
                None
                if container_started
                else ("docker client output limit was reached before container start was proven")
            ),
        )
        return _terminal(
            diagnostics=f"verifier pack output was rejected: {exc}",
            artifact={
                "files_changed": list(request.files_changed),
                "outcome": "test_output_limit",
                "setup_isolation": request.setup_isolation,
                "isolation_evidence": (
                    _suite_isolation_payload(request, services) if request.container_mode else None
                ),
                **services.runtime_evidence(),
            },
        )
    except ProcessContainmentError as exc:
        docker_failure = isinstance(
            exc,
            DockerRunContainmentError,
        )
        container_started = bool(getattr(exc, "container_started", True))
        delivered = (
            services.requested_isolation()
            if docker_failure and container_started
            else ("not_run" if docker_failure else "subprocess")
        )
        if container_started:
            trace.execution_state = "started_incomplete"
            trace.verifier_pack_started = True
        trace.verifier_pack_isolation_evidence = services.phase_isolation_evidence()(
            delivered,
            request.resolved_image,
            note=(
                "docker container cleanup was not proven"
                if docker_failure
                else "subprocess cleanup was not proven"
            ),
        )
        return _terminal(
            diagnostics=f"verifier pack containment failed: {exc}",
            artifact={
                "files_changed": list(request.files_changed),
                "outcome": "runtime_containment_error",
                "setup_isolation": request.setup_isolation,
                "isolation_evidence": (
                    _suite_isolation_payload(request, services) if request.container_mode else None
                ),
                **services.runtime_evidence(),
            },
        )
    except subprocess.TimeoutExpired:
        trace.execution_state = "started_incomplete"
        trace.verifier_pack_started = True
        trace.verifier_pack_isolation_evidence = services.phase_isolation_evidence()(
            "subprocess",
            request.resolved_image,
        )
        return _terminal(
            diagnostics=(f"verifier pack timed out after {services.timeout()}s"),
            artifact={
                "files_changed": list(request.files_changed),
                "outcome": "test_timeout",
                "setup_isolation": request.setup_isolation,
                "isolation_evidence": (
                    _suite_isolation_payload(request, services) if request.container_mode else None
                ),
                **services.runtime_evidence(),
            },
        )
    except FileNotFoundError:
        trace.verifier_pack_isolation_evidence = services.phase_isolation_evidence()(
            ("unavailable" if request.container_mode else "not_run"),
            request.resolved_image,
        )
        return _terminal(
            diagnostics=("verifier pack needs pytest/python in the judge environment"),
            artifact={
                "files_changed": list(request.files_changed),
                "outcome": "test_command_unavailable",
                "setup_isolation": request.setup_isolation,
                "isolation_evidence": (
                    _suite_isolation_payload(request, services) if request.container_mode else None
                ),
                **services.runtime_evidence(),
            },
        )

    if request.container_mode and process.returncode == 125:
        unavailable_evidence = services.phase_isolation_evidence()(
            "unavailable",
            request.resolved_image,
        )
        trace.verifier_pack_isolation_evidence = unavailable_evidence
        return _terminal(
            diagnostics=(
                f"the {services.requested_isolation()} verifier-pack "
                "container could not be started (docker exit 125): "
                + services.distill_diagnostics()(process.stdout + "\n" + process.stderr)
            ),
            artifact={
                "files_changed": list(request.files_changed),
                "outcome": "isolation_unavailable",
                "setup_isolation": request.setup_isolation,
                "isolation_evidence": _suite_isolation_payload(
                    request,
                    services,
                ),
                **services.runtime_evidence(),
            },
        )

    trace.verifier_pack_isolation_evidence = services.phase_isolation_evidence()(
        (services.requested_isolation() if request.container_mode else "subprocess"),
        request.resolved_image,
    )
    trace.execution_state = "completed"
    trace.verifier_pack_started = True
    trace.verifier_pack_completed = True
    return RepoPackExecutionOutcome(
        completed=RepoPackCompleted(
            report_path=report_path,
            returncode=process.returncode,
            stdout=process.stdout,
            stderr=process.stderr,
            report_expected=report_expected,
        )
    )


def interpret_repo_pack(
    request: RepoPackInterpretationRequest,
    *,
    services: RepoPackInterpretationServices,
) -> PackPhaseResult:
    """Read and interpret a completed pack after continuity verification."""

    completed = request.completed
    junit_text = services.read_report()(completed.report_path) or ""
    junit = services.parse_xml()(junit_text)
    junit_sha256 = hashlib.sha256(junit_text.encode("utf-8")).hexdigest() if junit_text else None
    junit_digest_format = services.junit_xml_digest_format() if junit_sha256 is not None else None
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
        )
    )


__all__ = [
    "RepoPackCompleted",
    "RepoPackExecutionOutcome",
    "RepoPackExecutionRequest",
    "RepoPackExecutionServices",
    "RepoPackInterpretationRequest",
    "RepoPackInterpretationServices",
    "execute_repo_pack",
    "interpret_repo_pack",
]
