# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Repository setup-command execution and fidelity verification.

This module owns only the optional setup phase that prepares a candidate copy
before its repository-native suite. It does not own candidate materialization,
runtime-identity capture, suite execution, or verifier-pack execution.

All historical runtime effects are injected as narrow call-through services.
``RepoVerifier`` deliberately resolves those services at their original use
sites so monkeypatch-based adopters retain the same observation order.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from evoom_guard.contracts import VerdictResult
from evoom_guard.domain.execution import IsolationObservation
from evoom_guard.execution import (
    ProcessContainmentError,
    ProcessOutputLimitExceeded,
)
from evoom_guard.isolation import (
    DockerRunContainmentError,
    DockerRunOutputLimit,
    DockerRunTimeout,
)
from evoom_guard.verifiers.fidelity import SetupFidelityError


class SetupExecutionTrace(Protocol):
    """Trace fields the setup phase is permitted to mutate."""

    execution_phase: str
    execution_state: str
    setup_isolation_evidence: IsolationObservation | None


class CompletedSetupProcess(Protocol):
    """Minimal completed-process observation used by setup policy."""

    returncode: int
    stdout: str
    stderr: str


class ResolveHostCommand(Protocol):
    """Resolve one host command at the historical operation site."""

    def __call__(
        self,
        command: list[str],
        *,
        cwd: str,
        env: Mapping[str, str],
    ) -> list[str]: ...


FidelityEntry = tuple[str, int, str]
FidelitySnapshot = dict[str, FidelityEntry]


class CaptureSetupBefore(Protocol):
    """Capture the pre-setup fidelity snapshot."""

    def __call__(
        self,
        root: str,
        output_globs: Sequence[str] = (),
    ) -> FidelitySnapshot: ...


class CaptureSetupAfter(Protocol):
    """Capture the post-setup fidelity snapshot."""

    def __call__(
        self,
        root: str,
        output_globs: Sequence[str],
        *,
        baseline: FidelitySnapshot,
    ) -> FidelitySnapshot: ...


class RunHostSetup(Protocol):
    """Run one bounded host setup command."""

    def __call__(
        self,
        command: list[str],
        *,
        cwd: str | None,
        env: Mapping[str, str],
        timeout: int,
        preexec_fn: Any,
        require_process_group_cleanup_proof: bool,
    ) -> CompletedSetupProcess: ...


class BuildDockerSetupCommand(Protocol):
    """Build the setup container command with a writable candidate copy."""

    def __call__(
        self,
        command: list[str],
        copy: str,
        outdir: str | None,
        name: str,
        *,
        work_writable: bool,
    ) -> list[str]: ...


class RunDockerSetup(Protocol):
    """Run one named setup container."""

    def __call__(
        self,
        command: list[str],
        name: str,
    ) -> CompletedSetupProcess: ...


class BuildIsolationEvidence(Protocol):
    """Build one phase isolation observation."""

    def __call__(
        self,
        delivered: str,
        image_digest: str | None,
        *,
        note: str | None = None,
    ) -> IsolationObservation: ...


@dataclass(frozen=True, slots=True)
class RepoSetupRequest:
    """Immutable inputs to one optional repository setup phase."""

    configured_command: str | Sequence[object] | None
    candidate_copy: str
    files_changed: tuple[str, ...]
    environment: Mapping[str, str]
    container_mode: bool
    requested_isolation: str
    trust_setup_on_host: bool
    setup_output_globs: tuple[str, ...]
    timeout: int
    strict_harness: bool
    resolved_image: str | None
    docker_network: str
    docker_runtime: str | None


@dataclass(frozen=True, slots=True)
class RepoSetupServices:
    """Live judge-owned effects needed by setup execution."""

    trace: SetupExecutionTrace
    resolve_host_command: ResolveHostCommand
    capture_setup_before: CaptureSetupBefore
    capture_setup_after: CaptureSetupAfter
    setup_fidelity_changes: Callable[[FidelitySnapshot, FidelitySnapshot], list[str]]
    run_host_setup: RunHostSetup
    container_name: Callable[[str], str]
    build_docker_command: BuildDockerSetupCommand
    run_docker_setup: RunDockerSetup
    limits: Callable[[], Any]
    phase_isolation_evidence: BuildIsolationEvidence
    distill_diagnostics: Callable[[str], str]


@dataclass(frozen=True, slots=True)
class RepoSetupOutcome:
    """Immutable result of the optional setup phase."""

    requested: bool
    setup_isolation: str | None = None
    terminal_result: VerdictResult | None = None


def _artifact(
    request: RepoSetupRequest,
    *,
    outcome: str,
    setup_isolation: str | None,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "files_changed": list(request.files_changed),
        "outcome": outcome,
        "setup_isolation": setup_isolation,
        **extra,
    }


def _terminal(
    request: RepoSetupRequest,
    *,
    diagnostics: str,
    outcome: str,
    setup_isolation: str | None,
    score: float = 0.0,
    **artifact: Any,
) -> RepoSetupOutcome:
    return RepoSetupOutcome(
        requested=True,
        setup_isolation=setup_isolation,
        terminal_result=VerdictResult(
            passed=False,
            score=score,
            diagnostics=diagnostics,
            artifact=_artifact(
                request,
                outcome=outcome,
                setup_isolation=setup_isolation,
                **artifact,
            ),
        ),
    )


def execute_repo_setup(
    request: RepoSetupRequest,
    *,
    services: RepoSetupServices,
) -> RepoSetupOutcome:
    """Execute and verify the configured setup command, failing closed."""

    setup_cmd_raw = request.configured_command
    if not setup_cmd_raw:
        return RepoSetupOutcome(requested=False)

    trace = services.trace
    trace.execution_phase = "setup"
    if isinstance(setup_cmd_raw, str):
        setup_cmd_raw = setup_cmd_raw.split()
    setup_tokens = [str(token) for token in setup_cmd_raw]
    setup_in_container = request.container_mode and not request.trust_setup_on_host
    setup_name: str | None = None
    if setup_in_container:
        setup_isolation: str | None = request.requested_isolation
        setup_name = services.container_name("setup")
        setup_run_cmd = services.build_docker_command(
            setup_tokens,
            request.candidate_copy,
            None,
            setup_name,
            work_writable=True,
        )
        setup_cwd = None
        setup_env = os.environ.copy()
    else:
        setup_isolation = "subprocess_host_opt_in" if request.container_mode else "subprocess"
        setup_run_cmd = setup_tokens
        setup_cwd = request.candidate_copy
        setup_env = dict(request.environment)
        setup_run_cmd = services.resolve_host_command(
            setup_run_cmd,
            cwd=setup_cwd,
            env=setup_env,
        )

    try:
        setup_before = services.capture_setup_before(
            request.candidate_copy,
            request.setup_output_globs,
        )
    except SetupFidelityError as exc:
        return _terminal(
            request,
            diagnostics=f"setup fidelity snapshot failed: {exc}",
            outcome="setup_failed",
            setup_isolation=None,
        )

    try:
        if setup_in_container:
            assert setup_name is not None
            r_setup = services.run_docker_setup(setup_run_cmd, setup_name)
        else:
            r_setup = services.run_host_setup(
                setup_run_cmd,
                cwd=setup_cwd,
                env=setup_env,
                timeout=request.timeout,
                preexec_fn=(services.limits() if os.name == "posix" else None),
                require_process_group_cleanup_proof=request.strict_harness,
            )
    except DockerRunTimeout as exc:
        delivered = request.requested_isolation if exc.container_started else "not_run"
        trace.setup_isolation_evidence = services.phase_isolation_evidence(
            delivered,
            request.resolved_image,
            note=(
                None
                if exc.container_started
                else "docker client timed out before container start was proven"
            ),
        )
        if exc.container_started:
            trace.execution_state = "started_incomplete"
            setup_isolation = request.requested_isolation
        else:
            setup_isolation = None
        return _terminal(
            request,
            diagnostics=f"setup command timed out after {request.timeout}s",
            outcome="setup_timeout",
            setup_isolation=setup_isolation,
            elapsed=request.timeout,
        )
    except ProcessOutputLimitExceeded as exc:
        docker_failure = isinstance(exc, DockerRunOutputLimit)
        container_started = bool(getattr(exc, "container_started", True))
        delivered = (
            request.requested_isolation
            if docker_failure and container_started
            else ("not_run" if docker_failure else (setup_isolation or "subprocess"))
        )
        reported_setup_isolation = (
            request.requested_isolation
            if docker_failure and container_started
            else (None if docker_failure else setup_isolation)
        )
        if container_started:
            trace.execution_state = "started_incomplete"
        trace.setup_isolation_evidence = services.phase_isolation_evidence(
            delivered,
            request.resolved_image,
            note=(
                None
                if container_started
                else ("docker client output limit was reached before container start was proven")
            ),
        )
        return _terminal(
            request,
            diagnostics=f"setup command output was rejected: {exc}",
            outcome="setup_output_limit",
            setup_isolation=reported_setup_isolation,
        )
    except ProcessContainmentError as exc:
        docker_failure = isinstance(exc, DockerRunContainmentError)
        container_started = bool(getattr(exc, "container_started", True))
        delivered = (
            request.requested_isolation
            if docker_failure and container_started
            else ("not_run" if docker_failure else (setup_isolation or "subprocess"))
        )
        reported_setup_isolation = (
            request.requested_isolation
            if docker_failure and container_started
            else (None if docker_failure else setup_isolation)
        )
        if container_started:
            trace.execution_state = "started_incomplete"
        trace.setup_isolation_evidence = services.phase_isolation_evidence(
            delivered,
            request.resolved_image,
            note=(
                "docker container cleanup was not proven"
                if docker_failure
                else "subprocess cleanup was not proven"
            ),
        )
        return _terminal(
            request,
            diagnostics=f"setup command containment failed: {exc}",
            outcome="runtime_containment_error",
            setup_isolation=reported_setup_isolation,
        )
    except subprocess.TimeoutExpired:
        trace.execution_state = "started_incomplete"
        trace.setup_isolation_evidence = services.phase_isolation_evidence(
            setup_isolation or "subprocess",
            request.resolved_image,
        )
        return _terminal(
            request,
            diagnostics=f"setup command timed out after {request.timeout}s",
            outcome="setup_timeout",
            setup_isolation=setup_isolation,
            elapsed=request.timeout,
        )
    except FileNotFoundError:
        trace.setup_isolation_evidence = services.phase_isolation_evidence(
            "unavailable" if setup_in_container else "not_run",
            request.resolved_image,
        )
        return _terminal(
            request,
            diagnostics=(
                f"{request.requested_isolation} isolation requested but the "
                "docker CLI was not found while starting setup_command"
                if setup_in_container
                else f"setup command not found: {setup_tokens[0]!r}"
            ),
            outcome="setup_failed",
            setup_isolation=None,
        )

    if setup_in_container and r_setup.returncode == 125:
        diag = services.distill_diagnostics(r_setup.stdout + "\n" + r_setup.stderr)
        trace.setup_isolation_evidence = services.phase_isolation_evidence(
            "unavailable",
            request.resolved_image,
        )
        return _terminal(
            request,
            diagnostics=(
                f"the {request.requested_isolation} setup container could not "
                f"be started (docker exit 125): {diag}"
            ),
            outcome="isolation_unavailable",
            setup_isolation="unavailable",
            isolation_evidence={
                "requested": request.requested_isolation,
                "delivered": "unavailable",
                "image_digest": request.resolved_image,
                "network": request.docker_network,
                "runtime": request.docker_runtime,
            },
        )

    trace.execution_state = "started_incomplete"
    trace.setup_isolation_evidence = services.phase_isolation_evidence(
        setup_isolation or request.requested_isolation,
        request.resolved_image,
    )
    if r_setup.returncode != 0:
        diag = services.distill_diagnostics(r_setup.stdout + "\n" + r_setup.stderr)
        hint = (
            " (setup ran inside the container: the image must contain "
            "the setup tool, and --docker-network none blocks registries)"
            if setup_in_container
            else ""
        )
        return _terminal(
            request,
            diagnostics=(f"setup command failed (exit {r_setup.returncode}){hint}: {diag}"),
            outcome="setup_failed",
            setup_isolation=setup_isolation,
        )

    try:
        setup_after = services.capture_setup_after(
            request.candidate_copy,
            request.setup_output_globs,
            baseline=setup_before,
        )
    except SetupFidelityError as exc:
        return _terminal(
            request,
            diagnostics=f"setup fidelity verification failed: {exc}",
            outcome="setup_failed",
            setup_isolation=setup_isolation,
        )

    setup_changes = services.setup_fidelity_changes(
        setup_before,
        setup_after,
    )
    if setup_changes:
        return _terminal(
            request,
            diagnostics=(
                "setup_command modified the judged source/harness outside "
                "declared setup outputs — refusing to run a suite against "
                "a tree different from the candidate: " + ", ".join(setup_changes[:20])
            ),
            outcome="setup_failed",
            setup_isolation=setup_isolation,
            setup_fidelity_changes=setup_changes,
        )

    return RepoSetupOutcome(
        requested=True,
        setup_isolation=setup_isolation,
    )


__all__ = [
    "RepoSetupOutcome",
    "RepoSetupRequest",
    "RepoSetupServices",
    "execute_repo_setup",
]
