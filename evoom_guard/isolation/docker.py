"""Typed Docker control, identity, and cleanup contracts.

This module deliberately contains no verdict or assurance policy.  It records
bounded Docker control-plane facts and enforces daemon-side cleanup invariants;
the repository verifier, black-box judge, and candidate runner adapt those
facts to their historical diagnostics and public results.
"""

from __future__ import annotations

import math
import os
import re
import secrets
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from evoom_guard.execution import (
    ProcessContainmentError,
    ProcessOutputLimitExceeded,
    run_bounded_subprocess,
)

DOCKER_CONTROL_TIMEOUT_SECONDS = 30.0
DOCKER_PULL_TIMEOUT_SECONDS = 600.0
DOCKER_CLEANUP_RECONCILE_ATTEMPTS = 10
DOCKER_CLEANUP_RECONCILE_INTERVAL_SECONDS = 0.05
DOCKER_CLEANUP_REQUIRED_FINAL_ABSENT_OBSERVATIONS = 3
DOCKER_CLEANUP_TOTAL_TIMEOUT_SECONDS = 10.0

_DOCKER_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
_DOCKER_CONTAINER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")


class BoundedProcessRunner(Protocol):
    """Callable boundary used to run one bounded native process."""

    def __call__(
        self,
        command: list[str],
        *,
        cwd: str | None,
        env: dict[str, str] | None,
        timeout: float,
    ) -> subprocess.CompletedProcess[str]: ...


class DockerControlRunner(Protocol):
    """Callable boundary for one already-adapted Docker control command."""

    def __call__(
        self, command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]: ...


class ContainerStartedProbe(Protocol):
    def __call__(self, name: str) -> bool: ...


class ContainerCleanup(Protocol):
    def __call__(self, name: str) -> bool: ...


class ContainerAbsenceProbe(Protocol):
    def __call__(
        self, name: str, *, timeout: float
    ) -> DockerContainerAbsenceObservation: ...


class CidScanner(Protocol):
    def __call__(self, cidfile_dir: str, /) -> DockerCidScanResult: ...


@dataclass(frozen=True, slots=True)
class DockerControlRequest:
    """Complete input contract for one bounded Docker control command."""

    command: tuple[str, ...]
    timeout_seconds: float
    environment: Mapping[str, str] | None = None

    @classmethod
    def from_command(
        cls,
        command: Sequence[str],
        *,
        timeout: float,
        environment: Mapping[str, str] | None = None,
    ) -> DockerControlRequest:
        return cls(tuple(command), timeout, environment)

    def __post_init__(self) -> None:
        if not self.command or any(not isinstance(part, str) for part in self.command):
            raise ValueError("Docker control command must contain string argv elements")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds < 0
        ):
            raise ValueError("Docker control timeout must be finite and non-negative")


@dataclass(frozen=True, slots=True)
class DockerControlResult:
    """Bounded Docker control facts independent of ``subprocess`` policy."""

    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @classmethod
    def from_completed(
        cls,
        completed: subprocess.CompletedProcess[str],
        *,
        command: Sequence[str] | None = None,
    ) -> DockerControlResult:
        completed_args = completed.args
        if command is not None:
            normalized_command = tuple(command)
        elif isinstance(completed_args, str):
            normalized_command = (completed_args,)
        else:
            normalized_command = tuple(str(part) for part in completed_args)
        return cls(
            command=normalized_command,
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )

    def as_completed_process(
        self,
        *,
        args: str | Sequence[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Adapt the facts while optionally preserving a caller's argv object."""

        completed_args: str | Sequence[str]
        completed_args = list(self.command) if args is None else args
        return subprocess.CompletedProcess(
            completed_args,
            self.returncode,
            stdout=self.stdout,
            stderr=self.stderr,
        )


def execute_docker_control(
    request: DockerControlRequest,
    *,
    process_runner: BoundedProcessRunner = run_bounded_subprocess,
    process_argv: list[str] | None = None,
) -> DockerControlResult:
    """Execute one Docker control command through bounded process capture."""

    argv = list(request.command) if process_argv is None else process_argv
    if tuple(argv) != request.command:
        raise ValueError("process argv must match the Docker control request")
    environment = (
        dict(os.environ)
        if request.environment is None
        else dict(request.environment)
    )
    completed = process_runner(
        argv,
        cwd=None,
        env=environment,
        timeout=request.timeout_seconds,
    )
    return DockerControlResult.from_completed(
        completed,
        command=request.command,
    )


@dataclass(frozen=True, slots=True)
class DockerImageResolution:
    """Docker image-inspection and optional pull facts for one mutable reference."""

    requested_image: str
    initial_inspection: DockerControlResult
    pull: DockerControlResult | None
    final_inspection: DockerControlResult | None
    image_id: str | None

    @property
    def pull_attempted(self) -> bool:
        return self.pull is not None


def _control_result(
    runner: DockerControlRunner,
    command: list[str],
    *,
    timeout: float,
) -> DockerControlResult:
    return DockerControlResult.from_completed(
        runner(command, timeout=timeout),
        command=command,
    )


def inspect_docker_image(
    image: str,
    *,
    control_runner: DockerControlRunner,
    timeout: float = DOCKER_CONTROL_TIMEOUT_SECONDS,
) -> DockerControlResult:
    """Return bounded identity-inspection facts without changing daemon state."""

    return _control_result(
        control_runner,
        [
            "docker",
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            image,
        ],
        timeout=timeout,
    )


def resolve_docker_image(
    image: str,
    *,
    control_runner: DockerControlRunner,
    pull_when_inspection_empty: bool,
    control_timeout: float = DOCKER_CONTROL_TIMEOUT_SECONDS,
    pull_timeout: float = DOCKER_PULL_TIMEOUT_SECONDS,
) -> DockerImageResolution:
    """Inspect, optionally pull, and re-inspect one Docker image reference.

    ``pull_when_inspection_empty`` is explicit because the two historical
    callers have intentionally different policies: the candidate runner treats
    an empty successful inspection as missing, whereas ``RepoVerifier`` treats
    it as an unresolved identity and fails without a network-changing pull.
    """

    initial = inspect_docker_image(
        image,
        control_runner=control_runner,
        timeout=control_timeout,
    )
    initial_id = initial.stdout.strip() if initial.returncode == 0 else ""
    if initial_id:
        return DockerImageResolution(image, initial, None, None, initial_id)

    should_pull = initial.returncode != 0 or pull_when_inspection_empty
    if not should_pull:
        return DockerImageResolution(image, initial, None, None, None)

    pull = _control_result(
        control_runner,
        ["docker", "pull", image],
        timeout=pull_timeout,
    )
    if pull.returncode != 0:
        return DockerImageResolution(image, initial, pull, None, None)

    final = inspect_docker_image(
        image,
        control_runner=control_runner,
        timeout=control_timeout,
    )
    final_id = final.stdout.strip() if final.returncode == 0 else ""
    return DockerImageResolution(
        image,
        initial,
        pull,
        final,
        final_id or None,
    )


def docker_container_name(
    stage: str,
    *,
    token_hex: Callable[[int], str] = secrets.token_hex,
) -> str:
    """Return a shell-safe collision-resistant name for a Docker run."""

    safe_stage = re.sub(r"[^a-zA-Z0-9_.-]+", "-", stage).strip("-.") or "run"
    return f"evoguard_{safe_stage[:32]}_{token_hex(8)}"


def _valid_docker_container_name(name: str) -> bool:
    return _DOCKER_CONTAINER_NAME.fullmatch(name) is not None


@dataclass(frozen=True, slots=True)
class DockerContainerProbe:
    """Fail-closed observation of one named container state."""

    name: str
    proven: bool
    inspection: DockerControlResult | None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class DockerContainerAbsenceObservation:
    """One exact-name absence observation with an explicit unknown state.

    ``absent`` is ``True`` only after a successful Docker enumeration omitted
    the exact validated name, ``False`` when that enumeration contained it,
    and ``None`` when Docker could not provide trustworthy evidence.
    """

    name: str
    absent: bool | None
    query: DockerControlResult | None
    error: str | None = None

    @property
    def proven(self) -> bool:
        return self.absent is True

    @property
    def observed(self) -> bool:
        return self.absent is not None


def probe_container_started(
    name: str,
    *,
    control_runner: DockerControlRunner,
    timeout: float = DOCKER_CONTROL_TIMEOUT_SECONDS,
) -> DockerContainerProbe:
    """Prove a named container has a non-zero Docker ``StartedAt`` value."""

    try:
        inspected = _control_result(
            control_runner,
            ["docker", "inspect", "--format", "{{.State.StartedAt}}", name],
            timeout=timeout,
        )
    except BaseException as exc:
        return DockerContainerProbe(name, False, None, type(exc).__name__)
    started_at = inspected.stdout.strip()
    proven = bool(
        inspected.returncode == 0
        and started_at
        and started_at not in {"<no value>", "0001-01-01T00:00:00Z"}
    )
    return DockerContainerProbe(name, proven, inspected)


def probe_container_absent(
    name: str,
    *,
    control_runner: DockerControlRunner,
    timeout: float = DOCKER_CONTROL_TIMEOUT_SECONDS,
) -> DockerContainerAbsenceObservation:
    """Obtain positive, exact-name absence evidence from Docker.

    ``docker inspect`` cannot distinguish not-found from daemon, authorization,
    client, and transport failures by status alone.  A successful bounded
    enumeration is therefore required.  The server-side filter limits output;
    the local exact-line comparison remains authoritative because Docker name
    filters are not exact-match contracts.
    """

    if not _valid_docker_container_name(name):
        return DockerContainerAbsenceObservation(
            name=name,
            absent=None,
            query=None,
            error="invalid_container_name",
        )

    try:
        listed = _control_result(
            control_runner,
            [
                "docker",
                "container",
                "ls",
                "--all",
                "--filter",
                f"name={name}",
                "--format",
                "{{.Names}}",
            ],
            timeout=timeout,
        )
    except BaseException as exc:
        return DockerContainerAbsenceObservation(
            name=name,
            absent=None,
            query=None,
            error=type(exc).__name__,
        )
    if listed.returncode != 0:
        return DockerContainerAbsenceObservation(
            name=name,
            absent=None,
            query=listed,
            error="docker_query_failed",
        )
    return DockerContainerAbsenceObservation(
        name=name,
        absent=name not in listed.stdout.splitlines(),
        query=listed,
    )


@dataclass(frozen=True, slots=True)
class DockerContainerCleanupResult:
    """Bounded removal attempts and exact-name absence observations."""

    name: str
    removals: tuple[DockerControlResult, ...]
    observations: tuple[DockerContainerAbsenceObservation, ...]
    proven_absent: bool
    error: str | None = None

    @property
    def removal(self) -> DockerControlResult | None:
        """First removal attempt, retained as a compatibility view."""

        return self.removals[0] if self.removals else None

    @property
    def absence(self) -> DockerContainerAbsenceObservation | None:
        """Final observation, retained as a compatibility view."""

        return self.observations[-1] if self.observations else None


def cleanup_named_container(
    name: str,
    *,
    control_runner: DockerControlRunner,
    control_timeout: float = DOCKER_CONTROL_TIMEOUT_SECONDS,
    total_timeout: float = DOCKER_CLEANUP_TOTAL_TIMEOUT_SECONDS,
    reconcile_attempts: int = DOCKER_CLEANUP_RECONCILE_ATTEMPTS,
    reconcile_interval: float = DOCKER_CLEANUP_RECONCILE_INTERVAL_SECONDS,
    required_final_absent_observations: int = (
        DOCKER_CLEANUP_REQUIRED_FINAL_ABSENT_OBSERVATIONS
    ),
    absence_probe: ContainerAbsenceProbe | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> DockerContainerCleanupResult:
    """Force-remove a named container and prove bounded stable absence.

    A single monotonic deadline bounds all removal and observation commands.
    Unverifiable observations fail immediately; removal is retried only after
    Docker positively reports that the exact container name is present.  The
    final consecutive-absence requirement catches late daemon-side creation
    within the reconciliation window without claiming permanent future absence.
    """

    for label, value, allow_zero in (
        ("control_timeout", control_timeout, False),
        ("total_timeout", total_timeout, False),
        ("reconcile_interval", reconcile_interval, True),
    ):
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < 0
            or (not allow_zero and value == 0)
        ):
            qualifier = "non-negative" if allow_zero else "positive"
            raise ValueError(f"{label} must be finite and {qualifier}")
    if (
        isinstance(reconcile_attempts, bool)
        or not isinstance(reconcile_attempts, int)
        or reconcile_attempts < 1
    ):
        raise ValueError("reconcile_attempts must be a positive integer")
    if (
        isinstance(required_final_absent_observations, bool)
        or not isinstance(required_final_absent_observations, int)
        or required_final_absent_observations < 1
        or required_final_absent_observations > reconcile_attempts
    ):
        raise ValueError(
            "required_final_absent_observations must be between 1 and "
            "reconcile_attempts"
        )

    if not _valid_docker_container_name(name):
        return DockerContainerCleanupResult(
            name=name,
            removals=(),
            observations=(),
            proven_absent=False,
            error="invalid_container_name",
        )

    deadline = monotonic() + total_timeout
    removals: list[DockerControlResult] = []
    observations: list[DockerContainerAbsenceObservation] = []

    def result(proven: bool, error: str | None = None) -> DockerContainerCleanupResult:
        return DockerContainerCleanupResult(
            name=name,
            removals=tuple(removals),
            observations=tuple(observations),
            proven_absent=proven,
            error=error,
        )

    def remaining_timeout() -> float | None:
        remaining = deadline - monotonic()
        if remaining <= 0:
            return None
        return min(control_timeout, remaining)

    def remove() -> str | None:
        timeout = remaining_timeout()
        if timeout is None:
            return "cleanup_deadline_exhausted"
        try:
            removal = _control_result(
                control_runner,
                ["docker", "rm", "-f", name],
                timeout=timeout,
            )
        except BaseException as exc:
            return type(exc).__name__
        removals.append(removal)
        return None

    removal_error = remove()
    if removal_error is not None:
        return result(False, removal_error)

    final_absent_observations = 0
    for attempt in range(reconcile_attempts):
        timeout = remaining_timeout()
        if timeout is None:
            return result(False, "cleanup_deadline_exhausted")
        if absence_probe is None:
            observation = probe_container_absent(
                name,
                control_runner=control_runner,
                timeout=timeout,
            )
        else:
            # Preserve cancellation at an explicitly injected test/caller seam.
            # The built-in probe converts control-plane failures into a typed,
            # fail-closed unknown observation.
            observation = absence_probe(name, timeout=timeout)
        observations.append(observation)
        if not observation.observed:
            return result(False, observation.error or "absence_unverifiable")
        if observation.proven:
            final_absent_observations += 1
        else:
            final_absent_observations = 0
            removal_error = remove()
            if removal_error is not None:
                return result(False, removal_error)
        if attempt + 1 < reconcile_attempts:
            remaining = deadline - monotonic()
            if remaining <= 0:
                return result(False, "cleanup_deadline_exhausted")
            sleeper(min(reconcile_interval, remaining))

    proven = (
        final_absent_observations
        >= required_final_absent_observations
    )
    return result(proven, None if proven else "absence_not_stable")


class DockerRunOutputLimit(ProcessOutputLimitExceeded):
    """A bounded Docker client overflowed after optional container start."""

    def __init__(
        self,
        output_error: ProcessOutputLimitExceeded,
        *,
        container_started: bool,
    ) -> None:
        super().__init__(output_error.limit)
        self.container_started = container_started


class DockerRunContainmentError(ProcessContainmentError):
    """Docker client/container cleanup could not be proven after a failure."""

    def __init__(self, message: str, *, container_started: bool) -> None:
        super().__init__(message)
        self.container_started = container_started


class DockerRunTimeout(subprocess.TimeoutExpired):
    """Docker CLI timeout with independent container-start evidence."""

    def __init__(
        self,
        timeout: subprocess.TimeoutExpired,
        *,
        container_started: bool,
    ) -> None:
        super().__init__(
            timeout.cmd,
            timeout.timeout,
            output=timeout.output,
            stderr=timeout.stderr,
        )
        self.container_started = container_started


@dataclass(frozen=True, slots=True)
class DockerRunRequest:
    """Complete input contract for one named ``docker run`` client."""

    command: tuple[str, ...]
    name: str
    timeout_seconds: float
    environment: Mapping[str, str]

    @classmethod
    def from_command(
        cls,
        command: Sequence[str],
        *,
        name: str,
        timeout: float,
        environment: Mapping[str, str],
    ) -> DockerRunRequest:
        return cls(tuple(command), name, timeout, environment)


def run_named_docker_client(
    request: DockerRunRequest,
    *,
    process_runner: BoundedProcessRunner,
    container_started: ContainerStartedProbe,
    cleanup_container: ContainerCleanup,
    process_argv: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one named container and enforce cleanup on every uncertain exit."""

    argv = list(request.command) if process_argv is None else process_argv
    if tuple(argv) != request.command:
        raise ValueError("process argv must match the Docker run request")

    try:
        result = process_runner(
            argv,
            cwd=None,
            env=dict(request.environment),
            timeout=request.timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        started = container_started(request.name)
        if not cleanup_container(request.name):
            raise DockerRunContainmentError(
                "docker client timed out and named container cleanup was not proven",
                container_started=started,
            ) from exc
        raise DockerRunTimeout(exc, container_started=started) from exc
    except ProcessOutputLimitExceeded as exc:
        started = container_started(request.name)
        if not cleanup_container(request.name):
            raise DockerRunContainmentError(
                "docker client exceeded the output limit and named container "
                "cleanup was not proven",
                container_started=started,
            ) from exc
        raise DockerRunOutputLimit(exc, container_started=started) from exc
    except ProcessContainmentError as exc:
        started = container_started(request.name)
        cleaned = cleanup_container(request.name)
        suffix = (
            "was not proven"
            if not cleaned
            else "was attempted after client failure"
        )
        raise DockerRunContainmentError(
            f"{exc}; docker named-container cleanup {suffix}",
            container_started=started,
        ) from exc
    except BaseException:
        cleanup_container(request.name)
        raise

    if result.returncode != 0:
        started = container_started(request.name)
        if not cleanup_container(request.name):
            raise DockerRunContainmentError(
                "docker client returned a non-zero exit and named container "
                "cleanup was not proven",
                container_started=started,
            )
    return result


@dataclass(frozen=True, slots=True)
class DockerCidScanResult:
    """Validated IDs and bounded scan/read failures from judge-owned cidfiles."""

    container_ids: tuple[str, ...]
    failures: tuple[str, ...] = ()


def scan_candidate_container_ids(cidfile_dir: str) -> DockerCidScanResult:
    """Read only regular, non-symlink cidfiles containing genuine Docker IDs."""

    try:
        entries = sorted(os.scandir(cidfile_dir), key=lambda entry: entry.name)
    except OSError as exc:
        return DockerCidScanResult(
            (),
            (f"could not scan candidate cidfile directory {cidfile_dir}: {exc}",),
        )

    container_ids: list[str] = []
    failures: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        if not entry.name.endswith(".cid"):
            continue
        try:
            if not entry.is_file(follow_symlinks=False):
                continue
            with open(entry.path, encoding="ascii") as cidfile:
                raw = cidfile.read(129)
        except (OSError, UnicodeError) as exc:
            failures.append(f"could not read candidate cidfile {entry.path}: {exc}")
            continue
        if len(raw) > 128:
            continue
        container_id = raw.strip()
        if not _DOCKER_CONTAINER_ID.fullmatch(container_id):
            continue
        if container_id not in seen:
            seen.add(container_id)
            container_ids.append(container_id)
    return DockerCidScanResult(tuple(container_ids), tuple(failures))


@dataclass(frozen=True, slots=True)
class DockerCandidateCleanupRequest:
    """Inputs for the bounded candidate-container cleanup backstop."""

    cidfile_dir: str
    wait_for_late_cidfiles: bool = False
    known_container_ids: frozenset[str] = frozenset()
    control_timeout_seconds: float = DOCKER_CONTROL_TIMEOUT_SECONDS


@dataclass(frozen=True, slots=True)
class DockerCandidateCleanupResult:
    """Every attempted valid ID plus failures that prevent absence proof."""

    attempted_container_ids: tuple[str, ...]
    failures: tuple[str, ...]

    @property
    def cleanup_proven(self) -> bool:
        return not self.failures


def cleanup_candidate_containers(
    request: DockerCandidateCleanupRequest,
    *,
    scanner: CidScanner,
    control_runner: DockerControlRunner,
    sleeper: Callable[[float], None] = time.sleep,
    path_exists: Callable[[str], bool] = os.path.lexists,
) -> DockerCandidateCleanupResult:
    """Remove every observed candidate container and prove each is absent."""

    known = set(request.known_container_ids)
    if not path_exists(request.cidfile_dir) and not known:
        return DockerCandidateCleanupResult((), ())

    attempts = 10 if request.wait_for_late_cidfiles else 1
    attempted: set[str] = set()
    failures: list[str] = []

    def container_present(container_id: str) -> bool:
        probe = control_runner(
            [
                "docker",
                "ps",
                "-aq",
                "--no-trunc",
                "--filter",
                f"id={container_id}",
            ],
            timeout=request.control_timeout_seconds,
        )
        if probe.returncode != 0:
            detail = (probe.stderr or probe.stdout).strip()[:200]
            raise _CandidateContainerOperationError(
                f"could not inspect candidate container {container_id}: "
                f"{detail or 'docker ps failed'}"
            )
        return container_id in {
            line.strip() for line in probe.stdout.splitlines()
        }

    for attempt in range(attempts):
        scanned = scanner(request.cidfile_dir)
        failures.extend(f"cidfile scan: {failure}" for failure in scanned.failures)
        for container_id in sorted(known | set(scanned.container_ids)):
            if container_id in attempted:
                continue
            attempted.add(container_id)
            try:
                if not container_present(container_id):
                    continue
                removal = control_runner(
                    ["docker", "rm", "-f", container_id],
                    timeout=request.control_timeout_seconds,
                )
                if removal.returncode != 0:
                    detail = (removal.stderr or removal.stdout).strip()[:200]
                    raise _CandidateContainerOperationError(
                        "docker rm -f failed for candidate container "
                        f"{container_id}: "
                        f"{detail or f'exit {removal.returncode}'}"
                    )
                if container_present(container_id):
                    raise _CandidateContainerOperationError(
                        f"candidate container {container_id} remained after "
                        "docker rm -f"
                    )
            except (
                OSError,
                subprocess.SubprocessError,
                _CandidateContainerOperationError,
                ProcessOutputLimitExceeded,
                ProcessContainmentError,
            ) as exc:
                failures.append(f"{container_id}: {exc}")
        if attempt + 1 < attempts:
            sleeper(0.05)

    return DockerCandidateCleanupResult(
        tuple(sorted(attempted)),
        tuple(failures),
    )


class _CandidateContainerOperationError(RuntimeError):
    """Internal typed-kernel signal adapted by the black-box facade."""
