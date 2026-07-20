"""Direct contracts for the extracted Docker isolation kernel."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import evoom_guard.blackbox as blackbox
import evoom_guard.candidate_runner as candidate_runner
import evoom_guard.verifiers.repo_verifier as repo_verifier
from evoom_guard.candidate_runner import CandidateRunner
from evoom_guard.execution import (
    ProcessContainmentError,
    ProcessOutputLimitExceeded,
)
from evoom_guard.isolation import (
    DOCKER_CLEANUP_RECONCILE_ATTEMPTS,
    DOCKER_CONTROL_TIMEOUT_SECONDS,
    DOCKER_PULL_TIMEOUT_SECONDS,
    DockerCandidateCleanupRequest,
    DockerCidScanResult,
    DockerContainerAbsenceObservation,
    DockerControlRequest,
    DockerRunContainmentError,
    DockerRunOutputLimit,
    DockerRunRequest,
    DockerRunTimeout,
    cleanup_candidate_containers,
    cleanup_named_container,
    docker_container_name,
    execute_docker_control,
    probe_container_absent,
    probe_container_started,
    resolve_docker_image,
    run_named_docker_client,
    scan_candidate_container_ids,
)


def _completed(
    command: list[str],
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def test_docker_control_request_uses_bounded_process_contract() -> None:
    observed: dict[str, object] = {}

    def process_runner(
        command: list[str],
        *,
        cwd: str | None,
        env: dict[str, str] | None,
        timeout: float,
    ) -> subprocess.CompletedProcess[str]:
        observed.update(
            command=command,
            cwd=cwd,
            env=env,
            timeout=timeout,
        )
        return _completed(command, 17, "bounded-out", "bounded-err")

    request = DockerControlRequest.from_command(
        ["docker", "version"],
        timeout=3.5,
        environment={"ONLY": "trusted"},
    )
    result = execute_docker_control(request, process_runner=process_runner)

    assert observed == {
        "command": ["docker", "version"],
        "cwd": None,
        "env": {"ONLY": "trusted"},
        "timeout": 3.5,
    }
    assert result.command == ("docker", "version")
    assert result.returncode == 17
    assert result.stdout == "bounded-out"
    assert result.stderr == "bounded-err"
    assert result.as_completed_process().args == ["docker", "version"]


def test_completed_process_adapter_can_preserve_original_argv_identity() -> None:
    original = ["docker", "version"]
    result = execute_docker_control(
        DockerControlRequest.from_command(original, timeout=1, environment={}),
        process_runner=lambda command, **_kwargs: _completed(command),
    )

    assert result.as_completed_process(args=original).args is original


@pytest.mark.parametrize("facade", [candidate_runner, blackbox, repo_verifier])
def test_docker_control_facades_preserve_original_argv_identity(
    facade: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = ["docker", "version"]
    observed: list[list[str]] = []

    def process_runner(
        argv: list[str],
        *,
        cwd: str | None,
        env: dict[str, str] | None,
        timeout: float,
    ) -> subprocess.CompletedProcess[str]:
        del cwd, env, timeout
        observed.append(argv)
        return _completed(argv)

    monkeypatch.setattr(facade, "_run_bounded_subprocess", process_runner)
    result = facade._run_docker_control(command, timeout=1)  # type: ignore[attr-defined]

    assert observed == [command]
    assert observed[0] is command
    assert result.args is command


@pytest.mark.parametrize("timeout", [-1, float("inf"), float("nan"), True])
def test_docker_control_request_rejects_unbounded_timeout(timeout: float) -> None:
    with pytest.raises(ValueError, match="finite and non-negative"):
        DockerControlRequest.from_command(["docker", "version"], timeout=timeout)


def test_image_resolution_pulls_only_after_missing_inspection() -> None:
    calls: list[tuple[list[str], float]] = []
    responses = iter(
        [
            _completed([], 1, "", "not found"),
            _completed([], 0, "pulled", ""),
            _completed([], 0, "sha256:immutable\n", ""),
        ]
    )

    def control(
        command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        calls.append((command, timeout))
        return next(responses)

    resolution = resolve_docker_image(
        "judge:latest",
        control_runner=control,
        pull_when_inspection_empty=False,
    )

    assert resolution.image_id == "sha256:immutable"
    assert resolution.pull_attempted is True
    assert calls == [
        (
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
                "judge:latest",
            ],
            DOCKER_CONTROL_TIMEOUT_SECONDS,
        ),
        (["docker", "pull", "judge:latest"], DOCKER_PULL_TIMEOUT_SECONDS),
        (
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
                "judge:latest",
            ],
            DOCKER_CONTROL_TIMEOUT_SECONDS,
        ),
    ]


def test_repo_image_policy_does_not_pull_after_empty_successful_inspection() -> None:
    calls: list[list[str]] = []

    def control(
        command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        del timeout
        calls.append(command)
        return _completed(command, 0, "\n", "")

    resolution = resolve_docker_image(
        "judge:latest",
        control_runner=control,
        pull_when_inspection_empty=False,
    )

    assert resolution.image_id is None
    assert resolution.pull_attempted is False
    assert len(calls) == 1


def test_candidate_image_policy_may_pull_after_empty_successful_inspection() -> None:
    responses = iter(
        [
            _completed([], 0, "", ""),
            _completed([], 1, "", "offline"),
        ]
    )

    def control(
        command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        del command, timeout
        return next(responses)

    resolution = resolve_docker_image(
        "candidate:latest",
        control_runner=control,
        pull_when_inspection_empty=True,
    )

    assert resolution.image_id is None
    assert resolution.pull is not None
    assert resolution.pull.returncode == 1
    assert resolution.final_inspection is None


def test_container_name_is_sanitized_bounded_and_injectable() -> None:
    name = docker_container_name(
        "../pack phase;$(touch pwned)" + "x" * 80,
        token_hex=lambda length: "a" * (length * 2),
    )

    assert name == "evoguard_pack-phase-touch-pwned-xxxxxxxxx_aaaaaaaaaaaaaaaa"
    assert len(name) <= len("evoguard_") + 32 + 1 + 16


@pytest.mark.parametrize(
    ("returncode", "started_at", "proven"),
    [
        (0, "2026-07-21T10:00:00Z", True),
        (0, "0001-01-01T00:00:00Z", False),
        (0, "<no value>", False),
        (1, "2026-07-21T10:00:00Z", False),
    ],
)
def test_started_probe_is_fail_closed(
    returncode: int, started_at: str, proven: bool
) -> None:
    probe = probe_container_started(
        "evoguard_case",
        control_runner=lambda command, *, timeout: _completed(
            command, returncode, started_at, ""
        ),
    )
    assert probe.proven is proven


def test_container_probe_suppresses_operator_exception_fail_closed() -> None:
    def interrupted(
        _command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        del timeout
        raise KeyboardInterrupt("operator cancelled inspect")

    started = probe_container_started("case", control_runner=interrupted)
    absent = probe_container_absent("case", control_runner=interrupted)

    assert started.proven is False
    assert absent.proven is False
    assert started.error == "KeyboardInterrupt"
    assert absent.error == "KeyboardInterrupt"


def test_kernel_absence_query_requires_success_and_exact_name() -> None:
    commands: list[list[str]] = []

    def control(
        command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        del timeout
        commands.append(command)
        return _completed(
            command,
            0,
            "case-prefix\nprefix-case\ncase\n",
            "",
        )

    observation = probe_container_absent("case", control_runner=control)

    assert observation.absent is False
    assert observation.proven is False
    assert commands == [
        [
            "docker",
            "container",
            "ls",
            "--all",
            "--filter",
            "name=case",
            "--format",
            "{{.Names}}",
        ]
    ]


def test_kernel_absence_query_rejects_daemon_failure() -> None:
    observation = probe_container_absent(
        "case",
        control_runner=lambda command, *, timeout: _completed(
            command,
            1,
            "",
            "Cannot connect to the Docker daemon",
        ),
    )

    assert observation.absent is None
    assert observation.proven is False
    assert observation.error == "docker_query_failed"


@pytest.mark.parametrize("name", ["", "case.*", "case\nother"])
def test_kernel_absence_query_rejects_invalid_name_without_docker(
    name: str,
) -> None:
    called = False

    def control(
        command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        nonlocal called
        del timeout
        called = True
        return _completed(command)

    observation = probe_container_absent(name, control_runner=control)

    assert observation.absent is None
    assert observation.error == "invalid_container_name"
    assert called is False


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"control_timeout": 0.0}, "control_timeout"),
        ({"total_timeout": float("inf")}, "total_timeout"),
        ({"reconcile_interval": -0.1}, "reconcile_interval"),
        ({"reconcile_attempts": 0}, "reconcile_attempts"),
        (
            {"reconcile_attempts": 2, "required_final_absent_observations": 3},
            "required_final_absent_observations",
        ),
    ],
)
def test_kernel_cleanup_rejects_invalid_bounds(
    kwargs: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        cleanup_named_container(
            "case",
            control_runner=lambda command, *, timeout: _completed(command),
            **kwargs,  # type: ignore[arg-type]
        )


def test_named_cleanup_requires_independent_absence_proof() -> None:
    calls: list[list[str]] = []

    def control(
        command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        del timeout
        calls.append(command)
        if command[:3] == ["docker", "rm", "-f"]:
            return _completed(command, 0)
        return _completed(command, 0, "case\n", "")

    cleanup = cleanup_named_container(
        "case",
        control_runner=control,
        sleeper=lambda _seconds: None,
    )

    assert cleanup.proven_absent is False
    assert cleanup.removal is not None
    assert cleanup.absence is not None
    assert cleanup.absence.absent is False
    assert len(cleanup.removals) == DOCKER_CLEANUP_RECONCILE_ATTEMPTS + 1
    assert len(cleanup.observations) == DOCKER_CLEANUP_RECONCILE_ATTEMPTS
    assert all(
        observation.query is not None
        and observation.query.command[:4]
        == ("docker", "container", "ls", "--all")
        for observation in cleanup.observations
    )


def test_kernel_cleanup_reconciles_late_create_and_requires_final_streak() -> None:
    observations = 0
    removals = 0
    present = False

    def control(
        command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        nonlocal observations, present, removals
        del timeout
        if command[:3] == ["docker", "rm", "-f"]:
            removals += 1
            present = False
            return _completed(command)
        observations += 1
        if observations == 4:
            present = True
        return _completed(command, 0, "case\n" if present else "", "")

    cleanup = cleanup_named_container(
        "case",
        control_runner=control,
        sleeper=lambda _seconds: None,
    )

    assert cleanup.proven_absent is True
    assert len(cleanup.observations) == DOCKER_CLEANUP_RECONCILE_ATTEMPTS
    assert removals == 2


def test_kernel_cleanup_rejects_absence_not_stable_at_window_end() -> None:
    observations = 0

    def control(
        command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        nonlocal observations
        del timeout
        if command[:3] == ["docker", "rm", "-f"]:
            return _completed(command)
        observations += 1
        present = observations == DOCKER_CLEANUP_RECONCILE_ATTEMPTS - 1
        return _completed(command, 0, "case\n" if present else "", "")

    cleanup = cleanup_named_container(
        "case",
        control_runner=control,
        sleeper=lambda _seconds: None,
    )

    assert cleanup.proven_absent is False
    assert cleanup.error == "absence_not_stable"


def test_kernel_cleanup_uses_decreasing_single_total_budget() -> None:
    clock = iter([0.0, 0.0, 2.0, 4.0, 5.0, 6.0])
    timeouts: list[float] = []
    queries = 0

    def control(
        command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        nonlocal queries
        timeouts.append(timeout)
        if command[:3] == ["docker", "rm", "-f"]:
            return _completed(command)
        queries += 1
        if queries == 1:
            return _completed(command, 0, "case\n", "")
        return _completed(command, 1, "", "daemon unavailable")

    cleanup = cleanup_named_container(
        "case",
        control_runner=control,
        monotonic=lambda: next(clock),
        sleeper=lambda _seconds: None,
    )

    assert cleanup.proven_absent is False
    assert cleanup.error == "docker_query_failed"
    assert timeouts == [10.0, 8.0, 6.0, 4.0]


def test_kernel_cleanup_stops_immediately_when_absence_is_unverifiable() -> None:
    commands: list[list[str]] = []

    def control(
        command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        del timeout
        commands.append(command)
        if command[:3] == ["docker", "rm", "-f"]:
            return _completed(command)
        return _completed(command, 1, "", "daemon unavailable")

    cleanup = cleanup_named_container(
        "case",
        control_runner=control,
        sleeper=lambda _seconds: None,
    )

    assert cleanup.proven_absent is False
    assert cleanup.error == "docker_query_failed"
    assert commands == [
        ["docker", "rm", "-f", "case"],
        [
            "docker",
            "container",
            "ls",
            "--all",
            "--filter",
            "name=case",
            "--format",
            "{{.Names}}",
        ],
    ]


@pytest.mark.parametrize(
    "primary",
    [KeyboardInterrupt("cancelled"), SystemExit("stopped")],
)
def test_named_cleanup_preserves_baseexception_from_injected_absence_probe(
    primary: BaseException,
) -> None:
    def raise_primary(
        _name: str, *, timeout: float
    ) -> DockerContainerAbsenceObservation:
        del timeout
        raise primary

    with pytest.raises(type(primary), match=str(primary)):
        cleanup_named_container(
            "case",
            control_runner=lambda command, *, timeout: _completed(command),
            absence_probe=raise_primary,
        )


@pytest.mark.parametrize(
    ("primary", "expected_type"),
    [
        (subprocess.TimeoutExpired(["docker", "run"], 1), DockerRunTimeout),
        (ProcessOutputLimitExceeded(128), DockerRunOutputLimit),
    ],
)
def test_named_run_preserves_failure_type_after_proven_cleanup(
    primary: BaseException,
    expected_type: type[BaseException],
) -> None:
    cleanups: list[str] = []

    def process_runner(
        _command: list[str],
        *,
        cwd: str | None,
        env: dict[str, str] | None,
        timeout: float,
    ) -> subprocess.CompletedProcess[str]:
        del cwd, env, timeout
        raise primary

    request = DockerRunRequest.from_command(
        ["docker", "run", "--name", "case"],
        name="case",
        timeout=1,
        environment={},
    )
    with pytest.raises(expected_type) as raised:
        run_named_docker_client(
            request,
            process_runner=process_runner,
            container_started=lambda _name: True,
            cleanup_container=lambda name: cleanups.append(name) or True,
        )

    assert raised.value.container_started is True
    assert cleanups == ["case"]


def test_named_run_can_preserve_original_process_argv_and_timeout_cmd() -> None:
    command = ["docker", "run", "--name", "case"]

    def process_runner(
        argv: list[str],
        *,
        cwd: str | None,
        env: dict[str, str] | None,
        timeout: float,
    ) -> subprocess.CompletedProcess[str]:
        del cwd, env
        assert argv is command
        raise subprocess.TimeoutExpired(argv, timeout)

    request = DockerRunRequest.from_command(
        command,
        name="case",
        timeout=1,
        environment={},
    )
    with pytest.raises(DockerRunTimeout) as raised:
        run_named_docker_client(
            request,
            process_runner=process_runner,
            container_started=lambda _name: False,
            cleanup_container=lambda _name: True,
            process_argv=command,
        )

    assert raised.value.cmd is command


def test_named_run_escalates_unproven_daemon_cleanup() -> None:
    primary = ProcessContainmentError("native process tree survived")

    def process_runner(
        _command: list[str],
        *,
        cwd: str | None,
        env: dict[str, str] | None,
        timeout: float,
    ) -> subprocess.CompletedProcess[str]:
        del cwd, env, timeout
        raise primary

    request = DockerRunRequest.from_command(
        ["docker", "run"], name="case", timeout=1, environment={}
    )
    with pytest.raises(DockerRunContainmentError, match="cleanup was not proven"):
        run_named_docker_client(
            request,
            process_runner=process_runner,
            container_started=lambda _name: False,
            cleanup_container=lambda _name: False,
        )


def test_cid_scanner_accepts_only_unique_regular_docker_ids(tmp_path: Path) -> None:
    cid_a = "a" * 64
    cid_b = "b" * 64
    (tmp_path / "01.cid").write_text(cid_a + "\n", encoding="ascii")
    (tmp_path / "02.cid").write_text(cid_a, encoding="ascii")
    (tmp_path / "03.cid").write_text(cid_b, encoding="ascii")
    (tmp_path / "bad.cid").write_text("not-a-container", encoding="ascii")
    (tmp_path / "large.cid").write_text("c" * 129, encoding="ascii")
    (tmp_path / "ignored.txt").write_text("d" * 64, encoding="ascii")

    scanned = scan_candidate_container_ids(str(tmp_path))

    assert scanned.container_ids == (cid_a, cid_b)
    assert scanned.failures == ()


def test_cid_scanner_reports_unreadable_directory_as_typed_fact(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    scanned = scan_candidate_container_ids(str(missing))

    assert scanned.container_ids == ()
    assert len(scanned.failures) == 1
    assert "could not scan candidate cidfile directory" in scanned.failures[0]


def test_candidate_cleanup_keeps_cid_and_named_container_semantics_separate() -> None:
    cid_a = "a" * 64
    cid_b = "b" * 64
    scans = [
        DockerCidScanResult((cid_a,), ()),
        DockerCidScanResult((cid_b,), ()),
    ]
    scan_count = 0
    present = {cid_a, cid_b}
    commands: list[list[str]] = []

    def scanner(_path: str) -> DockerCidScanResult:
        nonlocal scan_count
        result = scans[scan_count] if scan_count < len(scans) else DockerCidScanResult(())
        scan_count += 1
        return result

    def control(
        command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        del timeout
        commands.append(command)
        if command[:3] == ["docker", "rm", "-f"]:
            present.discard(command[-1])
            return _completed(command, 0)
        container_id = command[-1].removeprefix("id=")
        stdout = container_id + "\n" if container_id in present else ""
        return _completed(command, 0, stdout, "")

    cleanup = cleanup_candidate_containers(
        DockerCandidateCleanupRequest(
            cidfile_dir="/judge/cids",
            wait_for_late_cidfiles=True,
        ),
        scanner=scanner,
        control_runner=control,
        sleeper=lambda _seconds: None,
        path_exists=lambda _path: True,
    )

    assert cleanup.cleanup_proven is True
    assert cleanup.attempted_container_ids == (cid_a, cid_b)
    assert [command for command in commands if command[:3] == ["docker", "rm", "-f"]] == [
        ["docker", "rm", "-f", cid_a],
        ["docker", "rm", "-f", cid_b],
    ]


def test_repo_private_docker_exception_seams_are_exact_kernel_aliases() -> None:
    assert repo_verifier._DockerRunTimeout is DockerRunTimeout
    assert repo_verifier._DockerRunOutputLimit is DockerRunOutputLimit
    assert repo_verifier._DockerRunContainmentError is DockerRunContainmentError


def test_repo_image_facade_preserves_pull_order_and_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    responses = iter(
        [
            _completed([], 1, "", "missing"),
            _completed([], 0, "pulled", ""),
            _completed([], 0, "sha256:repo-pinned\n", ""),
        ]
    )

    def control(
        command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        del timeout
        calls.append(command)
        return next(responses)

    monkeypatch.setattr(repo_verifier, "_run_docker_control", control)
    verifier = repo_verifier.RepoVerifier(
        isolation="docker",
        docker_image="judge:latest",
        mem_limit_mb=0,
    )

    assert verifier._resolve_docker_image() == "sha256:repo-pinned"
    assert verifier._resolve_docker_image() == "sha256:repo-pinned"
    assert calls == [
        [
            "docker",
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            "judge:latest",
        ],
        ["docker", "pull", "judge:latest"],
        [
            "docker",
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            "judge:latest",
        ],
    ]


def test_repo_image_facade_preserves_phase_specific_capture_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def control(
        command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        del timeout
        if command[:2] == ["docker", "pull"]:
            raise ProcessOutputLimitExceeded(128)
        return _completed(command, 1, "", "missing")

    monkeypatch.setattr(repo_verifier, "_run_docker_control", control)
    verifier = repo_verifier.RepoVerifier(
        isolation="docker",
        docker_image="judge:latest",
        mem_limit_mb=0,
    )

    with pytest.raises(RuntimeError, match="pull could not be safely captured"):
        verifier._resolve_docker_image()


def test_candidate_image_identity_facade_preserves_private_control_seam(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], float]] = []

    def control(
        command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        calls.append((command, timeout))
        return _completed(command, 0, "sha256:candidate-pinned\n", "")

    monkeypatch.setattr(candidate_runner, "_run_docker_control", control)

    assert CandidateRunner._image_digest("candidate:latest") == (
        "sha256:candidate-pinned"
    )
    assert calls == [
        (
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
                "candidate:latest",
            ],
            DOCKER_CONTROL_TIMEOUT_SECONDS,
        )
    ]
