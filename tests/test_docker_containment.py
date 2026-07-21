"""Regression coverage for bounded Docker-client execution and cleanup."""

from __future__ import annotations

import subprocess

import pytest

import evoom_guard.verifiers.repo_verifier as repo_verifier
from evoom_guard.verifiers.repo_verifier import RepoVerifier


def _candidate() -> str:
    return "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n"


def test_docker_output_limit_removes_named_container_before_reporting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = RepoVerifier(
        isolation="docker", docker_image="judge:latest", mem_limit_mb=0
    )
    overflow = repo_verifier._SubprocessOutputLimitExceeded(123)
    monkeypatch.setattr(
        repo_verifier, "_run_bounded_subprocess", lambda *_args, **_kwargs: (_ for _ in ()).throw(overflow)
    )
    monkeypatch.setattr(repo_verifier, "_docker_container_started", lambda _name: True)
    cleaned: list[str] = []
    monkeypatch.setattr(
        repo_verifier,
        "_cleanup_docker_container",
        lambda name: cleaned.append(name) or True,
    )

    with pytest.raises(repo_verifier._DockerRunOutputLimit) as exc:
        verifier._run_docker_client(["docker", "run"], "evoguard_case")

    assert exc.value.limit == 123
    assert exc.value.container_started is True
    assert cleaned == ["evoguard_case"]


def test_docker_timeout_with_unproven_cleanup_is_containment_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = RepoVerifier(
        isolation="docker", docker_image="judge:latest", mem_limit_mb=0
    )
    timeout = subprocess.TimeoutExpired(["docker", "run"], 1)
    monkeypatch.setattr(
        repo_verifier, "_run_bounded_subprocess", lambda *_args, **_kwargs: (_ for _ in ()).throw(timeout)
    )
    monkeypatch.setattr(repo_verifier, "_docker_container_started", lambda _name: True)
    monkeypatch.setattr(repo_verifier, "_cleanup_docker_container", lambda _name: False)

    with pytest.raises(repo_verifier._DockerRunContainmentError) as exc:
        verifier._run_docker_client(["docker", "run"], "evoguard_case")

    assert exc.value.container_started is True
    assert "cleanup was not proven" in str(exc.value)


@pytest.mark.parametrize(
    ("primary", "cleanup_error"),
    [
        (
            KeyboardInterrupt("operator interrupted Docker client"),
            SystemExit("cleanup exited"),
        ),
        (
            SystemExit("operator stopped Docker client"),
            KeyboardInterrupt("cleanup interrupted"),
        ),
    ],
)
def test_docker_cleanup_baseexception_cannot_mask_unexpected_primary(
    monkeypatch: pytest.MonkeyPatch,
    primary: BaseException,
    cleanup_error: BaseException,
) -> None:
    verifier = RepoVerifier(
        isolation="docker", docker_image="judge:latest", mem_limit_mb=0
    )
    monkeypatch.setattr(
        repo_verifier,
        "_run_bounded_subprocess",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(primary),
    )
    monkeypatch.setattr(
        repo_verifier,
        "_cleanup_docker_container",
        lambda _name: (_ for _ in ()).throw(cleanup_error),
    )

    observed: BaseException | None = None
    try:
        verifier._run_docker_client(["docker", "run"], "evoguard_case")
    except BaseException as exc:
        # Catch KeyboardInterrupt/SystemExit inside the test so a precedence
        # regression is a normal assertion failure, not a pytest infrastructure
        # exit that the deterministic mutation gate could misclassify.
        observed = exc

    assert observed is primary
    notes = getattr(observed, "__notes__", [])
    assert any("cleanup raised" in note for note in notes)
    assert any(type(cleanup_error).__name__ in note for note in notes)


def test_unproven_docker_cleanup_is_not_hidden_by_unexpected_primary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = RepoVerifier(
        isolation="docker", docker_image="judge:latest", mem_limit_mb=0
    )
    primary = RuntimeError("unexpected Docker client failure")
    monkeypatch.setattr(
        repo_verifier,
        "_run_bounded_subprocess",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(primary),
    )
    monkeypatch.setattr(
        repo_verifier,
        "_cleanup_docker_container",
        lambda _name: False,
    )

    with pytest.raises(RuntimeError) as caught:
        verifier._run_docker_client(["docker", "run"], "evoguard_case")

    assert caught.value is primary
    assert any(
        "cleanup was not proven" in note
        for note in getattr(caught.value, "__notes__", [])
    )


def test_docker_nonzero_exit_proves_named_container_is_gone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = RepoVerifier(
        isolation="docker", docker_image="judge:latest", mem_limit_mb=0
    )
    run = subprocess.CompletedProcess(["docker", "run"], 1, "", "failed test")
    monkeypatch.setattr(
        repo_verifier, "_run_bounded_subprocess", lambda *_args, **_kwargs: run
    )
    monkeypatch.setattr(repo_verifier, "_docker_container_started", lambda _name: False)
    cleaned: list[str] = []
    monkeypatch.setattr(
        repo_verifier,
        "_cleanup_docker_container",
        lambda name: cleaned.append(name) or True,
    )

    result = verifier._run_docker_client(["docker", "run"], "evoguard_case")

    assert result.returncode == 1
    assert cleaned == ["evoguard_case"]


def test_docker_cleanup_requires_a_successful_exact_name_absence_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []

    def fake_control(
        command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[:3] == ["docker", "rm", "-f"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.CompletedProcess(
            command,
            0,
            "evoguard_case2\nevoguard_case\n",
            "",
        )

    monkeypatch.setattr(repo_verifier, "_run_docker_control", fake_control)
    monkeypatch.setattr(repo_verifier.time, "sleep", lambda _seconds: None)

    assert not repo_verifier._cleanup_docker_container("evoguard_case")
    removals = [command for command in commands if command[:3] == ["docker", "rm", "-f"]]
    queries = [command for command in commands if command[:3] == ["docker", "container", "ls"]]
    assert len(removals) == repo_verifier._DOCKER_CLEANUP_RECONCILE_ATTEMPTS + 1
    assert len(queries) == repo_verifier._DOCKER_CLEANUP_RECONCILE_ATTEMPTS
    assert all("--all" in command for command in queries)
    assert all(
        command[command.index("--filter") + 1] == "name=evoguard_case"
        for command in queries
    )


def test_docker_absence_query_accepts_only_successful_exact_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command: list[str] = []

    def fake_control(
        received: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        command.extend(received)
        return subprocess.CompletedProcess(
            received,
            0,
            "evoguard_case-prefix\nprefix-evoguard_case\nevoguard_other\n",
            "",
        )

    monkeypatch.setattr(repo_verifier, "_run_docker_control", fake_control)

    assert repo_verifier._docker_container_absent("evoguard_case")
    assert command == [
        "docker",
        "container",
        "ls",
        "--all",
        "--filter",
        "name=evoguard_case",
        "--format",
        "{{.Names}}",
    ]


def test_docker_cleanup_reconciles_a_late_daemon_side_create(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observations = 0
    removals = 0
    present = False

    def fake_control(
        command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        nonlocal observations, present, removals
        del timeout
        if command[:3] == ["docker", "rm", "-f"]:
            removals += 1
            present = False
            return subprocess.CompletedProcess(command, 0, "", "")
        observations += 1
        if observations == 4:
            present = True
        names = "evoguard_case\n" if present else ""
        return subprocess.CompletedProcess(command, 0, names, "")

    monkeypatch.setattr(repo_verifier, "_run_docker_control", fake_control)
    monkeypatch.setattr(repo_verifier.time, "sleep", lambda _seconds: None)

    assert repo_verifier._cleanup_docker_container("evoguard_case")
    assert observations == repo_verifier._DOCKER_CLEANUP_RECONCILE_ATTEMPTS
    assert removals == 2


def test_docker_cleanup_rejects_absence_not_stable_at_window_end(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observations = 0

    def fake_control(
        command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        nonlocal observations
        del timeout
        if command[:3] == ["docker", "rm", "-f"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        observations += 1
        names = (
            "evoguard_case\n"
            if observations
            == repo_verifier._DOCKER_CLEANUP_RECONCILE_ATTEMPTS - 1
            else ""
        )
        return subprocess.CompletedProcess(command, 0, names, "")

    monkeypatch.setattr(repo_verifier, "_run_docker_control", fake_control)
    monkeypatch.setattr(repo_verifier.time, "sleep", lambda _seconds: None)

    assert not repo_verifier._cleanup_docker_container("evoguard_case")


def test_docker_cleanup_applies_one_total_control_plane_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    timeouts: list[float] = []

    def timeout_control(
        command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        timeouts.append(timeout)
        raise subprocess.TimeoutExpired(command, timeout)

    monkeypatch.setattr(repo_verifier, "_run_docker_control", timeout_control)
    monkeypatch.setattr(repo_verifier.time, "monotonic", lambda: 100.0)

    assert not repo_verifier._cleanup_docker_container("evoguard_case")
    assert timeouts == [repo_verifier._DOCKER_CLEANUP_TOTAL_TIMEOUT_SECONDS]


def test_docker_cleanup_stops_immediately_on_unverifiable_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []

    def fake_control(
        command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        del timeout
        commands.append(command)
        if command[:3] == ["docker", "rm", "-f"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.CompletedProcess(
            command,
            1,
            "",
            "Cannot connect to the Docker daemon",
        )

    monkeypatch.setattr(repo_verifier, "_run_docker_control", fake_control)

    assert not repo_verifier._cleanup_docker_container("evoguard_case")
    assert len(commands) == 2
    assert commands[0][:3] == ["docker", "rm", "-f"]
    assert commands[1][:3] == ["docker", "container", "ls"]


def test_docker_absence_query_rejects_exact_present_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    present = subprocess.CompletedProcess(
        ["docker", "container", "ls"],
        0,
        "evoguard_other\nevoguard_case\n",
        "",
    )
    monkeypatch.setattr(repo_verifier, "_run_docker_control", lambda *_a, **_k: present)

    assert not repo_verifier._docker_container_absent("evoguard_case")


def test_docker_absence_query_rejects_daemon_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failed = subprocess.CompletedProcess(
        ["docker", "container", "ls"],
        1,
        "",
        "Cannot connect to the Docker daemon",
    )
    monkeypatch.setattr(repo_verifier, "_run_docker_control", lambda *_a, **_k: failed)

    assert not repo_verifier._docker_container_absent("evoguard_case")


@pytest.mark.parametrize(
    "error",
    [
        subprocess.TimeoutExpired(["docker", "container", "ls"], 30),
        repo_verifier._SubprocessOutputLimitExceeded(123),
    ],
    ids=["timeout", "output-limit"],
)
def test_docker_absence_query_rejects_unbounded_or_incomplete_observation(
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
) -> None:
    def fail_control(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(repo_verifier, "_run_docker_control", fail_control)

    assert not repo_verifier._docker_container_absent("evoguard_case")


@pytest.mark.parametrize("name", ["", "evoguard_.*", "evoguard_case\nother"])
def test_docker_absence_query_rejects_ambiguous_or_invalid_names(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    called = False

    def fake_control(*_args, **_kwargs):
        nonlocal called
        called = True
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(repo_verifier, "_run_docker_control", fake_control)

    assert not repo_verifier._docker_container_absent(name)
    assert called is False


def test_container_setup_output_limit_is_a_structured_setup_failure(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    verifier = RepoVerifier(
        isolation="docker",
        docker_image="judge:latest",
        setup_command=["prepare"],
        mem_limit_mb=0,
    )
    overflow = repo_verifier._DockerRunOutputLimit(
        repo_verifier._SubprocessOutputLimitExceeded(123), container_started=True
    )
    monkeypatch.setattr(verifier, "_resolve_docker_image", lambda: "sha256:judge")
    monkeypatch.setattr(
        verifier,
        "_run_docker_client",
        lambda *_args: (_ for _ in ()).throw(overflow),
    )

    result = verifier.verify(_candidate(), {"repo_path": str(tmp_path)})

    assert result.artifact["outcome"] == "setup_output_limit"
    assert result.artifact["setup_isolation"] == "docker"
    assert result.artifact["setup_isolation_evidence"]["delivered"] == "docker"


def test_container_suite_output_limit_preserves_container_delivery_evidence(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    verifier = RepoVerifier(
        isolation="docker", docker_image="judge:latest", mem_limit_mb=0
    )
    overflow = repo_verifier._DockerRunOutputLimit(
        repo_verifier._SubprocessOutputLimitExceeded(123), container_started=True
    )
    monkeypatch.setattr(verifier, "_resolve_docker_image", lambda: "sha256:judge")
    monkeypatch.setattr(
        verifier,
        "_run_docker_client",
        lambda *_args: (_ for _ in ()).throw(overflow),
    )

    result = verifier.verify(_candidate(), {"repo_path": str(tmp_path)})

    assert result.artifact["outcome"] == "test_output_limit"
    assert result.artifact["test_command_started"] is True
    assert result.artifact["delivered_isolation"] == "docker"
    assert result.artifact["repo_suite_isolation_evidence"]["delivered"] == "docker"
