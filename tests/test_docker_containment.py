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


def test_docker_cleanup_requires_the_container_name_to_be_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []

    def fake_control(command: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[:3] == ["docker", "rm", "-f"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.CompletedProcess(command, 0, "still-present", "")

    monkeypatch.setattr(repo_verifier, "_run_docker_control", fake_control)

    assert not repo_verifier._cleanup_docker_container("evoguard_case")
    assert commands == [
        ["docker", "rm", "-f", "evoguard_case"],
        ["docker", "inspect", "evoguard_case"],
    ]


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
