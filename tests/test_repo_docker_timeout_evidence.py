"""Fail-closed Docker start evidence for every repo-verifier phase."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from evoom_guard.verifiers import repo_verifier as repo_verifier_module
from evoom_guard.verifiers.repo_verifier import RepoVerifier

_STARTED_AT = "2026-07-13T10:11:12.123456789Z"


def _candidate() -> str:
    return "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n"


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "test_contract.py").write_text(
        "def test_contract():\n    assert True\n", encoding="utf-8"
    )
    return repo, pack


class _DockerFake:
    def __init__(
        self,
        *,
        timeout_phase: str | None = None,
        container_started: bool = False,
        pack_exit_125: bool = False,
    ) -> None:
        self.timeout_phase = timeout_phase
        self.container_started = container_started
        self.pack_exit_125 = pack_exit_125
        self.calls: list[list[str]] = []

    @staticmethod
    def _phase(command: list[str]) -> str:
        if "/verifier-pack" in command:
            return "verifier_pack"
        if any(
            isinstance(token, str) and token.endswith(":/out:rw")
            for token in command
        ):
            return "repo_suite"
        return "setup"

    @staticmethod
    def _write_junit(command: list[str]) -> None:
        for token in command:
            if isinstance(token, str) and token.endswith(":/out:rw"):
                outdir = token.removesuffix(":/out:rw")
                os.makedirs(outdir, exist_ok=True)
                Path(outdir, "judge-result.xml").write_text(
                    '<testsuite tests="1" failures="0" errors="0">'
                    '<testcase classname="x" name="ok"/></testsuite>',
                    encoding="utf-8",
                )

    def __call__(self, command, **_kwargs):
        cmd = list(command)
        self.calls.append(cmd)
        if cmd[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(
                cmd,
                0 if self.container_started else 1,
                _STARTED_AT if self.container_started else "",
                "",
            )
        if cmd[:3] == ["docker", "rm", "-f"]:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        assert cmd[:3] == ["docker", "run", "--rm"]
        phase = self._phase(cmd)
        if phase == self.timeout_phase:
            raise subprocess.TimeoutExpired(cmd, 7)
        if phase == "verifier_pack" and self.pack_exit_125:
            return subprocess.CompletedProcess(cmd, 125, "", "daemon unavailable")
        self._write_junit(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")


def _verifier(*, setup: bool = False) -> RepoVerifier:
    return RepoVerifier(
        timeout=7,
        mem_limit_mb=0,
        test_command=["python", "-c", "raise SystemExit(0)"],
        setup_command=["python", "-c", "pass"] if setup else None,
        isolation="docker",
        docker_image="judge:latest",
    )


@pytest.mark.parametrize("container_started", [False, True])
def test_setup_timeout_requires_inspect_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    container_started: bool,
) -> None:
    repo, _pack = _roots(tmp_path)
    fake = _DockerFake(timeout_phase="setup", container_started=container_started)
    verifier = _verifier(setup=True)
    monkeypatch.setattr(verifier, "_resolve_docker_image", lambda: "sha256:judge")
    monkeypatch.setattr(repo_verifier_module.subprocess, "run", fake)

    result = verifier.verify(_candidate(), {"repo_path": str(repo)})

    assert result.artifact["execution_state"] == (
        "started_incomplete" if container_started else "not_started"
    )
    assert result.artifact["test_command_started"] is False
    assert result.artifact["delivered_isolation"] == "not_run"
    assert result.artifact["setup_isolation"] == (
        "docker" if container_started else None
    )
    assert result.artifact["setup_isolation_evidence"]["delivered"] == (
        "docker" if container_started else "not_run"
    )
    assert any(call[:2] == ["docker", "inspect"] for call in fake.calls)


@pytest.mark.parametrize("container_started", [False, True])
def test_repo_suite_timeout_requires_inspect_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    container_started: bool,
) -> None:
    repo, _pack = _roots(tmp_path)
    fake = _DockerFake(
        timeout_phase="repo_suite", container_started=container_started
    )
    verifier = _verifier()
    monkeypatch.setattr(verifier, "_resolve_docker_image", lambda: "sha256:judge")
    monkeypatch.setattr(repo_verifier_module.subprocess, "run", fake)

    result = verifier.verify(_candidate(), {"repo_path": str(repo)})

    assert result.artifact["execution_state"] == (
        "started_incomplete" if container_started else "not_started"
    )
    assert result.artifact["test_command_started"] is container_started
    assert result.artifact["delivered_isolation"] == (
        "docker" if container_started else "not_run"
    )
    assert result.artifact["isolation_evidence"]["delivered"] == (
        "docker" if container_started else "not_run"
    )
    assert result.artifact["repo_suite_isolation_evidence"] == result.artifact[
        "isolation_evidence"
    ]


@pytest.mark.parametrize("container_started", [False, True])
def test_verifier_pack_timeout_requires_inspect_proof_without_erasing_suite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    container_started: bool,
) -> None:
    repo, pack = _roots(tmp_path)
    fake = _DockerFake(
        timeout_phase="verifier_pack", container_started=container_started
    )
    verifier = _verifier()
    monkeypatch.setattr(verifier, "_resolve_docker_image", lambda: "sha256:judge")
    monkeypatch.setattr(repo_verifier_module.subprocess, "run", fake)

    result = verifier.verify(
        _candidate(), {"repo_path": str(repo), "verifier_pack": str(pack)}
    )

    assert result.artifact["execution_state"] == "started_incomplete"
    assert result.artifact["test_command_started"] is True
    assert result.artifact["test_command_completed"] is True
    assert result.artifact["verifier_pack_started"] is container_started
    assert result.artifact["delivered_isolation"] == "docker"
    assert result.artifact["isolation_evidence"]["delivered"] == "docker"
    assert result.artifact["repo_suite_isolation_evidence"]["delivered"] == "docker"
    assert result.artifact["verifier_pack_isolation_evidence"]["delivered"] == (
        "docker" if container_started else "not_run"
    )


def test_pack_exit_125_keeps_repo_suite_delivery_and_records_pack_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, pack = _roots(tmp_path)
    fake = _DockerFake(pack_exit_125=True)
    verifier = _verifier()
    monkeypatch.setattr(verifier, "_resolve_docker_image", lambda: "sha256:judge")
    monkeypatch.setattr(repo_verifier_module.subprocess, "run", fake)

    result = verifier.verify(
        _candidate(), {"repo_path": str(repo), "verifier_pack": str(pack)}
    )

    assert result.passed is False
    assert result.artifact["outcome"] == "isolation_unavailable"
    assert result.artifact["execution_state"] == "started_incomplete"
    assert result.artifact["delivered_isolation"] == "docker"
    assert result.artifact["isolation_evidence"]["delivered"] == "docker"
    assert result.artifact["repo_suite_isolation_evidence"]["delivered"] == "docker"
    assert result.artifact["verifier_pack_isolation_evidence"]["delivered"] == (
        "unavailable"
    )
