"""Direct contracts for the extracted candidate-isolation implementation."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

import evoom_guard.candidate_runner as legacy
import evoom_guard.isolation as isolation
import evoom_guard.isolation.candidate as implementation


def _normalized(value: Any, root: Path) -> Any:
    if isinstance(value, dict):
        return {key: _normalized(item, root) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalized(item, root) for item in value]
    if isinstance(value, str):
        return value.replace(str(root), "<ROOT>").replace(
            str(root).replace("\\", "/"), "<ROOT>"
        )
    return value


def _candidate_plan(
    module: Any,
    runner_type: type[Any],
    root: Path,
    isolation_mode: str,
) -> dict[str, Any]:
    workdir = root / "workdir"
    target = root / "target"
    workdir.mkdir(parents=True)
    target.mkdir(parents=True)
    docker_calls: list[dict[str, Any]] = []

    def docker_control(
        command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        docker_calls.append({"command": list(command), "timeout": timeout})
        if command[:2] == ["docker", "version"]:
            return subprocess.CompletedProcess(command, 0, stdout="28.0.1\n", stderr="")
        if command[:3] == ["docker", "image", "inspect"]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=f"sha256:{'0123456789abcdef' * 4}\n",
                stderr="",
            )
        raise AssertionError(f"unexpected Docker control command: {command!r}")

    runner = runner_type(
        isolation=isolation_mode,
        docker_image=(
            "registry.example/guard:mutable"
            if isolation_mode in {"docker", "gvisor"}
            else None
        ),
        docker_network="guard-contract-net",
        mem_limit_mb=384,
        python="python-contract",
        invocation_socket=str(root / "receipt.sock"),
        invocation_token="candidate-core-differential-token",
    )
    control_name = (
        "_run_docker_control"
        if module is legacy
        else "_run_docker_control_default"
    )
    with (
        mock.patch.object(module.os, "name", "posix"),
        mock.patch.object(module.shutil, "which", return_value="/usr/bin/docker"),
        mock.patch.object(module.os, "getuid", return_value=1234, create=True),
        mock.patch.object(module.os, "getgid", return_value=5678, create=True),
        mock.patch.object(module, control_name, side_effect=docker_control),
    ):
        launcher, env, evidence = runner.prepare(str(workdir), str(target))

    launcher_path = Path(launcher)
    config = json.loads(
        launcher_path.with_suffix(".py.json").read_text(encoding="utf-8")
    )
    result = {
        "launcher": launcher,
        "env": env,
        "evidence": evidence.as_dict(),
        "config": config,
        "config_key_order": list(config),
        "launcher_source": launcher_path.read_text(encoding="utf-8"),
        "launcher_mode": stat.S_IMODE(os.stat(launcher_path).st_mode),
        "docker_calls": docker_calls,
        "cid_directory_exists": (
            workdir / implementation.CANDIDATE_CID_DIRNAME
        ).is_dir(),
    }
    return _normalized(result, root)


def test_legacy_facade_preserves_public_identity_and_dataclass_contract() -> None:
    assert legacy.CANDIDATE_CID_DIRNAME == implementation.CANDIDATE_CID_DIRNAME
    assert legacy.IsolationEvidence is implementation.IsolationEvidence
    assert legacy.IsolationUnavailable is implementation.IsolationUnavailable
    assert issubclass(legacy.CandidateRunner, implementation.CandidateRunner)
    assert isinstance(legacy.CandidateRunner(), implementation.CandidateRunner)
    assert legacy.__dict__.get("__all__") is None


def test_isolation_package_exports_the_typed_candidate_contract() -> None:
    assert isolation.CandidateRunner is implementation.CandidateRunner
    assert isolation.IsolationEvidence is implementation.IsolationEvidence
    assert isolation.IsolationUnavailable is implementation.IsolationUnavailable
    assert isolation.CANDIDATE_CID_DIRNAME == implementation.CANDIDATE_CID_DIRNAME


def test_candidate_implementation_import_has_no_legacy_or_blackbox_cycle() -> None:
    script = (
        "import sys\n"
        "import evoom_guard.isolation.candidate as candidate\n"
        "assert candidate.CandidateRunner\n"
        "assert 'evoom_guard.candidate_runner' not in sys.modules\n"
        "assert 'evoom_guard.blackbox' not in sys.modules\n"
    )
    subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )


def test_legacy_then_implementation_import_order_is_stable() -> None:
    script = (
        "import evoom_guard.candidate_runner as legacy\n"
        "import evoom_guard.isolation.candidate as implementation\n"
        "assert legacy.IsolationUnavailable is implementation.IsolationUnavailable\n"
        "assert issubclass(legacy.CandidateRunner, implementation.CandidateRunner)\n"
    )
    subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )


def test_core_candidate_runner_matches_legacy_for_all_boundaries(
    tmp_path: Path,
) -> None:
    for isolation_mode in ("subprocess", "docker", "gvisor"):
        legacy_plan = _candidate_plan(
            legacy,
            legacy.CandidateRunner,
            tmp_path / isolation_mode / "legacy",
            isolation_mode,
        )
        core_plan = _candidate_plan(
            implementation,
            implementation.CandidateRunner,
            tmp_path / isolation_mode / "core",
            isolation_mode,
        )
        assert core_plan == legacy_plan


def _subprocess_plan(
    tmp_path: Path, mem_limit_mb: int
) -> tuple[str, dict[str, Any], implementation.IsolationEvidence]:
    workdir = tmp_path / "workdir"
    target = tmp_path / "target"
    workdir.mkdir()
    target.mkdir()
    runner = implementation.CandidateRunner(
        isolation="subprocess", mem_limit_mb=mem_limit_mb
    )
    launcher, env, evidence = runner.prepare(str(workdir), str(target))
    config = json.loads(Path(launcher + ".json").read_text(encoding="utf-8"))
    return launcher, config, evidence


@pytest.mark.skipif(os.name == "nt", reason="POSIX launcher contract")
def test_subprocess_mem_limit_threads_rlimit_into_launcher_config(
    tmp_path: Path,
) -> None:
    _launcher, config, evidence = _subprocess_plan(tmp_path, mem_limit_mb=64)
    assert config["mem_limit_bytes"] == 64 * 1024 * 1024
    assert "RLIMIT_AS cap of 64 MiB" in evidence.note
    assert "fail-closed" in evidence.note


@pytest.mark.skipif(os.name == "nt", reason="POSIX launcher contract")
def test_subprocess_without_mem_limit_keeps_launcher_config_unchanged(
    tmp_path: Path,
) -> None:
    _launcher, config, evidence = _subprocess_plan(tmp_path, mem_limit_mb=0)
    assert "mem_limit_bytes" not in config
    assert "RLIMIT_AS" not in evidence.note


@pytest.mark.skipif(os.name == "nt", reason="POSIX launcher contract")
def test_subprocess_launcher_applies_rlimit_as_to_the_candidate(
    tmp_path: Path,
) -> None:
    launcher, config, _evidence = _subprocess_plan(tmp_path, mem_limit_mb=512)
    completed = subprocess.run(
        [
            launcher,
            sys.executable,
            "-c",
            "import resource; print(resource.getrlimit(resource.RLIMIT_AS)[0])",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert completed.stdout.strip() == str(config["mem_limit_bytes"])


@pytest.mark.skipif(os.name == "nt", reason="POSIX launcher contract")
def test_subprocess_launcher_fails_closed_on_unappliable_mem_limit(
    tmp_path: Path,
) -> None:
    workdir = tmp_path / "workdir"
    target = tmp_path / "target"
    workdir.mkdir()
    target.mkdir()
    launcher = implementation.CandidateRunner._write_launcher(
        str(workdir),
        {
            "mode": "subprocess",
            "target": str(target),
            "mem_limit_bytes": 64 * 1024 * 1024,
        },
    )
    # Shadow the stdlib resource module so setrlimit raises, simulating a
    # platform where the configured cap cannot be applied.
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "resource.py").write_text(
        "RLIMIT_AS = 9\n"
        "def setrlimit(res, limits):\n"
        "    raise OSError('cannot apply memory cap')\n",
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(shadow)
    completed = subprocess.run(
        [launcher, sys.executable, "-c", "print('ran')"],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    # An unappliable cap must abort the launch (125), never run uncapped,
    # and must say so on stderr so evidence can attribute the abort to the
    # launcher boundary rather than the candidate.
    assert completed.returncode == 125, completed.stdout + completed.stderr
    assert "ran" not in completed.stdout
    assert "memory cap could not be applied" in completed.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX launcher contract")
def test_prepare_refuses_a_provably_undeliverable_mem_limit(
    tmp_path: Path,
) -> None:
    import resource

    workdir = tmp_path / "workdir"
    target = tmp_path / "target"
    workdir.mkdir()
    target.mkdir()
    runner = implementation.CandidateRunner(isolation="subprocess", mem_limit_mb=64)
    cap = 64 * 1024 * 1024
    with (
        mock.patch.object(resource, "getrlimit", return_value=(cap - 1, cap - 1)),
        mock.patch.object(implementation.os, "geteuid", return_value=1000, create=True),
    ):
        with pytest.raises(implementation.IsolationUnavailable):
            runner.prepare(str(workdir), str(target))
