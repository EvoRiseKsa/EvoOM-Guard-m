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
                stdout="sha256:0123456789abcdef\n",
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
