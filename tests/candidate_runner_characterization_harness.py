"""Deterministic behavioral contract for :mod:`evoom_guard.candidate_runner`.

The runner is about to move behind a compatibility facade.  This harness freezes
the observable contract before that move without requiring Docker or a POSIX
host.  Docker control calls are simulated at the module seam; launcher files are
real.  Only temporary workspace paths and the judge-owned invocation token are
normalized.
"""

from __future__ import annotations

import dataclasses
import inspect
import json
import os
import runpy
import stat
import subprocess
import sys
from collections.abc import Callable
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

import evoom_guard.candidate_runner as candidate_runner_module
from evoom_guard.candidate_runner import (
    CANDIDATE_CID_DIRNAME,
    CandidateRunner,
    IsolationEvidence,
    IsolationUnavailable,
)
from evoom_guard.execution import (
    ProcessContainmentError,
    ProcessOutputLimitExceeded,
)

SCHEMA_VERSION = "candidate-runner-characterization-v1"
NORMALIZED_FIELDS = (
    "temporary workspace paths",
    "judge-owned invocation token",
)
CASE_NAMES = (
    "containment_error",
    "contract_surface",
    "daemon_unavailable",
    "docker_plan",
    "empty_digest_after_pull",
    "image_inspect_hit",
    "image_inspect_pull_inspect",
    "keyboard_interrupt",
    "launcher_files",
    "os_error",
    "output_limit",
    "pull_failure",
    "subprocess_plan",
    "system_exit",
    "timeout",
    "gvisor_plan",
)

_IMAGE = "registry.example/guard:mutable"
_DIGEST = "sha256:0123456789abcdef"
_TOKEN = "characterization-secret-token"


def _completed(
    command: list[str], returncode: int, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        command,
        returncode,
        stdout=stdout,
        stderr=stderr,
    )


class _DockerControlStub:
    def __init__(self, responses: list[subprocess.CompletedProcess[str]]) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def __call__(
        self, command: list[str], *, timeout: float
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append({"command": list(command), "timeout": timeout})
        if not self._responses:
            raise AssertionError(f"unexpected Docker control call: {command!r}")
        response = self._responses.pop(0)
        if response.args != command:
            raise AssertionError(
                f"Docker command drifted: expected {response.args!r}, observed {command!r}"
            )
        return response

    def assert_exhausted(self) -> None:
        if self._responses:
            raise AssertionError(f"unused Docker responses: {self._responses!r}")


def _normalize(value: Any, workspace: Path) -> Any:
    if isinstance(value, dict):
        return {str(key): _normalize(item, workspace) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(item, workspace) for item in value]
    if not isinstance(value, str):
        return value

    workspace_text = os.path.abspath(str(workspace))
    target_text = os.path.abspath(str(workspace / "target"))
    normalized = value
    for source, replacement in sorted(
        (
            (target_text, "<TARGET>"),
            (workspace_text, "<WORKSPACE>"),
            (_TOKEN, "<TOKEN>"),
        ),
        key=lambda item: len(item[0]),
        reverse=True,
    ):
        normalized = normalized.replace(source, replacement)
        normalized = normalized.replace(source.replace("\\", "/"), replacement)
    if "<WORKSPACE>" in normalized or "<TARGET>" in normalized:
        normalized = normalized.replace("\\", "/")
    return normalized


def _exception_record(exc: BaseException) -> dict[str, Any]:
    cause = exc.__cause__
    return {
        "type": type(exc).__name__,
        "message": str(exc),
        "cause_type": type(cause).__name__ if cause is not None else None,
        "cause_message": str(cause) if cause is not None else None,
    }


def _dataclass_contract(cls: type[Any]) -> list[dict[str, Any]]:
    contract: list[dict[str, Any]] = []
    for item in dataclasses.fields(cls):
        default: Any
        if item.default is dataclasses.MISSING:
            default = "<required>"
        else:
            default = item.default
        contract.append(
            {
                "name": item.name,
                "default": default,
                "init": item.init,
                "repr": item.repr,
                "compare": item.compare,
            }
        )
    return contract


def _contract_surface() -> dict[str, Any]:
    required_exports = {
        "CANDIDATE_CID_DIRNAME": "constant",
        "CandidateRunner": "class",
        "IsolationEvidence": "class",
        "IsolationUnavailable": "class",
    }
    observed_exports: dict[str, str] = {}
    for name in required_exports:
        value = getattr(candidate_runner_module, name)
        observed_exports[name] = "class" if inspect.isclass(value) else "constant"

    evidence = IsolationEvidence(
        requested="gvisor",
        delivered="gvisor",
        image="image:tag",
        image_digest="sha256:evidence",
        network="none",
        runtime="runsc",
        note="contract note",
    )
    evidence_dict = evidence.as_dict()
    return {
        "required_exports": required_exports,
        "observed_exports": observed_exports,
        "module___all__": getattr(candidate_runner_module, "__all__", None),
        "candidate_cid_dirname": CANDIDATE_CID_DIRNAME,
        "signatures": {
            "CandidateRunner": str(inspect.signature(CandidateRunner)),
            "CandidateRunner.prepare": str(inspect.signature(CandidateRunner.prepare)),
            "IsolationEvidence": str(inspect.signature(IsolationEvidence)),
            "IsolationEvidence.as_dict": str(
                inspect.signature(IsolationEvidence.as_dict)
            ),
        },
        "dataclass_fields": {
            "CandidateRunner": _dataclass_contract(CandidateRunner),
            "IsolationEvidence": _dataclass_contract(IsolationEvidence),
        },
        "isolation_evidence_key_order": list(evidence_dict),
        "isolation_evidence": evidence_dict,
        "isolation_unavailable_base": IsolationUnavailable.__bases__[0].__name__,
    }


def _launcher_files(workspace: Path) -> dict[str, Any]:
    workdir = workspace / "launcher"
    workdir.mkdir(parents=True)
    chmod_calls: list[dict[str, Any]] = []

    def record_chmod(path: str, mode: int) -> None:
        chmod_calls.append({"path": path, "mode": oct(mode)})

    config = {
        "mode": "subprocess",
        "target": str(workspace / "target"),
        "invocation_socket": str(workspace / "receipt.sock"),
        "invocation_token": _TOKEN,
    }
    with (
        mock.patch.object(candidate_runner_module.os, "chmod", side_effect=record_chmod),
        mock.patch.object(
            candidate_runner_module.os,
            "stat",
            return_value=SimpleNamespace(st_mode=0o640),
        ),
    ):
        launcher = CandidateRunner._write_launcher(str(workdir), config)

    launcher_path = Path(launcher)
    source = launcher_path.read_text(encoding="utf-8")
    raw_config = json.loads((launcher_path.with_suffix(".py.json")).read_text(encoding="utf-8"))
    return _normalize(
        {
            "launcher": launcher,
            "config": raw_config,
            "config_key_order": list(raw_config),
            "chmod_calls": chmod_calls,
            "expected_config_mode": oct(stat.S_IRUSR | stat.S_IWUSR),
            "source_contract": {
                "shebang": source.splitlines()[0],
                "execvp_calls": source.count("os.execvp"),
                "uses_shell": "/bin/sh" in source or "shell=True" in source,
                "loads_sidecar_json": "json.load" in source,
                "sends_receipt_before_mode_branch": source.index("_s.sendto")
                < source.index("if CFG['mode']"),
                "allocates_unique_cidfile": "secrets.token_hex(16)" in source,
            },
        },
        workspace,
    )


def _subprocess_plan(workspace: Path) -> dict[str, Any]:
    workdir = workspace / "subprocess"
    target = workspace / "target"
    workdir.mkdir(parents=True)
    target.mkdir(parents=True)
    runner = CandidateRunner(isolation="subprocess", python="python-contract")
    with mock.patch.object(candidate_runner_module.os, "name", "posix"):
        launcher, env, evidence = runner.prepare(str(workdir), str(target))

    launcher_path = Path(launcher)
    config = json.loads((launcher_path.with_suffix(".py.json")).read_text(encoding="utf-8"))
    observed_exec: dict[str, Any] = {}

    class ExecObserved(RuntimeError):
        pass

    def record_exec(executable: str, argv: list[str]) -> None:
        observed_exec.update(
            executable=executable,
            argv=list(argv),
            cwd=os.getcwd(),
        )
        raise ExecObserved

    original_cwd = os.getcwd()
    try:
        with (
            mock.patch.object(candidate_runner_module.os, "execvp", side_effect=record_exec),
            mock.patch.object(
                sys,
                "argv",
                [launcher, "python-contract", "-m", "tool", "semi;colon"],
            ),
        ):
            try:
                runpy.run_path(launcher, run_name="__main__")
            except ExecObserved:
                pass
            else:  # pragma: no cover - launcher must delegate through execvp
                raise AssertionError("subprocess launcher did not call os.execvp")
    finally:
        os.chdir(original_cwd)
    return _normalize(
        {
            "launcher": launcher,
            "env": env,
            "evidence": evidence.as_dict(),
            "config": config,
            "observed_exec": observed_exec,
        },
        workspace,
    )


def _container_plan(workspace: Path, isolation: str) -> dict[str, Any]:
    workdir = workspace / isolation
    target = workspace / "target"
    workdir.mkdir(parents=True)
    target.mkdir(parents=True, exist_ok=True)
    version_command = ["docker", "version", "--format", "{{.Server.Version}}"]
    inspect_command = [
        "docker",
        "image",
        "inspect",
        "--format",
        "{{.Id}}",
        _IMAGE,
    ]
    docker = _DockerControlStub(
        [
            _completed(version_command, 0, stdout="28.0.1\n"),
            _completed(inspect_command, 0, stdout=f"{_DIGEST}\n"),
        ]
    )
    runner = CandidateRunner(
        isolation=isolation,
        docker_image=_IMAGE,
        docker_network="guard-contract-net",
        mem_limit_mb=384,
        python="ignored-host-python",
        invocation_socket=str(workspace / "receipt.sock"),
        invocation_token=_TOKEN,
    )
    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(candidate_runner_module.os, "name", "posix"))
        stack.enter_context(
            mock.patch.object(
                candidate_runner_module.shutil,
                "which",
                return_value="/usr/bin/docker",
            )
        )
        stack.enter_context(
            mock.patch.object(
                candidate_runner_module.os,
                "getuid",
                return_value=1234,
                create=True,
            )
        )
        stack.enter_context(
            mock.patch.object(
                candidate_runner_module.os,
                "getgid",
                return_value=5678,
                create=True,
            )
        )
        stack.enter_context(
            mock.patch.object(candidate_runner_module, "_run_docker_control", docker)
        )
        launcher, env, evidence = runner.prepare(str(workdir), str(target))
    docker.assert_exhausted()
    launcher_path = Path(launcher)
    config = json.loads((launcher_path.with_suffix(".py.json")).read_text(encoding="utf-8"))
    return _normalize(
        {
            "launcher": launcher,
            "env": env,
            "evidence": evidence.as_dict(),
            "config": config,
            "docker_control_calls": docker.calls,
            "cid_directory_exists": (workdir / CANDIDATE_CID_DIRNAME).is_dir(),
        },
        workspace,
    )


def _image_resolution(case_name: str) -> dict[str, Any]:
    inspect = ["docker", "image", "inspect", "--format", "{{.Id}}", _IMAGE]
    pull = ["docker", "pull", _IMAGE]
    if case_name == "image_inspect_hit":
        responses = [_completed(inspect, 0, stdout=f"{_DIGEST}\n")]
    elif case_name == "image_inspect_pull_inspect":
        responses = [
            _completed(inspect, 1, stderr="not found"),
            _completed(pull, 0, stdout="pulled"),
            _completed(inspect, 0, stdout=f"{_DIGEST}\n"),
        ]
    elif case_name == "pull_failure":
        responses = [
            _completed(inspect, 1, stderr="not found"),
            _completed(pull, 1, stderr="registry unavailable"),
        ]
    elif case_name == "empty_digest_after_pull":
        responses = [
            _completed(inspect, 1, stderr="not found"),
            _completed(pull, 0, stdout="pulled"),
            _completed(inspect, 0, stdout="  \n"),
        ]
    else:  # pragma: no cover - guarded by capture_case
        raise AssertionError(case_name)

    docker = _DockerControlStub(responses)
    runner = CandidateRunner(isolation="docker", docker_image=_IMAGE)
    with mock.patch.object(candidate_runner_module, "_run_docker_control", docker):
        try:
            digest = runner._ensure_image(_IMAGE)
            outcome: dict[str, Any] = {"digest": digest, "exception": None}
        except IsolationUnavailable as exc:
            outcome = {"digest": None, "exception": _exception_record(exc)}
    docker.assert_exhausted()
    outcome["docker_control_calls"] = docker.calls
    return outcome


def _daemon_unavailable(workspace: Path) -> dict[str, Any]:
    workdir = workspace / "daemon"
    target = workspace / "target"
    workdir.mkdir(parents=True)
    target.mkdir(parents=True)
    version = ["docker", "version", "--format", "{{.Server.Version}}"]
    docker = _DockerControlStub(
        [_completed(version, 1, stderr="Cannot connect to the Docker daemon")]
    )
    runner = CandidateRunner(isolation="docker", docker_image=_IMAGE)
    with (
        mock.patch.object(candidate_runner_module.os, "name", "posix"),
        mock.patch.object(
            candidate_runner_module.shutil,
            "which",
            return_value="/usr/bin/docker",
        ),
        mock.patch.object(candidate_runner_module, "_run_docker_control", docker),
    ):
        try:
            runner.prepare(str(workdir), str(target))
        except IsolationUnavailable as exc:
            exception = _exception_record(exc)
        else:  # pragma: no cover - the frozen implementation fails closed
            raise AssertionError("Docker daemon failure unexpectedly prepared a launcher")
    docker.assert_exhausted()
    return {
        "exception": exception,
        "docker_control_calls": docker.calls,
        "workdir_entries": sorted(path.name for path in workdir.iterdir()),
    }


def _preflight_exception(
    workspace: Path,
    side_effect: BaseException,
) -> dict[str, Any]:
    workdir = workspace / "failure"
    target = workspace / "target"
    workdir.mkdir(parents=True)
    target.mkdir(parents=True)
    runner = CandidateRunner(isolation="docker", docker_image=_IMAGE)
    with (
        mock.patch.object(candidate_runner_module.os, "name", "posix"),
        mock.patch.object(
            candidate_runner_module.shutil,
            "which",
            return_value="/usr/bin/docker",
        ),
        mock.patch.object(
            candidate_runner_module,
            "_run_bounded_subprocess",
            side_effect=side_effect,
        ),
    ):
        try:
            runner.prepare(str(workdir), str(target))
        except BaseException as exc:
            exception = _exception_record(exc)
        else:  # pragma: no cover - every supplied effect must abort
            raise AssertionError("Docker control failure unexpectedly prepared a launcher")
    return {
        "exception": exception,
        "workdir_entries": sorted(path.name for path in workdir.iterdir()),
    }


def capture_case(case_name: str, workspace: Path) -> dict[str, Any]:
    """Capture one stable candidate-runner contract case."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown CandidateRunner characterization case: {case_name}")
    case_workspace = workspace / case_name
    case_workspace.mkdir(parents=True)

    if case_name == "contract_surface":
        result = _contract_surface()
    elif case_name == "launcher_files":
        result = _launcher_files(case_workspace)
    elif case_name == "subprocess_plan":
        result = _subprocess_plan(case_workspace)
    elif case_name in {"docker_plan", "gvisor_plan"}:
        result = _container_plan(case_workspace, case_name.removesuffix("_plan"))
    elif case_name in {
        "image_inspect_hit",
        "image_inspect_pull_inspect",
        "pull_failure",
        "empty_digest_after_pull",
    }:
        result = _image_resolution(case_name)
    elif case_name == "daemon_unavailable":
        result = _daemon_unavailable(case_workspace)
    else:
        effects: dict[str, Callable[[], BaseException]] = {
            "output_limit": lambda: ProcessOutputLimitExceeded(128),
            "containment_error": lambda: ProcessContainmentError(
                "process-tree cleanup was not proven"
            ),
            "timeout": lambda: subprocess.TimeoutExpired(
                ["docker", "version"], 30.0
            ),
            "os_error": lambda: OSError("docker executable vanished"),
            "keyboard_interrupt": lambda: KeyboardInterrupt("operator stop"),
            "system_exit": lambda: SystemExit("operator exit"),
        }
        result = _preflight_exception(case_workspace, effects[case_name]())
    return _normalize(result, case_workspace)


def capture_all(workspace: Path) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "normalization": list(NORMALIZED_FIELDS),
        "cases": {name: capture_case(name, workspace) for name in CASE_NAMES},
    }


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
