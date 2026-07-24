"""Deterministic characterization of RepoVerifier's setup-command phase."""

from __future__ import annotations

import copy
import json
import subprocess
import types
from collections.abc import Callable
from pathlib import Path
from typing import Any

from evoom_guard.contracts import VerdictResult
from evoom_guard.execution import (
    ProcessContainmentError,
    ProcessOutputLimitExceeded,
)
from evoom_guard.isolation import (
    DockerRunContainmentError,
    DockerRunOutputLimit,
    DockerRunTimeout,
)
from evoom_guard.verifiers import repo_verifier
from evoom_guard.verifiers.fidelity import SetupFidelityError

SCHEMA_VERSION = "repo-setup-characterization-v1"
CASE_NAMES = (
    "docker_containment_started",
    "docker_containment_unstarted",
    "docker_exit_125",
    "docker_not_found",
    "docker_output_limit_started",
    "docker_output_limit_unstarted",
    "docker_timeout_started",
    "docker_timeout_unstarted",
    "fidelity_change",
    "host_containment",
    "host_nonzero",
    "host_not_found",
    "host_output_limit",
    "host_timeout",
    "post_snapshot_error",
    "pre_snapshot_error",
)

_APP_EDIT = "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n"
_IMAGE_ID = "sha256:" + "d" * 64


def canonical_json(value: Any) -> str:
    """Return stable, human-reviewable JSON."""

    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _normalized_result(result: VerdictResult) -> dict[str, Any]:
    artifact = copy.deepcopy(result.artifact)
    artifact.pop("elapsed", None)
    return {
        "artifact": artifact,
        "diagnostics": result.diagnostics,
        "passed": result.passed,
        "score": result.score,
    }


def _docker_timeout(*, started: bool) -> DockerRunTimeout:
    return DockerRunTimeout(
        subprocess.TimeoutExpired(["docker", "run"], 7),
        container_started=started,
    )


def _docker_output_limit(*, started: bool) -> DockerRunOutputLimit:
    return DockerRunOutputLimit(
        ProcessOutputLimitExceeded(99),
        container_started=started,
    )


def _runner_effect(case_name: str) -> object:
    effects: dict[str, object] = {
        "docker_containment_started": DockerRunContainmentError(
            "docker cleanup missing", container_started=True
        ),
        "docker_containment_unstarted": DockerRunContainmentError(
            "docker cleanup missing", container_started=False
        ),
        "docker_exit_125": subprocess.CompletedProcess(
            ["docker", "setup"], 125, "raw stdout", "raw stderr"
        ),
        "docker_not_found": FileNotFoundError("docker"),
        "docker_output_limit_started": _docker_output_limit(started=True),
        "docker_output_limit_unstarted": _docker_output_limit(started=False),
        "docker_timeout_started": _docker_timeout(started=True),
        "docker_timeout_unstarted": _docker_timeout(started=False),
        "fidelity_change": subprocess.CompletedProcess(["setup"], 0, "raw stdout", "raw stderr"),
        "host_containment": ProcessContainmentError("host cleanup missing"),
        "host_nonzero": subprocess.CompletedProcess(["setup"], 3, "raw stdout", "raw stderr"),
        "host_not_found": FileNotFoundError("setup"),
        "host_output_limit": ProcessOutputLimitExceeded(99),
        "host_timeout": subprocess.TimeoutExpired(["setup"], 7),
        "post_snapshot_error": subprocess.CompletedProcess(
            ["setup"], 0, "raw stdout", "raw stderr"
        ),
        "pre_snapshot_error": subprocess.CompletedProcess(["setup"], 0, "raw stdout", "raw stderr"),
    }
    return effects[case_name]


def capture_case(case_name: str, workspace: Path) -> dict[str, Any]:
    """Capture one setup terminal branch and the dependency-call order."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown repo setup case: {case_name}")

    source = workspace / f"source-{case_name}"
    source.mkdir(parents=True)
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")

    events: list[dict[str, Any]] = []
    snapshot_count = 0
    effect = _runner_effect(case_name)
    container_case = case_name.startswith("docker_")

    originals = {
        "resolve_host": repo_verifier._resolve_host_command,
        "snapshot": repo_verifier._setup_fidelity_snapshot,
        "changes": repo_verifier._setup_fidelity_changes,
        "run": repo_verifier._run_bounded_subprocess,
        "distill": repo_verifier.distill_diagnostics,
    }

    def resolve_host(command, *, cwd, env):
        events.append(
            {
                "command": list(command),
                "op": "resolve-host",
            }
        )
        return list(command)

    def snapshot(root, output_globs=(), *, baseline=None):
        nonlocal snapshot_count
        snapshot_count += 1
        phase = "pre" if baseline is None else "post"
        events.append(
            {
                "baseline": baseline is not None,
                "globs": list(output_globs),
                "op": f"snapshot-{phase}",
            }
        )
        if case_name == "pre_snapshot_error" and baseline is None:
            raise SetupFidelityError("controlled pre-snapshot failure")
        if case_name == "post_snapshot_error" and baseline is not None:
            raise SetupFidelityError("controlled post-snapshot failure")
        return {"snapshot": snapshot_count}

    def changes(before, after):
        events.append(
            {
                "after": after["snapshot"],
                "before": before["snapshot"],
                "op": "changes",
            }
        )
        return ["app.py", "generated.txt"] if case_name == "fidelity_change" else []

    def host_run(command, **kwargs):
        events.append(
            {
                "command": list(command),
                "op": "host-run",
                "strict": kwargs["require_process_group_cleanup_proof"],
            }
        )
        if isinstance(effect, BaseException):
            raise effect
        return effect

    def distill(text: str) -> str:
        events.append({"op": "distill", "text": text})
        return "DISTILLED"

    repo_verifier._resolve_host_command = resolve_host
    repo_verifier._setup_fidelity_snapshot = snapshot
    repo_verifier._setup_fidelity_changes = changes
    repo_verifier._run_bounded_subprocess = host_run
    repo_verifier.distill_diagnostics = distill
    try:
        verifier = repo_verifier.RepoVerifier(
            isolation="docker" if container_case else "subprocess",
            docker_image="judge:latest" if container_case else None,
            mem_limit_mb=0,
            setup_command=["setup-tool", "--prepare"],
            setup_output_globs=("generated/**",),
            strict_harness=True,
            test_command=["unused-suite"],
            timeout=7,
        )

        if container_case:

            def resolve_image(_self):
                events.append({"op": "resolve-image"})
                return _IMAGE_ID

            def docker_command(
                _self,
                command,
                copy_path,
                outdir,
                name,
                report_env=None,
                *,
                work_writable=False,
                pack_dir=None,
            ):
                events.append(
                    {
                        "command": list(command),
                        "op": "docker-command",
                        "work_writable": work_writable,
                    }
                )
                return ["docker", "setup"]

            def docker_run(_self, command, name):
                events.append(
                    {
                        "command": list(command),
                        "op": "docker-run",
                    }
                )
                if isinstance(effect, BaseException):
                    raise effect
                return effect

            verifier._resolve_docker_image = types.MethodType(  # type: ignore[method-assign]
                resolve_image, verifier
            )
            verifier._docker_command = types.MethodType(  # type: ignore[method-assign]
                docker_command, verifier
            )
            verifier._run_docker_client = types.MethodType(  # type: ignore[method-assign]
                docker_run, verifier
            )

        result = verifier.verify(_APP_EDIT, {"repo_path": str(source)})
    finally:
        repo_verifier._resolve_host_command = originals["resolve_host"]
        repo_verifier._setup_fidelity_snapshot = originals["snapshot"]
        repo_verifier._setup_fidelity_changes = originals["changes"]
        repo_verifier._run_bounded_subprocess = originals["run"]
        repo_verifier.distill_diagnostics = originals["distill"]

    return {
        "events": events,
        "result": _normalized_result(result),
    }


def capture_all(workspace: Path) -> dict[str, Any]:
    """Capture all reviewed setup cases in one versioned envelope."""

    return {
        "cases": {name: capture_case(name, workspace) for name in CASE_NAMES},
        "schema_version": SCHEMA_VERSION,
    }


def capture_command(
    workspace: Path,
    *,
    constructor_command: object,
    problem_command: object,
) -> tuple[list[str], list[str]]:
    """Capture command precedence/token normalization before setup starts."""

    source = workspace / "source-command"
    source.mkdir(parents=True, exist_ok=True)
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    observed: list[str] = []
    events: list[str] = []
    originals = {
        "resolve": repo_verifier._resolve_host_command,
        "snapshot": repo_verifier._setup_fidelity_snapshot,
    }

    def resolve(command, *, cwd, env):
        observed.extend(command)
        events.append("resolve")
        return command

    def stop_after_resolve(root, output_globs=(), *, baseline=None):
        events.append("pre-snapshot")
        raise SetupFidelityError("stop after command capture")

    repo_verifier._resolve_host_command = resolve
    repo_verifier._setup_fidelity_snapshot = stop_after_resolve
    try:
        verifier = repo_verifier.RepoVerifier(
            setup_command=constructor_command,  # type: ignore[arg-type]
            test_command=["unused"],
            mem_limit_mb=0,
        )
        verifier.verify(
            _APP_EDIT,
            {
                "repo_path": str(source),
                "setup_command": problem_command,
            },
        )
    finally:
        repo_verifier._resolve_host_command = originals["resolve"]
        repo_verifier._setup_fidelity_snapshot = originals["snapshot"]
    return observed, events


def observe_live_operation_order(
    workspace: Path,
    *,
    on_event: Callable[[str], None] | None = None,
) -> list[str]:
    """Observe the historical lookup/evaluation order through suite entry."""

    source = workspace / "source-live-order"
    source.mkdir(parents=True, exist_ok=True)
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    events: list[str] = []
    originals = {
        "resolve": repo_verifier._resolve_host_command,
        "snapshot": repo_verifier._setup_fidelity_snapshot,
        "changes": repo_verifier._setup_fidelity_changes,
        "run": repo_verifier._run_bounded_subprocess,
    }
    snapshot_count = 0
    run_count = 0

    def record(event: str) -> None:
        events.append(event)
        if on_event is not None:
            on_event(event)

    def resolve(command, *, cwd, env):
        record("resolve-setup" if not events else "resolve-suite")
        return command

    def snapshot(root, output_globs=(), *, baseline=None):
        nonlocal snapshot_count
        snapshot_count += 1
        record("snapshot-pre" if baseline is None else "snapshot-post")
        return snapshot_count

    def changes(before, after):
        record("changes")
        return []

    def run(command, **kwargs):
        nonlocal run_count
        run_count += 1
        if run_count == 1:
            record("run-setup")
            return subprocess.CompletedProcess(command, 0, "", "")
        record("run-suite")
        raise FileNotFoundError("controlled suite stop")

    repo_verifier._resolve_host_command = resolve
    repo_verifier._setup_fidelity_snapshot = snapshot
    repo_verifier._setup_fidelity_changes = changes
    repo_verifier._run_bounded_subprocess = run
    try:
        repo_verifier.RepoVerifier(
            setup_command=["setup"],
            test_command=["suite"],
            mem_limit_mb=0,
        ).verify(_APP_EDIT, {"repo_path": str(source)})
    finally:
        repo_verifier._resolve_host_command = originals["resolve"]
        repo_verifier._setup_fidelity_snapshot = originals["snapshot"]
        repo_verifier._setup_fidelity_changes = originals["changes"]
        repo_verifier._run_bounded_subprocess = originals["run"]
    return events
