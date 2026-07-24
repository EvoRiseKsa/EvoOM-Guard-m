"""Deterministic characterization of RepoVerifier's verifier-pack phase."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import types
from collections.abc import Callable
from pathlib import Path
from typing import Any

from evoom_guard.contracts import VerdictResult
from evoom_guard.domain.verification import JUnitCounts, RepoPhaseResult
from evoom_guard.execution import (
    ProcessContainmentError,
    ProcessOutputLimitExceeded,
)
from evoom_guard.isolation import (
    DockerRunContainmentError,
    DockerRunOutputLimit,
    DockerRunTimeout,
)
from evoom_guard.pack_manifest import PackManifestError
from evoom_guard.runtime_identity import RuntimeIdentity
from evoom_guard.verifiers import repo_verifier
from evoom_guard.verifiers.repo_suite import (
    RepoSuiteCompleted,
    RepoSuiteExecutionOutcome,
)

SCHEMA_VERSION = "repo-pack-characterization-v1"
CASE_NAMES = (
    "docker_containment_started",
    "docker_containment_unstarted",
    "docker_exit_125",
    "docker_not_found",
    "docker_output_limit_started",
    "docker_output_limit_unstarted",
    "docker_pass",
    "docker_timeout_started",
    "docker_timeout_unstarted",
    "gvisor_pass",
    "host_containment",
    "host_not_found",
    "host_output_limit",
    "host_pass_strict",
    "host_timeout",
    "pack_drift_after_execution",
    "pack_drift_before_execution",
    "runtime_drift_after_execution",
)

_APP_EDIT = "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n"
_IMAGE_ID = "sha256:" + "d" * 64
_JUNIT_XML = (
    '<testsuite tests="1" failures="0" errors="0" skipped="0">'
    '<testcase classname="pack" name="passes"/></testsuite>'
)
_REPO_JUNIT = '<testsuite><testcase classname="repo" name="passes"/></testsuite>'
_REPO_JUNIT_SHA256 = "b" * 64
_RUNTIME = RuntimeIdentity(
    sha256="a" * 64,
    entries=3,
    regular_bytes=17,
    elapsed_ms=0.25,
    records=(),
)


def canonical_json(value: Any) -> str:
    """Return stable, human-reviewable JSON."""

    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _normalized_result(result: VerdictResult) -> dict[str, Any]:
    artifact = copy.deepcopy(result.artifact)
    artifact.pop("elapsed", None)
    artifact.pop("runtime_identity_elapsed_ms", None)
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
    completed = subprocess.CompletedProcess(
        ["pack"],
        0,
        "pack stdout",
        "pack stderr",
    )
    effects: dict[str, object] = {
        "docker_containment_started": DockerRunContainmentError(
            "docker cleanup missing",
            container_started=True,
        ),
        "docker_containment_unstarted": DockerRunContainmentError(
            "docker cleanup missing",
            container_started=False,
        ),
        "docker_exit_125": subprocess.CompletedProcess(
            ["docker", "pack"],
            125,
            "raw stdout",
            "raw stderr",
        ),
        "docker_not_found": FileNotFoundError("docker"),
        "docker_output_limit_started": _docker_output_limit(started=True),
        "docker_output_limit_unstarted": _docker_output_limit(started=False),
        "docker_pass": completed,
        "docker_timeout_started": _docker_timeout(started=True),
        "docker_timeout_unstarted": _docker_timeout(started=False),
        "gvisor_pass": completed,
        "host_containment": ProcessContainmentError("host cleanup missing"),
        "host_not_found": FileNotFoundError("python"),
        "host_output_limit": ProcessOutputLimitExceeded(99),
        "host_pass_strict": completed,
        "host_timeout": subprocess.TimeoutExpired(["python", "-m", "pytest"], 7),
        "pack_drift_after_execution": completed,
        "pack_drift_before_execution": completed,
        "runtime_drift_after_execution": completed,
    }
    return effects[case_name]


def _canonical_pack_command(command: list[str], pack_snapshot: str) -> list[str]:
    expected_python = "python" if command[0] == "python" else sys.executable
    if command[0] != expected_python:
        raise AssertionError(f"unexpected verifier-pack Python: {command[0]!r}")
    root = "/verifier-pack" if command[0] == "python" else pack_snapshot
    expected = [
        expected_python,
        "-m",
        "pytest",
        "-q",
        "--color=no",
        "-p",
        "no:cacheprovider",
        f"--confcutdir={root}",
        root,
    ]
    if command != expected:
        raise AssertionError(f"unexpected verifier-pack command: {command!r}")
    return [
        "<PYTHON>",
        "-m",
        "pytest",
        "-q",
        "--color=no",
        "-p",
        "no:cacheprovider",
        "--confcutdir=<PACK>",
        "<PACK>",
    ]


def _repo_phase() -> RepoPhaseResult:
    return RepoPhaseResult(
        passed=True,
        score=1.0,
        tests_passed=2,
        tests_total=2,
        tampered=False,
        output="repo stdout\nrepo stderr",
        verdict_source="junit+exit",
        outcome=None,
        returncode=0,
        junit_text=_REPO_JUNIT,
        junit_sha256=_REPO_JUNIT_SHA256,
        junit_digest_format=repo_verifier.JUNIT_XML_DIGEST_FORMAT,
    )


def _write_inputs(workspace: Path, case_name: str) -> tuple[Path, Path]:
    source = workspace / f"source-{case_name}"
    source.mkdir(parents=True)
    (source / "app.py").write_bytes(b"VALUE = 1\n")
    pack = workspace / f"pack-{case_name}"
    pack.mkdir()
    (pack / "test_contract.py").write_bytes(b"def test_contract():\n    assert True\n")
    return source, pack


def capture_case(case_name: str, workspace: Path) -> dict[str, Any]:
    """Capture one verifier-pack branch and its dependency-call order."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown repository pack case: {case_name}")

    source, pack = _write_inputs(workspace, case_name)
    events: list[dict[str, Any]] = []
    effect = _runner_effect(case_name)
    isolation = (
        "gvisor"
        if case_name.startswith("gvisor_")
        else ("docker" if case_name.startswith("docker_") else "subprocess")
    )
    container_mode = isolation in ("docker", "gvisor")
    state: dict[str, Any] = {
        "pack_verify_calls": 0,
        "runtime_verify_calls": 0,
    }

    originals = {
        "execute_suite": repo_verifier.execute_repo_suite,
        "interpret_suite": repo_verifier.interpret_repo_suite,
        "capture_runtime": repo_verifier.capture_runtime_identity,
        "verify_runtime": repo_verifier.verify_runtime_identity,
        "verify_pack": repo_verifier.verify_pack_snapshot,
        "instrument": repo_verifier.instrument_command,
        "resolve_host": repo_verifier._resolve_host_command,
        "run": repo_verifier._run_bounded_subprocess,
        "read": repo_verifier._read_text_or_none,
        "parse": repo_verifier.parse_junit_xml,
        "evaluate": repo_verifier.evaluate_pack_phase,
        "compose": repo_verifier.compose_repo_and_pack,
        "distill": repo_verifier.distill_diagnostics,
    }

    def execute_suite(request: Any, *, services: Any) -> RepoSuiteExecutionOutcome:
        events.append({"op": "suite-execute"})
        suite_evidence = services.phase_isolation_evidence()(
            isolation if container_mode else "subprocess",
            request.resolved_image,
        )
        services.trace.execution_state = "started_incomplete"
        services.trace.execution_phase = "repo_suite"
        services.trace.test_command_started = True
        services.trace.test_command_completed = True
        services.trace.delivered_isolation = isolation if container_mode else "subprocess"
        services.trace.repo_suite_isolation_evidence = suite_evidence
        if container_mode:
            services.trace.primary_isolation_evidence = suite_evidence
        return RepoSuiteExecutionOutcome(
            completed=RepoSuiteCompleted(
                report_path="repo-report.xml",
                returncode=0,
                stdout="repo stdout",
                stderr="repo stderr",
                report_expected=True,
                elapsed_seconds=0.5,
            )
        )

    def interpret_suite(_request: Any, *, services: Any) -> RepoPhaseResult:
        del services
        events.append({"op": "suite-interpret"})
        return _repo_phase()

    def capture_runtime(path: str) -> RuntimeIdentity:
        events.append(
            {
                "candidate_copy": Path(path).name == "repo",
                "op": "runtime-capture",
            }
        )
        return _RUNTIME

    def verify_runtime(
        path: str,
        baseline: RuntimeIdentity,
    ) -> tuple[RuntimeIdentity, list[str]]:
        assert baseline is _RUNTIME
        state["runtime_verify_calls"] += 1
        position = "after-suite" if state["runtime_verify_calls"] == 1 else "after-pack"
        events.append(
            {
                "candidate_copy": Path(path).name == "repo",
                "op": "verify-runtime",
                "position": position,
            }
        )
        if case_name == "runtime_drift_after_execution" and position == "after-pack":
            return _RUNTIME, ["app.py"]
        return _RUNTIME, []

    def verify_pack(snapshot: str, _identity: Any) -> None:
        state["pack_snapshot"] = snapshot
        state["pack_verify_calls"] += 1
        position = "before-execution" if state["pack_verify_calls"] == 1 else "after-execution"
        events.append(
            {
                "op": "verify-pack",
                "position": position,
                "snapshot_is_pack": Path(snapshot).name == "pack",
            }
        )
        if case_name == "pack_drift_before_execution" and position == "before-execution":
            raise PackManifestError("controlled pre-execution drift")
        if case_name == "pack_drift_after_execution" and position == "after-execution":
            raise PackManifestError("controlled post-execution drift")

    def instrument(
        command: list[str],
        report_path: str,
    ) -> tuple[list[str], bool, dict[str, str]]:
        events.append(
            {
                "command": _canonical_pack_command(
                    command,
                    state["pack_snapshot"],
                ),
                "op": "instrument",
                "report_outside_candidate": Path(report_path).parent.name == "pack-phase",
            }
        )
        state["report"] = report_path
        return ["instrumented-pack"], True, {"EVOGUARD_REPORT": report_path}

    def resolve_host(
        command: list[str],
        *,
        cwd: str,
        env: dict[str, str],
    ) -> list[str]:
        events.append(
            {
                "command": list(command),
                "cwd_is_candidate": Path(cwd).name == "repo",
                "op": "resolve-host",
                "report_env_bound": "EVOGUARD_REPORT" in env,
            }
        )
        return ["resolved-pack"]

    def host_run(
        command: list[str],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        events.append(
            {
                "command": list(command),
                "op": "host-run",
                "strict_cleanup": kwargs["require_process_group_cleanup_proof"],
                "timeout": kwargs["timeout"],
            }
        )
        if isinstance(effect, BaseException):
            raise effect
        assert isinstance(effect, subprocess.CompletedProcess)
        return effect

    def read_report(path: str) -> str:
        events.append(
            {
                "matches_instrumented_path": path == state.get("report"),
                "op": "read-pack-report",
            }
        )
        return _JUNIT_XML

    def parse_report(text: str) -> JUnitCounts:
        events.append(
            {
                "bytes": len(text.encode("utf-8")),
                "op": "parse-pack-report",
            }
        )
        return JUnitCounts(passed=1, total=1, failures=0, errors=0)

    def evaluate(evidence: Any) -> Any:
        events.append(
            {
                "junit_present": evidence.junit is not None,
                "op": "evaluate-pack",
                "report_expected": evidence.report_expected,
            }
        )
        return originals["evaluate"](evidence)

    def compose(repo: Any, pack_result: Any) -> Any:
        events.append(
            {
                "pack_tests": pack_result.tests_total,
                "repo_tests": repo.tests_total,
                "op": "compose",
            }
        )
        return originals["compose"](repo, pack_result)

    def distill(text: str) -> str:
        events.append({"op": "distill", "text": text})
        return "DISTILLED"

    repo_verifier.execute_repo_suite = execute_suite
    repo_verifier.interpret_repo_suite = interpret_suite
    repo_verifier.capture_runtime_identity = capture_runtime
    repo_verifier.verify_runtime_identity = verify_runtime
    repo_verifier.verify_pack_snapshot = verify_pack
    repo_verifier.instrument_command = instrument
    repo_verifier._resolve_host_command = resolve_host
    repo_verifier._run_bounded_subprocess = host_run
    repo_verifier._read_text_or_none = read_report
    repo_verifier.parse_junit_xml = parse_report
    repo_verifier.evaluate_pack_phase = evaluate
    repo_verifier.compose_repo_and_pack = compose
    repo_verifier.distill_diagnostics = distill
    try:
        verifier = repo_verifier.RepoVerifier(
            isolation=isolation,
            docker_image="judge:latest" if container_mode else None,
            mem_limit_mb=0,
            strict_harness=case_name == "host_pass_strict",
            test_command=["suite-tool"],
            timeout=7,
        )

        if container_mode:

            def resolve_image(
                _self: repo_verifier.RepoVerifier,
            ) -> str:
                events.append({"op": "resolve-image"})
                return _IMAGE_ID

            def docker_run(
                _self: repo_verifier.RepoVerifier,
                command: list[str],
                copy_path: str,
                workdir: str,
                *,
                pack_dir: str | None = None,
            ) -> tuple[
                str,
                subprocess.CompletedProcess[str],
                bool,
            ]:
                assert pack_dir is not None
                state["report"] = os.path.join(
                    workdir,
                    "out",
                    "judge-result.xml",
                )
                events.append(
                    {
                        "command": _canonical_pack_command(
                            command,
                            pack_dir,
                        ),
                        "copy_is_candidate": Path(copy_path).name == "repo",
                        "op": "docker-run",
                        "pack_mount_is_snapshot": Path(pack_dir).name == "pack",
                    }
                )
                if isinstance(effect, BaseException):
                    raise effect
                assert isinstance(effect, subprocess.CompletedProcess)
                return state["report"], effect, True

            verifier._resolve_docker_image = types.MethodType(  # type: ignore[method-assign]
                resolve_image,
                verifier,
            )
            verifier._run_docker = types.MethodType(  # type: ignore[method-assign]
                docker_run,
                verifier,
            )

        result = verifier.verify(
            _APP_EDIT,
            {
                "repo_path": str(source),
                "verifier_pack": str(pack),
            },
        )
    finally:
        repo_verifier.execute_repo_suite = originals["execute_suite"]
        repo_verifier.interpret_repo_suite = originals["interpret_suite"]
        repo_verifier.capture_runtime_identity = originals["capture_runtime"]
        repo_verifier.verify_runtime_identity = originals["verify_runtime"]
        repo_verifier.verify_pack_snapshot = originals["verify_pack"]
        repo_verifier.instrument_command = originals["instrument"]
        repo_verifier._resolve_host_command = originals["resolve_host"]
        repo_verifier._run_bounded_subprocess = originals["run"]
        repo_verifier._read_text_or_none = originals["read"]
        repo_verifier.parse_junit_xml = originals["parse"]
        repo_verifier.evaluate_pack_phase = originals["evaluate"]
        repo_verifier.compose_repo_and_pack = originals["compose"]
        repo_verifier.distill_diagnostics = originals["distill"]

    return {
        "events": events,
        "result": _normalized_result(result),
    }


def observe_live_host_provider_timing(
    workspace: Path,
    *,
    on_event: Callable[[str], None] | None = None,
) -> list[str]:
    """Observe host providers being rebound at their historical call sites."""

    source, pack = _write_inputs(workspace, "live-host-provider")
    events: list[str] = []
    state = {"pack_verifications": 0, "runtime_verifications": 0}
    originals = {
        "execute_suite": repo_verifier.execute_repo_suite,
        "interpret_suite": repo_verifier.interpret_repo_suite,
        "capture_runtime": repo_verifier.capture_runtime_identity,
        "verify_runtime": repo_verifier.verify_runtime_identity,
        "verify_pack": repo_verifier.verify_pack_snapshot,
        "instrument": repo_verifier.instrument_command,
        "resolve": repo_verifier._resolve_host_command,
        "run": repo_verifier._run_bounded_subprocess,
        "read": repo_verifier._read_text_or_none,
        "parse": repo_verifier.parse_junit_xml,
        "evaluate": repo_verifier.evaluate_pack_phase,
        "compose": repo_verifier.compose_repo_and_pack,
    }

    def record(event: str) -> None:
        events.append(event)
        if on_event is not None:
            on_event(event)

    def fail(name: str) -> Callable[..., Any]:
        def unexpected(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError(f"snapshotted early provider: {name}")

        return unexpected

    def execute_suite(request: Any, *, services: Any) -> RepoSuiteExecutionOutcome:
        evidence = services.phase_isolation_evidence()(
            "subprocess",
            request.resolved_image,
        )
        services.trace.test_command_started = True
        services.trace.test_command_completed = True
        services.trace.repo_suite_isolation_evidence = evidence
        return RepoSuiteExecutionOutcome(
            completed=RepoSuiteCompleted(
                "repo.xml",
                0,
                "",
                "",
                True,
                0.1,
            )
        )

    def verify_runtime(_path: str, _baseline: RuntimeIdentity) -> tuple[RuntimeIdentity, list[str]]:
        state["runtime_verifications"] += 1
        position = state["runtime_verifications"]
        record(f"runtime:{position}")
        if position == 2:
            repo_verifier._read_text_or_none = late_read
        return _RUNTIME, []

    def late_compose(repo: Any, pack_result: Any) -> Any:
        record("compose:late")
        return originals["compose"](repo, pack_result)

    def late_evaluate(evidence: Any) -> Any:
        record("evaluate:late")
        repo_verifier.compose_repo_and_pack = late_compose
        return originals["evaluate"](evidence)

    def late_parse(_text: str) -> JUnitCounts:
        record("parse:late")
        repo_verifier.evaluate_pack_phase = late_evaluate
        return JUnitCounts(1, 1, 0, 0)

    def late_read(_path: str) -> str:
        record("read:late")
        repo_verifier.parse_junit_xml = late_parse
        return _JUNIT_XML

    def late_phase(
        _self: repo_verifier.RepoVerifier,
        delivered: str,
        image_digest: str | None,
        *,
        note: str | None = None,
    ) -> Any:
        record("phase:late")
        return original_phase(
            delivered,
            image_digest,
            note=note,
        )

    def late_run(
        command: list[str],
        **_kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        record("run:late")
        verifier._phase_isolation_evidence = types.MethodType(  # type: ignore[method-assign]
            late_phase,
            verifier,
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    def late_resolve(
        command: list[str],
        *,
        cwd: str,
        env: dict[str, str],
    ) -> list[str]:
        del cwd, env
        record("resolve:late")
        repo_verifier._run_bounded_subprocess = late_run
        return command

    def late_instrument(
        command: list[str],
        report_path: str,
    ) -> tuple[list[str], bool, dict[str, str]]:
        del report_path
        record("instrument:late")
        repo_verifier._resolve_host_command = late_resolve
        return command, True, {}

    def verify_pack(_snapshot: str, _identity: Any) -> None:
        state["pack_verifications"] += 1
        position = state["pack_verifications"]
        record(f"pack:{position}")
        if position == 1:
            repo_verifier.instrument_command = late_instrument

    repo_verifier.execute_repo_suite = execute_suite
    repo_verifier.interpret_repo_suite = lambda _request, *, services: _repo_phase()
    repo_verifier.capture_runtime_identity = lambda _path: _RUNTIME
    repo_verifier.verify_runtime_identity = verify_runtime
    repo_verifier.verify_pack_snapshot = verify_pack
    repo_verifier.instrument_command = fail("instrument")
    repo_verifier._resolve_host_command = fail("resolve")
    repo_verifier._run_bounded_subprocess = fail("run")
    repo_verifier._read_text_or_none = fail("read")
    repo_verifier.parse_junit_xml = fail("parse")
    repo_verifier.evaluate_pack_phase = fail("evaluate")
    repo_verifier.compose_repo_and_pack = fail("compose")
    try:
        verifier = repo_verifier.RepoVerifier(
            mem_limit_mb=0,
            test_command=["suite"],
            timeout=7,
        )
        original_phase = verifier._phase_isolation_evidence
        result = verifier.verify(
            _APP_EDIT,
            {
                "repo_path": str(source),
                "verifier_pack": str(pack),
            },
        )
        assert result.passed
    finally:
        repo_verifier.execute_repo_suite = originals["execute_suite"]
        repo_verifier.interpret_repo_suite = originals["interpret_suite"]
        repo_verifier.capture_runtime_identity = originals["capture_runtime"]
        repo_verifier.verify_runtime_identity = originals["verify_runtime"]
        repo_verifier.verify_pack_snapshot = originals["verify_pack"]
        repo_verifier.instrument_command = originals["instrument"]
        repo_verifier._resolve_host_command = originals["resolve"]
        repo_verifier._run_bounded_subprocess = originals["run"]
        repo_verifier._read_text_or_none = originals["read"]
        repo_verifier.parse_junit_xml = originals["parse"]
        repo_verifier.evaluate_pack_phase = originals["evaluate"]
        repo_verifier.compose_repo_and_pack = originals["compose"]

    return events


def observe_live_container_provider_timing(
    workspace: Path,
    *,
    isolation: str,
) -> list[str]:
    """Observe late instance-method lookup on docker and gVisor pack paths."""

    if isolation not in ("docker", "gvisor"):
        raise ValueError(f"unsupported container isolation: {isolation}")
    source, pack = _write_inputs(workspace, f"live-{isolation}-provider")
    events: list[str] = []
    state = {"pack_verifications": 0}
    originals = {
        "execute_suite": repo_verifier.execute_repo_suite,
        "interpret_suite": repo_verifier.interpret_repo_suite,
        "capture_runtime": repo_verifier.capture_runtime_identity,
        "verify_runtime": repo_verifier.verify_runtime_identity,
        "verify_pack": repo_verifier.verify_pack_snapshot,
        "read": repo_verifier._read_text_or_none,
        "parse": repo_verifier.parse_junit_xml,
    }

    def execute_suite(request: Any, *, services: Any) -> RepoSuiteExecutionOutcome:
        evidence = services.phase_isolation_evidence()(
            isolation,
            request.resolved_image,
        )
        services.trace.test_command_started = True
        services.trace.test_command_completed = True
        services.trace.repo_suite_isolation_evidence = evidence
        services.trace.primary_isolation_evidence = evidence
        return RepoSuiteExecutionOutcome(
            completed=RepoSuiteCompleted(
                "repo.xml",
                0,
                "",
                "",
                True,
                0.1,
            )
        )

    def late_phase(
        _self: repo_verifier.RepoVerifier,
        delivered: str,
        image_digest: str | None,
        *,
        note: str | None = None,
    ) -> Any:
        events.append("phase:late")
        return original_phase(
            delivered,
            image_digest,
            note=note,
        )

    def late_docker(
        _self: repo_verifier.RepoVerifier,
        _command: list[str],
        _copy: str,
        workdir: str,
        *,
        pack_dir: str | None = None,
    ) -> tuple[str, subprocess.CompletedProcess[str], bool]:
        assert pack_dir is not None
        events.append("docker:late")
        verifier._phase_isolation_evidence = types.MethodType(  # type: ignore[method-assign]
            late_phase,
            verifier,
        )
        return (
            os.path.join(workdir, "judge-result.xml"),
            subprocess.CompletedProcess(["pack"], 0, "", ""),
            True,
        )

    def verify_pack(_snapshot: str, _identity: Any) -> None:
        state["pack_verifications"] += 1
        events.append(f"pack:{state['pack_verifications']}")
        if state["pack_verifications"] == 1:
            verifier._run_docker = types.MethodType(  # type: ignore[method-assign]
                late_docker,
                verifier,
            )

    repo_verifier.execute_repo_suite = execute_suite
    repo_verifier.interpret_repo_suite = lambda _request, *, services: _repo_phase()
    repo_verifier.capture_runtime_identity = lambda _path: _RUNTIME
    repo_verifier.verify_runtime_identity = lambda _path, _baseline: (_RUNTIME, [])
    repo_verifier.verify_pack_snapshot = verify_pack
    repo_verifier._read_text_or_none = lambda _path: _JUNIT_XML
    repo_verifier.parse_junit_xml = lambda _text: JUnitCounts(1, 1, 0, 0)
    try:
        verifier = repo_verifier.RepoVerifier(
            isolation=isolation,
            docker_image="judge:latest",
            mem_limit_mb=0,
            test_command=["suite"],
            timeout=7,
        )
        original_phase = verifier._phase_isolation_evidence
        verifier._resolve_docker_image = lambda: _IMAGE_ID  # type: ignore[method-assign]
        verifier._run_docker = (  # type: ignore[method-assign]
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("snapshotted early docker runner")
            )
        )
        result = verifier.verify(
            _APP_EDIT,
            {
                "repo_path": str(source),
                "verifier_pack": str(pack),
            },
        )
        assert result.passed
    finally:
        repo_verifier.execute_repo_suite = originals["execute_suite"]
        repo_verifier.interpret_repo_suite = originals["interpret_suite"]
        repo_verifier.capture_runtime_identity = originals["capture_runtime"]
        repo_verifier.verify_runtime_identity = originals["verify_runtime"]
        repo_verifier.verify_pack_snapshot = originals["verify_pack"]
        repo_verifier._read_text_or_none = originals["read"]
        repo_verifier.parse_junit_xml = originals["parse"]

    return events


def capture_all(workspace: Path) -> dict[str, Any]:
    """Capture all reviewed verifier-pack cases in one versioned envelope."""

    return {
        "cases": {name: capture_case(name, workspace) for name in CASE_NAMES},
        "schema_version": SCHEMA_VERSION,
    }
