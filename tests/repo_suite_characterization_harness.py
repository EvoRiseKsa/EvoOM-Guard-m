"""Deterministic characterization of RepoVerifier's repository-suite phase."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import types
from collections.abc import Callable
from pathlib import Path
from typing import Any

from evoom_guard.contracts import VerdictResult
from evoom_guard.domain.verification import JUnitCounts
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

SCHEMA_VERSION = "repo-suite-characterization-v1"
CASE_NAMES = (
    "docker_containment_started",
    "docker_containment_unstarted",
    "docker_exit_125",
    "docker_junit_file_pass",
    "docker_not_found",
    "docker_output_limit_started",
    "docker_output_limit_unstarted",
    "docker_timeout_started",
    "docker_timeout_unstarted",
    "gvisor_junit_file_pass",
    "host_containment",
    "host_junit_directory_pass",
    "host_junit_file_pass",
    "host_not_found",
    "host_output_limit",
    "host_timeout",
    "pack_configured_host_timeout",
)

_APP_EDIT = "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n"
_IMAGE_ID = "sha256:" + "d" * 64
_JUNIT_XML = (
    '<testsuite tests="1" failures="0" errors="0" skipped="0">'
    '<testcase classname="suite" name="passes"/></testsuite>'
)
_DIRECTORY_DIGEST = "e" * 64
_RUNTIME_TREE_DIGEST = "<PLATFORM-BOUND-RUNTIME-TREE-SHA256>"


def canonical_json(value: Any) -> str:
    """Return stable, human-reviewable JSON."""

    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _normalized_result(result: VerdictResult) -> dict[str, Any]:
    artifact = copy.deepcopy(result.artifact)
    artifact.pop("elapsed", None)
    artifact.pop("runtime_identity_elapsed_ms", None)
    runtime_tree_sha256 = artifact.get("runtime_tree_sha256")
    if runtime_tree_sha256 is not None:
        if (
            not isinstance(runtime_tree_sha256, str)
            or len(runtime_tree_sha256) != 64
            or any(character not in "0123456789abcdef" for character in runtime_tree_sha256)
        ):
            raise AssertionError("runtime-tree characterization digest is not canonical SHA-256")
        # Runtime-tree V1 deliberately binds executable permission bits.  The
        # same controlled bytes therefore have different identities on
        # Windows and POSIX.  Freeze the presence and shape here; dedicated
        # runtime-identity tests retain exact digest semantics.
        artifact["runtime_tree_sha256"] = _RUNTIME_TREE_DIGEST
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
    completed = subprocess.CompletedProcess(["suite"], 0, "suite stdout", "suite stderr")
    effects: dict[str, object] = {
        "docker_containment_started": DockerRunContainmentError(
            "docker cleanup missing", container_started=True
        ),
        "docker_containment_unstarted": DockerRunContainmentError(
            "docker cleanup missing", container_started=False
        ),
        "docker_exit_125": subprocess.CompletedProcess(
            ["docker", "suite"], 125, "raw stdout", "raw stderr"
        ),
        "docker_junit_file_pass": completed,
        "docker_not_found": FileNotFoundError("docker"),
        "docker_output_limit_started": _docker_output_limit(started=True),
        "docker_output_limit_unstarted": _docker_output_limit(started=False),
        "docker_timeout_started": _docker_timeout(started=True),
        "docker_timeout_unstarted": _docker_timeout(started=False),
        "gvisor_junit_file_pass": completed,
        "host_containment": ProcessContainmentError("host cleanup missing"),
        "host_junit_directory_pass": completed,
        "host_junit_file_pass": completed,
        "host_not_found": FileNotFoundError("suite-tool"),
        "host_output_limit": ProcessOutputLimitExceeded(99),
        "host_timeout": subprocess.TimeoutExpired(["suite-tool"], 7),
        "pack_configured_host_timeout": subprocess.TimeoutExpired(["suite-tool"], 7),
    }
    return effects[case_name]


def _is_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath(
            (os.path.abspath(path), os.path.abspath(root))
        ) == os.path.abspath(root)
    except ValueError:
        return False


def capture_case(case_name: str, workspace: Path) -> dict[str, Any]:
    """Capture one repository-suite branch and its dependency-call order."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown repository suite case: {case_name}")

    source = workspace / f"source-{case_name}"
    source.mkdir(parents=True)
    (source / "app.py").write_bytes(b"VALUE = 1\n")

    pack: Path | None = None
    if case_name == "pack_configured_host_timeout":
        pack = workspace / f"pack-{case_name}"
        pack.mkdir()
        (pack / "test_contract.py").write_bytes(b"def test_contract():\n    assert True\n")

    events: list[dict[str, Any]] = []
    effect = _runner_effect(case_name)
    isolation = (
        "gvisor"
        if case_name.startswith("gvisor_")
        else ("docker" if case_name.startswith("docker_") else "subprocess")
    )
    container_mode = isolation in ("docker", "gvisor")
    directory_case = case_name == "host_junit_directory_pass"
    state: dict[str, str] = {}

    originals = {
        "instrument": repo_verifier.instrument_command,
        "resolve_host": repo_verifier._resolve_host_command,
        "run": repo_verifier._run_bounded_subprocess,
        "read": repo_verifier._read_text_or_none,
        "parse_xml": repo_verifier.parse_junit_xml,
        "parse_dir": repo_verifier.parse_junit_dir_with_digest,
        "evaluate": repo_verifier.evaluate_repo_phase,
        "distill": repo_verifier.distill_diagnostics,
        "verify_pack": repo_verifier.verify_pack_snapshot,
    }

    def instrument(command: list[str], report_path: str) -> tuple[list[str], bool, dict[str, str]]:
        state["report"] = report_path
        events.append(
            {
                "command": list(command),
                "op": "instrument",
            }
        )
        return ["instrumented-suite"], True, {"EVOGUARD_REPORT": report_path}

    def resolve_host(
        command: list[str],
        *,
        cwd: str,
        env: dict[str, str],
    ) -> list[str]:
        state["copy"] = cwd
        events.append(
            {
                "command": list(command),
                "cwd_is_candidate": Path(cwd).name == "repo",
                "op": "resolve-host",
                "report_env_bound": "EVOGUARD_REPORT" in env,
                "report_outside_candidate": not _is_within(
                    state["report"],
                    cwd,
                ),
            }
        )
        return ["resolved-suite"]

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

    def read_report(path: str) -> str | None:
        events.append(
            {
                "matches_instrumented_path": path == state.get("report"),
                "op": "read-report",
                "outside_candidate": ("copy" in state and not _is_within(path, state["copy"])),
            }
        )
        return None if directory_case else _JUNIT_XML

    def parse_xml(text: str) -> JUnitCounts | None:
        events.append({"bytes": len(text.encode("utf-8")), "op": "parse-xml"})
        if directory_case:
            return None
        return JUnitCounts(passed=1, total=1, failures=0, errors=0)

    def parse_dir(path: str) -> tuple[JUnitCounts, str] | None:
        events.append(
            {
                "matches_owned_sibling": path == state.get("report", "") + ".d",
                "op": "parse-directory",
                "outside_candidate": ("copy" in state and not _is_within(path, state["copy"])),
            }
        )
        if not directory_case:
            return None
        return (
            JUnitCounts(passed=1, total=1, failures=0, errors=0),
            _DIRECTORY_DIGEST,
        )

    def evaluate(evidence: Any, *, strict_harness: bool) -> Any:
        events.append(
            {
                "junit_present": evidence.junit is not None,
                "op": "evaluate",
                "report_expected": evidence.report_expected,
                "strict": strict_harness,
            }
        )
        return originals["evaluate"](
            evidence,
            strict_harness=strict_harness,
        )

    def distill(text: str) -> str:
        events.append({"op": "distill", "text": text})
        return "DISTILLED"

    def verify_pack(*_args: Any, **_kwargs: Any) -> None:
        events.append({"op": "verify-pack"})

    repo_verifier.instrument_command = instrument
    repo_verifier._resolve_host_command = resolve_host
    repo_verifier._run_bounded_subprocess = host_run
    repo_verifier._read_text_or_none = read_report
    repo_verifier.parse_junit_xml = parse_xml
    repo_verifier.parse_junit_dir_with_digest = parse_dir
    repo_verifier.evaluate_repo_phase = evaluate
    repo_verifier.distill_diagnostics = distill
    repo_verifier.verify_pack_snapshot = verify_pack
    try:
        verifier = repo_verifier.RepoVerifier(
            isolation=isolation,
            docker_image="judge:latest" if container_mode else None,
            mem_limit_mb=0,
            strict_harness=case_name == "host_junit_file_pass",
            test_command=["suite-tool", "--run"],
            timeout=7,
        )

        def command(
            _self: repo_verifier.RepoVerifier,
            _problem: repo_verifier.RepoProblem | dict,
        ) -> list[str]:
            events.append({"op": "command"})
            return ["suite-tool", "--run"]

        verifier._command = types.MethodType(command, verifier)  # type: ignore[method-assign]
        original_phase_evidence = verifier._phase_isolation_evidence

        def phase_evidence(
            _self: repo_verifier.RepoVerifier,
            delivered: str,
            image_digest: str | None,
            *,
            note: str | None = None,
        ) -> Any:
            events.append(
                {
                    "delivered": delivered,
                    "image_digest": image_digest,
                    "note": note,
                    "op": "phase-evidence",
                }
            )
            return original_phase_evidence(
                delivered,
                image_digest,
                note=note,
            )

        verifier._phase_isolation_evidence = types.MethodType(  # type: ignore[method-assign]
            phase_evidence,
            verifier,
        )

        if container_mode:

            def resolve_image(
                _self: repo_verifier.RepoVerifier,
            ) -> str:
                events.append({"op": "resolve-image"})
                return _IMAGE_ID

            def docker_run(
                _self: repo_verifier.RepoVerifier,
                base_command: list[str],
                copy_path: str,
                workdir: str,
                *,
                pack_dir: str | None = None,
            ) -> tuple[
                str,
                subprocess.CompletedProcess[str],
                bool,
            ]:
                state["copy"] = copy_path
                report = os.path.join(workdir, "out", "judge-result.xml")
                state["report"] = report
                events.append(
                    {
                        "command": list(base_command),
                        "copy_is_candidate": Path(copy_path).name == "repo",
                        "op": "docker-run",
                        "pack_dir": pack_dir,
                        "report_outside_candidate": not _is_within(report, copy_path),
                    }
                )
                if isinstance(effect, BaseException):
                    raise effect
                assert isinstance(effect, subprocess.CompletedProcess)
                return report, effect, True

            verifier._resolve_docker_image = types.MethodType(  # type: ignore[method-assign]
                resolve_image,
                verifier,
            )
            verifier._run_docker = types.MethodType(  # type: ignore[method-assign]
                docker_run,
                verifier,
            )

        problem: dict[str, Any] = {"repo_path": str(source)}
        if pack is not None:
            problem["verifier_pack"] = str(pack)
        result = verifier.verify(_APP_EDIT, problem)
    finally:
        repo_verifier.instrument_command = originals["instrument"]
        repo_verifier._resolve_host_command = originals["resolve_host"]
        repo_verifier._run_bounded_subprocess = originals["run"]
        repo_verifier._read_text_or_none = originals["read"]
        repo_verifier.parse_junit_xml = originals["parse_xml"]
        repo_verifier.parse_junit_dir_with_digest = originals["parse_dir"]
        repo_verifier.evaluate_repo_phase = originals["evaluate"]
        repo_verifier.distill_diagnostics = originals["distill"]
        repo_verifier.verify_pack_snapshot = originals["verify_pack"]

    return {
        "events": events,
        "result": _normalized_result(result),
    }


def observe_live_provider_timing(
    workspace: Path,
    *,
    on_event: Callable[[str], None] | None = None,
) -> list[str]:
    """Observe provider rebinding at every historical suite call position."""

    source = workspace / "source-live-provider-timing"
    source.mkdir(parents=True, exist_ok=True)
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    events: list[str] = []

    originals = {
        "instrument": repo_verifier.instrument_command,
        "resolve": repo_verifier._resolve_host_command,
        "run": repo_verifier._run_bounded_subprocess,
        "read": repo_verifier._read_text_or_none,
        "parse": repo_verifier.parse_junit_xml,
        "evaluate": repo_verifier.evaluate_repo_phase,
    }

    def record(event: str) -> None:
        events.append(event)
        if on_event is not None:
            on_event(event)

    def fail(name: str) -> Callable[..., Any]:
        def unexpected(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError(f"snapshotted early provider: {name}")

        return unexpected

    repo_verifier.instrument_command = fail("instrument")
    repo_verifier._resolve_host_command = fail("resolve")
    repo_verifier._run_bounded_subprocess = fail("run")
    repo_verifier._read_text_or_none = fail("read")
    repo_verifier.parse_junit_xml = fail("parse")
    repo_verifier.evaluate_repo_phase = fail("evaluate")
    try:
        verifier = repo_verifier.RepoVerifier(
            mem_limit_mb=0,
            test_command=["suite"],
            timeout=7,
        )
        original_phase_evidence = verifier._phase_isolation_evidence

        def late_evaluate(evidence: Any, *, strict_harness: bool) -> Any:
            record("evaluate:late")
            return originals["evaluate"](
                evidence,
                strict_harness=strict_harness,
            )

        def late_parse(_text: str) -> JUnitCounts:
            record("parse:late")
            repo_verifier.evaluate_repo_phase = late_evaluate
            return JUnitCounts(passed=1, total=1, failures=0, errors=0)

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
            repo_verifier._read_text_or_none = late_read
            return original_phase_evidence(
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

        def command(
            _self: repo_verifier.RepoVerifier,
            _problem: repo_verifier.RepoProblem | dict,
        ) -> list[str]:
            record("command")
            repo_verifier.instrument_command = late_instrument
            return ["suite"]

        verifier._command = types.MethodType(command, verifier)  # type: ignore[method-assign]
        result = verifier.verify(_APP_EDIT, {"repo_path": str(source)})
        assert result.passed
    finally:
        repo_verifier.instrument_command = originals["instrument"]
        repo_verifier._resolve_host_command = originals["resolve"]
        repo_verifier._run_bounded_subprocess = originals["run"]
        repo_verifier._read_text_or_none = originals["read"]
        repo_verifier.parse_junit_xml = originals["parse"]
        repo_verifier.evaluate_repo_phase = originals["evaluate"]

    return events


def observe_live_container_provider_timing(workspace: Path) -> list[str]:
    """Observe late instance-method lookup on the container suite path."""

    source = workspace / "source-live-container-provider-timing"
    source.mkdir(parents=True, exist_ok=True)
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    events: list[str] = []
    verifier = repo_verifier.RepoVerifier(
        isolation="docker",
        docker_image="judge:latest",
        mem_limit_mb=0,
        test_command=["suite"],
        timeout=7,
    )
    original_phase_evidence = verifier._phase_isolation_evidence

    def fail_docker(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("snapshotted early docker suite runner")

    verifier._run_docker = fail_docker  # type: ignore[method-assign]

    def late_phase(
        _self: repo_verifier.RepoVerifier,
        delivered: str,
        image_digest: str | None,
        *,
        note: str | None = None,
    ) -> Any:
        events.append("phase:late")
        return original_phase_evidence(
            delivered,
            image_digest,
            note=note,
        )

    def late_docker(
        _self: repo_verifier.RepoVerifier,
        _base_command: list[str],
        _copy_path: str,
        workdir: str,
        *,
        pack_dir: str | None = None,
    ) -> tuple[str, subprocess.CompletedProcess[str], bool]:
        del pack_dir
        events.append("docker:late")
        verifier._phase_isolation_evidence = types.MethodType(  # type: ignore[method-assign]
            late_phase,
            verifier,
        )
        return (
            os.path.join(workdir, "judge-result.xml"),
            subprocess.CompletedProcess(["suite"], 0, "", ""),
            False,
        )

    def command(
        _self: repo_verifier.RepoVerifier,
        _problem: repo_verifier.RepoProblem | dict,
    ) -> list[str]:
        events.append("command")
        verifier._run_docker = types.MethodType(  # type: ignore[method-assign]
            late_docker,
            verifier,
        )
        return ["suite"]

    verifier._resolve_docker_image = (  # type: ignore[method-assign]
        lambda: _IMAGE_ID
    )
    verifier._command = types.MethodType(command, verifier)  # type: ignore[method-assign]
    result = verifier.verify(_APP_EDIT, {"repo_path": str(source)})
    assert result.passed
    return events


def capture_all(workspace: Path) -> dict[str, Any]:
    """Capture all reviewed suite cases in one versioned envelope."""

    return {
        "cases": {name: capture_case(name, workspace) for name in CASE_NAMES},
        "schema_version": SCHEMA_VERSION,
    }
