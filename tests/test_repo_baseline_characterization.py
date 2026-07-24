"""Behavioral lock for Guard's pristine repository baseline runner."""

from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace

import pytest

import evoom_guard.adapters as adapters
import evoom_guard.guard as guard_module
from evoom_guard.verifiers import fidelity, repo_baseline, repo_verifier


def _install_successful_baseline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[list[object], Path]:
    events: list[object] = []
    workspace = tmp_path / "owned-baseline"

    class FakeVerifier:
        def __init__(
            self,
            *,
            timeout: int,
            mem_limit_mb: int,
            strict_harness: bool,
        ) -> None:
            events.append(
                (
                    "verifier:init",
                    timeout,
                    mem_limit_mb,
                    strict_harness,
                )
            )

        def _limits(self) -> str:
            events.append("limits")
            return "LIMITS"

        def _command(self, problem: dict[str, str]) -> list[str]:
            events.append(("command", problem))
            return ["default-suite"]

    def make_workspace(*, prefix: str) -> str:
        events.append(("workspace", prefix))
        workspace.mkdir()
        return str(workspace)

    def copy_repository(source: str, destination: str) -> None:
        events.append(("copy", source, destination))
        Path(destination).mkdir()

    def environment(workdir: str) -> dict[str, str]:
        events.append(("environment", workdir))
        return {"JUDGE": "owned"}

    snapshot_count = 0

    def snapshot(
        root: str,
        globs: tuple[str, ...],
        *,
        baseline: object | None = None,
    ) -> dict[str, object]:
        nonlocal snapshot_count
        snapshot_count += 1
        phase = "before" if baseline is None else "after"
        events.append(("snapshot", phase, root, globs, baseline))
        return {"snapshot": snapshot_count}

    def changes(before: object, after: object) -> list[str]:
        events.append(("changes", before, after))
        return []

    def instrument(
        command: list[str],
        report_path: str,
    ) -> tuple[list[str], bool, dict[str, str]]:
        events.append(("instrument", command, report_path))
        return [*command, "--owned-report"], True, {"REPORT": report_path}

    def resolve(
        command: list[str],
        *,
        cwd: str,
        env: dict[str, str],
    ) -> list[str]:
        phase = "setup" if command == ["setup"] else "suite"
        events.append(("resolve", phase, command, cwd, dict(env)))
        return [f"resolved-{phase}"]

    def run(
        command: list[str],
        *,
        cwd: str,
        env: dict[str, str],
        timeout: int,
        preexec_fn: object,
        require_process_group_cleanup_proof: bool,
    ) -> subprocess.CompletedProcess[str]:
        phase = "setup" if command == ["resolved-setup"] else "suite"
        events.append(
            (
                "run",
                phase,
                command,
                cwd,
                dict(env),
                timeout,
                preexec_fn,
                require_process_group_cleanup_proof,
            )
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    junit = SimpleNamespace(total=1)

    def read_report(path: str) -> str:
        events.append(("read", path))
        return "<owned/>"

    def parse_xml(text: str) -> object:
        events.append(("parse-xml", text))
        return junit

    def parse_directory(path: str) -> object:
        events.append(("parse-directory", path))
        raise AssertionError("directory fallback must not run for parseable XML")

    def grade(
        returncode: int,
        observed: object,
        *,
        report_expected: bool,
    ) -> tuple[bool, float, int, int]:
        events.append(("grade", returncode, observed, report_expected))
        return True, 1.0, 1, 1

    def detect(
        returncode: int,
        observed: object,
        *,
        report_expected: bool,
    ) -> bool:
        events.append(("tamper", returncode, observed, report_expected))
        return False

    def cleanup(path: str, *, ignore_errors: bool) -> None:
        events.append(("cleanup", path, ignore_errors))

    monkeypatch.setattr(repo_verifier, "RepoVerifier", FakeVerifier)
    monkeypatch.setattr(tempfile, "mkdtemp", make_workspace)
    monkeypatch.setattr(guard_module, "copy_repo_tree", copy_repository)
    monkeypatch.setattr(guard_module, "judge_subprocess_env", environment)
    monkeypatch.setattr(fidelity, "setup_fidelity_snapshot", snapshot)
    monkeypatch.setattr(fidelity, "setup_fidelity_changes", changes)
    monkeypatch.setattr(adapters, "instrument_command", instrument)
    monkeypatch.setattr(guard_module, "_resolve_host_command", resolve)
    monkeypatch.setattr(guard_module, "_run_bounded_subprocess", run)
    monkeypatch.setattr(repo_verifier, "read_junit_xml", read_report)
    monkeypatch.setattr(repo_verifier, "parse_junit_xml", parse_xml)
    monkeypatch.setattr(repo_verifier, "parse_junit_dir", parse_directory)
    monkeypatch.setattr(repo_verifier, "grade_repo_run", grade)
    monkeypatch.setattr(repo_verifier, "detect_tamper", detect)
    monkeypatch.setattr(guard_module.shutil, "rmtree", cleanup)
    return events, workspace


def test_baseline_effect_order_trust_boundary_and_cleanup_are_frozen(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events, workspace = _install_successful_baseline(monkeypatch, tmp_path)
    source = tmp_path / "source"
    source.mkdir()

    result = guard_module._run_baseline_suite(
        str(source),
        test_command=["suite"],
        setup_command=["setup"],
        setup_output_globs=("generated/**",),
        timeout=17,
        mem_limit_mb=23,
        strict_harness=True,
    )

    assert result == {
        "verdict": "PASS",
        "tests_passed": 1,
        "tests_total": 1,
    }
    expected_operations = [
        "verifier:init",
        "workspace",
        "copy",
        "environment",
        "snapshot",
        "resolve",
    ]
    if os.name == "posix":
        expected_operations.append("limits")
    expected_operations.extend(
        [
            "run",
            "snapshot",
            "changes",
            "command",
            "instrument",
            "resolve",
        ]
    )
    if os.name == "posix":
        expected_operations.append("limits")
    expected_operations.extend(
        [
            "run",
            "read",
            "parse-xml",
            "grade",
            "tamper",
            "cleanup",
        ]
    )
    assert [
        event if isinstance(event, str) else event[0]
        for event in events
    ] == expected_operations

    candidate_copy = workspace / "repo"
    instrument_event = next(event for event in events if isinstance(event, tuple) and event[0] == "instrument")
    report_path = Path(instrument_event[2])
    assert report_path == workspace / "judge-result.xml"
    assert os.path.commonpath((str(report_path), str(candidate_copy))) != str(candidate_copy)

    run_events = [
        event
        for event in events
        if isinstance(event, tuple) and event[0] == "run"
    ]
    assert [event[1] for event in run_events] == ["setup", "suite"]
    assert [event[-2] for event in run_events] == (
        ["LIMITS", "LIMITS"] if os.name == "posix" else [None, None]
    )
    assert [event[-1] for event in run_events] == [True, True]
    assert events[-1] == ("cleanup", str(workspace), True)


def test_baseline_resolves_host_effects_at_each_historical_operation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events, _workspace = _install_successful_baseline(monkeypatch, tmp_path)
    source = tmp_path / "source"
    source.mkdir()
    early_resolve = guard_module._resolve_host_command
    early_run = guard_module._run_bounded_subprocess

    def late_resolve(
        command: list[str],
        *,
        cwd: str,
        env: dict[str, str],
    ) -> list[str]:
        events.append(("resolve-late", command, cwd, dict(env)))
        return ["resolved-suite"]

    def late_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        events.append(("run-late", command, kwargs))
        return subprocess.CompletedProcess(command, 0, "", "")

    def setup_run_then_rebind(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        events.append(("run-early", command, kwargs))
        monkeypatch.setattr(guard_module, "_resolve_host_command", late_resolve)
        monkeypatch.setattr(guard_module, "_run_bounded_subprocess", late_run)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(guard_module, "_run_bounded_subprocess", setup_run_then_rebind)

    result = guard_module._run_baseline_suite(
        str(source),
        test_command=["suite"],
        setup_command=["setup"],
        setup_output_globs=(),
        timeout=17,
        mem_limit_mb=23,
        strict_harness=True,
    )

    assert result["verdict"] == "PASS"
    operation_names = [
        event[0]
        for event in events
        if isinstance(event, tuple)
        and event[0] in {"resolve", "resolve-late", "run-early", "run-late"}
    ]
    assert operation_names == ["resolve", "run-early", "resolve-late", "run-late"]
    assert early_resolve is not late_resolve
    assert early_run is not late_run


def test_baseline_cleanup_runs_after_unhandled_primary_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[object] = []
    workspace = tmp_path / "owned-baseline"

    class FakeVerifier:
        def __init__(self, **_kwargs: object) -> None:
            events.append("verifier:init")

    def make_workspace(*, prefix: str) -> str:
        events.append(("workspace", prefix))
        workspace.mkdir()
        return str(workspace)

    primary = RuntimeError("copy failed")

    def fail_copy(_source: str, _destination: str) -> None:
        events.append("copy")
        raise primary

    def cleanup(path: str, *, ignore_errors: bool) -> None:
        events.append(("cleanup", path, ignore_errors))

    monkeypatch.setattr(repo_verifier, "RepoVerifier", FakeVerifier)
    monkeypatch.setattr(tempfile, "mkdtemp", make_workspace)
    monkeypatch.setattr(guard_module, "copy_repo_tree", fail_copy)
    monkeypatch.setattr(guard_module.shutil, "rmtree", cleanup)

    with pytest.raises(RuntimeError) as raised:
        guard_module._run_baseline_suite(
            str(tmp_path / "source"),
            test_command=["suite"],
            setup_command=None,
            setup_output_globs=(),
            timeout=17,
            mem_limit_mb=23,
            strict_harness=True,
        )

    assert raised.value is primary
    assert events == [
        "verifier:init",
        ("workspace", "evo_baseline_"),
        "copy",
        ("cleanup", str(workspace), True),
    ]


def test_repo_baseline_owner_exposes_an_immutable_request_contract() -> None:
    request = repo_baseline.RepoBaselineRequest(
        repository_path="repository",
        test_command=["suite"],
        setup_command=None,
        setup_output_globs=(),
        timeout=17,
        mem_limit_mb=23,
        strict_harness=True,
    )

    assert repo_baseline.run_repo_baseline.__module__ == (
        "evoom_guard.verifiers.repo_baseline"
    )
    assert not hasattr(request, "__dict__")
    with pytest.raises(FrozenInstanceError):
        request.strict_harness = False  # type: ignore[misc]
