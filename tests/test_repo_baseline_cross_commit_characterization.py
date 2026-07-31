"""Adversarial contracts shared by the pre- and post-extraction baseline runner."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

import evoom_guard.adapters as adapters
import evoom_guard.guard as guard_module
from evoom_guard.verifiers import fidelity, repo_verifier


def _install_success_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    copy_hook: Callable[[], None] | None = None,
    command_hook: Callable[[], None] | None = None,
    run_hook: Callable[[list[str]], None] | None = None,
    snapshot_hook: Callable[[object | None], None] | None = None,
) -> tuple[list[object], object]:
    events: list[object] = []
    workspace = tmp_path / "owned-baseline"
    real_rmtree = shutil.rmtree
    limits = object()

    class FakeVerifier:
        def __init__(self, **kwargs: object) -> None:
            events.append(("verifier", kwargs))

        def _command(self, context: dict[str, object]) -> list[str]:
            events.append(("default-command", dict(context)))
            if command_hook is not None:
                command_hook()
            return ["default-suite"]

        def _limits(self) -> object:
            events.append("limits")
            return limits

    def make_workspace(*, prefix: str) -> str:
        events.append(("workspace", prefix))
        workspace.mkdir()
        return str(workspace)

    def copy_repository(source: str, destination: str) -> None:
        events.append(("copy", source, destination))
        if copy_hook is not None:
            copy_hook()

    def judge_environment(workdir: str) -> dict[str, str]:
        events.append(("environment", workdir))
        return {"BASE": "1"}

    def snapshot(
        root: str,
        globs: tuple[str, ...],
        *,
        baseline: object | None = None,
    ) -> object:
        events.append(("snapshot", root, globs, baseline))
        if snapshot_hook is not None:
            snapshot_hook(baseline)
        return "before" if baseline is None else "after"

    def instrument(
        command: list[str],
        report_path: str,
    ) -> tuple[list[str], bool, dict[str, str]]:
        events.append(("instrument", list(command), report_path))
        return list(command), True, {"REPORT": report_path}

    def resolve(
        command: list[str],
        *,
        cwd: str,
        env: dict[str, str],
    ) -> list[str]:
        events.append(("resolve", list(command), cwd, dict(env)))
        return list(command)

    def run(
        command: list[str],
        *,
        cwd: str,
        env: dict[str, str],
        timeout: int,
        preexec_fn: object,
        require_process_group_cleanup_proof: bool,
    ) -> subprocess.CompletedProcess[str]:
        events.append(
            (
                "run",
                list(command),
                cwd,
                dict(env),
                timeout,
                preexec_fn,
                require_process_group_cleanup_proof,
            )
        )
        if run_hook is not None:
            run_hook(command)
        return subprocess.CompletedProcess(command, 0)

    def cleanup(path: str) -> None:
        events.append(("cleanup", path))
        real_rmtree(path)

    monkeypatch.setattr(repo_verifier, "RepoVerifier", FakeVerifier)
    monkeypatch.setattr("tempfile.mkdtemp", make_workspace)
    monkeypatch.setattr(guard_module, "copy_repo_tree", copy_repository)
    monkeypatch.setattr(guard_module, "judge_subprocess_env", judge_environment)
    monkeypatch.setattr(fidelity, "setup_fidelity_snapshot", snapshot)
    monkeypatch.setattr(fidelity, "setup_fidelity_changes", lambda *_args: [])
    monkeypatch.setattr(adapters, "instrument_command", instrument)
    monkeypatch.setattr(guard_module, "_resolve_host_command", resolve)
    monkeypatch.setattr(guard_module, "_run_bounded_subprocess", run)
    monkeypatch.setattr(repo_verifier, "read_junit_xml", lambda _path: "<xml />")
    monkeypatch.setattr(
        repo_verifier,
        "parse_junit_xml",
        lambda _xml: SimpleNamespace(total=1),
    )
    monkeypatch.setattr(repo_verifier, "parse_junit_dir", lambda _path: None)
    monkeypatch.setattr(
        repo_verifier,
        "grade_repo_run",
        lambda *_args, **_kwargs: (True, 1.0, 1, 1),
    )
    monkeypatch.setattr(
        repo_verifier,
        "detect_tamper",
        lambda *_args, **_kwargs: False,
    )
    monkeypatch.setattr(guard_module.shutil, "rmtree", cleanup)
    return events, limits


def test_baseline_cleanup_failure_preserves_an_active_primary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R3 hardening reports cleanup failure without replacing the primary."""

    workspace = tmp_path / "owned-baseline"
    primary = RuntimeError("repository copy failed")
    cleanup_failure = OSError("cleanup denied")

    class FakeVerifier:
        def __init__(self, **_kwargs: object) -> None:
            pass

    def make_workspace(*, prefix: str) -> str:
        assert prefix == "evo_baseline_"
        workspace.mkdir()
        return str(workspace)

    def fail_copy(_source: str, _destination: str) -> None:
        raise primary

    def fail_cleanup(_path: str) -> None:
        raise cleanup_failure

    monkeypatch.setattr(repo_verifier, "RepoVerifier", FakeVerifier)
    monkeypatch.setattr("tempfile.mkdtemp", make_workspace)
    monkeypatch.setattr(guard_module, "copy_repo_tree", fail_copy)
    monkeypatch.setattr(guard_module.shutil, "rmtree", fail_cleanup)

    with pytest.raises(RuntimeError) as caught:
        guard_module._run_baseline_suite(
            str(tmp_path / "source"),
            test_command=["suite"],
            setup_command=None,
            setup_output_globs=(),
            timeout=17,
            mem_limit_mb=23,
            strict_harness=True,
        )

    assert caught.value is primary
    assert any(
        "OSError: cleanup denied" in note
        for note in getattr(primary, "__notes__", [])
    )


def test_baseline_commands_keep_caller_lists_live_until_historical_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_command = ["suite", "early"]
    setup_command = ["setup", "early"]

    def mutate_setup(baseline: object | None) -> None:
        if baseline is None:
            setup_command[:] = ["setup", "late"]

    def mutate_test() -> None:
        test_command[:] = ["suite", "late"]

    events, _limits = _install_success_path(
        monkeypatch,
        tmp_path,
        command_hook=mutate_test,
        snapshot_hook=mutate_setup,
    )

    result = guard_module._run_baseline_suite(
        str(tmp_path / "source"),
        test_command=test_command,
        setup_command=setup_command,
        setup_output_globs=(),
        timeout=17,
        mem_limit_mb=23,
        strict_harness=True,
    )

    assert result["verdict"] == "PASS"
    resolved = [
        event[1]
        for event in events
        if isinstance(event, tuple) and event[0] == "resolve"
    ]
    assert resolved == [["setup", "late"], ["suite", "late"]]


def test_baseline_uses_guard_os_path_and_platform_at_each_historical_site(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    joins: list[tuple[str, tuple[str, ...]]] = []
    real_join = os.path.join

    def tracked_join(label: str) -> Callable[..., str]:
        def join(*parts: str) -> str:
            joins.append((label, parts))
            return real_join(*parts)

        return join

    early_os = SimpleNamespace(
        name="nt",
        path=SimpleNamespace(join=tracked_join("early")),
    )
    late_os = SimpleNamespace(
        name="posix",
        path=SimpleNamespace(join=tracked_join("late")),
    )

    def replace_guard_os() -> None:
        monkeypatch.setattr(guard_module, "os", late_os)

    monkeypatch.setattr(guard_module, "os", early_os)
    events, limits = _install_success_path(
        monkeypatch,
        tmp_path,
        copy_hook=replace_guard_os,
    )

    result = guard_module._run_baseline_suite(
        str(tmp_path / "source"),
        test_command=["suite"],
        setup_command=None,
        setup_output_globs=(),
        timeout=17,
        mem_limit_mb=23,
        strict_harness=True,
    )

    assert result["verdict"] == "PASS"
    assert [label for label, _parts in joins] == ["early", "late"]
    runs = [
        event
        for event in events
        if isinstance(event, tuple) and event[0] == "run"
    ]
    assert len(runs) == 1
    assert runs[0][5] is limits


@pytest.mark.parametrize("phase", ["setup", "suite"])
@pytest.mark.parametrize(
    "matcher",
    ["os-error", "containment", "output-limit", "timeout"],
)
def test_baseline_resolves_operational_exception_matchers_at_catch_time(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    phase: str,
    matcher: str,
) -> None:
    """Guard globals used by historical ``except`` clauses remain live."""

    class LateOperationalError(Exception):
        pass

    def rebind_and_raise(_command: list[str]) -> None:
        if matcher == "os-error":
            monkeypatch.setattr(
                guard_module,
                "OSError",
                LateOperationalError,
                raising=False,
            )
        elif matcher == "containment":
            monkeypatch.setattr(
                guard_module,
                "_SubprocessContainmentError",
                LateOperationalError,
            )
        elif matcher == "output-limit":
            monkeypatch.setattr(
                guard_module,
                "_SubprocessOutputLimitExceeded",
                LateOperationalError,
            )
        else:
            monkeypatch.setattr(
                guard_module,
                "subprocess",
                SimpleNamespace(TimeoutExpired=LateOperationalError),
            )
        raise LateOperationalError(matcher)

    _install_success_path(
        monkeypatch,
        tmp_path,
        run_hook=rebind_and_raise,
    )

    result = guard_module._run_baseline_suite(
        str(tmp_path / "source"),
        test_command=["suite"],
        setup_command=["setup"] if phase == "setup" else None,
        setup_output_globs=(),
        timeout=17,
        mem_limit_mb=23,
        strict_harness=True,
    )

    expected: dict[str, object] = {
        "verdict": "NO_CLEAN_VERDICT",
        "tests_passed": None,
        "tests_total": None,
    }
    if phase == "setup":
        expected["setup_fidelity"] = "unverified"
    assert result == expected


def test_baseline_snapshots_setup_fidelity_error_at_facade_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The historical function-local import is frozen once, at call entry."""

    class EntrySetupFidelityError(Exception):
        pass

    class ReboundSetupFidelityError(Exception):
        pass

    monkeypatch.setattr(
        repo_verifier,
        "SetupFidelityError",
        EntrySetupFidelityError,
    )

    def rebind_and_raise(_command: list[str]) -> None:
        monkeypatch.setattr(
            repo_verifier,
            "SetupFidelityError",
            ReboundSetupFidelityError,
        )
        raise EntrySetupFidelityError("entry binding must remain active")

    _install_success_path(
        monkeypatch,
        tmp_path,
        run_hook=rebind_and_raise,
    )

    result = guard_module._run_baseline_suite(
        str(tmp_path / "source"),
        test_command=["suite"],
        setup_command=["setup"],
        setup_output_globs=(),
        timeout=17,
        mem_limit_mb=23,
        strict_harness=True,
    )

    assert result == {
        "verdict": "NO_CLEAN_VERDICT",
        "tests_passed": None,
        "tests_total": None,
        "setup_fidelity": "unverified",
    }
