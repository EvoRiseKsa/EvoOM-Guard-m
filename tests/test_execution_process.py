"""Characterization and equivalence tests for the execution process kernel."""

from __future__ import annotations

import ast
import errno
import math
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import evoom_guard.execution.process as process_module
from evoom_guard.execution import (
    BoundedProcessRequest,
    PosixRLimitSpec,
    ProcessContainmentError,
    ProcessGroupCleanupUnavailable,
    ProcessLimits,
    ProcessOutputLimitExceeded,
    execute_bounded_process,
    run_bounded_subprocess,
)
from evoom_guard.verifiers import repo_verifier


def _command(source: str) -> list[str]:
    return [sys.executable, "-c", source]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_output_bytes": -1},
        {"read_chunk_bytes": 0},
        {"termination_grace_seconds": -0.1},
        {"termination_grace_seconds": math.nan},
        {"kill_grace_seconds": -0.1},
        {"reader_join_seconds": -0.1},
    ],
)
def test_process_limits_reject_unbounded_or_invalid_values(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        ProcessLimits(**kwargs)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"cpu_seconds": 0},
        {"cpu_seconds": True},
        {"cpu_seconds": 1.5},
        {"address_space_bytes": -1},
        {"address_space_bytes": False},
    ],
)
def test_posix_rlimit_spec_rejects_ambiguous_values(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        PosixRLimitSpec(**kwargs)


def test_arbitrary_preexec_callback_is_rejected_before_launch() -> None:
    with pytest.raises(ValueError, match="preexec_fn callbacks are unsafe"):
        BoundedProcessRequest.from_command(
            ["candidate"],
            cwd=None,
            env=None,
            timeout=1,
            preexec_fn=lambda: None,  # type: ignore[arg-type]
        )


def test_posix_rlimit_launcher_does_not_depend_on_module_file_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_member = "/opt/evo-guard.pyz/evoom_guard/execution/process.py"
    monkeypatch.setattr(process_module, "__file__", archive_member)

    command = process_module._posix_rlimit_launcher_command(
        ["candidate", "--flag"],
        PosixRLimitSpec(cpu_seconds=8, address_space_bytes=1024),
        17,
    )

    assert command[:4] == [sys.executable, "-I", "-S", "-c"]
    assert archive_member not in command
    assert "evoom_guard" not in command[4]
    assert command[5:] == [
        "--_evoguard-posix-rlimit-launcher",
        "8",
        "1024",
        "17",
        "--",
        "candidate",
        "--flag",
    ]


def test_posix_exec_status_pipe_moves_descriptors_out_of_stdio(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    duplicated = iter((2, 3, 4))
    closed: list[int] = []
    inheritability: list[tuple[int, bool]] = []
    monkeypatch.setattr(process_module.os, "pipe", lambda: (0, 1))
    monkeypatch.setattr(process_module.os, "dup", lambda descriptor: next(duplicated))
    monkeypatch.setattr(process_module.os, "close", closed.append)
    monkeypatch.setattr(
        process_module.os,
        "set_inheritable",
        lambda descriptor, inheritable: inheritability.append((descriptor, inheritable)),
    )

    assert process_module._open_posix_exec_status_pipe() == (3, 4)
    assert closed == [0, 2, 1]
    assert inheritability == [(3, False), (4, False)]


@pytest.mark.parametrize("invalid", [0, 1, None, "true", object()])
def test_typed_request_rejects_non_boolean_cleanup_requirement(
    invalid: object,
) -> None:
    with pytest.raises(
        ValueError,
        match="require_process_group_cleanup_proof must be a bool",
    ):
        BoundedProcessRequest.from_command(
            ["candidate"],
            cwd=None,
            env=None,
            timeout=1,
            require_process_group_cleanup_proof=invalid,  # type: ignore[arg-type]
        )


def test_process_group_cleanup_proof_requirement_defaults_off() -> None:
    request = BoundedProcessRequest.from_command(["trusted-tool"], cwd=None, env=None, timeout=1)

    assert request.require_process_group_cleanup_proof is False
    assert issubclass(ProcessGroupCleanupUnavailable, ProcessContainmentError)


@pytest.mark.parametrize(
    ("host_name", "killpg"),
    [
        ("nt", lambda *_args: None),
        ("posix", None),
    ],
)
def test_required_process_group_cleanup_proof_refuses_before_popen(
    monkeypatch: pytest.MonkeyPatch,
    host_name: str,
    killpg: object,
) -> None:
    launches: list[list[str]] = []
    monkeypatch.setattr(
        "evoom_guard.execution.process.os",
        SimpleNamespace(name=host_name, killpg=killpg),
    )

    def unexpected_popen(command: list[str], **_kwargs: object) -> None:
        launches.append(command)
        raise AssertionError("Popen must not run before capability preflight")

    monkeypatch.setattr(
        "evoom_guard.execution.process.subprocess.Popen",
        unexpected_popen,
    )
    request = BoundedProcessRequest.from_command(
        ["candidate"],
        cwd=None,
        env=None,
        timeout=1,
        require_process_group_cleanup_proof=True,
    )

    with pytest.raises(
        ProcessGroupCleanupUnavailable,
        match="requires POSIX process-group support",
    ):
        execute_bounded_process(request)

    assert launches == []


def test_public_facade_forwards_process_group_cleanup_proof_requirement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launches: list[list[str]] = []
    monkeypatch.setattr(
        "evoom_guard.execution.process.os",
        SimpleNamespace(name="nt", killpg=lambda *_args: None),
    )

    def unexpected_popen(command: list[str], **_kwargs: object) -> None:
        launches.append(command)
        raise AssertionError("Popen must not run before capability preflight")

    monkeypatch.setattr(
        "evoom_guard.execution.process.subprocess.Popen",
        unexpected_popen,
    )

    with pytest.raises(ProcessGroupCleanupUnavailable):
        run_bounded_subprocess(
            ["candidate"],
            cwd=None,
            env=None,
            timeout=1,
            require_process_group_cleanup_proof=True,
        )

    assert launches == []


def test_repo_verifier_facade_forwards_process_group_cleanup_proof_requirement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        observed.update(kwargs)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(repo_verifier, "run_bounded_subprocess", fake_run)

    repo_verifier._run_bounded_subprocess(
        ["candidate"],
        cwd=None,
        env=None,
        timeout=1,
        require_process_group_cleanup_proof=True,
    )

    assert observed["require_process_group_cleanup_proof"] is True


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups")
def test_required_process_group_cleanup_proof_runs_on_posix(tmp_path: Path) -> None:
    ready = tmp_path / "strict-child-ready"
    survived = tmp_path / "strict-child-survived"
    child = (
        "import signal, sys, time; from pathlib import Path; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "Path(sys.argv[1]).write_text('ready'); time.sleep(0.8); "
        "Path(sys.argv[2]).write_text('survived')"
    )
    parent = (
        "import subprocess, sys, time; from pathlib import Path; "
        "subprocess.Popen([sys.executable, '-c', sys.argv[3], sys.argv[1], sys.argv[2]], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL, close_fds=True); "
        "deadline=time.monotonic()+3; "
        "\nwhile not Path(sys.argv[1]).exists() and time.monotonic()<deadline: time.sleep(0.01); "
        "\nraise SystemExit(0 if Path(sys.argv[1]).exists() else 2)"
    )
    completed = run_bounded_subprocess(
        [sys.executable, "-c", parent, str(ready), str(survived), child],
        cwd=str(tmp_path),
        env=os.environ.copy(),
        timeout=5,
        limits=ProcessLimits(
            termination_grace_seconds=0.2,
            kill_grace_seconds=2,
            reader_join_seconds=1,
        ),
        require_process_group_cleanup_proof=True,
    )

    assert completed.returncode == 0
    assert completed.target_started is True
    assert ready.exists()
    time.sleep(0.9)
    assert not survived.exists()


def test_typed_request_preserves_exit_stdout_and_stderr(tmp_path: Path) -> None:
    request = BoundedProcessRequest.from_command(
        _command(
            "import sys; print('public-out'); "
            "print('public-err', file=sys.stderr); raise SystemExit(7)"
        ),
        cwd=str(tmp_path),
        env=os.environ.copy(),
        timeout=5,
    )

    result = execute_bounded_process(request)

    assert result.command == tuple(request.command)
    assert result.returncode == 7
    assert result.stdout.splitlines() == ["public-out"]
    assert result.stderr.splitlines() == ["public-err"]
    completed = result.as_completed_process()
    assert completed.args == list(request.command)
    assert (completed.returncode, completed.stdout, completed.stderr) == (
        result.returncode,
        result.stdout,
        result.stderr,
    )


def test_legacy_repo_facade_is_equivalent_to_public_runner(tmp_path: Path) -> None:
    command = _command(
        "import sys; sys.stdout.write('same-out'); "
        "sys.stderr.write('same-err'); raise SystemExit(3)"
    )
    kwargs = {
        "cwd": str(tmp_path),
        "env": os.environ.copy(),
        "timeout": 5,
    }

    public = run_bounded_subprocess(command, **kwargs)
    legacy = repo_verifier._run_bounded_subprocess(command, **kwargs)

    assert legacy.args is command
    assert public.args is command
    assert (legacy.args, legacy.returncode, legacy.stdout, legacy.stderr) == (
        public.args,
        public.returncode,
        public.stdout,
        public.stderr,
    )
    assert repo_verifier._SubprocessOutputLimitExceeded is ProcessOutputLimitExceeded
    assert repo_verifier._SubprocessContainmentError is ProcessContainmentError


def test_legacy_capture_uses_current_verifier_limit(monkeypatch) -> None:
    monkeypatch.setattr(repo_verifier, "_MAX_SUBPROCESS_OUTPUT_BYTES", 17)

    capture = repo_verifier._BoundedOutput()

    assert capture.limit == 17


def test_negative_timeout_remains_an_immediate_timeout(tmp_path: Path) -> None:
    command = _command("import time; time.sleep(60)")

    with pytest.raises(subprocess.TimeoutExpired) as exc:
        repo_verifier._run_bounded_subprocess(
            command,
            cwd=str(tmp_path),
            env=os.environ.copy(),
            timeout=-1,
        )

    assert exc.value.timeout == -1


def test_public_runner_timeout_preserves_partial_diagnostics(tmp_path: Path) -> None:
    command = _command(
        "import sys, time; print('before-timeout', flush=True); "
        "print('stderr-before-timeout', file=sys.stderr, flush=True); time.sleep(60)"
    )

    with pytest.raises(subprocess.TimeoutExpired) as exc:
        run_bounded_subprocess(
            command,
            cwd=str(tmp_path),
            env=os.environ.copy(),
            timeout=0.15,
        )

    assert "before-timeout" in (exc.value.output or "")
    assert "stderr-before-timeout" in (exc.value.stderr or "")


def test_public_runner_bounds_combined_output(tmp_path: Path) -> None:
    limit = 4 * 1024
    request = BoundedProcessRequest.from_command(
        _command(
            "import sys, time; sys.stdout.buffer.write(b'o' * 200000); "
            "sys.stderr.buffer.write(b'e' * 200000); "
            "sys.stdout.flush(); sys.stderr.flush(); time.sleep(60)"
        ),
        cwd=str(tmp_path),
        env=os.environ.copy(),
        timeout=10,
        limits=ProcessLimits(max_output_bytes=limit),
    )

    with pytest.raises(ProcessOutputLimitExceeded) as exc:
        execute_bounded_process(request)

    assert exc.value.limit == limit


@pytest.mark.skipif(os.name != "posix", reason="resource limits are POSIX-only")
def test_public_runner_applies_posix_address_space_spec(tmp_path: Path) -> None:
    resource = pytest.importorskip("resource")
    if not hasattr(resource, "RLIMIT_AS"):
        pytest.skip("RLIMIT_AS is unavailable")
    memory_limit = 1024 * 1024 * 1024

    completed = run_bounded_subprocess(
        _command("import resource; print(resource.getrlimit(resource.RLIMIT_AS)[0])"),
        cwd=str(tmp_path),
        env=os.environ.copy(),
        timeout=5,
        preexec_fn=PosixRLimitSpec(address_space_bytes=memory_limit),
    )

    assert completed.returncode == 0
    assert completed.stdout.strip() == str(memory_limit)


@pytest.mark.skipif(os.name != "posix", reason="resource launcher is POSIX-only")
def test_posix_rlimit_launcher_timeout_remains_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(subprocess.TimeoutExpired):
        run_bounded_subprocess(
            _command("import time; time.sleep(60)"),
            cwd=str(tmp_path),
            env=os.environ.copy(),
            timeout=0.1,
            preexec_fn=PosixRLimitSpec(cpu_seconds=5),
        )


@pytest.mark.skipif(os.name != "posix", reason="resource launcher is POSIX-only")
def test_posix_rlimit_exec_handshake_timeout_remains_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "candidate-ran"
    monkeypatch.setattr(
        process_module,
        "_POSIX_RLIMIT_LAUNCHER_SOURCE",
        "import time; time.sleep(60)",
    )

    with pytest.raises(subprocess.TimeoutExpired):
        run_bounded_subprocess(
            _command("from pathlib import Path; import sys; Path(sys.argv[1]).write_text('ran')")
            + [str(marker)],
            cwd=str(tmp_path),
            env=os.environ.copy(),
            timeout=0.1,
            preexec_fn=PosixRLimitSpec(cpu_seconds=5),
        )

    assert not marker.exists()


@pytest.mark.skipif(os.name != "posix", reason="resource launcher is POSIX-only")
def test_posix_rlimit_status_reports_missing_command_before_target_start(
    tmp_path: Path,
) -> None:
    with pytest.raises(FileNotFoundError) as caught:
        run_bounded_subprocess(
            ["evoguard-command-that-does-not-exist"],
            cwd=str(tmp_path),
            env=os.environ.copy(),
            timeout=5,
            preexec_fn=PosixRLimitSpec(cpu_seconds=5),
        )

    assert caught.value.errno == errno.ENOENT
    assert caught.value.filename == "evoguard-command-that-does-not-exist"
    assert caught.value.target_exec_failed is True  # type: ignore[attr-defined]
    assert caught.value.target_started is False  # type: ignore[attr-defined]


@pytest.mark.skipif(os.name != "posix", reason="resource launcher is POSIX-only")
def test_posix_rlimit_status_preserves_missing_shebang_interpreter(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "candidate-ran"
    candidate = tmp_path / "candidate"
    candidate.write_text(
        f"#!/definitely/missing/evoguard-interpreter\ntouch {marker}\n",
        encoding="utf-8",
    )
    candidate.chmod(0o700)

    with pytest.raises(FileNotFoundError) as caught:
        run_bounded_subprocess(
            [str(candidate)],
            cwd=str(tmp_path),
            env=os.environ.copy(),
            timeout=5,
            preexec_fn=PosixRLimitSpec(cpu_seconds=5),
        )

    assert caught.value.errno == errno.ENOENT
    assert caught.value.filename == str(candidate)
    assert not marker.exists()


@pytest.mark.skipif(os.name != "posix", reason="resource launcher is POSIX-only")
def test_posix_rlimit_status_preserves_exec_format_error(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.write_bytes(b"not an executable image\n")
    candidate.chmod(0o700)

    with pytest.raises(OSError) as caught:
        run_bounded_subprocess(
            [str(candidate)],
            cwd=str(tmp_path),
            env=os.environ.copy(),
            timeout=5,
            preexec_fn=PosixRLimitSpec(cpu_seconds=5),
        )

    assert caught.value.errno == errno.ENOEXEC
    assert caught.value.filename == str(candidate)
    assert caught.value.target_exec_failed is True  # type: ignore[attr-defined]
    assert caught.value.target_started is False  # type: ignore[attr-defined]


@pytest.mark.skipif(os.name != "posix", reason="resource launcher is POSIX-only")
def test_posix_rlimit_status_preserves_permission_error(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    candidate.chmod(0o600)

    with pytest.raises(PermissionError) as caught:
        run_bounded_subprocess(
            [str(candidate)],
            cwd=str(tmp_path),
            env=os.environ.copy(),
            timeout=5,
            preexec_fn=PosixRLimitSpec(cpu_seconds=5),
        )

    assert caught.value.errno == errno.EACCES
    assert caught.value.filename == str(candidate)
    assert caught.value.target_exec_failed is True  # type: ignore[attr-defined]
    assert caught.value.target_started is False  # type: ignore[attr-defined]


@pytest.mark.skipif(os.name != "posix", reason="resource launcher is POSIX-only")
def test_posix_rlimit_status_uses_child_cwd_for_relative_path_entries(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "bin" / "candidate"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)

    completed = run_bounded_subprocess(
        ["candidate"],
        cwd=str(tmp_path),
        env={"PATH": "bin"},
        timeout=5,
        preexec_fn=PosixRLimitSpec(cpu_seconds=5),
    )

    assert completed.returncode == 0


@pytest.mark.skipif(os.name != "posix", reason="resource launcher is POSIX-only")
def test_posix_rlimit_status_is_not_spoofed_by_candidate_stderr(
    tmp_path: Path,
) -> None:
    completed = run_bounded_subprocess(
        _command("import sys; sys.stderr.write('exec:2\\n')"),
        cwd=str(tmp_path),
        env=os.environ.copy(),
        timeout=5,
        preexec_fn=PosixRLimitSpec(cpu_seconds=5),
    )

    assert completed.returncode == 0
    assert completed.stderr == "exec:2\n"
    assert completed.target_started is True


@pytest.mark.skipif(os.name != "posix", reason="status pipes are POSIX-only")
def test_posix_exec_status_rejects_a_malformed_trusted_record() -> None:
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, b"candidate-controlled:2\n")
    finally:
        os.close(write_fd)
    try:
        with pytest.raises(ProcessContainmentError, match="status was malformed"):
            process_module._read_posix_exec_status(
                read_fd,
                deadline=time.monotonic() + 1,
            )
    finally:
        os.close(read_fd)


@pytest.mark.skipif(os.name != "posix", reason="status pipes are POSIX-only")
def test_posix_exec_status_rejects_eof_without_a_launch_record() -> None:
    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    try:
        with pytest.raises(
            ProcessContainmentError,
            match="closed without a launch record",
        ):
            process_module._read_posix_exec_status(
                read_fd,
                deadline=time.monotonic() + 1,
            )
    finally:
        os.close(read_fd)


@pytest.mark.skipif(os.name != "posix", reason="resource launcher is POSIX-only")
def test_abrupt_launcher_exit_before_exec_attempt_is_not_target_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        process_module,
        "_POSIX_RLIMIT_LAUNCHER_SOURCE",
        "import os; os._exit(73)\n",
    )

    with pytest.raises(
        ProcessContainmentError,
        match="closed without a launch record",
    ) as caught:
        run_bounded_subprocess(
            _command("raise AssertionError('target must not run')"),
            cwd=str(tmp_path),
            env=os.environ.copy(),
            timeout=5,
            preexec_fn=PosixRLimitSpec(cpu_seconds=5),
        )

    assert caught.value.target_started is False  # type: ignore[attr-defined]
    assert not hasattr(caught.value, "target_exec_failed")


@pytest.mark.skipif(os.name != "posix", reason="resource launcher is POSIX-only")
def test_status_pipe_creation_error_is_launcher_infrastructure_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipe_error = OSError(errno.EMFILE, "controlled descriptor exhaustion")
    monkeypatch.setattr(
        process_module,
        "_open_posix_exec_status_pipe",
        lambda: (_ for _ in ()).throw(pipe_error),
    )

    with pytest.raises(
        ProcessContainmentError,
        match="could not create the POSIX launcher status channel",
    ) as caught:
        run_bounded_subprocess(
            _command("raise AssertionError('target must not run')"),
            cwd=str(tmp_path),
            env=os.environ.copy(),
            timeout=5,
            preexec_fn=PosixRLimitSpec(cpu_seconds=5),
        )

    assert caught.value.__cause__ is pipe_error
    assert caught.value.target_started is False  # type: ignore[attr-defined]
    assert not hasattr(caught.value, "target_exec_failed")


@pytest.mark.skipif(os.name != "posix", reason="status pipes are POSIX-only")
def test_posix_exec_status_wraps_selector_range_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RangeLimitedSelector:
        def register(self, descriptor: int, events: int) -> None:
            del descriptor, events

        def select(self, timeout: float) -> list[object]:
            del timeout
            raise ValueError("filedescriptor out of range in select()")

        def close(self) -> None:
            return None

    read_fd, write_fd = os.pipe()
    monkeypatch.setattr(
        process_module.selectors,
        "DefaultSelector",
        RangeLimitedSelector,
    )
    try:
        with pytest.raises(
            ProcessContainmentError,
            match="could not read the POSIX launcher status channel",
        ):
            process_module._read_posix_exec_status(
                read_fd,
                deadline=time.monotonic() + 1,
            )
    finally:
        os.close(write_fd)
        os.close(read_fd)


@pytest.mark.skipif(os.name != "posix", reason="status pipes are POSIX-only")
def test_posix_exec_status_pipe_closes_if_wrapper_construction_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: tuple[int, int] | None = None
    original_open = process_module._open_posix_exec_status_pipe

    def tracked_open() -> tuple[int, int]:
        nonlocal opened
        opened = original_open()
        return opened

    def failed_wrapper(*args: object, **kwargs: object) -> list[str]:
        del args, kwargs
        raise RuntimeError("controlled wrapper construction failure")

    monkeypatch.setattr(
        process_module,
        "_open_posix_exec_status_pipe",
        tracked_open,
    )
    monkeypatch.setattr(
        process_module,
        "_posix_rlimit_launcher_command",
        failed_wrapper,
    )
    with pytest.raises(RuntimeError, match="wrapper construction failure"):
        run_bounded_subprocess(
            _command("raise AssertionError('must not run')"),
            cwd=str(tmp_path),
            env=os.environ.copy(),
            timeout=5,
            preexec_fn=PosixRLimitSpec(cpu_seconds=5),
        )

    assert opened is not None
    for descriptor in opened:
        with pytest.raises(OSError):
            os.fstat(descriptor)


@pytest.mark.skipif(os.name != "posix", reason="resource launcher is POSIX-only")
def test_unrepresentable_address_space_limit_never_runs_candidate(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "candidate-ran"
    completed = run_bounded_subprocess(
        _command("from pathlib import Path; import sys; Path(sys.argv[1]).write_text('ran')")
        + [str(marker)],
        cwd=str(tmp_path),
        env=os.environ.copy(),
        timeout=5,
        preexec_fn=PosixRLimitSpec(address_space_bytes=1 << 200),
    )

    assert completed.returncode == 125
    assert "POSIX rlimit launcher failed" in completed.stderr
    assert completed.target_started is False
    assert not marker.exists()


def test_execution_consumers_do_not_import_process_primitives_from_verifier() -> None:
    root = Path(__file__).resolve().parents[1] / "evoom_guard"
    extracted = {
        "_BoundedOutput",
        "_drain_subprocess_pipe",
        "_join_pipe_readers",
        "_run_bounded_subprocess",
        "_SubprocessContainmentError",
        "_SubprocessOutputLimitExceeded",
    }

    for relative in ("candidate_runner.py", "blackbox.py"):
        tree = ast.parse((root / relative).read_text(encoding="utf-8"))
        repo_imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module == "evoom_guard.verifiers.repo_verifier"
            for alias in node.names
        }
        execution_imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module == "evoom_guard.execution"
            for alias in node.names
        }
        assert not (repo_imports & extracted)
        assert "run_bounded_subprocess" in execution_imports
