# -----------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available - see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Direct behavior characterization of the black-box judge process boundary.

These tests intentionally resolve each private callable's defining module at
runtime.  A behavior-preserving extraction can therefore move the implementation
without tying the tests to the old file layout; the compatibility facade in
:mod:`evoom_guard.blackbox` must still preserve its documented patch seams.
"""

from __future__ import annotations

import io
import os
import signal
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import evoom_guard.blackbox as blackbox_api


class _PrimaryFailure(RuntimeError):
    """Distinct failure used to prove exception identity and precedence."""


class _Pipe(io.BytesIO):
    def __init__(self, data: bytes = b"", close_error: BaseException | None = None) -> None:
        super().__init__(data)
        self.close_calls = 0
        self.close_error = close_error

    def close(self) -> None:
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error
        super().close()


class _Process:
    pid = 7351

    def __init__(
        self,
        *,
        stdout: bytes = b"",
        stderr: bytes = b"",
        poll_values: tuple[int | None, ...] = (0,),
        initial_returncode: int | None = None,
        wait_effects: tuple[int | BaseException, ...] = (0,),
        terminate_error: BaseException | None = None,
        kill_error: BaseException | None = None,
    ) -> None:
        self.stdout = _Pipe(stdout)
        self.stderr = _Pipe(stderr)
        self.returncode = initial_returncode
        self._poll_values = list(poll_values)
        self._wait_effects = list(wait_effects)
        self.terminate_error = terminate_error
        self.kill_error = kill_error
        self.poll_calls = 0
        self.terminate_calls = 0
        self.kill_calls = 0
        self.wait_timeouts: list[float | None] = []

    def poll(self) -> int | None:
        self.poll_calls += 1
        if self._poll_values:
            observed = self._poll_values.pop(0)
            if observed is not None:
                self.returncode = observed
            return observed
        return self.returncode

    def terminate(self) -> None:
        self.terminate_calls += 1
        if self.terminate_error is not None:
            raise self.terminate_error

    def kill(self) -> None:
        self.kill_calls += 1
        if self.kill_error is not None:
            raise self.kill_error

    def wait(self, timeout: float | None = None) -> int:
        self.wait_timeouts.append(timeout)
        effect: int | BaseException = (
            self._wait_effects.pop(0) if self._wait_effects else 0
        )
        if isinstance(effect, BaseException):
            raise effect
        self.returncode = effect
        return effect


class _ImmediateReader:
    def __init__(
        self,
        *,
        target: Callable[..., object],
        args: tuple[Any, ...],
        daemon: bool,
    ) -> None:
        self.target = target
        self.args = args
        self.daemon = daemon
        self.start_calls = 0
        self.join_timeouts: list[float | None] = []
        self.started = False

    @property
    def ident(self) -> int | None:
        return 99 if self.started else None

    def start(self) -> None:
        self.start_calls += 1
        self.started = True
        self.target(*self.args)

    def join(self, timeout: float | None = None) -> None:
        self.join_timeouts.append(timeout)

    def is_alive(self) -> bool:
        return False


def _resolve(name: str) -> tuple[Callable[..., Any], ModuleType]:
    function = getattr(blackbox_api, name)
    assert callable(function)
    module = sys.modules[function.__module__]
    assert isinstance(module, ModuleType)
    return function, module


def _install_immediate_readers(
    monkeypatch: pytest.MonkeyPatch, module: ModuleType
) -> list[_ImmediateReader]:
    readers: list[_ImmediateReader] = []

    def factory(*_args: object, **kwargs: Any) -> _ImmediateReader:
        reader = _ImmediateReader(
            target=kwargs["target"],
            args=kwargs["args"],
            daemon=kwargs["daemon"],
        )
        readers.append(reader)
        return reader

    monkeypatch.setattr(module.threading, "Thread", factory)
    return readers


def _install_popen(
    monkeypatch: pytest.MonkeyPatch,
    module: ModuleType,
    process: _Process,
) -> list[tuple[list[str], dict[str, object]]]:
    calls: list[tuple[list[str], dict[str, object]]] = []

    def popen(command: list[str], **kwargs: object) -> _Process:
        calls.append((command, kwargs))
        return process

    monkeypatch.setattr(module.subprocess, "Popen", popen)
    return calls


def _install_cleanup_observers(
    monkeypatch: pytest.MonkeyPatch,
    module: ModuleType,
    *,
    join_result: bool = True,
) -> tuple[list[_Process], list[tuple[list[Any], list[Any]]]]:
    cleanup_calls: list[_Process] = []
    join_calls: list[tuple[list[Any], list[Any]]] = []

    monkeypatch.setattr(
        module,
        "_terminate_judge_process_group",
        lambda process: cleanup_calls.append(process),
    )

    def join(readers: list[Any], streams: list[Any]) -> bool:
        join_calls.append((list(readers), list(streams)))
        return join_result

    monkeypatch.setattr(module, "_join_judge_pipe_readers", join)
    return cleanup_calls, join_calls


def _capture_instance(
    monkeypatch: pytest.MonkeyPatch, module: ModuleType
) -> list[Any]:
    capture_type = module._BoundedOutput
    captures: list[Any] = []

    def factory(limit: int) -> Any:
        capture = capture_type(limit)
        captures.append(capture)
        return capture

    monkeypatch.setattr(module, "_BoundedOutput", factory)
    return captures


def _force_posix(monkeypatch: pytest.MonkeyPatch, module: ModuleType) -> None:
    monkeypatch.setattr(module.os, "name", "posix")
    monkeypatch.setattr(module.os, "killpg", lambda *_args: None, raising=False)


def _force_non_posix(monkeypatch: pytest.MonkeyPatch, module: ModuleType) -> None:
    monkeypatch.setattr(module.os, "name", "nt")


def test_runner_popen_thread_and_completed_process_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, module = _resolve("_run_judge_process")
    command = ["python", "-m", "pytest", "pack"]
    env = {"LANG": "C.UTF-8", "TOKEN": "owned"}
    process = _Process(
        stdout=b"judge-out\xff",
        stderr=b"judge-err",
        poll_values=(3,),
    )
    popen_calls = _install_popen(monkeypatch, module, process)
    readers = _install_immediate_readers(monkeypatch, module)
    cleanup_calls, join_calls = _install_cleanup_observers(monkeypatch, module)

    completed = runner(command, cwd="/judge/work", env=env, timeout=9)

    assert len(popen_calls) == 1
    observed_command, kwargs = popen_calls[0]
    assert observed_command is command
    assert kwargs == {
        "cwd": "/judge/work",
        "stdin": module.subprocess.DEVNULL,
        "stdout": module.subprocess.PIPE,
        "stderr": module.subprocess.PIPE,
        "env": env,
        "start_new_session": True,
    }
    assert kwargs["env"] is env
    assert completed.args is command
    assert completed.returncode == 3
    assert completed.stdout == "judge-out�"
    assert completed.stderr == "judge-err"
    assert len(readers) == 2
    assert [reader.daemon for reader in readers] == [True, True]
    assert [reader.start_calls for reader in readers] == [1, 1]
    assert [reader.args[0] for reader in readers] == [process.stdout, process.stderr]
    assert readers[0].args[1] is readers[1].args[1]
    assert [reader.args[2] for reader in readers] == ["stdout", "stderr"]
    assert cleanup_calls == [process]
    assert len(join_calls) == 2
    assert join_calls[0][0] == readers
    assert join_calls[0][1] == [process.stdout, process.stderr]


@pytest.mark.parametrize(
    "primary",
    [OSError("launch rejected"), KeyboardInterrupt("launch interrupted")],
)
def test_popen_failure_preserves_identity_and_skips_post_launch_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    primary: BaseException,
) -> None:
    runner, module = _resolve("_run_judge_process")
    cleanup_calls: list[Any] = []
    monkeypatch.setattr(
        module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(primary),
    )
    monkeypatch.setattr(
        module,
        "_terminate_judge_process_group",
        lambda process: cleanup_calls.append(process),
    )

    with pytest.raises(type(primary)) as exc:
        runner(["judge"], cwd="/judge", env={}, timeout=1)

    assert exc.value is primary
    assert cleanup_calls == []


@pytest.mark.parametrize(
    ("missing_stdout", "missing_stderr"),
    [(True, False), (False, True), (True, True)],
    ids=("stdout", "stderr", "both"),
)
def test_missing_popen_pipes_fail_closed_before_reader_construction(
    monkeypatch: pytest.MonkeyPatch,
    missing_stdout: bool,
    missing_stderr: bool,
) -> None:
    runner, module = _resolve("_run_judge_process")
    process = _Process(poll_values=(None,))
    stdout = process.stdout
    stderr = process.stderr
    if missing_stdout:
        process.stdout = None
    if missing_stderr:
        process.stderr = None
    _install_popen(monkeypatch, module, process)
    readers = _install_immediate_readers(monkeypatch, module)
    cleanup_calls: list[_Process] = []
    monkeypatch.setattr(
        module,
        "_terminate_judge_process_group",
        lambda candidate: cleanup_calls.append(candidate),
    )

    with pytest.raises(
        module.JudgeProcessCleanupError, match="output pipes were not created"
    ):
        runner(["judge"], cwd="/judge", env={}, timeout=1)

    assert readers == []
    assert cleanup_calls == [process]
    assert stdout.close_calls == int(not missing_stdout)
    assert stderr.close_calls == int(not missing_stderr)


def test_timeout_preserves_fields_and_output_drained_during_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, module = _resolve("_run_judge_process")
    command = ["judge", "--case", "timeout"]
    process = _Process(poll_values=(None,))
    _install_popen(monkeypatch, module, process)
    _install_immediate_readers(monkeypatch, module)
    captures = _capture_instance(monkeypatch, module)
    cleanup_calls: list[_Process] = []
    join_calls: list[tuple[list[Any], list[Any]]] = []

    def terminate(candidate: _Process) -> None:
        cleanup_calls.append(candidate)
        if len(cleanup_calls) == 1:
            captures[0].append("stdout", b"partial stdout")
            captures[0].append("stderr", b"partial stderr")

    def join(readers: list[Any], streams: list[Any]) -> bool:
        join_calls.append((list(readers), list(streams)))
        return True

    monotonic = iter((10.0, 17.0))
    monkeypatch.setattr(module, "_terminate_judge_process_group", terminate)
    monkeypatch.setattr(module, "_join_judge_pipe_readers", join)
    monkeypatch.setattr(module.time, "monotonic", lambda: next(monotonic))

    with pytest.raises(subprocess.TimeoutExpired) as exc:
        runner(command, cwd="/judge", env={}, timeout=7)

    assert exc.value.cmd is command
    assert exc.value.timeout == 7
    assert exc.value.output == "partial stdout"
    assert exc.value.stdout == "partial stdout"
    assert exc.value.stderr == "partial stderr"
    assert cleanup_calls == [process, process]
    assert len(join_calls) == 2
    assert process.poll_calls == 1


@pytest.mark.parametrize(
    ("stdout", "stderr", "expected_stdout", "expected_stderr"),
    [
        (b"abcdef", b"", "abcde", ""),
        (b"", b"abcdef", "", "abcde"),
        (b"abc", b"def", "abc", "de"),
    ],
    ids=("stdout", "stderr", "combined"),
)
def test_output_limit_is_shared_across_both_diagnostic_streams(
    monkeypatch: pytest.MonkeyPatch,
    stdout: bytes,
    stderr: bytes,
    expected_stdout: str,
    expected_stderr: str,
) -> None:
    runner, module = _resolve("_run_judge_process")
    process = _Process(stdout=stdout, stderr=stderr, poll_values=(None,))
    _install_popen(monkeypatch, module, process)
    _install_immediate_readers(monkeypatch, module)
    captures = _capture_instance(monkeypatch, module)
    cleanup_calls, join_calls = _install_cleanup_observers(monkeypatch, module)
    monkeypatch.setattr(module, "_MAX_SUBPROCESS_OUTPUT_BYTES", 5)

    with pytest.raises(module.JudgeOutputLimitError) as exc:
        runner(["judge"], cwd="/judge", env={}, timeout=10)

    assert exc.value.limit == 5
    assert captures[0].text("stdout") == expected_stdout
    assert captures[0].text("stderr") == expected_stderr
    assert captures[0].exceeded is True
    assert cleanup_calls == [process, process]
    assert len(join_calls) == 2
    assert process.poll_calls == 1


def test_exact_output_limit_succeeds_without_false_overflow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, module = _resolve("_run_judge_process")
    process = _Process(stdout=b"abc", stderr=b"de", poll_values=(0,))
    _install_popen(monkeypatch, module, process)
    _install_immediate_readers(monkeypatch, module)
    cleanup_calls, _join_calls = _install_cleanup_observers(monkeypatch, module)
    monkeypatch.setattr(module, "_MAX_SUBPROCESS_OUTPUT_BYTES", 5)

    completed = runner(["judge"], cwd="/judge", env={}, timeout=10)

    assert completed.stdout == "abc"
    assert completed.stderr == "de"
    assert cleanup_calls == [process]


def test_short_lived_process_overflow_is_checked_after_poll_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, module = _resolve("_run_judge_process")
    process = _Process(stdout=b"abcdef", poll_values=(0,))
    _install_popen(monkeypatch, module, process)
    _install_immediate_readers(monkeypatch, module)
    cleanup_calls, join_calls = _install_cleanup_observers(monkeypatch, module)
    monkeypatch.setattr(module, "_MAX_SUBPROCESS_OUTPUT_BYTES", 5)

    with pytest.raises(module.JudgeOutputLimitError) as exc:
        runner(["judge"], cwd="/judge", env={}, timeout=10)

    assert exc.value.limit == 5
    assert process.poll_calls == 1
    assert cleanup_calls == [process, process]
    assert len(join_calls) == 2


def test_real_short_lived_process_cannot_escape_output_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, module = _resolve("_run_judge_process")
    monkeypatch.setattr(module, "_MAX_SUBPROCESS_OUTPUT_BYTES", 32)

    with pytest.raises(module.JudgeOutputLimitError) as exc:
        runner(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'x' * 65536); sys.stdout.flush()",
            ],
            cwd=str(tmp_path),
            env=dict(os.environ),
            timeout=10,
        )

    assert exc.value.limit == 32


def test_output_limit_is_rechecked_after_reader_join(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, module = _resolve("_run_judge_process")
    process = _Process(poll_values=(0,))
    _install_popen(monkeypatch, module, process)
    readers = _install_immediate_readers(monkeypatch, module)
    captures = _capture_instance(monkeypatch, module)
    monkeypatch.setattr(module, "_MAX_SUBPROCESS_OUTPUT_BYTES", 5)
    cleanup_calls: list[_Process] = []
    join_calls = 0

    def join(_readers: list[Any], _streams: list[Any]) -> bool:
        nonlocal join_calls
        join_calls += 1
        if join_calls == 1:
            captures[0].append("stderr", b"abcdef")
        return True

    monkeypatch.setattr(
        module,
        "_terminate_judge_process_group",
        lambda candidate: cleanup_calls.append(candidate),
    )
    monkeypatch.setattr(module, "_join_judge_pipe_readers", join)

    with pytest.raises(module.JudgeOutputLimitError) as exc:
        runner(["judge"], cwd="/judge", env={}, timeout=10)

    assert exc.value.limit == 5
    assert captures[0].text("stderr") == "abcde"
    assert [reader.start_calls for reader in readers] == [1, 1]
    assert join_calls == 3
    assert cleanup_calls == [process, process]


def test_timeout_remains_primary_if_cleanup_itself_crosses_output_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, module = _resolve("_run_judge_process")
    process = _Process(poll_values=(None,))
    _install_popen(monkeypatch, module, process)
    _install_immediate_readers(monkeypatch, module)
    captures = _capture_instance(monkeypatch, module)
    monkeypatch.setattr(module, "_MAX_SUBPROCESS_OUTPUT_BYTES", 5)
    cleanup_calls = 0

    def terminate(_candidate: _Process) -> None:
        nonlocal cleanup_calls
        cleanup_calls += 1
        if cleanup_calls == 1:
            captures[0].append("stdout", b"abcdef")

    monotonic = iter((1.0, 2.0))
    monkeypatch.setattr(module, "_terminate_judge_process_group", terminate)
    monkeypatch.setattr(module, "_join_judge_pipe_readers", lambda *_args: True)
    monkeypatch.setattr(module.time, "monotonic", lambda: next(monotonic))

    with pytest.raises(subprocess.TimeoutExpired) as exc:
        runner(["judge"], cwd="/judge", env={}, timeout=1)

    assert exc.value.output == "abcde"
    assert captures[0].exceeded is True
    assert cleanup_calls == 2


def test_output_limit_cleanup_failure_takes_precedence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, module = _resolve("_run_judge_process")
    process = _Process(stdout=b"abcdef", poll_values=(None,))
    _install_popen(monkeypatch, module, process)
    _install_immediate_readers(monkeypatch, module)
    monkeypatch.setattr(module, "_MAX_SUBPROCESS_OUTPUT_BYTES", 5)
    failure = module.JudgeProcessCleanupError("cleanup not proven")
    cleanup_calls = 0

    def terminate(_candidate: _Process) -> None:
        nonlocal cleanup_calls
        cleanup_calls += 1
        raise failure

    monkeypatch.setattr(module, "_terminate_judge_process_group", terminate)
    monkeypatch.setattr(module, "_join_judge_pipe_readers", lambda *_args: True)

    with pytest.raises(module.JudgeProcessCleanupError) as exc:
        runner(["judge"], cwd="/judge", env={}, timeout=10)

    assert exc.value is failure
    assert cleanup_calls == 2


def test_normal_cleanup_failure_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, module = _resolve("_run_judge_process")
    process = _Process(poll_values=(0,))
    _install_popen(monkeypatch, module, process)
    _install_immediate_readers(monkeypatch, module)
    failure = module.JudgeProcessCleanupError("normal cleanup not proven")
    cleanup_calls = 0
    join_calls = 0

    def terminate(_candidate: _Process) -> None:
        nonlocal cleanup_calls
        cleanup_calls += 1
        raise failure

    def join(*_args: Any) -> bool:
        nonlocal join_calls
        join_calls += 1
        return True

    monkeypatch.setattr(module, "_terminate_judge_process_group", terminate)
    monkeypatch.setattr(module, "_join_judge_pipe_readers", join)

    with pytest.raises(module.JudgeProcessCleanupError) as exc:
        runner(["judge"], cwd="/judge", env={}, timeout=10)

    assert exc.value is failure
    assert cleanup_calls == 2
    assert join_calls == 2


def test_unexpected_normal_cleanup_exception_is_wrapped_with_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, module = _resolve("_run_judge_process")
    process = _Process(poll_values=(0,))
    _install_popen(monkeypatch, module, process)
    _install_immediate_readers(monkeypatch, module)
    primary = ValueError("unexpected cleanup failure")
    monkeypatch.setattr(
        module,
        "_terminate_judge_process_group",
        lambda _candidate: (_ for _ in ()).throw(primary),
    )
    monkeypatch.setattr(module, "_join_judge_pipe_readers", lambda *_args: True)

    with pytest.raises(
        module.JudgeProcessCleanupError,
        match="unexpected judge process-group cleanup failure",
    ) as exc:
        runner(["judge"], cwd="/judge", env={}, timeout=10)

    assert exc.value.__cause__ is primary


def test_false_reader_join_proof_is_a_cleanup_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, module = _resolve("_run_judge_process")
    process = _Process(poll_values=(0,))
    _install_popen(monkeypatch, module, process)
    _install_immediate_readers(monkeypatch, module)
    cleanup_calls, join_calls = _install_cleanup_observers(
        monkeypatch, module, join_result=False
    )

    with pytest.raises(
        module.JudgeProcessCleanupError,
        match="judge exited with live output pipes; judge output pipes did not close",
    ):
        runner(["judge"], cwd="/judge", env={}, timeout=10)

    assert cleanup_calls == [process, process]
    assert len(join_calls) == 3


def test_timeout_join_failure_takes_precedence_and_preserves_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, module = _resolve("_run_judge_process")
    process = _Process(poll_values=(None,))
    _install_popen(monkeypatch, module, process)
    _install_immediate_readers(monkeypatch, module)
    failure = _PrimaryFailure("join proof failed")
    cleanup_calls: list[_Process] = []
    join_calls = 0

    def join(*_args: Any) -> bool:
        nonlocal join_calls
        join_calls += 1
        raise failure

    monotonic = iter((1.0, 2.0))
    monkeypatch.setattr(
        module,
        "_terminate_judge_process_group",
        lambda candidate: cleanup_calls.append(candidate),
    )
    monkeypatch.setattr(module, "_join_judge_pipe_readers", join)
    monkeypatch.setattr(module.time, "monotonic", lambda: next(monotonic))

    with pytest.raises(_PrimaryFailure) as exc:
        runner(["judge"], cwd="/judge", env={}, timeout=1)

    assert exc.value is failure
    assert cleanup_calls == [process, process]
    assert join_calls == 2


def test_timeout_process_cleanup_failure_takes_precedence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, module = _resolve("_run_judge_process")
    process = _Process(poll_values=(None,))
    _install_popen(monkeypatch, module, process)
    _install_immediate_readers(monkeypatch, module)
    failure = module.JudgeProcessCleanupError("timeout cleanup not proven")
    cleanup_calls = 0
    join_calls = 0

    def terminate(_candidate: _Process) -> None:
        nonlocal cleanup_calls
        cleanup_calls += 1
        raise failure

    def join(*_args: Any) -> bool:
        nonlocal join_calls
        join_calls += 1
        return True

    monotonic = iter((1.0, 2.0))
    monkeypatch.setattr(module, "_terminate_judge_process_group", terminate)
    monkeypatch.setattr(module, "_join_judge_pipe_readers", join)
    monkeypatch.setattr(module.time, "monotonic", lambda: next(monotonic))

    with pytest.raises(module.JudgeProcessCleanupError) as exc:
        runner(["judge"], cwd="/judge", env={}, timeout=1)

    assert exc.value is failure
    assert cleanup_calls == 2
    assert join_calls == 1


def test_normal_cleanup_baseexception_propagates_without_masking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, module = _resolve("_run_judge_process")
    process = _Process(poll_values=(0,))
    _install_popen(monkeypatch, module, process)
    _install_immediate_readers(monkeypatch, module)
    failure = SystemExit("normal cleanup stopped")
    cleanup_calls = 0
    join_calls = 0

    def terminate(_candidate: _Process) -> None:
        nonlocal cleanup_calls
        cleanup_calls += 1
        raise failure

    def join(*_args: Any) -> bool:
        nonlocal join_calls
        join_calls += 1
        return True

    monkeypatch.setattr(module, "_terminate_judge_process_group", terminate)
    monkeypatch.setattr(module, "_join_judge_pipe_readers", join)

    with pytest.raises(SystemExit) as exc:
        runner(["judge"], cwd="/judge", env={}, timeout=1)

    assert exc.value is failure
    assert cleanup_calls == 2
    assert join_calls == 2


def test_normal_join_baseexception_propagates_without_masking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, module = _resolve("_run_judge_process")
    process = _Process(poll_values=(0,))
    _install_popen(monkeypatch, module, process)
    _install_immediate_readers(monkeypatch, module)
    failure = KeyboardInterrupt("normal join interrupted")
    cleanup_calls: list[_Process] = []
    join_calls = 0

    def join(*_args: Any) -> bool:
        nonlocal join_calls
        join_calls += 1
        raise failure

    monkeypatch.setattr(
        module,
        "_terminate_judge_process_group",
        lambda candidate: cleanup_calls.append(candidate),
    )
    monkeypatch.setattr(module, "_join_judge_pipe_readers", join)

    with pytest.raises(KeyboardInterrupt) as exc:
        runner(["judge"], cwd="/judge", env={}, timeout=1)

    assert exc.value is failure
    assert cleanup_calls == [process]
    assert join_calls == 2


@pytest.mark.parametrize(
    "primary",
    [
        KeyboardInterrupt("runner interrupted"),
        SystemExit("runner exited"),
        GeneratorExit("runner generator closed"),
    ],
)
def test_post_launch_baseexception_survives_every_cleanup_failure(
    monkeypatch: pytest.MonkeyPatch,
    primary: BaseException,
) -> None:
    runner, module = _resolve("_run_judge_process")
    process = _Process(poll_values=(None,))
    _install_popen(monkeypatch, module, process)
    _install_immediate_readers(monkeypatch, module)
    monotonic = iter((1.0, 1.0))
    monkeypatch.setattr(module.time, "monotonic", lambda: next(monotonic))
    monkeypatch.setattr(
        module.time,
        "sleep",
        lambda _seconds: (_ for _ in ()).throw(primary),
    )
    monkeypatch.setattr(
        module,
        "_terminate_judge_process_group",
        lambda _candidate: (_ for _ in ()).throw(SystemExit("cleanup failed")),
    )
    monkeypatch.setattr(
        module,
        "_join_judge_pipe_readers",
        lambda *_args: (_ for _ in ()).throw(GeneratorExit("join failed")),
    )

    with pytest.raises(type(primary)) as exc:
        runner(["judge"], cwd="/judge", env={}, timeout=10)

    assert exc.value is primary


@pytest.mark.parametrize("close_error", [OSError("close"), ValueError("closed")])
def test_reader_helper_reports_best_effort_close_failure(
    monkeypatch: pytest.MonkeyPatch,
    close_error: BaseException,
) -> None:
    helper, module = _resolve("_join_judge_pipe_readers")
    stream = _Pipe(close_error=close_error)
    monkeypatch.setattr(module, "_join_pipe_readers", lambda *_args: True)

    assert helper([object()], [stream]) is False
    assert stream.close_calls == 1


def test_reader_helper_propagates_close_baseexception_after_safe_join(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, module = _resolve("_join_judge_pipe_readers")
    failure = KeyboardInterrupt("close interrupted")
    stream = _Pipe(close_error=failure)
    monkeypatch.setattr(module, "_join_pipe_readers", lambda *_args: True)

    with pytest.raises(KeyboardInterrupt) as exc:
        helper([object()], [stream])

    assert exc.value is failure


@pytest.mark.parametrize("sig", [int(signal.SIGTERM), int(getattr(signal, "SIGKILL", 9))])
def test_posix_signal_helper_targets_the_isolated_pgid(
    monkeypatch: pytest.MonkeyPatch, sig: int
) -> None:
    helper, module = _resolve("_signal_judge_process_group")
    process = _Process(poll_values=())
    calls: list[tuple[int, int]] = []
    monkeypatch.setattr(module.os, "name", "posix")
    monkeypatch.setattr(
        module.os,
        "killpg",
        lambda process_group, observed_sig: calls.append(
            (process_group, int(observed_sig))
        ),
        raising=False,
    )

    helper(process, sig)

    assert calls == [(process.pid, sig)]
    assert process.terminate_calls == 0
    assert process.kill_calls == 0


@pytest.mark.parametrize(
    ("sig", "expected_terminate", "expected_kill"),
    [
        (int(signal.SIGTERM), 1, 0),
        (int(getattr(signal, "SIGKILL", 9)), 0, 1),
    ],
)
def test_non_posix_signal_helper_dispatches_to_the_leader(
    monkeypatch: pytest.MonkeyPatch,
    sig: int,
    expected_terminate: int,
    expected_kill: int,
) -> None:
    helper, module = _resolve("_signal_judge_process_group")
    process = _Process(poll_values=())
    _force_non_posix(monkeypatch, module)

    helper(process, sig)

    assert process.terminate_calls == expected_terminate
    assert process.kill_calls == expected_kill


@pytest.mark.parametrize(
    ("outcome", "expected", "message"),
    [
        (None, True, None),
        (ProcessLookupError("gone"), False, None),
        (PermissionError("denied"), None, "cannot inspect judge process group"),
        (OSError("probe failed"), None, "process-group inspection failed"),
    ],
)
def test_process_group_probe_contract(
    monkeypatch: pytest.MonkeyPatch,
    outcome: BaseException | None,
    expected: bool | None,
    message: str | None,
) -> None:
    helper, module = _resolve("_process_group_exists")
    calls: list[tuple[int, int]] = []

    def killpg(process_group: int, sig: int) -> None:
        calls.append((process_group, sig))
        if outcome is not None:
            raise outcome

    monkeypatch.setattr(module.os, "killpg", killpg, raising=False)
    if message is None:
        assert helper(7351) is expected
    else:
        with pytest.raises(module.JudgeProcessCleanupError, match=message) as exc:
            helper(7351)
        assert exc.value.__cause__ is outcome
    assert calls == [(7351, 0)]


def test_process_group_probe_requires_callable_killpg(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, module = _resolve("_process_group_exists")
    monkeypatch.setattr(module.os, "killpg", None, raising=False)

    with pytest.raises(module.JudgeProcessCleanupError, match="killpg is unavailable"):
        helper(7351)


def test_wait_for_process_group_exit_polls_reaps_and_sleeps_boundedly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, module = _resolve("_wait_for_process_group_exit")
    process = _Process(poll_values=(None, 0))
    exists = iter((True, False))
    monotonic = iter((10.0, 10.0, 10.0))
    sleeps: list[float] = []
    monkeypatch.setattr(
        module, "_process_group_exists", lambda _process_group: next(exists)
    )
    monkeypatch.setattr(module.time, "monotonic", lambda: next(monotonic))
    monkeypatch.setattr(module.time, "sleep", lambda seconds: sleeps.append(seconds))

    assert helper(process, process.pid, 1.0) is True
    assert process.poll_calls == 2
    assert sleeps == [module._JUDGE_GROUP_POLL_SECONDS]


def test_wait_for_process_group_exit_times_out_without_unbounded_sleep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, module = _resolve("_wait_for_process_group_exit")
    process = _Process(poll_values=(None,))
    sleeps: list[float] = []
    monkeypatch.setattr(module, "_process_group_exists", lambda _pgid: True)
    monkeypatch.setattr(module.time, "monotonic", lambda: 5.0)
    monkeypatch.setattr(module.time, "sleep", lambda seconds: sleeps.append(seconds))

    assert helper(process, process.pid, 0.0) is False
    assert process.poll_calls == 1
    assert sleeps == []


def test_reap_helper_skips_wait_for_completed_leader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, _module = _resolve("_reap_judge_leader")
    process = _Process(poll_values=(0,), wait_effects=())

    helper(process)

    assert process.poll_calls == 1
    assert process.wait_timeouts == []


def test_reap_helper_waits_boundedly_for_live_leader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, module = _resolve("_reap_judge_leader")
    process = _Process(poll_values=(None,), wait_effects=(0,))

    helper(process)

    assert process.wait_timeouts == [module._JUDGE_TERMINATION_GRACE_SECONDS]
    assert process.returncode == 0


@pytest.mark.parametrize(
    "wait_error",
    [
        OSError("wait failed"),
        subprocess.TimeoutExpired(["judge"], timeout=1),
    ],
)
def test_reap_helper_wraps_wait_failure(
    monkeypatch: pytest.MonkeyPatch,
    wait_error: BaseException,
) -> None:
    helper, module = _resolve("_reap_judge_leader")
    process = _Process(poll_values=(None,), wait_effects=(wait_error,))

    with pytest.raises(module.JudgeProcessCleanupError, match="could not be reaped") as exc:
        helper(process)

    assert exc.value.__cause__ is wait_error


def test_posix_terminate_skips_signal_when_group_is_already_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, module = _resolve("_terminate_judge_process_group")
    process = _Process(poll_values=())
    _force_posix(monkeypatch, module)
    reaped: list[_Process] = []
    monkeypatch.setattr(module, "_process_group_exists", lambda _pgid: False)
    monkeypatch.setattr(
        module,
        "_signal_judge_process_group",
        lambda *_args: pytest.fail("absent group must not be signalled"),
    )
    monkeypatch.setattr(module, "_reap_judge_leader", lambda item: reaped.append(item))

    helper(process)

    assert reaped == [process]


def test_posix_terminate_reaps_after_term_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, module = _resolve("_terminate_judge_process_group")
    process = _Process(poll_values=())
    _force_posix(monkeypatch, module)
    signals: list[int] = []
    waits: list[tuple[int, float]] = []
    reaped: list[_Process] = []
    monkeypatch.setattr(module, "_process_group_exists", lambda _pgid: True)
    monkeypatch.setattr(
        module,
        "_signal_judge_process_group",
        lambda _process, sig: signals.append(int(sig)),
    )

    def wait(_process: _Process, pgid: int, timeout: float) -> bool:
        waits.append((pgid, timeout))
        return True

    monkeypatch.setattr(module, "_wait_for_process_group_exit", wait)
    monkeypatch.setattr(module, "_reap_judge_leader", lambda item: reaped.append(item))

    helper(process)

    assert signals == [int(signal.SIGTERM)]
    assert waits == [(process.pid, module._JUDGE_TERMINATION_GRACE_SECONDS)]
    assert reaped == [process]


def test_posix_terminate_tolerates_term_processlookup_race(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, module = _resolve("_terminate_judge_process_group")
    process = _Process(poll_values=())
    _force_posix(monkeypatch, module)
    reaped: list[_Process] = []
    monkeypatch.setattr(module, "_process_group_exists", lambda _pgid: True)
    monkeypatch.setattr(
        module,
        "_signal_judge_process_group",
        lambda *_args: (_ for _ in ()).throw(ProcessLookupError("gone")),
    )
    monkeypatch.setattr(module, "_wait_for_process_group_exit", lambda *_args: True)
    monkeypatch.setattr(module, "_reap_judge_leader", lambda item: reaped.append(item))

    helper(process)

    assert reaped == [process]


def test_posix_terminate_wraps_term_oserror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, module = _resolve("_terminate_judge_process_group")
    process = _Process(poll_values=())
    _force_posix(monkeypatch, module)
    failure = OSError("term failed")
    monkeypatch.setattr(module, "_process_group_exists", lambda _pgid: True)
    monkeypatch.setattr(
        module,
        "_signal_judge_process_group",
        lambda *_args: (_ for _ in ()).throw(failure),
    )

    with pytest.raises(module.JudgeProcessCleanupError, match="could not terminate") as exc:
        helper(process)

    assert exc.value.__cause__ is failure


def test_posix_terminate_escalates_to_kill_and_reaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, module = _resolve("_terminate_judge_process_group")
    process = _Process(poll_values=())
    _force_posix(monkeypatch, module)
    signals: list[int] = []
    waits = iter((False, True))
    reaped: list[_Process] = []
    monkeypatch.setattr(module, "_process_group_exists", lambda _pgid: True)
    monkeypatch.setattr(
        module,
        "_signal_judge_process_group",
        lambda _process, sig: signals.append(int(sig)),
    )
    monkeypatch.setattr(
        module, "_wait_for_process_group_exit", lambda *_args: next(waits)
    )
    monkeypatch.setattr(module, "_reap_judge_leader", lambda item: reaped.append(item))

    helper(process)

    assert signals == [int(signal.SIGTERM), module._SIGKILL]
    assert reaped == [process]


def test_posix_terminate_tolerates_kill_processlookup_race(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, module = _resolve("_terminate_judge_process_group")
    process = _Process(poll_values=())
    _force_posix(monkeypatch, module)
    signals: list[int] = []
    waits = iter((False, True))
    reaped: list[_Process] = []

    def signal_group(_process: _Process, sig: int) -> None:
        signals.append(int(sig))
        if int(sig) == module._SIGKILL:
            raise ProcessLookupError("gone before kill")

    monkeypatch.setattr(module, "_process_group_exists", lambda _pgid: True)
    monkeypatch.setattr(module, "_signal_judge_process_group", signal_group)
    monkeypatch.setattr(
        module, "_wait_for_process_group_exit", lambda *_args: next(waits)
    )
    monkeypatch.setattr(module, "_reap_judge_leader", lambda item: reaped.append(item))

    helper(process)

    assert signals == [int(signal.SIGTERM), module._SIGKILL]
    assert reaped == [process]


def test_posix_terminate_wraps_kill_oserror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, module = _resolve("_terminate_judge_process_group")
    process = _Process(poll_values=())
    _force_posix(monkeypatch, module)
    failure = OSError("kill failed")

    def signal_group(_process: _Process, sig: int) -> None:
        if int(sig) == module._SIGKILL:
            raise failure

    monkeypatch.setattr(module, "_process_group_exists", lambda _pgid: True)
    monkeypatch.setattr(module, "_signal_judge_process_group", signal_group)
    monkeypatch.setattr(module, "_wait_for_process_group_exit", lambda *_args: False)

    with pytest.raises(module.JudgeProcessCleanupError, match="could not kill") as exc:
        helper(process)

    assert exc.value.__cause__ is failure


def test_posix_terminate_rejects_group_surviving_sigkill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, module = _resolve("_terminate_judge_process_group")
    process = _Process(poll_values=())
    _force_posix(monkeypatch, module)
    monkeypatch.setattr(module, "_process_group_exists", lambda _pgid: True)
    monkeypatch.setattr(module, "_signal_judge_process_group", lambda *_args: None)
    monkeypatch.setattr(module, "_wait_for_process_group_exit", lambda *_args: False)

    with pytest.raises(module.JudgeProcessCleanupError, match="survived SIGKILL"):
        helper(process)


def test_non_posix_cleanup_is_noop_for_completed_leader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, module = _resolve("_terminate_judge_process_group")
    process = _Process(poll_values=(0,), wait_effects=())
    _force_non_posix(monkeypatch, module)

    helper(process)

    assert process.terminate_calls == 0
    assert process.kill_calls == 0
    assert process.wait_timeouts == []


def test_non_posix_cleanup_terminates_and_waits_for_live_leader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, module = _resolve("_terminate_judge_process_group")
    process = _Process(poll_values=(None,), wait_effects=(0,))
    _force_non_posix(monkeypatch, module)

    helper(process)

    assert process.terminate_calls == 1
    assert process.kill_calls == 0
    assert process.wait_timeouts == [module._JUDGE_TERMINATION_GRACE_SECONDS]


def test_non_posix_cleanup_escalates_wait_timeout_to_kill_and_reap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, module = _resolve("_terminate_judge_process_group")
    first_timeout = subprocess.TimeoutExpired(["judge"], timeout=1)
    process = _Process(
        poll_values=(None, None),
        wait_effects=(first_timeout, -9),
    )
    _force_non_posix(monkeypatch, module)

    helper(process)

    assert process.terminate_calls == 1
    assert process.kill_calls == 1
    assert process.wait_timeouts == [
        module._JUDGE_TERMINATION_GRACE_SECONDS,
        module._JUDGE_TERMINATION_GRACE_SECONDS,
    ]
    assert process.returncode == -9


@pytest.mark.parametrize(
    "reap_error",
    [OSError("reap failed"), subprocess.TimeoutExpired(["judge"], timeout=1)],
)
def test_non_posix_cleanup_reports_post_kill_reap_failure(
    monkeypatch: pytest.MonkeyPatch,
    reap_error: BaseException,
) -> None:
    helper, module = _resolve("_terminate_judge_process_group")
    first_timeout = subprocess.TimeoutExpired(["judge"], timeout=1)
    process = _Process(
        poll_values=(None, None),
        wait_effects=(first_timeout, reap_error),
    )
    _force_non_posix(monkeypatch, module)

    with pytest.raises(module.JudgeProcessCleanupError, match="could not be reaped") as exc:
        helper(process)

    assert exc.value.__cause__ is reap_error
    assert process.terminate_calls == 1
    assert process.kill_calls == 1


def test_non_posix_initial_wait_oserror_propagates_without_kill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, module = _resolve("_terminate_judge_process_group")
    failure = OSError("initial wait failed")
    process = _Process(poll_values=(None,), wait_effects=(failure,))
    _force_non_posix(monkeypatch, module)

    with pytest.raises(OSError) as exc:
        helper(process)

    assert exc.value is failure
    assert process.terminate_calls == 1
    assert process.kill_calls == 0
