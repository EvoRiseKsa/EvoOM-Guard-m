# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available - see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Adversarial contracts for bounded-process reader bootstrap cleanup."""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import evoom_guard.execution.process as process_module
from evoom_guard.execution import ProcessContainmentError, execute_bounded_process


class _ReaderStartFailure(RuntimeError):
    """Distinct primary failure used to prove exception identity."""


class _FakePipe:
    def __init__(self, close_error: BaseException | None = None) -> None:
        self.close_calls = 0
        self.close_error = close_error

    def close(self) -> None:
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


class _FakeProcess:
    pid = 4242

    def __init__(self, *, returncode: int | None = 0) -> None:
        self.returncode = returncode
        self.stdout: _FakePipe | None = _FakePipe()
        self.stderr: _FakePipe | None = _FakePipe()

    def poll(self) -> int | None:
        return self.returncode


class _FakeReader:
    def __init__(
        self,
        index: int,
        *,
        failure_index: int,
        primary: BaseException,
        starts_before_failure: bool,
    ) -> None:
        self.index = index
        self.failure_index = failure_index
        self.primary = primary
        self.starts_before_failure = starts_before_failure
        self.started = False
        self.start_calls = 0
        self.join_calls = 0

    def start(self) -> None:
        self.start_calls += 1
        if self.index == self.failure_index:
            self.started = self.starts_before_failure
            raise self.primary
        self.started = True

    def join(self, _timeout: float | None = None) -> None:
        self.join_calls += 1
        if not self.started:
            raise RuntimeError("cannot join thread before it is started")

    def is_alive(self) -> bool:
        return False


def _request() -> process_module.BoundedProcessRequest:
    return process_module.BoundedProcessRequest.from_command(
        ["candidate"], cwd=None, env=None, timeout=1
    )


def _install_process(
    monkeypatch: pytest.MonkeyPatch, process: _FakeProcess
) -> None:
    monkeypatch.setattr(
        process_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(process_module, "process_group_popen_kwargs", lambda: {})


def _install_reader_factory(
    monkeypatch: pytest.MonkeyPatch,
    *,
    failure_index: int,
    primary: BaseException,
    starts_before_failure: bool,
) -> list[_FakeReader]:
    readers: list[_FakeReader] = []

    def factory(*_args: Any, **_kwargs: Any) -> _FakeReader:
        reader = _FakeReader(
            len(readers),
            failure_index=failure_index,
            primary=primary,
            starts_before_failure=starts_before_failure,
        )
        readers.append(reader)
        return reader

    monkeypatch.setattr(process_module.threading, "Thread", factory)
    return readers


@pytest.mark.parametrize(
    ("failure_index", "starts_before_failure"),
    [(0, False), (1, False), (1, True)],
)
def test_reader_start_failure_cleans_tree_and_preserves_primary(
    monkeypatch: pytest.MonkeyPatch,
    failure_index: int,
    starts_before_failure: bool,
) -> None:
    """Partial startup cannot leak an exited leader's surviving descendants."""

    primary = _ReaderStartFailure(f"reader {failure_index} failed")
    process = _FakeProcess(returncode=0)
    _install_process(monkeypatch, process)
    readers = _install_reader_factory(
        monkeypatch,
        failure_index=failure_index,
        primary=primary,
        starts_before_failure=starts_before_failure,
    )
    cleanup_calls: list[_FakeProcess] = []
    joined_indexes: list[int] = []
    monkeypatch.setattr(
        process_module,
        "_terminate_process_tree",
        lambda candidate, _limits: cleanup_calls.append(candidate) or True,
    )

    def join_one(
        attempted: list[_FakeReader], streams: list[Any], _timeout: float
    ) -> bool:
        assert len(attempted) == 1
        assert streams == []
        joined_indexes.append(attempted[0].index)
        attempted[0].join()
        return True

    monkeypatch.setattr(process_module, "join_pipe_readers", join_one)

    with pytest.raises(_ReaderStartFailure) as exc:
        execute_bounded_process(_request())

    assert exc.value is primary
    assert cleanup_calls == [process]
    assert joined_indexes == list(range(failure_index + 1))
    assert [reader.start_calls for reader in readers] == [
        1 if index <= failure_index else 0 for index in range(2)
    ]
    expected_close_calls = [
        int(
            index < failure_index
            or (index == failure_index and starts_before_failure)
            or index > failure_index
        )
        for index in range(2)
    ]
    assert process.stdout is not None and process.stderr is not None
    assert [process.stdout.close_calls, process.stderr.close_calls] == (
        expected_close_calls
    )


@pytest.mark.parametrize(
    "primary_factory",
    [
        lambda: _ReaderStartFailure("reader failed"),
        lambda: KeyboardInterrupt("reader interrupted"),
        lambda: SystemExit("reader stopped"),
    ],
)
def test_reader_start_primary_survives_cleanup_baseexceptions(
    monkeypatch: pytest.MonkeyPatch,
    primary_factory: Callable[[], BaseException],
) -> None:
    """Cleanup is best effort while an active BaseException remains authoritative."""

    primary = primary_factory()
    process = _FakeProcess(returncode=None)
    assert process.stdout is not None
    process.stdout.close_error = GeneratorExit("close failed")
    _install_process(monkeypatch, process)
    _install_reader_factory(
        monkeypatch,
        failure_index=0,
        primary=primary,
        starts_before_failure=True,
    )
    monkeypatch.setattr(
        process_module,
        "_terminate_process_tree",
        lambda *_args: (_ for _ in ()).throw(SystemExit("cleanup failed")),
    )
    monkeypatch.setattr(
        process_module,
        "join_pipe_readers",
        lambda *_args: (_ for _ in ()).throw(KeyboardInterrupt("join failed")),
    )

    with pytest.raises(type(primary)) as exc:
        execute_bounded_process(_request())

    assert exc.value is primary
    assert process.stdout.close_calls == 0
    assert process.stderr is not None
    assert process.stderr.close_calls == 1


def test_second_reader_constructor_failure_cleans_tree_and_both_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = _ReaderStartFailure("second reader constructor failed")
    process = _FakeProcess(returncode=0)
    _install_process(monkeypatch, process)
    constructor_calls = 0
    cleanup_calls: list[_FakeProcess] = []

    def factory(*_args: Any, **_kwargs: Any) -> _FakeReader:
        nonlocal constructor_calls
        constructor_calls += 1
        if constructor_calls == 2:
            raise primary
        return _FakeReader(
            0,
            failure_index=99,
            primary=primary,
            starts_before_failure=False,
        )

    monkeypatch.setattr(process_module.threading, "Thread", factory)
    monkeypatch.setattr(
        process_module,
        "_terminate_process_tree",
        lambda candidate, _limits: cleanup_calls.append(candidate) or True,
    )

    with pytest.raises(_ReaderStartFailure) as exc:
        execute_bounded_process(_request())

    assert exc.value is primary
    assert cleanup_calls == [process]
    assert process.stdout is not None and process.stderr is not None
    assert process.stdout.close_calls == 1
    assert process.stderr.close_calls == 1


def test_missing_output_pipe_fails_closed_after_cleaning_spawned_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(returncode=None)
    process.stderr = None
    _install_process(monkeypatch, process)
    cleanup_calls: list[_FakeProcess] = []
    monkeypatch.setattr(
        process_module,
        "_terminate_process_tree",
        lambda candidate, _limits: cleanup_calls.append(candidate) or True,
    )

    with pytest.raises(ProcessContainmentError, match="output pipes were not created"):
        execute_bounded_process(_request())

    assert cleanup_calls == [process]
    assert process.stdout is not None
    assert process.stdout.close_calls == 1


def test_post_start_baseexception_cleans_even_completed_tree_without_masking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = _ReaderStartFailure("clock failed")
    process = _FakeProcess(returncode=0)
    _install_process(monkeypatch, process)
    readers = _install_reader_factory(
        monkeypatch,
        failure_index=99,
        primary=primary,
        starts_before_failure=False,
    )
    cleanup_calls: list[_FakeProcess] = []
    monkeypatch.setattr(
        process_module,
        "_terminate_process_tree",
        lambda candidate, _limits: cleanup_calls.append(candidate) or True,
    )
    monkeypatch.setattr(
        process_module.time,
        "monotonic",
        lambda: (_ for _ in ()).throw(primary),
    )
    monkeypatch.setattr(
        process_module,
        "join_pipe_readers",
        lambda *_args: (_ for _ in ()).throw(SystemExit("join failed")),
    )

    with pytest.raises(_ReaderStartFailure) as exc:
        execute_bounded_process(_request())

    assert exc.value is primary
    assert cleanup_calls == [process]
    assert [reader.start_calls for reader in readers] == [1, 1]


def test_attempted_reader_without_join_proof_never_closes_its_pipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = _ReaderStartFailure("unused")
    reader = _FakeReader(
        0,
        failure_index=0,
        primary=primary,
        starts_before_failure=False,
    )
    attempted_stream = _FakePipe(AssertionError("uncertain stream was closed"))
    unattempted_stream = _FakePipe()
    monkeypatch.setattr(
        process_module,
        "join_pipe_readers",
        lambda *_args: (_ for _ in ()).throw(
            RuntimeError("cannot join thread before it is started")
        ),
    )

    with pytest.raises(RuntimeError, match="cannot join"):
        process_module._join_attempted_pipe_readers(  # type: ignore[attr-defined]
            [reader], [attempted_stream, unattempted_stream], 0.1
        )

    assert attempted_stream.close_calls == 0
    assert unattempted_stream.close_calls == 1


def test_live_reader_pipe_is_never_closed_synchronously() -> None:
    class LiveReader:
        def join(self, _timeout: float | None = None) -> None:
            return None

        def is_alive(self) -> bool:
            return True

    stream = _FakePipe(AssertionError("live reader stream must not be closed"))

    assert process_module.join_pipe_readers([LiveReader()], [stream], 0.01) is False  # type: ignore[list-item]
    assert stream.close_calls == 0


def test_inherited_pipe_does_not_extend_the_bounded_join_window(
    tmp_path: Path,
) -> None:
    """A departed leader's descendant cannot turn pipe close into an unbounded wait."""

    ready_file = tmp_path / "descendant.ready"
    child = (
        "from pathlib import Path; import sys, time; "
        "Path(sys.argv[1]).write_text('ready'); time.sleep(2)"
    )
    parent = (
        "from pathlib import Path; import subprocess, sys, time; "
        "subprocess.Popen([sys.executable, '-c', sys.argv[2], sys.argv[1]]); "
        "p=Path(sys.argv[1]); "
        "[time.sleep(0.01) for _ in range(100) if not p.exists()]"
    )
    request = process_module.BoundedProcessRequest.from_command(
        [sys.executable, "-c", parent, str(ready_file), child],
        cwd=str(tmp_path),
        env=os.environ.copy(),
        timeout=1,
        limits=process_module.ProcessLimits(
            termination_grace_seconds=0.2,
            kill_grace_seconds=0.5,
            reader_join_seconds=0.05,
        ),
    )

    started = time.monotonic()
    try:
        with pytest.raises(ProcessContainmentError):
            execute_bounded_process(request)
    finally:
        elapsed = time.monotonic() - started
        # The Windows fallback cannot prove an already-orphaned descendant was
        # killed. Let the deliberately short-lived fixture exit by itself;
        # never signal a stale PID that the runner might already have reused.
        time.sleep(2.25)

    assert elapsed < 1.25


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups")
def test_real_reader_start_failure_kills_descendant_before_side_effect(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The startup guard stops a real descendant, not only a mocked leader."""

    marker = tmp_path / "descendant-survived"
    child = (
        "from pathlib import Path; import sys, time; "
        "time.sleep(0.8); Path(sys.argv[1]).write_text('survived')"
    )
    parent = (
        "import subprocess, sys, time; "
        "subprocess.Popen([sys.executable, '-c', sys.argv[2], sys.argv[1]]); "
        "time.sleep(5)"
    )
    primary = _ReaderStartFailure("reader bootstrap failed")

    class FailingReader:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            self.started = False

        def start(self) -> None:
            # Give the managed leader time to create its descendant before the
            # asynchronous startup failure reaches the lifecycle guard.
            time.sleep(0.25)
            raise primary

        def join(self, _timeout: float | None = None) -> None:
            raise RuntimeError("reader startup was not proven")

        def is_alive(self) -> bool:
            return self.started

    monkeypatch.setattr(process_module.threading, "Thread", FailingReader)
    request = process_module.BoundedProcessRequest.from_command(
        [sys.executable, "-c", parent, str(marker), child],
        cwd=str(tmp_path),
        env=os.environ.copy(),
        timeout=3,
        limits=process_module.ProcessLimits(
            termination_grace_seconds=0.2,
            kill_grace_seconds=2,
            reader_join_seconds=0.1,
        ),
    )

    with pytest.raises(_ReaderStartFailure) as exc:
        execute_bounded_process(request)

    assert exc.value is primary
    time.sleep(0.9)
    assert not marker.exists()
