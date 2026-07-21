# -----------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available - see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Adversarial contracts for black-box judge reader bootstrap cleanup."""

from __future__ import annotations

import signal
import subprocess
from collections.abc import Callable
from typing import Any

import pytest

import evoom_guard.blackbox as blackbox_module


class _ReaderStartFailure(RuntimeError):
    """Distinct primary failure used to prove exception identity."""


class _CleanupFailure(RuntimeError):
    """Distinct secondary failure that pytest can classify as an assertion failure."""


class _FakePipe:
    def __init__(self, close_error: BaseException | None = None) -> None:
        self.close_calls = 0
        self.close_error = close_error

    def close(self) -> None:
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


class _FakeJudgeProcess:
    pid = 4242

    def __init__(
        self,
        *,
        returncode: int | None = 0,
        pipe_close_error: BaseException | None = None,
    ) -> None:
        self.returncode = returncode
        self.stdout = _FakePipe(pipe_close_error)
        self.stderr = _FakePipe(pipe_close_error)
        self.terminate_calls = 0
        self.kill_calls = 0
        self.wait_calls = 0

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminate_calls += 1
        self.returncode = -int(signal.SIGTERM)

    def kill(self) -> None:
        self.kill_calls += 1
        self.returncode = -int(getattr(signal, "SIGKILL", 9))

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self.wait_calls += 1
        if self.returncode is None:
            raise subprocess.TimeoutExpired(["pytest"], 1)
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

    @property
    def ident(self) -> int | None:
        return self.index + 100 if self.started else None

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

    monkeypatch.setattr(blackbox_module.threading, "Thread", factory)
    return readers


@pytest.mark.parametrize(
    ("failure_index", "starts_before_failure"),
    [(0, False), (1, False), (1, True)],
)
def test_reader_start_failure_cleans_group_handles_pipes_and_preserves_primary(
    monkeypatch: pytest.MonkeyPatch,
    failure_index: int,
    starts_before_failure: bool,
) -> None:
    """Partial reader startup can neither leak the judge nor mask its cause."""

    primary = _ReaderStartFailure(f"reader {failure_index} failed")
    process = _FakeJudgeProcess(returncode=0)
    readers = _install_reader_factory(
        monkeypatch,
        failure_index=failure_index,
        primary=primary,
        starts_before_failure=starts_before_failure,
    )
    cleanup_calls: list[_FakeJudgeProcess] = []
    joined_reader_indexes: list[int] = []

    monkeypatch.setattr(
        blackbox_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        blackbox_module,
        "_terminate_judge_process_group",
        lambda candidate: cleanup_calls.append(candidate),
    )

    def join_attempted_reader(
        attempted: list[_FakeReader], _streams: list[Any]
    ) -> bool:
        assert len(attempted) == 1
        joined_reader_indexes.append(attempted[0].index)
        attempted[0].join()
        return True

    monkeypatch.setattr(
        blackbox_module,
        "_join_pipe_readers",
        join_attempted_reader,
    )

    with pytest.raises(_ReaderStartFailure) as exc:
        blackbox_module._run_judge_process(
            ["pytest"], cwd="/judge", env={}, timeout=1
        )

    assert exc.value is primary
    # Cleanup is unconditional: an exited leader is not proof that its process
    # group has no surviving descendant.
    assert cleanup_calls == [process]
    expected_close_calls = [
        int(
            index < failure_index
            or (index == failure_index and starts_before_failure)
            or index > failure_index
        )
        for index in range(2)
    ]
    assert [
        process.stdout.close_calls,
        process.stderr.close_calls,
    ] == expected_close_calls
    assert joined_reader_indexes == list(range(failure_index + 1))
    assert [reader.start_calls for reader in readers] == [
        1 if index <= failure_index else 0 for index in range(2)
    ]


@pytest.mark.parametrize(
    "primary_factory",
    [
        lambda: _ReaderStartFailure("reader failed"),
        lambda: KeyboardInterrupt("reader interrupted"),
        lambda: SystemExit("reader stopped"),
    ],
)
def test_reader_start_primary_survives_every_cleanup_baseexception(
    monkeypatch: pytest.MonkeyPatch,
    primary_factory: Callable[[], BaseException],
) -> None:
    """Cleanup failures are secondary to an active reader-start BaseException."""

    primary = primary_factory()
    process = _FakeJudgeProcess(
        returncode=None,
        pipe_close_error=GeneratorExit("pipe close failed"),
    )
    _install_reader_factory(
        monkeypatch,
        failure_index=0,
        primary=primary,
        starts_before_failure=True,
    )
    monkeypatch.setattr(
        blackbox_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        blackbox_module,
        "_terminate_judge_process_group",
        lambda _process: (_ for _ in ()).throw(SystemExit("cleanup failed")),
    )
    monkeypatch.setattr(
        blackbox_module,
        "_join_pipe_readers",
        lambda *_args: (_ for _ in ()).throw(_CleanupFailure("join failed")),
    )

    with pytest.raises(type(primary)) as exc:
        blackbox_module._run_judge_process(
            ["pytest"], cwd="/judge", env={}, timeout=1
        )

    assert exc.value is primary
    # The attempted stdout reader may be live after failed process cleanup, so
    # its BufferedReader is deliberately not closed synchronously. The stderr
    # reader was never attempted and is safe to close.
    assert process.stdout.close_calls == 0
    assert process.stderr.close_calls == 1


def test_second_reader_constructor_failure_cleans_process_and_both_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A constructor failure after Popen is part of the guarded startup phase."""

    primary = _ReaderStartFailure("second reader constructor failed")
    process = _FakeJudgeProcess(returncode=0)
    constructor_calls = 0
    constructed_readers: list[_FakeReader] = []
    cleanup_calls: list[_FakeJudgeProcess] = []

    def factory(*_args: Any, **_kwargs: Any) -> _FakeReader:
        nonlocal constructor_calls
        constructor_calls += 1
        if constructor_calls == 2:
            raise primary
        reader = _FakeReader(
            0,
            failure_index=99,
            primary=primary,
            starts_before_failure=False,
        )
        constructed_readers.append(reader)
        return reader

    monkeypatch.setattr(blackbox_module.threading, "Thread", factory)
    monkeypatch.setattr(
        blackbox_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        blackbox_module,
        "_terminate_judge_process_group",
        lambda candidate: cleanup_calls.append(candidate),
    )

    with pytest.raises(_ReaderStartFailure) as exc:
        blackbox_module._run_judge_process(
            ["pytest"], cwd="/judge", env={}, timeout=1
        )

    assert exc.value is primary
    assert cleanup_calls == [process]
    assert process.stdout.close_calls == 1
    assert process.stderr.close_calls == 1
    assert len(constructed_readers) == 1
    assert constructed_readers[0].start_calls == 0
    assert constructed_readers[0].join_calls == 0


def test_missing_output_pipe_fails_closed_and_reaps_spawned_judge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A violated Popen pipe invariant must not leave the spawned process alive."""

    process = _FakeJudgeProcess(returncode=None)
    process.stderr = None
    cleanup_calls: list[_FakeJudgeProcess] = []
    monkeypatch.setattr(
        blackbox_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        blackbox_module,
        "_terminate_judge_process_group",
        lambda candidate: cleanup_calls.append(candidate),
    )

    with pytest.raises(
        blackbox_module.JudgeProcessCleanupError,
        match="output pipes were not created",
    ):
        blackbox_module._run_judge_process(
            ["pytest"], cwd="/judge", env={}, timeout=1
        )

    assert cleanup_calls == [process]
    assert process.stdout.close_calls == 1


def test_live_reader_pipe_is_never_closed_synchronously(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A blocked BufferedReader close must not defeat the bounded join contract."""

    stream = _FakePipe(AssertionError("live reader stream must not be closed"))
    primary = _ReaderStartFailure("unused")
    reader = _FakeReader(
        0,
        failure_index=99,
        primary=primary,
        starts_before_failure=False,
    )
    reader.started = True
    monkeypatch.setattr(
        blackbox_module,
        "_join_pipe_readers",
        lambda *_args: False,
    )

    assert blackbox_module._join_judge_pipe_readers([reader], [stream]) is False
    assert stream.close_calls == 0


def test_attempted_reader_without_ident_is_not_assumed_safe_to_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Native startup can precede both Thread.ident and the started event."""

    stream = _FakePipe(AssertionError("attempted reader stream must not be closed"))
    reader = _FakeReader(
        0,
        failure_index=0,
        primary=_ReaderStartFailure("unused"),
        starts_before_failure=False,
    )
    assert reader.ident is None
    monkeypatch.setattr(
        blackbox_module,
        "_join_pipe_readers",
        lambda *_args: (_ for _ in ()).throw(
            RuntimeError("cannot join thread before it is started")
        ),
    )

    with pytest.raises(RuntimeError, match="cannot join"):
        blackbox_module._join_judge_pipe_readers([reader], [stream])

    assert stream.close_calls == 0


def test_post_start_baseexception_cleans_completed_group_and_preserves_primary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The one lifecycle guard also covers failures after both readers start."""

    primary = _ReaderStartFailure("post-start failure")
    process = _FakeJudgeProcess(returncode=0)
    readers = _install_reader_factory(
        monkeypatch,
        failure_index=99,
        primary=primary,
        starts_before_failure=False,
    )
    cleanup_calls: list[_FakeJudgeProcess] = []
    monkeypatch.setattr(
        blackbox_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        blackbox_module,
        "_terminate_judge_process_group",
        lambda candidate: cleanup_calls.append(candidate),
    )
    monkeypatch.setattr(
        blackbox_module.time,
        "monotonic",
        lambda: (_ for _ in ()).throw(primary),
    )
    monkeypatch.setattr(
        blackbox_module,
        "_join_pipe_readers",
        lambda *_args: (_ for _ in ()).throw(_CleanupFailure("join failed")),
    )

    with pytest.raises(_ReaderStartFailure) as exc:
        blackbox_module._run_judge_process(
            ["pytest"], cwd="/judge", env={}, timeout=1
        )

    assert exc.value is primary
    assert cleanup_calls == [process]
    assert [reader.start_calls for reader in readers] == [1, 1]


def test_reader_start_failure_uses_posix_group_cleanup_for_exited_leader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Partial startup still reaps a POSIX PGID when its leader already exited."""

    primary = _ReaderStartFailure("reader failed")
    process = _FakeJudgeProcess(returncode=0)
    _install_reader_factory(
        monkeypatch,
        failure_index=0,
        primary=primary,
        starts_before_failure=False,
    )
    group_alive = True
    signals: list[int] = []

    def killpg(_process_group: int, sig: int) -> None:
        nonlocal group_alive
        if sig == 0:
            if group_alive:
                return
            raise ProcessLookupError
        signals.append(int(sig))
        group_alive = False

    monkeypatch.setattr(
        blackbox_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(blackbox_module.os, "name", "posix")
    monkeypatch.setattr(blackbox_module.os, "killpg", killpg, raising=False)

    with pytest.raises(_ReaderStartFailure) as exc:
        blackbox_module._run_judge_process(
            ["pytest"], cwd="/judge", env={}, timeout=1
        )

    assert exc.value is primary
    assert signals == [int(signal.SIGTERM)]


def test_reader_start_failure_uses_bounded_non_posix_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fallback terminates and reaps a live leader after startup failure."""

    primary = _ReaderStartFailure("reader failed")
    process = _FakeJudgeProcess(returncode=None)
    _install_reader_factory(
        monkeypatch,
        failure_index=0,
        primary=primary,
        starts_before_failure=False,
    )
    monkeypatch.setattr(
        blackbox_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(blackbox_module.os, "name", "nt")

    with pytest.raises(_ReaderStartFailure) as exc:
        blackbox_module._run_judge_process(
            ["pytest"], cwd="/judge", env={}, timeout=1
        )

    assert exc.value is primary
    assert process.terminate_calls == 1
    assert process.kill_calls == 0
    assert process.wait_calls == 1
