from __future__ import annotations

import io
import os
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

from evoom_guard import finalizer_derivation
from evoom_guard.finalizer_derivation import FinalizerDerivationError, _git_command


class _PrimaryAbort(BaseException):
    pass


class _CleanupAbort(BaseException):
    pass


class _TrackingStream(io.BytesIO):
    def __init__(self, initial: bytes = b"") -> None:
        super().__init__(initial)
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1
        super().close()


class _FakeProcess:
    def __init__(
        self,
        *,
        stdout: object | None = None,
        stderr: object | None = None,
        wait_actions: list[BaseException | int] | None = None,
        kill_error: BaseException | None = None,
        poll_result: int | None = 0,
    ) -> None:
        self.stdout = _TrackingStream() if stdout is None else stdout
        self.stderr = _TrackingStream() if stderr is None else stderr
        self.returncode: int | None = None
        self.wait_actions = list(wait_actions or [])
        self.wait_timeouts: list[float] = []
        self.kill_calls = 0
        self.kill_error = kill_error
        self.poll_result = poll_result

    def poll(self) -> int | None:
        if self.poll_result is not None:
            self.returncode = self.poll_result
        return self.poll_result

    def wait(self, *, timeout: float) -> int:
        assert timeout > 0
        self.wait_timeouts.append(timeout)
        if self.wait_actions:
            action = self.wait_actions.pop(0)
            if isinstance(action, BaseException):
                raise action
            self.returncode = action
            return action
        if self.returncode is None:
            self.returncode = 0
        return self.returncode

    def kill(self) -> None:
        self.kill_calls += 1
        if self.kill_error is not None:
            raise self.kill_error
        self.returncode = -9


def _install_process(
    monkeypatch: pytest.MonkeyPatch,
    process: _FakeProcess,
) -> None:
    monkeypatch.setattr(
        finalizer_derivation.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )

    def terminate(candidate: _FakeProcess, limits: object) -> bool:
        if candidate.returncode is None:
            candidate.kill()
        try:
            candidate.wait(  # type: ignore[attr-defined]
                timeout=limits.kill_grace_seconds  # type: ignore[attr-defined]
            )
        except BaseException:
            return False
        return candidate.returncode is not None

    monkeypatch.setattr(finalizer_derivation, "terminate_process_tree", terminate)


@pytest.mark.parametrize("failed_start", [0, 1])
def test_reader_start_failure_kills_and_reaps_git_without_masking_primary(
    monkeypatch: pytest.MonkeyPatch,
    failed_start: int,
) -> None:
    process = _FakeProcess()
    _install_process(monkeypatch, process)
    created: list[object] = []

    class ControlledThread:
        def __init__(self, **_kwargs: object) -> None:
            self.index = len(created)
            self.started = False
            self.join_timeouts: list[float] = []
            created.append(self)

        def start(self) -> None:
            if self.index == failed_start:
                raise _PrimaryAbort("reader start failed")
            self.started = True

        def join(self, timeout: float) -> None:
            self.join_timeouts.append(timeout)
            if not self.started:
                raise RuntimeError("thread was never started")

        def is_alive(self) -> bool:
            return False

    monkeypatch.setattr(finalizer_derivation.threading, "Thread", ControlledThread)

    with pytest.raises(_PrimaryAbort, match="reader start failed"):
        _git_command("repo", ["rev-parse", "HEAD"], bare=False)

    assert process.kill_calls == 1
    assert process.wait_timeouts == [finalizer_derivation._GIT_KILL_REAP_SECONDS]
    failed_reader = created[failed_start]
    assert len(failed_reader.join_timeouts) == 1  # type: ignore[attr-defined]
    assert (  # type: ignore[attr-defined]
        0 <= failed_reader.join_timeouts[0]
        <= finalizer_derivation._GIT_READER_JOIN_SECONDS
    )
    failed_stream = process.stdout if failed_start == 0 else process.stderr
    assert isinstance(failed_stream, _TrackingStream)
    assert failed_stream.close_calls == 0


def test_reader_join_clamps_floating_point_deadline_overshoot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monotonic_value = 127.99045836929314
    assert (
        monotonic_value
        + finalizer_derivation._GIT_READER_JOIN_SECONDS
        - monotonic_value
        > finalizer_derivation._GIT_READER_JOIN_SECONDS
    )

    class ControlledThread:
        def __init__(self) -> None:
            self.join_timeouts: list[float] = []

        def join(self, timeout: float) -> None:
            self.join_timeouts.append(timeout)

        def is_alive(self) -> bool:
            return False

    reader = ControlledThread()
    stream = _TrackingStream()
    monkeypatch.setattr(
        finalizer_derivation.time,
        "monotonic",
        lambda: monotonic_value,
    )

    assert finalizer_derivation._join_and_close_git_readers(  # type: ignore[arg-type]
        [reader],
        [stream],
    )
    assert reader.join_timeouts == [finalizer_derivation._GIT_READER_JOIN_SECONDS]
    assert stream.close_calls == 1


def test_reader_constructor_failure_cleans_git_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess()
    _install_process(monkeypatch, process)

    def fail_constructor(**_kwargs: object) -> object:
        raise _PrimaryAbort("reader construction failed")

    monkeypatch.setattr(finalizer_derivation.threading, "Thread", fail_constructor)

    with pytest.raises(_PrimaryAbort, match="reader construction failed"):
        _git_command("repo", ["rev-parse", "HEAD"], bare=False)

    assert process.kill_calls == 1
    assert process.returncode == -9
    assert isinstance(process.stdout, _TrackingStream)
    assert isinstance(process.stderr, _TrackingStream)
    assert process.stdout.close_calls == 1
    assert process.stderr.close_calls == 1


def test_missing_pipe_fails_closed_after_bounded_child_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stderr = _TrackingStream()
    process = _FakeProcess(stdout=None, stderr=stderr)
    process.stdout = None
    _install_process(monkeypatch, process)

    with pytest.raises(FinalizerDerivationError, match="output pipes were not created"):
        _git_command("repo", ["rev-parse", "HEAD"], bare=False)

    assert process.kill_calls == 1
    assert process.wait_timeouts == [finalizer_derivation._GIT_KILL_REAP_SECONDS]
    assert stderr.close_calls == 1


@pytest.mark.parametrize(
    "failure_factory",
    [
        pytest.param(lambda: OSError("reader exploded"), id="oserror"),
        pytest.param(lambda: ValueError("reader exploded"), id="valueerror"),
        pytest.param(lambda: _PrimaryAbort("reader exploded"), id="baseexception"),
    ],
)
def test_worker_read_failure_cannot_return_partial_git_output(
    monkeypatch: pytest.MonkeyPatch,
    failure_factory: Callable[[], BaseException],
) -> None:
    failed = threading.Event()

    class PartialThenFailure(_TrackingStream):
        def __init__(self) -> None:
            super().__init__()
            self.reads = 0

        def read(self, _size: int = -1) -> bytes:
            self.reads += 1
            if self.reads == 1:
                return b"plausible-prefix"
            failed.set()
            raise failure_factory()

    process = _FakeProcess(stdout=PartialThenFailure())

    def poll_after_reader_failure() -> int:
        assert failed.wait(1), "reader did not reach its injected failure"
        process.returncode = 0
        return 0

    process.poll = poll_after_reader_failure  # type: ignore[method-assign]
    _install_process(monkeypatch, process)

    class ImmediateThread:
        def __init__(
            self,
            *,
            target: Callable[..., None],
            args: tuple[object, ...],
            kwargs: dict[str, object],
            daemon: bool,
        ) -> None:
            assert daemon is True
            self.target = target
            self.args = args
            self.kwargs = kwargs

        def start(self) -> None:
            self.target(*self.args, **self.kwargs)

        def join(self, _timeout: float) -> None:
            pass

        def is_alive(self) -> bool:
            return False

    monkeypatch.setattr(finalizer_derivation.threading, "Thread", ImmediateThread)

    with pytest.raises(FinalizerDerivationError, match="reader exploded"):
        _git_command("repo", ["ls-tree", "HEAD"], bare=False)

    assert process.wait_timeouts == [finalizer_derivation._GIT_KILL_REAP_SECONDS]


def test_worker_read_failure_stops_a_still_live_git_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ImmediateReadFailure(_TrackingStream):
        def read(self, _size: int = -1) -> bytes:
            raise ValueError("live reader exploded")

    process = _FakeProcess(
        stdout=ImmediateReadFailure(),
        poll_result=None,
    )
    _install_process(monkeypatch, process)
    monkeypatch.setattr(finalizer_derivation, "_GIT_QUERY_TIMEOUT_SECONDS", 0.1)

    with pytest.raises(FinalizerDerivationError, match="live reader exploded"):
        _git_command("repo", ["ls-tree", "HEAD"], bare=False)

    assert process.kill_calls == 1


def test_git_launch_applies_the_managed_process_group_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(stdout=_TrackingStream(b"ok\n"))
    _install_process(monkeypatch, process)
    observed: dict[str, object] = {}

    def fake_popen(_command: list[str], **kwargs: object) -> _FakeProcess:
        observed.update(kwargs)
        return process

    monkeypatch.setattr(finalizer_derivation.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        finalizer_derivation,
        "process_group_popen_kwargs",
        lambda: {"managed_group_marker": True},
    )

    output = _git_command("repo", ["rev-parse", "HEAD"], bare=False)

    assert observed.get("managed_group_marker") is True
    assert output == b"ok\n"


def test_git_bytes_remain_exact_and_reader_joins_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"raw\x00bytes\xff\n"
    process = _FakeProcess(stdout=_TrackingStream(payload))
    _install_process(monkeypatch, process)
    readers: list[object] = []

    class ImmediateThread:
        def __init__(
            self,
            *,
            target: Callable[..., None],
            args: tuple[object, ...],
            kwargs: dict[str, object],
            daemon: bool,
        ) -> None:
            assert daemon is True
            self.target = target
            self.args = args
            self.kwargs = kwargs
            self.join_timeouts: list[float] = []
            readers.append(self)

        def start(self) -> None:
            self.target(*self.args, **self.kwargs)

        def join(self, timeout: float) -> None:
            assert timeout >= 0
            self.join_timeouts.append(timeout)

        def is_alive(self) -> bool:
            return False

    monkeypatch.setattr(finalizer_derivation.threading, "Thread", ImmediateThread)

    output = _git_command("repo", ["cat-file", "blob", "a" * 40], bare=False)

    assert output == payload
    assert len(readers) == 2
    assert all(len(reader.join_timeouts) == 1 for reader in readers)
    assert all(
        0 <= timeout <= finalizer_derivation._GIT_READER_JOIN_SECONDS
        for reader in readers
        for timeout in reader.join_timeouts
    )


def test_posix_success_proves_post_completion_group_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(stdout=_TrackingStream(b"ok\n"))
    _install_process(monkeypatch, process)
    monkeypatch.setattr(
        finalizer_derivation,
        "os",
        SimpleNamespace(name="posix", environ=os.environ),
    )

    assert _git_command("repo", ["rev-parse", "HEAD"], bare=False) == b"ok\n"
    assert process.wait_timeouts == [finalizer_derivation._GIT_KILL_REAP_SECONDS] * 2


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups")
def test_real_posix_git_group_cleanup_stops_inherited_pipe_descendant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ready = tmp_path / "git-descendant-ready"
    survived = tmp_path / "git-descendant-survived"
    child = (
        "import signal, sys, time; from pathlib import Path; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "Path(sys.argv[1]).write_text('ready'); time.sleep(1.5); "
        "Path(sys.argv[2]).write_text('survived')"
    )
    parent = (
        "import subprocess, sys, time; from pathlib import Path; "
        "subprocess.Popen([sys.executable, '-c', sys.argv[3], "
        "sys.argv[1], sys.argv[2]]); "
        "deadline=time.monotonic()+3; "
        "\nwhile not Path(sys.argv[1]).exists() and "
        "time.monotonic()<deadline: time.sleep(0.01); "
        "\nraise SystemExit(0 if Path(sys.argv[1]).exists() else 2)"
    )
    real_popen = subprocess.Popen

    def descendant_git(
        _command: list[str],
        **kwargs: object,
    ) -> subprocess.Popen[bytes]:
        return real_popen(
            [sys.executable, "-c", parent, str(ready), str(survived), child],
            **kwargs,
        )

    monkeypatch.setattr(finalizer_derivation.subprocess, "Popen", descendant_git)

    assert _git_command("repo", ["rev-parse", "HEAD"], bare=False) == b""
    assert ready.exists()
    time.sleep(1.6)
    assert not survived.exists()


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_post_poll_wait_baseexception_remains_authoritative(
    monkeypatch: pytest.MonkeyPatch,
    cleanup_fails: bool,
) -> None:
    primary = _PrimaryAbort("post-poll cancellation")
    actions: list[BaseException | int] = [primary]
    if cleanup_fails:
        actions.extend(
            [
                _CleanupAbort("first cleanup failed"),
                _CleanupAbort("second cleanup failed"),
            ]
        )
    process = _FakeProcess(
        stdout=_TrackingStream(b"must-not-return\n"),
        wait_actions=actions,
    )
    _install_process(monkeypatch, process)

    with pytest.raises(_PrimaryAbort) as captured:
        _git_command("repo", ["rev-parse", "HEAD"], bare=False)

    assert captured.value is primary


def test_reader_join_baseexception_remains_authoritative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = _PrimaryAbort("join cancellation")
    stdout = _TrackingStream(b"must-not-return\n")
    process = _FakeProcess(stdout=stdout)
    _install_process(monkeypatch, process)
    created: list[object] = []

    class JoinFailureThread:
        def __init__(
            self,
            *,
            target: Callable[..., None],
            args: tuple[object, ...],
            kwargs: dict[str, object],
            daemon: bool,
        ) -> None:
            assert daemon is True
            self.index = len(created)
            self.target = target
            self.args = args
            self.kwargs = kwargs
            created.append(self)

        def start(self) -> None:
            self.target(*self.args, **self.kwargs)

        def join(self, _timeout: float) -> None:
            if self.index == 0:
                raise primary

        def is_alive(self) -> bool:
            return False

    monkeypatch.setattr(finalizer_derivation.threading, "Thread", JoinFailureThread)

    with pytest.raises(_PrimaryAbort) as captured:
        _git_command("repo", ["rev-parse", "HEAD"], bare=False)

    assert captured.value is primary
    assert stdout.close_calls == 0


def test_timeout_uses_bounded_kill_reap_and_reader_join(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(poll_result=None)
    _install_process(monkeypatch, process)
    monkeypatch.setattr(finalizer_derivation, "_GIT_QUERY_TIMEOUT_SECONDS", 0.01)

    with pytest.raises(FinalizerDerivationError, match="Git query timed out$"):
        _git_command("repo", ["rev-parse", "HEAD"], bare=False)

    assert process.kill_calls == 1
    assert process.wait_timeouts == [
        finalizer_derivation._GIT_KILL_REAP_SECONDS,
    ]


def test_timeout_reports_unproven_cleanup_without_unbounded_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(
        wait_actions=[
            subprocess.TimeoutExpired(["git"], 3),
            subprocess.TimeoutExpired(["git"], 3),
        ],
        poll_result=None,
    )
    _install_process(monkeypatch, process)
    monkeypatch.setattr(finalizer_derivation, "_GIT_QUERY_TIMEOUT_SECONDS", 0.01)

    with pytest.raises(
        FinalizerDerivationError,
        match="process cleanup could not be proven",
    ):
        _git_command("repo", ["rev-parse", "HEAD"], bare=False)

    assert process.kill_calls == 1
    assert process.wait_timeouts == [
        finalizer_derivation._GIT_KILL_REAP_SECONDS,
        finalizer_derivation._GIT_KILL_REAP_SECONDS,
    ]


def test_live_reader_stream_is_never_closed_synchronously(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout = _TrackingStream()
    stderr = _TrackingStream()
    process = _FakeProcess(stdout=stdout, stderr=stderr)
    _install_process(monkeypatch, process)
    created: list[object] = []

    class LiveThread:
        def __init__(self, **_kwargs: object) -> None:
            self.join_timeouts: list[float] = []
            created.append(self)

        def start(self) -> None:
            pass

        def join(self, timeout: float) -> None:
            self.join_timeouts.append(timeout)

        def is_alive(self) -> bool:
            return True

    monkeypatch.setattr(finalizer_derivation.threading, "Thread", LiveThread)

    with pytest.raises(
        FinalizerDerivationError,
        match="output readers did not stop after cleanup",
    ):
        _git_command("repo", ["rev-parse", "HEAD"], bare=False)

    assert stdout.close_calls == 0
    assert stderr.close_calls == 0
    assert all(len(thread.join_timeouts) == 2 for thread in created)
    assert all(
        0 <= timeout <= finalizer_derivation._GIT_READER_JOIN_SECONDS
        for thread in created
        for timeout in thread.join_timeouts
    )


def test_cleanup_baseexceptions_do_not_replace_reader_start_primary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(
        wait_actions=[_CleanupAbort("wait cleanup failed")],
        kill_error=_CleanupAbort("kill cleanup failed"),
    )
    _install_process(monkeypatch, process)
    join_calls: list[float] = []

    class FailingThread:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def start(self) -> None:
            raise _PrimaryAbort("authoritative primary")

        def join(self, timeout: float) -> None:
            join_calls.append(timeout)
            raise _CleanupAbort("join cleanup failed")

        def is_alive(self) -> bool:
            return True

    monkeypatch.setattr(finalizer_derivation.threading, "Thread", FailingThread)

    with pytest.raises(_PrimaryAbort, match="authoritative primary"):
        _git_command("repo", ["rev-parse", "HEAD"], bare=False)

    assert process.kill_calls == 1
    assert len(join_calls) == 1
