from __future__ import annotations

import io
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

from evoom_guard import github_attestation
from evoom_guard.github_attestation import GitHubAttestationError


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
        self.stdout = _TrackingStream(b"[{}]") if stdout is None else stdout
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
        assert timeout >= 0
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
) -> list[_FakeProcess]:
    cleanup_calls: list[_FakeProcess] = []
    monkeypatch.setattr(
        github_attestation.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )

    def terminate(candidate: _FakeProcess) -> bool:
        cleanup_calls.append(candidate)
        if candidate.returncode is None:
            candidate.kill()
        try:
            candidate.wait(
                timeout=github_attestation._GITHUB_ATTESTATION_KILL_REAP_SECONDS
            )
        except BaseException:
            return False
        return candidate.returncode is not None

    monkeypatch.setattr(github_attestation, "_terminate_gh_process_tree", terminate)
    return cleanup_calls


def _execute(tmp_path: Path, *, timeout_seconds: int = 1) -> bytes:
    return github_attestation._execute_gh_attestation_command(
        ["trusted-gh", "attestation", "verify"],
        gh_executable="trusted-gh",
        timeout_seconds=timeout_seconds,
        directory=str(tmp_path),
    )


@pytest.mark.parametrize("failed_start", [0, 1])
def test_reader_start_failure_cleans_child_without_masking_primary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_start: int,
) -> None:
    process = _FakeProcess()
    cleanups = _install_process(monkeypatch, process)
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

    monkeypatch.setattr(github_attestation.threading, "Thread", ControlledThread)

    with pytest.raises(_PrimaryAbort, match="reader start failed"):
        _execute(tmp_path)

    assert cleanups == [process]
    assert process.kill_calls == 1
    failed_reader = created[failed_start]
    assert len(failed_reader.join_timeouts) == 1  # type: ignore[attr-defined]
    failed_stream = process.stdout if failed_start == 0 else process.stderr
    assert isinstance(failed_stream, _TrackingStream)
    assert failed_stream.close_calls == 0
    safe_stream = process.stderr if failed_start == 0 else process.stdout
    assert isinstance(safe_stream, _TrackingStream)
    assert safe_stream.close_calls == 1


def test_reader_constructor_failure_cleans_child_and_pipes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess()
    cleanups = _install_process(monkeypatch, process)

    def fail_constructor(**_kwargs: object) -> object:
        raise _PrimaryAbort("reader construction failed")

    monkeypatch.setattr(github_attestation.threading, "Thread", fail_constructor)

    with pytest.raises(_PrimaryAbort, match="reader construction failed"):
        _execute(tmp_path)

    assert cleanups == [process]
    assert isinstance(process.stdout, _TrackingStream)
    assert isinstance(process.stderr, _TrackingStream)
    assert process.stdout.close_calls == 1
    assert process.stderr.close_calls == 1


@pytest.mark.parametrize("missing", ["stdout", "stderr"])
def test_missing_pipe_fails_after_bounded_child_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    missing: str,
) -> None:
    process = _FakeProcess()
    missing_stream = getattr(process, missing)
    setattr(process, missing, None)
    cleanups = _install_process(monkeypatch, process)

    with pytest.raises(GitHubAttestationError, match="did not provide output pipes"):
        _execute(tmp_path)

    assert cleanups == [process]
    assert isinstance(missing_stream, _TrackingStream)
    assert missing_stream.close_calls == 0
    remaining = process.stderr if missing == "stdout" else process.stdout
    assert isinstance(remaining, _TrackingStream)
    assert remaining.close_calls == 1


@pytest.mark.parametrize(
    "failure_factory",
    [
        pytest.param(lambda: OSError("reader exploded"), id="oserror"),
        pytest.param(lambda: ValueError("reader exploded"), id="valueerror"),
        pytest.param(lambda: _PrimaryAbort("reader exploded"), id="baseexception"),
    ],
)
def test_worker_failure_cannot_accept_plausible_partial_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_factory: Callable[[], BaseException],
) -> None:
    class PartialThenFailure(_TrackingStream):
        def __init__(self) -> None:
            super().__init__()
            self.reads = 0

        def read(self, _size: int = -1) -> bytes:
            self.reads += 1
            if self.reads == 1:
                return b"[{}]"
            raise failure_factory()

        read1 = read

    process = _FakeProcess(stdout=PartialThenFailure())
    cleanups = _install_process(monkeypatch, process)

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

    monkeypatch.setattr(github_attestation.threading, "Thread", ImmediateThread)

    with pytest.raises(GitHubAttestationError, match="reader exploded") as captured:
        _execute(tmp_path)

    assert isinstance(captured.value.__cause__, type(failure_factory()))
    assert cleanups == [process]


def test_worker_failure_stops_a_still_live_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ImmediateReadFailure(_TrackingStream):
        def read(self, _size: int = -1) -> bytes:
            raise ValueError("live reader exploded")

        read1 = read

    process = _FakeProcess(stdout=ImmediateReadFailure(), poll_result=None)
    cleanups = _install_process(monkeypatch, process)

    with pytest.raises(GitHubAttestationError, match="live reader exploded"):
        _execute(tmp_path)

    assert cleanups == [process]
    assert process.kill_calls == 1


def test_launch_uses_managed_group_and_preserves_exact_raw_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b" \n[ {\"opaque\":\"\xe2\x98\x83\"} ]\t"
    process = _FakeProcess(stdout=_TrackingStream(payload))
    _install_process(monkeypatch, process)
    observed: dict[str, object] = {}
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

        def join(self, timeout: float | None = None) -> None:
            assert timeout is not None
            assert timeout >= 0
            self.join_timeouts.append(timeout)

        def is_alive(self) -> bool:
            return False

    def fake_popen(_command: list[str], **kwargs: object) -> _FakeProcess:
        observed.update(kwargs)
        return process

    monkeypatch.setattr(github_attestation.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(github_attestation.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(
        github_attestation,
        "process_group_popen_kwargs",
        lambda: {"managed_group_marker": True},
    )

    assert _execute(tmp_path) == payload
    assert observed["managed_group_marker"] is True
    assert observed["shell"] is False
    assert observed["stdin"] is subprocess.DEVNULL
    assert len(readers) == 2
    assert all(len(reader.join_timeouts) == 1 for reader in readers)  # type: ignore[attr-defined]
    assert all(  # type: ignore[attr-defined]
        0 <= reader.join_timeouts[0]
        <= github_attestation._GITHUB_ATTESTATION_READER_JOIN_SECONDS
        for reader in readers
    )


@pytest.mark.parametrize("stream_name", ["stdout", "stderr"])
def test_stdout_and_stderr_limits_are_independent_and_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stream_name: str,
) -> None:
    monkeypatch.setattr(github_attestation, "MAX_GITHUB_ATTESTATION_OUTPUT_BYTES", 4)
    monkeypatch.setattr(github_attestation, "_GITHUB_ATTESTATION_STDERR_BYTES", 4)
    process = _FakeProcess(
        stdout=_TrackingStream(b"xxxxx" if stream_name == "stdout" else b"[{}]"),
        stderr=_TrackingStream(b"xxxxx" if stream_name == "stderr" else b""),
    )
    cleanups = _install_process(monkeypatch, process)

    with pytest.raises(GitHubAttestationError, match="bounded standard-output"):
        _execute(tmp_path)

    assert cleanups == [process]


def test_timeout_uses_tree_cleanup_and_independent_reader_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(poll_result=None)
    cleanups = _install_process(monkeypatch, process)

    with pytest.raises(GitHubAttestationError, match="exceeded 0 seconds"):
        _execute(tmp_path, timeout_seconds=0)

    assert cleanups == [process]
    assert process.kill_calls == 1


def test_windows_departed_root_preserves_original_failure_without_tree_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(poll_result=None)
    polls = iter([None, 0])
    cleanup_calls: list[object] = []

    def poll() -> int | None:
        result = next(polls, 0)
        if result is not None:
            process.returncode = result
        return result

    process.poll = poll  # type: ignore[method-assign]
    monkeypatch.setattr(
        github_attestation.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        github_attestation,
        "_terminate_gh_process_tree",
        lambda candidate: cleanup_calls.append(candidate) is not None,
    )
    monkeypatch.setattr(
        github_attestation,
        "os",
        SimpleNamespace(
            name="nt",
            environ=os.environ,
            path=os.path,
            makedirs=os.makedirs,
        ),
    )

    with pytest.raises(GitHubAttestationError, match="exceeded 0 seconds"):
        _execute(tmp_path, timeout_seconds=0)

    # The outer best-effort cleanup is attempted, but its failure does not
    # replace the triggering error or become a false Windows tree-proof claim.
    assert cleanup_calls == [process]


def test_windows_root_exit_during_cleanup_preserves_original_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(poll_result=None)
    poll_calls = 0
    cleanup_calls: list[object] = []

    def poll() -> int | None:
        nonlocal poll_calls
        poll_calls += 1
        if poll_calls <= 2:
            return None
        return process.returncode

    def raced_cleanup(candidate: object) -> bool:
        cleanup_calls.append(candidate)
        process.returncode = 0
        return False

    process.poll = poll  # type: ignore[method-assign]
    monkeypatch.setattr(
        github_attestation.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        github_attestation,
        "_terminate_gh_process_tree",
        raced_cleanup,
    )
    monkeypatch.setattr(
        github_attestation,
        "os",
        SimpleNamespace(
            name="nt",
            environ=os.environ,
            path=os.path,
            makedirs=os.makedirs,
        ),
    )

    with pytest.raises(GitHubAttestationError, match="exceeded 0 seconds"):
        _execute(tmp_path, timeout_seconds=0)

    assert cleanup_calls == [process, process]


def test_unproven_tree_cleanup_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(poll_result=None)
    calls: list[object] = []
    monkeypatch.setattr(
        github_attestation.subprocess,
        "Popen",
        lambda *_args, **_kwargs: process,
    )

    def cannot_prove(candidate: object, _limits: object) -> bool:
        calls.append(candidate)
        return False

    monkeypatch.setattr(github_attestation, "terminate_process_tree", cannot_prove)

    with pytest.raises(GitHubAttestationError, match="cleanup could not be proven"):
        _execute(tmp_path, timeout_seconds=0)

    assert calls == [process, process]


def test_posix_success_proves_post_completion_group_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess()
    cleanups = _install_process(monkeypatch, process)
    monkeypatch.setattr(
        github_attestation,
        "os",
        SimpleNamespace(
            name="posix",
            environ=os.environ,
            path=os.path,
            makedirs=os.makedirs,
        ),
    )

    assert _execute(tmp_path) == b"[{}]"
    assert cleanups == [process]


@pytest.mark.parametrize("cleanup_raises", [False, True])
def test_post_poll_wait_baseexception_remains_authoritative(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cleanup_raises: bool,
) -> None:
    primary = _PrimaryAbort("post-poll cancellation")
    process = _FakeProcess(wait_actions=[primary])
    _install_process(monkeypatch, process)
    if cleanup_raises:
        monkeypatch.setattr(
            github_attestation,
            "_terminate_gh_process_tree",
            lambda _process: (_ for _ in ()).throw(_CleanupAbort("cleanup failed")),
        )

    with pytest.raises(_PrimaryAbort) as captured:
        _execute(tmp_path)

    assert captured.value is primary


def test_poll_baseexception_cleans_child_and_remains_authoritative(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = _PrimaryAbort("poll cancellation")
    process = _FakeProcess(poll_result=None)
    cleanups = _install_process(monkeypatch, process)

    def fail_poll() -> int | None:
        raise primary

    process.poll = fail_poll  # type: ignore[method-assign]

    with pytest.raises(_PrimaryAbort) as captured:
        _execute(tmp_path)

    assert captured.value is primary
    assert cleanups == [process]


@pytest.mark.parametrize(
    "failure_factory",
    [
        pytest.param(lambda: OSError("close failed"), id="oserror"),
        pytest.param(lambda: ValueError("close failed"), id="valueerror"),
    ],
)
def test_stream_close_failure_cannot_be_a_successful_cleanup_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_factory: Callable[[], BaseException],
) -> None:
    class CloseFailureStream(_TrackingStream):
        def close(self) -> None:
            self.close_calls += 1
            raise failure_factory()

    process = _FakeProcess(stdout=CloseFailureStream(b"[{}]"))
    _install_process(monkeypatch, process)

    with pytest.raises(GitHubAttestationError, match="left output pipes open"):
        _execute(tmp_path)


def test_stream_close_baseexception_remains_authoritative(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = _PrimaryAbort("close cancellation")

    class CloseAbortStream(_TrackingStream):
        def close(self) -> None:
            self.close_calls += 1
            raise primary

    stdout = CloseAbortStream(b"[{}]")
    process = _FakeProcess(stdout=stdout)
    _install_process(monkeypatch, process)

    with pytest.raises(_PrimaryAbort) as captured:
        _execute(tmp_path)

    assert captured.value is primary


def test_process_poll_wait_is_bounded_and_wakes_for_recheck(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess()
    _install_process(monkeypatch, process)
    polls = iter([None, 0])
    waits: list[float] = []

    def poll() -> int | None:
        result = next(polls, 0)
        if result is not None:
            process.returncode = result
        return result

    class ControlledEvent:
        def set(self) -> None:
            pass

        def wait(self, timeout: float | None = None) -> bool:
            assert timeout is not None
            waits.append(timeout)
            return False

    process.poll = poll  # type: ignore[method-assign]
    real_thread = github_attestation.threading.Thread
    monkeypatch.setattr(
        github_attestation,
        "threading",
        SimpleNamespace(Event=ControlledEvent, Thread=real_thread),
    )

    assert _execute(tmp_path) == b"[{}]"
    assert len(waits) == 1
    assert 0 < waits[0] <= github_attestation._GITHUB_ATTESTATION_PROCESS_POLL_SECONDS


def test_reader_joins_share_one_total_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = 0.0
    timeouts: list[float] = []

    def monotonic() -> float:
        return now

    class BudgetReader:
        def join(self, timeout: float) -> None:
            nonlocal now
            timeouts.append(timeout)
            now += 1.25

        def is_alive(self) -> bool:
            return False

    monkeypatch.setattr(
        github_attestation,
        "time",
        SimpleNamespace(monotonic=monotonic),
    )
    streams = [_TrackingStream(), _TrackingStream()]

    assert github_attestation._join_and_close_gh_readers(
        [BudgetReader(), BudgetReader()],  # type: ignore[list-item]
        streams,
    )
    assert timeouts == pytest.approx([2.0, 0.75])


def test_reader_join_baseexception_remains_authoritative_and_stream_stays_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = _PrimaryAbort("join cancellation")
    stdout = _TrackingStream(b"[{}]")
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

    monkeypatch.setattr(github_attestation.threading, "Thread", JoinFailureThread)

    with pytest.raises(_PrimaryAbort) as captured:
        _execute(tmp_path)

    assert captured.value is primary
    assert stdout.close_calls == 0


def test_live_reader_stream_is_never_closed_synchronously(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout = _TrackingStream(b"[{}]")
    stderr = _TrackingStream()
    process = _FakeProcess(stdout=stdout, stderr=stderr)
    _install_process(monkeypatch, process)
    created: list[object] = []
    monkeypatch.setattr(github_attestation, "_GITHUB_ATTESTATION_READER_JOIN_SECONDS", 0.01)

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

    monkeypatch.setattr(github_attestation.threading, "Thread", LiveThread)

    with pytest.raises(GitHubAttestationError, match="left output pipes open"):
        _execute(tmp_path)

    assert stdout.close_calls == 0
    assert stderr.close_calls == 0
    assert all(len(reader.join_timeouts) == 2 for reader in created)  # type: ignore[attr-defined]


def test_cleanup_baseexceptions_do_not_replace_reader_start_primary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess()
    _install_process(monkeypatch, process)
    monkeypatch.setattr(
        github_attestation,
        "_terminate_gh_process_tree",
        lambda _process: (_ for _ in ()).throw(_CleanupAbort("cleanup failed")),
    )

    class FailingThread:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def start(self) -> None:
            raise _PrimaryAbort("authoritative primary")

        def join(self, _timeout: float) -> None:
            raise _CleanupAbort("join cleanup failed")

        def is_alive(self) -> bool:
            return True

    monkeypatch.setattr(github_attestation.threading, "Thread", FailingThread)

    with pytest.raises(_PrimaryAbort, match="authoritative primary"):
        _execute(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups")
def test_real_posix_cleanup_stops_inherited_pipe_descendant(
    tmp_path: Path,
) -> None:
    ready = tmp_path / "gh-descendant-ready"
    survived = tmp_path / "gh-descendant-survived"
    process_group = tmp_path / "gh-process-group"
    child = (
        "import signal, sys, time; from pathlib import Path; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "Path(sys.argv[1]).write_text('ready'); time.sleep(10); "
        "Path(sys.argv[2]).write_text('survived')"
    )
    parent = (
        "import os, subprocess, sys, time; from pathlib import Path; "
        "Path(sys.argv[3]).write_text(str(os.getpgrp())); "
        "subprocess.Popen([sys.executable, '-c', sys.argv[4], "
        "sys.argv[1], sys.argv[2]]); "
        "deadline=time.monotonic()+3; "
        "\nwhile not Path(sys.argv[1]).exists() and "
        "time.monotonic()<deadline: time.sleep(0.01); "
        "\nsys.stdout.buffer.write(b'[{}]'); sys.stdout.flush(); "
        "raise SystemExit(0 if Path(sys.argv[1]).exists() else 2)"
    )
    command = [
        sys.executable,
        "-c",
        parent,
        str(ready),
        str(survived),
        str(process_group),
        child,
    ]

    assert github_attestation._execute_gh_attestation_command(
        command,
        gh_executable=sys.executable,
        timeout_seconds=5,
        directory=str(tmp_path),
    ) == b"[{}]"
    assert ready.exists()
    group_id = int(process_group.read_text(encoding="utf-8"))
    with pytest.raises(ProcessLookupError):
        os.killpg(group_id, 0)
    assert not survived.exists()
