"""Focused, self-terminating contracts for the security mutation gate."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import evoom_guard.execution.process as process_module
from evoom_guard.execution import (
    BoundedOutput,
    BoundedProcessRequest,
    ProcessContainmentError,
    ProcessLimits,
    ProcessOutputLimitExceeded,
    execute_bounded_process,
)


class _FakePipe:
    def close(self) -> None:
        return None


class _FakeProcess:
    pid = 4242

    def __init__(self, poll_result: int | None) -> None:
        self.stdout = _FakePipe()
        self.stderr = _FakePipe()
        self.returncode = poll_result
        self._poll_result = poll_result

    def poll(self) -> int | None:
        return self._poll_result

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self.returncode = 0
        self._poll_result = 0
        return 0

    def kill(self) -> None:
        self.returncode = -1
        self._poll_result = -1


class _NoopThread:
    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def start(self) -> None:
        return None

    def join(self, _timeout: float | None = None) -> None:
        return None

    def is_alive(self) -> bool:
        return False


class _AlwaysExceededCapture:
    def __init__(self, _limit: int) -> None:
        pass

    @property
    def exceeded(self) -> bool:
        return True

    def text(self, _stream: str) -> str:
        return ""


class _NeverExceededCapture:
    def __init__(self, _limit: int) -> None:
        pass

    @property
    def exceeded(self) -> bool:
        return False

    def text(self, _stream: str) -> str:
        return ""


def _fake_request(*, timeout: float = 1.0) -> BoundedProcessRequest:
    return BoundedProcessRequest.from_command(
        ["self-terminating-fake"],
        cwd=None,
        env=None,
        timeout=timeout,
        limits=ProcessLimits(max_output_bytes=4),
    )


def _install_fake_launcher(
    monkeypatch: pytest.MonkeyPatch,
    process: _FakeProcess,
    capture_type: type,
    *,
    observed_kwargs: dict[str, Any] | None = None,
) -> None:
    def fake_popen(_command: list[str], **kwargs: Any) -> _FakeProcess:
        if observed_kwargs is not None:
            observed_kwargs.update(kwargs)
        return process

    monkeypatch.setattr(process_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(process_module, "threading", SimpleNamespace(Thread=_NoopThread))
    monkeypatch.setattr(process_module, "BoundedOutput", capture_type)


def test_bounded_output_marks_any_truncated_bytes_as_exceeded() -> None:
    capture = BoundedOutput(limit=4)

    capture.append("stdout", b"12345")

    assert capture.exceeded is True
    assert capture.text("stdout") == "1234"


def test_live_output_overflow_is_stopped_before_process_completion(
    tmp_path: Path,
) -> None:
    """The live-loop check must stop a flooder before its delayed side effect."""

    marker = tmp_path / "process-completed"
    request = BoundedProcessRequest.from_command(
        [
            sys.executable,
            "-c",
            (
                "from pathlib import Path; import sys, time; "
                "sys.stdout.buffer.write(b'x' * 65536); sys.stdout.flush(); "
                "time.sleep(0.75); Path(sys.argv[1]).write_text('completed')"
            ),
            str(marker),
        ],
        cwd=str(tmp_path),
        env=os.environ.copy(),
        timeout=3,
        limits=ProcessLimits(
            max_output_bytes=128,
            termination_grace_seconds=0.2,
            kill_grace_seconds=2,
            reader_join_seconds=1,
        ),
    )

    with pytest.raises(ProcessOutputLimitExceeded):
        execute_bounded_process(request)

    assert not marker.exists()


def test_post_poll_overflow_stops_before_normal_reader_join(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fast process observed after exit must not enter the normal join path."""

    events: list[str] = []
    process = _FakeProcess(poll_result=0)
    _install_fake_launcher(monkeypatch, process, _AlwaysExceededCapture)
    monkeypatch.setattr(process_module, "process_group_popen_kwargs", lambda: {})
    monkeypatch.setattr(
        process_module,
        "_terminate_process_tree",
        lambda *_args: events.append("terminate") or True,
    )
    monkeypatch.setattr(
        process_module,
        "join_pipe_readers",
        lambda *_args: events.append("join") or True,
    )

    with pytest.raises(ProcessOutputLimitExceeded):
        execute_bounded_process(_fake_request())

    assert events == ["terminate", "join"]


def test_post_join_overflow_is_not_returned_as_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bytes detected while readers finish must still invalidate the result."""

    class CaptureAfterJoin(_NeverExceededCapture):
        instance: CaptureAfterJoin | None = None

        def __init__(self, limit: int) -> None:
            super().__init__(limit)
            self.finished_over_limit = False
            type(self).instance = self

        @property
        def exceeded(self) -> bool:
            return self.finished_over_limit

    process = _FakeProcess(poll_result=0)
    _install_fake_launcher(monkeypatch, process, CaptureAfterJoin)
    monkeypatch.setattr(process_module, "process_group_popen_kwargs", lambda: {})
    monkeypatch.setattr(process_module, "_terminate_process_tree", lambda *_args: True)

    def finish_readers(*_args: Any) -> bool:
        assert CaptureAfterJoin.instance is not None
        CaptureAfterJoin.instance.finished_over_limit = True
        return True

    monkeypatch.setattr(process_module, "join_pipe_readers", finish_readers)

    with pytest.raises(ProcessOutputLimitExceeded):
        execute_bounded_process(_fake_request())


def test_deadline_interrupts_a_self_terminating_process(tmp_path: Path) -> None:
    """The mutant can finish by itself, so an outer timeout is never a kill."""

    request = BoundedProcessRequest.from_command(
        [sys.executable, "-c", "import time; time.sleep(0.6)"],
        cwd=str(tmp_path),
        env=os.environ.copy(),
        timeout=0.05,
    )

    with pytest.raises(subprocess.TimeoutExpired):
        execute_bounded_process(request)


def test_cleanup_failure_preempts_the_triggering_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unproved cleanup must be authoritative, not hidden as overflow."""

    process = _FakeProcess(poll_result=None)
    _install_fake_launcher(monkeypatch, process, _AlwaysExceededCapture)
    monkeypatch.setattr(process_module, "process_group_popen_kwargs", lambda: {})
    monkeypatch.setattr(process_module, "_terminate_process_tree", lambda *_args: False)
    monkeypatch.setattr(process_module, "join_pipe_readers", lambda *_args: True)

    with pytest.raises(ProcessContainmentError, match="could not prove"):
        execute_bounded_process(_fake_request())


def test_execute_passes_the_process_group_contract_to_popen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The launcher must consume, not merely define, its containment kwargs."""

    observed: dict[str, Any] = {}
    process = _FakeProcess(poll_result=0)
    _install_fake_launcher(
        monkeypatch,
        process,
        _NeverExceededCapture,
        observed_kwargs=observed,
    )
    monkeypatch.setattr(
        process_module,
        "process_group_popen_kwargs",
        lambda: {"start_new_session": True},
    )
    monkeypatch.setattr(process_module, "join_pipe_readers", lambda *_args: True)
    monkeypatch.setattr(process_module, "_terminate_process_tree", lambda *_args: True)

    execute_bounded_process(_fake_request())

    assert observed["start_new_session"] is True


def test_posix_process_group_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_module, "os", SimpleNamespace(name="posix"))

    assert process_module.process_group_popen_kwargs() == {"start_new_session": True}


def test_windows_process_group_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    expected_flag = 0x00000200
    monkeypatch.setattr(process_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        process_module.subprocess,
        "CREATE_NEW_PROCESS_GROUP",
        expected_flag,
        raising=False,
    )

    assert process_module.process_group_popen_kwargs() == {
        "creationflags": expected_flag
    }
