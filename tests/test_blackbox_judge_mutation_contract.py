"""Deterministic contracts for black-box judge lifecycle mutations."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

import evoom_guard.blackbox as blackbox_module


class _FakePipe:
    def __init__(self) -> None:
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


class _FakeProcess:
    pid = 4242

    def __init__(self, poll_results: list[int | None]) -> None:
        if not poll_results:
            raise ValueError("poll_results must not be empty")
        self.stdout = _FakePipe()
        self.stderr = _FakePipe()
        self.returncode = poll_results[-1]
        self._poll_results = list(poll_results)
        self.poll_calls = 0

    def poll(self) -> int | None:
        self.poll_calls += 1
        if len(self._poll_results) > 1:
            return self._poll_results.pop(0)
        result = self._poll_results[0]
        self.returncode = result
        return result


class _NoopReader:
    ident = 1

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self.start_calls = 0

    def start(self) -> None:
        self.start_calls += 1


class _NeverExceededCapture:
    instance: _NeverExceededCapture | None = None

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.finished_over_limit = False
        type(self).instance = self

    @property
    def exceeded(self) -> bool:
        return self.finished_over_limit

    def text(self, _stream: str) -> str:
        return ""


class _AlwaysExceededCapture(_NeverExceededCapture):
    @property
    def exceeded(self) -> bool:
        return True


def _install_judge_harness(
    monkeypatch: pytest.MonkeyPatch,
    process: _FakeProcess,
    capture_type: type[_NeverExceededCapture],
    *,
    observed_popen: dict[str, Any] | None = None,
) -> None:
    def popen(_command: list[str], **kwargs: Any) -> _FakeProcess:
        if observed_popen is not None:
            observed_popen.update(kwargs)
        return process

    monkeypatch.setattr(blackbox_module.subprocess, "Popen", popen)
    monkeypatch.setattr(blackbox_module.threading, "Thread", _NoopReader)
    monkeypatch.setattr(blackbox_module, "_BoundedOutput", capture_type)
    monkeypatch.setattr(blackbox_module.time, "sleep", lambda _seconds: None)


def _monotonic(values: list[float | BaseException]) -> Callable[[], float]:
    remaining = iter(values)

    def read() -> float:
        value = next(remaining)
        if isinstance(value, BaseException):
            raise value
        return value

    return read


def test_judge_popen_starts_a_dedicated_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess([0])
    observed: dict[str, Any] = {}
    cleanup_calls: list[_FakeProcess] = []
    _install_judge_harness(
        monkeypatch,
        process,
        _NeverExceededCapture,
        observed_popen=observed,
    )
    monkeypatch.setattr(
        blackbox_module,
        "_join_judge_pipe_readers",
        lambda *_args: True,
    )
    monkeypatch.setattr(
        blackbox_module,
        "_terminate_judge_process_group",
        lambda candidate: cleanup_calls.append(candidate),
    )

    completed = blackbox_module._run_judge_process(
        ["pytest"], cwd="/judge", env={}, timeout=1
    )

    assert completed.returncode == 0
    assert observed["start_new_session"] is True
    assert cleanup_calls == [process]


def test_judge_timeout_is_not_bypassed_before_process_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess([None, 0])
    cleanup_calls: list[_FakeProcess] = []
    _install_judge_harness(monkeypatch, process, _NeverExceededCapture)
    monkeypatch.setattr(
        blackbox_module.time,
        "monotonic",
        _monotonic([0.0, 1.0]),
    )
    monkeypatch.setattr(
        blackbox_module,
        "_join_judge_pipe_readers",
        lambda *_args: True,
    )
    monkeypatch.setattr(
        blackbox_module,
        "_terminate_judge_process_group",
        lambda candidate: cleanup_calls.append(candidate),
    )

    with pytest.raises(blackbox_module.subprocess.TimeoutExpired):
        blackbox_module._run_judge_process(
            ["pytest"], cwd="/judge", env={}, timeout=0
        )

    assert cleanup_calls


def test_completed_judge_still_proves_process_group_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess([0])
    cleanup_calls: list[_FakeProcess] = []
    _install_judge_harness(monkeypatch, process, _NeverExceededCapture)
    monkeypatch.setattr(
        blackbox_module,
        "_join_judge_pipe_readers",
        lambda *_args: True,
    )
    monkeypatch.setattr(
        blackbox_module,
        "_terminate_judge_process_group",
        lambda candidate: cleanup_calls.append(candidate),
    )

    completed = blackbox_module._run_judge_process(
        ["pytest"], cwd="/judge", env={}, timeout=1
    )

    assert completed.returncode == 0
    assert cleanup_calls == [process]


def test_live_output_checkpoint_runs_before_the_next_poll(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess([None, 0])
    _install_judge_harness(monkeypatch, process, _AlwaysExceededCapture)
    monkeypatch.setattr(blackbox_module.time, "monotonic", lambda: 0.0)
    monkeypatch.setattr(
        blackbox_module,
        "_join_judge_pipe_readers",
        lambda *_args: True,
    )
    monkeypatch.setattr(
        blackbox_module,
        "_terminate_judge_process_group",
        lambda _process: None,
    )

    with pytest.raises(blackbox_module.JudgeOutputLimitError):
        blackbox_module._run_judge_process(
            ["pytest"], cwd="/judge", env={}, timeout=1
        )

    assert process.poll_calls == 1


def test_post_poll_output_checkpoint_precedes_normal_reader_join(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess([0])
    events: list[str] = []
    _install_judge_harness(monkeypatch, process, _AlwaysExceededCapture)
    monkeypatch.setattr(
        blackbox_module,
        "_join_judge_pipe_readers",
        lambda *_args: events.append("join") or True,
    )
    monkeypatch.setattr(
        blackbox_module,
        "_terminate_judge_process_group",
        lambda _process: events.append("terminate"),
    )

    with pytest.raises(blackbox_module.JudgeOutputLimitError):
        blackbox_module._run_judge_process(
            ["pytest"], cwd="/judge", env={}, timeout=1
        )

    assert events[0] == "terminate"


def test_post_join_output_checkpoint_cannot_return_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess([0])
    _install_judge_harness(monkeypatch, process, _NeverExceededCapture)
    monkeypatch.setattr(
        blackbox_module,
        "_terminate_judge_process_group",
        lambda _process: None,
    )

    def finish_readers(*_args: Any) -> bool:
        assert _NeverExceededCapture.instance is not None
        _NeverExceededCapture.instance.finished_over_limit = True
        return True

    monkeypatch.setattr(
        blackbox_module,
        "_join_judge_pipe_readers",
        finish_readers,
    )

    with pytest.raises(blackbox_module.JudgeOutputLimitError):
        blackbox_module._run_judge_process(
            ["pytest"], cwd="/judge", env={}, timeout=1
        )


def test_reader_join_failure_cannot_be_returned_as_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess([0])
    join_results = iter([False, True, True])
    _install_judge_harness(monkeypatch, process, _NeverExceededCapture)
    monkeypatch.setattr(
        blackbox_module,
        "_terminate_judge_process_group",
        lambda _process: None,
    )
    monkeypatch.setattr(
        blackbox_module,
        "_join_judge_pipe_readers",
        lambda *_args: next(join_results, True),
    )

    with pytest.raises(
        blackbox_module.JudgeProcessCleanupError,
        match="judge exited but its output pipes did not close",
    ):
        blackbox_module._run_judge_process(
            ["pytest"], cwd="/judge", env={}, timeout=1
        )


def test_runtime_baseexception_remains_primary_after_cleanup_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary = KeyboardInterrupt("stop judge")
    process = _FakeProcess([None])
    _install_judge_harness(monkeypatch, process, _NeverExceededCapture)
    monkeypatch.setattr(
        blackbox_module.time,
        "monotonic",
        _monotonic([0.0, primary]),
    )
    monkeypatch.setattr(
        blackbox_module,
        "_terminate_judge_process_group",
        lambda _process: (_ for _ in ()).throw(SystemExit("cleanup failed")),
    )
    monkeypatch.setattr(
        blackbox_module,
        "_join_judge_pipe_readers",
        lambda *_args: (_ for _ in ()).throw(GeneratorExit("join failed")),
    )

    with pytest.raises(KeyboardInterrupt) as exc:
        blackbox_module._run_judge_process(
            ["pytest"], cwd="/judge", env={}, timeout=1
        )

    assert exc.value is primary
