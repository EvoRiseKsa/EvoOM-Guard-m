"""Direct contracts for the typed black-box judge execution kernel."""

from __future__ import annotations

import math
from collections.abc import Callable

import pytest

import evoom_guard.execution as execution_api
import evoom_guard.execution.judge as judge_module


class _Pipe:
    def __init__(self, label: str) -> None:
        self.label = label
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


class _Process:
    pid = 7319

    def __init__(self, poll_results: list[int | None]) -> None:
        self.stdout = _Pipe("stdout")
        self.stderr = _Pipe("stderr")
        self.returncode: int | None = None
        self._poll_results = list(poll_results)
        self.poll_calls = 0

    def poll(self) -> int | None:
        self.poll_calls += 1
        if not self._poll_results:
            return self.returncode
        result = self._poll_results.pop(0)
        if result is not None:
            self.returncode = result
        return result


class _Reader:
    created: list[_Reader] = []

    def __init__(
        self,
        *,
        target: Callable[..., object],
        args: tuple[object, ...],
        daemon: bool,
    ) -> None:
        self.target = target
        self.args = args
        self.daemon = daemon
        self.start_calls = 0
        self.join_calls: list[float | None] = []
        type(self).created.append(self)

    def start(self) -> None:
        self.start_calls += 1

    def join(self, timeout: float | None = None) -> None:
        self.join_calls.append(timeout)

    def is_alive(self) -> bool:
        return False


class _Capture:
    created: list[_Capture] = []

    def __init__(self, limit: int) -> None:
        self.limit = limit
        type(self).created.append(self)

    @property
    def exceeded(self) -> bool:
        return False

    def text(self, stream: str) -> str:
        return f"captured-{stream}"


def test_execute_resolves_runtime_globals_at_call_time_and_preserves_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = ["judge-python", "-m", "pytest"]
    environment = {"SAFE": "1"}
    process = _Process([None, 7])
    popen_calls: list[tuple[object, object]] = []
    join_calls: list[tuple[list[object], list[object]]] = []
    terminate_calls: list[tuple[_Process, judge_module.JudgeProcessLimits]] = []
    monotonic_calls: list[float] = []
    sleep_calls: list[float] = []

    _Reader.created.clear()
    _Capture.created.clear()

    def drain_sentinel(*_args: object) -> None:
        return None

    def popen(candidate: object, **kwargs: object) -> _Process:
        popen_calls.append((candidate, kwargs["env"]))
        return process

    def join(readers: list[object], streams: list[object]) -> bool:
        join_calls.append((list(readers), list(streams)))
        return True

    def terminate(
        candidate: _Process,
        *,
        limits: judge_module.JudgeProcessLimits,
    ) -> None:
        terminate_calls.append((candidate, limits))

    def monotonic() -> float:
        monotonic_calls.append(10.0)
        return 10.0

    monkeypatch.setattr(judge_module.subprocess, "Popen", popen)
    monkeypatch.setattr(judge_module.threading, "Thread", _Reader)
    monkeypatch.setattr(judge_module.os, "name", "posix")
    monkeypatch.setattr(judge_module.os, "killpg", lambda *_args: None, raising=False)
    monkeypatch.setattr(judge_module, "BoundedOutput", _Capture)
    monkeypatch.setattr(judge_module, "drain_process_pipe", drain_sentinel)
    monkeypatch.setattr(judge_module, "join_judge_pipe_readers", join)
    monkeypatch.setattr(judge_module, "terminate_judge_process_group", terminate)
    monkeypatch.setattr(judge_module.time, "monotonic", monotonic)
    monkeypatch.setattr(
        judge_module.time,
        "sleep",
        lambda seconds: sleep_calls.append(seconds),
    )

    limits = judge_module.JudgeProcessLimits(
        max_output_bytes=313,
        termination_grace_seconds=0.5,
        group_poll_seconds=0.125,
        sigkill=99,
    )
    request = judge_module.JudgeProcessRequest(
        command=command,
        cwd="/judge",
        env=environment,
        timeout_seconds=1,
        limits=limits,
    )

    result = judge_module.execute_judge_process(request)
    completed = result.as_completed_process()

    assert popen_calls == [(command, environment)]
    assert popen_calls[0][0] is command
    assert popen_calls[0][1] is environment
    assert len(_Capture.created) == 1
    assert _Capture.created[0].limit == 313
    assert [reader.target for reader in _Reader.created] == [
        drain_sentinel,
        drain_sentinel,
    ]
    assert [reader.start_calls for reader in _Reader.created] == [1, 1]
    assert join_calls == [
        (_Reader.created, [process.stdout, process.stderr]),
        (_Reader.created, [process.stdout, process.stderr]),
    ]
    assert terminate_calls == [(process, limits)]
    assert monotonic_calls == [10.0, 10.0]
    assert sleep_calls == [0.125]
    assert result.command is command
    assert completed.args is command
    assert completed.returncode == 7
    assert completed.stdout == "captured-stdout"
    assert completed.stderr == "captured-stderr"


def test_wait_helper_resolves_monkeypatched_globals_at_call_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _Process([None, 0])
    probes = iter((True, False))
    probe_calls: list[int] = []
    sleep_calls: list[float] = []
    monotonic_calls: list[float] = []

    def group_exists(process_group: int) -> bool:
        probe_calls.append(process_group)
        return next(probes)

    def monotonic() -> float:
        monotonic_calls.append(20.0)
        return 20.0

    monkeypatch.setattr(judge_module, "judge_process_group_exists", group_exists)
    monkeypatch.setattr(judge_module, "DEFAULT_JUDGE_GROUP_POLL_SECONDS", 0.375)
    monkeypatch.setattr(judge_module.time, "monotonic", monotonic)
    monkeypatch.setattr(
        judge_module.time,
        "sleep",
        lambda seconds: sleep_calls.append(seconds),
    )

    assert judge_module.wait_for_judge_process_group_exit(
        process,
        process.pid,
        1.0,
    ) is True
    assert probe_calls == [process.pid, process.pid]
    assert process.poll_calls == 2
    assert monotonic_calls == [20.0, 20.0, 20.0]
    assert sleep_calls == [0.375]


def test_join_helper_resolves_monkeypatched_generic_joiner_at_call_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = object()
    stream = _Pipe("stdout")
    calls: list[tuple[list[object], list[object]]] = []

    def join(readers: list[object], streams: list[object]) -> bool:
        calls.append((readers, streams))
        return True

    monkeypatch.setattr(judge_module, "join_pipe_readers", join)

    assert judge_module.join_judge_pipe_readers([reader], [stream]) is True  # type: ignore[list-item]
    assert calls == [([reader], [])]
    assert stream.close_calls == 1


def test_termination_helpers_resolve_monkeypatched_defaults_at_call_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _Process([None])
    events: list[tuple[str, object]] = []

    monkeypatch.setattr(judge_module.os, "name", "posix")
    monkeypatch.setattr(judge_module.os, "killpg", lambda *_args: None, raising=False)
    monkeypatch.setattr(
        judge_module,
        "judge_process_group_exists",
        lambda process_group: events.append(("probe", process_group)) or True,
    )
    monkeypatch.setattr(
        judge_module,
        "signal_judge_process_group",
        lambda candidate, sig: events.append(("signal", (candidate, sig))),
    )
    monkeypatch.setattr(
        judge_module,
        "wait_for_judge_process_group_exit",
        lambda candidate, process_group, timeout, **_kwargs: (
            events.append(("wait", (candidate, process_group, timeout))) or True
        ),
    )
    monkeypatch.setattr(
        judge_module,
        "reap_judge_leader",
        lambda candidate, **_kwargs: events.append(("reap", candidate)),
    )

    limits = judge_module.JudgeProcessLimits(termination_grace_seconds=0.75)
    judge_module.terminate_judge_process_group(process, limits=limits)  # type: ignore[arg-type]

    assert events == [
        ("probe", process.pid),
        ("signal", (process, int(judge_module.signal.SIGTERM))),
        ("wait", (process, process.pid, 0.75)),
        ("reap", process),
    ]


def test_execution_package_exports_exact_judge_error_identities() -> None:
    assert execution_api.JudgeProcessCleanupError is judge_module.JudgeProcessCleanupError
    assert execution_api.JudgeOutputLimitError is judge_module.JudgeOutputLimitError
    assert "JudgeProcessCleanupError" in execution_api.__all__
    assert "JudgeOutputLimitError" in execution_api.__all__


@pytest.mark.parametrize(
    ("os_name", "killpg"),
    [("nt", lambda *_args: None), ("posix", None)],
)
def test_default_direct_executor_rejects_missing_group_proof_before_launch(
    monkeypatch: pytest.MonkeyPatch,
    os_name: str,
    killpg: object,
) -> None:
    launched = False
    process = _Process([0])

    def popen(*_args: object, **_kwargs: object) -> _Process:
        nonlocal launched
        launched = True
        return process

    monkeypatch.setattr(judge_module.os, "name", os_name)
    monkeypatch.setattr(judge_module.os, "killpg", killpg, raising=False)
    monkeypatch.setattr(judge_module.subprocess, "Popen", popen)
    monkeypatch.setattr(judge_module.threading, "Thread", _Reader)
    monkeypatch.setattr(judge_module, "BoundedOutput", _Capture)
    monkeypatch.setattr(judge_module, "drain_process_pipe", lambda *_args: None)
    monkeypatch.setattr(
        judge_module,
        "join_judge_pipe_readers",
        lambda *_args: True,
    )
    request = judge_module.JudgeProcessRequest(
        command=["judge"],
        cwd="/judge",
        env={},
        timeout_seconds=1,
    )

    with pytest.raises(
        judge_module.JudgeProcessCleanupError,
        match="requires POSIX process-group cleanup",
    ):
        judge_module.execute_judge_process(request)

    assert launched is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_output_bytes", -1),
        ("max_output_bytes", True),
        ("termination_grace_seconds", -1.0),
        ("termination_grace_seconds", math.nan),
        ("termination_grace_seconds", math.inf),
        ("group_poll_seconds", -1.0),
        ("group_poll_seconds", 0.0),
        ("group_poll_seconds", math.nan),
        ("group_poll_seconds", math.inf),
        ("sigkill", 0),
        ("sigkill", True),
    ],
)
def test_judge_limits_reject_unbounded_values(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        judge_module.JudgeProcessLimits(**{field: value})  # type: ignore[arg-type]


@pytest.mark.parametrize("timeout", [-1, True, 1.0, math.nan, math.inf])
def test_judge_request_rejects_invalid_timeout_before_launch(timeout: object) -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        judge_module.JudgeProcessRequest(
            command=["judge"],
            cwd="/judge",
            env={},
            timeout_seconds=timeout,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("limits", [None, object()])
def test_judge_request_rejects_unvalidated_limits_before_launch(
    limits: object,
) -> None:
    with pytest.raises(ValueError, match="JudgeProcessLimits"):
        judge_module.JudgeProcessRequest(
            command=["judge"],
            cwd="/judge",
            env={},
            timeout_seconds=1,
            limits=limits,  # type: ignore[arg-type]
        )
