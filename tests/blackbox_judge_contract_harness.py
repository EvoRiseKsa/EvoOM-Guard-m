"""Deterministic characterization seam for black-box judge process extraction."""

from __future__ import annotations

import inspect
import json
import signal
import subprocess
from contextlib import ExitStack
from typing import Any
from unittest.mock import patch

import evoom_guard.blackbox as blackbox_module

SCHEMA_VERSION = "blackbox-judge-process-contract-v1"

REQUIRED_PATCH_SEAMS = (
    "subprocess.Popen",
    "threading.Thread",
    "time.monotonic",
    "time.sleep",
    "_BoundedOutput",
    "_drain_subprocess_pipe",
    "_join_pipe_readers",
    "_join_judge_pipe_readers",
    "_terminate_judge_process_group",
    "_process_group_exists",
    "_signal_judge_process_group",
    "_wait_for_process_group_exit",
    "_reap_judge_leader",
    "_MAX_SUBPROCESS_OUTPUT_BYTES",
    "_JUDGE_TERMINATION_GRACE_SECONDS",
    "_JUDGE_GROUP_POLL_SECONDS",
    "_SIGKILL",
)


class _Pipe:
    def __init__(self, label: str) -> None:
        self.label = label
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


class _CompletedJudgeProcess:
    pid = 4321

    def __init__(self) -> None:
        self.returncode: int | None = None
        self.stdout = _Pipe("stdout")
        self.stderr = _Pipe("stderr")
        self.poll_calls = 0

    def poll(self) -> int | None:
        self.poll_calls += 1
        if self.poll_calls == 1:
            return None
        self.returncode = 7
        return self.returncode


class _Capture:
    limit = 321
    exceeded = False

    def text(self, stream: str) -> str:
        return f"captured-{stream}"


class _Reader:
    def __init__(self, *, target: object, args: tuple[object, ...], daemon: bool) -> None:
        self.target = target
        self.args = args
        self.daemon = daemon
        self.start_calls = 0

    def start(self) -> None:
        self.start_calls += 1


class _GroupProcess:
    pid = 4321


class _JoinReader:
    pass


def _parameter_contract(function: object) -> dict[str, object]:
    signature = inspect.signature(function)  # type: ignore[arg-type]
    return_annotation = signature.return_annotation
    return {
        "parameters": [
            {
                "name": parameter.name,
                "kind": parameter.kind.name,
                "default": (
                    "<REQUIRED>"
                    if parameter.default is inspect.Parameter.empty
                    else repr(parameter.default)
                ),
                "annotation": (
                    "<EMPTY>"
                    if parameter.annotation is inspect.Parameter.empty
                    else str(parameter.annotation)
                ),
            }
            for parameter in signature.parameters.values()
        ],
        "return_annotation": (
            "<EMPTY>"
            if return_annotation is inspect.Signature.empty
            else str(return_annotation)
        ),
    }


def _resolve_patch_seam(path: str) -> object:
    value: object = blackbox_module
    for component in path.split("."):
        value = getattr(value, component)
    return value


def capture_static_contract() -> dict[str, object]:
    cleanup_error = blackbox_module.JudgeProcessCleanupError("cleanup sentinel")
    output_error = blackbox_module.JudgeOutputLimitError(4096)
    return {
        "signatures": {
            name: _parameter_contract(getattr(blackbox_module, name))
            for name in (
                "_run_judge_process",
                "_terminate_judge_process_group",
                "_join_judge_pipe_readers",
            )
        },
        "constants": {
            "_MAX_SUBPROCESS_OUTPUT_BYTES": (
                blackbox_module._MAX_SUBPROCESS_OUTPUT_BYTES
            ),
            "_JUDGE_TERMINATION_GRACE_SECONDS": (
                blackbox_module._JUDGE_TERMINATION_GRACE_SECONDS
            ),
            "_JUDGE_GROUP_POLL_SECONDS": blackbox_module._JUDGE_GROUP_POLL_SECONDS,
            "_SIGKILL": blackbox_module._SIGKILL,
        },
        "errors": {
            "JudgeProcessCleanupError": {
                "base": blackbox_module.JudgeProcessCleanupError.__bases__[0].__name__,
                "args": list(cleanup_error.args),
                "fields": dict(cleanup_error.__dict__),
                "message": str(cleanup_error),
            },
            "JudgeOutputLimitError": {
                "base": blackbox_module.JudgeOutputLimitError.__bases__[0].__name__,
                "args": list(output_error.args),
                "fields": dict(output_error.__dict__),
                "message": str(output_error),
            },
        },
        "required_patch_seams": list(REQUIRED_PATCH_SEAMS),
        "patch_seam_presence": {
            seam: _resolve_patch_seam(seam) is not None for seam in REQUIRED_PATCH_SEAMS
        },
    }


def capture_completed_run_contract() -> dict[str, object]:
    process = _CompletedJudgeProcess()
    capture = _Capture()
    command = ["judge-python", "-m", "pytest"]
    environment = {"SAFE": "1"}
    popen_observation: dict[str, object] = {}
    created_readers: list[_Reader] = []
    join_calls: list[dict[str, object]] = []
    terminate_calls: list[bool] = []
    monotonic_calls: list[float] = []
    sleep_calls: list[float] = []
    output_limits: list[int] = []

    def popen(command_argument: list[str], **kwargs: Any) -> _CompletedJudgeProcess:
        popen_observation.update(
            {
                "command_identity": command_argument is command,
                "command": list(command_argument),
                "cwd": kwargs.get("cwd"),
                "env_identity": kwargs.get("env") is environment,
                "env": dict(kwargs.get("env") or {}),
                "stdin_is_devnull": kwargs.get("stdin") is subprocess.DEVNULL,
                "stdout_is_pipe": kwargs.get("stdout") is subprocess.PIPE,
                "stderr_is_pipe": kwargs.get("stderr") is subprocess.PIPE,
                "start_new_session": kwargs.get("start_new_session"),
                "keyword_names": sorted(kwargs),
            }
        )
        return process

    def reader_factory(*, target: object, args: tuple[object, ...], daemon: bool) -> _Reader:
        reader = _Reader(target=target, args=args, daemon=daemon)
        created_readers.append(reader)
        return reader

    def output_factory(limit: int) -> _Capture:
        output_limits.append(limit)
        return capture

    def drain_pipe(_stream: object, _capture: object, _name: str) -> None:
        raise AssertionError("fake reader must not execute its target")

    def join_readers(readers: list[_Reader], streams: list[_Pipe]) -> bool:
        join_calls.append(
            {
                "reader_count": len(readers),
                "readers_match_created": list(readers) == created_readers,
                "stream_labels": [stream.label for stream in streams],
            }
        )
        return True

    def terminate(candidate: _CompletedJudgeProcess) -> None:
        terminate_calls.append(candidate is process)

    def monotonic() -> float:
        monotonic_calls.append(100.0)
        return 100.0

    with ExitStack() as stack:
        stack.enter_context(patch.object(blackbox_module.subprocess, "Popen", popen))
        stack.enter_context(
            patch.object(blackbox_module.threading, "Thread", reader_factory)
        )
        stack.enter_context(patch.object(blackbox_module, "_BoundedOutput", output_factory))
        stack.enter_context(
            patch.object(blackbox_module, "_drain_subprocess_pipe", drain_pipe)
        )
        stack.enter_context(
            patch.object(blackbox_module, "_join_judge_pipe_readers", join_readers)
        )
        stack.enter_context(
            patch.object(blackbox_module, "_terminate_judge_process_group", terminate)
        )
        stack.enter_context(
            patch.object(blackbox_module, "_MAX_SUBPROCESS_OUTPUT_BYTES", 321)
        )
        stack.enter_context(
            patch.object(blackbox_module, "_JUDGE_GROUP_POLL_SECONDS", 0.125)
        )
        stack.enter_context(patch.object(blackbox_module.time, "monotonic", monotonic))
        stack.enter_context(
            patch.object(
                blackbox_module.time,
                "sleep",
                side_effect=lambda seconds: sleep_calls.append(seconds),
            )
        )
        completed = blackbox_module._run_judge_process(
            command,
            cwd="/judge",
            env=environment,
            timeout=7,
        )

    return {
        "popen": popen_observation,
        "reader_factory": {
            "count": len(created_readers),
            "daemon_values": [reader.daemon for reader in created_readers],
            "start_calls": [reader.start_calls for reader in created_readers],
            "targets_use_drain_patch": [
                reader.target is drain_pipe for reader in created_readers
            ],
            "stream_args": [reader.args[0].label for reader in created_readers],
            "capture_identity": [
                reader.args[1] is capture for reader in created_readers
            ],
            "stream_names": [reader.args[2] for reader in created_readers],
        },
        "runtime_seams": {
            "output_limits": output_limits,
            "join_calls": join_calls,
            "monotonic_calls": monotonic_calls,
            "terminate_process_identity": terminate_calls,
            "sleep_calls": sleep_calls,
            "poll_calls": process.poll_calls,
        },
        "completed_process": {
            "type": type(completed).__name__,
            "args_identity": completed.args is command,
            "args": list(completed.args),
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        },
    }


def capture_termination_contract() -> dict[str, object]:
    process = _GroupProcess()
    group_probes: list[int] = []
    signals: list[list[int]] = []
    waits: list[dict[str, object]] = []
    reaps: list[bool] = []
    event_trace: list[str] = []

    def group_exists(process_group: int) -> bool:
        event_trace.append("probe")
        group_probes.append(process_group)
        return True

    def signal_group(candidate: _GroupProcess, sig: int) -> None:
        event_trace.append(
            "signal-term" if int(sig) == int(signal.SIGTERM) else "signal-kill"
        )
        signals.append([int(candidate.pid), int(sig)])

    def wait_for_exit(
        candidate: _GroupProcess, process_group: int, timeout: float
    ) -> bool:
        event_trace.append("wait")
        waits.append(
            {
                "process_identity": candidate is process,
                "process_group": process_group,
                "timeout": timeout,
            }
        )
        return len(waits) == 2

    def reap(candidate: _GroupProcess) -> None:
        event_trace.append("reap")
        reaps.append(candidate is process)

    with ExitStack() as stack:
        stack.enter_context(patch.object(blackbox_module.os, "name", "posix"))
        stack.enter_context(
            patch.object(blackbox_module.os, "killpg", lambda *_args: None, create=True)
        )
        stack.enter_context(
            patch.object(blackbox_module, "_process_group_exists", group_exists)
        )
        stack.enter_context(
            patch.object(blackbox_module, "_signal_judge_process_group", signal_group)
        )
        stack.enter_context(
            patch.object(blackbox_module, "_wait_for_process_group_exit", wait_for_exit)
        )
        stack.enter_context(patch.object(blackbox_module, "_reap_judge_leader", reap))
        stack.enter_context(
            patch.object(blackbox_module, "_JUDGE_TERMINATION_GRACE_SECONDS", 0.75)
        )
        stack.enter_context(patch.object(blackbox_module, "_SIGKILL", 99))
        blackbox_module._terminate_judge_process_group(process)  # type: ignore[arg-type]

    return {
        "process_group_probes": group_probes,
        "signals": signals,
        "sigterm": int(signal.SIGTERM),
        "waits": waits,
        "reaps": reaps,
        "event_trace": event_trace,
    }


def capture_join_contract() -> dict[str, object]:
    cases: dict[str, object] = {}
    for case_name, join_outcome in (("stopped", True), ("live", False)):
        reader = _JoinReader()
        stream = _Pipe(case_name)
        calls: list[dict[str, object]] = []

        def join(
            readers: list[_JoinReader],
            streams: list[object],
            *,
            expected_reader: _JoinReader = reader,
            observed_calls: list[dict[str, object]] = calls,
            outcome: bool = join_outcome,
        ) -> bool:
            observed_calls.append(
                {
                    "reader_identity": readers == [expected_reader],
                    "streams_are_empty": streams == [],
                }
            )
            return outcome

        with patch.object(blackbox_module, "_join_pipe_readers", join):
            result = blackbox_module._join_judge_pipe_readers([reader], [stream])
        cases[case_name] = {
            "result": result,
            "close_calls": stream.close_calls,
            "generic_join_calls": calls,
        }

    reader = _JoinReader()
    stream = _Pipe("join-error")

    def fail_join(_readers: list[_JoinReader], _streams: list[object]) -> bool:
        raise RuntimeError("join sentinel")

    try:
        with patch.object(blackbox_module, "_join_pipe_readers", fail_join):
            blackbox_module._join_judge_pipe_readers([reader], [stream])
    except BaseException as exc:
        cases["join_error"] = {
            "exception_type": type(exc).__name__,
            "message": str(exc),
            "close_calls": stream.close_calls,
        }
    return cases


def capture_contract() -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "static": capture_static_contract(),
        "completed_run": capture_completed_run_contract(),
        "termination": capture_termination_contract(),
        "join": capture_join_contract(),
    }


def canonical_json(payload: object) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"
