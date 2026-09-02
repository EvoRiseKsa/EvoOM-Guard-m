# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Bounded Git-query process lifecycle for the Trusted Finalizer.

The raw-object derivation facade supplies its historical exception type,
runtime limits, and cleanup hooks explicitly.  This owner keeps subprocess
lifecycle complexity inside the finalizer package without importing that
facade or weakening its monkeypatch-compatible test boundary.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class GitCommandLimits:
    """Runtime bounds retained by one raw-Git query."""

    stdout_bytes: int
    stderr_bytes: int
    stream_chunk_bytes: int
    query_timeout_seconds: float
    process_poll_seconds: float
    kill_reap_seconds: float


@dataclass(frozen=True, slots=True)
class GitCommandServices:
    """Effect boundary supplied by the legacy finalizer-derivation facade."""

    popen: Callable[..., Any]
    thread_factory: Callable[..., Any]
    event_factory: Callable[[], Any]
    monotonic: Callable[[], float]
    environment: Mapping[str, str]
    os_name: str
    devnull_path: Callable[[], str]
    devnull_input: Any
    pipe_output: Any
    process_group_popen_kwargs: Callable[[], dict[str, Any]]
    terminate_process_tree: Callable[..., bool]
    join_and_close_readers: Callable[..., bool]
    error_factory: Callable[[str], BaseException]
    note_abort_cleanup_failure: Callable[[BaseException, object], None]
    abort_cleanup_exception_summary: Callable[[BaseException], str]


@dataclass
class _GitCommandState:
    process: Any = None
    streams: list[Any] = field(default_factory=list)
    reader_start_attempts: list[Any] = field(default_factory=list)
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    overflow: set[str] = field(default_factory=set)
    read_errors: list[BaseException] = field(default_factory=list)
    cleanup_proven: bool = False
    readers_closed: bool = False


def _command(repo: str, args: list[str], *, bare: bool, executable: str) -> list[str]:
    command = [executable, "--no-replace-objects"]
    command.extend(["--git-dir", repo] if bare else ["-C", repo])
    command.extend(args)
    return command


def _environment(
    services: GitCommandServices,
    *,
    isolated: bool,
) -> dict[str, str]:
    if isolated:
        environment = {
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": services.devnull_path(),
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
            "LANG": "C",
        }
        if services.os_name == "nt":
            for name in ("SYSTEMROOT", "WINDIR"):
                if name in services.environment:
                    environment[name] = services.environment[name]
        return environment
    environment = {
        key: value
        for key, value in services.environment.items()
        if not key.upper().startswith("GIT_")
    }
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    return environment


def _start_process(
    state: _GitCommandState,
    command: list[str],
    environment: Mapping[str, str],
    services: GitCommandServices,
) -> tuple[Any, Any]:
    try:
        state.process = services.popen(
            command,
            stdin=services.devnull_input,
            stdout=services.pipe_output,
            stderr=services.pipe_output,
            env=environment,
            **services.process_group_popen_kwargs(),
        )
    except OSError as exc:
        raise services.error_factory(
            f"could not read immutable Git object: {exc}"
        ) from exc
    stdout_stream = state.process.stdout
    stderr_stream = state.process.stderr
    state.streams = [
        stream for stream in (stdout_stream, stderr_stream) if stream is not None
    ]
    if stdout_stream is None or stderr_stream is None:
        raise services.error_factory(
            "could not read immutable Git object: Git output pipes were not created"
        )
    return stdout_stream, stderr_stream


def _drain_stream(
    stream: Any,
    *,
    maximum: int,
    target: bytearray,
    label: str,
    state: _GitCommandState,
    reader_signal: Any,
    chunk_bytes: int,
) -> None:
    try:
        while True:
            chunk = stream.read(chunk_bytes)
            if not chunk:
                return
            remaining = maximum + 1 - len(target)
            if remaining > 0:
                target.extend(chunk[:remaining])
            if len(target) > maximum:
                state.overflow.add(label)
                reader_signal.set()
    except BaseException as exc:
        state.read_errors.append(exc)
        reader_signal.set()


def _start_readers(
    state: _GitCommandState,
    stdout_stream: Any,
    stderr_stream: Any,
    reader_signal: Any,
    limits: GitCommandLimits,
    services: GitCommandServices,
) -> None:
    # Build both readers atomically. If the second constructor raises, neither
    # reader is treated as start-attempted and both untouched streams can close.
    readers = [
        services.thread_factory(
            target=_drain_stream,
            args=(stdout_stream,),
            kwargs={
                "maximum": limits.stdout_bytes,
                "target": state.stdout,
                "label": "stdout",
                "state": state,
                "reader_signal": reader_signal,
                "chunk_bytes": limits.stream_chunk_bytes,
            },
            daemon=True,
        ),
        services.thread_factory(
            target=_drain_stream,
            args=(stderr_stream,),
            kwargs={
                "maximum": limits.stderr_bytes,
                "target": state.stderr,
                "label": "stderr",
                "state": state,
                "reader_signal": reader_signal,
                "chunk_bytes": limits.stream_chunk_bytes,
            },
            daemon=True,
        ),
    ]
    for reader in readers:
        # start() may fail after a native thread exists, so record first.
        state.reader_start_attempts.append(reader)
        reader.start()


def _wait_for_process(
    state: _GitCommandState,
    reader_signal: Any,
    limits: GitCommandLimits,
    services: GitCommandServices,
) -> bool:
    deadline = services.monotonic() + limits.query_timeout_seconds
    while state.process.poll() is None:
        if state.read_errors or state.overflow:
            return False
        remaining = deadline - services.monotonic()
        if remaining <= 0:
            return True
        reader_signal.wait(min(limits.process_poll_seconds, remaining))
    return False


def _stop_interrupted_process(
    state: _GitCommandState,
    services: GitCommandServices,
) -> None:
    if services.terminate_process_tree(state.process) is not True:
        raise services.error_factory(
            "could not read immutable Git object: Git query process "
            "cleanup could not be proven"
        )
    state.cleanup_proven = True


def _complete_process(
    state: _GitCommandState,
    limits: GitCommandLimits,
    services: GitCommandServices,
) -> None:
    state.process.wait(timeout=limits.kill_reap_seconds)
    if services.os_name == "posix":
        _stop_interrupted_process(state, services)


def _close_readers(
    state: _GitCommandState,
    services: GitCommandServices,
) -> None:
    if (
        services.join_and_close_readers(
            state.reader_start_attempts,
            state.streams,
        )
        is not True
    ):
        raise services.error_factory(
            "could not read immutable Git object: Git query output readers "
            "did not stop after cleanup"
        )
    state.readers_closed = True


def _result_or_error(
    state: _GitCommandState,
    *,
    timed_out: bool,
    services: GitCommandServices,
) -> bytes:
    if timed_out:
        raise services.error_factory(
            "could not read immutable Git object: Git query timed out"
        )
    if state.read_errors:
        error = state.read_errors[0]
        raise services.error_factory(
            f"could not read immutable Git object: {error}"
        ) from error
    if "stdout" in state.overflow:
        raise services.error_factory("Git object listing exceeds the finalizer limit")
    if "stderr" in state.overflow:
        raise services.error_factory("Git error output exceeds the finalizer limit")
    if state.process.returncode != 0:
        detail = bytes(state.stderr).decode("utf-8", "replace")[:512].strip()
        raise services.error_factory(
            f"Git object lookup failed: {detail or state.process.returncode}"
        )
    return bytes(state.stdout)


def _execute(
    state: _GitCommandState,
    *,
    repo: str,
    args: list[str],
    bare: bool,
    executable: str,
    isolated_environment: bool,
    limits: GitCommandLimits,
    services: GitCommandServices,
) -> bytes:
    command = _command(repo, args, bare=bare, executable=executable)
    environment = _environment(services, isolated=isolated_environment)
    stdout_stream, stderr_stream = _start_process(
        state,
        command,
        environment,
        services,
    )
    reader_signal = services.event_factory()
    _start_readers(
        state,
        stdout_stream,
        stderr_stream,
        reader_signal,
        limits,
        services,
    )
    timed_out = _wait_for_process(state, reader_signal, limits, services)
    interrupted = timed_out or bool(state.read_errors) or bool(state.overflow)
    if interrupted:
        _stop_interrupted_process(state, services)
    else:
        _complete_process(state, limits, services)
    _close_readers(state, services)
    return _result_or_error(state, timed_out=timed_out, services=services)


def _record_tree_abort_cleanup(
    state: _GitCommandState,
    primary: BaseException,
    services: GitCommandServices,
) -> None:
    try:
        result = services.terminate_process_tree(state.process)
    except BaseException as cleanup_error:
        services.note_abort_cleanup_failure(
            primary,
            "Raw-Git finalizer process-tree abort cleanup raised while "
            "preserving the primary exception: "
            + services.abort_cleanup_exception_summary(cleanup_error),
        )
    else:
        if result is True:
            state.cleanup_proven = True
        else:
            services.note_abort_cleanup_failure(
                primary,
                "Raw-Git finalizer process-tree abort cleanup was not "
                "proven while preserving the primary exception",
            )


def _record_reader_abort_cleanup(
    state: _GitCommandState,
    primary: BaseException,
    services: GitCommandServices,
) -> None:
    try:
        result = services.join_and_close_readers(
            state.reader_start_attempts,
            state.streams,
        )
    except BaseException as cleanup_error:
        services.note_abort_cleanup_failure(
            primary,
            "Raw-Git finalizer output-reader abort cleanup raised while "
            "preserving the primary exception: "
            + services.abort_cleanup_exception_summary(cleanup_error),
        )
    else:
        if result is True:
            state.readers_closed = True
        else:
            services.note_abort_cleanup_failure(
                primary,
                "Raw-Git finalizer output-reader abort cleanup was not "
                "proven while preserving the primary exception",
            )


def _cleanup_after_abort(
    state: _GitCommandState,
    primary: BaseException,
    services: GitCommandServices,
) -> None:
    if state.process is None:
        return
    if state.cleanup_proven is not True:
        _record_tree_abort_cleanup(state, primary, services)
    if state.readers_closed is not True:
        _record_reader_abort_cleanup(state, primary, services)


def run_bounded_git_command(
    repo: str,
    args: list[str],
    *,
    bare: bool,
    executable: str,
    isolated_environment: bool,
    limits: GitCommandLimits,
    services: GitCommandServices,
) -> bytes:
    """Run one Git query while preserving bounded finalizer observables."""

    state = _GitCommandState()
    try:
        return _execute(
            state,
            repo=repo,
            args=args,
            bare=bare,
            executable=executable,
            isolated_environment=isolated_environment,
            limits=limits,
            services=services,
        )
    except BaseException as primary:
        _cleanup_after_abort(state, primary, services)
        raise


__all__ = [
    "GitCommandLimits",
    "GitCommandServices",
    "run_bounded_git_command",
]
