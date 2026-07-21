"""Typed execution boundary for the external black-box judge process.

This module owns process launch, bounded output capture, and process-group
containment for one judge invocation.  It deliberately does not know how a
judge command is assembled and does not import :mod:`evoom_guard.blackbox`.
The black-box module remains a compatibility facade for its historical private
patch seams while delegating the execution mechanics defined here.
"""

from __future__ import annotations

import math
import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from evoom_guard.execution.process import (
    DEFAULT_MAX_OUTPUT_BYTES,
    BoundedOutput,
    drain_process_pipe,
    join_pipe_readers,
)

DEFAULT_JUDGE_TERMINATION_GRACE_SECONDS = 2.0
DEFAULT_JUDGE_GROUP_POLL_SECONDS = 0.02
DEFAULT_JUDGE_SIGKILL = int(getattr(signal, "SIGKILL", 9))


@dataclass(frozen=True, slots=True)
class JudgeProcessLimits:
    """Resource and cleanup bounds for one judge process group."""

    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    termination_grace_seconds: float = DEFAULT_JUDGE_TERMINATION_GRACE_SECONDS
    group_poll_seconds: float = DEFAULT_JUDGE_GROUP_POLL_SECONDS
    sigkill: int = DEFAULT_JUDGE_SIGKILL

    def __post_init__(self) -> None:
        if type(self.max_output_bytes) is not int or self.max_output_bytes < 0:
            raise ValueError("max_output_bytes must be a non-negative integer")
        for name, value, allow_zero in (
            ("termination_grace_seconds", self.termination_grace_seconds, True),
            ("group_poll_seconds", self.group_poll_seconds, False),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value < 0
                or (not allow_zero and value == 0)
            ):
                qualifier = "non-negative" if allow_zero else "positive"
                raise ValueError(f"{name} must be a finite {qualifier} number")
        if type(self.sigkill) is not int or self.sigkill <= 0:
            raise ValueError("sigkill must be a positive integer signal number")


@dataclass(frozen=True, slots=True)
class JudgeProcessRequest:
    """Complete typed input for one judge-owned process invocation."""

    command: list[str]
    cwd: str
    env: dict[str, str]
    timeout_seconds: int
    limits: JudgeProcessLimits = field(default_factory=JudgeProcessLimits)

    def __post_init__(self) -> None:
        if type(self.limits) is not JudgeProcessLimits:
            raise ValueError("limits must be a JudgeProcessLimits instance")
        if type(self.timeout_seconds) is not int or self.timeout_seconds < 0:
            raise ValueError("timeout_seconds must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class JudgeProcessResult:
    """Completed judge facts independent of ``subprocess`` adaptation."""

    command: list[str]
    returncode: int
    stdout: str
    stderr: str

    def as_completed_process(self) -> subprocess.CompletedProcess[str]:
        """Adapt the facts while preserving the caller-owned argv object."""

        return subprocess.CompletedProcess(
            self.command,
            self.returncode,
            stdout=self.stdout,
            stderr=self.stderr,
        )


class JudgeProcessCleanupError(RuntimeError):
    """The judge session could not be proven free of surviving descendants."""


class JudgeOutputLimitError(RuntimeError):
    """The judge-owned pack exceeded its bounded diagnostic channel."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        super().__init__(
            "black-box judge output exceeded the "
            f"{limit}-byte judge capture limit"
        )


def signal_judge_process_group(
    process: subprocess.Popen[Any], sig: int
) -> None:
    """Signal only the dedicated judge session created by the executor."""

    killpg = getattr(os, "killpg", None)
    if os.name == "posix" and callable(killpg):
        killpg(process.pid, sig)
    elif sig == int(signal.SIGTERM):
        process.terminate()
    else:
        process.kill()


def judge_process_group_exists(process_group: int) -> bool:
    """Return whether a POSIX process group still has any member."""

    killpg = getattr(os, "killpg", None)
    if not callable(killpg):
        raise JudgeProcessCleanupError("POSIX killpg is unavailable")
    try:
        killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError as exc:
        raise JudgeProcessCleanupError(
            f"cannot inspect judge process group {process_group}: {exc}"
        ) from exc
    except OSError as exc:
        raise JudgeProcessCleanupError(
            f"judge process-group inspection failed for {process_group}: {exc}"
        ) from exc
    return True


def wait_for_judge_process_group_exit(
    process: subprocess.Popen[Any],
    process_group: int,
    timeout: float,
    *,
    process_group_exists: Callable[[int], bool] | None = None,
    group_poll_seconds: float | None = None,
    monotonic: Callable[[], float] | None = None,
    sleeper: Callable[[float], object] | None = None,
) -> bool:
    """Boundedly poll until a judge process group no longer exists."""

    if process_group_exists is None:
        process_group_exists = judge_process_group_exists
    if group_poll_seconds is None:
        group_poll_seconds = DEFAULT_JUDGE_GROUP_POLL_SECONDS
    if monotonic is None:
        monotonic = time.monotonic
    if sleeper is None:
        sleeper = time.sleep
    deadline = monotonic() + max(timeout, 0.0)
    while True:
        # poll() also reaps the direct leader when it has exited. Do this on
        # every iteration so a zombie leader cannot make killpg(..., 0) look
        # like a live descendant forever.
        process.poll()
        if not process_group_exists(process_group):
            return True
        if monotonic() >= deadline:
            return False
        sleeper(min(group_poll_seconds, max(deadline - monotonic(), 0.0)))


def reap_judge_leader(
    process: subprocess.Popen[Any],
    *,
    termination_grace_seconds: float | None = None,
) -> None:
    """Boundedly reap the direct judge process leader."""

    if termination_grace_seconds is None:
        termination_grace_seconds = DEFAULT_JUDGE_TERMINATION_GRACE_SECONDS
    if process.poll() is not None:
        return
    try:
        process.wait(timeout=termination_grace_seconds)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise JudgeProcessCleanupError(
            f"judge leader {process.pid} could not be reaped after group cleanup"
        ) from exc


def terminate_judge_process_group(
    process: subprocess.Popen[Any],
    *,
    limits: JudgeProcessLimits | None = None,
    process_group_exists: Callable[[int], bool] | None = None,
    signal_process_group: Callable[[subprocess.Popen[Any], int], None] | None = None,
    wait_for_group_exit: Callable[
        [subprocess.Popen[Any], int, float], bool
    ] | None = None,
    reap_leader: Callable[[subprocess.Popen[Any]], None] | None = None,
) -> None:
    """Boundedly reap pytest and every non-detached group descendant."""

    active_limits = JudgeProcessLimits() if limits is None else limits
    if process_group_exists is None:
        process_group_exists = judge_process_group_exists
    if signal_process_group is None:
        signal_process_group = signal_judge_process_group
    if wait_for_group_exit is None:
        def default_wait_for_group_exit(
            candidate: subprocess.Popen[Any], group: int, timeout: float
        ) -> bool:
            return wait_for_judge_process_group_exit(
                candidate,
                group,
                timeout,
                process_group_exists=process_group_exists,
                group_poll_seconds=active_limits.group_poll_seconds,
            )

        wait_for_group_exit = default_wait_for_group_exit
    if reap_leader is None:
        def default_reap_leader(candidate: subprocess.Popen[Any]) -> None:
            reap_judge_leader(
                candidate,
                termination_grace_seconds=(
                    active_limits.termination_grace_seconds
                ),
            )

        reap_leader = default_reap_leader

    if os.name != "posix" or not hasattr(os, "killpg"):
        # Production black-box execution fails before this point on Windows.
        # Keep the fallback bounded for embedding tests, but make no group claim.
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=active_limits.termination_grace_seconds)
            except subprocess.TimeoutExpired:
                process.kill()
                reap_leader(process)
        return

    process_group = process.pid  # start_new_session=True makes PGID == leader PID
    if process_group_exists(process_group):
        try:
            signal_process_group(process, int(signal.SIGTERM))
        except ProcessLookupError:
            pass
        except OSError as exc:
            raise JudgeProcessCleanupError(
                f"could not terminate judge process group {process_group}: {exc}"
            ) from exc
        if not wait_for_group_exit(
            process, process_group, active_limits.termination_grace_seconds
        ):
            try:
                signal_process_group(process, active_limits.sigkill)
            except ProcessLookupError:
                pass
            except OSError as exc:
                raise JudgeProcessCleanupError(
                    f"could not kill judge process group {process_group}: {exc}"
                ) from exc
            if not wait_for_group_exit(
                process,
                process_group,
                active_limits.termination_grace_seconds,
            ):
                raise JudgeProcessCleanupError(
                    f"judge process group {process_group} survived SIGKILL"
                )
    reap_leader(process)


def join_judge_pipe_readers(
    readers: list[threading.Thread],
    streams: list[Any],
    *,
    generic_joiner: Callable[[list[threading.Thread], list[Any]], bool] | None = None,
) -> bool:
    """Boundedly join attempted readers without closing under a live read."""

    if generic_joiner is None:
        generic_joiner = join_pipe_readers
    stopped: list[bool] = []
    first_error: BaseException | None = None
    for reader in readers:
        reader_stopped = False
        try:
            reader_stopped = generic_joiner([reader], [])
        except RuntimeError as exc:
            # An interrupted Thread.start() can create the native thread before
            # ``ident`` or ``_started`` becomes observable. A failed join is
            # never proof that the corresponding pipe is safe to close.
            if first_error is None:
                first_error = exc
        except BaseException as exc:
            if first_error is None:
                first_error = exc
        stopped.append(reader_stopped)

    streams_closed = True
    for index, stream in enumerate(streams):
        safe_to_close = index >= len(stopped) or stopped[index]
        if not safe_to_close:
            streams_closed = False
            continue
        try:
            stream.close()
        except (OSError, ValueError):
            streams_closed = False
        except BaseException as exc:
            streams_closed = False
            if first_error is None:
                first_error = exc

    if first_error is not None:
        raise first_error
    return all(stopped) and streams_closed


def execute_judge_process(
    request: JudgeProcessRequest,
    *,
    popen_factory: Callable[..., Any] | None = None,
    thread_factory: Callable[..., Any] | None = None,
    output_factory: Callable[[int], Any] | None = None,
    pipe_drain: Callable[[Any, Any, str], None] | None = None,
    pipe_join: Callable[[list[threading.Thread], list[Any]], bool] | None = None,
    process_group_terminator: Callable[[subprocess.Popen[Any]], None] | None = None,
    monotonic: Callable[[], float] | None = None,
    sleeper: Callable[[float], object] | None = None,
) -> JudgeProcessResult:
    """Execute one judge process and prove bounded process-group cleanup.

    The built-in terminator requires POSIX process-group support. On another
    platform, a caller must provide an explicit terminator that raises unless
    it can prove the requested containment boundary is clean.
    """

    if popen_factory is None:
        popen_factory = subprocess.Popen
    if thread_factory is None:
        thread_factory = threading.Thread
    if output_factory is None:
        output_factory = BoundedOutput
    if pipe_drain is None:
        pipe_drain = drain_process_pipe
    if pipe_join is None:
        pipe_join = join_judge_pipe_readers
    if monotonic is None:
        monotonic = time.monotonic
    if sleeper is None:
        sleeper = time.sleep
    if process_group_terminator is None:
        if os.name != "posix" or not callable(getattr(os, "killpg", None)):
            raise JudgeProcessCleanupError(
                "default judge execution requires POSIX process-group cleanup; "
                "provide an explicit trusted process_group_terminator"
            )
        def default_process_group_terminator(
            process: subprocess.Popen[Any],
        ) -> None:
            terminate_judge_process_group(process, limits=request.limits)

        process_group_terminator = default_process_group_terminator

    process: subprocess.Popen[Any] | None = None
    streams: list[Any] = []
    reader_start_attempts: list[threading.Thread] = []
    try:
        process = popen_factory(
            request.command,
            cwd=request.cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=request.env,
            start_new_session=True,
        )
        stdout = process.stdout
        stderr = process.stderr
        streams = [stream for stream in (stdout, stderr) if stream is not None]
        if stdout is None or stderr is None:
            raise JudgeProcessCleanupError("judge output pipes were not created")
        capture = output_factory(request.limits.max_output_bytes)
        readers: list[threading.Thread] = [
            thread_factory(
                target=pipe_drain,
                args=(stdout, capture, "stdout"),
                daemon=True,
            ),
            thread_factory(
                target=pipe_drain,
                args=(stderr, capture, "stderr"),
                daemon=True,
            ),
        ]
        for reader in readers:
            # Record before start(): an asynchronous BaseException can arrive
            # after the native thread exists but before start() returns.
            reader_start_attempts.append(reader)
            reader.start()

        def cleanup_and_prove(reason: str) -> None:
            try:
                process_group_terminator(process)
            except JudgeProcessCleanupError:
                raise
            except Exception as exc:
                raise JudgeProcessCleanupError(
                    f"unexpected judge process-group cleanup failure: {exc}"
                ) from exc
            if not pipe_join(readers, streams):
                raise JudgeProcessCleanupError(
                    f"{reason}; judge output pipes did not close after cleanup"
                )

        deadline = monotonic() + max(0.0, float(request.timeout_seconds))
        while process.poll() is None:
            if capture.exceeded:
                cleanup_and_prove("judge output limit reached")
                raise JudgeOutputLimitError(capture.limit)
            if monotonic() >= deadline:
                cleanup_and_prove("judge timed out")
                raise subprocess.TimeoutExpired(
                    request.command,
                    request.timeout_seconds,
                    output=capture.text("stdout"),
                    stderr=capture.text("stderr"),
                )
            sleeper(request.limits.group_poll_seconds)

        # A short-lived process can flood a pipe and exit before the polling
        # loop observes it. Reap the group before reporting capture overflow.
        if capture.exceeded:
            cleanup_and_prove("judge output limit reached")
            raise JudgeOutputLimitError(capture.limit)
        if not pipe_join(readers, streams):
            cleanup_and_prove("judge exited with live output pipes")
            raise JudgeProcessCleanupError(
                "judge exited but its output pipes did not close"
            )
        if capture.exceeded:
            cleanup_and_prove("judge output limit reached")
            raise JudgeOutputLimitError(capture.limit)
        cleanup_and_prove("judge completed")
        return JudgeProcessResult(
            command=request.command,
            returncode=int(process.returncode or 0),
            stdout=capture.text("stdout"),
            stderr=capture.text("stderr"),
        )
    except BaseException:
        if process is not None:
            try:
                # A reaped leader is not proof that its process group has no
                # surviving descendant, so abort cleanup is unconditional.
                process_group_terminator(process)
            except BaseException:
                # An active primary exception must not be replaced by cleanup.
                pass
            try:
                pipe_join(reader_start_attempts, streams)
            except BaseException:
                pass
        raise


__all__ = [
    "DEFAULT_JUDGE_GROUP_POLL_SECONDS",
    "DEFAULT_JUDGE_SIGKILL",
    "DEFAULT_JUDGE_TERMINATION_GRACE_SECONDS",
    "JudgeOutputLimitError",
    "JudgeProcessCleanupError",
    "JudgeProcessLimits",
    "JudgeProcessRequest",
    "JudgeProcessResult",
    "execute_judge_process",
]
