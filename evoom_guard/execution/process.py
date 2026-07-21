"""Bounded native-process execution and its typed contracts.

This module owns the process boundary shared by repository verification,
black-box support, evidence collection, and candidate-runner control commands.
It deliberately does not own Docker policy or verdict composition.

The public contract is fail-closed:

* stdout and stderr share one bounded diagnostic budget;
* timeout and output overflow stop the complete managed process tree before an
  exception is returned;
* POSIX completion also proves that no member of the dedicated process group
  remains; and
* a caller-supplied ``preexec_fn`` is applied only on POSIX, preserving the
  existing resource-limit hook without claiming support on Windows.
"""

from __future__ import annotations

import math
import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

DEFAULT_MAX_OUTPUT_BYTES = 1 * 1024 * 1024
DEFAULT_READ_CHUNK_BYTES = 64 * 1024
DEFAULT_TERMINATION_GRACE_SECONDS = 1.0
DEFAULT_KILL_GRACE_SECONDS = 3.0
DEFAULT_READER_JOIN_SECONDS = 2.0


@dataclass(frozen=True, slots=True)
class ProcessLimits:
    """Bounded resources controlled directly by the process runner.

    Address-space and CPU limits remain caller policy and are supplied through
    ``BoundedProcessRequest.preexec_fn`` on POSIX.  These fields govern only
    output retention and bounded cleanup waits.
    """

    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    read_chunk_bytes: int = DEFAULT_READ_CHUNK_BYTES
    termination_grace_seconds: float = DEFAULT_TERMINATION_GRACE_SECONDS
    kill_grace_seconds: float = DEFAULT_KILL_GRACE_SECONDS
    reader_join_seconds: float = DEFAULT_READER_JOIN_SECONDS

    def __post_init__(self) -> None:
        if type(self.max_output_bytes) is not int or self.max_output_bytes < 0:
            raise ValueError("max_output_bytes must be non-negative")
        if type(self.read_chunk_bytes) is not int or self.read_chunk_bytes <= 0:
            raise ValueError("read_chunk_bytes must be positive")
        for name, value in (
            ("termination_grace_seconds", self.termination_grace_seconds),
            ("kill_grace_seconds", self.kill_grace_seconds),
            ("reader_join_seconds", self.reader_join_seconds),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value < 0
            ):
                raise ValueError(f"{name} must be a finite non-negative number")


@dataclass(frozen=True, slots=True)
class BoundedProcessRequest:
    """Complete input contract for one bounded native process execution."""

    command: tuple[str, ...]
    cwd: str | None
    env: Mapping[str, str] | None
    timeout_seconds: float
    preexec_fn: Callable[[], object] | None = None
    limits: ProcessLimits = field(default_factory=ProcessLimits)

    @classmethod
    def from_command(
        cls,
        command: Sequence[str],
        *,
        cwd: str | None,
        env: Mapping[str, str] | None,
        timeout: float,
        preexec_fn: Callable[[], object] | None = None,
        limits: ProcessLimits | None = None,
    ) -> BoundedProcessRequest:
        """Freeze a caller command into the execution request contract."""

        return cls(
            command=tuple(command),
            cwd=cwd,
            env=env,
            timeout_seconds=timeout,
            preexec_fn=preexec_fn,
            limits=ProcessLimits() if limits is None else limits,
        )


@dataclass(frozen=True, slots=True)
class BoundedProcessResult:
    """Completed process facts before adaptation to ``CompletedProcess``."""

    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    def as_completed_process(self) -> subprocess.CompletedProcess[str]:
        """Return the historical subprocess-compatible result surface."""

        return subprocess.CompletedProcess(
            list(self.command),
            self.returncode,
            stdout=self.stdout,
            stderr=self.stderr,
        )


class ProcessOutputLimitExceeded(RuntimeError):
    """A managed command exceeded the shared diagnostic-output budget."""

    def __init__(self, limit: int = DEFAULT_MAX_OUTPUT_BYTES) -> None:
        self.limit = limit
        super().__init__(
            "candidate subprocess output exceeded the "
            f"{self.limit}-byte judge capture limit"
        )


class ProcessContainmentError(RuntimeError):
    """The runner could not prove cleanup of its managed process tree."""


class BoundedOutput:
    """Thread-safe stdout/stderr capture sharing one byte limit."""

    def __init__(self, limit: int = DEFAULT_MAX_OUTPUT_BYTES) -> None:
        if limit < 0:
            raise ValueError("output limit must be non-negative")
        self.limit = limit
        self._stdout = bytearray()
        self._stderr = bytearray()
        self._captured = 0
        self._exceeded = False
        self._lock = threading.Lock()

    def append(self, stream: str, data: bytes) -> None:
        with self._lock:
            remaining = max(0, self.limit - self._captured)
            accepted = data[:remaining]
            if stream == "stdout":
                self._stdout.extend(accepted)
            else:
                self._stderr.extend(accepted)
            self._captured += len(accepted)
            if len(accepted) != len(data):
                self._exceeded = True

    @property
    def exceeded(self) -> bool:
        with self._lock:
            return self._exceeded

    def text(self, stream: str) -> str:
        with self._lock:
            data = bytes(self._stdout if stream == "stdout" else self._stderr)
        return data.decode("utf-8", errors="replace")


def drain_process_pipe(
    stream: Any,
    capture: BoundedOutput,
    stream_name: str,
    read_chunk_bytes: int = DEFAULT_READ_CHUNK_BYTES,
) -> None:
    """Drain one subprocess pipe without retaining unbounded output."""

    if read_chunk_bytes <= 0:
        raise ValueError("read_chunk_bytes must be positive")

    try:
        while True:
            chunk = stream.read(read_chunk_bytes)
            if not chunk:
                return
            capture.append(stream_name, chunk)
    except (OSError, ValueError):
        # A containment path may close a reader that was still blocked in read().
        return
    finally:
        try:
            stream.close()
        except OSError:
            pass


def process_group_popen_kwargs() -> dict[str, Any]:
    """Return the host-specific Popen settings for a managed process tree."""

    if os.name == "posix":
        return {"start_new_session": True}
    if os.name == "nt":
        return {
            "creationflags": int(
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            )
        }
    return {}


def _wait_for_exit(process: subprocess.Popen[Any], timeout: float) -> bool:
    try:
        process.wait(timeout=max(0.0, timeout))
    except (OSError, subprocess.TimeoutExpired):
        return False
    return True


def _kill_process_group(pid: int, signum: int) -> None:
    killpg = getattr(os, "killpg", None)
    if not callable(killpg):
        raise OSError("process-group cleanup is unavailable on this host")
    killpg(pid, signum)


def _posix_group_exists(pid: int) -> bool:
    try:
        _kill_process_group(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        # Permission / platform errors do not prove that the group is gone.
        return True
    return True


def _terminate_process_tree(
    process: subprocess.Popen[Any], limits: ProcessLimits
) -> bool:
    """Terminate a launched command and prove its managed tree has exited."""

    if os.name == "posix":
        try:
            _kill_process_group(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return _wait_for_exit(process, limits.kill_grace_seconds)
        except OSError:
            return False

        deadline = time.monotonic() + limits.termination_grace_seconds
        while time.monotonic() < deadline:
            process.poll()
            if not _posix_group_exists(process.pid):
                return _wait_for_exit(process, limits.kill_grace_seconds)
            time.sleep(0.02)
        try:
            _kill_process_group(
                process.pid, getattr(signal, "SIGKILL", signal.SIGTERM)
            )
        except ProcessLookupError:
            return _wait_for_exit(process, limits.kill_grace_seconds)
        except OSError:
            return False
        deadline = time.monotonic() + limits.kill_grace_seconds
        while time.monotonic() < deadline:
            process.poll()
            if not _posix_group_exists(process.pid):
                return _wait_for_exit(process, limits.kill_grace_seconds)
            time.sleep(0.02)
        return False

    if os.name == "nt":
        # Windows cannot reconstruct descendants after the leader exits, so a
        # departed root is not accepted as proof that the tree is absent.
        if process.poll() is not None:
            return False
        try:
            killed = subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=limits.kill_grace_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return killed.returncode == 0 and _wait_for_exit(
            process, limits.kill_grace_seconds
        )

    return False


def join_pipe_readers(
    readers: list[threading.Thread],
    streams: list[Any],
    timeout_seconds: float = DEFAULT_READER_JOIN_SECONDS,
) -> bool:
    """Boundedly wait for pipe drain without closing under a live reader.

    Closing a buffered pipe while another thread is blocked in ``read()`` can
    itself block on the stream lock.  The caller must terminate the managed
    process tree before retrying a reader that remains alive.
    """

    del streams  # Retained for the historical compatibility signature.
    for reader in readers:
        reader.join(timeout_seconds)
    return not any(reader.is_alive() for reader in readers)


def _join_attempted_pipe_readers(
    readers: list[threading.Thread],
    streams: list[Any],
    timeout_seconds: float,
) -> bool:
    """Boundedly join startup-attempted readers before closing safe pipes.

    ``Thread.start()`` may create a native thread and then raise before Python
    exposes enough state for a caller to distinguish that case from a thread
    that never started.  A failed join is therefore not proof that the
    corresponding stream can be closed without blocking under a live read.
    Streams with no attempted reader are safe to close after process cleanup.
    """

    stopped: list[bool] = []
    first_error: BaseException | None = None
    for reader in readers:
        reader_stopped = False
        try:
            reader_stopped = join_pipe_readers([reader], [], timeout_seconds)
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


def execute_bounded_process(request: BoundedProcessRequest) -> BoundedProcessResult:
    """Execute one request while bounding capture, timeout, and tree cleanup."""

    command = list(request.command)
    limits = request.limits
    kwargs: dict[str, Any] = {
        "cwd": request.cwd,
        "env": request.env,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        **process_group_popen_kwargs(),
    }
    if request.preexec_fn is not None and os.name == "posix":
        kwargs["preexec_fn"] = request.preexec_fn
    process: subprocess.Popen[Any] | None = None
    streams: list[Any] = []
    reader_start_attempts: list[threading.Thread] = []
    tree_cleanup_proven = False
    reader_cleanup_proven = False
    try:
        process = subprocess.Popen(command, **kwargs)
        stdout = process.stdout
        stderr = process.stderr
        streams = [stream for stream in (stdout, stderr) if stream is not None]
        if stdout is None or stderr is None:
            raise ProcessContainmentError(
                "subprocess output pipes were not created"
            )
        capture = BoundedOutput(limits.max_output_bytes)
        readers = [
            threading.Thread(
                target=drain_process_pipe,
                args=(stdout, capture, "stdout", limits.read_chunk_bytes),
                daemon=True,
            ),
            threading.Thread(
                target=drain_process_pipe,
                args=(stderr, capture, "stderr", limits.read_chunk_bytes),
                daemon=True,
            ),
        ]
        for reader in readers:
            # Record before start(): an asynchronous BaseException can arrive
            # after the native thread exists but before start() returns.
            reader_start_attempts.append(reader)
            reader.start()

        def stop_and_prove(reason: str) -> None:
            nonlocal reader_cleanup_proven, tree_cleanup_proven
            if not _terminate_process_tree(process, limits):
                raise ProcessContainmentError(
                    f"{reason}; could not prove subprocess-tree cleanup"
                )
            tree_cleanup_proven = True
            if not join_pipe_readers(
                readers, streams, limits.reader_join_seconds
            ):
                raise ProcessContainmentError(
                    f"{reason}; subprocess output pipes did not close after cleanup"
                )
            reader_cleanup_proven = True

        deadline = time.monotonic() + max(0.0, float(request.timeout_seconds))
        while process.poll() is None:
            if capture.exceeded:
                stop_and_prove("subprocess output limit reached")
                raise ProcessOutputLimitExceeded(limits.max_output_bytes)
            if time.monotonic() >= deadline:
                stop_and_prove("subprocess timed out")
                raise subprocess.TimeoutExpired(
                    command,
                    request.timeout_seconds,
                    output=capture.text("stdout"),
                    stderr=capture.text("stderr"),
                )
            time.sleep(0.02)

        if capture.exceeded:
            stop_and_prove("subprocess output limit reached")
            raise ProcessOutputLimitExceeded(limits.max_output_bytes)
        if not join_pipe_readers(
            readers, streams, limits.reader_join_seconds
        ):
            stop_and_prove("subprocess exited with live output pipes")
            raise ProcessContainmentError(
                "subprocess exited but its output pipes did not close"
            )
        reader_cleanup_proven = True
        if capture.exceeded:
            stop_and_prove("subprocess output limit reached")
            raise ProcessOutputLimitExceeded(limits.max_output_bytes)
        if os.name == "posix":
            if not _terminate_process_tree(process, limits):
                raise ProcessContainmentError(
                    "subprocess completed but post-completion tree cleanup was not proven"
                )
            tree_cleanup_proven = True
        assert process.returncode is not None
        return BoundedProcessResult(
            command=tuple(command),
            returncode=process.returncode,
            stdout=capture.text("stdout"),
            stderr=capture.text("stderr"),
        )
    except BaseException:
        # Cancellation and unexpected reader errors must not leak the runner's
        # own child tree.  The primary exception remains authoritative.
        if process is not None:
            if not tree_cleanup_proven:
                try:
                    # A reaped leader is not proof that its process group has no
                    # surviving descendant, so abort cleanup is unconditional
                    # until one successful proof has already been recorded.
                    _terminate_process_tree(process, limits)
                except BaseException:
                    pass
            if not reader_cleanup_proven:
                try:
                    _join_attempted_pipe_readers(
                        reader_start_attempts,
                        streams,
                        limits.reader_join_seconds,
                    )
                except BaseException:
                    pass
        raise


def run_bounded_subprocess(
    command: Sequence[str],
    *,
    cwd: str | None,
    env: Mapping[str, str] | None,
    timeout: float,
    preexec_fn: Callable[[], object] | None = None,
    limits: ProcessLimits | None = None,
) -> subprocess.CompletedProcess[str]:
    """Subprocess-compatible facade over the typed execution contract."""

    request = BoundedProcessRequest.from_command(
        command,
        cwd=cwd,
        env=env,
        timeout=timeout,
        preexec_fn=preexec_fn,
        limits=limits,
    )
    completed = execute_bounded_process(request).as_completed_process()
    # Preserve the historical subprocess facade: callers that supplied a list
    # observed that same object through CompletedProcess.args. The typed result
    # above remains immutable; only the compatibility surface retains identity.
    completed.args = command
    return completed
