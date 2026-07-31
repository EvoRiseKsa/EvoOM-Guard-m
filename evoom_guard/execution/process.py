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
* cancellation preserves the exact active ``BaseException`` while attaching
  bounded diagnostics for every unproved or raised abort-cleanup stage; and
* POSIX resource limits are data, not a caller-supplied ``preexec_fn``. A clean
  exec-based launcher applies them without running Python callbacks in the
  unsafe child interval between ``fork`` and ``exec``.
"""

from __future__ import annotations

import math
import os
import selectors
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

DEFAULT_MAX_OUTPUT_BYTES = 1 * 1024 * 1024
DEFAULT_READ_CHUNK_BYTES = 64 * 1024
DEFAULT_TERMINATION_GRACE_SECONDS = 1.0
DEFAULT_KILL_GRACE_SECONDS = 3.0
DEFAULT_READER_JOIN_SECONDS = 2.0
_POSIX_RLIMIT_LAUNCHER_FLAG = "--_evoguard-posix-rlimit-launcher"
_POSIX_EXEC_ATTEMPT_STATUS = b"exec-attempt\n"
_POSIX_EXEC_ERROR_PREFIX = b"exec:"
_POSIX_LAUNCHER_ERROR_STATUS = b"launcher\n"
_POSIX_EXEC_STATUS_MAX_BYTES = 64
_POSIX_RLIMIT_LAUNCHER_SOURCE = r"""
import errno
import os
import sys

def write_status(descriptor, payload):
    try:
        while payload:
            written = os.write(descriptor, payload)
            if written <= 0:
                return False
            payload = payload[written:]
    except OSError:
        return False
    return True

exec_status_fd = None
exec_error_reported = False
try:
    arguments = sys.argv[1:]
    if (
        os.name != "posix"
        or len(arguments) < 4
        or arguments[0] != "--_evoguard-posix-rlimit-launcher"
    ):
        raise ValueError("invalid EvoGuard POSIX rlimit launcher invocation")
    exec_status_fd = int(arguments[3])
    if exec_status_fd < 0:
        raise ValueError("POSIX rlimit launcher status descriptor is invalid")
    os.set_inheritable(exec_status_fd, False)
    if len(arguments) < 6 or arguments[4] != "--":
        raise ValueError("invalid EvoGuard POSIX rlimit launcher invocation")

    def parse_limit(value):
        parsed = int(value)
        if parsed == -1:
            return None
        if parsed <= 0:
            raise ValueError("launcher limits must be positive integers or -1")
        return parsed

    cpu_seconds = parse_limit(arguments[1])
    address_space_bytes = parse_limit(arguments[2])
    command = arguments[5:]
    if not command:
        raise ValueError("POSIX rlimit launcher command is empty")

    import resource

    if cpu_seconds is not None:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
    if address_space_bytes is not None:
        # A requested containment limit is part of the verdict boundary. If
        # this platform cannot apply it, abort the launcher with status 125;
        # silently running the candidate without the promised cap would be a
        # fail-open isolation defect.
        resource.setrlimit(
            resource.RLIMIT_AS,
            (address_space_bytes, address_space_bytes),
        )
    if not write_status(exec_status_fd, b"exec-attempt\n"):
        raise OSError("could not report target exec attempt")
    try:
        os.execvpe(command[0], command, os.environ)
    except OSError as exc:
        error_number = (
            exc.errno
            if isinstance(exc.errno, int) and exc.errno > 0
            else errno.EIO
        )
        exec_error_reported = write_status(
            exec_status_fd,
            ("exec:" + str(error_number) + "\n").encode("ascii"),
        )
        raise
except BaseException as exc:
    if exec_status_fd is not None and not exec_error_reported:
        write_status(exec_status_fd, b"launcher\n")
    diagnostic = (
        "EvoGuard POSIX rlimit launcher failed: "
        + type(exc).__name__
        + ": "
        + str(exc)
        + "\n"
    ).encode("utf-8", errors="replace")[:4096]
    try:
        os.write(2, diagnostic)
    except OSError:
        pass
    raise SystemExit(125)
"""


@dataclass(frozen=True, slots=True)
class PosixRLimitSpec:
    """Serializable POSIX resource limits for the exec-based child launcher."""

    cpu_seconds: int | None = None
    address_space_bytes: int | None = None

    def __post_init__(self) -> None:
        for name, value in (
            ("cpu_seconds", self.cpu_seconds),
            ("address_space_bytes", self.address_space_bytes),
        ):
            if value is not None and (type(value) is not int or value <= 0):
                raise ValueError(f"{name} must be a positive integer or None")


@dataclass(frozen=True, slots=True)
class ProcessLimits:
    """Bounded resources controlled directly by the process runner.

    Address-space and CPU limits remain caller policy and are supplied as a
    :class:`PosixRLimitSpec`. These fields govern only output retention and
    bounded cleanup waits.
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
    # The compatibility spelling is retained for internal call sites while the
    # value is now inert data. Arbitrary callback execution is rejected.
    preexec_fn: PosixRLimitSpec | None = None
    limits: ProcessLimits = field(default_factory=ProcessLimits)
    require_process_group_cleanup_proof: bool = False

    def __post_init__(self) -> None:
        if self.preexec_fn is not None and type(self.preexec_fn) is not PosixRLimitSpec:
            raise ValueError("preexec_fn callbacks are unsafe; pass PosixRLimitSpec data instead")
        if type(self.require_process_group_cleanup_proof) is not bool:
            raise ValueError("require_process_group_cleanup_proof must be a bool")

    @classmethod
    def from_command(
        cls,
        command: Sequence[str],
        *,
        cwd: str | None,
        env: Mapping[str, str] | None,
        timeout: float,
        preexec_fn: PosixRLimitSpec | None = None,
        limits: ProcessLimits | None = None,
        require_process_group_cleanup_proof: bool = False,
    ) -> BoundedProcessRequest:
        """Freeze a caller command into the execution request contract."""

        return cls(
            command=tuple(command),
            cwd=cwd,
            env=env,
            timeout_seconds=timeout,
            preexec_fn=preexec_fn,
            limits=ProcessLimits() if limits is None else limits,
            require_process_group_cleanup_proof=(require_process_group_cleanup_proof),
        )


@dataclass(frozen=True, slots=True)
class BoundedProcessResult:
    """Completed process facts before adaptation to ``CompletedProcess``."""

    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    target_started: bool = True

    def as_completed_process(self) -> subprocess.CompletedProcess[str]:
        """Return the historical subprocess-compatible result surface."""

        completed = subprocess.CompletedProcess(
            list(self.command),
            self.returncode,
            stdout=self.stdout,
            stderr=self.stderr,
        )
        completed.target_started = self.target_started  # type: ignore[attr-defined]
        return completed


class ProcessOutputLimitExceeded(RuntimeError):
    """A managed command exceeded the shared diagnostic-output budget."""

    def __init__(self, limit: int = DEFAULT_MAX_OUTPUT_BYTES) -> None:
        self.limit = limit
        super().__init__(
            f"candidate subprocess output exceeded the {self.limit}-byte judge capture limit"
        )


class ProcessContainmentError(RuntimeError):
    """The runner could not prove cleanup of its managed process tree."""


class ProcessTargetStartError(ProcessContainmentError):
    """The runner could not prove that the requested target reached exec."""

    target_started = False


class ProcessGroupCleanupUnavailable(ProcessTargetStartError):
    """The host cannot provide the requested process-group cleanup proof."""


_MAX_ABORT_CLEANUP_NOTE_CHARS = 2_000
_ABORT_CLEANUP_NOTE_ELLIPSIS = "..."


def _abort_cleanup_exception_type_name(error: BaseException) -> str:
    """Return one exact exception type name without consulting its instance."""

    try:
        name = type(error).__name__
    except BaseException:
        return "BaseException"
    return name if type(name) is str else "BaseException"


def _bounded_abort_cleanup_text(value: object) -> str:
    """Render one bounded exact ``str`` without trusting subclass hooks."""

    try:
        if isinstance(value, str):
            rendered = value if type(value) is str else str.__str__(value)
        else:
            rendered = str(value)
            if type(rendered) is not str:
                rendered = str.__str__(rendered)
    except BaseException:
        rendered = "<unprintable>"
    if type(rendered) is not str:
        rendered = "<unprintable>"
    if len(rendered) <= _MAX_ABORT_CLEANUP_NOTE_CHARS:
        return rendered
    keep = _MAX_ABORT_CLEANUP_NOTE_CHARS - len(_ABORT_CLEANUP_NOTE_ELLIPSIS)
    return rendered[:keep] + _ABORT_CLEANUP_NOTE_ELLIPSIS


def _abort_cleanup_exception_summary(error: BaseException) -> str:
    """Describe a cleanup exception even when its ``__str__`` is hostile."""

    error_type = _abort_cleanup_exception_type_name(error)
    try:
        detail = _bounded_abort_cleanup_text(str(error))
    except BaseException as stringify_error:
        detail = (
            "<unprintable; __str__ raised "
            + _abort_cleanup_exception_type_name(stringify_error)
            + ">"
        )
    return _bounded_abort_cleanup_text(error_type + ": " + detail)


def _note_abort_cleanup_failure(primary: BaseException, message: object) -> None:
    """Attach secondary cleanup evidence without ever replacing ``primary``.

    Python 3.11+ renders ``BaseException.add_note`` values in tracebacks.  The
    direct ``__notes__`` fallback retains the same machine-readable fact on
    Python 3.10 and when an exception exposes a hostile ``add_note`` override.
    """

    note = _bounded_abort_cleanup_text(message)
    try:
        add_note = getattr(primary, "add_note", None)
        if callable(add_note):
            add_note(note)
            return
    except BaseException:
        # Fall through to the BaseException instance dictionary.  Reporting is
        # secondary and may never mask the active cancellation/error.
        pass
    try:
        namespace = object.__getattribute__(primary, "__dict__")
        notes = namespace.get("__notes__")
        if type(notes) is list:
            notes.append(note)
        else:
            namespace["__notes__"] = [note]
    except BaseException:
        pass


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
        return {"creationflags": int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))}
    return {}


def _posix_rlimit_launcher_command(
    command: list[str],
    limits: PosixRLimitSpec,
    exec_status_fd: int,
) -> list[str]:
    """Wrap ``command`` in a clean interpreter that applies POSIX rlimits.

    ``-I -S`` keeps candidate-controlled Python startup hooks out of the
    launcher. The helper then ``exec``-replaces itself, preserving the managed
    PID/session and inherited output pipes.
    """

    return [
        sys.executable,
        "-I",
        "-S",
        "-c",
        _POSIX_RLIMIT_LAUNCHER_SOURCE,
        _POSIX_RLIMIT_LAUNCHER_FLAG,
        "-1" if limits.cpu_seconds is None else str(limits.cpu_seconds),
        ("-1" if limits.address_space_bytes is None else str(limits.address_space_bytes)),
        str(exec_status_fd),
        "--",
        *command,
    ]


def _open_posix_exec_status_pipe() -> tuple[int, int]:
    """Create non-inheritable status descriptors outside the stdio range."""

    read_fd, write_fd = os.pipe()
    low_fds: list[int] = []
    try:
        while read_fd < 3:
            low_fds.append(read_fd)
            read_fd = os.dup(read_fd)
        while write_fd < 3:
            low_fds.append(write_fd)
            write_fd = os.dup(write_fd)
        os.set_inheritable(read_fd, False)
        os.set_inheritable(write_fd, False)
    except BaseException:
        for descriptor in {*low_fds, read_fd, write_fd}:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise
    for descriptor in low_fds:
        try:
            os.close(descriptor)
        except OSError:
            pass
    return read_fd, write_fd


def _read_posix_exec_status(
    descriptor: int,
    *,
    deadline: float,
) -> tuple[str, int | None] | None:
    """Read the trusted launcher's CLOEXEC status pipe within the run budget."""

    payload = bytearray()
    try:
        status_selector = selectors.DefaultSelector()
    except (OSError, ValueError) as exc:
        raise ProcessTargetStartError("could not open the POSIX launcher status channel") from exc
    try:
        status_selector.register(descriptor, selectors.EVENT_READ)
    except (OSError, ValueError) as exc:
        status_selector.close()
        raise ProcessTargetStartError("could not open the POSIX launcher status channel") from exc
    try:
        while True:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                readable = status_selector.select(remaining)
            except InterruptedError:
                continue
            except (OSError, ValueError) as exc:
                raise ProcessTargetStartError(
                    "could not read the POSIX launcher status channel"
                ) from exc
            if not readable:
                raise TimeoutError("POSIX launcher did not reach exec before timeout")
            try:
                chunk = os.read(
                    descriptor,
                    _POSIX_EXEC_STATUS_MAX_BYTES + 1 - len(payload),
                )
            except InterruptedError:
                continue
            except OSError as exc:
                raise ProcessTargetStartError(
                    "could not read the POSIX launcher status channel"
                ) from exc
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > _POSIX_EXEC_STATUS_MAX_BYTES:
                raise ProcessTargetStartError("POSIX launcher status exceeded its bounded contract")
    finally:
        try:
            status_selector.close()
        except OSError:
            pass

    if not payload:
        raise ProcessTargetStartError(
            "POSIX launcher status closed without a launch record"
        )
    if payload == _POSIX_LAUNCHER_ERROR_STATUS:
        return ("launcher", None)
    if payload == _POSIX_EXEC_ATTEMPT_STATUS:
        return None
    expected_exec_prefix = _POSIX_EXEC_ATTEMPT_STATUS + _POSIX_EXEC_ERROR_PREFIX
    if (
        not payload.startswith(expected_exec_prefix)
        or not payload.endswith(b"\n")
        or not payload[len(expected_exec_prefix) : -1].isdigit()
    ):
        raise ProcessTargetStartError("POSIX launcher status was malformed")
    error_number = int(payload[len(expected_exec_prefix) : -1])
    if error_number <= 0 or error_number > (2**31 - 1):
        raise ProcessTargetStartError("POSIX launcher errno was invalid")
    return ("exec", error_number)


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


def _terminate_process_tree(process: subprocess.Popen[Any], limits: ProcessLimits) -> bool:
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
            _kill_process_group(process.pid, getattr(signal, "SIGKILL", signal.SIGTERM))
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
        return killed.returncode == 0 and _wait_for_exit(process, limits.kill_grace_seconds)

    return False


def terminate_process_tree(process: subprocess.Popen[Any], limits: ProcessLimits) -> bool:
    """Terminate a process in its managed launch group and prove cleanup.

    The process must have been launched with ``process_group_popen_kwargs()``.
    A return value from an arbitrary ``Popen`` instance is not a process-tree
    cleanup proof.
    """

    return _terminate_process_tree(process, limits)


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
    launch_command = command
    limits = request.limits
    if request.require_process_group_cleanup_proof and (
        os.name != "posix" or not callable(getattr(os, "killpg", None))
    ):
        raise ProcessGroupCleanupUnavailable(
            "process-group cleanup proof requires POSIX process-group support "
            "and is unavailable on this host"
        )
    kwargs: dict[str, Any] = {
        "cwd": request.cwd,
        "env": request.env,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        **process_group_popen_kwargs(),
    }
    # Charge the trusted launcher's exec-status handshake to the same wall-clock
    # budget as the target process.
    deadline = time.monotonic() + max(0.0, float(request.timeout_seconds))
    exec_status_read_fd: int | None = None
    exec_status_write_fd: int | None = None
    process: subprocess.Popen[Any] | None = None
    streams: list[Any] = []
    reader_start_attempts: list[threading.Thread] = []
    tree_cleanup_proven = False
    reader_cleanup_proven = False
    target_started = False
    try:
        if request.preexec_fn is not None and os.name == "posix":
            try:
                exec_status_read_fd, exec_status_write_fd = (
                    _open_posix_exec_status_pipe()
                )
            except OSError as exc:
                raise ProcessTargetStartError(
                    "could not create the POSIX launcher status channel"
                ) from exc
            kwargs["pass_fds"] = (exec_status_write_fd,)
            launch_command = _posix_rlimit_launcher_command(
                command,
                request.preexec_fn,
                exec_status_write_fd,
            )
        try:
            process = subprocess.Popen(launch_command, **kwargs)
        except BaseException as exc:
            if exec_status_write_fd is not None:
                try:
                    os.close(exec_status_write_fd)
                except OSError:
                    pass
                exec_status_write_fd = None
            if exec_status_read_fd is not None and isinstance(exc, OSError):
                raise ProcessTargetStartError(
                    "could not start the trusted POSIX resource-limit launcher"
                ) from exc
            if exec_status_read_fd is None and isinstance(exc, OSError):
                try:
                    exc.target_exec_failed = True  # type: ignore[attr-defined]
                except (AttributeError, TypeError):
                    pass
            raise
        if exec_status_write_fd is not None:
            try:
                os.close(exec_status_write_fd)
            except OSError as exc:
                exec_status_write_fd = None
                raise ProcessTargetStartError(
                    "could not close the parent POSIX launcher status channel"
                ) from exc
            exec_status_write_fd = None
        if exec_status_read_fd is None:
            # Ordinary Popen does not return until the requested target either
            # reached exec or raised its startup error through Python's errpipe.
            target_started = True
        stdout = process.stdout
        stderr = process.stderr
        streams = [stream for stream in (stdout, stderr) if stream is not None]
        if stdout is None or stderr is None:
            raise ProcessContainmentError("subprocess output pipes were not created")
        if exec_status_read_fd is not None:
            try:
                try:
                    exec_status = _read_posix_exec_status(
                        exec_status_read_fd,
                        deadline=deadline,
                    )
                except TimeoutError:
                    timeout_error = subprocess.TimeoutExpired(
                        command,
                        request.timeout_seconds,
                    )
                    timeout_error.target_started = False  # type: ignore[attr-defined]
                    raise timeout_error from None
            finally:
                try:
                    os.close(exec_status_read_fd)
                except OSError:
                    pass
                exec_status_read_fd = None
            if exec_status is not None:
                status_kind, error_number = exec_status
                if status_kind == "launcher":
                    target_started = False
                else:
                    assert status_kind == "exec"
                    assert error_number is not None
                    exec_error = OSError(
                        error_number,
                        os.strerror(error_number),
                        command[0],
                    )
                    exec_error.target_exec_failed = True  # type: ignore[attr-defined]
                    raise exec_error
            else:
                # The trusted launcher reported that it reached the exec call,
                # and CLOEXEC then closed the descriptor without an exec error.
                target_started = True
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
                raise ProcessContainmentError(f"{reason}; could not prove subprocess-tree cleanup")
            tree_cleanup_proven = True
            if not join_pipe_readers(readers, streams, limits.reader_join_seconds):
                raise ProcessContainmentError(
                    f"{reason}; subprocess output pipes did not close after cleanup"
                )
            reader_cleanup_proven = True

        # Re-read the clock after process and reader startup so that launcher
        # setup is charged to the timeout even when the child is already close
        # to completion before the normal polling loop begins.
        startup_deadline_reached = time.monotonic() >= deadline
        if startup_deadline_reached and process.poll() is None:
            stop_and_prove("subprocess timed out")
            raise subprocess.TimeoutExpired(
                command,
                request.timeout_seconds,
                output=capture.text("stdout"),
                stderr=capture.text("stderr"),
            )

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
        if not join_pipe_readers(readers, streams, limits.reader_join_seconds):
            stop_and_prove("subprocess exited with live output pipes")
            raise ProcessContainmentError("subprocess exited but its output pipes did not close")
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
            target_started=target_started,
        )
    except BaseException as primary:
        # Cancellation and unexpected reader errors must not leak the runner's
        # own child tree.  The primary exception remains authoritative.
        try:
            primary.target_started = target_started  # type: ignore[attr-defined]
        except (AttributeError, TypeError):
            pass
        for descriptor in (exec_status_read_fd, exec_status_write_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if process is not None:
            if not tree_cleanup_proven:
                try:
                    # A reaped leader is not proof that its process group has no
                    # surviving descendant, so abort cleanup is unconditional
                    # until one successful proof has already been recorded.
                    tree_cleanup_result = _terminate_process_tree(process, limits)
                except BaseException as cleanup_error:
                    _note_abort_cleanup_failure(
                        primary,
                        "Managed subprocess-tree abort cleanup raised while "
                        "preserving the primary exception: "
                        + _abort_cleanup_exception_summary(cleanup_error),
                    )
                else:
                    if tree_cleanup_result is True:
                        tree_cleanup_proven = True
                    else:
                        _note_abort_cleanup_failure(
                            primary,
                            "Managed subprocess-tree abort cleanup was not "
                            "proven while preserving the primary exception",
                        )
            if not reader_cleanup_proven:
                try:
                    reader_cleanup_result = _join_attempted_pipe_readers(
                        reader_start_attempts,
                        streams,
                        limits.reader_join_seconds,
                    )
                except BaseException as cleanup_error:
                    _note_abort_cleanup_failure(
                        primary,
                        "Managed subprocess output-reader abort cleanup raised "
                        "while preserving the primary exception: "
                        + _abort_cleanup_exception_summary(cleanup_error),
                    )
                else:
                    if reader_cleanup_result is True:
                        reader_cleanup_proven = True
                    else:
                        _note_abort_cleanup_failure(
                            primary,
                            "Managed subprocess output-reader abort cleanup was "
                            "not proven while preserving the primary exception",
                        )
        raise


def run_bounded_subprocess(
    command: Sequence[str],
    *,
    cwd: str | None,
    env: Mapping[str, str] | None,
    timeout: float,
    preexec_fn: PosixRLimitSpec | None = None,
    limits: ProcessLimits | None = None,
    require_process_group_cleanup_proof: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Subprocess-compatible facade over the typed execution contract."""

    request = BoundedProcessRequest.from_command(
        command,
        cwd=cwd,
        env=env,
        timeout=timeout,
        preexec_fn=preexec_fn,
        limits=limits,
        require_process_group_cleanup_proof=require_process_group_cleanup_proof,
    )
    completed = execute_bounded_process(request).as_completed_process()
    # Preserve the historical subprocess facade: callers that supplied a list
    # observed that same object through CompletedProcess.args. The typed result
    # above remains immutable; only the compatibility surface retains identity.
    completed.args = command
    return completed
