"""Public contracts for EvoOM Guard's internal execution kernel.

The package is intentionally small and stdlib-only.  Callers depend on these
typed contracts instead of importing process helpers from a concrete verifier.
"""

from evoom_guard.execution.process import (
    DEFAULT_KILL_GRACE_SECONDS,
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_READ_CHUNK_BYTES,
    DEFAULT_READER_JOIN_SECONDS,
    DEFAULT_TERMINATION_GRACE_SECONDS,
    BoundedOutput,
    BoundedProcessRequest,
    BoundedProcessResult,
    ProcessContainmentError,
    ProcessLimits,
    ProcessOutputLimitExceeded,
    drain_process_pipe,
    execute_bounded_process,
    join_pipe_readers,
    process_group_popen_kwargs,
    run_bounded_subprocess,
)

__all__ = [
    "DEFAULT_KILL_GRACE_SECONDS",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "DEFAULT_READER_JOIN_SECONDS",
    "DEFAULT_READ_CHUNK_BYTES",
    "DEFAULT_TERMINATION_GRACE_SECONDS",
    "BoundedOutput",
    "BoundedProcessRequest",
    "BoundedProcessResult",
    "ProcessContainmentError",
    "ProcessLimits",
    "ProcessOutputLimitExceeded",
    "drain_process_pipe",
    "execute_bounded_process",
    "join_pipe_readers",
    "process_group_popen_kwargs",
    "run_bounded_subprocess",
]
