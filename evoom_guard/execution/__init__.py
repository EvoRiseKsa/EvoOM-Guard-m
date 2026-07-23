"""Public contracts for EvoOM Guard's internal execution kernel.

The package is intentionally small and stdlib-only.  Callers depend on these
typed contracts instead of importing process helpers from a concrete verifier.
"""

# isort: off
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
    ProcessGroupCleanupUnavailable,
    ProcessLimits,
    ProcessOutputLimitExceeded,
    drain_process_pipe,
    execute_bounded_process,
    join_pipe_readers,
    process_group_popen_kwargs,
    run_bounded_subprocess,
    terminate_process_tree,
)
from evoom_guard.execution.judge import (
    JudgeOutputLimitError,
    JudgeProcessCleanupError,
    JudgeProcessLimits,
    JudgeProcessRequest,
    JudgeProcessResult,
    execute_judge_process,
)
from evoom_guard.execution.command import resolve_host_command
# isort: on

__all__ = [
    "DEFAULT_KILL_GRACE_SECONDS",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "DEFAULT_READER_JOIN_SECONDS",
    "DEFAULT_READ_CHUNK_BYTES",
    "DEFAULT_TERMINATION_GRACE_SECONDS",
    "JudgeOutputLimitError",
    "JudgeProcessCleanupError",
    "JudgeProcessLimits",
    "JudgeProcessRequest",
    "JudgeProcessResult",
    "BoundedOutput",
    "BoundedProcessRequest",
    "BoundedProcessResult",
    "ProcessContainmentError",
    "ProcessGroupCleanupUnavailable",
    "ProcessLimits",
    "ProcessOutputLimitExceeded",
    "drain_process_pipe",
    "execute_bounded_process",
    "execute_judge_process",
    "join_pipe_readers",
    "process_group_popen_kwargs",
    "run_bounded_subprocess",
    "resolve_host_command",
    "terminate_process_tree",
]
