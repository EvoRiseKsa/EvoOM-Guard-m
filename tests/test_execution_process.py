"""Characterization and equivalence tests for the execution process kernel."""

from __future__ import annotations

import ast
import math
import os
import subprocess
import sys
from pathlib import Path

import pytest

from evoom_guard.execution import (
    BoundedProcessRequest,
    ProcessContainmentError,
    ProcessLimits,
    ProcessOutputLimitExceeded,
    execute_bounded_process,
    run_bounded_subprocess,
)
from evoom_guard.verifiers import repo_verifier


def _command(source: str) -> list[str]:
    return [sys.executable, "-c", source]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_output_bytes": -1},
        {"read_chunk_bytes": 0},
        {"termination_grace_seconds": -0.1},
        {"termination_grace_seconds": math.nan},
        {"kill_grace_seconds": -0.1},
        {"reader_join_seconds": -0.1},
    ],
)
def test_process_limits_reject_unbounded_or_invalid_values(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        ProcessLimits(**kwargs)


def test_typed_request_preserves_exit_stdout_and_stderr(tmp_path: Path) -> None:
    request = BoundedProcessRequest.from_command(
        _command(
            "import sys; print('public-out'); "
            "print('public-err', file=sys.stderr); raise SystemExit(7)"
        ),
        cwd=str(tmp_path),
        env=os.environ.copy(),
        timeout=5,
    )

    result = execute_bounded_process(request)

    assert result.command == tuple(request.command)
    assert result.returncode == 7
    assert result.stdout.splitlines() == ["public-out"]
    assert result.stderr.splitlines() == ["public-err"]
    completed = result.as_completed_process()
    assert completed.args == list(request.command)
    assert (completed.returncode, completed.stdout, completed.stderr) == (
        result.returncode,
        result.stdout,
        result.stderr,
    )


def test_legacy_repo_facade_is_equivalent_to_public_runner(tmp_path: Path) -> None:
    command = _command(
        "import sys; sys.stdout.write('same-out'); "
        "sys.stderr.write('same-err'); raise SystemExit(3)"
    )
    kwargs = {
        "cwd": str(tmp_path),
        "env": os.environ.copy(),
        "timeout": 5,
    }

    public = run_bounded_subprocess(command, **kwargs)
    legacy = repo_verifier._run_bounded_subprocess(command, **kwargs)

    assert legacy.args is command
    assert public.args is command
    assert (legacy.args, legacy.returncode, legacy.stdout, legacy.stderr) == (
        public.args,
        public.returncode,
        public.stdout,
        public.stderr,
    )
    assert repo_verifier._SubprocessOutputLimitExceeded is ProcessOutputLimitExceeded
    assert repo_verifier._SubprocessContainmentError is ProcessContainmentError


def test_legacy_capture_uses_current_verifier_limit(monkeypatch) -> None:
    monkeypatch.setattr(repo_verifier, "_MAX_SUBPROCESS_OUTPUT_BYTES", 17)

    capture = repo_verifier._BoundedOutput()

    assert capture.limit == 17


def test_negative_timeout_remains_an_immediate_timeout(tmp_path: Path) -> None:
    command = _command("import time; time.sleep(60)")

    with pytest.raises(subprocess.TimeoutExpired) as exc:
        repo_verifier._run_bounded_subprocess(
            command,
            cwd=str(tmp_path),
            env=os.environ.copy(),
            timeout=-1,
        )

    assert exc.value.timeout == -1


def test_public_runner_timeout_preserves_partial_diagnostics(tmp_path: Path) -> None:
    command = _command(
        "import sys, time; print('before-timeout', flush=True); "
        "print('stderr-before-timeout', file=sys.stderr, flush=True); time.sleep(60)"
    )

    with pytest.raises(subprocess.TimeoutExpired) as exc:
        run_bounded_subprocess(
            command,
            cwd=str(tmp_path),
            env=os.environ.copy(),
            timeout=0.15,
        )

    assert "before-timeout" in (exc.value.output or "")
    assert "stderr-before-timeout" in (exc.value.stderr or "")


def test_public_runner_bounds_combined_output(tmp_path: Path) -> None:
    limit = 4 * 1024
    request = BoundedProcessRequest.from_command(
        _command(
            "import sys, time; sys.stdout.buffer.write(b'o' * 200000); "
            "sys.stderr.buffer.write(b'e' * 200000); "
            "sys.stdout.flush(); sys.stderr.flush(); time.sleep(60)"
        ),
        cwd=str(tmp_path),
        env=os.environ.copy(),
        timeout=10,
        limits=ProcessLimits(max_output_bytes=limit),
    )

    with pytest.raises(ProcessOutputLimitExceeded) as exc:
        execute_bounded_process(request)

    assert exc.value.limit == limit


@pytest.mark.skipif(os.name != "posix", reason="preexec resource limits are POSIX-only")
def test_public_runner_applies_posix_address_space_hook(tmp_path: Path) -> None:
    resource = pytest.importorskip("resource")
    if not hasattr(resource, "RLIMIT_AS"):
        pytest.skip("RLIMIT_AS is unavailable")
    memory_limit = 1024 * 1024 * 1024

    def apply_memory_limit() -> None:
        resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))

    completed = run_bounded_subprocess(
        _command(
            "import resource; "
            "print(resource.getrlimit(resource.RLIMIT_AS)[0])"
        ),
        cwd=str(tmp_path),
        env=os.environ.copy(),
        timeout=5,
        preexec_fn=apply_memory_limit,
    )

    assert completed.returncode == 0
    assert completed.stdout.strip() == str(memory_limit)


def test_execution_consumers_do_not_import_process_primitives_from_verifier() -> None:
    root = Path(__file__).resolve().parents[1] / "evoom_guard"
    extracted = {
        "_BoundedOutput",
        "_drain_subprocess_pipe",
        "_join_pipe_readers",
        "_run_bounded_subprocess",
        "_SubprocessContainmentError",
        "_SubprocessOutputLimitExceeded",
    }

    for relative in ("candidate_runner.py", "blackbox.py"):
        tree = ast.parse((root / relative).read_text(encoding="utf-8"))
        repo_imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module == "evoom_guard.verifiers.repo_verifier"
            for alias in node.names
        }
        execution_imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module == "evoom_guard.execution"
            for alias in node.names
        }
        assert not (repo_imports & extracted)
        assert "run_bounded_subprocess" in execution_imports
