"""Run a deterministic, bounded mutation gate over assurance-sensitive logic.

This is intentionally smaller than a general mutation framework.  Every mutant
models a reviewed security regression, must apply exactly once, and is executed
against one focused test in an isolated package overlay.  A mutant is killed
only by a normal pytest assertion failure (exit 1); collection errors, timeouts,
and infrastructure failures fail the gate instead of becoming false positives.

The outer watchdog is a liveness guard, not a sandbox.  On POSIX it can stop
only processes that remain in pytest's dedicated process group; a descendant
that deliberately creates a new session escapes that boundary.  Real-process
mutation contracts therefore terminate by themselves even when their target
check is bypassed, and an outer timeout is always an infrastructure error.
"""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Mutation:
    name: str
    path: str
    before: str
    after: str
    test: str


MUTATIONS = (
    Mutation(
        name="invocation-drain-batch-limit-bypass",
        path="evoom_guard/isolation/invocation.py",
        before=(
            "            for _ in range("
            "_MAX_INVOCATION_DATAGRAMS_PER_DRAIN):\n"
        ),
        after=(
            "            for _ in range("
            "_MAX_INVOCATION_DATAGRAMS_PER_DRAIN + 1):\n"
        ),
        test=(
            "tests/test_blackbox_invocation_recorder.py::"
            "test_flooded_receiver_has_a_bounded_lock_hold_and_close_path"
        ),
    ),
    Mutation(
        name="invocation-drain-stop-check-bypass",
        path="evoom_guard/isolation/invocation.py",
        before="                if self._stop.is_set() and not final:\n",
        after="                if False and self._stop.is_set() and not final:\n",
        test=(
            "tests/test_blackbox_invocation_recorder.py::"
            "test_stopped_background_drain_does_not_read_an_unbounded_source"
        ),
    ),
    Mutation(
        name="invocation-post-bind-unlink-bypass",
        path="evoom_guard/isolation/invocation.py",
        before=(
            "    if bound:\n"
            "        try:\n"
            "            os.unlink(path)\n"
        ),
        after=(
            "    if False and bound:\n"
            "        try:\n"
            "            os.unlink(path)\n"
        ),
        test=(
            "tests/test_blackbox_invocation_recorder.py::"
            "test_post_bind_failure_closes_and_unlinks_socket[chmod]"
        ),
    ),
    Mutation(
        name="judge-reader-start-cleanup-bypass",
        path="evoom_guard/blackbox.py",
        before=(
            "                _terminate_judge_process_group(process)\n"
            "            except BaseException:\n"
            "                # An active primary exception must not be replaced by cleanup.\n"
        ),
        after=(
            "                pass\n"
            "            except BaseException:\n"
            "                # An active primary exception must not be replaced by cleanup.\n"
        ),
        test=(
            "tests/test_blackbox_judge_reader_start.py::"
            "test_reader_start_failure_cleans_group_handles_pipes_and_preserves_primary"
        ),
    ),
    Mutation(
        name="judge-reader-start-tracking-bypass",
        path="evoom_guard/blackbox.py",
        before=(
            "            reader_start_attempts.append(reader)\n"
            "            reader.start()\n"
        ),
        after="            reader.start()\n",
        test=(
            "tests/test_blackbox_judge_reader_start.py::"
            "test_reader_start_failure_cleans_group_handles_pipes_and_preserves_primary"
        ),
    ),
    Mutation(
        name="judge-reader-start-pipe-close-bypass",
        path="evoom_guard/blackbox.py",
        before="        safe_to_close = index >= len(stopped) or stopped[index]\n",
        after="        safe_to_close = False\n",
        test=(
            "tests/test_blackbox_judge_reader_start.py::"
            "test_reader_start_failure_cleans_group_handles_pipes_and_preserves_primary"
        ),
    ),
    Mutation(
        name="judge-live-reader-synchronous-close",
        path="evoom_guard/blackbox.py",
        before=(
            "        if not safe_to_close:\n"
            "            streams_closed = False\n"
            "            continue\n"
        ),
        after=(
            "        if False and not safe_to_close:\n"
            "            streams_closed = False\n"
            "            continue\n"
        ),
        test=(
            "tests/test_blackbox_judge_reader_start.py::"
            "test_live_reader_pipe_is_never_closed_synchronously"
        ),
    ),
    Mutation(
        name="judge-attempted-reader-ident-proof-bypass",
        path="evoom_guard/blackbox.py",
        before=(
            "        except RuntimeError as exc:\n"
            "            # An interrupted Thread.start() can create the native thread before\n"
            "            # ``ident`` or ``_started`` becomes observable. A failed join is\n"
            "            # therefore never proof that the corresponding pipe is safe to\n"
            "            # close, even when ``reader.ident is None``.\n"
            "            if first_error is None:\n"
            "                first_error = exc\n"
        ),
        after=(
            "        except RuntimeError as exc:\n"
            "            # Mutant: treat missing ident as proof that no native reader exists.\n"
            "            reader_stopped = reader.ident is None\n"
            "            if not reader_stopped and first_error is None:\n"
            "                first_error = exc\n"
        ),
        test=(
            "tests/test_blackbox_judge_reader_start.py::"
            "test_attempted_reader_without_ident_is_not_assumed_safe_to_close"
        ),
    ),
    Mutation(
        name="judge-reader-start-primary-exception-mask",
        path="evoom_guard/blackbox.py",
        before=(
            "                _join_judge_pipe_readers(reader_start_attempts, streams)\n"
            "            except BaseException:\n"
            "                pass\n"
        ),
        after=(
            "                _join_judge_pipe_readers(reader_start_attempts, streams)\n"
            "            except BaseException:\n"
            "                raise\n"
        ),
        test=(
            "tests/test_blackbox_judge_reader_start.py::"
            "test_reader_start_primary_survives_every_cleanup_baseexception"
        ),
    ),
    Mutation(
        name="judge-reader-start-terminator-baseexception-mask",
        path="evoom_guard/blackbox.py",
        before=(
            "                _terminate_judge_process_group(process)\n"
            "            except BaseException:\n"
            "                # An active primary exception must not be replaced by cleanup.\n"
        ),
        after=(
            "                _terminate_judge_process_group(process)\n"
            "            except Exception:\n"
            "                # An active primary exception must not be replaced by cleanup.\n"
        ),
        test=(
            "tests/test_blackbox_judge_reader_start.py::"
            "test_reader_start_primary_survives_every_cleanup_baseexception"
        ),
    ),
    Mutation(
        name="docker-absence-daemon-failure-bypass",
        path="evoom_guard/isolation/docker.py",
        before=(
            "            absent=None,\n"
            "            query=listed,\n"
            '            error="docker_query_failed",\n'
        ),
        after=(
            "            absent=True,\n"
            "            query=listed,\n"
            '            error="docker_query_failed",\n'
        ),
        test=(
            "tests/test_isolation_docker.py::"
            "test_kernel_absence_query_rejects_daemon_failure"
        ),
    ),
    Mutation(
        name="docker-absence-present-name-bypass",
        path="evoom_guard/isolation/docker.py",
        before="        absent=name not in listed.stdout.splitlines(),\n",
        after="        absent=True,\n",
        test=(
            "tests/test_isolation_docker.py::"
            "test_kernel_absence_query_requires_success_and_exact_name"
        ),
    ),
    Mutation(
        name="docker-absence-stopped-container-bypass",
        path="evoom_guard/isolation/docker.py",
        before='                "--all",\n                "--filter",\n',
        after='                "--filter",\n',
        test=(
            "tests/test_isolation_docker.py::"
            "test_kernel_absence_query_requires_success_and_exact_name"
        ),
    ),
    Mutation(
        name="docker-absence-name-validation-bypass",
        path="evoom_guard/isolation/docker.py",
        before=(
            "    return _DOCKER_CONTAINER_NAME.fullmatch(name) is not None\n"
        ),
        after="    return True\n",
        test=(
            "tests/test_isolation_docker.py::"
            "test_kernel_absence_query_rejects_invalid_name_without_docker"
        ),
    ),
    Mutation(
        name="docker-absence-stability-streak-bypass",
        path="evoom_guard/isolation/docker.py",
        before=(
            "    proven = (\n"
            "        final_absent_observations\n"
            "        >= required_final_absent_observations\n"
            "    )\n"
        ),
        after="    proven = final_absent_observations > 0\n",
        test=(
            "tests/test_isolation_docker.py::"
            "test_kernel_cleanup_rejects_absence_not_stable_at_window_end"
        ),
    ),
    Mutation(
        name="docker-cleanup-total-budget-bypass",
        path="evoom_guard/isolation/docker.py",
        before="        return min(control_timeout, remaining)\n",
        after="        return control_timeout\n",
        test=(
            "tests/test_isolation_docker.py::"
            "test_kernel_cleanup_uses_decreasing_single_total_budget"
        ),
    ),
    Mutation(
        name="docker-cleanup-unverifiable-retry-bypass",
        path="evoom_guard/isolation/docker.py",
        before="        if not observation.observed:\n",
        after="        if False and not observation.observed:\n",
        test=(
            "tests/test_isolation_docker.py::"
            "test_kernel_cleanup_stops_immediately_when_absence_is_unverifiable"
        ),
    ),
    Mutation(
        name="protected-edit-preflight-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before="        if rejection is not None:\n            return rejection\n",
        after="        if False and rejection is not None:\n            return rejection\n",
        test=(
            "tests/test_repo_verifier_characterization.py::"
            "test_frozen_repo_verifier_behavior_and_evidence[protected_test_edit]"
        ),
    ),
    Mutation(
        name="protected-deletion-preflight-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "            if del_rejection is not None:\n"
            "                return del_rejection\n"
        ),
        after=(
            "            if False and del_rejection is not None:\n"
            "                return del_rejection\n"
        ),
        test=(
            "tests/test_repo_verifier_characterization.py::"
            "test_frozen_repo_verifier_behavior_and_evidence[deleted_protected_test]"
        ),
    ),
    Mutation(
        name="strict-harness-exit-only-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before="            if strict_harness and (junit is None or junit.total <= 0):\n",
        after="            if False and strict_harness and (junit is None or junit.total <= 0):\n",
        test=(
            "tests/test_repo_verifier_characterization.py::"
            "test_frozen_repo_verifier_behavior_and_evidence[strict_exit_only_rejected]"
        ),
    ),
    Mutation(
        name="junit-exit-disagreement-bypass",
        path="evoom_guard/verifiers/junit_oracle.py",
        before="    if has_failures and returncode == 0:\n        return True\n",
        after="    if False and has_failures and returncode == 0:\n        return True\n",
        test=(
            "tests/test_repo_verifier_characterization.py::"
            "test_frozen_repo_verifier_behavior_and_evidence[junit_tamper]"
        ),
    ),
    Mutation(
        name="junit-doctype-filter-bypass",
        path="evoom_guard/verifiers/junit_oracle.py",
        before='    if "<!DOCTYPE" in xml_text or "<!ENTITY" in xml_text:\n        return None\n',
        after=(
            '    if False and ("<!DOCTYPE" in xml_text or "<!ENTITY" in xml_text):\n'
            "        return None\n"
        ),
        test="tests/test_junit_hardening.py::test_rejects_doctype_billion_laughs_without_expanding",
    ),
    Mutation(
        name="subprocess-output-cap-bypass",
        path="evoom_guard/execution/process.py",
        before="                self._exceeded = True\n",
        after="                self._exceeded = False\n",
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_bounded_output_marks_any_truncated_bytes_as_exceeded"
        ),
    ),
    Mutation(
        name="subprocess-live-output-check-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "        while process.poll() is None:\n"
            "            if capture.exceeded:\n"
            '                stop_and_prove("subprocess output limit reached")\n'
        ),
        after=(
            "        while process.poll() is None:\n"
            "            if False and capture.exceeded:\n"
            '                stop_and_prove("subprocess output limit reached")\n'
        ),
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_live_output_overflow_is_stopped_before_process_completion"
        ),
    ),
    Mutation(
        name="subprocess-post-poll-output-check-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "        if capture.exceeded:\n"
            '            stop_and_prove("subprocess output limit reached")\n'
            "            raise ProcessOutputLimitExceeded(limits.max_output_bytes)\n"
            "        if not join_pipe_readers(\n"
        ),
        after=(
            "        if False and capture.exceeded:\n"
            '            stop_and_prove("subprocess output limit reached")\n'
            "            raise ProcessOutputLimitExceeded(limits.max_output_bytes)\n"
            "        if not join_pipe_readers(\n"
        ),
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_post_poll_overflow_stops_before_normal_reader_join"
        ),
    ),
    Mutation(
        name="subprocess-post-join-output-check-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "        if capture.exceeded:\n"
            '            stop_and_prove("subprocess output limit reached")\n'
            "            raise ProcessOutputLimitExceeded(limits.max_output_bytes)\n"
            '        if os.name == "posix" and not _terminate_process_tree(process, limits):\n'
        ),
        after=(
            "        if False and capture.exceeded:\n"
            '            stop_and_prove("subprocess output limit reached")\n'
            "            raise ProcessOutputLimitExceeded(limits.max_output_bytes)\n"
            '        if os.name == "posix" and not _terminate_process_tree(process, limits):\n'
        ),
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_post_join_overflow_is_not_returned_as_success"
        ),
    ),
    Mutation(
        name="subprocess-deadline-check-bypass",
        path="evoom_guard/execution/process.py",
        before="            if time.monotonic() >= deadline:\n",
        after="            if False and time.monotonic() >= deadline:\n",
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_deadline_interrupts_a_self_terminating_process"
        ),
    ),
    Mutation(
        name="subprocess-cleanup-proof-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "        if not _terminate_process_tree(process, limits):\n"
            "            raise ProcessContainmentError(\n"
            '                f"{reason}; could not prove subprocess-tree cleanup"\n'
            "            )\n"
        ),
        after=(
            "        if False and not _terminate_process_tree(process, limits):\n"
            "            raise ProcessContainmentError(\n"
            '                f"{reason}; could not prove subprocess-tree cleanup"\n'
            "            )\n"
        ),
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_cleanup_failure_preempts_the_triggering_error"
        ),
    ),
    Mutation(
        name="subprocess-group-kwargs-use-bypass",
        path="evoom_guard/execution/process.py",
        before="        **process_group_popen_kwargs(),\n",
        after="        **{},\n",
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_execute_passes_the_process_group_contract_to_popen"
        ),
    ),
    Mutation(
        name="subprocess-posix-group-contract-bypass",
        path="evoom_guard/execution/process.py",
        before='        return {"start_new_session": True}\n',
        after='        return {"start_new_session": False}\n',
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_posix_process_group_contract"
        ),
    ),
    Mutation(
        name="subprocess-windows-group-contract-bypass",
        path="evoom_guard/execution/process.py",
        before='                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)\n',
        after="                0\n",
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_windows_process_group_contract"
        ),
    ),
)


def _module_name(path: str) -> str:
    """Return the import name for one mutated Python source path."""

    module = path.removesuffix(".py").replace("/", ".")
    if module.endswith(".__init__"):
        module = module.removesuffix(".__init__")
    if not module.startswith("evoom_guard."):
        raise RuntimeError(f"mutation path is outside the package: {path}")
    return module


def _apply_mutation(overlay: Path, mutation: Mutation) -> None:
    target = overlay / mutation.path
    source = target.read_text(encoding="utf-8")
    count = source.count(mutation.before)
    if count != 1:
        raise RuntimeError(
            f"{mutation.name}: expected one mutation site in {mutation.path}, found {count}"
        )
    target.write_text(
        source.replace(mutation.before, mutation.after, 1),
        encoding="utf-8",
        newline="\n",
    )


def _watchdog_popen_kwargs() -> dict[str, Any]:
    """Create a gate-owned process-tree boundary independent of mutated code."""

    if os.name == "posix":
        return {"start_new_session": True}
    if os.name == "nt":
        creation_flag = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        if creation_flag == 0:
            raise RuntimeError("watchdog process-group support is unavailable on Windows")
        return {"creationflags": creation_flag}
    raise RuntimeError(f"watchdog containment is unsupported on host: {os.name}")


def _stop_watchdog_tree(process: subprocess.Popen[str]) -> None:
    """Stop a timed-out pytest process and members of its inherited boundary."""

    cleanup_error: str | None = None
    if os.name == "posix":
        killpg = getattr(os, "killpg", None)
        if not callable(killpg):
            cleanup_error = "killpg is unavailable"
        else:
            try:
                killpg(
                    process.pid,
                    getattr(signal, "SIGKILL", signal.SIGTERM),
                )
            except ProcessLookupError:
                pass
            except OSError as exc:
                cleanup_error = f"killpg failed: {exc}"
    elif os.name == "nt":
        try:
            killed = subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            cleanup_error = f"taskkill failed: {exc}"
        else:
            # A departed Windows root does not prove that descendants are gone;
            # taskkill must positively accept the /T cleanup request.
            if killed.returncode != 0:
                cleanup_error = f"taskkill exited {killed.returncode}"
    else:  # pragma: no cover - rejected before launch
        cleanup_error = f"unsupported watchdog host: {os.name}"

    if process.poll() is None:
        try:
            process.kill()
        except OSError as exc:
            cleanup_error = cleanup_error or f"direct kill failed: {exc}"
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        cleanup_error = cleanup_error or "watchdog tree retained inherited pipes"
    if process.poll() is None:
        cleanup_error = cleanup_error or "watchdog root did not exit"
    if cleanup_error is not None:
        raise RuntimeError(cleanup_error)


def _run_overlay_test(
    overlay: Path, mutation: Mutation, timeout: float
) -> subprocess.CompletedProcess[str]:
    """Run one focused test and prove it imported the requested overlay module."""

    module_name = _module_name(mutation.path)
    expected_path = str((overlay / mutation.path).resolve())
    bootstrap = (
        "import importlib, pathlib, sys; "
        f"sys.path.insert(0, {str(overlay)!r}); "
        f"mutated = importlib.import_module({module_name!r}); "
        "loaded = pathlib.Path(mutated.__file__).resolve(); "
        f"expected = pathlib.Path({expected_path!r}).resolve(); "
        "assert loaded == expected, (loaded, expected); "
        "import pytest; "
        f"raise SystemExit(pytest.main([{mutation.test!r}, '-q']))"
    )
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONHASHSEED="0")
    process = subprocess.Popen(
        [sys.executable, "-c", bootstrap],
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        **_watchdog_popen_kwargs(),
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _stop_watchdog_tree(process)
        raise
    return subprocess.CompletedProcess(
        process.args,
        process.returncode,
        stdout=stdout,
        stderr=stderr,
    )


def _run_mutant(mutation: Mutation, timeout: float) -> tuple[str, str]:
    with tempfile.TemporaryDirectory(prefix="evoguard-mutant-") as temp:
        overlay = Path(temp)
        shutil.copytree(
            ROOT / "evoom_guard",
            overlay / "evoom_guard",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        try:
            control = _run_overlay_test(overlay, mutation, timeout)
        except subprocess.TimeoutExpired:
            return "infrastructure-error", f"control exceeded {timeout:g}s"
        control_output = (control.stdout + "\n" + control.stderr).strip()
        if control.returncode != 0:
            return (
                "infrastructure-error",
                f"control pytest exit {control.returncode}\n{control_output}",
            )

        _apply_mutation(overlay, mutation)
        try:
            completed = _run_overlay_test(overlay, mutation, timeout)
        except subprocess.TimeoutExpired:
            return "infrastructure-error", f"mutant exceeded {timeout:g}s"

    output = (completed.stdout + "\n" + completed.stderr).strip()
    if completed.returncode == 1:
        return "killed", output
    if completed.returncode == 0:
        return "survived", output
    return "infrastructure-error", f"pytest exit {completed.returncode}\n{output}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="per-mutant timeout in seconds (default: 20)",
    )
    parser.add_argument(
        "--mutation",
        action="append",
        default=[],
        help="run only this mutation name (repeatable)",
    )
    args = parser.parse_args()
    if not 1 <= args.timeout <= 120:
        parser.error("--timeout must be between 1 and 120 seconds")

    requested = set(args.mutation)
    known = {mutation.name for mutation in MUTATIONS}
    unknown = requested - known
    if unknown:
        parser.error("unknown mutation(s): " + ", ".join(sorted(unknown)))
    selected = [m for m in MUTATIONS if not requested or m.name in requested]

    failures: list[str] = []
    for mutation in selected:
        try:
            status, detail = _run_mutant(mutation, args.timeout)
        except (OSError, RuntimeError) as exc:
            status, detail = "infrastructure-error", str(exc)
        print(f"{status.upper():20} {mutation.name}")
        if status != "killed":
            failures.append(f"{mutation.name}: {status}\n{detail}")

    if failures:
        print("\nMutation gate failed:\n" + "\n\n".join(failures), file=sys.stderr)
        return 1
    print(f"\nReviewed security mutants: {len(selected)}/{len(selected)} killed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
