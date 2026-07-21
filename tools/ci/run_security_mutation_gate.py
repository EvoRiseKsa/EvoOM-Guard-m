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
        name="judge-output-limit-validation-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "        if type(self.max_output_bytes) is not int or "
            "self.max_output_bytes < 0:\n"
            "            raise ValueError("
            '"max_output_bytes must be a non-negative integer")\n'
        ),
        after=(
            "        if False and (type(self.max_output_bytes) is not int or "
            "self.max_output_bytes < 0):\n"
            "            raise ValueError("
            '"max_output_bytes must be a non-negative integer")\n'
        ),
        test=(
            "tests/test_judge_execution_kernel.py::"
            "test_judge_limits_reject_unbounded_values"
        ),
    ),
    Mutation(
        name="judge-finite-cleanup-limit-validation-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "        ):\n"
            "            if (\n"
            "                isinstance(value, bool)\n"
            "                or not isinstance(value, (int, float))\n"
            "                or not math.isfinite(value)\n"
            "                or value < 0\n"
            "                or (not allow_zero and value == 0)\n"
            "            ):\n"
        ),
        after=(
            "        ):\n"
            "            if False and (\n"
            "                isinstance(value, bool)\n"
            "                or not isinstance(value, (int, float))\n"
            "                or not math.isfinite(value)\n"
            "                or value < 0\n"
            "                or (not allow_zero and value == 0)\n"
            "            ):\n"
        ),
        test=(
            "tests/test_judge_execution_kernel.py::"
            "test_judge_limits_reject_unbounded_values"
        ),
    ),
    Mutation(
        name="judge-sigkill-validation-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "        if type(self.sigkill) is not int or self.sigkill <= 0:\n"
            "            raise ValueError("
            '"sigkill must be a positive integer signal number")\n'
        ),
        after=(
            "        if False and (type(self.sigkill) is not int or "
            "self.sigkill <= 0):\n"
            "            raise ValueError("
            '"sigkill must be a positive integer signal number")\n'
        ),
        test=(
            "tests/test_judge_execution_kernel.py::"
            "test_judge_limits_reject_unbounded_values"
        ),
    ),
    Mutation(
        name="judge-request-limits-type-validation-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "        if type(self.limits) is not JudgeProcessLimits:\n"
            '            raise ValueError("limits must be a '
            'JudgeProcessLimits instance")\n'
        ),
        after=(
            "        if False and type(self.limits) is not JudgeProcessLimits:\n"
            '            raise ValueError("limits must be a '
            'JudgeProcessLimits instance")\n'
        ),
        test=(
            "tests/test_judge_execution_kernel.py::"
            "test_judge_request_rejects_unvalidated_limits_before_launch"
        ),
    ),
    Mutation(
        name="judge-request-timeout-validation-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "        if type(self.timeout_seconds) is not int or "
            "self.timeout_seconds < 0:\n"
            '            raise ValueError("timeout_seconds must be a '
            'non-negative integer")\n'
        ),
        after=(
            "        if False and (type(self.timeout_seconds) is not int or "
            "self.timeout_seconds < 0):\n"
            '            raise ValueError("timeout_seconds must be a '
            'non-negative integer")\n'
        ),
        test=(
            "tests/test_judge_execution_kernel.py::"
            "test_judge_request_rejects_invalid_timeout_before_launch"
        ),
    ),
    Mutation(
        name="judge-default-group-proof-preflight-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            '        if os.name != "posix" or not callable('
            'getattr(os, "killpg", None)):\n'
            "            raise JudgeProcessCleanupError(\n"
            '                "default judge execution requires POSIX '
            'process-group cleanup; "\n'
            '                "provide an explicit trusted '
            'process_group_terminator"\n'
            "            )\n"
        ),
        after=(
            '        if False and (os.name != "posix" or not callable('
            'getattr(os, "killpg", None))):\n'
            "            raise JudgeProcessCleanupError(\n"
            '                "default judge execution requires POSIX '
            'process-group cleanup; "\n'
            '                "provide an explicit trusted '
            'process_group_terminator"\n'
            "            )\n"
        ),
        test=(
            "tests/test_judge_execution_kernel.py::"
            "test_default_direct_executor_rejects_missing_group_proof_before_launch"
        ),
    ),
    Mutation(
        name="judge-reader-start-cleanup-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "                process_group_terminator(process)\n"
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
        path="evoom_guard/execution/judge.py",
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
        path="evoom_guard/execution/judge.py",
        before="        safe_to_close = index >= len(stopped) or stopped[index]\n",
        after="        safe_to_close = False\n",
        test=(
            "tests/test_blackbox_judge_reader_start.py::"
            "test_reader_start_failure_cleans_group_handles_pipes_and_preserves_primary"
        ),
    ),
    Mutation(
        name="judge-live-reader-synchronous-close",
        path="evoom_guard/execution/judge.py",
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
        path="evoom_guard/execution/judge.py",
        before=(
            "        except RuntimeError as exc:\n"
            "            # An interrupted Thread.start() can create the native thread before\n"
            "            # ``ident`` or ``_started`` becomes observable. A failed join is\n"
            "            # never proof that the corresponding pipe is safe to close.\n"
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
        path="evoom_guard/execution/judge.py",
        before=(
            "                pipe_join(reader_start_attempts, streams)\n"
            "            except BaseException:\n"
            "                pass\n"
        ),
        after=(
            "                pipe_join(reader_start_attempts, streams)\n"
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
        path="evoom_guard/execution/judge.py",
        before=(
            "                process_group_terminator(process)\n"
            "            except BaseException:\n"
            "                # An active primary exception must not be replaced by cleanup.\n"
        ),
        after=(
            "                process_group_terminator(process)\n"
            "            except Exception:\n"
            "                # An active primary exception must not be replaced by cleanup.\n"
        ),
        test=(
            "tests/test_blackbox_judge_reader_start.py::"
            "test_reader_start_primary_survives_every_cleanup_baseexception"
        ),
    ),
    Mutation(
        name="judge-start-new-session-bypass",
        path="evoom_guard/execution/judge.py",
        before="            start_new_session=True,\n",
        after="            start_new_session=False,\n",
        test=(
            "tests/test_blackbox_judge_mutation_contract.py::"
            "test_judge_popen_starts_a_dedicated_session"
        ),
    ),
    Mutation(
        name="judge-timeout-cleanup-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "            if monotonic() >= deadline:\n"
            "                cleanup_and_prove(\"judge timed out\")\n"
            "                raise subprocess.TimeoutExpired(\n"
        ),
        after=(
            "            if False and monotonic() >= deadline:\n"
            "                cleanup_and_prove(\"judge timed out\")\n"
            "                raise subprocess.TimeoutExpired(\n"
        ),
        test=(
            "tests/test_blackbox_judge_mutation_contract.py::"
            "test_judge_timeout_is_not_bypassed_before_process_cleanup"
        ),
    ),
    Mutation(
        name="judge-post-completion-group-proof-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "        cleanup_and_prove(\"judge completed\")\n"
            "        return JudgeProcessResult(\n"
        ),
        after="        return JudgeProcessResult(\n",
        test=(
            "tests/test_blackbox_judge_mutation_contract.py::"
            "test_completed_judge_still_proves_process_group_cleanup"
        ),
    ),
    Mutation(
        name="judge-live-output-checkpoint-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "        while process.poll() is None:\n"
            "            if capture.exceeded:\n"
            "                cleanup_and_prove(\"judge output limit reached\")\n"
        ),
        after=(
            "        while process.poll() is None:\n"
            "            if False and capture.exceeded:\n"
            "                cleanup_and_prove(\"judge output limit reached\")\n"
        ),
        test=(
            "tests/test_blackbox_judge_mutation_contract.py::"
            "test_live_output_checkpoint_runs_before_the_next_poll"
        ),
    ),
    Mutation(
        name="judge-post-poll-output-checkpoint-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "        if capture.exceeded:\n"
            "            cleanup_and_prove(\"judge output limit reached\")\n"
            "            raise JudgeOutputLimitError(capture.limit)\n"
            "        if not pipe_join(readers, streams):\n"
        ),
        after=(
            "        if False and capture.exceeded:\n"
            "            cleanup_and_prove(\"judge output limit reached\")\n"
            "            raise JudgeOutputLimitError(capture.limit)\n"
            "        if not pipe_join(readers, streams):\n"
        ),
        test=(
            "tests/test_blackbox_judge_mutation_contract.py::"
            "test_post_poll_output_checkpoint_precedes_normal_reader_join"
        ),
    ),
    Mutation(
        name="judge-post-join-output-checkpoint-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "        if capture.exceeded:\n"
            "            cleanup_and_prove(\"judge output limit reached\")\n"
            "            raise JudgeOutputLimitError(capture.limit)\n"
            "        cleanup_and_prove(\"judge completed\")\n"
        ),
        after=(
            "        if False and capture.exceeded:\n"
            "            cleanup_and_prove(\"judge output limit reached\")\n"
            "            raise JudgeOutputLimitError(capture.limit)\n"
            "        cleanup_and_prove(\"judge completed\")\n"
        ),
        test=(
            "tests/test_blackbox_judge_mutation_contract.py::"
            "test_post_join_output_checkpoint_cannot_return_success"
        ),
    ),
    Mutation(
        name="judge-reader-join-failure-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "        if not pipe_join(readers, streams):\n"
            "            cleanup_and_prove(\"judge exited with live output pipes\")\n"
            "            raise JudgeProcessCleanupError(\n"
            "                \"judge exited but its output pipes did not close\"\n"
            "            )\n"
        ),
        after=(
            "        pipe_join(readers, streams)\n"
        ),
        test=(
            "tests/test_blackbox_judge_mutation_contract.py::"
            "test_reader_join_failure_cannot_be_returned_as_success"
        ),
    ),
    Mutation(
        name="judge-runtime-baseexception-precedence-bypass",
        path="evoom_guard/execution/judge.py",
        before=(
            "            except BaseException:\n"
            "                pass\n"
            "        raise\n"
            "\n"
            "\n"
            "__all__ = [\n"
        ),
        after=(
            "            except BaseException:\n"
            "                pass\n"
            "        raise JudgeProcessCleanupError(\"mutant masked primary\")\n"
            "\n"
            "\n"
            "__all__ = [\n"
        ),
        test=(
            "tests/test_blackbox_judge_mutation_contract.py::"
            "test_runtime_baseexception_remains_primary_after_cleanup_failures"
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
        name="finalizer-git-env-scrub-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before='        if not key.upper().startswith("GIT_")\n',
        after="        if True\n",
        test=(
            "tests/test_finalizer_derivation.py::"
            "test_raw_git_command_scrubs_all_ambient_git_environment"
        ),
    ),
    Mutation(
        name="finalizer-git-no-replace-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before='    command = ["git", "--no-replace-objects"]\n',
        after='    command = ["git"]\n',
        test=(
            "tests/test_finalizer_derivation.py::"
            "test_raw_git_reader_ignores_replace_refs"
        ),
    ),
    Mutation(
        name="finalizer-git-tree-cleanup-proof-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before="    return terminate_process_tree(process, _GIT_PROCESS_LIMITS)\n",
        after="    return True\n",
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_timeout_reports_unproven_cleanup_without_unbounded_wait"
        ),
    ),
    Mutation(
        name="finalizer-git-process-group-launch-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before="                **process_group_popen_kwargs(),\n",
        after="                **{},\n",
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_git_launch_applies_the_managed_process_group_contract"
        ),
    ),
    Mutation(
        name="finalizer-git-reader-join-bound-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "            reader.join(max(0.0, deadline - time.monotonic()))\n"
        ),
        after="            reader.join()\n",
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_git_bytes_remain_exact_and_reader_joins_are_bounded"
        ),
    ),
    Mutation(
        name="finalizer-git-live-reader-close-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before="        safe_to_close = index >= len(stopped) or stopped[index]\n",
        after="        safe_to_close = True\n",
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_live_reader_stream_is_never_closed_synchronously"
        ),
    ),
    Mutation(
        name="finalizer-git-reader-start-tracking-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "            reader_start_attempts.append(reader)\n"
            "            reader.start()\n"
        ),
        after="            reader.start()\n",
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_reader_start_failure_kills_and_reaps_git_without_masking_primary"
        ),
    ),
    Mutation(
        name="finalizer-git-overflow-state-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "                        overflow.add(label)\n"
            "                        reader_signal.set()\n"
        ),
        after="                        reader_signal.set()\n",
        test=(
            "tests/test_finalizer_derivation.py::"
            "test_raw_git_command_bounds_pipes_while_the_child_is_running"
        ),
    ),
    Mutation(
        name="finalizer-git-reader-error-record-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "                read_errors.append(exc)\n"
            "                reader_signal.set()\n"
        ),
        after="                reader_signal.set()\n",
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_worker_read_failure_cannot_return_partial_git_output"
        ),
    ),
    Mutation(
        name="finalizer-git-reader-baseexception-narrowing",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "            except BaseException as exc:\n"
            "                read_errors.append(exc)\n"
        ),
        after=(
            "            except Exception as exc:\n"
            "                read_errors.append(exc)\n"
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_worker_read_failure_cannot_return_partial_git_output"
        ),
    ),
    Mutation(
        name="finalizer-git-live-reader-error-cleanup-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "        interrupted = timed_out or bool(read_errors) or bool(overflow)\n"
        ),
        after="        interrupted = timed_out or bool(overflow)\n",
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_worker_read_failure_stops_a_still_live_git_child"
        ),
    ),
    Mutation(
        name="finalizer-git-interrupt-cleanup-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "        if interrupted:\n"
            "            if not _terminate_git_process_tree(process):\n"
        ),
        after=(
            "        if interrupted:\n"
            "            if False and not _terminate_git_process_tree(process):\n"
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_timeout_uses_bounded_kill_reap_and_reader_join"
        ),
    ),
    Mutation(
        name="finalizer-git-posix-post-completion-proof-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            '            if os.name == "posix":\n'
            "                if not _terminate_git_process_tree(process):\n"
        ),
        after=(
            '            if False and os.name == "posix":\n'
            "                if not _terminate_git_process_tree(process):\n"
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_posix_success_proves_post_completion_group_cleanup"
        ),
    ),
    Mutation(
        name="finalizer-git-post-poll-primary-suppression",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "                raise\n"
            '            if os.name == "posix":\n'
        ),
        after=(
            "                pass\n"
            '            if os.name == "posix":\n'
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_post_poll_wait_baseexception_remains_authoritative"
        ),
    ),
    Mutation(
        name="finalizer-git-reader-join-primary-suppression",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "    if first_error is not None:\n"
            "        raise first_error\n"
        ),
        after=(
            "    if False and first_error is not None:\n"
            "        raise first_error\n"
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_reader_join_baseexception_remains_authoritative"
        ),
    ),
    Mutation(
        name="finalizer-git-abort-cleanup-bypass",
        path="evoom_guard/finalizer_derivation.py",
        before=(
            "    except BaseException:\n"
            "        # Preserve the active exception while attempting bounded cleanup.\n"
        ),
        after=(
            "    except Exception:\n"
            "        # Preserve the active exception while attempting bounded cleanup.\n"
        ),
        test=(
            "tests/test_finalizer_git_lifecycle.py::"
            "test_reader_start_failure_kills_and_reaps_git_without_masking_primary"
        ),
    ),
    Mutation(
        name="github-attestation-tree-cleanup-proof-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "    return terminate_process_tree("
            "process, _GITHUB_ATTESTATION_PROCESS_LIMITS)\n"
        ),
        after="    return True\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_unproven_tree_cleanup_fails_closed"
        ),
    ),
    Mutation(
        name="github-attestation-process-group-launch-bypass",
        path="evoom_guard/github_attestation.py",
        before="                **process_group_popen_kwargs(),\n",
        after="                **{},\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_launch_uses_managed_group_and_preserves_exact_raw_bytes"
        ),
    ),
    Mutation(
        name="github-attestation-reader-join-bound-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "            reader.join(max(0.0, deadline - time.monotonic()))\n"
        ),
        after="            reader.join()\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_launch_uses_managed_group_and_preserves_exact_raw_bytes"
        ),
    ),
    Mutation(
        name="github-attestation-reader-total-budget-reset",
        path="evoom_guard/github_attestation.py",
        before=(
            "    deadline = time.monotonic() + "
            "_GITHUB_ATTESTATION_READER_JOIN_SECONDS\n"
            "    for reader in readers:\n"
        ),
        after=(
            "    for reader in readers:\n"
            "        deadline = time.monotonic() + "
            "_GITHUB_ATTESTATION_READER_JOIN_SECONDS\n"
        ),
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_reader_joins_share_one_total_budget"
        ),
    ),
    Mutation(
        name="github-attestation-poll-wait-bound-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "            reader_signal.wait("
            "min(_GITHUB_ATTESTATION_PROCESS_POLL_SECONDS, remaining))\n"
        ),
        after="            reader_signal.wait()\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_process_poll_wait_is_bounded_and_wakes_for_recheck"
        ),
    ),
    Mutation(
        name="github-attestation-live-reader-close-bypass",
        path="evoom_guard/github_attestation.py",
        before="        safe_to_close = index >= len(stopped) or stopped[index]\n",
        after="        safe_to_close = True\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_live_reader_stream_is_never_closed_synchronously"
        ),
    ),
    Mutation(
        name="github-attestation-stream-close-proof-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "        except (OSError, ValueError):\n"
            "            streams_closed = False\n"
        ),
        after=(
            "        except (OSError, ValueError):\n"
            "            streams_closed = True\n"
        ),
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_stream_close_failure_cannot_be_a_successful_cleanup_proof"
        ),
    ),
    Mutation(
        name="github-attestation-stream-close-primary-suppression",
        path="evoom_guard/github_attestation.py",
        before=(
            "        except BaseException as exc:\n"
            "            streams_closed = False\n"
            "            if first_error is None:\n"
            "                first_error = exc\n"
        ),
        after=(
            "        except BaseException as exc:\n"
            "            streams_closed = False\n"
            "            if False and first_error is None:\n"
            "                first_error = exc\n"
        ),
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_stream_close_baseexception_remains_authoritative"
        ),
    ),
    Mutation(
        name="github-attestation-unattempted-reader-pipe-close-bypass",
        path="evoom_guard/github_attestation.py",
        before="        safe_to_close = index >= len(stopped) or stopped[index]\n",
        after=(
            "        safe_to_close = index < len(stopped) and stopped[index]\n"
        ),
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_reader_start_failure_cleans_child_without_masking_primary"
        ),
    ),
    Mutation(
        name="github-attestation-reader-start-tracking-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "            reader_start_attempts.append(reader)\n"
            "            reader.start()\n"
        ),
        after="            reader.start()\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_reader_start_failure_cleans_child_without_masking_primary"
        ),
    ),
    Mutation(
        name="github-attestation-overflow-state-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "                        overflow.add(label)\n"
            "                        reader_signal.set()\n"
        ),
        after="                        reader_signal.set()\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_stdout_and_stderr_limits_are_independent_and_fail_closed"
        ),
    ),
    Mutation(
        name="github-attestation-reader-error-record-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "                read_errors.append(exc)\n"
            "                reader_signal.set()\n"
        ),
        after="                reader_signal.set()\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_worker_failure_cannot_accept_plausible_partial_json"
        ),
    ),
    Mutation(
        name="github-attestation-reader-baseexception-narrowing",
        path="evoom_guard/github_attestation.py",
        before=(
            "            except BaseException as exc:\n"
            "                read_errors.append(exc)\n"
        ),
        after=(
            "            except Exception as exc:\n"
            "                read_errors.append(exc)\n"
        ),
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_worker_failure_cannot_accept_plausible_partial_json"
        ),
    ),
    Mutation(
        name="github-attestation-live-reader-error-cleanup-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "        interrupted = timed_out or bool(read_errors) or bool(overflow)\n"
        ),
        after="        interrupted = timed_out or bool(overflow)\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_worker_failure_stops_a_still_live_child"
        ),
    ),
    Mutation(
        name="github-attestation-interrupt-cleanup-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "            if not root_exited_on_windows:\n"
            "                if not _terminate_gh_process_tree(process):\n"
        ),
        after=(
            "            if not root_exited_on_windows:\n"
            "                if False and not _terminate_gh_process_tree(process):\n"
        ),
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_timeout_uses_tree_cleanup_and_independent_reader_budget"
        ),
    ),
    Mutation(
        name="github-attestation-windows-departed-root-reason-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            '            root_exited_on_windows = os.name == "nt" and '
            "process.poll() is not None\n"
        ),
        after="            root_exited_on_windows = False\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_windows_departed_root_preserves_original_failure_without_tree_claim"
        ),
    ),
    Mutation(
        name="github-attestation-windows-cleanup-race-recheck-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "                    root_exited_on_windows = (\n"
            "                        os.name == \"nt\" and process.poll() is not None\n"
            "                    )\n"
        ),
        after="                    root_exited_on_windows = False\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_windows_root_exit_during_cleanup_preserves_original_failure"
        ),
    ),
    Mutation(
        name="github-attestation-deadline-check-bypass",
        path="evoom_guard/github_attestation.py",
        before="            if remaining <= 0:\n",
        after="            if False and remaining <= 0:\n",
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_windows_departed_root_preserves_original_failure_without_tree_claim"
        ),
    ),
    Mutation(
        name="github-attestation-posix-post-completion-proof-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "            if os.name == \"posix\":\n"
            "                if not _terminate_gh_process_tree(process):\n"
        ),
        after=(
            "            if False and os.name == \"posix\":\n"
            "                if not _terminate_gh_process_tree(process):\n"
        ),
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_posix_success_proves_post_completion_group_cleanup"
        ),
    ),
    Mutation(
        name="github-attestation-post-poll-primary-suppression",
        path="evoom_guard/github_attestation.py",
        before=(
            "                raise\n"
            "            if os.name == \"posix\":\n"
        ),
        after=(
            "                pass\n"
            "            if os.name == \"posix\":\n"
        ),
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_post_poll_wait_baseexception_remains_authoritative"
        ),
    ),
    Mutation(
        name="github-attestation-reader-join-primary-suppression",
        path="evoom_guard/github_attestation.py",
        before=(
            "    if first_error is not None:\n"
            "        raise first_error\n"
        ),
        after=(
            "    if False and first_error is not None:\n"
            "        raise first_error\n"
        ),
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_reader_join_baseexception_remains_authoritative_and_stream_stays_open"
        ),
    ),
    Mutation(
        name="github-attestation-abort-cleanup-bypass",
        path="evoom_guard/github_attestation.py",
        before=(
            "    except BaseException:\n"
            "        # Preserve the active exception while attempting bounded cleanup.\n"
        ),
        after=(
            "    except Exception:\n"
            "        # Preserve the active exception while attempting bounded cleanup.\n"
        ),
        test=(
            "tests/test_github_attestation_lifecycle.py::"
            "test_reader_start_failure_cleans_child_without_masking_primary"
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
        name="subprocess-cleanup-requirement-validation-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "        if type(self.require_process_group_cleanup_proof) is not bool:\n"
        ),
        after=(
            "        if False and type(self.require_process_group_cleanup_proof) "
            "is not bool:\n"
        ),
        test=(
            "tests/test_execution_process.py::"
            "test_typed_request_rejects_non_boolean_cleanup_requirement"
        ),
    ),
    Mutation(
        name="subprocess-process-group-cleanup-preflight-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "    if request.require_process_group_cleanup_proof and (\n"
            '        os.name != "posix" or not callable(getattr(os, "killpg", None))\n'
            "    ):\n"
        ),
        after=(
            "    if False and request.require_process_group_cleanup_proof and (\n"
            '        os.name != "posix" or not callable(getattr(os, "killpg", None))\n'
            "    ):\n"
        ),
        test=(
            "tests/test_execution_process.py::"
            "test_required_process_group_cleanup_proof_refuses_before_popen"
        ),
    ),
    Mutation(
        name="subprocess-process-group-platform-preflight-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "    if request.require_process_group_cleanup_proof and (\n"
            '        os.name != "posix" or not callable(getattr(os, "killpg", None))\n'
            "    ):\n"
        ),
        after=(
            "    if request.require_process_group_cleanup_proof and (\n"
            '        False or not callable(getattr(os, "killpg", None))\n'
            "    ):\n"
        ),
        test=(
            "tests/test_execution_process.py::"
            "test_required_process_group_cleanup_proof_refuses_before_popen"
        ),
    ),
    Mutation(
        name="subprocess-process-group-killpg-preflight-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "    if request.require_process_group_cleanup_proof and (\n"
            '        os.name != "posix" or not callable(getattr(os, "killpg", None))\n'
            "    ):\n"
        ),
        after=(
            "    if request.require_process_group_cleanup_proof and (\n"
            '        os.name != "posix" or False\n'
            "    ):\n"
        ),
        test=(
            "tests/test_execution_process.py::"
            "test_required_process_group_cleanup_proof_refuses_before_popen"
        ),
    ),
    Mutation(
        name="subprocess-process-group-cleanup-facade-forward-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "        require_process_group_cleanup_proof="
            "require_process_group_cleanup_proof,\n"
        ),
        after="        require_process_group_cleanup_proof=False,\n",
        test=(
            "tests/test_execution_process.py::"
            "test_public_facade_forwards_process_group_cleanup_proof_requirement"
        ),
    ),
    Mutation(
        name="subprocess-required-process-group-launch-bypass",
        path="evoom_guard/execution/process.py",
        before="        **process_group_popen_kwargs(),\n",
        after=(
            "        **({} if request.require_process_group_cleanup_proof "
            "else process_group_popen_kwargs()),\n"
        ),
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_execute_passes_the_process_group_contract_to_popen"
        ),
    ),
    Mutation(
        name="subprocess-reader-start-cleanup-bypass",
        path="evoom_guard/execution/process.py",
        before="        if process is not None:\n",
        after="        if False and process is not None:\n",
        test=(
            "tests/test_execution_process_reader_start.py::"
            "test_reader_start_failure_cleans_tree_and_preserves_primary"
        ),
    ),
    Mutation(
        name="subprocess-reader-start-tracking-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "            reader_start_attempts.append(reader)\n"
            "            reader.start()\n"
        ),
        after="            reader.start()\n",
        test=(
            "tests/test_execution_process_reader_start.py::"
            "test_reader_start_failure_cleans_tree_and_preserves_primary"
        ),
    ),
    Mutation(
        name="subprocess-reader-safe-close-proof-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "        safe_to_close = index >= len(stopped) or stopped[index]\n"
        ),
        after="        safe_to_close = True\n",
        test=(
            "tests/test_execution_process_reader_start.py::"
            "test_attempted_reader_without_join_proof_never_closes_its_pipe"
        ),
    ),
    Mutation(
        name="subprocess-live-reader-synchronous-close",
        path="evoom_guard/execution/process.py",
        before=(
            "    del streams  # Retained for the historical compatibility signature.\n"
            "    for reader in readers:\n"
        ),
        after=(
            "    for stream in streams:\n"
            "        stream.close()\n"
            "    for reader in readers:\n"
        ),
        test=(
            "tests/test_execution_process_reader_start.py::"
            "test_live_reader_pipe_is_never_closed_synchronously"
        ),
    ),
    Mutation(
        name="subprocess-reader-start-primary-exception-mask",
        path="evoom_guard/execution/process.py",
        before=(
            "                except BaseException:\n"
            "                    pass\n"
            "            if not reader_cleanup_proven:\n"
        ),
        after=(
            "                except Exception:\n"
            "                    pass\n"
            "            if not reader_cleanup_proven:\n"
        ),
        test=(
            "tests/test_execution_process_reader_start.py::"
            "test_reader_start_primary_survives_cleanup_baseexceptions"
        ),
    ),
    Mutation(
        name="subprocess-reader-join-primary-exception-mask",
        path="evoom_guard/execution/process.py",
        before=(
            "                except BaseException:\n"
            "                    pass\n"
            "        raise\n"
        ),
        after=(
            "                except Exception:\n"
            "                    pass\n"
            "        raise\n"
        ),
        test=(
            "tests/test_execution_process_reader_start.py::"
            "test_post_start_baseexception_cleans_even_completed_tree_without_masking"
        ),
    ),
    Mutation(
        name="subprocess-tree-cleanup-proof-state-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "            tree_cleanup_proven = True\n"
            "            if not join_pipe_readers(\n"
        ),
        after="            if not join_pipe_readers(\n",
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_post_poll_overflow_stops_before_normal_reader_join"
        ),
    ),
    Mutation(
        name="subprocess-reader-cleanup-proof-state-bypass",
        path="evoom_guard/execution/process.py",
        before=(
            "            reader_cleanup_proven = True\n"
            "\n"
            "        deadline = time.monotonic()"
        ),
        after="\n        deadline = time.monotonic()",
        test=(
            "tests/test_security_mutation_contract.py::"
            "test_post_poll_overflow_stops_before_normal_reader_join"
        ),
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
            '        if os.name == "posix":\n'
        ),
        after=(
            "        if False and capture.exceeded:\n"
            '            stop_and_prove("subprocess output limit reached")\n'
            "            raise ProcessOutputLimitExceeded(limits.max_output_bytes)\n"
            '        if os.name == "posix":\n'
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
            "            if not _terminate_process_tree(process, limits):\n"
            "                raise ProcessContainmentError(\n"
            '                    f"{reason}; could not prove subprocess-tree cleanup"\n'
            "                )\n"
        ),
        after=(
            "            if False and not _terminate_process_tree(process, limits):\n"
            "                raise ProcessContainmentError(\n"
            '                    f"{reason}; could not prove subprocess-tree cleanup"\n'
            "                )\n"
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
    Mutation(
        name="diff-coverage-isolated-launch-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "        interpreter,\n"
            "        *interpreter_options,\n"
            '        "-I",\n'
            '        "-c",\n'
            "        _TRUSTED_COVERAGE_LAUNCHER,\n"
            '        "run",\n'
        ),
        after=(
            "        interpreter,\n"
            "        *interpreter_options,\n"
            '        "-c",\n'
            "        _TRUSTED_COVERAGE_LAUNCHER,\n"
            '        "run",\n'
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_candidate_coverage_module_and_config_cannot_disable_measurement"
        ),
    ),
    Mutation(
        name="diff-coverage-repository-config-bypass",
        path="evoom_guard/evidence.py",
        before=(
            '        "run",\n'
            '        f"--rcfile={os.devnull}",\n'
        ),
        after=(
            '        "run",\n'
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_candidate_coverage_module_and_config_cannot_disable_measurement"
        ),
    ),
    Mutation(
        name="diff-coverage-report-isolated-launch-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "        interpreter,\n"
            "        *interpreter_options,\n"
            '        "-I",\n'
            '        "-c",\n'
            "        _TRUSTED_COVERAGE_LAUNCHER,\n"
            '        "json",\n'
        ),
        after=(
            "        interpreter,\n"
            "        *interpreter_options,\n"
            '        "-c",\n'
            "        _TRUSTED_COVERAGE_LAUNCHER,\n"
            '        "json",\n'
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_coverage_commands_use_isolated_python_and_ignore_repo_config"
        ),
    ),
    Mutation(
        name="diff-coverage-report-config-bypass",
        path="evoom_guard/evidence.py",
        before=(
            '        "json",\n'
            '        f"--rcfile={os.devnull}",\n'
        ),
        after='        "json",\n',
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_coverage_commands_use_isolated_python_and_ignore_repo_config"
        ),
    ),
    Mutation(
        name="diff-coverage-wrapper-prefix-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "    return [\n"
            "        *prefix,\n"
            "        interpreter,\n"
            "        *interpreter_options,\n"
            '        "-I",\n'
            '        "-c",\n'
            "        _TRUSTED_COVERAGE_LAUNCHER,\n"
            '        "run",\n'
        ),
        after=(
            "    return [\n"
            "        interpreter,\n"
            "        *interpreter_options,\n"
            '        "-I",\n'
            '        "-c",\n'
            "        _TRUSTED_COVERAGE_LAUNCHER,\n"
            '        "run",\n'
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_coverage_command_preserves_trusted_interpreter_and_wrapper_prefixes"
        ),
    ),
    Mutation(
        name="diff-coverage-report-environment-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "    return [\n"
            "        *prefix,\n"
            "        interpreter,\n"
            "        *interpreter_options,\n"
            '        "-I",\n'
            '        "-c",\n'
            "        _TRUSTED_COVERAGE_LAUNCHER,\n"
            '        "json",\n'
        ),
        after=(
            "    return [\n"
            "        sys.executable,\n"
            '        "-I",\n'
            '        "-c",\n'
            "        _TRUSTED_COVERAGE_LAUNCHER,\n"
            '        "json",\n'
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_coverage_command_preserves_trusted_interpreter_and_wrapper_prefixes"
        ),
    ),
    Mutation(
        name="diff-coverage-required-unmeasured-pass-bypass",
        path="evoom_guard/guard.py",
        before='            if coverage_evidence.get("measured") is not True:\n',
        after=(
            '            if False and coverage_evidence.get("measured") '
            'is not True:\n'
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_required_coverage_fails_closed_when_measurement_is_unavailable"
        ),
    ),
    Mutation(
        name="diff-coverage-required-clean-run-bypass",
        path="evoom_guard/guard.py",
        before=(
            "            require_passing_suite=(\n"
            "                core_verdict_passed and min_diff_coverage is not None\n"
            "            ),\n"
        ),
        after="            require_passing_suite=False,\n",
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_required_coverage_rejects_a_wrapped_suite_that_does_not_pass"
        ),
    ),
    Mutation(
        name="diff-coverage-cross-drive-path-crash",
        path="evoom_guard/evidence.py",
        before=(
            "    except (OSError, ValueError):\n"
            "        return None\n"
        ),
        after=(
            "    except OSError:\n"
            "        return None\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_external_or_cross_drive_coverage_paths_are_ignored_fail_closed"
        ),
    ),
    Mutation(
        name="diff-coverage-external-path-acceptance",
        path="evoom_guard/evidence.py",
        before="    return normalized if is_safe_relpath(normalized) else None\n",
        after="    return normalized\n",
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_coverage_path_normalization_accepts_only_repo_relative_paths"
        ),
    ),
    Mutation(
        name="diff-coverage-baseline-effect-ordering-bypass",
        path="evoom_guard/guard.py",
        before=(
            '        elif baseline_info.get("verdict") == "FAIL" '
            "and candidate_suite_passed:\n"
        ),
        after=(
            '        elif baseline_info.get("verdict") == "FAIL" and v == PASS:\n'
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_baseline_effect_survives_a_later_coverage_gate_demotion"
        ),
    ),
    Mutation(
        name="diff-coverage-record-baseline-ordering-bypass",
        path="evoom_guard/record_verifier.py",
        before=(
            "        candidate_suite_passed = "
            "_repo_suite_pass_evidence(record, attestation)\n"
        ),
        after='        candidate_suite_passed = verdict == "PASS"\n',
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_baseline_effect_survives_a_later_coverage_gate_demotion"
        ),
    ),
    Mutation(
        name="repo-pack-baseline-phase-selection-bypass",
        path="evoom_guard/guard.py",
        before=(
            "    candidate_suite_passed = (\n"
            "        repo_suite_pass_value is True if repo_suite_completed "
            "else core_verdict_passed\n"
            "    )\n"
        ),
        after="    candidate_suite_passed = core_verdict_passed\n",
        test=(
            "tests/test_record_verifier.py::"
            "test_pack_failure_preserves_repo_suite_baseline_effect"
        ),
    ),
    Mutation(
        name="repo-pack-phase-snapshot-pass-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                    repo_suite_passed=(\n"
            "                        passed if verdict_source is not None else None\n"
            "                    ),\n"
        ),
        after="                    repo_suite_passed=False,\n",
        test=(
            "tests/test_record_verifier.py::"
            "test_pack_failure_preserves_repo_suite_baseline_effect"
        ),
    ),
    Mutation(
        name="repo-pack-record-phase-selection-bypass",
        path="evoom_guard/record_verifier.py",
        before=(
            "        candidate_suite_passed = "
            "_repo_suite_pass_evidence(record, attestation)\n"
        ),
        after=(
            "        candidate_suite_passed = _completed_all_pass_evidence(record)\n"
        ),
        test=(
            "tests/test_record_verifier.py::"
            "test_pack_failure_preserves_repo_suite_baseline_effect"
        ),
    ),
    Mutation(
        name="repo-pack-composite-phase-parity-bypass",
        path="evoom_guard/record_verifier.py",
        before=(
            '                and attestation.get("repo_suite_passed") '
            "is clean_repo_pass\n"
        ),
        after="                and True\n",
        test=(
            "tests/test_record_verifier.py::"
            "test_pack_failure_preserves_repo_suite_baseline_effect"
        ),
    ),
    Mutation(
        name="repo-pack-zero-test-record-rejection",
        path="evoom_guard/record_verifier.py",
        before=(
            "                and pack_total > 0\n"
            "                or completed_zero_test_error\n"
        ),
        after="                and pack_total > 0\n",
        test=(
            "tests/test_record_verifier.py::"
            "test_completed_zero_test_pack_is_a_valid_no_verdict_error"
        ),
    ),
    Mutation(
        name="junit-report-set-content-digest-bypass",
        path="evoom_guard/verifiers/junit_oracle.py",
        before="        digest.update(text_bytes)\n",
        after="        digest.update(b\"\")\n",
        test=(
            "tests/test_adversarial_integrity_boundaries.py::"
            "test_junit_report_set_digest_is_deterministic_and_content_bound"
        ),
    ),
    Mutation(
        name="junit-report-set-format-binding-bypass",
        path="evoom_guard/verifiers/repo_verifier.py",
        before=(
            "                    repo_junit_digest_format = "
            "JUNIT_REPORT_SET_DIGEST_FORMAT\n"
        ),
        after="                    repo_junit_digest_format = None\n",
        test=(
            "tests/test_adversarial_integrity_boundaries.py::"
            "test_maven_report_set_and_pack_are_both_bound_into_composite_evidence"
        ),
    ),
    Mutation(
        name="junit-composite-pack-digest-substitution",
        path="evoom_guard/verifiers/repo_verifier.py",
        before="                            + pack_junit_sha256\n",
        after="                            + repo_junit_sha256\n",
        test=(
            "tests/test_adversarial_integrity_boundaries.py::"
            "test_maven_report_set_and_pack_are_both_bound_into_composite_evidence"
        ),
    ),
    Mutation(
        name="repo-pack-composite-digest-parity-bypass",
        path="evoom_guard/record_verifier.py",
        before=").hexdigest() == cast(str, top_digest)\n",
        after=").hexdigest() == cast(str, top_digest) or True\n",
        test=(
            "tests/test_record_verifier.py::"
            "test_pack_failure_preserves_repo_suite_baseline_effect"
        ),
    ),
    Mutation(
        name="repo-junit-source-format-parity-bypass",
        path="evoom_guard/record_verifier.py",
        before="            and _known_string(junit_format, _JUNIT_PHASE_FORMATS)\n",
        after="            and _known_string(junit_format, _JUNIT_TOP_FORMATS)\n",
        test=(
            "tests/test_record_verifier.py::"
            "test_real_completed_repo_records_are_semantically_valid[False]"
        ),
    ),
    Mutation(
        name="repo-junit-current-missing-identity-bypass",
        path="evoom_guard/record_verifier.py",
        before=(
            "        not _producer_version_at_least(attestation, (4, 0, 2))\n"
        ),
        after="        True\n",
        test=(
            "tests/test_record_verifier.py::"
            "test_real_completed_repo_records_are_semantically_valid[False]"
        ),
    ),
    Mutation(
        name="repo-pack-required-phase-contract-bypass",
        path="evoom_guard/record_verifier.py",
        before=(
            "    elif _requires_repo_phase_evidence(attestation) and not "
            "repo_phase_claimed:\n"
        ),
        after=(
            "    elif False and _requires_repo_phase_evidence(attestation) and not "
            "repo_phase_claimed:\n"
        ),
        test=(
            "tests/test_record_verifier.py::"
            "test_pack_failure_preserves_repo_suite_baseline_effect"
        ),
    ),
    Mutation(
        name="diff-coverage-source-exclusion-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "        if line in excluded_known:\n"
            "            missed.append(line)\n"
            "            source_exclusion_seen = True\n"
        ),
        after=(
            "        if line in excluded_known:\n"
            "            continue\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_inline_no_cover_cannot_remove_changed_statements_from_the_floor"
        ),
    ),
    Mutation(
        name="diff-coverage-inline-docstring-code-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "            if any(\n"
            "                start <= item.start and item.end <= end\n"
            "                for start, end in docstring_spans\n"
            "            ):\n"
            "                continue\n"
        ),
        after=(
            "            if any(\n"
            "                start[0] <= item.start[0] <= end[0]\n"
            "                for start, end in docstring_spans\n"
            "            ):\n"
            "                continue\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_code_after_docstring_on_the_same_line_remains_in_the_floor"
        ),
    ),
    Mutation(
        name="diff-coverage-tokenizer-failure-bypass",
        path="evoom_guard/evidence.py",
        before="        return set(range(1, len(source_lines) + 1))\n",
        after="        return code_lines\n",
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_tokenizer_failure_counts_touched_lines_conservatively"
        ),
    ),
    Mutation(
        name="diff-coverage-unknown-executable-line-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "        else:\n"
            "            # Missing and unknown executable lines both fail conservatively.\n"
            "            # In particular, execution of a multi-line statement's first line\n"
            "            # does not prove a short-circuited continuation was evaluated.\n"
            "            missed.append(line)\n"
        ),
        after=(
            "        else:\n"
            "            continue\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_multiline_statement_continuation_cannot_disappear_from_the_floor"
        ),
    ),
    Mutation(
        name="diff-coverage-unimported-source-classification-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "            executed, missed, _ = _classify_touched_lines(\n"
            "                new_contents.get(path), touched, {}\n"
            "            )\n"
        ),
        after=(
            "            executed, missed = [], sorted(touched)\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_comment_only_change_in_unimported_file_is_not_a_false_gap"
        ),
    ),
    Mutation(
        name="diff-coverage-structured-file-blocks-bypass",
        path="evoom_guard/evidence.py",
        before="        repo_path, candidate, file_blocks=file_blocks\n",
        after="        repo_path, candidate, file_blocks=None\n",
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_structured_file_blocks_are_the_coverage_diff_ground_truth"
        ),
    ),
    Mutation(
        name="diff-coverage-setup-forwarding-bypass",
        path="evoom_guard/guard.py",
        before=(
            "            setup_command=setup_command, "
            "setup_output_globs=setup_output_globs,\n"
        ),
        after=(
            "            setup_command=None, "
            "setup_output_globs=setup_output_globs,\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_coverage_replays_setup_with_the_main_fidelity_policy"
        ),
    ),
    Mutation(
        name="diff-coverage-setup-fidelity-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "    changes = setup_fidelity_changes(before, after)\n"
            "    if changes:\n"
        ),
        after=(
            "    changes = []\n"
            "    if changes:\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_coverage_setup_cannot_rewrite_judged_source"
        ),
    ),
    Mutation(
        name="diff-coverage-setup-resource-limit-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "            timeout=timeout,\n"
            "            preexec_fn=preexec_fn,\n"
            "        )\n"
            "        after = setup_fidelity_snapshot(\n"
        ),
        after=(
            "            timeout=timeout,\n"
            "            preexec_fn=None,\n"
            "        )\n"
            "        after = setup_fidelity_snapshot(\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_coverage_subprocesses_receive_the_main_resource_limits"
        ),
    ),
    Mutation(
        name="diff-coverage-suite-resource-limit-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "            coverage_run = _run_bounded_subprocess(\n"
            "                wrapped,\n"
            "                cwd=copy,\n"
            "                env=env,\n"
            "                timeout=timeout,\n"
            "                preexec_fn=preexec_fn,\n"
            "            )\n"
        ),
        after=(
            "            coverage_run = _run_bounded_subprocess(\n"
            "                wrapped,\n"
            "                cwd=copy,\n"
            "                env=env,\n"
            "                timeout=timeout,\n"
            "                preexec_fn=None,\n"
            "            )\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_coverage_subprocesses_receive_the_main_resource_limits"
        ),
    ),
    Mutation(
        name="diff-coverage-report-resource-limit-bypass",
        path="evoom_guard/evidence.py",
        before=(
            "                timeout=60,\n"
            "                preexec_fn=preexec_fn,\n"
            "            )\n"
        ),
        after=(
            "                timeout=60,\n"
            "                preexec_fn=None,\n"
            "            )\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_coverage_subprocesses_receive_the_main_resource_limits"
        ),
    ),
    Mutation(
        name="diff-coverage-memory-policy-forwarding-bypass",
        path="evoom_guard/guard.py",
        before=(
            "            setup_command=setup_command, "
            "setup_output_globs=setup_output_globs,\n"
            "            timeout=timeout, mem_limit_mb=mem_limit_mb,\n"
            "            file_blocks=file_blocks,\n"
        ),
        after=(
            "            setup_command=setup_command, "
            "setup_output_globs=setup_output_globs,\n"
            "            timeout=timeout, mem_limit_mb=1024,\n"
            "            file_blocks=file_blocks,\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_guard_forwards_the_configured_memory_limit_to_coverage"
        ),
    ),
    Mutation(
        name="diff-coverage-exact-ratio-bypass",
        path="evoom_guard/guard.py",
        before=(
            "                if isinstance(min_diff_coverage, int):\n"
            "                    floor_numerator, floor_denominator = "
            "min_diff_coverage, 1\n"
            "                else:\n"
            "                    floor_numerator, floor_denominator = (\n"
            "                        min_diff_coverage.as_integer_ratio()\n"
            "                    )\n"
            "                coverage_below_floor = (\n"
            "                    coverage_total > 0\n"
            "                    and 100 * coverage_executed * floor_denominator\n"
            "                    < floor_numerator * coverage_total\n"
            "                )\n"
        ),
        after=(
            "                coverage_below_floor = (\n"
            "                    float(coverage_evidence['percent'])\n"
            "                    < min_diff_coverage\n"
            "                )\n"
        ),
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_exact_ratio_not_rounded_display_controls_the_floor"
        ),
    ),
    Mutation(
        name="diff-coverage-record-exact-ratio-bypass",
        path="evoom_guard/record_verifier.py",
        before=(
            "    if isinstance(threshold, int):\n"
            "        floor_numerator, floor_denominator = threshold, 1\n"
            "    else:\n"
            "        floor_numerator, floor_denominator = threshold.as_integer_ratio()\n"
            "    return 100 * executed * floor_denominator >= floor_numerator * total\n"
        ),
        after="    return coverage['percent'] >= threshold\n",
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_exact_ratio_not_rounded_display_controls_the_floor"
        ),
    ),
    Mutation(
        name="diff-coverage-record-huge-number-overflow",
        path="evoom_guard/record_verifier.py",
        before=(
            "    if isinstance(value, bool) or not isinstance(value, (int, float)):\n"
            "        return False\n"
            "    return isinstance(value, int) or math.isfinite(value)\n"
        ),
        after=(
            "    return (\n"
            "        isinstance(value, (int, float))\n"
            "        and not isinstance(value, bool)\n"
            "        and math.isfinite(value)\n"
            "    )\n"
        ),
        test=(
            "tests/test_record_verifier.py::"
            "test_effective_policy_requires_all_24_typed_fields"
            "[min-diff-coverage-huge-int]"
        ),
    ),
    Mutation(
        name="diff-coverage-api-floor-implication-bypass",
        path="evoom_guard/guard.py",
        before="    diff_coverage = diff_coverage or min_diff_coverage is not None\n",
        after="    diff_coverage = diff_coverage\n",
        test=(
            "tests/test_diff_coverage_trust.py::"
            "test_python_api_coverage_floor_implies_measurement"
        ),
    ),
    Mutation(
        name="diff-coverage-floor-validation-bypass",
        path="evoom_guard/guard.py",
        before=(
            "    if (\n"
            "        min_diff_coverage is not None\n"
            "        and (\n"
        ),
        after=(
            "    if False and (\n"
            "        min_diff_coverage is not None\n"
            "        and (\n"
        ),
        test=(
            "tests/test_guard.py::MemLimitOptionTests::"
            "test_guard_api_rejects_values_that_cannot_form_a_valid_policy"
        ),
    ),
    Mutation(
        name="diff-coverage-required-shortfall-proof-bypass",
        path="evoom_guard/record_verifier.py",
        before="                (floor_shortfall or coverage_shortfall)\n",
        after="                floor_shortfall\n",
        test=(
            "tests/test_record_verifier.py::"
            "test_required_unmeasured_coverage_record_is_a_valid_assurance_error"
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
