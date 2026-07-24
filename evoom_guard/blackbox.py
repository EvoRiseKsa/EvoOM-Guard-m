# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""The external black-box judge — an isolated report channel.

The default judge runs the candidate's code in the **same process** as pytest
and the report writer, so a patch that writes ``atexit`` + ``os._exit(0)`` +
a forged ``--junitxml`` can fake a ``PASS`` (see ``docs/ASSURANCE.md``). No
in-process change can close that: same-process authority is same-process control.

The black-box phase closes that channel-local hole by construction. The default
Guard policy is composite and also requires the weaker repo-native channel;
``--blackbox-only`` is required for end-to-end external report integrity.

  * The **verdict-producing process is the judge's own** — it runs a pack of
    **judge-owned tests** (the "protocol pack") and NEVER imports the candidate's
    code. Its exit code is therefore authoritative: the candidate cannot register
    an ``atexit`` hook in it or call ``os._exit`` on it. In host-subprocess mode
    the same OS user may still reach the XML path, but rewriting XML cannot forge
    a clean PASS consistent with the judge's own exit; Docker also removes that
    file reachability.
  * The candidate is exercised **only across a process boundary** — the pack
    invokes it as a subprocess (a CLI, a server, `python -m tool`, …) through the
    ``EVOGUARD_EXEC`` launcher, which runs it under the delivered isolation, and
    asserts on its observable outputs. Forgery
    code in the candidate's source runs only inside those child processes, where
    ``os._exit(0)`` affects the child, not the judge. The pack checks *outputs*,
    not the child's exit code, so a lying child changes nothing.

Guarantee and its edge (stated plainly):

  * This phase's report_integrity is **external_process_isolated**: the demonstrated
    same-process forgery is defeated — proven by an adversarial test that plants
    the exact ``atexit``/``os._exit`` forgery in the candidate and still gets the
    correct ``FAIL``.
  * POSIX cleanup reaps the judge's process group on normal completion and abort,
    but a hostile host-mode child can deliberately create a new session and
    escape that group. The judge reads its report immediately and grades primarily
    by its **own exit code**; delivered Docker/gVisor isolation contains that
    escape. CID cleanup is fail-closed: inability to prove a candidate container
    absent invalidates a pending verdict. Documented, not hidden.

Scope: this fits targets with a **process/protocol boundary** — CLIs, HTTP
services, DB-backed programs. A pure library that the pack must ``import`` is
back in-process and gets the same-process assurance; wrap it behind a thin CLI
to get the black-box guarantee. See ``docs/BLACKBOX.md``.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Literal, NamedTuple, cast

from evoom_guard.candidate import parse_file_blocks, parse_patch_blocks
from evoom_guard.candidate_runner import (
    CANDIDATE_CID_DIRNAME,
    CandidateRunner,
    IsolationUnavailable,
)
from evoom_guard.execution import (
    DEFAULT_MAX_OUTPUT_BYTES as _MAX_SUBPROCESS_OUTPUT_BYTES,
)
from evoom_guard.execution import (
    BoundedOutput as _BoundedOutput,
)
from evoom_guard.execution import (
    JudgeOutputLimitError,  # noqa: F401 - historical public patch seam
    JudgeProcessCleanupError,  # noqa: F401 - historical public patch seam
    JudgeProcessLimits,
    JudgeProcessRequest,
    ProcessContainmentError,
    ProcessOutputLimitExceeded,
    execute_judge_process,
)
from evoom_guard.execution import (
    drain_process_pipe as _drain_subprocess_pipe,
)
from evoom_guard.execution import (
    join_pipe_readers as _join_pipe_readers,
)
from evoom_guard.execution import (
    run_bounded_subprocess as _run_bounded_subprocess,
)
from evoom_guard.execution.judge import (
    join_judge_pipe_readers as _join_judge_pipe_readers_kernel,
)
from evoom_guard.execution.judge import (
    judge_process_group_exists as _process_group_exists_kernel,
)
from evoom_guard.execution.judge import (
    reap_judge_leader as _reap_judge_leader_kernel,
)
from evoom_guard.execution.judge import (
    signal_judge_process_group as _signal_judge_process_group_kernel,
)
from evoom_guard.execution.judge import (
    terminate_judge_process_group as _terminate_judge_process_group_kernel,
)
from evoom_guard.execution.judge import (
    wait_for_judge_process_group_exit as _wait_for_process_group_exit_kernel,
)
from evoom_guard.isolation import (
    DockerCandidateCleanupRequest,
    DockerCidScanResult,
    DockerControlRequest,
    execute_docker_control,
    scan_candidate_container_ids,
)
from evoom_guard.isolation import (
    InvocationRecorder as _InvocationRecorder,
)
from evoom_guard.isolation import (
    cleanup_candidate_containers as _cleanup_candidate_containers_kernel,
)
from evoom_guard.pack_manifest import (
    PackManifestError,
    digest_and_manifest,
    snapshot_pack,
    verify_pack_snapshot,
)
from evoom_guard.verifiers.blackbox_pack import (
    BlackboxPackExecutionRequest,
    BlackboxPackExecutionServices,
    BlackboxPackInterpretationRequest,
    BlackboxPackInterpretationServices,
    BlackboxPackLifecycle,
    BlackboxPackVerdictFacts,
    ParseJUnitReport,
    VerifyPackSnapshot,
    execute_blackbox_pack,
    interpret_blackbox_pack,
)
from evoom_guard.verifiers.junit_oracle import read_junit_xml
from evoom_guard.verifiers.repo_verifier import (
    apply_blocks_to_copy,
    copy_repo_tree,
    distill_diagnostics,
    is_safe_relpath,
    judge_subprocess_env,
    parse_junit_xml,
)
from evoom_guard.workspace import UnsafeWorkspacePath, delete_path_within_root

_SubprocessContainmentError = ProcessContainmentError
_SubprocessOutputLimitExceeded = ProcessOutputLimitExceeded


class BlackboxResult(NamedTuple):
    passed: bool
    tests_passed: int
    tests_total: int
    diagnostics: str
    ran: bool          # did the judge pack actually run to a verdict?
    error: str | None  # set when the run could not be graded (setup problem)
    pack_sha256: str | None = None       # content digest of the judge-owned pack
    pack_manifest: dict | None = None    # optional pack.json (id/version/…)
    junit_sha256: str | None = None      # digest of the judge-owned report
    isolation: dict[str, Any] | None = None   # IsolationEvidence.as_dict() — DELIVERED
    deleted_applied: list[str] | None = None  # deletions actually applied to the copy
    # Execution facts are separate from ``ran``. ``ran`` deliberately keeps its
    # historical meaning: a clean, gradeable black-box verdict was produced.
    # A timed-out judge did start but did not complete; a returned pytest process
    # completed even when its report/exit pair cannot be graded.
    started: bool = False
    completed: bool = False
    execution_state: Literal["not_started", "started_incomplete", "completed"] = (
        "not_started"
    )
    execution_phase: Literal["preflight", "blackbox_pack"] = "preflight"
    pack_present: bool | None = None
    # Candidate isolation is claimed only when the judge observes an invocation
    # receipt from EVOGUARD_EXEC. Container modes additionally require a valid
    # Docker-written CID, so preparing/probing a runner can never by itself
    # satisfy an isolation policy floor. The precise fact is *launcher invoked*:
    # pack semantics decide whether its argv meaningfully exercised candidate
    # code, which is why the boolean deliberately avoids the stronger word
    # ``execution``.
    candidate_invocations: int = 0
    candidate_launcher_invocation_observed: bool = False


def _run_docker_control(
    command: list[str], *, timeout: float = 30.0
) -> subprocess.CompletedProcess[str]:
    """Bound Docker cleanup diagnostics before they reach judge memory."""
    request = DockerControlRequest.from_command(
        command,
        timeout=timeout,
        environment=os.environ,
    )
    return execute_docker_control(
        request,
        process_runner=_run_bounded_subprocess,
        process_argv=command,
    ).as_completed_process(args=command)


def _candidate_container_ids(
    cidfile_dir: str, *, strict: bool = False
) -> list[str]:
    """Read only genuine Docker IDs from regular judge-owned cidfiles.

    Treating cidfile contents as untrusted keeps cleanup shell-free and prevents
    a malformed file from becoming a Docker option or an unrelated container
    name. Docker emits a 64-character lowercase hexadecimal container ID.
    """
    scanned = scan_candidate_container_ids(cidfile_dir)
    if strict and scanned.failures:
        raise CandidateContainerCleanupError(scanned.failures[0])
    return list(scanned.container_ids)


def _attach_candidate_execution_evidence(
    result: BlackboxResult,
    *,
    recorder: _InvocationRecorder | None,
    cidfile_dir: str,
    wait_for_late_container_evidence: bool = False,
    observed_container_ids: set[str] | None = None,
) -> BlackboxResult:
    """Attach conservative proof that a candidate boundary actually started.

    For host subprocess mode, a valid launcher receipt is sufficient.  Docker
    and gVisor additionally require a genuine Docker CID written to a judge-owned
    cidfile; a receipt alone proves only that the Docker launcher was attempted.
    The reported invocation count is therefore the conjunction (minimum) of the
    two independent observations for container modes.
    """
    isolation = dict(result.isolation or {})
    delivered = str(isolation.get("delivered") or "")
    attempts = (
        10
        if wait_for_late_container_evidence and delivered in {"docker", "gvisor"}
        else 1
    )
    launcher_events = 0
    container_ids: list[str] = []
    for attempt in range(attempts):
        launcher_events = recorder.drain() if recorder is not None else 0
        container_ids = _candidate_container_ids(cidfile_dir)
        if observed_container_ids is not None:
            # Evidence is monotonic. Once a genuine runtime-written CID has
            # been observed, a later transient/empty directory scan cannot
            # erase the fact that this container existed and still requires
            # an absence proof during strict cleanup.
            observed_container_ids.update(container_ids)
            container_ids = sorted(observed_container_ids)
        if delivered == "subprocess":
            candidate_invocations = launcher_events
        elif delivered in {"docker", "gvisor"}:
            candidate_invocations = min(launcher_events, len(container_ids))
        else:
            candidate_invocations = 0
        if candidate_invocations > 0 or attempt + 1 == attempts:
            break
        time.sleep(0.05)

    candidate_launcher_invocation_observed = candidate_invocations > 0
    if (
        not candidate_launcher_invocation_observed
        and delivered not in {"", "not_run", "unavailable"}
    ):
        preparation_note = isolation.get("note")
        isolation["prepared"] = delivered
        isolation["delivered"] = "not_run"
        if preparation_note:
            isolation["preparation_note"] = preparation_note
        isolation["note"] = (
            "the boundary was prepared, but the required launcher/runtime "
            "invocation evidence was not observed; no candidate isolation is "
            "claimed"
        )
    isolation.update(
        {
            "candidate_launcher_events": launcher_events,
            "candidate_container_ids_observed": len(container_ids),
            "candidate_invocations": candidate_invocations,
            "candidate_launcher_invocation_observed": (
                candidate_launcher_invocation_observed
            ),
            "candidate_invocation_evidence_note": (
                "proves the trusted pack invoked EVOGUARD_EXEC; it does not by "
                "itself prove that the pack-supplied argv exercised candidate code. "
                "Only the zero/nonzero fact is security-relevant; same-host code "
                "could discover the sidecar after its first invocation, so the raw "
                "receipt count is not an audited exact call count"
            ),
        }
    )
    return result._replace(
        isolation=isolation,
        candidate_invocations=candidate_invocations,
        candidate_launcher_invocation_observed=(
            candidate_launcher_invocation_observed
        ),
    )


def _cleanup_candidate_containers(
    cidfile_dir: str,
    *,
    wait_for_late_cidfiles: bool = False,
    strict: bool = False,
    known_container_ids: set[str] | None = None,
) -> None:
    """Force-remove every candidate container named by a valid cidfile.

    ``docker run --rm`` remains the normal lifecycle. This is the failure-path
    backstop for a judge timeout or ``KeyboardInterrupt``, where killing pytest
    does not necessarily reap its descendant Docker client/container. A short,
    bounded rescan catches a cidfile that Docker finishes writing concurrently.
    Cleanup continues through every ID so one daemon error cannot skip later
    containers. In ``strict`` mode any container whose absence cannot be proven
    becomes an explicit infrastructure failure rather than allowing PASS.
    """
    def scan(path: str) -> DockerCidScanResult:
        try:
            return DockerCidScanResult(
                tuple(_candidate_container_ids(path, strict=strict))
            )
        except CandidateContainerCleanupError as exc:
            return DockerCidScanResult((), (str(exc),))

    cleanup = _cleanup_candidate_containers_kernel(
        DockerCandidateCleanupRequest(
            cidfile_dir=cidfile_dir,
            wait_for_late_cidfiles=wait_for_late_cidfiles,
            known_container_ids=frozenset(known_container_ids or ()),
        ),
        scanner=scan,
        control_runner=_run_docker_control,
        sleeper=time.sleep,
        path_exists=os.path.lexists,
    )
    if strict and cleanup.failures:
        raise CandidateContainerCleanupError(
            "candidate container cleanup could not prove absence: "
            + "; ".join(cleanup.failures)
        )


def _pack_digest_and_manifest(pack_dir: str) -> tuple[str, dict | None]:
    """Compatibility wrapper around the canonical pack-contract parser."""
    return digest_and_manifest(pack_dir)


def _judge_command(pack_dir: str, xml_path: str) -> list[str]:
    # The JUDGE's own pytest, run over the judge-owned pack. No candidate code is
    # imported here; the pack reaches the candidate only via subprocess.
    return [
        sys.executable, "-m", "pytest", "-q", "--color=no",
        "-p", "no:cacheprovider", pack_dir,
        f"--junitxml={xml_path}", "-o", "junit_family=xunit2",
    ]


_JUDGE_TERMINATION_GRACE_SECONDS = 2.0
_JUDGE_GROUP_POLL_SECONDS = 0.02
_SIGKILL = int(getattr(signal, "SIGKILL", 9))


class CandidateContainerCleanupError(RuntimeError):
    """A candidate container could not be proven absent after execution."""


class _BlackboxCleanupFailure(RuntimeError):
    """Internal control flow carrying a reportable cleanup result."""

    def __init__(self, result: BlackboxResult) -> None:
        super().__init__(result.diagnostics)
        self.result = result


def _signal_judge_process_group(
    process: subprocess.Popen[Any], sig: int
) -> None:
    """Signal only the isolated judge session created by ``Popen`` below."""
    _signal_judge_process_group_kernel(process, sig)


def _process_group_exists(process_group: int) -> bool:
    """Return whether a POSIX process group still has any member."""
    return _process_group_exists_kernel(process_group)


def _wait_for_process_group_exit(
    process: subprocess.Popen[Any], process_group: int, timeout: float
) -> bool:
    return _wait_for_process_group_exit_kernel(
        process,
        process_group,
        timeout,
        process_group_exists=_process_group_exists,
        group_poll_seconds=_JUDGE_GROUP_POLL_SECONDS,
        monotonic=time.monotonic,
        sleeper=time.sleep,
    )


def _reap_judge_leader(process: subprocess.Popen[Any]) -> None:
    _reap_judge_leader_kernel(
        process,
        termination_grace_seconds=_JUDGE_TERMINATION_GRACE_SECONDS,
    )


def _terminate_judge_process_group(process: subprocess.Popen[Any]) -> None:
    """Boundedly reap pytest and every non-detached process-group descendant.

    The leader may already be reaped while a background child still owns the
    PGID. Therefore neither ``poll()`` nor ``wait()`` is a group-cleanup proof;
    POSIX cleanup always probes/signals the PGID itself.
    """
    _terminate_judge_process_group_kernel(
        process,
        limits=JudgeProcessLimits(
            max_output_bytes=_MAX_SUBPROCESS_OUTPUT_BYTES,
            termination_grace_seconds=_JUDGE_TERMINATION_GRACE_SECONDS,
            group_poll_seconds=_JUDGE_GROUP_POLL_SECONDS,
            sigkill=_SIGKILL,
        ),
        process_group_exists=_process_group_exists,
        signal_process_group=_signal_judge_process_group,
        wait_for_group_exit=_wait_for_process_group_exit,
        reap_leader=_reap_judge_leader,
    )


def _join_judge_pipe_readers(
    readers: list[threading.Thread], streams: list[Any]
) -> bool:
    """Boundedly join attempted readers without closing under a live read.

    ``BufferedReader.close()`` can itself block on the reader's internal lock
    while another thread is stuck in ``read()``.  The generic join primitive is
    therefore called with no streams here.  A stream is closed only after its
    reader is proven stopped, or when no startup attempt referenced that pipe.
    """
    return _join_judge_pipe_readers_kernel(
        readers,
        streams,
        generic_joiner=_join_pipe_readers,
    )


def _run_judge_process(
    command: list[str],
    *,
    cwd: str,
    env: dict[str, str],
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    """Run pytest in its own POSIX session and kill the whole group on abort.

    ``subprocess.run`` kills only the direct pytest process on timeout. A pack's
    EVOGUARD_EXEC launcher and candidate can then survive as orphans. Starting a
    fresh session makes its process group an unambiguous cleanup target. The
    original TimeoutExpired/KeyboardInterrupt/BaseException is always preserved.
    """
    limits = JudgeProcessLimits(
        max_output_bytes=_MAX_SUBPROCESS_OUTPUT_BYTES,
        termination_grace_seconds=_JUDGE_TERMINATION_GRACE_SECONDS,
        group_poll_seconds=_JUDGE_GROUP_POLL_SECONDS,
        sigkill=_SIGKILL,
    )
    request = JudgeProcessRequest(
        command=command,
        cwd=cwd,
        env=env,
        timeout_seconds=timeout,
        limits=limits,
    )
    return execute_judge_process(
        request,
        popen_factory=subprocess.Popen,
        thread_factory=threading.Thread,
        output_factory=_BoundedOutput,
        pipe_drain=_drain_subprocess_pipe,
        pipe_join=_join_judge_pipe_readers,
        process_group_terminator=_terminate_judge_process_group,
        monotonic=time.monotonic,
        sleeper=time.sleep,
    ).as_completed_process()


def _run_blackbox_impl(
    repo_path: str,
    candidate: str,
    pack_dir: str,
    *,
    timeout: int = 120,
    isolation: str = "subprocess",
    docker_image: str | None = None,
    docker_network: str = "none",
    docker_runtime: str | None = None,
    mem_limit_mb: int = 0,
    deleted_paths: tuple[str, ...] = (),
    file_blocks: dict[str, str] | None = None,
    expect_verifier_pack_sha256: str | None = None,
) -> BlackboxResult:
    """Judge ``candidate`` against ``repo_path`` through the black-box ``pack_dir``.

    The patch (including deletions) is applied to a throwaway copy; the judge then
    runs ``pack_dir``'s tests in its own process, reaching the candidate only
    through a :class:`CandidateRunner`-provided launcher (``EVOGUARD_EXEC``) that
    runs it under the **delivered** isolation boundary. The verdict is the judge's
    own pytest result — a process the candidate never runs in — and the returned
    :class:`BlackboxResult` records the isolation that was *actually* delivered,
    never the value that was requested.
    """
    if not pack_dir or not os.path.lexists(pack_dir):
        return BlackboxResult(
            False, 0, 0, "", False,
            f"verifier pack not found: {pack_dir!r}",
            pack_present=False,
        )

    workdir = tempfile.mkdtemp(prefix="evo_blackbox_")
    copy = os.path.join(workdir, "repo")
    pack_workdir: str | None = None
    pack_lifecycle = BlackboxPackLifecycle()
    invocation_recorder: _InvocationRecorder | None = None
    pack_sha256: str | None = None
    pack_manifest: dict | None = None
    deleted_applied: list[str] = []
    iso: dict[str, Any] | None = None
    observed_candidate_container_ids: set[str] = set()
    try:
        try:
            # The candidate inherits HOME=workdir. Keep hidden checks outside
            # that tree so subprocess mode does not hand it $HOME/pack.
            pack_workdir = tempfile.mkdtemp(prefix="evo_blackbox_pack_")
            pack_snapshot = os.path.join(pack_workdir, "pack")
            pack_identity = snapshot_pack(pack_dir, pack_snapshot)
            pack_sha256, pack_manifest = pack_identity
        except PackManifestError as exc:
            # The snapshot is the exact tree the judge executes; a broken or
            # moving contract must stop rather than produce an unbound verdict.
            return BlackboxResult(
                False, 0, 0, str(exc), False, "verifier pack invalid",
                pack_present=True,
            )
        expected_pack_sha256 = (expect_verifier_pack_sha256 or "").lower()
        if expected_pack_sha256 and pack_sha256.lower() != expected_pack_sha256:
            return BlackboxResult(
                False,
                0,
                0,
                (
                    "verifier-pack identity mismatch: expected "
                    f"{expected_pack_sha256}, observed {pack_sha256}"
                ),
                False,
                "verifier pack identity mismatch",
                pack_sha256,
                pack_manifest,
                pack_present=True,
            )
        copy_repo_tree(repo_path, copy)
        apply_error = apply_blocks_to_copy(
            copy,
            file_blocks if file_blocks else parse_file_blocks(candidate),
            [] if file_blocks else parse_patch_blocks(candidate),
        )
        if apply_error is not None:
            return BlackboxResult(
                False, 0, 0, apply_error, False, "patch did not apply",
                pack_sha256, pack_manifest, pack_present=True,
            )

        # Apply deletions to the copy so the judged tree matches the real merge —
        # a change that removes a file must be judged with that file ABSENT.
        deleted_applied = []
        try:
            for rel in deleted_paths:
                if not is_safe_relpath(rel):
                    continue
                if delete_path_within_root(copy, rel):
                    deleted_applied.append(rel)
        except (OSError, UnsafeWorkspacePath) as exc:
            return BlackboxResult(
                False,
                0,
                0,
                f"candidate deletion could not be applied safely: {exc}",
                False,
                "unsafe deletion path",
                pack_sha256,
                pack_manifest,
                pack_present=True,
            )

        # Deliver a REAL isolation boundary (fail-closed) and record what ran.
        invocation_recorder = _InvocationRecorder.create(workdir)
        runner = CandidateRunner(
            isolation=isolation, docker_image=docker_image,
            docker_network=docker_network, docker_runtime=docker_runtime,
            mem_limit_mb=mem_limit_mb, python=sys.executable,
            invocation_socket=(
                invocation_recorder.path if invocation_recorder is not None else None
            ),
            invocation_token=(
                invocation_recorder.token if invocation_recorder is not None else None
            ),
        )
        try:
            _launcher, run_env, evidence = runner.prepare(workdir, copy)
        except IsolationUnavailable as exc:
            # A stronger boundary was required but cannot be delivered. Refuse to
            # run rather than silently judge under a weaker one.
            return BlackboxResult(
                False, 0, 0, str(exc), False, "isolation unavailable",
                pack_sha256, pack_manifest, None,
                {"requested": isolation, "delivered": "unavailable", "note": str(exc)},
                deleted_applied,
                pack_present=True,
            )
        iso = evidence.as_dict()
        cidfile_dir = os.path.join(workdir, CANDIDATE_CID_DIRNAME)

        def with_candidate_evidence(
            result: BlackboxResult, *, wait_for_late_container_evidence: bool = False
        ) -> BlackboxResult:
            return _attach_candidate_execution_evidence(
                result,
                recorder=invocation_recorder,
                cidfile_dir=cidfile_dir,
                wait_for_late_container_evidence=wait_for_late_container_evidence,
                observed_container_ids=observed_candidate_container_ids,
            )

        def project_pack_verdict(
            facts: BlackboxPackVerdictFacts,
        ) -> BlackboxResult:
            result = BlackboxResult(
                facts.passed,
                facts.tests_passed,
                facts.tests_total,
                facts.diagnostics,
                facts.ran,
                facts.error,
                pack_sha256,
                pack_manifest,
                facts.junit_sha256,
                iso,
                deleted_applied,
                started=facts.started,
                completed=facts.completed,
                execution_state=facts.execution_state,
                execution_phase=facts.execution_phase,
                pack_present=True,
            )
            if not facts.attach_candidate_evidence:
                return result
            return with_candidate_evidence(
                result,
                wait_for_late_container_evidence=(
                    facts.wait_for_late_container_evidence
                ),
            )

        xml_path = os.path.join(workdir, "judge-blackbox.xml")
        env = {
            **judge_subprocess_env(workdir),
            # How the pack reaches the candidate. EVOGUARD_TARGET stays for
            # backward compatibility; EVOGUARD_EXEC is the delivered-isolation
            # launcher the pack should prefer.
            **run_env,
        }
        execution = execute_blackbox_pack(
            BlackboxPackExecutionRequest(
                pack_snapshot=pack_snapshot,
                pack_identity=pack_identity,
                xml_path=xml_path,
                environment=env,
                timeout=timeout,
            ),
            lifecycle=pack_lifecycle,
            services=BlackboxPackExecutionServices(
                verify_snapshot=lambda: cast(
                    VerifyPackSnapshot,
                    verify_pack_snapshot,
                ),
                build_command=lambda: _judge_command,
                run_judge=lambda: _run_judge_process,
                perf_counter=lambda: time.perf_counter(),
            ),
        )
        if execution.terminal is not None:
            return project_pack_verdict(execution.terminal)
        completed_pack = execution.completed
        if completed_pack is None:
            raise RuntimeError(
                "black-box pack execution returned no terminal or completed value"
            )
        verdict = interpret_blackbox_pack(
            BlackboxPackInterpretationRequest(completed=completed_pack),
            services=BlackboxPackInterpretationServices(
                read_report=lambda: read_junit_xml,
                parse_report=lambda: cast(
                    ParseJUnitReport,
                    parse_junit_xml,
                ),
                digest_text=lambda text: hashlib.sha256(
                    text.encode("utf-8")
                ).hexdigest(),
                distill_diagnostics=lambda: distill_diagnostics,
                perf_counter=lambda: time.perf_counter(),
            ),
        )
        return project_pack_verdict(verdict)
    finally:
        # A timed-out/interrupted pytest can leave its Docker descendant alive.
        # Clean it before deleting the cidfiles. Expected operational cleanup
        # failures are handled inside the helper. A KeyboardInterrupt/SystemExit
        # raised by cleanup itself must remain visible after a normal run; only
        # suppress it while an earlier unhandled exception is already unwinding.
        primary_exception_active = sys.exc_info()[0] is not None
        cidfile_dir = os.path.join(workdir, CANDIDATE_CID_DIRNAME)
        try:
            try:
                _cleanup_candidate_containers(
                    cidfile_dir,
                    wait_for_late_cidfiles=pack_lifecycle.active,
                    # A caught timeout/incomplete result or an unhandled
                    # operator exception remains primary. A normally completed
                    # judge must prove every candidate container absent before
                    # its pending PASS/FAIL can be returned.
                    strict=not pack_lifecycle.active,
                    known_container_ids=observed_candidate_container_ids,
                )
            except CandidateContainerCleanupError as exc:
                if primary_exception_active or pack_lifecycle.active:
                    pass
                else:
                    cleanup_result = BlackboxResult(
                        False,
                        0,
                        0,
                        str(exc),
                        False,
                        "candidate container cleanup failed",
                        pack_sha256,
                        pack_manifest,
                        None,
                        iso,
                        deleted_applied,
                        started=pack_lifecycle.started,
                        completed=False,
                        execution_state=(
                            "started_incomplete"
                            if pack_lifecycle.started
                            else "not_started"
                        ),
                        execution_phase=(
                            "blackbox_pack" if pack_lifecycle.started else "preflight"
                        ),
                        pack_present=True if pack_sha256 else None,
                    )
                    if pack_lifecycle.started:
                        cleanup_result = _attach_candidate_execution_evidence(
                            cleanup_result,
                            recorder=invocation_recorder,
                            cidfile_dir=cidfile_dir,
                            observed_container_ids=observed_candidate_container_ids,
                        )
                    raise _BlackboxCleanupFailure(cleanup_result) from exc
            except BaseException:
                if not primary_exception_active:
                    raise
        finally:
            try:
                if invocation_recorder is not None:
                    try:
                        invocation_recorder.close()
                    except BaseException:
                        if not primary_exception_active:
                            raise
            finally:
                shutil.rmtree(workdir, ignore_errors=True)
                if pack_workdir is not None:
                    shutil.rmtree(pack_workdir, ignore_errors=True)


def run_blackbox(
    repo_path: str,
    candidate: str,
    pack_dir: str,
    *,
    timeout: int = 120,
    isolation: str = "subprocess",
    docker_image: str | None = None,
    docker_network: str = "none",
    docker_runtime: str | None = None,
    mem_limit_mb: int = 0,
    deleted_paths: tuple[str, ...] = (),
    file_blocks: dict[str, str] | None = None,
    expect_verifier_pack_sha256: str | None = None,
) -> BlackboxResult:
    """Run the black-box judge and report strict post-run cleanup failures."""
    try:
        return _run_blackbox_impl(
            repo_path,
            candidate,
            pack_dir,
            timeout=timeout,
            isolation=isolation,
            docker_image=docker_image,
            docker_network=docker_network,
            docker_runtime=docker_runtime,
            mem_limit_mb=mem_limit_mb,
            deleted_paths=deleted_paths,
            file_blocks=file_blocks,
            expect_verifier_pack_sha256=expect_verifier_pack_sha256,
        )
    except _BlackboxCleanupFailure as exc:
        return exc.result
