# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ─────────────────────────────────────────────────────────────────────────────
"""Sixth domain — repo-level evolution (S19).

The hypothesis is no longer a single function: it is a *set of file edits*
applied to a copy of a real repository, judged by the repository's own test
suite. The repo becomes the fitness landscape; the loop evolves patches.

Hypothesis format — full-file blocks, not unified diffs (LLM diffs break on
drifted line numbers; whole-file replacement is robust):

    <<<FILE: relative/path/to/file.py>>>
    ...the complete new content of that file...
    <<<END FILE>>>

Any number of blocks. Each block replaces (or creates) one file inside a
throwaway copy of the repo; the original repository is **never** touched.

Surgical-edit format — for changing a *large existing* file without rewriting it
whole (issue #15), a search/replace block applied via
:func:`evoom_guard.patch_applier.apply_patch` with a unique anchor:

    <<<PATCH: relative/path/to/file.py>>>
    <<<SEARCH>>>
    ...a unique anchor copied verbatim from the file...
    <<<REPLACE>>>
    ...its replacement...
    <<<END PATCH>>>

The anchor must occur **exactly once** in the file (else the patch is rejected
with ``AmbiguousMatchError``); a missing anchor is ``NoMatchError``. Both surface
as a precise diagnostic the loop feeds back, so the next generation can fix the
anchor. ``FILE`` and ``PATCH`` blocks may be mixed; patches apply in order, after
the file blocks.

Protected-path rule: the candidate may not edit or delete a path covered by the
active judge policy. Paths under ``tests/``, files named
``test_*.py`` / ``*_test.py`` / ``conftest.py``, JavaScript/TypeScript colocated
test files (``*.test.ts``, ``*.spec.ts``, etc.), and any extra ``protected`` globs
are rejected outright, otherwise the loop would learn to delete its own judge. The
same rejection covers test-runner / build configuration (``pyproject.toml``,
``pytest.ini``, ``tox.ini``, ``setup.cfg``, ``vitest.config.*``, ``foundry.toml``,
…) and dependency lock files (``pnpm-lock.yaml``, ``package-lock.json``,
``yarn.lock``, ``Cargo.lock``, …): editing them is a *reward-hack* — a candidate
can make a failing suite report success WITHOUT fixing the code. See
:func:`is_protected_config`. EvoGuard's own ``.evoguard.json`` and the CI files
that run the gate (``.github/workflows/``, ``.github/actions/``) are rejected for
the same reason — editing them could rewrite the test command or disable the gate
outright (see :func:`is_protected_ci`). The dual-purpose ``package.json`` is not
rejected (it carries real dependencies and source metadata); instead its
test-harness fields (``scripts.test`` and embedded ``jest``/``vitest`` config) are
restored from the pristine original after a candidate edit — see
:func:`restore_judge_package_json`. Custom repository-local wrappers/helpers
must be listed as exact regular paths in trusted ``harness_inputs``. EvoGuard
does not parse commands, imports, package scripts, or dynamic loads to infer a
complete transitive execution graph.

Score gradient (reuses :func:`evoom_guard.verifiers.grading.fraction_score`):

    0.02  no parseable file blocks
    0.05  unsafe / protected / config path (absolute, ``..`` escape, test or
          test-config files)
    0.10  test session failed to start (collection/usage error, no tests ran)
    0.25+ tests ran; score climbs with the fraction passed
    1.00  full pass (exit code 0)

SECURITY — the suite runs in a subprocess with a hard timeout and POSIX
rlimits, but it needs the repo's installed dependencies, so strong interpreter
isolation (``-I -S``, viable only for self-contained code) does not apply here.
Treat this as *basic* isolation: for untrusted targets or unattended VPS
operation, run it inside a network-less container with CPU/memory limits (see the
trust boundary in ``docs/GUARD.md``).
"""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from contextvars import ContextVar
from typing import Any, TypedDict, cast

from evoom_guard.adapters import instrument_command
from evoom_guard.candidate import (
    PatchBlock as PatchBlock,
)
from evoom_guard.candidate import (
    PatchError as PatchError,
)
from evoom_guard.candidate import (
    apply_patch,
)
from evoom_guard.candidate import edits as _candidate_edits
from evoom_guard.candidate import (
    parse_blocks_lenient as parse_blocks_lenient,
)
from evoom_guard.candidate import (
    parse_file_blocks as parse_file_blocks,
)
from evoom_guard.candidate import (
    parse_patch_blocks as parse_patch_blocks,
)
from evoom_guard.contracts import VerdictResult
from evoom_guard.domain import validate_isolation_mode
from evoom_guard.domain.execution import IsolationObservation
from evoom_guard.execution import (
    DEFAULT_KILL_GRACE_SECONDS,
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_READ_CHUNK_BYTES,
    DEFAULT_READER_JOIN_SECONDS,
    DEFAULT_TERMINATION_GRACE_SECONDS,
    BoundedOutput,
    PosixRLimitSpec,
    ProcessLimits,
    drain_process_pipe,
    join_pipe_readers,
    process_group_popen_kwargs,
    resolve_host_command,
    run_bounded_subprocess,
)
from evoom_guard.execution import (
    ProcessContainmentError as _SubprocessContainmentError,
)
from evoom_guard.execution import (
    ProcessOutputLimitExceeded as _SubprocessOutputLimitExceeded,
)
from evoom_guard.execution.judge_environment import create_judge_phase_environment
from evoom_guard.isolation import (
    DOCKER_CLEANUP_RECONCILE_ATTEMPTS as _DOCKER_CLEANUP_RECONCILE_ATTEMPTS,
)
from evoom_guard.isolation import (
    DOCKER_CLEANUP_RECONCILE_INTERVAL_SECONDS as _DOCKER_CLEANUP_RECONCILE_INTERVAL_SECONDS,
)
from evoom_guard.isolation import (
    DOCKER_CLEANUP_REQUIRED_FINAL_ABSENT_OBSERVATIONS as _DOCKER_CLEANUP_REQUIRED_FINAL_ABSENT_OBSERVATIONS,
)
from evoom_guard.isolation import (
    DOCKER_CLEANUP_TOTAL_TIMEOUT_SECONDS as _DOCKER_CLEANUP_TOTAL_TIMEOUT_SECONDS,
)
from evoom_guard.isolation import (
    DOCKER_CONTROL_TIMEOUT_SECONDS as _DOCKER_CONTROL_TIMEOUT_SECONDS,
)
from evoom_guard.isolation import (
    DOCKER_PULL_TIMEOUT_SECONDS as _DOCKER_PULL_TIMEOUT_SECONDS,
)
from evoom_guard.isolation import (
    DockerControlRequest,
    DockerRunContainmentError,
    DockerRunOutputLimit,
    DockerRunRequest,
    DockerRunTimeout,
    cleanup_named_container,
    docker_container_name,
    execute_docker_control,
    probe_container_absent,
    probe_container_started,
    require_canonical_docker_image_id,
    resolve_docker_image,
    run_named_docker_client,
)
from evoom_guard.pack_manifest import (
    snapshot_pack,
    verify_pack_snapshot,
)
from evoom_guard.policy.harness import (
    HarnessInputPolicyError,
    normalize_harness_inputs,
    setup_output_harness_conflicts,
)
from evoom_guard.runtime_identity import (
    RuntimeIdentity as RuntimeIdentity,
)
from evoom_guard.runtime_identity import (
    RuntimeIdentityError as RuntimeIdentityError,
)
from evoom_guard.runtime_identity import (
    capture_runtime_identity,
    verify_runtime_identity,
)
from evoom_guard.verifiers import assert_liveness
from evoom_guard.verifiers.diagnostics import distill_diagnostics
from evoom_guard.verifiers.fidelity import (
    _DEFAULT_SETUP_OUTPUT_DIRS as _DEFAULT_SETUP_OUTPUT_DIRS,
)
from evoom_guard.verifiers.fidelity import (
    SetupFidelityError as SetupFidelityError,
)
from evoom_guard.verifiers.fidelity import (
    _fidelity_entry_state as _fidelity_entry_state,
)
from evoom_guard.verifiers.fidelity import (
    _is_default_setup_output as _is_default_setup_output,
)
from evoom_guard.verifiers.fidelity import setup_fidelity_changes, setup_fidelity_snapshot
from evoom_guard.verifiers.harness_policy import (
    _AUTOEXEC_TESTLIKE as _AUTOEXEC_TESTLIKE,
)
from evoom_guard.verifiers.harness_policy import (
    _PKG_RUNNER_KEYS as _PKG_RUNNER_KEYS,
)
from evoom_guard.verifiers.harness_policy import (
    _PROTECTED_AUTOEXEC as _PROTECTED_AUTOEXEC,
)
from evoom_guard.verifiers.harness_policy import (
    _PROTECTED_BASENAMES as _PROTECTED_BASENAMES,
)
from evoom_guard.verifiers.harness_policy import (
    _PROTECTED_CI_PREFIXES as _PROTECTED_CI_PREFIXES,
)
from evoom_guard.verifiers.harness_policy import (
    _PROTECTED_CONFIG as _PROTECTED_CONFIG,
)
from evoom_guard.verifiers.harness_policy import (
    HarnessInputIntegrityError,
    capture_harness_input_snapshot,
    harness_input_snapshot_changes,
    matches_globs,
    validate_harness_input_files,
)
from evoom_guard.verifiers.harness_policy import (
    _is_judge_script as _is_judge_script,
)
from evoom_guard.verifiers.harness_policy import (
    discover_local_action_dirs as discover_local_action_dirs,
)
from evoom_guard.verifiers.harness_policy import (
    is_addable_new_test as is_addable_new_test,
)
from evoom_guard.verifiers.harness_policy import (
    is_allowlist_exemptible as is_allowlist_exemptible,
)
from evoom_guard.verifiers.harness_policy import (
    is_judge_autoexec as is_judge_autoexec,
)
from evoom_guard.verifiers.harness_policy import (
    is_protected as is_protected,
)
from evoom_guard.verifiers.harness_policy import (
    is_protected_ci as is_protected_ci,
)
from evoom_guard.verifiers.harness_policy import (
    is_protected_config as is_protected_config,
)
from evoom_guard.verifiers.harness_policy import (
    is_safe_relpath as is_safe_relpath,
)
from evoom_guard.verifiers.harness_policy import (
    reject_unsafe_or_protected as reject_unsafe_or_protected,
)
from evoom_guard.verifiers.harness_policy import (
    restore_judge_package_json as restore_judge_package_json,
)
from evoom_guard.verifiers.junit_oracle import (
    JUNIT_COMPOSITE_DIGEST_FORMAT as JUNIT_COMPOSITE_DIGEST_FORMAT,
)
from evoom_guard.verifiers.junit_oracle import (
    JUNIT_REPORT_SET_DIGEST_FORMAT as JUNIT_REPORT_SET_DIGEST_FORMAT,
)
from evoom_guard.verifiers.junit_oracle import (
    JUNIT_XML_DIGEST_FORMAT as JUNIT_XML_DIGEST_FORMAT,
)
from evoom_guard.verifiers.junit_oracle import (
    JUnitCounts as JUnitCounts,
)
from evoom_guard.verifiers.junit_oracle import (
    _count_testcases as _count_testcases,
)
from evoom_guard.verifiers.junit_oracle import (
    canary_case_failed as canary_case_failed,
)
from evoom_guard.verifiers.junit_oracle import (
    detect_tamper as detect_tamper,
)
from evoom_guard.verifiers.junit_oracle import (
    grade_repo_run as grade_repo_run,
)
from evoom_guard.verifiers.junit_oracle import (
    parse_junit_dir as parse_junit_dir,
)
from evoom_guard.verifiers.junit_oracle import (
    parse_junit_dir_with_digest as parse_junit_dir_with_digest,
)
from evoom_guard.verifiers.junit_oracle import (
    parse_junit_xml as parse_junit_xml,
)
from evoom_guard.verifiers.junit_oracle import (
    parse_pytest_counts as parse_pytest_counts,
)
from evoom_guard.verifiers.junit_oracle import (
    read_junit_xml as read_junit_xml,
)
from evoom_guard.verifiers.repo_candidate import (
    RepoCandidateAdmissionRequest,
    RepoCandidateAdmissionServices,
    RepoCandidateDeletionRequest,
    RepoCandidateDeletionServices,
    RepoCandidateMaterializationRequest,
    RepoCandidateMaterializationServices,
    admit_repo_candidate,
    apply_repo_candidate_deletions,
    materialize_repo_candidate,
)
from evoom_guard.verifiers.repo_cleanup import (
    RepoCleanupRequest,
    RepoCleanupServices,
    cleanup_repo_verification,
)
from evoom_guard.verifiers.repo_execution import (
    RepoExecutionTrace,
    isolation_observation_payload,
)
from evoom_guard.verifiers.repo_materialization import materialize_candidate_edits
from evoom_guard.verifiers.repo_pack import (
    RepoPackExecutionRequest,
    RepoPackExecutionServices,
    RepoPackInterpretationRequest,
    RepoPackInterpretationServices,
    execute_repo_pack,
    interpret_repo_pack,
)
from evoom_guard.verifiers.repo_pack_continuity import (
    AcceptedRepoPackIdentity,
    RepoPackContinuity,
    RepoPackContinuityRequest,
    RepoPackContinuityServices,
)
from evoom_guard.verifiers.repo_pack_intake import (
    RepoPackIntakeRequest,
    RepoPackIntakeServices,
    intake_repo_pack,
    rejection_artifact,
)
from evoom_guard.verifiers.repo_phase_contracts import (
    compose_repo_and_pack,
    evaluate_pack_phase,
    evaluate_repo_phase,
)
from evoom_guard.verifiers.repo_result import (
    FinalRepoPhase,
    RepoFinalArtifactRequest,
    RepoPackPhaseArtifact,
    RepoResultProjection,
    build_final_repo_artifact,
)
from evoom_guard.verifiers.repo_runtime_continuity import (
    RepoRuntimeContinuity,
    RepoRuntimeContinuityRequest,
    RepoRuntimeContinuityServices,
    runtime_identity_evidence_payload,
)
from evoom_guard.verifiers.repo_setup import (
    RepoSetupRequest,
    RepoSetupServices,
    execute_repo_setup,
)
from evoom_guard.verifiers.repo_suite import (
    RepoSuiteExecutionRequest,
    RepoSuiteExecutionServices,
    RepoSuiteInterpretationRequest,
    RepoSuiteInterpretationServices,
    execute_repo_suite,
    interpret_repo_suite,
)
from evoom_guard.workspace import (
    UnsafeWorkspacePath,
    delete_path_within_root,
    read_text_within_root,
    write_text_within_root,
)
from evoom_guard.workspace import repository as _repository_workspace
from evoom_guard.workspace.repository_lifetime import RepositoryWorkspaceLifetime

_BLOCK_RE = _candidate_edits._BLOCK_RE
_LENIENT_FILE_RE = _candidate_edits._LENIENT_FILE_RE
_LENIENT_PATCH_RE = _candidate_edits._LENIENT_PATCH_RE
_PATCH_BLOCK_RE = _candidate_edits._PATCH_BLOCK_RE

# Stable compatibility facades. Internal call sites retain their historical
# names so monkeypatch-based adopters keep controlling RepoVerifier, while new
# callers can import the public contracts from their owning modules.
_matches_globs = matches_globs
_resolve_host_command = resolve_host_command
_setup_fidelity_changes = setup_fidelity_changes
_setup_fidelity_snapshot = setup_fidelity_snapshot

try:  # POSIX-only; absent on Windows.
    import resource
except ImportError:  # pragma: no cover - platform dependent
    resource = None  # type: ignore[assignment]

# Stable compatibility constant. The facade below still injects this module's
# current value on every call so existing monkeypatch seams remain live.
COPY_IGNORE = _repository_workspace.COPY_IGNORE


def judge_subprocess_env(workdir: str) -> dict[str, str]:
    """Minimal cross-platform environment for judge-owned subprocesses.

    Windows runtimes depend on a small set of OS variables even when the judged
    program does not.  In particular, current Node releases abort during CSPRNG
    initialization when ``SYSTEMROOT`` is absent.  Preserve only the OS plumbing
    needed to start tools; keep scratch paths inside the judge-owned workdir and
    continue excluding user Python startup state.
    """
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin"),
        "HOME": workdir,
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }
    if os.name == "nt":
        for key in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
            value = os.environ.get(key)
            if value:
                env[key] = value
        env["TEMP"] = workdir
        env["TMP"] = workdir
    return env


class RepoProblem(TypedDict, total=False):
    """A repo-level problem definition."""

    name: str
    repo_path: str            # root of the target repository (never modified)
    description: str          # the task brief, in natural language
    test_command: list[str]   # judge command (default: pytest -q in the copy)
    setup_command: list[str]  # optional: runs before test_command inside the copy
                              # (e.g. ["pnpm", "install", "--frozen-lockfile"] for
                              # Node.js repos where COPY_IGNORE strips node_modules)
    target_files: list[str]   # generator hint: files to show the model first
    protected: list[str]      # extra globs the candidate may not modify
    allow: list[str]          # baseline allowlist: globs exempt from the test/config/
                              # CI rejection (never auto-exec or unsafe paths)
    allow_new_tests: bool     # opt-in "feature mode": allow *net-new* test files
                              # (existing-test / config / auto-exec edits stay rejected)
    deleted: list[str]        # paths the candidate deletes (from a base→head diff):
                              # safe source deletions are applied to the copy; a
                              # protected-harness deletion is rejected
    timeout: int              # per-candidate suite timeout (CLI uses this)
    mem_limit_mb: int         # address-space cap for the suite (CLI uses this);
                              # 0 disables the cap — required for node/V8 suites,
                              # whose virtual reservations exceed any sane RLIMIT_AS
    hide_tests: bool          # closed-book mode: the generator must not show the
                              # judging test files' content to the model
    file_blocks: dict[str, str]  # STRUCTURED candidate override: {relpath: content}.
                              # When present, the hypothesis text is NOT parsed for
                              # <<<FILE>>> blocks — this is how the dirs/diff path
                              # avoids the marker round-trip (a target file whose
                              # CONTENT legitimately contains "<<<END FILE>>>" must
                              # not terminate its own block; found by running Guard
                               # on Guard's own source, which embeds those markers).
    expect_verifier_pack_sha256: str  # optional V2 identity pin; mismatch fails closed
    # Container-judge fields used by Docker/gVisor isolation:
    docker_image: str         # runtime image, e.g. "node:22-slim"
    network: str              # "none" (default) or a docker network name
    judge_env: dict[str, str]  # explicit env passed into the container
    mounts_ro: list[str]      # "host:container" read-only binds
    tmpfs: list[str]          # container paths granted scratch (tmpfs) writes


# Candidate commands control stdout/stderr. A full capture is therefore a
# bounded execution concern, not verifier policy. These names remain as
# compatibility seams for existing in-package callers and tests.
_MAX_SUBPROCESS_OUTPUT_BYTES = DEFAULT_MAX_OUTPUT_BYTES
_SUBPROCESS_READ_CHUNK_BYTES = DEFAULT_READ_CHUNK_BYTES
_PROCESS_TERM_GRACE_SECONDS = DEFAULT_TERMINATION_GRACE_SECONDS
_PROCESS_KILL_GRACE_SECONDS = DEFAULT_KILL_GRACE_SECONDS
_READER_JOIN_SECONDS = DEFAULT_READER_JOIN_SECONDS
class _BoundedOutput(BoundedOutput):
    """Compatibility capture using the verifier's current patched limit."""

    def __init__(self, limit: int | None = None) -> None:
        super().__init__(
            _MAX_SUBPROCESS_OUTPUT_BYTES if limit is None else limit
        )


def _drain_subprocess_pipe(
    stream: Any, capture: BoundedOutput, stream_name: str
) -> None:
    """Compatibility facade using the verifier's current read chunk."""

    drain_process_pipe(
        stream,
        capture,
        stream_name,
        _SUBPROCESS_READ_CHUNK_BYTES,
    )


def _join_pipe_readers(
    readers: list[Any], streams: list[Any]
) -> bool:
    """Compatibility facade using the verifier's current join deadline."""

    return join_pipe_readers(readers, streams, _READER_JOIN_SECONDS)


_DockerRunOutputLimit = DockerRunOutputLimit
_DockerRunContainmentError = DockerRunContainmentError
_DockerRunTimeout = DockerRunTimeout


def _subprocess_group_kwargs() -> dict[str, Any]:
    """Compatibility facade for the extracted host process-group contract."""

    return process_group_popen_kwargs()


def _run_bounded_subprocess(
    command: list[str],
    *,
    cwd: str | None,
    env: dict[str, str] | None,
    timeout: float,
    preexec_fn: Any = None,
    require_process_group_cleanup_proof: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Compatibility facade over the typed execution-kernel contract."""

    return run_bounded_subprocess(
        command,
        cwd=cwd,
        env=env,
        timeout=timeout,
        preexec_fn=preexec_fn,
        require_process_group_cleanup_proof=(
            require_process_group_cleanup_proof
        ),
        limits=ProcessLimits(
            max_output_bytes=_MAX_SUBPROCESS_OUTPUT_BYTES,
            read_chunk_bytes=_SUBPROCESS_READ_CHUNK_BYTES,
            termination_grace_seconds=_PROCESS_TERM_GRACE_SECONDS,
            kill_grace_seconds=_PROCESS_KILL_GRACE_SECONDS,
            reader_join_seconds=_READER_JOIN_SECONDS,
        ),
    )


def _read_text_or_none(path: str) -> str | None:
    """Compatibility wrapper for bounded judge-owned JUnit report reads."""
    return read_junit_xml(path)


def copy_repo_tree(src: str, dst: str) -> None:
    """Copy a repository into a throwaway working copy, faithfully.

    ``symlinks=True`` keeps symlinks *as symlinks* (and regular files keep their
    permission bits via ``copy2``), which matters twice:

    * **No crash on dangling links.** Real repos routinely carry symlinks into
      directories ``COPY_IGNORE`` strips (``.venv/``, ``node_modules/``) or
      plain broken links; dereferencing (the ``symlinks=False`` default) makes
      ``copytree`` raise on those, crashing the judge instead of judging.
    * **No content smuggling.** Dereferencing would copy the link's *target
      content* into the copy — for an absolute link that means host files get
      materialized inside the tree that container isolation later mounts.

    Writing *through* a symlink is prevented separately by the descriptor-bound
    workspace helpers used in :func:`apply_blocks_to_copy`.
    """

    _repository_workspace.copy_repo_tree(
        src,
        dst,
        copy_ignore=COPY_IGNORE,
        copytree=shutil.copytree,
        ignore_patterns=shutil.ignore_patterns,
    )


def apply_blocks_to_copy(
    copy: str, file_blocks: dict[str, str], patch_blocks: list[PatchBlock]
) -> str | None:
    """Compatibility facade for ordered candidate edit materialization."""

    return materialize_candidate_edits(
        copy,
        file_blocks,
        patch_blocks,
        read_text=lambda root, path: read_text_within_root(root, path),
        write_text=lambda root, path, content: write_text_within_root(
            root, path, content
        ),
        patcher=lambda source, search, replace: apply_patch(source, search, replace),
        restore_package_json=lambda original, candidate: restore_judge_package_json(
            original, candidate
        ),
    )


def _docker_container_name(stage: str) -> str:
    """Collision-resistant name for concurrent setup/suite/pack containers."""
    return docker_container_name(stage, token_hex=secrets.token_hex)


def _run_docker_control(
    command: list[str], *, timeout: float
) -> subprocess.CompletedProcess[str]:
    """Run a Docker control-plane command with the same bounded capture.

    Docker's own diagnostics are not trustworthy enough to let ``inspect`` or
    ``pull`` allocate unbounded memory in the judge.  These commands do not run
    a candidate process directly, but their daemon responses are still external
    input and can be arbitrarily large on a compromised or misconfigured host.
    """
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


def _docker_container_started(name: str) -> bool:
    """Return true only when Docker proves that the named container started.

    A timeout of the ``docker run`` client is not itself evidence that the
    daemon created or started the container.  Inspect is deliberately
    fail-closed: any missing/empty/zero ``StartedAt`` value means not proven.
    """
    return probe_container_started(
        name,
        control_runner=_run_docker_control,
        timeout=_DOCKER_CONTROL_TIMEOUT_SECONDS,
    ).proven


def _docker_container_absence_observation(
    name: str,
    *,
    timeout: float = _DOCKER_CONTROL_TIMEOUT_SECONDS,
) -> bool | None:
    """Return one positive presence/absence observation, or ``None`` on doubt.

    The typed isolation kernel owns validation, exact-name enumeration, and the
    fail-closed distinction between present and unverifiable observations.
    """
    return probe_container_absent(
        name,
        control_runner=_run_docker_control,
        timeout=timeout,
    ).absent


def _docker_container_absent(name: str) -> bool:
    """Return true only after one successful exact-name absence observation."""

    return _docker_container_absence_observation(name) is True


def _cleanup_docker_container(name: str) -> bool:
    """Force-remove a named container and establish bounded stable absence.

    ``docker run --rm`` normally removes a container when its client exits, but
    an interrupted client can leave the daemon-side workload alive.  A failed
    or unverifiable cleanup is a containment failure, not a routine timeout.
    ``docker rm`` output is captured only through the shared bounded control
    channel.
    """
    cleanup = cleanup_named_container(
        name,
        control_runner=_run_docker_control,
        control_timeout=_DOCKER_CONTROL_TIMEOUT_SECONDS,
        total_timeout=_DOCKER_CLEANUP_TOTAL_TIMEOUT_SECONDS,
        reconcile_attempts=_DOCKER_CLEANUP_RECONCILE_ATTEMPTS,
        reconcile_interval=_DOCKER_CLEANUP_RECONCILE_INTERVAL_SECONDS,
        required_final_absent_observations=(
            _DOCKER_CLEANUP_REQUIRED_FINAL_ABSENT_OBSERVATIONS
        ),
        monotonic=time.monotonic,
        sleeper=time.sleep,
    )
    return cleanup.proven_absent


def _note_repo_cleanup_failure(primary: BaseException, message: str) -> None:
    """Attach cleanup diagnostics without ever replacing ``primary``."""

    _repository_workspace.note_cleanup_failure(primary, message)


def _cleanup_repo_workspaces(
    workspaces: tuple[tuple[str, str | None], ...],
    *,
    primary: BaseException | None,
) -> None:
    """Remove every judge-owned workspace with explicit exception precedence.

    All paths are attempted.  With no active exception, the first cleanup
    failure remains visible (and any later failures are attached as notes).
    While another exception is unwinding, that exact exception remains primary
    and receives one note per cleanup failure instead of being masked.
    """

    cleanup_repo_verification(
        RepoCleanupRequest(
            workspaces=workspaces,
            primary=primary,
        ),
        services=RepoCleanupServices(
            cleanup_workspaces_provider=(
                lambda: _repository_workspace.cleanup_repo_workspaces
            ),
            remove_tree_provider=lambda: shutil.rmtree,
            note_failure_provider=lambda: _note_repo_cleanup_failure,
        ),
    )


class RepoVerifier:
    """Apply the hypothesis to a copy of the repo and judge it with its tests."""

    domain = "repo"

    def __init__(
        self,
        timeout: int = 120,
        mem_limit_mb: int = 1024,
        *,
        test_command: list[str] | None = None,
        setup_command: list[str] | None = None,
        protected: tuple[str, ...] = (),
        allow: tuple[str, ...] = (),
        allow_new_tests: bool = False,
        isolation: str = "subprocess",
        docker_image: str | None = None,
        docker_network: str = "none",
        docker_runtime: str | None = None,
        trust_setup_on_host: bool = False,
        setup_output_globs: tuple[str, ...] = (),
        strict_harness: bool = False,
        harness_inputs: tuple[str, ...] = (),
        require_suite_continuity: bool = False,
        require_assert_liveness: bool = False,
        require_structured_verdict: bool = False,
    ) -> None:
        validate_isolation_mode(isolation)
        self.timeout = timeout
        self.mem_limit_mb = mem_limit_mb
        self.test_command = test_command
        self.setup_command = setup_command
        self.protected = protected
        # Adopter-curated allowlist (baseline): globs exempt from the test/config/CI
        # rejection (never auto-exec or unsafe paths). See reject_unsafe_or_protected.
        self.allow = allow
        # Opt-in feature mode: allow net-new test files (see is_addable_new_test).
        self.allow_new_tests = allow_new_tests
        # isolation == "docker" runs the suite inside a short-lived, network-less,
        # read-only container (defence in depth for semi-trusted code); the default
        # "subprocess" path is unchanged. See ``_docker_command`` and docs/GUARD.md.
        # isolation == "gvisor" is the same container judge but through the gVisor
        # OCI runtime (`runsc`) — a user-space guest kernel, no /dev/kvm needed — so
        # the suite runs under a separate kernel. See docs/VM_ISOLATION.md.
        self.isolation = isolation
        self.docker_image = docker_image
        self.docker_network = docker_network
        self.docker_runtime = docker_runtime or ("runsc" if isolation == "gvisor" else None)
        self._active_docker_image: ContextVar[str | None] = ContextVar(
            f"evoom_guard_repo_image_{id(self)}",
            default=None,
        )
        # Compatibility/diagnostic seam: the last identity resolved by this
        # instance. Verification commands use the context-local identity above,
        # so concurrent or later calls cannot inherit this mutable observation.
        self._resolved_docker_image: str | None = None
        # Explicit compatibility escape hatch. By default candidate-influenced
        # setup runs inside the same requested boundary as the suite.
        self.trust_setup_on_host = trust_setup_on_host
        self.setup_output_globs = setup_output_globs
        # Strict profile is opt-in: it makes the verifier refuse exit-only or
        # zero-test success, and the preflight treats execution-environment
        # manifests as immutable judge inputs.
        self.strict_harness = strict_harness
        # Opt-in trusted-repository control: capture the fully prepared tree and
        # reject a repo suite that rewrites it at runtime, even when no verifier
        # pack is configured. Default off, so the ordinary subprocess path is
        # unchanged; intended for trusted suites that never write into the tree.
        self.require_suite_continuity = require_suite_continuity
        # Opt-in trusted-repository control: auto-inject the judge-owned
        # assertion-liveness canary (catalog row 11b) into the pytest command so a
        # candidate that neuters unittest assertions is caught instead of yielding a
        # false PASS. Default off; pytest-only (a non-pytest command with this set is
        # refused before any suite runs). See evoom_guard/verifiers/assert_liveness.py.
        self.require_assert_liveness = require_assert_liveness
        # Opt-in trusted-repository control: refuse (ERROR) rather than run when the
        # repository test command has no structured runner adapter, i.e. the verdict
        # would be graded from the process exit code alone with no judge-owned JUnit
        # evidence and no exit/report tamper cross-check. Default off; a requested
        # security control must never silently downgrade, so the refusal is terminal
        # and fires before any suite runs. See _structured_verdict_preflight.
        self.require_structured_verdict = require_structured_verdict
        # Command wrappers and explicitly declared helper files are judge-owned
        # and cannot be waived through the ordinary adopter allowlist.
        self.harness_inputs = normalize_harness_inputs(harness_inputs)
        harness_conflicts = setup_output_harness_conflicts(
            self.harness_inputs,
            self.setup_output_globs,
        )
        if harness_conflicts:
            raise HarnessInputPolicyError(
                "setup_output_globs cannot exclude harness_inputs: "
                + ", ".join(harness_conflicts)
            )

    # ------------------------------------------------------------------ #
    def _limits(self) -> PosixRLimitSpec | None:
        """Return inert CPU/address-space policy for the POSIX launcher."""
        if resource is None:
            return None

        return PosixRLimitSpec(
            cpu_seconds=max(1, int(self.timeout) + 1),
            address_space_bytes=(
                self.mem_limit_mb * 1024 * 1024
                if self.mem_limit_mb > 0
                else None
            ),
        )

    # ------------------------------------------------------------------ #
    def _base_command(self, problem: RepoProblem | dict) -> list[str]:
        cmd = self.test_command or problem.get("test_command")
        if isinstance(cmd, str):
            return cmd.split()
        if cmd:
            return list(cmd)
        python = "python" if self.isolation in ("docker", "gvisor") else sys.executable
        return [python, "-m", "pytest", "-q", "--color=no", "-p", "no:cacheprovider"]

    # ------------------------------------------------------------------ #
    def _command(self, problem: RepoProblem | dict) -> list[str]:
        base = self._base_command(problem)
        # When assertion-liveness is required, load the judge-owned canary plugin
        # (``-p assert_liveness_plugin``) rather than a positional test path: a
        # positional path would suppress the repository's own testpaths collection
        # and skip the real suite, whereas the plugin appends the canary to whatever
        # is already collected. The non-pytest case is refused earlier in ``verify``
        # before any suite runs; the guard here keeps a non-pytest command untouched.
        if self.require_assert_liveness and assert_liveness.command_is_pytest(base):
            return [*base, *assert_liveness.plugin_command_args()]
        return base

    # ------------------------------------------------------------------ #
    def _docker_command(
        self, cmd: list[str], copy: str, outdir: str | None, name: str,
        report_env: dict[str, str] | None = None,
        *,
        work_writable: bool = False,
        pack_dir: str | None = None,
    ) -> list[str]:
        """Wrap ``cmd`` in a short-lived, isolated ``docker run`` for the docker /
        gvisor judge (``--runtime runsc`` is added when ``docker_runtime`` is set)."""
        docker = [
            "docker", "run", "--rm", "--name", name,
            "--network", self.docker_network,
            "--pids-limit", "256", "--cpus", "1", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--ulimit", "nofile=1024:1024",
            "--tmpfs", "/tmp:rw,exec",
            "-e", "HOME=/tmp",
            "-e", "TMPDIR=/tmp",
            "-e", "TEMP=/tmp",
            "-e", "TMP=/tmp",
            "-e", "XDG_CACHE_HOME=/tmp",
            "-e", "PYTHONDONTWRITEBYTECODE=1",
            "-e", "PYTHONNOUSERSITE=1",
            "-e", "LANG=C.UTF-8",
            "-v", f"{copy}:/work:{'rw' if work_writable else 'ro'}",
        ]
        if outdir is not None:
            docker += ["-v", f"{outdir}:/out:rw"]
        if pack_dir is not None:
            docker += ["-v", f"{pack_dir}:/verifier-pack:ro"]
        if self.require_assert_liveness:
            # The copy mounts read-only at /work, so the judge-owned canary plugin
            # in /work/.evoguard is untamperable; put that directory on PYTHONPATH
            # so ``-p assert_liveness_plugin`` loads inside the container.
            docker += ["-e", f"PYTHONPATH=/work/{assert_liveness.CANARY_DIRNAME}"]
        getuid = getattr(os, "getuid", None)
        getgid = getattr(os, "getgid", None)
        if callable(getuid) and callable(getgid):
            # Match ownership of the host-created work/report directories. This
            # lets us drop every capability without relying on root's DAC bypass.
            docker += ["--user", f"{getuid()}:{getgid()}"]
        docker += ["-w", "/work"]
        # A stronger OCI runtime (gVisor's `runsc`) gives the suite its own
        # user-space guest kernel without needing /dev/kvm.
        if self.docker_runtime:
            docker += ["--runtime", self.docker_runtime]
        # Reporter env a runner needs to reach the judge-owned report (jest-junit).
        for _k, _v in (report_env or {}).items():
            docker += ["-e", f"{_k}={_v}"]
        if self.mem_limit_mb > 0:
            docker += ["--memory", f"{self.mem_limit_mb}m"]
        active_image = self._active_docker_image.get()
        image_id = require_canonical_docker_image_id(
            str(active_image or self._resolved_docker_image or self.docker_image)
        )
        return [*docker, image_id, *cmd]

    def _resolve_docker_image(self) -> str:
        """Resolve the configured tag for one verification session."""
        image = str(self.docker_image or "")

        def control(
            command: list[str], *, timeout: float
        ) -> subprocess.CompletedProcess[str]:
            try:
                return _run_docker_control(command, timeout=timeout)
            except (_SubprocessOutputLimitExceeded, _SubprocessContainmentError) as exc:
                phase = "pull" if command[:2] == ["docker", "pull"] else "inspection"
                raise RuntimeError(
                    f"container image {image!r} {phase} could not be safely captured: {exc}"
                ) from exc

        resolution = resolve_docker_image(
            image,
            control_runner=control,
            pull_when_inspection_empty=False,
            control_timeout=_DOCKER_CONTROL_TIMEOUT_SECONDS,
            pull_timeout=_DOCKER_PULL_TIMEOUT_SECONDS,
        )
        if resolution.pull is not None and resolution.pull.returncode != 0:
            raise RuntimeError(
                f"container image {image!r} could not be resolved: "
                + distill_diagnostics(
                    resolution.pull.stdout + "\n" + resolution.pull.stderr
                )
            )
        if resolution.image_id is None:
            raise RuntimeError(f"container image {image!r} has no resolvable image ID")
        self._resolved_docker_image = resolution.image_id
        return resolution.image_id

    def _run_docker_client(
        self, docker_cmd: list[str], name: str
    ) -> subprocess.CompletedProcess[str]:
        """Run one named container, bounding output and cleaning it on every abort.

        Killing the Docker CLI is not enough: the daemon may keep the named
        container alive.  We observe whether it started *before* removing it,
        then require a successful, observable cleanup before returning any
        timeout or output-limit result to the caller.
        """
        request = DockerRunRequest.from_command(
            docker_cmd,
            name=name,
            timeout=self.timeout,
            environment=os.environ,
        )
        return run_named_docker_client(
            request,
            process_runner=_run_bounded_subprocess,
            container_started=_docker_container_started,
            cleanup_container=_cleanup_docker_container,
            process_argv=docker_cmd,
        )

    def _run_docker(
        self, base_cmd, copy, workdir, *, pack_dir=None
    ):  # pragma: no cover - needs docker daemon
        """Run the suite inside the docker judge."""
        outdir = os.path.join(workdir, "out")
        os.makedirs(outdir, exist_ok=True)
        host_xml = os.path.join(outdir, "judge-result.xml")
        cmd, report_expected, report_env = instrument_command(base_cmd, "/out/judge-result.xml")
        name = _docker_container_name(os.path.basename(workdir.rstrip("/")))
        docker_cmd = self._docker_command(
            cmd, copy, outdir, name, report_env, pack_dir=pack_dir
        )
        r = self._run_docker_client(docker_cmd, name)
        return host_xml, r, report_expected

    def _phase_isolation_evidence(
        self,
        delivered: str,
        image_digest: str | None,
        *,
        note: str | None = None,
    ) -> IsolationObservation:
        """Build one phase's isolation evidence without implying execution."""
        return IsolationObservation(
            requested=self.isolation,
            delivered=delivered,
            image_digest=image_digest,
            network=(
                self.docker_network
                if self.isolation in ("docker", "gvisor")
                else None
            ),
            runtime=(
                self.docker_runtime
                if self.isolation in ("docker", "gvisor")
                else None
            ),
            note=note,
        )

    # ------------------------------------------------------------------ #
    def verify(self, hypothesis: str, problem: RepoProblem | dict) -> VerdictResult:
        """Verify a candidate and attach truthful phase/execution evidence."""
        image_token = self._active_docker_image.set(None)
        try:
            trace = RepoExecutionTrace()
            result_projection = RepoResultProjection()
            pack_dir = str(problem.get("verifier_pack", "") or "")
            # Presence is not validity: an existing file/symlink is present but the
            # pack contract will reject it as an invalid root.
            pack_present = bool(pack_dir and os.path.lexists(pack_dir))
            result = self._verify(
                hypothesis,
                problem,
                trace,
                result_projection,
            )
            return result_projection.finalize(
                result,
                execution=trace.snapshot(),
                verifier_pack_present=pack_present,
            )
        finally:
            self._active_docker_image.reset(image_token)

    # ------------------------------------------------------------------ #
    # Assertion-liveness (catalog row 11b) lifecycle, factored out of
    # ``_verify`` so the main flow stays readable: a pre-suite preflight, a
    # suite-environment tweak, and an after-suite tamper check. Each is a no-op
    # when ``--require-assert-liveness`` is off, so the default path is unchanged.
    def _structured_verdict_preflight(
        self,
        *,
        problem: RepoProblem | dict,
        changed: list[str],
        setup_isolation: object,
        runtime_evidence: Callable[[], dict[str, Any]],
    ) -> VerdictResult | None:
        """Refuse an exit-code-only repository suite loudly when required.

        When ``--require-structured-verdict`` is set, a test command that no
        structured runner adapter recognizes would have its verdict graded from
        the process exit code alone — no judge-owned JUnit evidence and no
        exit/report tamper cross-check. A requested security control must never
        silently downgrade, so this returns a terminal ``VerdictResult`` before
        any suite runs. Instrumentation is a pure argv transform (nothing runs);
        the check uses the same live registry execution uses. A no-op when the
        flag is off. Only reached on the repository-suite path, so an
        ``--blackbox-only`` run — where the repository suite is not a verdict
        source — never triggers it.
        """

        if not self.require_structured_verdict:
            return None
        base_command = self._base_command(problem)
        _, report_expected, _ = instrument_command(
            [str(token) for token in base_command], "/out/judge-result.xml"
        )
        if report_expected:
            return None
        return VerdictResult(
            passed=False,
            score=0.0,
            diagnostics=(
                "--require-structured-verdict needs a test command a structured "
                "runner adapter recognizes (pytest, node --test, vitest, jest, "
                "mocha, gotestsum, rspec, maven), directly or behind a supported "
                "launcher; the configured command has none, so its verdict would "
                "be graded from the process exit code alone with no judge-owned "
                f"JUnit evidence and no tamper cross-check: {base_command}"
            ),
            artifact={
                "files_changed": changed,
                "outcome": "structured_verdict_unavailable",
                "setup_isolation": setup_isolation,
                **runtime_evidence(),
            },
        )

    def _assert_liveness_preflight(
        self,
        *,
        problem: RepoProblem | dict,
        copy: str,
        changed: list[str],
        setup_isolation: object,
        runtime_evidence: Callable[[], dict[str, Any]],
    ) -> VerdictResult | None:
        """Refuse a non-pytest command loudly, else install the judge-owned canary.

        Returns a terminal ``VerdictResult`` when the flag is set on a non-pytest
        command (a requested security control must never silently no-op); ``None``
        to proceed. The canary is written into the prepared copy *before* the
        continuity baseline, so it is part of the judged tree (and, under docker's
        read-only mount, untamperable at runtime).
        """

        if not self.require_assert_liveness:
            return None
        base_command = self._base_command(problem)
        if not assert_liveness.command_is_pytest(base_command):
            return VerdictResult(
                passed=False,
                score=0.0,
                diagnostics=(
                    "--require-assert-liveness needs a pytest test command "
                    "(the assertion-liveness canary is a pytest file); the "
                    f"configured command is not pytest: {base_command}"
                ),
                artifact={
                    "files_changed": changed,
                    "outcome": "assert_liveness_unavailable",
                    "setup_isolation": setup_isolation,
                    **runtime_evidence(),
                },
            )
        assert_liveness.install_into(copy)
        return None

    def _suite_env_with_liveness(
        self, env: dict[str, str], copy: str
    ) -> dict[str, str]:
        """Prepend the judge-owned ``.evoguard/`` dir to ``PYTHONPATH`` when required.

        Only that directory is added, so the canary plugin loads via ``-p`` under
        any pytest invocation form without shadowing a repository or stdlib module.
        A no-op when the flag is off.
        """

        if not self.require_assert_liveness:
            return env
        return assert_liveness.prepend_pythonpath(
            env, os.path.join(copy, assert_liveness.CANARY_DIRNAME)
        )

    def _assert_liveness_tamper(
        self,
        *,
        report_path: str,
        changed: list[str],
        setup_isolation: object,
        runtime_evidence: Callable[[], dict[str, Any]],
    ) -> VerdictResult | None:
        """Grade TAMPERED when the judge-owned canary node itself failed.

        A canary failure means candidate-imported code neutered the assertion
        machinery, so the report's *passes* cannot be trusted — this is tamper,
        not a plain ``tests_failed``. Returns ``None`` to fold back into the
        ordinary grading path.
        """

        if not self.require_assert_liveness:
            return None
        if not canary_case_failed(
            _read_text_or_none(report_path) or "",
            assert_liveness.CANARY_TESTID,
        ):
            return None
        return VerdictResult(
            passed=False,
            score=0.0,
            diagnostics=(
                "the assertion-liveness canary "
                f"({assert_liveness.CANARY_TESTID}) failed: candidate-"
                "imported code neutered the test framework's assertion "
                "methods, so the suite's reported passes are not trustworthy"
            ),
            artifact={
                "files_changed": changed,
                "outcome": "assertion_liveness_failed",
                "tamper": True,
                "setup_isolation": setup_isolation,
                **runtime_evidence(),
            },
        )

    # ------------------------------------------------------------------ #
    def _verify_after_suite_continuity(
        self,
        *,
        runtime_continuity: RepoRuntimeContinuity,
        changed: list[str],
        setup_isolation: object,
        runtime_evidence: Callable[[], dict[str, Any]],
        pack_sha256: str | None,
        pack_manifest: dict[str, Any] | None,
    ) -> VerdictResult | None:
        """Re-verify the judged tree's identity after the suite.

        Returns a terminal ``TAMPERED`` ``VerdictResult`` when the runtime tree
        drifted during the run (a mid-run rewrite of a judged path or a
        verification error), ``None`` when the tree is intact or no baseline was
        captured. Behaviour-preserving extraction of the after-suite continuity
        boundary from ``_verify``.
        """

        if runtime_continuity.baseline is None:
            return None
        runtime_failure = runtime_continuity.verify_after_suite()
        if runtime_failure is None:
            return None
        if runtime_failure.kind == "verification_error":
            return VerdictResult(
                passed=False,
                score=0.0,
                diagnostics=runtime_failure.diagnostics,
                artifact={
                    "files_changed": changed,
                    "outcome": "candidate_tree_changed",
                    "tamper": True,
                    "setup_isolation": setup_isolation,
                    **runtime_evidence(),
                },
            )
        assert runtime_failure.kind == "suite_drift"
        return VerdictResult(
            passed=False,
            score=0.0,
            diagnostics=runtime_failure.diagnostics,
            artifact={
                "files_changed": changed,
                "outcome": "candidate_tree_changed",
                "tamper": True,
                "candidate_fidelity_changes": list(runtime_failure.changes),
                "verifier_pack_sha256": pack_sha256,
                "verifier_pack_manifest": pack_manifest,
                "setup_isolation": setup_isolation,
                **runtime_evidence(),
            },
        )

    def _verify(
        self,
        hypothesis: str,
        problem: RepoProblem | dict,
        trace: RepoExecutionTrace,
        result_projection: RepoResultProjection,
    ) -> VerdictResult:
        repo_path = str(problem.get("repo_path", ""))
        problem_harness_inputs = problem.get("harness_inputs", ())
        if not isinstance(problem_harness_inputs, (list, tuple)):
            raise ValueError("problem['harness_inputs'] must be a list or tuple")
        effective_harness_inputs = normalize_harness_inputs(
            self.harness_inputs + tuple(problem_harness_inputs)
        )
        harness_conflicts = (
            setup_output_harness_conflicts(
                effective_harness_inputs,
                self.setup_output_globs,
            )
            if effective_harness_inputs
            else ()
        )
        if harness_conflicts:
            raise HarnessInputPolicyError(
                "setup_output_globs cannot exclude harness_inputs: "
                + ", ".join(harness_conflicts)
            )
        harness_input_problems = validate_harness_input_files(
            repo_path,
            effective_harness_inputs,
        )
        if harness_input_problems:
            raise HarnessInputPolicyError(
                "invalid harness_inputs in trusted base: "
                + "; ".join(harness_input_problems)
            )
        try:
            trusted_harness_baseline = capture_harness_input_snapshot(
                repo_path,
                effective_harness_inputs,
            )
        except (HarnessInputPolicyError, HarnessInputIntegrityError) as exc:
            return VerdictResult(
                passed=False,
                score=0.0,
                diagnostics=(
                    "declared harness input integrity could not be bound in "
                    f"the trusted base: {exc}"
                ),
                artifact={
                    "files_changed": [],
                    "outcome": "candidate_tree_changed",
                    "tamper": True,
                    "candidate_fidelity_changes": list(
                        effective_harness_inputs
                    ),
                },
            )
        admission = admit_repo_candidate(
            RepoCandidateAdmissionRequest(
                hypothesis=hypothesis,
                repo_path=repo_path,
            ),
            services=RepoCandidateAdmissionServices(
                is_directory=lambda: os.path.isdir,
                deleted_paths=lambda: problem.get("deleted", ()),
                file_blocks_override=lambda: problem.get("file_blocks"),
                target_files=lambda: problem.get("target_files", ()),
                extra_protected=lambda: (
                    self.protected + tuple(problem.get("protected", ()))
                ),
                harness_inputs=lambda: (
                    effective_harness_inputs
                ),
                allow=lambda: self.allow + tuple(problem.get("allow", ())),
                allow_new_tests=lambda: (
                    self.allow_new_tests
                    or bool(problem.get("allow_new_tests"))
                ),
                strict_harness=lambda: (
                    self.strict_harness
                    or problem.get("strict_harness") is True
                ),
                parse_file_blocks=lambda: parse_file_blocks,
                parse_patch_blocks=lambda: parse_patch_blocks,
                parse_blocks_lenient=lambda: parse_blocks_lenient,
                discover_local_action_dirs=lambda: discover_local_action_dirs,
                is_safe_relpath=lambda: is_safe_relpath,
                join_path=lambda: os.path.join,
                path_exists=lambda: os.path.exists,
                reject_paths=lambda: cast(
                    Any, reject_unsafe_or_protected
                ),
            ),
        )
        if admission.terminal_result is not None:
            return admission.terminal_result
        assert admission.candidate is not None
        candidate = admission.candidate
        deleted_paths = list(candidate.deleted_paths)
        changed = list(candidate.files_changed)
        strict_harness = candidate.strict_harness

        workspace_lifetime = RepositoryWorkspaceLifetime.create(
            prefix="evo_repo_",
            create_workspace=lambda *, prefix: (
                _repository_workspace.allocate_owned_workspace(
                    prefix=prefix,
                    create_workspace=tempfile.mkdtemp,
                )
            ),
            join_path=lambda root, path: os.path.join(root, path),
        )
        workdir = workspace_lifetime.candidate_root
        copy = workspace_lifetime.candidate_copy
        pack_snapshot: str | None = None
        pack_continuity: RepoPackContinuity | None = None
        cleanup_primary: BaseException | None = None
        try:
            materialization = materialize_repo_candidate(
                RepoCandidateMaterializationRequest(
                    candidate_copy=copy,
                    candidate=candidate,
                ),
                services=RepoCandidateMaterializationServices(
                    copy_repo_tree=lambda: copy_repo_tree,
                    apply_candidate_edits=lambda: cast(
                        Any, apply_blocks_to_copy
                    ),
                ),
            )
            if materialization.terminal_result is not None:
                return materialization.terminal_result

            # Accept an Independent Verifier Pack into a separate judge-owned
            # snapshot outside both the candidate tree and HOME. The legacy mount
            # namespace remains reserved so a repo cannot pre-plant a shadow copy.
            pack_dir = str(problem.get("verifier_pack", "") or "")
            expected_pack_sha256 = str(
                problem.get("expect_verifier_pack_sha256", "") or ""
            ).lower()
            pack_request = RepoPackIntakeRequest(
                candidate_copy=copy,
                files_changed=tuple(changed),
                pack_dir=pack_dir,
                expected_pack_sha256=expected_pack_sha256,
            )

            def create_pack_workspace(prefix: str) -> str:
                return workspace_lifetime.create_pack(
                    prefix,
                    create_workspace=lambda *, prefix: (
                        _repository_workspace.allocate_owned_workspace(
                            prefix=prefix,
                            create_workspace=tempfile.mkdtemp,
                        )
                    ),
                )

            pack_intake = intake_repo_pack(
                pack_request,
                services=RepoPackIntakeServices(
                    lexists=lambda path: os.path.lexists(path),
                    create_workspace=create_pack_workspace,
                    snapshot_pack=lambda source, destination: snapshot_pack(
                        source, destination
                    ),
                ),
            )
            workspace_lifetime.retain_pack_root(pack_intake.pack_workdir)
            pack_snapshot = pack_intake.pack_snapshot
            pack_sha256 = pack_intake.pack_sha256
            pack_manifest = (
                None
                if pack_intake.pack_manifest is None
                else dict(pack_intake.pack_manifest)
            )
            pack_identity = pack_intake.identity()
            if pack_identity is not None:
                # Once accepted, bind every later early-return artifact to the
                # exact judge-owned snapshot. Individual return sites must not
                # accidentally erase this delivered evidence.
                assert pack_sha256 is not None
                result_projection.bind_pack_identity(
                    sha256=pack_sha256,
                    manifest=pack_manifest,
                )
            if pack_intake.failure is not None:
                return VerdictResult(
                    passed=False,
                    score=pack_intake.failure.score,
                    diagnostics=pack_intake.failure.diagnostics,
                    artifact=rejection_artifact(pack_request, pack_intake),
                )
            if pack_identity is not None:
                assert pack_snapshot is not None
                accepted_pack_identity = AcceptedRepoPackIdentity(
                    sha256=pack_identity[0],
                    manifest=pack_identity[1],
                )
                pack_continuity = RepoPackContinuity(
                    RepoPackContinuityRequest(
                        pack_snapshot=pack_snapshot,
                        identity=accepted_pack_identity,
                    ),
                    RepoPackContinuityServices(
                        verify_snapshot=lambda: verify_pack_snapshot,
                    ),
                )

            deletion = apply_repo_candidate_deletions(
                RepoCandidateDeletionRequest(
                    candidate_copy=copy,
                    candidate=candidate,
                ),
                services=RepoCandidateDeletionServices(
                    is_safe_relpath=lambda: is_safe_relpath,
                    delete_path=lambda: delete_path_within_root,
                    deletion_errors=lambda: (OSError, UnsafeWorkspacePath),
                ),
            )
            if deletion.terminal_result is not None:
                return deletion.terminal_result

            try:
                candidate_harness_snapshot = capture_harness_input_snapshot(
                    copy,
                    effective_harness_inputs,
                )
            except (HarnessInputPolicyError, HarnessInputIntegrityError) as exc:
                return VerdictResult(
                    passed=False,
                    score=0.0,
                    diagnostics=(
                        "declared harness input integrity could not be bound "
                        f"before execution: {exc}"
                    ),
                    artifact={
                        "files_changed": changed,
                        "outcome": "candidate_tree_changed",
                        "tamper": True,
                        "candidate_fidelity_changes": list(
                            effective_harness_inputs
                        ),
                    },
                )
            candidate_harness_changes = harness_input_snapshot_changes(
                trusted_harness_baseline,
                candidate_harness_snapshot,
            )
            if candidate_harness_changes:
                return VerdictResult(
                    passed=False,
                    score=0.0,
                    diagnostics=(
                        "candidate materialization changed a declared harness "
                        "input before execution: "
                        + ", ".join(candidate_harness_changes)
                    ),
                    artifact={
                        "files_changed": changed,
                        "outcome": "candidate_tree_changed",
                        "tamper": True,
                        "candidate_fidelity_changes": list(
                            candidate_harness_changes
                        ),
                    },
                )
            harness_input_baseline = trusted_harness_baseline

            def verify_harness_checkpoint(
                checkpoint: str,
                *,
                setup_isolation: str | None,
            ) -> VerdictResult | None:
                try:
                    observed = capture_harness_input_snapshot(
                        copy,
                        effective_harness_inputs,
                    )
                except (
                    HarnessInputPolicyError,
                    HarnessInputIntegrityError,
                ) as exc:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=(
                            "declared harness input integrity could not be "
                            f"proven {checkpoint}: {exc}"
                        ),
                        artifact={
                            "files_changed": changed,
                            "outcome": "candidate_tree_changed",
                            "tamper": True,
                            "candidate_fidelity_changes": list(
                                effective_harness_inputs
                            ),
                            "setup_isolation": setup_isolation,
                        },
                    )
                changes = harness_input_snapshot_changes(
                    harness_input_baseline,
                    observed,
                )
                if not changes:
                    return None
                return VerdictResult(
                    passed=False,
                    score=0.0,
                    diagnostics=(
                        "declared harness input changed "
                        f"{checkpoint}: " + ", ".join(changes)
                    ),
                    artifact={
                        "files_changed": changed,
                        "outcome": "candidate_tree_changed",
                        "tamper": True,
                        "candidate_fidelity_changes": list(changes),
                        "setup_isolation": setup_isolation,
                    },
                )

            container_mode = self.isolation in ("docker", "gvisor")
            if container_mode and not self.docker_image:
                return VerdictResult(
                    passed=False,
                    score=0.0,
                    diagnostics=f"{self.isolation} isolation requires a docker image (--docker-image)",
                    artifact={
                        "files_changed": changed,
                        "outcome": "isolation_unavailable",
                        "isolation_evidence": {
                            "requested": self.isolation,
                            "delivered": "unavailable",
                            "image_digest": None,
                            "network": self.docker_network,
                            "runtime": self.docker_runtime,
                        },
                    },
                )
            resolved_image: str | None = None
            if container_mode:
                try:
                    resolved_image = require_canonical_docker_image_id(
                        self._resolve_docker_image()
                    )
                    # Tests may stub the resolver; pin its returned ID explicitly
                    # so setup, suite and pack all use the same image reference.
                    self._resolved_docker_image = resolved_image
                    self._active_docker_image.set(resolved_image)
                except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"{self.isolation} isolation unavailable: {exc}",
                        artifact={
                            "files_changed": changed,
                            "outcome": "isolation_unavailable",
                            "isolation_evidence": {
                                "requested": self.isolation,
                                "delivered": "unavailable",
                                "image_digest": None,
                                "network": self.docker_network,
                                "runtime": self.docker_runtime,
                                "note": str(exc),
                            },
                        },
                    )

            # Run optional setup_command before the suite under the requested
            # boundary. Every service is a call-through adapter so historical
            # monkeypatch seams remain live at their original operation sites.
            setup_cmd_raw = self.setup_command or problem.get("setup_command")
            setup_isolation: str | None = None
            if setup_cmd_raw:
                setup_env = create_judge_phase_environment(workdir, "setup")
                setup_outcome = execute_repo_setup(
                    RepoSetupRequest(
                        configured_command=setup_cmd_raw,
                        candidate_copy=copy,
                        files_changed=tuple(changed),
                        environment=setup_env,
                        container_mode=container_mode,
                        resolved_image=resolved_image,
                    ),
                    services=RepoSetupServices(
                        trace=trace,
                        requested_isolation=lambda: self.isolation,
                        trust_setup_on_host=lambda: self.trust_setup_on_host,
                        setup_output_globs=lambda: self.setup_output_globs,
                        timeout=lambda: self.timeout,
                        strict_harness=lambda: strict_harness,
                        docker_network=lambda: self.docker_network,
                        docker_runtime=lambda: self.docker_runtime,
                        resolve_host_command=lambda: cast(
                            Any, _resolve_host_command
                        ),
                        capture_setup_before=lambda: cast(
                            Any, _setup_fidelity_snapshot
                        ),
                        capture_setup_after=lambda: cast(
                            Any, _setup_fidelity_snapshot
                        ),
                        setup_fidelity_changes=lambda: _setup_fidelity_changes,
                        run_host_setup=lambda: cast(
                            Any, _run_bounded_subprocess
                        ),
                        container_name=lambda: _docker_container_name,
                        build_docker_command=lambda: cast(
                            Any, self._docker_command
                        ),
                        run_docker_setup=lambda: cast(
                            Any, self._run_docker_client
                        ),
                        limits=lambda: self._limits(),
                        phase_isolation_evidence=lambda: (
                            self._phase_isolation_evidence
                        ),
                        distill_diagnostics=lambda: distill_diagnostics,
                    ),
                )
                setup_isolation = setup_outcome.setup_isolation
                if setup_outcome.terminal_result is not None:
                    return setup_outcome.terminal_result
            harness_failure = verify_harness_checkpoint(
                "before the repository suite",
                setup_isolation=setup_isolation,
            )
            if harness_failure is not None:
                return harness_failure
            # A mandatory repo-native pack must judge the exact fully prepared
            # runtime tree the repo suite received. Setup fidelity deliberately
            # permits new dependency/build outputs; this second identity includes
            # all of them and never applies setup_output_globs.
            runtime_continuity = RepoRuntimeContinuity(
                RepoRuntimeContinuityRequest(
                    candidate_copy=copy,
                    pack_configured=bool(pack_dir),
                    container_mode=container_mode,
                    setup_configured=bool(setup_cmd_raw),
                    trust_setup_on_host=(
                        self.trust_setup_on_host
                        if pack_dir and container_mode and bool(setup_cmd_raw)
                        else False
                    ),
                    require_suite_continuity=self.require_suite_continuity,
                ),
                RepoRuntimeContinuityServices(
                    trace=trace,
                    capture_identity=lambda: capture_runtime_identity,
                    verify_identity=lambda: verify_runtime_identity,
                ),
            )

            def runtime_evidence() -> dict[str, Any]:
                """Describe runtime evidence truthfully on every exit path."""
                return cast(
                    dict[str, Any],
                    runtime_identity_evidence_payload(
                        runtime_continuity.evidence()
                    ),
                )

            # Structured-verdict requirement: refuse an exit-code-only repository
            # suite before anything runs, so a requested control never silently
            # downgrades to exit-code grading. See ``_structured_verdict_preflight``.
            structured_refusal = self._structured_verdict_preflight(
                problem=problem,
                changed=changed,
                setup_isolation=setup_isolation,
                runtime_evidence=runtime_evidence,
            )
            if structured_refusal is not None:
                return structured_refusal

            # Assertion-liveness (catalog row 11b): refuse a non-pytest command and
            # install the judge-owned canary into the prepared copy *before* the
            # continuity baseline below. See ``_assert_liveness_preflight``.
            liveness_refusal = self._assert_liveness_preflight(
                problem=problem,
                copy=copy,
                changed=changed,
                setup_isolation=setup_isolation,
                runtime_evidence=runtime_evidence,
            )
            if liveness_refusal is not None:
                return liveness_refusal

            if runtime_continuity.required:
                capture_failure = runtime_continuity.capture_baseline()
                if capture_failure is not None:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=capture_failure.diagnostics,
                        artifact={
                            "files_changed": changed,
                            "outcome": "runtime_identity_unavailable",
                            "setup_isolation": setup_isolation,
                            **runtime_evidence(),
                        },
                    )

            # Execute the repository suite first, but preserve runtime identity
            # verification below before any JUnit report is interpreted. When
            # assertion-liveness is required, the suite environment carries the
            # judge-owned canary directory on PYTHONPATH (see ``_suite_env_with_liveness``).
            suite_env = self._suite_env_with_liveness(
                create_judge_phase_environment(workdir, "repo-suite"), copy
            )
            suite_execution = execute_repo_suite(
                RepoSuiteExecutionRequest(
                    candidate_copy=copy,
                    workdir=workdir,
                    files_changed=tuple(changed),
                    environment=suite_env,
                    container_mode=container_mode,
                    resolved_image=resolved_image,
                    pack_configured=bool(pack_dir),
                    setup_isolation=setup_isolation,
                    strict_harness=strict_harness,
                ),
                services=RepoSuiteExecutionServices(
                    trace=trace,
                    command=lambda: self._command(problem),
                    requested_isolation=lambda: self.isolation,
                    timeout=lambda: self.timeout,
                    instrument_command=lambda: cast(
                        Any,
                        instrument_command,
                    ),
                    resolve_host_command=lambda: cast(
                        Any,
                        _resolve_host_command,
                    ),
                    run_host_suite=lambda: cast(
                        Any,
                        _run_bounded_subprocess,
                    ),
                    run_docker_suite=lambda: cast(
                        Any,
                        self._run_docker,
                    ),
                    limits=lambda: self._limits(),
                    phase_isolation_evidence=lambda: (
                        self._phase_isolation_evidence
                    ),
                    runtime_evidence=lambda: runtime_evidence(),
                    isolation_payload=lambda: isolation_observation_payload,
                    distill_diagnostics=lambda: distill_diagnostics,
                    perf_counter=lambda: time.perf_counter(),
                ),
            )
            harness_failure = verify_harness_checkpoint(
                "after the repository suite",
                setup_isolation=setup_isolation,
            )
            if harness_failure is not None:
                return harness_failure
            if suite_execution.terminal_result is not None:
                return suite_execution.terminal_result
            assert suite_execution.completed is not None
            completed_suite = suite_execution.completed
            elapsed = completed_suite.elapsed_seconds
            suite_isolation_evidence = (
                trace.repo_suite_isolation_evidence
            )
            assert suite_isolation_evidence is not None

            continuity_drift = self._verify_after_suite_continuity(
                runtime_continuity=runtime_continuity,
                changed=changed,
                setup_isolation=setup_isolation,
                runtime_evidence=runtime_evidence,
                pack_sha256=pack_sha256,
                pack_manifest=pack_manifest,
            )
            if continuity_drift is not None:
                return continuity_drift
            # With no verifier pack, a clean after-suite check is the terminal
            # continuity boundary (an opt-in require_suite_continuity run). This
            # is a no-op when a pack is configured — the pack path owns delivery.
            runtime_continuity.finalize_suite_only()

            # Assertion-liveness (catalog row 11b): if the judge-owned canary node
            # failed, the assertion machinery was neutered — grade TAMPERED with a
            # distinct reason rather than folding into ``tests_failed``. See
            # ``_assert_liveness_tamper``.
            liveness_tamper = self._assert_liveness_tamper(
                report_path=completed_suite.report_path,
                changed=changed,
                setup_isolation=setup_isolation,
                runtime_evidence=runtime_evidence,
            )
            if liveness_tamper is not None:
                return liveness_tamper

            repo_phase = interpret_repo_suite(
                RepoSuiteInterpretationRequest(
                    completed=completed_suite,
                    strict_harness=strict_harness,
                ),
                services=RepoSuiteInterpretationServices(
                    read_report=lambda: _read_text_or_none,
                    parse_xml=lambda: cast(
                        Any,
                        parse_junit_xml,
                    ),
                    parse_directory=lambda: cast(
                        Any,
                        parse_junit_dir_with_digest,
                    ),
                    evaluate_phase=lambda: evaluate_repo_phase,
                    junit_xml_digest_format=lambda: JUNIT_XML_DIGEST_FORMAT,
                    junit_report_set_digest_format=(
                        lambda: JUNIT_REPORT_SET_DIGEST_FORMAT
                    ),
                ),
            )
            # Preserve the repo phase before a verifier pack is composed into
            # the top-level result. Baseline evidence is explicitly scoped to
            # this phase, so a later pack failure must not turn repo PASS into
            # an apparent candidate-suite failure. These facts are copied into
            # the attestation (and any configured detached signature) and bound
            # to the composite count remainder.
            if pack_dir:
                result_projection.bind_repo_suite_phase(repo_phase)
            pack_phase_artifact: RepoPackPhaseArtifact | None = None
            final_phase: FinalRepoPhase = repo_phase

            # A copied pack is not evidence that its checks ran. Execute it as a
            # separate mandatory phase, explicitly addressed by path, then
            # compose both outcomes. This works even when the repo command is
            # narrowed (for example ``pytest tests/``) or is a custom command.
            if pack_dir:
                trace.execution_phase = "verifier_pack"
                assert pack_snapshot is not None and pack_continuity is not None
                pack_execution_services = RepoPackExecutionServices(
                    trace=trace,
                    requested_isolation=lambda: self.isolation,
                    timeout=lambda: self.timeout,
                    python_executable=lambda: sys.executable,
                    instrument_command=lambda: cast(
                        Any, instrument_command
                    ),
                    resolve_host_command=lambda: cast(
                        Any, _resolve_host_command
                    ),
                    run_host_pack=lambda: cast(
                        Any, _run_bounded_subprocess
                    ),
                    run_docker_pack=lambda: cast(
                        Any, self._run_docker
                    ),
                    limits=lambda: self._limits(),
                    phase_isolation_evidence=lambda: (
                        self._phase_isolation_evidence
                    ),
                    runtime_evidence=lambda: runtime_evidence(),
                    isolation_payload=lambda: isolation_observation_payload,
                    distill_diagnostics=lambda: distill_diagnostics,
                )
                pack_continuity_failure = (
                    pack_continuity.verify_before_execution()
                )
                if pack_continuity_failure is not None:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=pack_continuity_failure.diagnostics,
                        artifact={
                            "files_changed": changed,
                            "outcome": "pack_snapshot_changed",
                            "tamper": True,
                            "verifier_pack_sha256": pack_sha256,
                            "verifier_pack_manifest": pack_manifest,
                            "setup_isolation": setup_isolation,
                            **runtime_evidence(),
                        },
                    )
                pack_env = create_judge_phase_environment(
                    workdir,
                    "verifier-pack",
                )
                pack_execution_request = RepoPackExecutionRequest(
                    candidate_copy=copy,
                    workdir=workdir,
                    pack_snapshot=pack_snapshot,
                    files_changed=tuple(changed),
                    environment=pack_env,
                    container_mode=container_mode,
                    resolved_image=resolved_image,
                    setup_isolation=setup_isolation,
                    suite_isolation_evidence=suite_isolation_evidence,
                    strict_harness=strict_harness,
                )
                pack_execution = execute_repo_pack(
                    pack_execution_request,
                    services=pack_execution_services,
                )
                if pack_execution.terminal_result is not None:
                    return pack_execution.terminal_result
                assert pack_execution.completed is not None
                completed_pack = pack_execution.completed
                trace.execution_phase = "runtime_verification"
                pack_continuity_failure = (
                    pack_continuity.verify_after_execution()
                )
                if pack_continuity_failure is not None:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=pack_continuity_failure.diagnostics,
                        artifact={
                            "files_changed": changed,
                            "outcome": "pack_snapshot_changed",
                            "tamper": True,
                            "verifier_pack_sha256": pack_sha256,
                            "verifier_pack_manifest": pack_manifest,
                            "setup_isolation": setup_isolation,
                            **runtime_evidence(),
                        },
                    )
                assert runtime_continuity.baseline is not None
                runtime_failure = runtime_continuity.verify_after_pack()
                if (
                    runtime_failure is not None
                    and runtime_failure.kind == "verification_error"
                ):
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=runtime_failure.diagnostics,
                        artifact={
                            "files_changed": changed,
                            "outcome": "candidate_tree_changed",
                            "tamper": True,
                            "setup_isolation": setup_isolation,
                            **runtime_evidence(),
                        },
                    )
                if runtime_failure is not None:
                    assert runtime_failure.kind == "pack_drift"
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=runtime_failure.diagnostics,
                        artifact={
                            "files_changed": changed,
                            "outcome": "candidate_tree_changed",
                            "tamper": True,
                            "candidate_fidelity_changes": list(
                                runtime_failure.changes
                            ),
                            "verifier_pack_sha256": pack_sha256,
                            "verifier_pack_manifest": pack_manifest,
                            "setup_isolation": setup_isolation,
                            **runtime_evidence(),
                        },
                    )
                pack_phase_result = interpret_repo_pack(
                    RepoPackInterpretationRequest(
                        completed=completed_pack,
                    ),
                    services=RepoPackInterpretationServices(
                        read_report=lambda: _read_text_or_none,
                        parse_xml=lambda: cast(Any, parse_junit_xml),
                        evaluate_phase=lambda: evaluate_pack_phase,
                        junit_xml_digest_format=lambda: JUNIT_XML_DIGEST_FORMAT,
                    ),
                )
                composite_phase = compose_repo_and_pack(
                    repo_phase,
                    pack_phase_result,
                )
                pack_phase_artifact = RepoPackPhaseArtifact.from_phase(
                    pack_phase_result
                )
                final_phase = composite_phase
                trace.execution_phase = "verifier_pack"

            if not pack_dir:
                trace.execution_phase = "repo_suite"

            diagnostics = distill_diagnostics(final_phase.output)
            final_runtime_evidence = runtime_evidence()
            return VerdictResult(
                passed=final_phase.passed,
                score=final_phase.score,
                diagnostics=diagnostics,
                artifact=build_final_repo_artifact(
                    RepoFinalArtifactRequest(
                        returncode=completed_suite.returncode,
                        elapsed_seconds=elapsed,
                        phase=final_phase,
                        files_changed=tuple(changed),
                        files_deleted=tuple(deleted_paths),
                        pack_identity=result_projection.pack_identity,
                        expected_pack_sha256=expected_pack_sha256,
                        pack_phase=pack_phase_artifact,
                        pack_configured=bool(pack_dir),
                        setup_isolation=setup_isolation,
                        setup_configured=bool(setup_cmd_raw),
                        runtime_evidence=final_runtime_evidence,
                        resolved_image=resolved_image,
                        suite_isolation_evidence=suite_isolation_evidence,
                        container_mode=container_mode,
                    )
                ),
            )
        except BaseException as error:
            # ``sys.exc_info()`` can expose an exception still handled by the
            # caller even when this verification completed normally. Only a
            # failure raised inside this operation may outrank cleanup.
            cleanup_primary = error
            raise
        finally:
            _cleanup_repo_workspaces(
                workspace_lifetime.cleanup_targets(),
                primary=cleanup_primary,
            )
