# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
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

Golden rule, enforced: the candidate may NOT modify the harness that judges it
— neither the tests nor their configuration. Paths under ``tests/``, files named
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
:func:`restore_judge_package_json`.

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

import hashlib
import ntpath
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, TypedDict, cast

from evoom_guard.adapters import instrument_command
from evoom_guard.contracts import VerdictResult
from evoom_guard.execution import (
    DEFAULT_KILL_GRACE_SECONDS,
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_READ_CHUNK_BYTES,
    DEFAULT_READER_JOIN_SECONDS,
    DEFAULT_TERMINATION_GRACE_SECONDS,
    BoundedOutput,
    ProcessLimits,
    drain_process_pipe,
    join_pipe_readers,
    process_group_popen_kwargs,
    run_bounded_subprocess,
)
from evoom_guard.execution import (
    ProcessContainmentError as _SubprocessContainmentError,
)
from evoom_guard.execution import (
    ProcessOutputLimitExceeded as _SubprocessOutputLimitExceeded,
)
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
    resolve_docker_image,
    run_named_docker_client,
)
from evoom_guard.pack_manifest import (
    PackManifestError,
    snapshot_pack,
    verify_pack_snapshot,
)
from evoom_guard.patch_applier import PatchError, apply_patch
from evoom_guard.runtime_identity import (
    RuntimeIdentity,
    RuntimeIdentityError,
    capture_runtime_identity,
    verify_runtime_identity,
)
from evoom_guard.verifiers.candidate_edits import (
    _BLOCK_RE as _BLOCK_RE,
)
from evoom_guard.verifiers.candidate_edits import (
    _LENIENT_FILE_RE as _LENIENT_FILE_RE,
)
from evoom_guard.verifiers.candidate_edits import (
    _LENIENT_PATCH_RE as _LENIENT_PATCH_RE,
)
from evoom_guard.verifiers.candidate_edits import (
    _PATCH_BLOCK_RE as _PATCH_BLOCK_RE,
)
from evoom_guard.verifiers.candidate_edits import (
    PatchBlock as PatchBlock,
)
from evoom_guard.verifiers.candidate_edits import (
    parse_blocks_lenient as parse_blocks_lenient,
)
from evoom_guard.verifiers.candidate_edits import (
    parse_file_blocks as parse_file_blocks,
)
from evoom_guard.verifiers.candidate_edits import (
    parse_patch_blocks as parse_patch_blocks,
)
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
from evoom_guard.verifiers.fidelity import (
    _setup_fidelity_changes as _setup_fidelity_changes,
)
from evoom_guard.verifiers.fidelity import (
    _setup_fidelity_snapshot as _setup_fidelity_snapshot,
)
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
    _is_judge_script as _is_judge_script,
)
from evoom_guard.verifiers.harness_policy import (
    _matches_globs as _matches_globs,
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
from evoom_guard.workspace import (
    UnsafeWorkspacePath,
    delete_path_within_root,
    read_text_within_root,
    write_text_within_root,
)

# Stable intra-package facades for evidence/baseline phases. The leading-
# underscore implementations remain local compatibility names, while callers
# outside ``verifiers`` avoid private cross-package imports.
setup_fidelity_changes = _setup_fidelity_changes
setup_fidelity_snapshot = _setup_fidelity_snapshot

try:  # POSIX-only; absent on Windows.
    import resource
except ImportError:  # pragma: no cover - platform dependent
    resource = None  # type: ignore[assignment]

# Directories never copied into the throwaway working copy.
COPY_IGNORE = (
    ".git", "__pycache__", ".venv", "venv", "node_modules",
    ".evo_runs", ".pytest_cache", ".mypy_cache", "dist", "build",
)


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


def _resolve_host_command(
    command: list[str],
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    platform: str | None = None,
) -> list[str]:
    """Resolve Windows ``.cmd``/``.bat`` shims before ``subprocess.run``.

    Windows command prompts consult ``PATHEXT`` for a bare command such as
    ``vitest`` or ``npm``; ``CreateProcess`` (used by ``subprocess`` without a
    shell) does not. Resolve the concrete shim without enabling ``shell=True``.

    The search is intentionally implemented here instead of with
    :func:`shutil.which`: recent Python versions may implicitly prepend the
    process working directory on Windows. A candidate-controlled checkout must
    not shadow a judge command unless the adopter explicitly supplied a relative
    command path or put that directory in ``PATH``. Bare commands therefore use
    absolute ``PATH`` entries only. POSIX behavior is unchanged.

    ``platform`` is an internal test seam; production callers use ``os.name``.
    """
    if (os.name if platform is None else platform) != "nt" or not command:
        return list(command)

    executable = command[0]
    search_env = os.environ if env is None else env
    raw_extensions = search_env.get("PATHEXT", ".COM;.EXE;.BAT;.CMD")
    extensions = tuple(
        ext if ext.startswith(".") else f".{ext}"
        for item in raw_extensions.split(";")
        if (ext := item.strip())
    )

    def existing_candidate(base: str) -> str | None:
        direct = (
            (base,)
            if any(base.lower().endswith(ext.lower()) for ext in extensions)
            else ()
        )
        for candidate in (*direct, *(f"{base}{ext}" for ext in extensions)):
            if os.path.isfile(candidate):
                return candidate
        return None

    if "/" in executable or "\\" in executable:
        explicit = executable
        if cwd and not ntpath.isabs(explicit):
            explicit = ntpath.join(cwd, explicit)
        resolved = existing_candidate(explicit)
        return [resolved, *command[1:]] if resolved else list(command)

    for item in search_env.get("PATH", "").split(";"):
        directory = os.path.expandvars(item.strip().strip('"'))
        if not directory or not ntpath.isabs(directory):
            continue
        resolved = existing_candidate(ntpath.join(directory, executable))
        if resolved:
            return [resolved, *command[1:]]
    return list(command)


resolve_host_command = _resolve_host_command


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
) -> subprocess.CompletedProcess[str]:
    """Compatibility facade over the typed execution-kernel contract."""

    return run_bounded_subprocess(
        command,
        cwd=cwd,
        env=env,
        timeout=timeout,
        preexec_fn=preexec_fn,
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
    shutil.copytree(src, dst, symlinks=True, ignore=shutil.ignore_patterns(*COPY_IGNORE))


def apply_blocks_to_copy(
    copy: str, file_blocks: dict[str, str], patch_blocks: list[PatchBlock]
) -> str | None:
    """Materialize file blocks then patches into ``copy``."""
    def safe_read(relative_path: str) -> tuple[str | None, str | None]:
        try:
            return read_text_within_root(copy, relative_path), None
        except FileNotFoundError:
            return None, None
        except (UnicodeError, UnsafeWorkspacePath, OSError) as exc:
            return None, (
                "edit source could not be read safely — refusing to treat it "
                f"as absent: {relative_path} ({exc})"
            )

    def safe_write(relative_path: str, content: str) -> str | None:
        try:
            write_text_within_root(copy, relative_path, content)
        except (OSError, UnsafeWorkspacePath) as exc:
            return (
                "edit target escapes the repo copy or changed inside it — "
                f"refusing to write: {relative_path} ({exc})"
            )
        return None

    pkg_paths = sorted(
        {p for p in file_blocks if p.split("/")[-1] == "package.json"}
        | {pb.path for pb in patch_blocks if pb.path.split("/")[-1] == "package.json"}
    )
    pkg_originals: dict[str, str | None] = {}
    for rel in pkg_paths:
        original, read_error = safe_read(rel)
        if read_error is not None:
            return read_error
        pkg_originals[rel] = original

    for path, content in file_blocks.items():
        write_error = safe_write(path, content)
        if write_error is not None:
            return write_error

    for pb in patch_blocks:
        source, read_error = safe_read(pb.path)
        if read_error is not None:
            return read_error
        if source is None:
            return (
                f"PATCH target not found: {pb.path} — "
                "use a <<<FILE>>> block "
                "to create new files"
            )
        try:
            patched = apply_patch(source, pb.search, pb.replace)
        except (PatchError, ValueError) as exc:
            return (
                f"PATCH did not apply to {pb.path}: "
                f"{type(exc).__name__}: {exc} — "
                ""
                "copy a unique anchor verbatim from the shown file"
            )
        write_error = safe_write(pb.path, patched)
        if write_error is not None:
            return write_error

    for rel in pkg_paths:
        candidate_pkg, read_error = safe_read(rel)
        if read_error is not None:
            return read_error
        if candidate_pkg is None:
            return f"edited package manifest disappeared before verification: {rel}"
        restored = restore_judge_package_json(pkg_originals.get(rel), candidate_pkg)
        if restored != candidate_pkg:
            write_error = safe_write(rel, restored)
            if write_error is not None:
                return write_error
    return None


def _docker_container_name(stage: str) -> str:
    """Collision-resistant name for concurrent setup/suite/pack containers."""
    return docker_container_name(stage, token_hex=secrets.token_hex)


def _execution_trace() -> dict[str, Any]:
    """Return the fail-closed execution trace attached to every repo verdict."""
    return {
        "execution_state": "not_started",
        "execution_phase": "preflight",
        "test_command_started": False,
        "test_command_completed": False,
        "verifier_pack_started": False,
        "verifier_pack_completed": False,
        "delivered_isolation": "not_run",
        "setup_isolation_evidence": None,
        "repo_suite_isolation_evidence": None,
        "verifier_pack_isolation_evidence": None,
    }


def _clean_verdict_source(
    returncode: int,
    junit: JUnitCounts | None,
    *,
    report_expected: bool,
) -> str | None:
    """Name a source only for a cleanly gradeable pass/fail evidence pair."""
    if junit is not None:
        return "junit+exit" if junit.total > 0 and returncode in (0, 1) else None
    if not report_expected and returncode in (0, 1):
        return "exit"
    return None


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
    ) -> None:
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
        self._resolved_docker_image: str | None = None
        # Explicit compatibility escape hatch. By default candidate-influenced
        # setup runs inside the same requested boundary as the suite.
        self.trust_setup_on_host = trust_setup_on_host
        self.setup_output_globs = setup_output_globs
        # Strict profile is opt-in: it makes the verifier refuse exit-only or
        # zero-test success, and the preflight treats execution-environment
        # manifests as immutable judge inputs.
        self.strict_harness = strict_harness

    # ------------------------------------------------------------------ #
    def _limits(self):  # pragma: no cover - exercised in the child process
        """preexec hook: cap CPU seconds and address space before exec."""
        if resource is None:
            return None

        def apply() -> None:
            resource_api = cast(Any, resource)
            cpu = max(1, int(self.timeout) + 1)
            resource_api.setrlimit(resource_api.RLIMIT_CPU, (cpu, cpu))
            if self.mem_limit_mb <= 0:
                return
            mem = self.mem_limit_mb * 1024 * 1024
            try:
                resource_api.setrlimit(resource_api.RLIMIT_AS, (mem, mem))
            except (ValueError, OSError):
                pass

        return apply

    # ------------------------------------------------------------------ #
    def _command(self, problem: RepoProblem | dict) -> list[str]:
        cmd = self.test_command or problem.get("test_command")
        if isinstance(cmd, str):
            return cmd.split()
        if cmd:
            return list(cmd)
        python = "python" if self.isolation in ("docker", "gvisor") else sys.executable
        return [python, "-m", "pytest", "-q", "--color=no", "-p", "no:cacheprovider"]

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
            "-e", "HOME=/tmp", "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "LANG=C.UTF-8",
            "-v", f"{copy}:/work:{'rw' if work_writable else 'ro'}",
        ]
        if outdir is not None:
            docker += ["-v", f"{outdir}:/out:rw"]
        if pack_dir is not None:
            docker += ["-v", f"{pack_dir}:/verifier-pack:ro"]
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
        return [*docker, str(self._resolved_docker_image or self.docker_image), *cmd]

    def _resolve_docker_image(self) -> str:
        """Resolve a tag once so setup and suite use the exact same image bytes."""
        if self._resolved_docker_image:
            return self._resolved_docker_image
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
    ) -> dict[str, Any]:
        """Build one phase's isolation evidence without implying execution."""
        evidence: dict[str, Any] = {
            "requested": self.isolation,
            "delivered": delivered,
            "image_digest": image_digest,
            "network": (
                self.docker_network
                if self.isolation in ("docker", "gvisor")
                else None
            ),
            "runtime": (
                self.docker_runtime
                if self.isolation in ("docker", "gvisor")
                else None
            ),
        }
        if note:
            evidence["note"] = note
        return evidence

    # ------------------------------------------------------------------ #
    def verify(self, hypothesis: str, problem: RepoProblem | dict) -> VerdictResult:
        """Verify a candidate and attach truthful phase/execution evidence."""
        trace = _execution_trace()
        pack_dir = str(problem.get("verifier_pack", "") or "")
        # Presence is not validity: an existing file/symlink is present but the
        # pack contract will reject it as an invalid root.
        pack_present = bool(pack_dir and os.path.lexists(pack_dir))
        result = self._verify(hypothesis, problem, trace)
        result.artifact.update(trace)
        result.artifact.setdefault("verifier_pack_present", pack_present)
        return result

    def _verify(
        self,
        hypothesis: str,
        problem: RepoProblem | dict,
        trace: dict[str, Any],
    ) -> VerdictResult:
        repo_path = str(problem.get("repo_path", ""))
        if not repo_path or not os.path.isdir(repo_path):
            raise ValueError(f"problem['repo_path'] is not a directory: {repo_path!r}")

        # Paths the candidate deletes (set by Guard from a base→head diff). A deleted
        # *source* file is applied to the copy so the verdict matches the merge; a
        # deleted protected harness file is rejected below (removing a check is a
        # reward-hack as direct as editing it).
        deleted_paths = [str(p) for p in problem.get("deleted", ()) if str(p).strip()]

        fb_override = problem.get("file_blocks")
        if isinstance(fb_override, dict) and fb_override:
            # Structured candidate (the dirs/diff path): trust the mapping, skip
            # the marker parse entirely — content containing literal block markers
            # must never terminate its own block.
            file_blocks = {str(k): str(v) for k, v in fb_override.items()}
            patch_blocks: list[PatchBlock] = []
        else:
            file_blocks = parse_file_blocks(hypothesis)
            patch_blocks = parse_patch_blocks(hypothesis)
            if not file_blocks and not patch_blocks:
                targets = [str(t) for t in problem.get("target_files", ()) if str(t).strip()]
                default_path = targets[0] if len(targets) == 1 else None
                file_blocks, patch_blocks = parse_blocks_lenient(hypothesis, default_path)
        if not file_blocks and not patch_blocks and not deleted_paths:
            return VerdictResult(
                passed=False,
                score=0.02,
                diagnostics=(
                    "no parseable blocks; expected "
                    "<<<FILE: path>>> … <<<END FILE>>> or "
                    "<<<PATCH: path>>> <<<SEARCH>>> … <<<REPLACE>>> … <<<END PATCH>>>"
                ),
                artifact={"files_changed": []},
            )

        extra = self.protected + tuple(problem.get("protected", ()))
        allow = self.allow + tuple(problem.get("allow", ()))
        # Local actions may execute helper files beside their manifest.  Discover
        # their directories in the unmodified repository before candidate files
        # are applied, then pass that base-owned policy into the pure preflight.
        local_action_dirs = discover_local_action_dirs(repo_path)
        changed = sorted(set(file_blocks) | {pb.path for pb in patch_blocks})
        allow_new_tests = self.allow_new_tests or bool(problem.get("allow_new_tests"))
        strict_harness = self.strict_harness or problem.get("strict_harness") is True
        new_paths = frozenset(
            p for p in changed
            if is_safe_relpath(p) and not os.path.exists(os.path.join(repo_path, p))
        )
        rejection = reject_unsafe_or_protected(
            changed,
            extra,
            allow_new_tests=allow_new_tests,
            new_paths=new_paths,
            allow=allow,
            local_action_dirs=local_action_dirs,
            strict_harness=strict_harness,
        )
        if rejection is not None:
            return rejection
        # Deletions are never "new" and feature mode never exempts removing a check,
        # so a protected deletion is always rejected (defence in depth — Guard also
        # filters these before calling verify).
        if deleted_paths:
            del_rejection = reject_unsafe_or_protected(
                deleted_paths,
                extra,
                allow=allow,
                local_action_dirs=local_action_dirs,
                strict_harness=strict_harness,
            )
            if del_rejection is not None:
                return del_rejection

        workdir = tempfile.mkdtemp(prefix="evo_repo_")
        copy = os.path.join(workdir, "repo")
        pack_workdir: str | None = None
        pack_snapshot: str | None = None
        try:
            copy_repo_tree(repo_path, copy)
            apply_error = apply_blocks_to_copy(copy, file_blocks, patch_blocks)
            if apply_error is not None:
                return VerdictResult(
                    passed=False,
                    score=0.08,
                    diagnostics=apply_error,
                    artifact={"files_changed": changed},
                )

            # Accept an Independent Verifier Pack into a separate judge-owned
            # snapshot outside both the candidate tree and HOME. The legacy mount
            # namespace remains reserved so a repo cannot pre-plant a shadow copy.
            pack_sha256 = None
            pack_manifest: dict | None = None
            pack_identity: tuple[str, dict | None] | None = None
            pack_dir = str(problem.get("verifier_pack", "") or "")
            expected_pack_sha256 = str(
                problem.get("expect_verifier_pack_sha256", "") or ""
            ).lower()
            if expected_pack_sha256 and not pack_dir:
                return VerdictResult(
                    passed=False,
                    score=0.0,
                    diagnostics=(
                        "an expected verifier-pack SHA-256 was configured but no "
                        "verifier pack was supplied"
                    ),
                    artifact={
                        "files_changed": changed,
                        "outcome": "pack_identity_mismatch",
                        "expected_verifier_pack_sha256": expected_pack_sha256,
                    },
                )
            if pack_dir:
                reserved = os.path.join(copy, "evoguard_verifier_pack")
                if os.path.lexists(reserved):
                    return VerdictResult(
                        passed=False, score=0.05,
                        diagnostics=(
                            "the repo already contains 'evoguard_verifier_pack/' — the "
                            "judge-owned pack mount point must not exist in the tree"
                        ),
                        artifact={"files_changed": changed},
                    )
                try:
                    # Keep the accepted snapshot outside both the candidate tree
                    # and its HOME. The repo suite never receives this path.
                    pack_workdir = tempfile.mkdtemp(prefix="evo_pack_snapshot_")
                    pack_snapshot = os.path.join(pack_workdir, "pack")
                    pack_identity = snapshot_pack(pack_dir, pack_snapshot)
                    pack_sha256, pack_manifest = pack_identity
                    # Once accepted, bind every later early-return artifact to
                    # the exact judge-owned snapshot.  Individual return sites
                    # must not accidentally erase this delivered evidence.
                    trace.update(
                        verifier_pack_sha256=pack_sha256,
                        verifier_pack_manifest=pack_manifest,
                    )
                except PackManifestError as exc:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=str(exc),
                        artifact={"files_changed": changed, "outcome": "pack_invalid"},
                    )
                if expected_pack_sha256 and pack_sha256.lower() != expected_pack_sha256:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=(
                            "verifier-pack identity mismatch: expected "
                            f"{expected_pack_sha256}, observed {pack_sha256}"
                        ),
                        artifact={
                            "files_changed": changed,
                            "outcome": "pack_identity_mismatch",
                            "expected_verifier_pack_sha256": expected_pack_sha256,
                            "verifier_pack_sha256": pack_sha256,
                            "verifier_pack_manifest": pack_manifest,
                        },
                    )

            # Apply deletions to the copy so the verdict reflects the real merge
            # (a removed source file should be *absent* when the suite runs).
            try:
                for rel in deleted_paths:
                    if not is_safe_relpath(rel):
                        continue  # already gated; belt-and-braces
                    delete_path_within_root(copy, rel)
            except (OSError, UnsafeWorkspacePath) as exc:
                return VerdictResult(
                    passed=False,
                    score=0.05,
                    diagnostics=f"candidate deletion could not be applied safely: {exc}",
                    artifact={"files_changed": changed, "files_deleted": []},
                )

            env = judge_subprocess_env(workdir)

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
                    resolved_image = self._resolve_docker_image()
                    # Tests may stub the resolver; pin its returned ID explicitly
                    # so setup, suite and pack all use the same image reference.
                    self._resolved_docker_image = resolved_image
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
            # container boundary by default (or a restricted host environment by
            # explicit compatibility opt-in). The suite stays restricted, and
            # the verdict is read only from the judge-owned JUnit report + the test
            # command's exit code — so setup's stdout can never inflate the verdict.
            setup_cmd_raw = self.setup_command or problem.get("setup_command")
            setup_isolation: str | None = None
            if setup_cmd_raw:
                trace["execution_phase"] = "setup"
                if isinstance(setup_cmd_raw, str):
                    setup_cmd_raw = setup_cmd_raw.split()
                setup_tokens = [str(token) for token in setup_cmd_raw]
                setup_in_container = container_mode and not self.trust_setup_on_host
                setup_name: str | None = None
                if setup_in_container:
                    setup_isolation = self.isolation
                    setup_name = _docker_container_name("setup")
                    setup_run_cmd = self._docker_command(
                        setup_tokens,
                        copy,
                        None,
                        setup_name,
                        work_writable=True,
                    )
                    setup_cwd = None
                    setup_env = os.environ.copy()
                else:
                    setup_isolation = (
                        "subprocess_host_opt_in" if container_mode else "subprocess"
                    )
                    setup_run_cmd = setup_tokens
                    setup_cwd = copy
                    setup_env = dict(env)
                    setup_run_cmd = _resolve_host_command(
                        setup_run_cmd, cwd=setup_cwd, env=setup_env
                    )
                try:
                    setup_before = _setup_fidelity_snapshot(
                        copy, self.setup_output_globs
                    )
                except SetupFidelityError as exc:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"setup fidelity snapshot failed: {exc}",
                        artifact={
                            "files_changed": changed,
                            "outcome": "setup_failed",
                            "setup_isolation": None,
                        },
                    )
                try:
                    if setup_in_container:
                        assert setup_name is not None
                        r_setup = self._run_docker_client(setup_run_cmd, setup_name)
                    else:
                        r_setup = _run_bounded_subprocess(
                            setup_run_cmd,
                            cwd=setup_cwd,
                            env=setup_env,
                            timeout=self.timeout,
                            preexec_fn=(
                                self._limits() if os.name == "posix" else None
                            ),
                        )
                except _DockerRunTimeout as exc:
                    delivered = self.isolation if exc.container_started else "not_run"
                    trace["setup_isolation_evidence"] = self._phase_isolation_evidence(
                        delivered,
                        resolved_image,
                        note=(
                            None
                            if exc.container_started
                            else "docker client timed out before container start was proven"
                        ),
                    )
                    if exc.container_started:
                        trace["execution_state"] = "started_incomplete"
                        setup_isolation = self.isolation
                    else:
                        setup_isolation = None
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"setup command timed out after {self.timeout}s",
                        artifact={
                            "elapsed": self.timeout,
                            "files_changed": changed,
                            "outcome": "setup_timeout",
                            "setup_isolation": setup_isolation,
                        },
                    )
                except _SubprocessOutputLimitExceeded as exc:
                    docker_failure = isinstance(exc, _DockerRunOutputLimit)
                    container_started = bool(
                        getattr(exc, "container_started", True)
                    )
                    delivered = (
                        self.isolation
                        if docker_failure and container_started
                        else ("not_run" if docker_failure else (setup_isolation or "subprocess"))
                    )
                    reported_setup_isolation = (
                        self.isolation
                        if docker_failure and container_started
                        else (None if docker_failure else setup_isolation)
                    )
                    if container_started:
                        trace["execution_state"] = "started_incomplete"
                    trace["setup_isolation_evidence"] = self._phase_isolation_evidence(
                        delivered,
                        resolved_image,
                        note=(
                            None
                            if container_started
                            else "docker client output limit was reached before container start was proven"
                        ),
                    )
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"setup command output was rejected: {exc}",
                        artifact={
                            "files_changed": changed,
                            "outcome": "setup_output_limit",
                            "setup_isolation": reported_setup_isolation,
                        },
                    )
                except _SubprocessContainmentError as exc:
                    docker_failure = isinstance(exc, _DockerRunContainmentError)
                    container_started = bool(
                        getattr(exc, "container_started", True)
                    )
                    delivered = (
                        self.isolation
                        if docker_failure and container_started
                        else ("not_run" if docker_failure else (setup_isolation or "subprocess"))
                    )
                    reported_setup_isolation = (
                        self.isolation
                        if docker_failure and container_started
                        else (None if docker_failure else setup_isolation)
                    )
                    if container_started:
                        trace["execution_state"] = "started_incomplete"
                    trace["setup_isolation_evidence"] = self._phase_isolation_evidence(
                        delivered,
                        resolved_image,
                        note=(
                            "docker container cleanup was not proven"
                            if docker_failure
                            else "subprocess cleanup was not proven"
                        ),
                    )
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"setup command containment failed: {exc}",
                        artifact={
                            "files_changed": changed,
                            "outcome": "runtime_containment_error",
                            "setup_isolation": reported_setup_isolation,
                        },
                    )
                except subprocess.TimeoutExpired:
                    trace.update(
                        execution_state="started_incomplete",
                    )
                    trace["setup_isolation_evidence"] = self._phase_isolation_evidence(
                        setup_isolation or "subprocess", resolved_image
                    )
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"setup command timed out after {self.timeout}s",
                        artifact={
                            "elapsed": self.timeout,
                            "files_changed": changed,
                            "outcome": "setup_timeout",
                            "setup_isolation": setup_isolation,
                        },
                    )
                except FileNotFoundError:
                    trace["setup_isolation_evidence"] = self._phase_isolation_evidence(
                        "unavailable" if setup_in_container else "not_run",
                        resolved_image,
                    )
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=(
                            f"{self.isolation} isolation requested but the docker CLI "
                            "was not found while starting setup_command"
                            if setup_in_container
                            else f"setup command not found: {setup_tokens[0]!r}"
                        ),
                        artifact={
                            "files_changed": changed,
                            "outcome": "setup_failed",
                            "setup_isolation": None,
                        },
                    )
                if setup_in_container and r_setup.returncode == 125:
                    diag = distill_diagnostics(r_setup.stdout + "\n" + r_setup.stderr)
                    trace["setup_isolation_evidence"] = self._phase_isolation_evidence(
                        "unavailable", resolved_image
                    )
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=(
                            f"the {self.isolation} setup container could not be "
                            f"started (docker exit 125): {diag}"
                        ),
                        artifact={
                            "files_changed": changed,
                            "outcome": "isolation_unavailable",
                            "setup_isolation": "unavailable",
                            "isolation_evidence": {
                                "requested": self.isolation,
                                "delivered": "unavailable",
                                "image_digest": resolved_image,
                                "network": self.docker_network,
                                "runtime": self.docker_runtime,
                            },
                        },
                    )
                trace.update(
                    execution_state="started_incomplete",
                )
                trace["setup_isolation_evidence"] = self._phase_isolation_evidence(
                    setup_isolation or self.isolation, resolved_image
                )
                if r_setup.returncode != 0:
                    diag = distill_diagnostics(r_setup.stdout + "\n" + r_setup.stderr)
                    hint = (
                        " (setup ran inside the container: the image must contain "
                        "the setup tool, and --docker-network none blocks registries)"
                        if setup_in_container
                        else ""
                    )
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=(
                            f"setup command failed (exit {r_setup.returncode}){hint}: {diag}"
                        ),
                        artifact={
                            "files_changed": changed,
                            "outcome": "setup_failed",
                            "setup_isolation": setup_isolation,
                        },
                    )
                try:
                    setup_after = _setup_fidelity_snapshot(
                        copy,
                        self.setup_output_globs,
                        baseline=setup_before,
                    )
                except SetupFidelityError as exc:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"setup fidelity verification failed: {exc}",
                        artifact={
                            "files_changed": changed,
                            "outcome": "setup_failed",
                            "setup_isolation": setup_isolation,
                        },
                    )
                setup_changes = _setup_fidelity_changes(setup_before, setup_after)
                if setup_changes:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=(
                            "setup_command modified the judged source/harness outside "
                            "declared setup outputs — refusing to run a suite against "
                            "a tree different from the candidate: "
                            + ", ".join(setup_changes[:20])
                        ),
                        artifact={
                            "files_changed": changed,
                            "outcome": "setup_failed",
                            "setup_isolation": setup_isolation,
                            "setup_fidelity_changes": setup_changes,
                        },
                    )
            # A mandatory repo-native pack must judge the exact fully prepared
            # runtime tree the repo suite received. Setup fidelity deliberately
            # permits new dependency/build outputs; this second identity includes
            # all of them and never applies setup_output_globs.
            candidate_runtime_baseline: RuntimeIdentity | None = None
            runtime_identity_elapsed_ms = 0.0
            runtime_continuity = "not_applicable"
            runtime_delivery = "not_applicable"

            def runtime_evidence(*, status: str | None = None) -> dict[str, Any]:
                """Describe runtime evidence truthfully on every exit path."""
                baseline = candidate_runtime_baseline
                return {
                    "runtime_tree_sha256": baseline.sha256 if baseline else None,
                    "runtime_tree_digest_format": (
                        baseline.digest_format if baseline else None
                    ),
                    "runtime_tree_entries": baseline.entries if baseline else None,
                    "runtime_tree_bytes": baseline.regular_bytes if baseline else None,
                    "runtime_identity_elapsed_ms": runtime_identity_elapsed_ms,
                    "runtime_continuity": status or runtime_continuity,
                }

            if pack_dir:
                trace["execution_phase"] = "runtime_verification"
                runtime_delivery = (
                    "read_only_enforced"
                    if container_mode
                    and not (bool(setup_cmd_raw) and self.trust_setup_on_host)
                    else "snapshot_boundary_checked"
                )
                runtime_continuity = "unavailable"
                try:
                    candidate_runtime_baseline = capture_runtime_identity(copy)
                    runtime_identity_elapsed_ms += candidate_runtime_baseline.elapsed_ms
                except RuntimeIdentityError as exc:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"candidate runtime identity failed: {exc}",
                        artifact={
                            "files_changed": changed,
                            "outcome": "runtime_identity_unavailable",
                            "setup_isolation": setup_isolation,
                            **runtime_evidence(status="unavailable"),
                        },
                    )
                runtime_continuity = "incomplete"

            # The machine-readable verdict is written to a JUnit report the JUDGE
            # owns — a path *outside* the repo copy, so the candidate (restricted to
            # relative paths inside the copy) cannot pre-plant or overwrite it via an
            # edit. The score is read from this report and the exit code, never from
            # the candidate-influenced stdout.
            trace["execution_phase"] = "repo_suite"
            base_cmd = self._command(problem)
            t0 = time.perf_counter()
            try:
                if self.isolation in ("docker", "gvisor"):
                    host_xml, r, report_expected = self._run_docker(base_cmd, copy, workdir)
                else:
                    host_xml = os.path.join(workdir, "judge-result.xml")
                    cmd, report_expected, report_env = instrument_command(base_cmd, host_xml)
                    run_env = {**env, **report_env}
                    cmd = _resolve_host_command(cmd, cwd=copy, env=run_env)
                    r = _run_bounded_subprocess(
                        cmd,
                        cwd=copy,
                        env=run_env,
                        timeout=self.timeout,
                        preexec_fn=self._limits() if os.name == "posix" else None,
                    )
            except _DockerRunTimeout as exc:
                delivered = self.isolation if exc.container_started else "not_run"
                suite_isolation_evidence = self._phase_isolation_evidence(
                    delivered,
                    resolved_image,
                    note=(
                        None
                        if exc.container_started
                        else "docker client timed out before container start was proven"
                    ),
                )
                trace["repo_suite_isolation_evidence"] = suite_isolation_evidence
                if exc.container_started:
                    trace.update(
                        execution_state="started_incomplete",
                        test_command_started=True,
                        delivered_isolation=self.isolation,
                    )
                return VerdictResult(
                    passed=False,
                    score=0.0,
                    diagnostics=f"test suite timed out after {self.timeout}s",
                    artifact={
                        "elapsed": self.timeout,
                        "files_changed": changed,
                        "outcome": "test_timeout",
                        "isolation_evidence": suite_isolation_evidence,
                        **runtime_evidence(),
                    },
                )
            except _SubprocessOutputLimitExceeded as exc:
                docker_failure = isinstance(exc, _DockerRunOutputLimit)
                container_started = bool(getattr(exc, "container_started", True))
                delivered = (
                    self.isolation
                    if docker_failure and container_started
                    else ("not_run" if docker_failure else "subprocess")
                )
                if container_started:
                    trace.update(
                        execution_state="started_incomplete",
                        test_command_started=True,
                        delivered_isolation=delivered,
                    )
                trace["repo_suite_isolation_evidence"] = self._phase_isolation_evidence(
                    delivered,
                    resolved_image,
                    note=(
                        None
                        if container_started
                        else "docker client output limit was reached before container start was proven"
                    ),
                )
                return VerdictResult(
                    passed=False,
                    score=0.0,
                    diagnostics=f"test suite output was rejected: {exc}",
                    artifact={
                        "files_changed": changed,
                        "outcome": "test_output_limit",
                        "setup_isolation": setup_isolation,
                        **runtime_evidence(),
                    },
                )
            except _SubprocessContainmentError as exc:
                docker_failure = isinstance(exc, _DockerRunContainmentError)
                container_started = bool(getattr(exc, "container_started", True))
                delivered = (
                    self.isolation
                    if docker_failure and container_started
                    else ("not_run" if docker_failure else "subprocess")
                )
                if container_started:
                    trace.update(
                        execution_state="started_incomplete",
                        test_command_started=True,
                        delivered_isolation=delivered,
                    )
                trace["repo_suite_isolation_evidence"] = self._phase_isolation_evidence(
                    delivered,
                    resolved_image,
                    note=(
                        "docker container cleanup was not proven"
                        if docker_failure
                        else "subprocess cleanup was not proven"
                    ),
                )
                return VerdictResult(
                    passed=False,
                    score=0.0,
                    diagnostics=f"test suite containment failed: {exc}",
                    artifact={
                        "files_changed": changed,
                        "outcome": "runtime_containment_error",
                        "setup_isolation": setup_isolation,
                        **runtime_evidence(),
                    },
                )
            except subprocess.TimeoutExpired:
                trace.update(
                    execution_state="started_incomplete",
                    test_command_started=True,
                    delivered_isolation="subprocess",
                )
                trace["repo_suite_isolation_evidence"] = self._phase_isolation_evidence(
                    "subprocess", resolved_image
                )
                return VerdictResult(
                    passed=False,
                    score=0.0,
                    diagnostics=f"test suite timed out after {self.timeout}s",
                    artifact={
                        "elapsed": self.timeout,
                        "files_changed": changed,
                        "outcome": "test_timeout",
                        **runtime_evidence(),
                    },
                )
            except FileNotFoundError:
                unavailable_evidence = self._phase_isolation_evidence(
                    "unavailable" if container_mode else "not_run",
                    resolved_image,
                )
                trace["repo_suite_isolation_evidence"] = unavailable_evidence
                return VerdictResult(
                    passed=False, score=0.0,
                    diagnostics=(
                        f"{self.isolation} isolation requested but the docker CLI was not found"
                        if container_mode
                        else f"test command not found: {base_cmd[0]!r}"
                    ),
                    artifact={
                        "files_changed": changed,
                        "outcome": (
                            "isolation_unavailable"
                            if container_mode
                            else "test_command_unavailable"
                        ),
                        "setup_isolation": setup_isolation,
                        "isolation_evidence": (
                            unavailable_evidence if container_mode else None
                        ),
                        **runtime_evidence(),
                    },
                )
            elapsed = time.perf_counter() - t0

            if container_mode and r.returncode == 125:
                unavailable_evidence = self._phase_isolation_evidence(
                    "unavailable", resolved_image
                )
                trace["repo_suite_isolation_evidence"] = unavailable_evidence
                return VerdictResult(
                    passed=False,
                    score=0.0,
                    diagnostics=(
                        f"the {self.isolation} suite container could not be started "
                        "(docker exit 125): "
                        + distill_diagnostics(r.stdout + "\n" + r.stderr)
                    ),
                    artifact={
                        "files_changed": changed,
                        "outcome": "isolation_unavailable",
                        "setup_isolation": setup_isolation,
                        "isolation_evidence": unavailable_evidence,
                        **runtime_evidence(),
                    },
                )

            suite_isolation_evidence = self._phase_isolation_evidence(
                self.isolation if container_mode else "subprocess",
                resolved_image,
            )
            trace["repo_suite_isolation_evidence"] = suite_isolation_evidence
            if container_mode:
                # ``isolation_evidence`` is the top-level repo-suite boundary.
                # Later verifier-pack failures must not overwrite this proven
                # delivery with the pack phase's independent availability.
                trace["isolation_evidence"] = suite_isolation_evidence
            trace.update(
                execution_state=("started_incomplete" if pack_dir else "completed"),
                test_command_started=True,
                test_command_completed=True,
                delivered_isolation=(
                    self.isolation if container_mode else "subprocess"
                ),
            )

            if candidate_runtime_baseline is not None:
                trace["execution_phase"] = "runtime_verification"
                try:
                    candidate_after_suite, candidate_changes = verify_runtime_identity(
                        copy, candidate_runtime_baseline
                    )
                    runtime_identity_elapsed_ms += candidate_after_suite.elapsed_ms
                except RuntimeIdentityError as exc:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"candidate runtime identity verification failed: {exc}",
                        artifact={
                            "files_changed": changed,
                            "outcome": "candidate_tree_changed",
                            "tamper": True,
                            "setup_isolation": setup_isolation,
                            **runtime_evidence(status="verification_failed"),
                        },
                    )
                if candidate_changes:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=(
                            "repo suite modified the candidate tree before verifier-pack "
                            "execution: " + ", ".join(candidate_changes[:20])
                        ),
                        artifact={
                            "files_changed": changed,
                            "outcome": "candidate_tree_changed",
                            "tamper": True,
                            "candidate_fidelity_changes": candidate_changes,
                            "verifier_pack_sha256": pack_sha256,
                            "verifier_pack_manifest": pack_manifest,
                            "setup_isolation": setup_isolation,
                            **runtime_evidence(status="verification_failed"),
                        },
                    )

            xml_text = _read_text_or_none(host_xml) or ""
            junit = parse_junit_xml(xml_text)
            repo_junit_sha256 = (
                hashlib.sha256(xml_text.encode("utf-8")).hexdigest()
                if junit is not None and xml_text
                else None
            )
            repo_junit_digest_format = (
                JUNIT_XML_DIGEST_FORMAT if repo_junit_sha256 is not None else None
            )
            if junit is None:
                # Directory-based runners (Maven Surefire) write one report file per
                # test class into a judge-owned dir derived as ``<report>.d``.
                report_set = parse_junit_dir_with_digest(host_xml + ".d")
                if report_set is not None:
                    junit, repo_junit_sha256 = report_set
                    repo_junit_digest_format = JUNIT_REPORT_SET_DIGEST_FORMAT
            passed, score, tests_passed, tests_total = grade_repo_run(
                r.returncode, junit, report_expected=report_expected
            )
            tampered = detect_tamper(r.returncode, junit, report_expected=report_expected)
            output = r.stdout + "\n" + r.stderr
            junit_sha256 = repo_junit_sha256
            junit_digest_format = repo_junit_digest_format
            verdict_source = _clean_verdict_source(
                r.returncode, junit, report_expected=report_expected
            )
            # The normal profile preserves compatibility with runners for which
            # EvoGuard cannot inject JUnit.  The strict profile deliberately
            # does not: exit code 0 with no report (or a report collecting zero
            # cases) is not a test verdict and must never become PASS.
            if strict_harness and (junit is None or junit.total <= 0):
                passed = False
                score = 0.0
                verdict_source = None
                output += (
                    "\nstrict_harness requires a non-empty structured JUnit "
                    "test verdict; exit-only/zero-test success was rejected"
                )
            # Preserve the repo phase before a verifier pack is composed into
            # the top-level result. Baseline evidence is explicitly scoped to
            # this phase, so a later pack failure must not turn repo PASS into
            # an apparent candidate-suite failure. These facts are copied into
            # the attestation (and any configured detached signature) and bound
            # to the composite count remainder.
            if pack_dir:
                trace.update(
                    repo_suite_started=True,
                    repo_suite_completed=True,
                    repo_suite_state="repo_phase_completed",
                    repo_suite_passed=(
                        passed if verdict_source is not None else None
                    ),
                    repo_suite_tests_passed=tests_passed,
                    repo_suite_tests_total=tests_total,
                    repo_suite_verdict_source=verdict_source,
                    repo_suite_returncode=r.returncode,
                    repo_suite_junit_sha256=repo_junit_sha256,
                    repo_suite_junit_digest_format=repo_junit_digest_format,
                )
            pack_tests_passed: int | None = None
            pack_tests_total: int | None = None
            pack_junit_sha256: str | None = None
            pack_junit_digest_format: str | None = None
            outcome: str | None = (
                None if verdict_source is not None else "no_test_verdict"
            )

            # A copied pack is not evidence that its checks ran. Execute it as a
            # separate mandatory phase, explicitly addressed by path, then
            # compose both outcomes. This works even when the repo command is
            # narrowed (for example ``pytest tests/``) or is a custom command.
            if pack_dir:
                trace["execution_phase"] = "verifier_pack"
                assert pack_snapshot is not None and pack_identity is not None
                try:
                    verify_pack_snapshot(pack_snapshot, pack_identity)
                except PackManifestError as exc:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"verifier pack was changed before execution: {exc}",
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
                pack_phase = os.path.join(workdir, "pack-phase")
                os.makedirs(pack_phase, exist_ok=True)
                pack_test_root = "/verifier-pack" if container_mode else pack_snapshot
                pack_cmd = [
                    "python" if container_mode else sys.executable,
                    "-m", "pytest", "-q", "--color=no", "-p", "no:cacheprovider",
                    # The pack snapshot is intentionally outside ``cwd=copy``.
                    # Without an explicit conftest boundary pytest walks their
                    # common ancestors and may enumerate unrelated volatile temp
                    # siblings.  On Windows its same-file fallback then stats a
                    # sibling another verifier has just cleaned up (WinError 2).
                    f"--confcutdir={pack_test_root}",
                    pack_test_root,
                ]
                try:
                    if container_mode:
                        pack_xml, pack_run, pack_report_expected = self._run_docker(
                            pack_cmd, copy, pack_phase, pack_dir=pack_snapshot
                        )
                    else:
                        pack_xml = os.path.join(pack_phase, "judge-result.xml")
                        instrumented, pack_report_expected, pack_report_env = (
                            instrument_command(pack_cmd, pack_xml)
                        )
                        pack_env = {**env, **pack_report_env}
                        instrumented = _resolve_host_command(
                            instrumented, cwd=copy, env=pack_env
                        )
                        pack_run = _run_bounded_subprocess(
                            instrumented,
                            cwd=copy,
                            env=pack_env,
                            timeout=self.timeout,
                            preexec_fn=(
                                self._limits() if os.name == "posix" else None
                            ),
                        )
                except _DockerRunTimeout as exc:
                    delivered = self.isolation if exc.container_started else "not_run"
                    trace["verifier_pack_isolation_evidence"] = (
                        self._phase_isolation_evidence(
                            delivered,
                            resolved_image,
                            note=(
                                None
                                if exc.container_started
                                else (
                                    "docker client timed out before container start "
                                    "was proven"
                                )
                            ),
                        )
                    )
                    if exc.container_started:
                        trace.update(
                            execution_state="started_incomplete",
                            verifier_pack_started=True,
                        )
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"verifier pack timed out after {self.timeout}s",
                        artifact={
                            "files_changed": changed,
                            "outcome": "test_timeout",
                            "setup_isolation": setup_isolation,
                            "isolation_evidence": suite_isolation_evidence,
                            **runtime_evidence(),
                        },
                    )
                except _SubprocessOutputLimitExceeded as exc:
                    docker_failure = isinstance(exc, _DockerRunOutputLimit)
                    container_started = bool(
                        getattr(exc, "container_started", True)
                    )
                    delivered = (
                        self.isolation
                        if docker_failure and container_started
                        else ("not_run" if docker_failure else "subprocess")
                    )
                    if container_started:
                        trace.update(
                            execution_state="started_incomplete",
                            verifier_pack_started=True,
                        )
                    trace["verifier_pack_isolation_evidence"] = (
                        self._phase_isolation_evidence(
                            delivered,
                            resolved_image,
                            note=(
                                None
                                if container_started
                                else "docker client output limit was reached before container start was proven"
                            ),
                        )
                    )
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"verifier pack output was rejected: {exc}",
                        artifact={
                            "files_changed": changed,
                            "outcome": "test_output_limit",
                            "setup_isolation": setup_isolation,
                            "isolation_evidence": (
                                suite_isolation_evidence if container_mode else None
                            ),
                            **runtime_evidence(),
                        },
                    )
                except _SubprocessContainmentError as exc:
                    docker_failure = isinstance(exc, _DockerRunContainmentError)
                    container_started = bool(
                        getattr(exc, "container_started", True)
                    )
                    delivered = (
                        self.isolation
                        if docker_failure and container_started
                        else ("not_run" if docker_failure else "subprocess")
                    )
                    if container_started:
                        trace.update(
                            execution_state="started_incomplete",
                            verifier_pack_started=True,
                        )
                    trace["verifier_pack_isolation_evidence"] = (
                        self._phase_isolation_evidence(
                            delivered,
                            resolved_image,
                            note=(
                                "docker container cleanup was not proven"
                                if docker_failure
                                else "subprocess cleanup was not proven"
                            ),
                        )
                    )
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"verifier pack containment failed: {exc}",
                        artifact={
                            "files_changed": changed,
                            "outcome": "runtime_containment_error",
                            "setup_isolation": setup_isolation,
                            "isolation_evidence": (
                                suite_isolation_evidence if container_mode else None
                            ),
                            **runtime_evidence(),
                        },
                    )
                except subprocess.TimeoutExpired:
                    trace.update(
                        execution_state="started_incomplete",
                        verifier_pack_started=True,
                    )
                    trace["verifier_pack_isolation_evidence"] = (
                        self._phase_isolation_evidence("subprocess", resolved_image)
                    )
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"verifier pack timed out after {self.timeout}s",
                        artifact={
                            "files_changed": changed,
                            "outcome": "test_timeout",
                            "setup_isolation": setup_isolation,
                            "isolation_evidence": (
                                suite_isolation_evidence if container_mode else None
                            ),
                            **runtime_evidence(),
                        },
                    )
                except FileNotFoundError:
                    trace["verifier_pack_isolation_evidence"] = (
                        self._phase_isolation_evidence(
                            "unavailable" if container_mode else "not_run",
                            resolved_image,
                        )
                    )
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics="verifier pack needs pytest/python in the judge environment",
                        artifact={
                            "files_changed": changed,
                            "outcome": "test_command_unavailable",
                            "setup_isolation": setup_isolation,
                            "isolation_evidence": (
                                suite_isolation_evidence if container_mode else None
                            ),
                            **runtime_evidence(),
                        },
                    )
                if container_mode and pack_run.returncode == 125:
                    pack_unavailable_evidence = self._phase_isolation_evidence(
                        "unavailable", resolved_image
                    )
                    trace["verifier_pack_isolation_evidence"] = (
                        pack_unavailable_evidence
                    )
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=(
                            f"the {self.isolation} verifier-pack container could not "
                            "be started (docker exit 125): "
                            + distill_diagnostics(pack_run.stdout + "\n" + pack_run.stderr)
                        ),
                        artifact={
                            "files_changed": changed,
                            "outcome": "isolation_unavailable",
                            "setup_isolation": setup_isolation,
                            "isolation_evidence": suite_isolation_evidence,
                            **runtime_evidence(),
                        },
                    )
                trace["verifier_pack_isolation_evidence"] = (
                    self._phase_isolation_evidence(
                        self.isolation if container_mode else "subprocess",
                        resolved_image,
                    )
                )
                trace.update(
                    execution_state="completed",
                    verifier_pack_started=True,
                    verifier_pack_completed=True,
                )
                trace["execution_phase"] = "runtime_verification"
                try:
                    verify_pack_snapshot(pack_snapshot, pack_identity)
                except PackManifestError as exc:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"verifier pack changed while executing: {exc}",
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
                assert candidate_runtime_baseline is not None
                try:
                    candidate_after_pack, candidate_changes = verify_runtime_identity(
                        copy, candidate_runtime_baseline
                    )
                    runtime_identity_elapsed_ms += candidate_after_pack.elapsed_ms
                except RuntimeIdentityError as exc:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=f"candidate runtime identity verification failed: {exc}",
                        artifact={
                            "files_changed": changed,
                            "outcome": "candidate_tree_changed",
                            "tamper": True,
                            "setup_isolation": setup_isolation,
                            **runtime_evidence(status="verification_failed"),
                        },
                    )
                if candidate_changes:
                    return VerdictResult(
                        passed=False,
                        score=0.0,
                        diagnostics=(
                            "verifier-pack execution modified the candidate tree: "
                            + ", ".join(candidate_changes[:20])
                        ),
                        artifact={
                            "files_changed": changed,
                            "outcome": "candidate_tree_changed",
                            "tamper": True,
                            "candidate_fidelity_changes": candidate_changes,
                            "verifier_pack_sha256": pack_sha256,
                            "verifier_pack_manifest": pack_manifest,
                            "setup_isolation": setup_isolation,
                            **runtime_evidence(status="verification_failed"),
                        },
                    )
                runtime_continuity = runtime_delivery
                pack_xml_text = _read_text_or_none(pack_xml) or ""
                pack_junit = parse_junit_xml(pack_xml_text)
                pack_junit_sha256 = (
                    hashlib.sha256(pack_xml_text.encode("utf-8")).hexdigest()
                    if pack_xml_text
                    else None
                )
                pack_junit_digest_format = (
                    JUNIT_XML_DIGEST_FORMAT
                    if pack_junit_sha256 is not None
                    else None
                )
                pack_passed, pack_score, pack_tests_passed, pack_tests_total = grade_repo_run(
                    pack_run.returncode,
                    pack_junit,
                    report_expected=pack_report_expected,
                )
                pack_verdict_source = _clean_verdict_source(
                    pack_run.returncode,
                    pack_junit,
                    report_expected=pack_report_expected,
                )
                if not pack_tests_total:
                    pack_passed = False
                    pack_score = 0.0
                    if pack_junit is not None:
                        outcome = "pack_no_tests"
                        output += "\nverifier pack collected zero tests"
                    else:
                        outcome = "pack_no_verdict"
                        output += "\nverifier pack produced no valid JUnit verdict"
                elif pack_verdict_source is None:
                    pack_passed = False
                    pack_score = 0.0
                    outcome = "pack_no_verdict"
                    output += "\nverifier pack produced no clean pass/fail verdict"
                passed = passed and pack_passed
                score = min(score, pack_score)
                tampered = tampered or detect_tamper(
                    pack_run.returncode,
                    pack_junit,
                    report_expected=pack_report_expected,
                )
                tests_passed += pack_tests_passed or 0
                tests_total += pack_tests_total or 0
                output += "\n" + pack_run.stdout + "\n" + pack_run.stderr
                if repo_junit_digest_format in (
                    JUNIT_XML_DIGEST_FORMAT,
                    JUNIT_REPORT_SET_DIGEST_FORMAT,
                ):
                    if repo_junit_sha256 is not None and pack_junit_sha256 is not None:
                        composite_identity = (
                            JUNIT_COMPOSITE_DIGEST_FORMAT
                            + "\0repo\0"
                            + repo_junit_digest_format
                            + "\0"
                            + repo_junit_sha256
                            + "\0verifier-pack\0"
                            + JUNIT_XML_DIGEST_FORMAT
                            + "\0"
                            + pack_junit_sha256
                        )
                        junit_sha256 = hashlib.sha256(
                            composite_identity.encode("utf-8")
                        ).hexdigest()
                        junit_digest_format = JUNIT_COMPOSITE_DIGEST_FORMAT
                    else:
                        junit_sha256 = None
                        junit_digest_format = None
                else:
                    # Preserve the historical V1 raw-XML framing for existing
                    # single-document and exit-only repo adapters.
                    combined_junit = (
                        "repo\0" + xml_text + "\0verifier-pack\0" + pack_xml_text
                    )
                    junit_sha256 = hashlib.sha256(
                        combined_junit.encode("utf-8")
                    ).hexdigest()
                    junit_digest_format = "EVOGUARD_JUNIT_COMPOSITE_V1"
                verdict_source = (
                    "composite:repo+verifier-pack"
                    if verdict_source is not None and pack_verdict_source is not None
                    else None
                )
                trace["execution_phase"] = "verifier_pack"

            if not pack_dir:
                trace["execution_phase"] = "repo_suite"

            return VerdictResult(
                passed=passed,
                score=score,
                diagnostics=distill_diagnostics(output),
                artifact={
                    "returncode": r.returncode,
                    "elapsed": elapsed,
                    "tests_passed": tests_passed,
                    "tests_total": tests_total,
                    "files_changed": changed,
                    "files_deleted": deleted_paths,
                    "verdict_source": verdict_source,
                    "outcome": outcome,
                    "tamper": tampered,
                    "junit_sha256": junit_sha256,
                    "junit_digest_format": junit_digest_format,
                    "verifier_pack_sha256": pack_sha256,
                    "expected_verifier_pack_sha256": expected_pack_sha256 or None,
                    "verifier_pack_manifest": pack_manifest,
                    "verifier_pack_tests_passed": pack_tests_passed,
                    "verifier_pack_tests_total": pack_tests_total,
                    **(
                        {
                            "verifier_pack_junit_sha256": pack_junit_sha256,
                            "verifier_pack_junit_digest_format": (
                                pack_junit_digest_format
                            ),
                        }
                        if pack_dir
                        else {}
                    ),
                    "setup_isolation": setup_isolation,
                    "setup_fidelity": "verified" if setup_cmd_raw else "not_applicable",
                    "candidate_fidelity": "verified" if pack_dir else "not_applicable",
                    **runtime_evidence(),
                    "image_digest": resolved_image,
                    "isolation_evidence": (
                        suite_isolation_evidence if container_mode else None
                    ),
                },
            )
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
            if pack_workdir is not None:
                shutil.rmtree(pack_workdir, ignore_errors=True)
