"""Raw-Git bindings for the Trusted Finalizer.

The finalizer cannot treat a verdict produced by candidate execution as the
authority for its candidate, policy, or verifier-pack fingerprints. This module
derives those values from immutable Git objects only. It never checks out,
imports, or executes a candidate tree.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evoom_guard.evidence_bundle import (
    EvidenceBundleError,
    _canonical_json,
    _load_json_object,
    _read_regular_file,
    validate_evidence_context,
)
from evoom_guard.execution import (
    ProcessLimits,
    process_group_popen_kwargs,
    terminate_process_tree,
)
from evoom_guard.guard import (
    _effective_policy,
    effective_policy_sha256,
    serialize_candidate_blocks,
)
from evoom_guard.pack_manifest import PACK_DIGEST_FORMAT, extract_manifest, manifest_problems
from evoom_guard.policy.config import ConfigError, load_config
from evoom_guard.strict_json import strict_json_loads
from evoom_guard.verifiers.harness_policy import is_safe_relpath
from evoom_guard.verifiers.repo_verifier import COPY_IGNORE

FINALIZER_DERIVATION_FORMAT = "EVOGUARD_FINALIZER_GIT_BINDINGS_V1"
FINALIZER_DERIVATION_ROLE = "trusted-finalizer-git-bindings"
MAX_GIT_TREE_BYTES = 16 * 1024 * 1024
MAX_GIT_TREE_ENTRIES = 100_000
MAX_POLICY_BYTES = 1 * 1024 * 1024
MAX_CANDIDATE_FILE_BYTES = 1 * 1024 * 1024
MAX_PACK_FILE_BYTES = 8 * 1024 * 1024
MAX_PACK_BYTES = 32 * 1024 * 1024
MAX_BINDINGS_BYTES = 512 * 1024
MAX_GIT_STDERR_BYTES = 64 * 1024
MAX_GIT_EXECUTABLE_BYTES = 256 * 1024 * 1024
_GIT_STREAM_CHUNK_BYTES = 64 * 1024
_GIT_QUERY_TIMEOUT_SECONDS = 30.0
_GIT_PROCESS_POLL_SECONDS = 0.02
_GIT_KILL_REAP_SECONDS = 3.0
_GIT_READER_JOIN_SECONDS = 2.0
_GIT_PROCESS_LIMITS = ProcessLimits(
    termination_grace_seconds=1.0,
    kill_grace_seconds=_GIT_KILL_REAP_SECONDS,
    reader_join_seconds=_GIT_READER_JOIN_SECONDS,
)

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_BINDING_KEYS = {
    "format",
    "source",
    "repository",
    "repository_id",
    "guard_artifact_sha256",
    "base_tree_sha",
    "head_tree_sha",
    "candidate_sha256",
    "deleted_paths",
    "policy_sha256",
    "verifier_pack_sha256",
    "verifier_pack_manifest",
    "effective_policy",
}
_SOURCE_KEYS = {
    "pull_request_number",
    "workflow_run_id",
    "workflow_run_attempt",
    "base_sha",
    "head_sha",
}


class FinalizerDerivationError(ValueError):
    """A binding could not be derived or did not match a verdict."""


def _is_reparse_point(metadata: os.stat_result) -> bool:
    """Return whether Windows metadata names a link-like reparse point."""

    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _descriptor_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _path_descriptor_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    """Compare path/open identities without Windows' incompatible ctime views."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _validate_git_executable_pin_values(
    executable_path: object,
    executable_sha256: object,
) -> tuple[str, str]:
    if not _git_executable_pinning_supported():
        raise FinalizerDerivationError(
            "pinned Git executable execution requires POSIX stable-snapshot support"
        )
    if (
        not isinstance(executable_path, str)
        or not executable_path
        or len(executable_path) > 4096
        or "\x00" in executable_path
        or not os.path.isabs(executable_path)
    ):
        raise FinalizerDerivationError("pinned Git executable must be an absolute path")
    if os.path.normpath(executable_path) != executable_path:
        raise FinalizerDerivationError("pinned Git executable path must be canonical")
    if not isinstance(executable_sha256, str) or _SHA256.fullmatch(executable_sha256) is None:
        raise FinalizerDerivationError(
            "pinned Git executable SHA-256 must be lowercase 64-hex"
        )
    return executable_path, executable_sha256


def _git_executable_pinning_supported() -> bool:
    """Expose the POSIX snapshot requirement through one testable seam."""

    return os.name == "posix"


def _hash_git_descriptor(
    descriptor: int,
    *,
    expected_identity: tuple[int, int, int, int, int],
) -> str:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or _is_reparse_point(before)
            or _descriptor_identity(before) != expected_identity
            or before.st_size <= 0
            or before.st_size > MAX_GIT_EXECUTABLE_BYTES
        ):
            raise FinalizerDerivationError(
                "pinned Git executable changed while its stable binding was open"
            )
        digest = hashlib.sha256()
        read = 0
        while True:
            chunk = os.read(descriptor, _GIT_STREAM_CHUNK_BYTES)
            if not chunk:
                break
            read += len(chunk)
            if read > MAX_GIT_EXECUTABLE_BYTES:
                raise FinalizerDerivationError(
                    "pinned Git executable exceeds its bounded size limit"
                )
            digest.update(chunk)
        after = os.fstat(descriptor)
        if _descriptor_identity(after) != expected_identity or read != before.st_size:
            raise FinalizerDerivationError(
                "pinned Git executable changed while its stable binding was read"
            )
        return digest.hexdigest()
    except OSError as exc:
        raise FinalizerDerivationError(
            f"could not read pinned Git executable through a stable binding: {exc}"
        ) from exc
    finally:
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
        except OSError:
            pass


def _open_pinned_git_executable(
    executable_path: str,
    executable_sha256: str,
) -> tuple[int, os.stat_result, os.stat_result]:
    executable_path, executable_sha256 = _validate_git_executable_pin_values(
        executable_path,
        executable_sha256,
    )
    if os.path.normcase(os.path.realpath(executable_path)) != os.path.normcase(executable_path):
        raise FinalizerDerivationError(
            "pinned Git executable path must not traverse symlinks"
        )
    try:
        before_path = os.lstat(executable_path)
    except OSError as exc:
        raise FinalizerDerivationError(
            f"could not inspect pinned Git executable {executable_path!r}: {exc}"
        ) from exc
    if (
        stat.S_ISLNK(before_path.st_mode)
        or _is_reparse_point(before_path)
        or not stat.S_ISREG(before_path.st_mode)
    ):
        raise FinalizerDerivationError(
            "pinned Git executable must be a regular non-symlink file"
        )
    if before_path.st_size <= 0 or before_path.st_size > MAX_GIT_EXECUTABLE_BYTES:
        raise FinalizerDerivationError(
            "pinned Git executable exceeds its bounded size limit"
        )
    executable = stat.S_IMODE(before_path.st_mode) & 0o111 != 0
    if not executable:
        raise FinalizerDerivationError("pinned Git executable is not executable")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(executable_path, flags)
    except OSError as exc:
        raise FinalizerDerivationError(
            f"could not open pinned Git executable {executable_path!r}: {exc}"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse_point(opened)
            or _path_descriptor_identity(opened) != _path_descriptor_identity(before_path)
        ):
            raise FinalizerDerivationError(
                "pinned Git executable changed while its stable binding was opened"
            )
        actual_sha256 = _hash_git_descriptor(
            descriptor,
            expected_identity=_descriptor_identity(opened),
        )
        after_path = os.lstat(executable_path)
        if (
            stat.S_ISLNK(after_path.st_mode)
            or _is_reparse_point(after_path)
            or _descriptor_identity(after_path) != _descriptor_identity(before_path)
        ):
            raise FinalizerDerivationError(
                "pinned Git executable path changed while its stable binding was read"
            )
        if actual_sha256 != executable_sha256:
            raise FinalizerDerivationError(
                "pinned Git executable SHA-256 does not match the configured digest"
            )
        return descriptor, opened, after_path
    except BaseException:
        os.close(descriptor)
        raise


@dataclass(frozen=True)
class GitExecutablePin:
    """Immutable opt-in identity for the Git binary used by raw-object readers."""

    executable_path: str
    executable_sha256: str

    def __post_init__(self) -> None:
        descriptor, _opened, _path = _open_pinned_git_executable(
            self.executable_path,
            self.executable_sha256,
        )
        os.close(descriptor)


def git_executable_pin(
    executable_path: str,
    executable_sha256: str,
) -> GitExecutablePin:
    """Construct a fail-closed Git executable pin after reading its exact bytes."""

    return GitExecutablePin(
        executable_path=executable_path,
        executable_sha256=executable_sha256,
    )


def _require_git_executable_pin(value: GitExecutablePin) -> GitExecutablePin:
    if type(value) is not GitExecutablePin:
        raise FinalizerDerivationError("git_executable must be a GitExecutablePin")
    _validate_git_executable_pin_values(value.executable_path, value.executable_sha256)
    return value


@dataclass(frozen=True)
class _GitEntry:
    """One raw Git tree entry. Git trees have no explicit directory entries."""

    mode: str
    object_type: str
    object_id: str

    @property
    def regular(self) -> bool:
        return self.mode in {"100644", "100755"} and self.object_type == "blob"


@dataclass(frozen=True)
class DerivedFinalizerBindings:
    """The canonical output of raw-Git derivation before verdict comparison."""

    payload: dict[str, Any]

    @property
    def source(self) -> dict[str, Any]:
        return dict(self.payload["source"])

    @property
    def candidate_sha256(self) -> str:
        return str(self.payload["candidate_sha256"])

    @property
    def deleted_paths(self) -> tuple[str, ...]:
        return tuple(self.payload["deleted_paths"])

    @property
    def policy_sha256(self) -> str:
        return str(self.payload["policy_sha256"])

    @property
    def verifier_pack_sha256(self) -> str | None:
        value = self.payload["verifier_pack_sha256"]
        return value if isinstance(value, str) else None

    @property
    def effective_policy(self) -> dict[str, Any]:
        return dict(self.payload["effective_policy"])


def _bounded_string(value: object, *, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise FinalizerDerivationError(
            f"{label} must be a non-empty Unicode string of at most {maximum} characters"
        )
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise FinalizerDerivationError(f"{label} must not contain an unpaired surrogate") from exc
    if any(ord(character) < 0x20 for character in value):
        raise FinalizerDerivationError(f"{label} must not contain control characters")
    return value


def _validate_source(value: Mapping[str, Any]) -> dict[str, Any]:
    source = dict(value)
    if set(source) != _SOURCE_KEYS:
        raise FinalizerDerivationError("derivation source has non-canonical keys")
    number = source.get("pull_request_number")
    if type(number) is not int or not 1 <= number <= 2_147_483_647:
        raise FinalizerDerivationError("source.pull_request_number is invalid")
    _bounded_string(source.get("workflow_run_id"), label="source.workflow_run_id", maximum=256)
    attempt = source.get("workflow_run_attempt")
    if type(attempt) is not int or not 1 <= attempt <= 2_147_483_647:
        raise FinalizerDerivationError("source.workflow_run_attempt is invalid")
    for field in ("base_sha", "head_sha"):
        item = source.get(field)
        if not isinstance(item, str) or _GIT_SHA.fullmatch(item) is None:
            raise FinalizerDerivationError(f"source.{field} must be a lowercase Git digest")
    return source


def _validate_sha256(value: object, *, label: str, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        suffix = " or null" if nullable else ""
        raise FinalizerDerivationError(f"{label} must be a lowercase SHA-256 digest{suffix}")
    return value


def _valid_git_sha(value: str, *, label: str) -> str:
    if _GIT_SHA.fullmatch(value) is None:
        raise FinalizerDerivationError(f"{label} must be a lowercase immutable Git digest")
    return value


def _snapshot_git_executable(
    source_descriptor: int,
    source_identity: tuple[int, int, int, int, int],
    pin: GitExecutablePin,
    directory: str,
) -> tuple[str, int, os.stat_result, os.stat_result]:
    """Copy the reviewed Git binary from a stable descriptor into a private path."""

    suffix = Path(pin.executable_path).suffix if os.name == "nt" else ""
    # Git dispatches on argv[0]; a name such as ``git-pinned`` is interpreted
    # as the nonexistent ``pinned`` builtin. Keep the canonical executable name.
    snapshot_path = os.path.join(directory, "git" + suffix)
    snapshot_descriptor = -1
    try:
        snapshot_descriptor = os.open(
            snapshot_path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0),
            0o500,
        )
        os.lseek(source_descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        copied = 0
        while True:
            chunk = os.read(source_descriptor, _GIT_STREAM_CHUNK_BYTES)
            if not chunk:
                break
            copied += len(chunk)
            if copied > MAX_GIT_EXECUTABLE_BYTES:
                raise FinalizerDerivationError(
                    "pinned Git executable exceeds its bounded size limit"
                )
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(snapshot_descriptor, view)
                if written <= 0:  # pragma: no cover - defensive OS contract
                    raise OSError("short write while snapshotting Git executable")
                view = view[written:]
        os.fsync(snapshot_descriptor)
        after_source = os.fstat(source_descriptor)
        if (
            _descriptor_identity(after_source) != source_identity
            or copied != after_source.st_size
        ):
            raise FinalizerDerivationError(
                "pinned Git executable changed while its snapshot was created"
            )
        if digest.hexdigest() != pin.executable_sha256:
            raise FinalizerDerivationError(
                "pinned Git executable SHA-256 does not match the configured digest"
            )
        os.close(snapshot_descriptor)
        snapshot_descriptor = -1
        os.chmod(snapshot_path, 0o500)
        return (snapshot_path, *_open_pinned_git_executable(snapshot_path, pin.executable_sha256))
    except OSError as exc:
        raise FinalizerDerivationError(
            f"could not create a stable pinned Git executable snapshot: {exc}"
        ) from exc
    except BaseException:
        try:
            os.unlink(snapshot_path)
        except OSError:
            pass
        raise
    finally:
        if snapshot_descriptor >= 0:
            os.close(snapshot_descriptor)
        try:
            os.lseek(source_descriptor, 0, os.SEEK_SET)
        except OSError:
            pass


class _PinnedGitExecutableBinding:
    """Own one stable executable binding for a raw-Git reader lifetime."""

    def __init__(self, pin: GitExecutablePin) -> None:
        self._pin = _require_git_executable_pin(pin)
        self._temporary_directory: tempfile.TemporaryDirectory[str] | None = None
        self._descriptor = -1
        self._descriptor_identity: tuple[int, int, int, int, int] | None = None
        self._path_identity: tuple[int, int, int, int, int] | None = None
        self.executable = self._pin.executable_path

        source_descriptor, source_opened, _source_path = _open_pinned_git_executable(
            self._pin.executable_path,
            self._pin.executable_sha256,
        )
        temporary = tempfile.TemporaryDirectory(prefix=".evoguard-finalizer-git-")
        try:
            snapshot, descriptor, opened, path = _snapshot_git_executable(
                source_descriptor,
                _descriptor_identity(source_opened),
                self._pin,
                temporary.name,
            )
        except BaseException:
            temporary.cleanup()
            raise
        finally:
            os.close(source_descriptor)
        self._temporary_directory = temporary
        self._descriptor = descriptor
        self._descriptor_identity = _descriptor_identity(opened)
        self._path_identity = _descriptor_identity(path)
        self.executable = snapshot

    def prove_stable(self) -> None:
        if (
            self._descriptor < 0
            or self._descriptor_identity is None
            or self._path_identity is None
        ):
            raise FinalizerDerivationError("pinned Git executable binding is closed")
        actual_sha256 = _hash_git_descriptor(
            self._descriptor,
            expected_identity=self._descriptor_identity,
        )
        try:
            current_path = os.lstat(self.executable)
        except OSError as exc:
            raise FinalizerDerivationError(
                f"pinned Git executable path changed during execution: {exc}"
            ) from exc
        if (
            stat.S_ISLNK(current_path.st_mode)
            or _is_reparse_point(current_path)
            or not stat.S_ISREG(current_path.st_mode)
            or _descriptor_identity(current_path) != self._path_identity
            or _path_descriptor_identity(current_path)
            != _path_descriptor_identity(os.fstat(self._descriptor))
        ):
            raise FinalizerDerivationError(
                "pinned Git executable path changed during execution"
            )
        if actual_sha256 != self._pin.executable_sha256:
            raise FinalizerDerivationError(
                "pinned Git executable changed during execution"
            )

    def close(self) -> None:
        descriptor = self._descriptor
        self._descriptor = -1
        if descriptor >= 0:
            os.close(descriptor)
        temporary = self._temporary_directory
        self._temporary_directory = None
        if temporary is not None:
            temporary.cleanup()

    def __enter__(self) -> _PinnedGitExecutableBinding:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _terminate_git_process_tree(process: subprocess.Popen[Any]) -> bool:
    """Terminate the dedicated Git process group and prove managed cleanup."""

    return terminate_process_tree(process, _GIT_PROCESS_LIMITS)


def _join_and_close_git_readers(
    readers: list[threading.Thread],
    streams: list[Any],
) -> bool:
    """Boundedly join attempted readers and close only streams proven safe."""

    stopped: list[bool] = []
    first_error: BaseException | None = None
    deadline = time.monotonic() + _GIT_READER_JOIN_SECONDS
    for reader in readers:
        try:
            reader.join(max(0.0, deadline - time.monotonic()))
            stopped.append(not reader.is_alive())
        except BaseException as exc:
            # Thread.start() can raise after a native thread may exist. A join
            # failure is therefore not proof that its stream is safe to close.
            stopped.append(False)
            if first_error is None:
                first_error = exc

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


def _run_git_command(
    repo: str,
    args: list[str],
    *,
    bare: bool,
    executable: str,
    limit: int = MAX_GIT_TREE_BYTES,
    isolated_environment: bool = False,
) -> bytes:
    """Run one read-only Git query with bounded streaming output.

    A raw tree can be candidate-controlled.  Do not use ``capture_output`` and
    check its size afterwards: that would let a very large tree occupy memory
    in the privileged finalizer process before the stated limit takes effect.
    Both pipes are drained concurrently so a verbose error cannot deadlock the
    child or bypass a resource bound.
    """

    command = [executable, "--no-replace-objects"]
    command.extend(["--git-dir", repo] if bare else ["-C", repo])
    command.extend(args)
    if isolated_environment:
        # A digest-pinned executable is not a meaningful code pin if the
        # dynamic loader, HOME/XDG configuration, or executable search path can
        # still be injected by the parent.  The high-trust pinned path therefore
        # gets a closed environment.  The two Windows variables are retained
        # only for platform process startup; pinned execution itself is POSIX-
        # only and fails before this point on Windows.
        environment = {
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
            "LANG": "C",
        }
        if os.name == "nt":  # pragma: no cover - pinned mode rejects Windows
            for name in ("SYSTEMROOT", "WINDIR"):
                if name in os.environ:
                    environment[name] = os.environ[name]
    else:
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.upper().startswith("GIT_")
        }
        environment["GIT_OPTIONAL_LOCKS"] = "0"
    process: subprocess.Popen[Any] | None = None
    streams: list[Any] = []
    reader_start_attempts: list[threading.Thread] = []
    cleanup_proven = False
    readers_closed = False
    try:
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                **process_group_popen_kwargs(),
            )
        except OSError as exc:
            raise FinalizerDerivationError(
                f"could not read immutable Git object: {exc}"
            ) from exc
        stdout_stream = process.stdout
        stderr_stream = process.stderr
        streams = [
            stream for stream in (stdout_stream, stderr_stream) if stream is not None
        ]
        if stdout_stream is None or stderr_stream is None:
            raise FinalizerDerivationError(
                "could not read immutable Git object: Git output pipes were not created"
            )
        stdout = bytearray()
        stderr = bytearray()
        overflow: set[str] = set()
        read_errors: list[BaseException] = []
        reader_signal = threading.Event()

        def drain(stream: Any, *, maximum: int, target: bytearray, label: str) -> None:
            try:
                while True:
                    chunk = stream.read(_GIT_STREAM_CHUNK_BYTES)
                    if not chunk:
                        return
                    remaining = maximum + 1 - len(target)
                    if remaining > 0:
                        target.extend(chunk[:remaining])
                    if len(target) > maximum:
                        overflow.add(label)
                        reader_signal.set()
            except BaseException as exc:
                read_errors.append(exc)
                reader_signal.set()

        readers = [
            threading.Thread(
                target=drain,
                args=(stdout_stream,),
                kwargs={"maximum": limit, "target": stdout, "label": "stdout"},
                daemon=True,
            ),
            threading.Thread(
                target=drain,
                args=(stderr_stream,),
                kwargs={
                    "maximum": MAX_GIT_STDERR_BYTES,
                    "target": stderr,
                    "label": "stderr",
                },
                daemon=True,
            ),
        ]
        for reader in readers:
            # Record before start(): start may fail after a native thread exists.
            reader_start_attempts.append(reader)
            reader.start()
        deadline = time.monotonic() + _GIT_QUERY_TIMEOUT_SECONDS
        timed_out = False
        while process.poll() is None:
            if read_errors or overflow:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            reader_signal.wait(min(_GIT_PROCESS_POLL_SECONDS, remaining))

        interrupted = timed_out or bool(read_errors) or bool(overflow)
        if interrupted:
            if not _terminate_git_process_tree(process):
                raise FinalizerDerivationError(
                    "could not read immutable Git object: Git query process "
                    "cleanup could not be proven"
                )
            cleanup_proven = True
        else:
            try:
                process.wait(timeout=_GIT_KILL_REAP_SECONDS)
            except BaseException:
                try:
                    cleanup_proven = _terminate_git_process_tree(process)
                except BaseException:
                    pass
                raise
            if os.name == "posix":
                if not _terminate_git_process_tree(process):
                    raise FinalizerDerivationError(
                        "could not read immutable Git object: Git query process "
                        "cleanup could not be proven"
                    )
                cleanup_proven = True

        if not _join_and_close_git_readers(reader_start_attempts, streams):
            raise FinalizerDerivationError(
                "could not read immutable Git object: Git query output readers "
                "did not stop after cleanup"
            )
        readers_closed = True

        if timed_out:
            raise FinalizerDerivationError(
                "could not read immutable Git object: Git query timed out"
            )
        if read_errors:
            raise FinalizerDerivationError(
                f"could not read immutable Git object: {read_errors[0]}"
            ) from read_errors[0]
        if "stdout" in overflow:
            raise FinalizerDerivationError("Git object listing exceeds the finalizer limit")
        if "stderr" in overflow:
            raise FinalizerDerivationError("Git error output exceeds the finalizer limit")
        if process.returncode != 0:
            detail = bytes(stderr).decode("utf-8", "replace")[:512].strip()
            raise FinalizerDerivationError(
                f"Git object lookup failed: {detail or process.returncode}"
            )
        return bytes(stdout)
    except BaseException:
        # Preserve the active exception while attempting bounded cleanup.
        if process is not None:
            if not cleanup_proven:
                try:
                    cleanup_proven = _terminate_git_process_tree(process)
                except BaseException:
                    pass
            if not readers_closed:
                try:
                    readers_closed = _join_and_close_git_readers(
                        reader_start_attempts,
                        streams,
                    )
                except BaseException:
                    pass
        raise


def _git_command(
    repo: str,
    args: list[str],
    *,
    bare: bool,
    limit: int = MAX_GIT_TREE_BYTES,
    git_executable: GitExecutablePin | None = None,
) -> bytes:
    """Run one raw Git query, optionally through a reviewed executable pin."""

    if git_executable is None:
        return _run_git_command(
            repo,
            args,
            bare=bare,
            executable="git",
            limit=limit,
        )
    with _PinnedGitExecutableBinding(git_executable) as binding:
        try:
            return _run_git_command(
                repo,
                args,
                bare=bare,
                executable=binding.executable,
                limit=limit,
                isolated_environment=True,
            )
        finally:
            binding.prove_stable()


class _GitReader:
    """Read raw objects from a worktree or bare object store without checkout."""

    def __init__(
        self,
        repo: str,
        *,
        bare: bool,
        git_executable: GitExecutablePin | None = None,
    ) -> None:
        self.repo = os.path.abspath(repo)
        self.bare = bare
        self._git_binding: _PinnedGitExecutableBinding | None = None
        self._closed = False
        if not os.path.isdir(self.repo):
            raise FinalizerDerivationError(f"Git repository directory does not exist: {repo!r}")
        if git_executable is not None:
            self._git_binding = _PinnedGitExecutableBinding(git_executable)

    def command(self, args: list[str], *, limit: int = MAX_GIT_TREE_BYTES) -> bytes:
        if self._closed:
            raise FinalizerDerivationError("raw Git reader is closed")
        binding = self._git_binding
        if binding is None:
            return _git_command(self.repo, args, bare=self.bare, limit=limit)
        try:
            return _run_git_command(
                self.repo,
                args,
                bare=self.bare,
                executable=binding.executable,
                limit=limit,
                isolated_environment=True,
            )
        finally:
            binding.prove_stable()

    def close(self) -> None:
        self._closed = True
        binding = self._git_binding
        self._git_binding = None
        if binding is not None:
            binding.close()

    def __enter__(self) -> _GitReader:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def commit_tree(self, sha: str) -> str:
        _valid_git_sha(sha, label="commit")
        output = self.command(["rev-parse", "--verify", f"{sha}^{{tree}}"], limit=256)
        return _valid_git_sha(output.decode("ascii", "strict").strip(), label="derived tree")

    def tree(self, sha: str) -> dict[str, _GitEntry]:
        _valid_git_sha(sha, label="treeish")
        raw = self.command(["ls-tree", "-rz", "--full-tree", sha])
        entries: dict[str, _GitEntry] = {}
        for row in raw.split(b"\0"):
            if not row:
                continue
            try:
                metadata, raw_path = row.split(b"\t", 1)
                mode, object_type, object_id = metadata.decode("ascii", "strict").split(" ", 2)
                path = raw_path.decode("utf-8", "strict")
            except (UnicodeDecodeError, ValueError) as exc:
                raise FinalizerDerivationError(
                    "raw Git tree contains an invalid or non-UTF-8 path"
                ) from exc
            if not is_safe_relpath(path):
                raise FinalizerDerivationError(f"raw Git tree has unsafe path: {path!r}")
            if path in entries:
                raise FinalizerDerivationError(f"raw Git tree duplicates path: {path!r}")
            if len(entries) >= MAX_GIT_TREE_ENTRIES:
                raise FinalizerDerivationError("raw Git tree exceeds the entry limit")
            entries[path] = _GitEntry(mode=mode, object_type=object_type, object_id=object_id)
        return entries

    def blob(self, object_id: str, *, maximum: int, label: str) -> bytes:
        _valid_git_sha(object_id, label=f"{label} object")
        size_raw = self.command(["cat-file", "-s", object_id], limit=128)
        try:
            size = int(size_raw.decode("ascii", "strict").strip())
        except ValueError as exc:
            raise FinalizerDerivationError(f"{label} has no valid Git blob size") from exc
        if size < 0 or size > maximum:
            raise FinalizerDerivationError(f"{label} exceeds the {maximum}-byte finalizer limit")
        data = self.command(["cat-file", "blob", object_id], limit=maximum)
        if len(data) != size:
            raise FinalizerDerivationError(f"{label} changed or was truncated while reading")
        return data


def resolve_raw_git_regular_blob(
    *,
    repository: str,
    treeish: str,
    path: str,
    bare: bool = False,
    git_executable: GitExecutablePin | None = None,
) -> str:
    """Resolve one safe regular-file path to its raw Git blob object ID.

    This is the narrow public raw-Git boundary for callers that need to bind a
    reviewed workflow or other protected file without importing the private
    reader or exposing its tree-entry representation.
    """

    if not isinstance(path, str) or not is_safe_relpath(path):
        raise FinalizerDerivationError(
            "raw Git regular-blob path must be a safe relative path"
        )
    with _GitReader(
        repository,
        bare=bare,
        git_executable=git_executable,
    ) as reader:
        entry = reader.tree(treeish).get(path)
    if entry is None or not entry.regular:
        raise FinalizerDerivationError(
            "raw Git regular-blob path is missing or is not a regular blob"
        )
    return _valid_git_sha(entry.object_id, label="regular blob")


def derive_raw_ref_parent_pair(
    *,
    repository: str,
    ref: str,
    bare: bool = False,
    git_executable: GitExecutablePin | None = None,
) -> tuple[str, str, str, str]:
    """Resolve one exact ref and its single parent from raw immutable Git objects.

    This deliberately uses Git plumbing only: no checkout, no import, and no
    candidate command execution.  The returned tuple is ``(commit, tree,
    parent_commit, parent_tree)``.  A V1 caller that needs a deterministic
    before/after boundary must reject root and merge commits rather than
    silently choosing one of several parents.
    """

    if not isinstance(ref, str) or not ref.startswith("refs/") or "\x00" in ref:
        raise FinalizerDerivationError("raw Git ref must be a canonical refs/* name")
    with _GitReader(
        repository,
        bare=bare,
        git_executable=git_executable,
    ) as reader:
        raw_commit = reader.command(
            ["rev-parse", "--verify", f"{ref}^{{commit}}"],
            limit=256,
        )
        commit = _valid_git_sha(
            raw_commit.decode("ascii", "strict").strip(),
            label="derived ref",
        )
        raw_parents = reader.command(
            ["rev-list", "--parents", "-n", "1", commit],
            limit=512,
        )
        try:
            parents = raw_parents.decode("ascii", "strict").strip().split()
        except UnicodeDecodeError as exc:  # pragma: no cover - defensive parity with Git reader
            raise FinalizerDerivationError("raw Git parent listing is not ASCII") from exc
        if len(parents) != 2 or parents[0] != commit:
            raise FinalizerDerivationError(
                "V1 protected-release source must be a non-merge commit with exactly one parent"
            )
        parent = _valid_git_sha(parents[1], label="derived parent commit")
        return commit, reader.commit_tree(commit), parent, reader.commit_tree(parent)


def derive_raw_evaluation_bindings(
    *,
    base_repo: str,
    head_repo: str,
    base_sha: str,
    head_sha: str,
    base_tree_sha: str,
    head_tree_sha: str,
    base_is_bare: bool = False,
    head_is_bare: bool = False,
    git_executable: GitExecutablePin | None = None,
) -> dict[str, Any]:
    """Derive candidate, policy, and verifier-pack values from raw Git only.

    This is intentionally source-shape agnostic.  The PR finalizer and the
    release-source finalizer share the exact immutable-object calculation but
    retain separate public source and evidence contracts.
    """

    for label, value in (
        ("base_sha", base_sha),
        ("head_sha", head_sha),
        ("base_tree_sha", base_tree_sha),
        ("head_tree_sha", head_tree_sha),
    ):
        _valid_git_sha(value, label=label)
    base = _GitReader(
        base_repo,
        bare=base_is_bare,
        git_executable=git_executable,
    )
    try:
        head = _GitReader(
            head_repo,
            bare=head_is_bare,
            git_executable=git_executable,
        )
    except BaseException:
        base.close()
        raise
    try:
        return _derive_raw_evaluation_from_readers(
            base,
            head,
            base_sha=base_sha,
            head_sha=head_sha,
            base_tree_sha=base_tree_sha,
            head_tree_sha=head_tree_sha,
        )
    finally:
        head.close()
        base.close()


def _derive_raw_evaluation_from_readers(
    base: _GitReader,
    head: _GitReader,
    *,
    base_sha: str,
    head_sha: str,
    base_tree_sha: str,
    head_tree_sha: str,
) -> dict[str, Any]:
    if base.commit_tree(base_sha) != base_tree_sha or head.commit_tree(head_sha) != head_tree_sha:
        raise FinalizerDerivationError("provided commit/tree binding is not immutable Git reality")

    base_entries = base.tree(base_sha)
    head_entries = head.tree(head_sha)
    policy_entry = base_entries.get(".evoguard.json")
    if policy_entry is None or not policy_entry.regular:
        raise FinalizerDerivationError("trusted finalizer requires a regular base .evoguard.json")
    policy_bytes = base.blob(
        policy_entry.object_id,
        maximum=MAX_POLICY_BYTES,
        label="base .evoguard.json",
    )
    head_package = head_entries.get("package.json")
    policy, pack_path, pack_pin = _effective_policy_from_raw_config(
        policy_bytes,
        head_has_package_json=head_package is not None and head_package.regular,
    )
    pack_digest: str | None = None
    pack_manifest: dict[str, Any] | None = None
    if pack_path is not None:
        pack_digest, pack_manifest = _raw_pack_identity(base, base_sha, pack_path)
        if pack_pin is None:
            raise FinalizerDerivationError(
                "trusted finalizer requires expect_verifier_pack_sha256 with verifier_pack"
            )
        if pack_digest != pack_pin:
            raise FinalizerDerivationError(
                "base verifier-pack digest does not match its immutable policy pin"
            )
    elif pack_pin is not None:
        raise FinalizerDerivationError("base policy pins a verifier pack without verifier_pack")
    candidate = serialize_candidate_blocks(
        _candidate_blocks(base, head, base_sha=base_sha, head_sha=head_sha)
    )
    return {
        "candidate_sha256": hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
        "deleted_paths": _deleted_paths(base_entries, head_entries),
        "policy_sha256": effective_policy_sha256(policy),
        "verifier_pack_sha256": pack_digest,
        "verifier_pack_manifest": pack_manifest,
        "effective_policy": policy,
    }


def _ignored_path(path: str) -> bool:
    ignored = set(COPY_IGNORE) | {".git"}
    return any(part in ignored for part in path.split("/"))


def _candidate_blocks(
    base: _GitReader,
    head: _GitReader,
    *,
    base_sha: str,
    head_sha: str,
) -> dict[str, str]:
    base_tree = {
        path: entry for path, entry in base.tree(base_sha).items() if not _ignored_path(path)
    }
    head_tree = {
        path: entry for path, entry in head.tree(head_sha).items() if not _ignored_path(path)
    }
    blocks: dict[str, str] = {}
    problems: list[str] = []
    for path in sorted(head_tree):
        candidate = head_tree[path]
        original = base_tree.get(path)
        unchanged = original is not None and (
            original.mode == candidate.mode
            and original.object_type == candidate.object_type
            and original.object_id == candidate.object_id
        )
        if unchanged:
            continue
        if original is not None and original.mode != candidate.mode:
            problems.append(f"{path}: path mode changed")
            continue
        if original is not None and original.object_type != candidate.object_type:
            problems.append(f"{path}: path type changed")
            continue
        if not candidate.regular:
            problems.append(f"{path}: path is not a regular file")
            continue
        try:
            data = head.blob(
                candidate.object_id,
                maximum=MAX_CANDIDATE_FILE_BYTES,
                label=f"candidate path {path!r}",
            )
            blocks[path] = data.decode("utf-8", "strict")
        except UnicodeDecodeError:
            problems.append(f"{path}: changed file is not valid UTF-8 text")
        except FinalizerDerivationError as exc:
            problems.append(f"{path}: {exc}")
    if problems:
        raise FinalizerDerivationError(
            "changed raw Git paths cannot be represented by Guard: " + "; ".join(problems)
        )
    return blocks


def _tree_paths_with_directories(entries: Mapping[str, _GitEntry]) -> set[str]:
    """Reconstruct the tracked paths a clean checkout exposes to Guard.

    A recursive Git tree listing contains leaf entries, while Guard also sees
    ordinary parent directories created for those entries. Empty directories
    are not representable in Git, so this is the exact relevant set for a
    clean base/head checkout.
    """

    paths: set[str] = set()
    for path in entries:
        if _ignored_path(path):
            continue
        paths.add(path)
        pieces = path.split("/")
        paths.update("/".join(pieces[:index]) for index in range(1, len(pieces)))
    return paths


def _deleted_paths(
    base_entries: Mapping[str, _GitEntry],
    head_entries: Mapping[str, _GitEntry],
) -> list[str]:
    """Derive the deletion list that Guard receives for a base/head checkout."""

    return sorted(
        _tree_paths_with_directories(base_entries) - _tree_paths_with_directories(head_entries)
    )


def _parse_pack_manifest(data: bytes) -> dict[str, Any] | None:
    try:
        decoded = strict_json_loads(data.decode("utf-8", "strict"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise FinalizerDerivationError(f"raw Git pack.json is invalid JSON: {exc}") from exc
    problems = manifest_problems(decoded)
    if problems:
        raise FinalizerDerivationError("raw Git pack.json is invalid: " + "; ".join(problems))
    assert isinstance(decoded, dict)
    return extract_manifest(decoded)


def _framed_path(digest: Any, kind: bytes, path: str) -> None:
    encoded = path.encode("utf-8")
    digest.update(kind)
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)


def _raw_pack_identity(
    reader: _GitReader,
    tree_sha: str,
    pack_path: str,
) -> tuple[str, dict[str, Any] | None]:
    if not is_safe_relpath(pack_path):
        raise FinalizerDerivationError("verifier_pack must be a safe relative base-tree path")
    prefix = pack_path.rstrip("/") + "/"
    tree = reader.tree(tree_sha)
    members = {
        path[len(prefix) :]: entry for path, entry in tree.items() if path.startswith(prefix)
    }
    if not members:
        raise FinalizerDerivationError("verifier_pack is absent from the immutable base tree")
    if any(not rel or not is_safe_relpath(rel) for rel in members):
        raise FinalizerDerivationError("verifier_pack contains an unsafe raw Git path")
    if any(not entry.regular for entry in members.values()):
        raise FinalizerDerivationError(
            "verifier_pack contains a symlink, submodule, or special path"
        )
    directories: set[str] = set()
    for rel in members:
        parts = rel.split("/")
        directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
    digest = hashlib.sha256()
    digest.update(PACK_DIGEST_FORMAT.encode("ascii") + b"\0")
    for directory in sorted(directories):
        _framed_path(digest, b"D", directory)
    total = 0
    manifest: dict[str, Any] | None = None
    has_test = False
    for rel in sorted(members):
        data = reader.blob(
            members[rel].object_id,
            maximum=MAX_PACK_FILE_BYTES,
            label=f"verifier-pack path {rel!r}",
        )
        total += len(data)
        if total > MAX_PACK_BYTES:
            raise FinalizerDerivationError("verifier_pack exceeds the total finalizer limit")
        _framed_path(digest, b"F", rel)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
        if os.path.basename(rel).startswith("test_") and rel.endswith(".py"):
            has_test = True
        if rel == "pack.json":
            manifest = _parse_pack_manifest(data)
    if not has_test:
        raise FinalizerDerivationError("verifier_pack contains no test_*.py file")
    return digest.hexdigest(), manifest


def _effective_policy_from_raw_config(
    policy_bytes: bytes,
    *,
    head_has_package_json: bool,
) -> tuple[dict[str, Any], str | None, str | None]:
    """Reuse Guard strict configuration validation for the finalizer profile."""

    if len(policy_bytes) > MAX_POLICY_BYTES:
        raise FinalizerDerivationError("base .evoguard.json exceeds the finalizer limit")
    try:
        policy_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise FinalizerDerivationError("base .evoguard.json is not UTF-8") from exc
    with tempfile.TemporaryDirectory(prefix=".evoguard-finalizer-policy-") as directory:
        policy_path = os.path.join(directory, ".evoguard.json")
        Path(policy_path).write_bytes(policy_bytes)
        try:
            cfg = load_config(policy_path, required=True, out=lambda _message: None)
        except ConfigError as exc:
            raise FinalizerDerivationError(f"base .evoguard.json is invalid: {exc}") from exc

    def policy_bool(key: str) -> bool:
        value = cfg.get(key)
        return value if isinstance(value, bool) else False

    def policy_int(key: str) -> int | None:
        value = cfg.get(key)
        return value if type(value) is int else None

    def policy_str(key: str) -> str | None:
        value = cfg.get(key)
        return value if isinstance(value, str) else None

    def policy_float(key: str) -> float | None:
        value = cfg.get(key)
        return value if isinstance(value, float) else None

    raw_command = cfg.get("test_command")
    if isinstance(raw_command, str):
        shell_operators = ("&&", "||", ";", "|", ">", "<", "$(", chr(96))
        test_command: list[str] | None = (
            ["sh", "-c", raw_command]
            if any(operator in raw_command for operator in shell_operators)
            else raw_command.split()
        )
    elif isinstance(raw_command, list):
        test_command = [str(item) for item in raw_command]
    else:
        test_command = None
    setup_raw = cfg.get("setup_command")
    setup_command = [str(item) for item in setup_raw] if isinstance(setup_raw, list) else None
    protected_raw = cfg.get("protected")
    protected = (
        tuple(str(item) for item in protected_raw) if isinstance(protected_raw, list) else ()
    )
    allow_raw = cfg.get("allow")
    allow = tuple(str(item) for item in allow_raw) if isinstance(allow_raw, list) else ()
    setup_globs_raw = cfg.get("setup_output_globs")
    setup_globs = (
        tuple(str(item) for item in setup_globs_raw) if isinstance(setup_globs_raw, list) else ()
    )
    timeout = policy_int("timeout") or 120
    configured_mem_limit = policy_int("mem_limit")
    mem_limit = configured_mem_limit if configured_mem_limit is not None else 1024
    if mem_limit == 1024 and head_has_package_json:
        if "mem_limit" not in cfg:
            raise FinalizerDerivationError(
                "trusted finalizer requires an explicit base-policy mem_limit for a Node project"
            )
        mem_limit = 0
    isolation = policy_str("isolation") or "subprocess"
    docker_image = policy_str("docker_image")
    docker_network = policy_str("docker_network") or "none"
    if isolation in {"docker", "gvisor"} and not docker_image:
        raise FinalizerDerivationError(f"base policy {isolation!r} requires docker_image")
    pack = policy_str("verifier_pack")
    pack_pin = policy_str("expect_verifier_pack_sha256")
    policy = _effective_policy(
        mode="blackbox" if policy_bool("blackbox") else "repo",
        isolation=isolation,
        docker_image=docker_image,
        docker_network=docker_network,
        test_command=test_command,
        setup_command=setup_command,
        trust_setup_on_host=policy_bool("trust_setup_on_host"),
        setup_output_globs=setup_globs,
        protected=protected,
        allow=allow,
        allow_new_tests=policy_bool("allow_new_tests"),
        timeout=timeout,
        mem_limit_mb=mem_limit,
        verifier_pack=pack,
        expect_verifier_pack_sha256=pack_pin,
        blackbox=policy_bool("blackbox"),
        blackbox_only=policy_bool("blackbox_only"),
        require_report_integrity=policy_str("require_report_integrity"),
        require_candidate_isolation=policy_str("require_candidate_isolation"),
        min_diff_coverage=policy_float("min_diff_coverage"),
        baseline_evidence=policy_bool("baseline_evidence"),
        require_demonstrated_fix=policy_bool("require_demonstrated_fix"),
        strict_harness=policy_bool("strict_harness"),
        policy_id=policy_str("policy_id"),
        policy_version=policy_str("policy_version"),
    )
    return policy, pack, pack_pin


def derive_finalizer_bindings(
    *,
    base_repo: str,
    head_repo: str,
    base_sha: str,
    head_sha: str,
    base_tree_sha: str,
    head_tree_sha: str,
    source: Mapping[str, Any],
    repository: str,
    repository_id: str,
    guard_artifact_sha256: str,
    base_is_bare: bool = False,
    head_is_bare: bool = False,
    git_executable: GitExecutablePin | None = None,
) -> DerivedFinalizerBindings:
    """Derive candidate, policy, and pack bindings from raw immutable Git objects."""

    verified_source = _validate_source(source)
    for label, value in (
        ("base_sha", base_sha),
        ("head_sha", head_sha),
        ("base_tree_sha", base_tree_sha),
        ("head_tree_sha", head_tree_sha),
    ):
        _valid_git_sha(value, label=label)
    if verified_source["base_sha"] != base_sha or verified_source["head_sha"] != head_sha:
        raise FinalizerDerivationError("source revision does not match derivation revision")
    _bounded_string(repository, label="repository", maximum=512)
    _bounded_string(repository_id, label="repository_id", maximum=256)
    _validate_sha256(guard_artifact_sha256, label="guard_artifact_sha256")
    raw = derive_raw_evaluation_bindings(
        base_repo=base_repo,
        head_repo=head_repo,
        base_sha=base_sha,
        head_sha=head_sha,
        base_tree_sha=base_tree_sha,
        head_tree_sha=head_tree_sha,
        base_is_bare=base_is_bare,
        head_is_bare=head_is_bare,
        git_executable=git_executable,
    )
    payload = {
        "format": FINALIZER_DERIVATION_FORMAT,
        "source": verified_source,
        "repository": repository,
        "repository_id": repository_id,
        "guard_artifact_sha256": guard_artifact_sha256,
        "base_tree_sha": base_tree_sha,
        "head_tree_sha": head_tree_sha,
        "candidate_sha256": raw["candidate_sha256"],
        "deleted_paths": raw["deleted_paths"],
        "policy_sha256": raw["policy_sha256"],
        "verifier_pack_sha256": raw["verifier_pack_sha256"],
        "verifier_pack_manifest": raw["verifier_pack_manifest"],
        "effective_policy": raw["effective_policy"],
    }
    return DerivedFinalizerBindings(payload=_validate_derived_bindings(payload))


def _validate_derived_bindings(value: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(value)
    if set(payload) != _BINDING_KEYS:
        raise FinalizerDerivationError("derived bindings have non-canonical keys")
    if payload.get("format") != FINALIZER_DERIVATION_FORMAT:
        raise FinalizerDerivationError("derived bindings have an unsupported format")
    source = payload.get("source")
    if not isinstance(source, dict):
        raise FinalizerDerivationError("derived bindings source must be an object")
    payload["source"] = _validate_source(source)
    _bounded_string(payload.get("repository"), label="repository", maximum=512)
    _bounded_string(payload.get("repository_id"), label="repository_id", maximum=256)
    _validate_sha256(payload.get("guard_artifact_sha256"), label="guard_artifact_sha256")
    for field in ("base_tree_sha", "head_tree_sha"):
        item = payload.get(field)
        if not isinstance(item, str) or _GIT_SHA.fullmatch(item) is None:
            raise FinalizerDerivationError(f"derived bindings {field} is invalid")
    _validate_sha256(payload.get("candidate_sha256"), label="candidate_sha256")
    deleted = payload.get("deleted_paths")
    if not isinstance(deleted, list) or any(
        not isinstance(path, str) or not is_safe_relpath(path) for path in deleted
    ):
        raise FinalizerDerivationError("derived bindings deleted_paths must be safe relative paths")
    if deleted != sorted(set(deleted)):
        raise FinalizerDerivationError("derived bindings deleted_paths must be sorted and unique")
    _validate_sha256(payload.get("policy_sha256"), label="policy_sha256")
    _validate_sha256(
        payload.get("verifier_pack_sha256"),
        label="verifier_pack_sha256",
        nullable=True,
    )
    policy = payload.get("effective_policy")
    if not isinstance(policy, dict):
        raise FinalizerDerivationError("derived bindings effective_policy must be an object")
    if effective_policy_sha256(policy) != payload["policy_sha256"]:
        raise FinalizerDerivationError("derived bindings policy digest is inconsistent")
    manifest = payload.get("verifier_pack_manifest")
    if manifest is not None:
        if not isinstance(manifest, dict):
            raise FinalizerDerivationError(
                "derived verifier-pack manifest must be an object or null"
            )
        problems = manifest_problems(manifest)
        if problems or extract_manifest(manifest) != manifest:
            raise FinalizerDerivationError("derived verifier-pack manifest is invalid")
    if payload["verifier_pack_sha256"] is None and manifest is not None:
        raise FinalizerDerivationError("a null verifier-pack digest cannot have a manifest")
    return payload


def validate_finalizer_bindings(value: Mapping[str, Any]) -> DerivedFinalizerBindings:
    """Validate an in-memory raw-Git derivation record."""

    return DerivedFinalizerBindings(payload=_validate_derived_bindings(value))


def read_finalizer_bindings(path: str) -> DerivedFinalizerBindings:
    """Read a canonical bindings file without treating it as a trust root."""

    try:
        data = _read_regular_file(path, limit=MAX_BINDINGS_BYTES, label="finalizer bindings")
        payload = _load_json_object(data, "finalizer bindings")
    except EvidenceBundleError as exc:
        raise FinalizerDerivationError(str(exc)) from exc
    if _canonical_json(payload) != data:
        raise FinalizerDerivationError("finalizer bindings are not canonical JSON")
    return validate_finalizer_bindings(payload)


def _write_canonical(path: str, payload: dict[str, Any], *, force: bool) -> str:
    absolute = os.path.abspath(path)
    if os.path.isdir(absolute):
        raise FinalizerDerivationError(f"output is a directory: {absolute}")
    data = _canonical_json(payload)
    parent = os.path.dirname(absolute) or os.curdir
    os.makedirs(parent, exist_ok=True)
    try:
        with open(absolute, "wb" if force else "xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise FinalizerDerivationError(
            f"refusing to overwrite existing output: {absolute}"
        ) from exc
    os.chmod(absolute, 0o644)
    return absolute


def write_finalizer_bindings(
    bindings: DerivedFinalizerBindings,
    *,
    bindings_path: str,
    force: bool = False,
) -> str:
    """Write the canonical raw-Git derivation record."""

    return _write_canonical(bindings_path, bindings.payload, force=force)


def _attestation(record: Mapping[str, Any]) -> Mapping[str, Any]:
    attestation = record.get("attestation")
    if not isinstance(attestation, dict):
        raise FinalizerDerivationError("verdict record has no attestation")
    return attestation


def context_from_verified_bindings(
    bindings: DerivedFinalizerBindings,
    record: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate raw-Git values, then form the existing source/context pair.

    A null verifier-pack value remains valid for a static Guard denial. A record
    that claims a pack result must match the independently derived base-tree
    pack digest and manifest exactly.
    """

    attestation = _attestation(record)
    if attestation.get("candidate_sha256") != bindings.candidate_sha256:
        raise FinalizerDerivationError("record candidate digest differs from raw-Git derivation")
    if attestation.get("deleted_paths") != list(bindings.deleted_paths):
        raise FinalizerDerivationError("record deleted paths differ from raw-Git derivation")
    if attestation.get("policy_sha256") != bindings.policy_sha256:
        raise FinalizerDerivationError("record policy digest differs from raw-Git derivation")
    if attestation.get("effective_policy") != bindings.effective_policy:
        raise FinalizerDerivationError("record effective policy differs from raw-Git derivation")
    record_pack = attestation.get("verifier_pack_sha256")
    if record_pack is not None and record_pack != bindings.verifier_pack_sha256:
        raise FinalizerDerivationError(
            "record verifier-pack digest differs from raw-Git derivation"
        )
    expected_manifest = (
        bindings.payload["verifier_pack_manifest"] if record_pack is not None else None
    )
    if attestation.get("verifier_pack_manifest") != expected_manifest:
        raise FinalizerDerivationError(
            "record verifier-pack manifest differs from raw-Git derivation"
        )
    for field in ("base_sha", "head_sha", "base_tree_sha", "head_tree_sha"):
        expected = (
            bindings.source[field] if field in {"base_sha", "head_sha"} else bindings.payload[field]
        )
        observed = attestation.get(field)
        if observed is not None and observed != expected:
            raise FinalizerDerivationError(f"record {field} differs from raw-Git derivation")
    source = bindings.source
    context = {
        "repository": bindings.payload["repository"],
        "repository_id": bindings.payload["repository_id"],
        "run_id": source["workflow_run_id"],
        "run_attempt": source["workflow_run_attempt"],
        "base_sha": source["base_sha"],
        "head_sha": source["head_sha"],
        "base_tree_sha": bindings.payload["base_tree_sha"],
        "head_tree_sha": bindings.payload["head_tree_sha"],
        "candidate_sha256": bindings.candidate_sha256,
        "policy_sha256": bindings.policy_sha256,
        "verifier_pack_sha256": record_pack,
        "guard_artifact_sha256": bindings.payload["guard_artifact_sha256"],
    }
    try:
        return source, validate_evidence_context(context, verdict=dict(record))
    except EvidenceBundleError as exc:
        raise FinalizerDerivationError(f"derived context does not bind verdict: {exc}") from exc


def write_verified_finalizer_context(
    bindings: DerivedFinalizerBindings,
    record: Mapping[str, Any],
    *,
    source_path: str,
    context_path: str,
    force: bool = False,
) -> tuple[str, str]:
    """Write source/context only after verdict values passed raw-Git comparison."""

    source, context = context_from_verified_bindings(bindings, record)
    source_out = _write_canonical(source_path, source, force=force)
    try:
        context_out = _write_canonical(context_path, context, force=force)
    except BaseException:
        try:
            os.unlink(source_out)
        except OSError:
            pass
        raise
    return source_out, context_out
