# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Optional Ed25519 signing of Guard verdicts — tamper-evident evidence.

A Guard verdict is only as trustworthy as its storage: a JSON report sitting in
an artifact bucket can be edited after the fact. Signing closes that hole — the
judge (e.g. the CI job) holds an Ed25519 private key and emits a detached
signature next to the verdict; anyone holding the public key can verify,
offline, that the verdict bytes are exactly what the judge wrote.

What a signature does — and does not — prove:

  * it proves the verdict file was **not altered after signing**, and that it
    was signed by the holder of the private key;
  * it does **not** prove the run itself was honest — that trust comes from the
    key belonging to a judge you control (a CI secret, not the patch author).

The signature covers the **exact bytes of the verdict file** (no
canonicalization step to get subtly wrong), and is written as base64 to a
``<file>.sig`` sidecar.

This module is the integration point for signed-evidence pipelines (e.g.
feeding verdicts into an audit trail such as Sentinel AI's Merkle log — see
``docs/SIGNED_VERDICTS.md``). The core gate stays stdlib-only: ``cryptography``
is imported lazily and only needed if you actually sign or verify. Because
EvoGuard is not published on PyPI, add the extra to a source install or install
the dependency directly with ``python -m pip install "cryptography>=41"``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import stat
from dataclasses import dataclass
from typing import Any

_MAX_PRIVATE_KEY_BYTES = 64 * 1024
_MAX_PUBLIC_KEY_BYTES = 64 * 1024
_MAX_SIGNED_FILE_BYTES = 64 * 1024 * 1024
_MAX_SIGNATURE_SIDECAR_BYTES = 4 * 1024
_SIGNATURE_SIDECAR_MODE = 0o600
_MAX_CREATED_OUTPUT_CLOSE_ATTEMPTS = 2


class SigningUnavailableError(RuntimeError):
    """Raised when the optional ``cryptography`` dependency is not installed."""


class RetainedDescriptorCloseError(OSError):
    """A close error that explicitly owns only proven-safe descriptors.

    A descriptor number is never touched again after ``close()`` reports an
    error: POSIX permits that number to have been released and reused already.
    Recovery therefore operates only on a safe duplicate made *before* the
    failed close. ``descriptor_ownership_indeterminate`` records close attempts
    that may have left an unreachable descriptor open until process exit.

    ``release_retained_descriptors()`` is bounded and acts only on proven-safe
    duplicates. Its true result means that no such recoverable descriptor
    remains; it cannot resolve an already-indeterminate descriptor number.
    No recovery operation follows, truncates, or removes a pathname.
    """

    def __init__(
        self,
        message: str,
        *,
        descriptor_states: list[_CreatedKeyFile] | None = None,
    ) -> None:
        super().__init__(message)
        self._descriptor_states = list(descriptor_states or [])
        self._refresh_retained_descriptor_state()

    def _refresh_retained_descriptor_state(self) -> None:
        self._descriptor_states = [
            output
            for output in self._descriptor_states
            if (
                output.descriptor is not None
                or output.indeterminate_descriptor_count > 0
            )
        ]
        self.retained_descriptor_count = sum(
            output.descriptor is not None for output in self._descriptor_states
        )
        self.descriptor_retained = self.retained_descriptor_count > 0
        self.indeterminate_descriptor_count = sum(
            output.indeterminate_descriptor_count
            for output in self._descriptor_states
        )
        self.descriptor_ownership_indeterminate = (
            self.indeterminate_descriptor_count > 0
        )
        self.possible_descriptor_leak = self.descriptor_ownership_indeterminate
        self.process_exit_may_be_required = self.descriptor_ownership_indeterminate

    def release_retained_descriptors(self) -> bool:
        """Boundedly release every proven-safe descriptor still owned here."""

        for output in tuple(self._descriptor_states):
            if output.descriptor is not None:
                _release_created_output_descriptor(output)
        self._refresh_retained_descriptor_state()
        return not self.descriptor_retained

    def release_retained_descriptor(self) -> bool:
        """Singular convenience spelling for one-output errors."""

        return self.release_retained_descriptors()

    def _take_descriptor_states(self) -> list[_CreatedKeyFile]:
        """Transfer safe ownership and indeterminate-close state."""

        descriptor_states = self._descriptor_states
        self._descriptor_states = []
        self._refresh_retained_descriptor_state()
        return descriptor_states

    def _take_retained_outputs(self) -> list[_CreatedKeyFile]:
        """Compatibility spelling for transferring all descriptor state."""

        return self._take_descriptor_states()


class RetainedOutputCloseError(RetainedDescriptorCloseError):
    """A created-output close error with explicit descriptor state."""

    def __init__(
        self,
        message: str,
        *,
        retained_outputs: list[_CreatedKeyFile] | None = None,
    ) -> None:
        super().__init__(message, descriptor_states=retained_outputs)


class OutputReservationCloseError(RetainedOutputCloseError):
    """An exclusively-created output could not be validated and released."""

    def __init__(
        self,
        message: str,
        *,
        output_path: str,
        descriptor_state: str,
        retained_output: _CreatedKeyFile,
    ) -> None:
        super().__init__(message, retained_outputs=[retained_output])
        self.output_path = output_path
        self.descriptor_state = descriptor_state


class KeypairCloseError(RetainedOutputCloseError):
    """A keypair operation could not release every created descriptor cleanly.

    ``key_material_invalidated`` is true only when every created output that
    could contain key bytes was truncated and fsynced through its retained
    descriptor. When false, one or more outputs may contain live key bytes
    because invalidation could not be proven, whether failure occurred before or
    after the commit point; callers must inspect them explicitly.
    Cleanup never follows, truncates, or removes a final pathname.
    ``descriptor_retained`` refers only to a safe duplicate created before a
    close attempt. ``descriptor_ownership_indeterminate`` means a descriptor
    number whose close failed was abandoned without probing or retry and may
    remain open until process exit.
    """

    def __init__(
        self,
        message: str,
        *,
        key_material_invalidated: bool,
        retained_outputs: list[_CreatedKeyFile] | None = None,
    ) -> None:
        super().__init__(message, retained_outputs=retained_outputs)
        self.key_material_invalidated = key_material_invalidated


class SignatureSidecarCloseError(RetainedOutputCloseError):
    """A signature-sidecar descriptor could not be closed cleanly.

    ``sidecar_committed`` records that the exact sidecar bytes were file-fsynced,
    read back through the retained descriptor, and bound to the final path before
    the close was attempted. ``sidecar_invalidated`` is true only when those
    created bytes were subsequently truncated and fsynced through that same
    retained descriptor. The two values describe ordered events, so both can be
    true.

    ``descriptor_retained`` refers only to a safe duplicate made before a close
    attempt. In that rare state the caller must invoke
    :meth:`release_retained_descriptor` before discarding the exception.
    ``descriptor_ownership_indeterminate`` separately records failed close
    attempts whose descriptor numbers can never safely be retried and may remain
    open until process exit. Recovery never follows, truncates, or removes a
    pathname.
    """

    def __init__(
        self,
        message: str,
        *,
        sidecar_committed: bool,
        sidecar_invalidated: bool,
        descriptor_state: str,
        retained_output: _CreatedKeyFile | None = None,
    ) -> None:
        super().__init__(
            message,
            retained_outputs=(
                [retained_output] if retained_output is not None else None
            ),
        )
        self.sidecar_committed = sidecar_committed
        self.sidecar_invalidated = sidecar_invalidated
        self.descriptor_state = descriptor_state


class InputSnapshotCloseError(RetainedDescriptorCloseError):
    """An input snapshot could not release its descriptor unambiguously."""

    def __init__(
        self,
        message: str,
        *,
        input_path: str,
        descriptor_state: str,
        descriptor_owner: _CreatedKeyFile,
    ) -> None:
        super().__init__(message, descriptor_states=[descriptor_owner])
        self.input_path = input_path
        self.descriptor_state = descriptor_state


@dataclass(frozen=True)
class SigningKeySnapshot:
    """Opaque loaded key plus the identity derived from that exact object.

    Callers may inspect ``key_id`` and pass the snapshot to
    :func:`sign_bytes_with_snapshot`; the cryptographic key object itself is an
    implementation detail and is intentionally excluded from representation.
    """

    _key: Any
    key_id: str


# Private compatibility spelling retained for the existing flat envelope
# implementations and their monkeypatch seams.
_PrivateKeySnapshot = SigningKeySnapshot


def _crypto():
    """Lazily import the Ed25519 primitives (the ``sign`` extra)."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - exercised via the CLI tests
        raise SigningUnavailableError(
            "verdict signing needs the 'cryptography' package — "
            'install it with: python -m pip install "cryptography>=41"'
        ) from exc
    return ed25519, serialization


def _require_bytes(value: object, *, name: str) -> bytes:
    """Return ``value`` when it is bytes; reject ambiguous implicit coercions."""
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes, got {type(value).__name__}")
    return value


def _is_reparse_point(metadata: os.stat_result) -> bool:
    """Return whether Windows metadata names a link-like reparse point."""

    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _key_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Capture the metadata that must remain stable around one key read."""

    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(stat.S_IFMT(metadata.st_mode)),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _key_path_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Capture path/descriptor fields with consistent cross-platform meaning.

    Windows can report slightly different ``st_ctime_ns`` values for the same
    object through path and descriptor APIs, so creation/change time is used
    only for descriptor-before/after stability, not path binding.
    """

    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(stat.S_IFMT(metadata.st_mode)),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


@dataclass
class _CreatedKeyFile:
    """One exclusively-created output retained until its operation commits."""

    path: str
    descriptor: int | None
    may_contain_key_material: bool = False
    indeterminate_descriptor_count: int = 0


class _CreatedOutputCloseError(OSError):
    """Internal close failure with conservative descriptor state."""

    def __init__(
        self,
        path: str,
        *,
        descriptor_state: str,
        original: BaseException,
    ) -> None:
        super().__init__(
            f"descriptor close failed for {path} "
            f"(descriptor_state={descriptor_state}): {original}"
        )
        self.descriptor_state = descriptor_state
        self.original = original


def _open_exclusive_regular_output(
    path: str,
    mode: int,
    *,
    output_label: str,
    readable: bool = False,
) -> _CreatedKeyFile:
    """Reserve one regular output without following or replacing a path."""

    # Windows' CRT ``os.open(..., O_EXCL)`` can follow a dangling symlink and
    # create its target. Reject every already-named object before opening so a
    # static link/reparse point is never followed. ``O_EXCL`` below handles
    # ordinary creation collisions, but Windows has no portable no-follow
    # create primitive here. Callers therefore require a trusted, quiescent
    # parent directory for the unavoidable gap between these pathname checks.
    try:
        os.lstat(path)
    except FileNotFoundError:
        pass
    else:
        raise FileExistsError(
            f"refusing to overwrite an existing {output_label}: {path}"
        )

    flags = (
        (os.O_RDWR if readable else os.O_WRONLY)
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, mode)
    except FileExistsError as exc:
        raise FileExistsError(
            f"refusing to overwrite an existing {output_label}: {path}"
        ) from exc

    created = _CreatedKeyFile(
        path=path,
        descriptor=descriptor,
    )
    try:
        metadata = os.fstat(descriptor)
    except BaseException as primary:
        # The caller cannot own or release a descriptor when this helper never
        # returns. Close only the object just created; never inspect or modify
        # the final pathname during exception cleanup.
        close_error = _release_created_output_descriptor(created)
        if close_error is not None:
            raise OutputReservationCloseError(
                f"new {output_label} output metadata could not be inspected and "
                "descriptor release did not complete cleanly; never retry a "
                "descriptor number after close reports an error. Release any "
                "proven-safe backup exposed by this error before discarding it; "
                "indeterminate descriptors may remain open until process exit",
                output_path=path,
                descriptor_state=close_error.descriptor_state,
                retained_output=created,
            ) from primary
        raise
    if not stat.S_ISREG(metadata.st_mode) or _is_reparse_point(metadata):
        validation_error = OSError(
            f"new {output_label} output is not a regular file: {path}"
        )
        close_error = _release_created_output_descriptor(created)
        if close_error is not None:
            raise OutputReservationCloseError(
                f"new {output_label} output is not regular and descriptor "
                "release did not complete cleanly; release any proven-safe "
                "backup exposed by this error before discarding it; "
                "indeterminate descriptors may remain open until process exit",
                output_path=path,
                descriptor_state=close_error.descriptor_state,
                retained_output=created,
            ) from validation_error
        raise validation_error
    return created


def _open_exclusive_key_file(path: str, mode: int) -> _CreatedKeyFile:
    """Reserve one regular key output without following or replacing a path."""

    return _open_exclusive_regular_output(
        path,
        mode,
        output_label="key",
        readable=True,
    )


def _open_exclusive_signature_sidecar(path: str) -> _CreatedKeyFile:
    """Reserve a detached-signature sidecar without following or replacing it."""

    return _open_exclusive_regular_output(
        path,
        _SIGNATURE_SIDECAR_MODE,
        output_label="signature sidecar",
        readable=True,
    )


def _write_all(descriptor: int, payload: bytes) -> None:
    """Write every byte to an already reserved output descriptor."""

    view = memoryview(payload)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise OSError("output write made no progress")
        written += count


def _close_created_key_file(created: _CreatedKeyFile) -> None:
    """Close one descriptor without ever retrying a number after close errors.

    A safe duplicate is made before the first close attempt. If closing the
    original number fails, that number becomes permanently indeterminate and is
    never probed, truncated, or closed again; the pre-close duplicate remains
    the only recoverable owner. If closing the original succeeds, the duplicate
    is closed once without retry. A failure of that final close is likewise
    indeterminate and is never touched again.
    """

    if created.descriptor is None:
        return
    descriptor = created.descriptor
    try:
        safe_backup = os.dup(descriptor)
    except BaseException as duplicate_error:
        # No close was attempted, so the original descriptor is still a
        # proven-safe owner and may be retried by bounded recovery.
        raise _CreatedOutputCloseError(
            created.path,
            descriptor_state="retained-before-close",
            original=duplicate_error,
        ) from duplicate_error

    # From this point onward ``created.descriptor`` names only the safe backup.
    # The original integer is never stored or touched after its close attempt.
    created.descriptor = safe_backup
    try:
        os.close(descriptor)
    except BaseException as close_error:
        created.indeterminate_descriptor_count += 1
        raise _CreatedOutputCloseError(
            created.path,
            descriptor_state="indeterminate-after-close-error",
            original=close_error,
        ) from close_error

    # The original closed cleanly. The backup exists only to make the preceding
    # failure path safe, so close it exactly once. Clear the stored number before
    # the call: if close reports an error, it too may already have been reused.
    created.descriptor = None
    try:
        os.close(safe_backup)
    except BaseException as close_error:
        created.indeterminate_descriptor_count += 1
        raise _CreatedOutputCloseError(
            created.path,
            descriptor_state="indeterminate-after-backup-close-error",
            original=close_error,
        ) from close_error


def _release_created_output_descriptor(
    created: _CreatedKeyFile,
) -> _CreatedOutputCloseError | None:
    """Boundedly release an owned descriptor, retrying only proven retention.

    Retrying an ambiguous failed ``close`` is unsafe when another thread may
    already have reused its integer value. :func:`_close_created_key_file`
    instead advances ownership to a duplicate created before that close. Only
    that proven-safe duplicate may be retried here. Attempts are bounded so a
    persistently failing runtime cannot hang the process.

    The last close error is returned for diagnostics. An indeterminate number
    is never stored, probed, or retried.
    """

    last_error: _CreatedOutputCloseError | None = None
    attempts = 0
    while (
        created.descriptor is not None
        and attempts < _MAX_CREATED_OUTPUT_CLOSE_ATTEMPTS
    ):
        attempts += 1
        try:
            _close_created_key_file(created)
        except _CreatedOutputCloseError as close_error:
            last_error = close_error
            if (
                created.descriptor is None
                or not isinstance(close_error.original, OSError)
            ):
                break
        else:
            if created.indeterminate_descriptor_count == 0:
                last_error = None
            break
    return last_error


def _invalidate_and_close_created_key_files(
    created: list[_CreatedKeyFile],
) -> bool:
    """Invalidate every still-bound output, then best-effort close descriptors.

    The return value proves full invalidation only when every output that may
    contain key material still had its exact descriptor and was durably
    truncated. Pathnames are never used for cleanup.
    """

    invalidation_results = [
        _invalidate_created_key_file(output) for output in created
    ]
    invalidation_proven = all(invalidation_results)
    for output in created:
        _release_created_output_descriptor(output)
    return invalidation_proven


def _invalidate_created_key_file(created: _CreatedKeyFile) -> bool:
    """Erase key bytes through the exact descriptor without touching its path.

    Portable filesystems provide no atomic "unlink this name only if it still
    identifies my inode" operation. Failure cleanup therefore never unlinks a
    final path: it truncates only the retained descriptor and leaves a
    zero-length reservation for explicit operator inspection/removal.
    """

    if not created.may_contain_key_material:
        return True
    if created.descriptor is None:
        return False
    try:
        os.ftruncate(created.descriptor, 0)
        os.fsync(created.descriptor)
    except OSError:
        # Never fall back to a path-based truncate or unlink that could target
        # a concurrent swap. The caller makes failed invalidation authoritative.
        return False
    created.may_contain_key_material = False
    return True


def _sync_and_require_created_key_file_bound(
    created: _CreatedKeyFile,
    *,
    expected_payload: bytes,
    key_label: str,
) -> None:
    """Flush, read back, and bind one exact key output to its final name.

    ``O_EXCL`` protects only the instant of creation. On filesystems that permit
    renaming an open file, another actor could otherwise move that object and
    replace its pathname or rewrite the same inode before key generation reports
    success. Keep the read/write descriptor open through ``fsync``, read back
    the exact expected bytes through that descriptor, and compare the final path
    to the same stable object. A mismatch is handled by descriptor-only
    invalidation; this helper never truncates or removes the pathname that won
    the race.
    """

    descriptor = created.descriptor
    if descriptor is None:
        raise OSError(f"{key_label} descriptor closed before commit: {created.path}")

    os.fsync(descriptor)
    before_read = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before_read.st_mode)
        or _is_reparse_point(before_read)
        or before_read.st_nlink != 1
        or before_read.st_size != len(expected_payload)
    ):
        raise OSError(
            f"{key_label} content changed while it was being written: {created.path}"
        )

    observed = _read_created_output_from_start(
        descriptor,
        len(expected_payload),
    )
    after_read = os.fstat(descriptor)
    if (
        _key_file_identity(after_read) != _key_file_identity(before_read)
        or after_read.st_nlink != 1
        or observed != expected_payload
    ):
        raise OSError(
            f"{key_label} content changed while it was being written: {created.path}"
        )

    try:
        at_path = os.lstat(created.path)
    except OSError as exc:
        raise OSError(
            f"{key_label} path changed while it was being written: {created.path}"
        ) from exc
    final_descriptor = os.fstat(descriptor)
    if (
        _key_file_identity(final_descriptor) != _key_file_identity(after_read)
        or final_descriptor.st_nlink != 1
    ):
        raise OSError(
            f"{key_label} content changed while it was being written: {created.path}"
        )
    if (
        stat.S_ISLNK(at_path.st_mode)
        or _is_reparse_point(at_path)
        or not stat.S_ISREG(at_path.st_mode)
        or at_path.st_nlink != 1
        or _key_path_identity(at_path) != _key_path_identity(final_descriptor)
    ):
        raise OSError(
            f"{key_label} path changed while it was being written: {created.path}"
        )


def _read_created_output_from_start(descriptor: int, max_bytes: int) -> bytes:
    """Read at most ``max_bytes + 1`` bytes from one retained output descriptor."""

    os.lseek(descriptor, 0, os.SEEK_SET)
    observed = bytearray()
    while len(observed) <= max_bytes:
        remaining = max_bytes + 1 - len(observed)
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        observed.extend(chunk)
    return bytes(observed)


def _sync_and_require_created_signature_sidecar_bound(
    created: _CreatedKeyFile,
    payload: bytes,
) -> None:
    """Flush, read back, and path-bind the exact created sidecar bytes.

    The content check uses the same descriptor that performed the write. Stable
    descriptor metadata is checked around that read-back and once more after the
    final-path observation. This detects same-inode writes that a path-identity
    comparison alone cannot detect. No portable pathname API can remove the
    remaining race after the final descriptor/path check; callers still require
    a trusted, quiescent parent directory.
    """

    descriptor = created.descriptor
    if descriptor is None:
        raise OSError(f"signature sidecar descriptor closed before commit: {created.path}")

    os.fsync(descriptor)
    before_read = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before_read.st_mode)
        or _is_reparse_point(before_read)
        or before_read.st_nlink != 1
        or before_read.st_size != len(payload)
    ):
        raise OSError(
            f"signature sidecar content changed while it was being written: {created.path}"
        )

    observed = _read_created_output_from_start(descriptor, len(payload))
    after_read = os.fstat(descriptor)
    if (
        _key_file_identity(after_read) != _key_file_identity(before_read)
        or after_read.st_nlink != 1
        or observed != payload
    ):
        raise OSError(
            f"signature sidecar content changed while it was being written: {created.path}"
        )

    try:
        at_path = os.lstat(created.path)
    except OSError as exc:
        raise OSError(
            f"signature sidecar path changed while it was being written: {created.path}"
        ) from exc

    final_descriptor = os.fstat(descriptor)
    if (
        _key_file_identity(final_descriptor) != _key_file_identity(after_read)
        or final_descriptor.st_nlink != 1
    ):
        raise OSError(
            f"signature sidecar content changed while it was being written: {created.path}"
        )
    if (
        stat.S_ISLNK(at_path.st_mode)
        or _is_reparse_point(at_path)
        or not stat.S_ISREG(at_path.st_mode)
        or at_path.st_nlink != 1
        or _key_path_identity(at_path) != _key_path_identity(final_descriptor)
    ):
        raise OSError(
            f"signature sidecar path changed while it was being written: {created.path}"
        )


def _invalidate_created_signature_sidecar(created: _CreatedKeyFile) -> bool:
    """Durably truncate only the exact retained sidecar descriptor."""

    if created.descriptor is None:
        return False
    try:
        os.ftruncate(created.descriptor, 0)
        os.fsync(created.descriptor)
    except OSError:
        return False
    return True


def _write_signature_sidecar(path: str, payload: bytes) -> None:
    """Create and commit one exact, exclusively-created signature sidecar.

    Commit requires file ``fsync``, exact same-descriptor content read-back, and
    final-path binding. A post-commit close error raises
    :class:`SignatureSidecarCloseError`, whose public state distinguishes a
    committed live sidecar from one invalidated through a retained descriptor.
    No cleanup follows a pathname, and a race remains after the final check.
    """

    try:
        created = _open_exclusive_signature_sidecar(path)
    except OutputReservationCloseError as reservation_error:
        descriptor_states = reservation_error._take_descriptor_states()
        retained_output = descriptor_states[0] if descriptor_states else None
        raise SignatureSidecarCloseError(
            "signature sidecar reservation failed before commit and descriptor "
            "release did not complete cleanly; release any proven-safe backup "
            "before discarding this error. An indeterminate descriptor may "
            "remain open until process exit",
            sidecar_committed=False,
            sidecar_invalidated=False,
            descriptor_state=reservation_error.descriptor_state,
            retained_output=retained_output,
        ) from reservation_error
    assert created.descriptor is not None
    try:
        _write_all(created.descriptor, payload)
        _sync_and_require_created_signature_sidecar_bound(created, payload)
    except BaseException as primary:
        invalidated = False
        try:
            invalidated = _invalidate_created_signature_sidecar(created)
        finally:
            close_error = _release_created_output_descriptor(created)
        if close_error is not None:
            raise SignatureSidecarCloseError(
                "signature sidecar failed before commit and descriptor release "
                "did not complete cleanly; no descriptor number was retried "
                "after close reported an error. Release any proven-safe backup "
                "before discarding this error; an indeterminate descriptor may "
                "remain open until process exit",
                sidecar_committed=False,
                sidecar_invalidated=invalidated,
                descriptor_state=close_error.descriptor_state,
                retained_output=created,
            ) from primary
        raise

    try:
        _close_created_key_file(created)
    except _CreatedOutputCloseError as close_error:
        invalidated = False
        try:
            if created.descriptor is not None:
                invalidated = _invalidate_created_signature_sidecar(created)
        finally:
            _release_created_output_descriptor(created)

        descriptor_retained = created.descriptor is not None
        descriptor_indeterminate = created.indeterminate_descriptor_count > 0
        if invalidated:
            message = (
                "signature sidecar reached its file-fsync, exact-content, and "
                "path-binding commit point, but descriptor close failed before "
                "release; the created sidecar bytes were invalidated through "
                "a safe pre-close duplicate and a zero-length reservation may remain"
            )
        else:
            message = (
                "signature sidecar reached its file-fsync, exact-content, and "
                "path-binding commit point, but descriptor close failed after "
                "release, became unidentifiable, or could not be invalidated; "
                "treat the final path as a committed or indeterminate live "
                "sidecar and inspect it explicitly before retrying"
            )
        if descriptor_retained:
            message += (
                "; a proven-safe backup descriptor remains, so call "
                "release_retained_descriptor() before discarding this error"
            )
        if descriptor_indeterminate:
            message += (
                "; one or more failed close attempts left descriptor ownership "
                "indeterminate and may require process exit for full release"
            )
        raise SignatureSidecarCloseError(
            message,
            sidecar_committed=True,
            sidecar_invalidated=invalidated,
            descriptor_state=close_error.descriptor_state,
            retained_output=(
                created
                if descriptor_retained or descriptor_indeterminate
                else None
            ),
        ) from close_error


def _read_key_snapshot(
    key_path: str,
    *,
    key_label: str,
    max_bytes: int,
) -> bytes:
    """Read one bounded, stable, regular non-link file snapshot.

    The descriptor is opened once and retained through the read. Path and
    descriptor metadata are compared before and after the bounded read so a
    concurrent replacement, truncation, extension, or in-place rewrite fails
    closed. The historical helper name remains because keys were its first
    consumers; file signing and verification use the same snapshot contract.
    """

    try:
        before_path = os.lstat(key_path)
    except OSError:
        # Preserve the path-based API's historical FileNotFoundError and
        # PermissionError behavior for an input that cannot be inspected.
        raise
    if (
        stat.S_ISLNK(before_path.st_mode)
        or _is_reparse_point(before_path)
        or not stat.S_ISREG(before_path.st_mode)
    ):
        raise ValueError(f"{key_label} must be a regular non-symlink file: {key_path}")
    if before_path.st_size > max_bytes:
        raise ValueError(f"{key_label} exceeds the {max_bytes}-byte limit: {key_path}")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(key_path, flags)
    except OSError as exc:
        raise ValueError(f"unable to open {key_label} safely: {key_path}") from exc

    descriptor_owner = _CreatedKeyFile(
        path=key_path,
        descriptor=descriptor,
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse_point(opened)
            or _key_path_identity(opened) != _key_path_identity(before_path)
        ):
            raise ValueError(f"{key_label} changed while it was being opened: {key_path}")
        if opened.st_size > max_bytes:
            raise ValueError(f"{key_label} exceeds the {max_bytes}-byte limit: {key_path}")

        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            pem = handle.read(max_bytes + 1)

        after_descriptor = os.fstat(descriptor)
        if _key_file_identity(after_descriptor) != _key_file_identity(opened):
            raise ValueError(f"{key_label} changed while it was being read: {key_path}")
        if len(pem) > max_bytes:
            raise ValueError(
                f"{key_label} exceeded the {max_bytes}-byte limit while reading: {key_path}"
            )
        if len(pem) != opened.st_size:
            raise ValueError(f"{key_label} size changed while it was being read: {key_path}")

        try:
            after_path = os.lstat(key_path)
        except OSError as exc:
            raise ValueError(
                f"{key_label} path changed while it was being read: {key_path}"
            ) from exc
        if (
            stat.S_ISLNK(after_path.st_mode)
            or _is_reparse_point(after_path)
            or _key_path_identity(after_path) != _key_path_identity(opened)
        ):
            raise ValueError(f"{key_label} path changed while it was being read: {key_path}")
    except BaseException as primary:
        close_error = _release_created_output_descriptor(descriptor_owner)
        if close_error is not None:
            raise InputSnapshotCloseError(
                f"{key_label} snapshot failed and its descriptor did not close "
                "cleanly; no descriptor number was retried after close reported "
                "an error. Release any proven-safe backup exposed by this error; "
                "a possible descriptor leak may remain until process exit",
                input_path=key_path,
                descriptor_state=close_error.descriptor_state,
                descriptor_owner=descriptor_owner,
            ) from primary
        raise

    close_error = _release_created_output_descriptor(descriptor_owner)
    if close_error is not None:
        raise InputSnapshotCloseError(
            f"{key_label} snapshot was read successfully, but its descriptor "
            "did not close cleanly; no descriptor number was retried after "
            "close reported an error. Release any proven-safe backup exposed "
            "by this error; a possible descriptor leak may remain until process "
            "exit",
            input_path=key_path,
            descriptor_state=close_error.descriptor_state,
            descriptor_owner=descriptor_owner,
        ) from close_error
    return pem


def _read_private_key_snapshot(private_key_path: str) -> bytes:
    """Read one bounded, stable, regular non-link private-key snapshot."""

    return _read_key_snapshot(
        private_key_path,
        key_label="private key",
        max_bytes=_MAX_PRIVATE_KEY_BYTES,
    )


def _read_public_key_snapshot(public_key_path: str) -> bytes:
    """Read one bounded, stable, regular non-link public-key snapshot."""

    return _read_key_snapshot(
        public_key_path,
        key_label="public key",
        max_bytes=_MAX_PUBLIC_KEY_BYTES,
    )


def _load_private_key(private_key_path: str):
    """Load an unencrypted PEM Ed25519 private key with stable diagnostics."""
    ed25519, serialization = _crypto()
    pem = _read_private_key_snapshot(private_key_path)
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"unable to load an unencrypted PEM private key: {private_key_path}"
        ) from exc
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError(f"not an Ed25519 private key: {private_key_path}")
    return key


def _load_private_key_snapshot(private_key_path: str) -> _PrivateKeySnapshot:
    """Load a signing key once for a multi-step, identity-bound operation.

    Callers that must place ``key_id`` inside the bytes they sign cannot safely
    derive the ID and sign through two independent path opens: the file may be
    rotated between them.  This opaque snapshot keeps both operations bound to
    one loaded key object.
    """

    key = _load_private_key(private_key_path)
    return _PrivateKeySnapshot(_key=key, key_id=_key_id(key.public_key()))


def load_signing_key_snapshot(private_key_path: str) -> SigningKeySnapshot:
    """Load one opaque key snapshot for an identity-bound signing operation."""

    return _load_private_key_snapshot(private_key_path)


def _load_public_key(public_key_path: str):
    """Load a PEM Ed25519 public key with stable diagnostics."""
    ed25519, serialization = _crypto()
    pem = _read_public_key_snapshot(public_key_path)
    try:
        key = serialization.load_pem_public_key(pem)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"unable to load a PEM public key: {public_key_path}") from exc
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError(f"not an Ed25519 public key: {public_key_path}")
    return key


def _public_key_der(key) -> bytes:
    """Serialize an Ed25519 public key as canonical DER SubjectPublicKeyInfo."""
    _ed25519, serialization = _crypto()
    return key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _key_id(key) -> str:
    """Return the stable content identity of a public key."""
    return "sha256:" + hashlib.sha256(_public_key_der(key)).hexdigest()


def generate_keypair(private_path: str, public_path: str) -> None:
    """Generate an Ed25519 keypair as PEM files (private: PKCS8, public: SPKI).

    Creation requests POSIX mode ``0600`` for the private key, but mode bits are
    only a best-effort portability control. In particular, they do not install
    a restrictive Windows DACL; operators must protect the key with an
    appropriate ACL or secret store. Keep it as a CI secret — it *is* the
    judge's identity. Refuses to overwrite an existing file. If the two-file
    operation fails before the commit point, including a final-path swap,
    cleanup attempts to invalidate key bytes through retained descriptors.
    The commit point is reached only after both contents are file-fsynced and
    both final paths are rebound to their retained descriptors.

    The output parent directories must be trusted and quiescent. In particular,
    Windows provides no portable atomic create-without-following primitive here;
    the pre-open name check prevents following a static dangling reparse path,
    but does not claim safety against a concurrent parent-directory writer.

    A descriptor close error after that point has an explicit state contract.
    A safe duplicate is made before close, so key bytes can be
    descriptor-truncated and fsynced without ever retrying an ambiguous
    descriptor number before
    :class:`KeypairCloseError` is raised with
    ``key_material_invalidated=True``. If invalidation through a safe descriptor
    cannot be proven, no pathname is touched and the exception carries
    ``key_material_invalidated=False``; treat the outputs as a committed live
    keypair until inspected. Cleanup never performs a path-based truncate or
    unlink. ``descriptor_retained`` exposes only safe pre-close duplicates;
    ``descriptor_ownership_indeterminate`` warns that failed close attempts may
    have leaked descriptors until process exit.
    """
    ed25519, serialization = _crypto()
    key = ed25519.Ed25519PrivateKey.generate()
    priv = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    created: list[_CreatedKeyFile] = []
    try:
        # Reserve both final names before writing either payload. The helper
        # rejects existing names, including static dangling/reparse paths, and
        # uses O_EXCL for ordinary creation collisions. Its documented trusted,
        # quiescent-parent boundary applies across both reservations.
        created.append(_open_exclusive_key_file(private_path, 0o600))
        created.append(_open_exclusive_key_file(public_path, 0o644))
        assert created[0].descriptor is not None
        assert created[1].descriptor is not None
        created[0].may_contain_key_material = True
        _write_all(created[0].descriptor, priv)
        created[1].may_contain_key_material = True
        _write_all(created[1].descriptor, pub)
        _sync_and_require_created_key_file_bound(
            created[0],
            expected_payload=priv,
            key_label="private key",
        )
        _sync_and_require_created_key_file_bound(
            created[1],
            expected_payload=pub,
            key_label="public key",
        )
    except BaseException as primary:
        invalidation_proven = _invalidate_and_close_created_key_files(created)
        descriptor_states = [
            output
            for output in created
            if (
                output.descriptor is not None
                or output.indeterminate_descriptor_count > 0
            )
        ]
        if isinstance(primary, RetainedOutputCloseError):
            descriptor_states.extend(primary._take_descriptor_states())
        if descriptor_states:
            raise KeypairCloseError(
                "key generation failed before commit and descriptor release did "
                "not complete cleanly; no descriptor number was retried after "
                "close reported an error. Release any proven-safe backups before "
                "discarding this error; indeterminate descriptors may remain "
                "open until process exit",
                key_material_invalidated=invalidation_proven,
                retained_outputs=descriptor_states,
            ) from primary
        if not invalidation_proven:
            raise OSError(
                "key generation failed and key-output invalidation "
                "could not be proven"
            ) from primary
        raise

    for output in created:
        try:
            _close_created_key_file(output)
        except _CreatedOutputCloseError as close_error:
            invalidation_proven = _invalidate_and_close_created_key_files(created)
            descriptor_states = [
                created_output
                for created_output in created
                if (
                    created_output.descriptor is not None
                    or created_output.indeterminate_descriptor_count > 0
                )
            ]
            retained_message = (
                "; proven-safe backup descriptors remain, so call "
                "release_retained_descriptors() before discarding this error"
                if any(
                    created_output.descriptor is not None
                    for created_output in descriptor_states
                )
                else ""
            )
            indeterminate_message = (
                "; failed close attempts left descriptor ownership indeterminate "
                "and may require process exit for full release"
                if any(
                    created_output.indeterminate_descriptor_count > 0
                    for created_output in descriptor_states
                )
                else ""
            )
            if invalidation_proven:
                raise KeypairCloseError(
                    "keypair reached its file-fsync and path-binding commit "
                    "point, but descriptor close failed before release; all "
                    "key bytes were invalidated through retained descriptors "
                    "and zero-length reservations may remain"
                    + retained_message
                    + indeterminate_message,
                    key_material_invalidated=True,
                    retained_outputs=descriptor_states,
                ) from close_error
            raise KeypairCloseError(
                "keypair reached its file-fsync and path-binding commit point, "
                "but descriptor close failed after an output descriptor was "
                "released or became unidentifiable; one or more outputs may "
                "contain committed key bytes. No pathname cleanup was "
                "attempted; treat every output as live key material and "
                "inspect it explicitly before retrying"
                + retained_message
                + indeterminate_message,
                key_material_invalidated=False,
                retained_outputs=descriptor_states,
            ) from close_error


def sign_bytes(payload: bytes, private_key_path: str) -> bytes:
    """Return a raw 64-byte Ed25519 signature of ``payload``.

    ``payload`` must already be the exact byte representation the caller wants
    authenticated. This function performs no text encoding or canonicalization.
    The key must be an unencrypted PEM Ed25519 private key.
    """
    signature, _key_id_value = sign_bytes_with_key_id(payload, private_key_path)
    return signature


def sign_bytes_with_key_id(
    payload: bytes,
    private_key_path: str,
) -> tuple[bytes, str]:
    """Sign bytes and derive the public-key ID from the same path snapshot."""

    return _sign_bytes_with_key_id(payload, private_key_path)


def _sign_bytes_with_key_id(
    payload: bytes,
    private_key: str | _PrivateKeySnapshot,
) -> tuple[bytes, str]:
    """Internal multi-step signer accepting an already loaded key snapshot.

    The public API remains path-based. Evidence-envelope construction uses this
    helper so the key ID embedded in its payload and the signature come from one
    private-key load without exposing the opaque snapshot type publicly.
    """

    payload = _require_bytes(payload, name="payload")
    snapshot = (
        _load_private_key_snapshot(private_key) if isinstance(private_key, str) else private_key
    )
    return snapshot._key.sign(payload), snapshot.key_id


def sign_bytes_with_snapshot(
    payload: bytes,
    signing_key: SigningKeySnapshot,
) -> tuple[bytes, str]:
    """Sign exact bytes with a previously loaded identity-bound key snapshot."""

    if type(signing_key) is not _PrivateKeySnapshot:
        raise TypeError("signing_key must be a key snapshot returned by load_signing_key_snapshot")
    return _sign_bytes_with_key_id(payload, signing_key)


def verify_bytes(payload: bytes, signature: bytes, public_key_path: str) -> bool:
    """Return whether a raw Ed25519 ``signature`` authenticates ``payload``.

    A cryptographically invalid signature, including a raw value of the wrong
    length, returns ``False``. Malformed API inputs or an unusable/non-Ed25519
    public key raise a clear exception instead of being mistaken for a verdict.
    """
    verified, _key_id_value = verify_bytes_with_key_id(payload, signature, public_key_path)
    return verified


def verify_bytes_with_key_id(
    payload: bytes,
    signature: bytes,
    public_key_path: str,
) -> tuple[bool, str]:
    """Verify bytes and derive the trusted key ID from one public-key snapshot."""

    payload = _require_bytes(payload, name="payload")
    signature = _require_bytes(signature, name="signature")
    key = _load_public_key(public_key_path)
    key_id = _key_id(key)
    if len(signature) != 64:
        return False, key_id

    from cryptography.exceptions import InvalidSignature

    try:
        key.verify(signature, payload)
        return True, key_id
    except InvalidSignature:
        return False, key_id
    except Exception as exc:
        # Reloading cryptography's process-resident extension can leave its
        # live InvalidSignature class distinct from the freshly imported
        # Python wrapper class. Preserve the public "invalid => False"
        # contract while allowing every other verification error to surface.
        if (
            type(exc).__name__ == "InvalidSignature"
            and type(exc).__module__ == "cryptography.exceptions"
        ):
            return False, key_id
        raise


def public_key_id(public_key_path: str) -> str:
    """Return ``sha256:<hex>`` over the public key's DER SPKI encoding."""
    return _key_id(_load_public_key(public_key_path))


def private_key_public_id(private_key_path: str) -> str:
    """Return the public-key ID corresponding to an Ed25519 private key."""
    return _key_id(_load_private_key(private_key_path).public_key())


def sign_file(path: str, private_key_path: str) -> str:
    """Sign the exact bytes of ``path``; write base64 to ``<path>.sig``.

    Returns the sidecar path. The signature is a detached Ed25519 signature of
    one bounded, stable, regular non-link snapshot of the file — byte-for-byte,
    with no canonicalization. The sidecar is exclusively created, fsynced,
    read back through its writing descriptor, and never replaces or truncates
    an existing path. A sidecar descriptor-close failure raises
    :class:`SignatureSidecarCloseError`; its attributes state whether commit was
    reached, whether the created bytes were subsequently invalidated, and
    whether bounded close attempts left an exact retained descriptor whose
    ownership the caller must release explicitly.

    These checks detect changes observed through the final descriptor/path
    comparison. They cannot eliminate a later pathname race, so the signed file
    and sidecar parent must remain trusted and quiescent for the operation.
    """
    payload = _read_key_snapshot(
        path,
        key_label="signed file",
        max_bytes=_MAX_SIGNED_FILE_BYTES,
    )
    sig_path = path + ".sig"
    encoded_signature = base64.b64encode(
        sign_bytes(payload, private_key_path)
    ) + b"\n"
    _write_signature_sidecar(sig_path, encoded_signature)
    return sig_path


def verify_file(path: str, sig_path: str, public_key_path: str) -> bool:
    """True iff ``sig_path`` is a valid signature of ``path`` under the key.

    Never raises on an *invalid* signature — that is the ``False`` return; it
    does raise on unusable inputs (missing, linked, non-regular, changing, or
    oversized files; a non-Ed25519 key; or undecodable base64), which are caller
    errors rather than verdicts.
    """
    payload = _read_key_snapshot(
        path,
        key_label="signed file",
        max_bytes=_MAX_SIGNED_FILE_BYTES,
    )
    encoded = _read_key_snapshot(
        sig_path,
        key_label="signature sidecar",
        max_bytes=_MAX_SIGNATURE_SIDECAR_BYTES,
    ).strip()
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"invalid base64 signature: {sig_path}") from exc
    return verify_bytes(payload, signature, public_key_path)
