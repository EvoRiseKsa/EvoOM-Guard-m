"""Stable, bounded, non-link file I/O for retained conformance evidence."""

from __future__ import annotations

import os
import stat
from pathlib import Path

MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024


class ConformanceIOError(OSError):
    """A conformance input or output path violated the evidence contract."""


def _is_reparse(st: os.stat_result) -> bool:
    attributes = getattr(st, "st_file_attributes", 0)
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(marker and attributes & marker)


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
    )


def _same_snapshot(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        _same_file(left, right)
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_ctime_ns == right.st_ctime_ns
    )


def read_stable_regular_file(
    path: Path,
    *,
    label: str,
    max_bytes: int = MAX_EVIDENCE_BYTES,
) -> bytes:
    """Read exact bytes once while rejecting links, reparse points, and races."""

    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or _is_reparse(before):
        raise ConformanceIOError(f"{label} must not be a link or reparse point")
    if not stat.S_ISREG(before.st_mode):
        raise ConformanceIOError(f"{label} must be a regular file")
    if before.st_size > max_bytes:
        raise ConformanceIOError(f"{label} exceeds the {max_bytes}-byte limit")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or not _same_file(before, opened)
        ):
            raise ConformanceIOError(f"{label} changed before it was opened")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ConformanceIOError(f"{label} exceeds the {max_bytes}-byte limit")
        after = os.fstat(descriptor)
        if not _same_snapshot(opened, after) or total != after.st_size:
            raise ConformanceIOError(f"{label} changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def write_create_only_bytes(path: Path, payload: bytes) -> None:
    """Create one regular evidence file without replacing or following a target."""

    path.parent.mkdir(parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or _is_reparse(parent)
    ):
        raise ConformanceIOError("output parent must be a non-link directory")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    created_identity: os.stat_result | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        created_identity = os.fstat(descriptor)
        if not stat.S_ISREG(created_identity.st_mode) or _is_reparse(created_identity):
            raise ConformanceIOError("created output is not a regular file")
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        if created_identity is not None:
            try:
                current = path.lstat()
                if _same_file(created_identity, current) and stat.S_ISREG(current.st_mode):
                    path.unlink()
            except OSError:
                pass
        raise


__all__ = [
    "ConformanceIOError",
    "MAX_EVIDENCE_BYTES",
    "read_stable_regular_file",
    "write_create_only_bytes",
]
