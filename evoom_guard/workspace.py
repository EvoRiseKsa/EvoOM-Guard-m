# ---------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ---------------------------------------------------------------------------
"""Shared containment primitives for judge-owned throwaway workspaces."""

from __future__ import annotations

import contextlib
import os
import secrets
import shutil
import stat
import tempfile
from collections.abc import Iterator


class UnsafeWorkspacePath(ValueError):
    """A requested workspace operation would escape its judge-owned root."""


def _is_safe_relative_path(path: str) -> bool:
    if not path or os.path.isabs(path) or "\\" in path:
        return False
    return all(part not in ("", ".", "..") for part in path.split("/"))


def _is_within(root: str, path: str) -> bool:
    try:
        common = os.path.commonpath((root, path))
    except ValueError:
        return False
    return os.path.normcase(common) == os.path.normcase(root)


_DIR_FD_FUNCTIONS = (os.open, os.mkdir, os.stat, os.unlink, os.rmdir, os.rename)
_HAS_DESCRIPTOR_RELATIVE = (
    os.name == "posix"
    and hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
    and all(function in os.supports_dir_fd for function in _DIR_FD_FUNCTIONS)
    and os.listdir in os.supports_fd
)


def _require_posix_descriptor_support() -> None:
    if os.name == "posix" and not _HAS_DESCRIPTOR_RELATIVE:
        raise UnsafeWorkspacePath(
            "this POSIX runtime lacks the descriptor-relative/no-follow operations "
            "required for atomic workspace containment"
        )


def _object_identity(info: os.stat_result) -> tuple[int, int, int]:
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))


def _stable_file_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


@contextlib.contextmanager
def _open_parent_dir_fd(
    root: str, relative_path: str, *, create: bool
) -> Iterator[tuple[int, int, str, tuple[str, ...]]]:
    """Open a path's parent from ``root`` without following any POSIX symlink."""
    if not _HAS_DESCRIPTOR_RELATIVE:
        raise NotImplementedError("descriptor-relative traversal requires POSIX")
    if not _is_safe_relative_path(relative_path):
        raise UnsafeWorkspacePath(
            f"unsafe workspace path is not normalized: {relative_path!r}"
        )

    components = tuple(relative_path.split("/"))
    parent_components = components[:-1]
    flags = _directory_open_flags()
    root_before = os.lstat(root)
    if not stat.S_ISDIR(root_before.st_mode):
        raise UnsafeWorkspacePath("workspace root is not a real directory")
    root_fd = os.open(root, flags)
    parent_fd = root_fd
    try:
        if not (
            _object_identity(root_before) == _object_identity(os.fstat(root_fd))
            == _object_identity(os.lstat(root))
        ):
            raise UnsafeWorkspacePath(
                "workspace root changed while it was being opened"
            )
        for component in parent_components:
            if create:
                try:
                    os.mkdir(component, 0o777, dir_fd=parent_fd)
                except FileExistsError:
                    pass
            next_fd = os.open(component, flags, dir_fd=parent_fd)
            if parent_fd != root_fd:
                os.close(parent_fd)
            parent_fd = next_fd
        yield root_fd, parent_fd, components[-1], parent_components
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise UnsafeWorkspacePath(
            f"workspace path changed or traverses a symlink: {relative_path!r} ({exc})"
        ) from exc
    finally:
        if parent_fd != root_fd:
            os.close(parent_fd)
        os.close(root_fd)


def _reopen_parent(root_fd: int, components: tuple[str, ...]) -> int:
    current = os.dup(root_fd)
    flags = _directory_open_flags()
    try:
        for component in components:
            next_fd = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = next_fd
        return current
    except BaseException:
        os.close(current)
        raise


def _verify_parent_still_bound(
    root: str, root_fd: int, parent_fd: int, components: tuple[str, ...]
) -> None:
    try:
        current_root = os.lstat(root)
    except OSError as exc:
        raise UnsafeWorkspacePath(
            "workspace root changed while a protected operation was running"
        ) from exc
    if _object_identity(current_root) != _object_identity(os.fstat(root_fd)):
        raise UnsafeWorkspacePath(
            "workspace root changed while a protected operation was running"
        )
    try:
        reopened = _reopen_parent(root_fd, components)
    except OSError as exc:
        raise UnsafeWorkspacePath(
            "workspace parent changed while a protected operation was running"
        ) from exc
    try:
        if _object_identity(os.fstat(parent_fd)) != _object_identity(os.fstat(reopened)):
            raise UnsafeWorkspacePath(
                "workspace parent changed while a protected operation was running"
            )
    finally:
        os.close(reopened)


def _best_effort_target(
    root: str, relative_path: str, *, create: bool
) -> tuple[str, str, os.stat_result, os.stat_result]:
    """Windows fallback: reject reparse parents and capture parent identity.

    This is intentionally a best-effort check, not an atomic containment claim;
    Python's stdlib exposes no Windows equivalent of ``openat``/``unlinkat``.
    """
    if not _is_safe_relative_path(relative_path):
        raise UnsafeWorkspacePath(
            f"unsafe workspace path is not normalized: {relative_path!r}"
        )
    root_before = os.lstat(root)
    is_junction = getattr(os.path, "isjunction", lambda _path: False)
    if (
        not stat.S_ISDIR(root_before.st_mode)
        or os.path.islink(root)
        or is_junction(root)
    ):
        raise UnsafeWorkspacePath("workspace root is a symlink, junction, or non-directory")
    real_root = os.path.realpath(root)
    cursor = root
    for component in relative_path.split("/")[:-1]:
        cursor = os.path.join(cursor, component)
        if not os.path.lexists(cursor):
            if not create:
                raise FileNotFoundError(cursor)
            os.mkdir(cursor)
        if os.path.islink(cursor) or is_junction(cursor):
            raise UnsafeWorkspacePath(
                f"workspace path traverses a reparse/symlink parent: {relative_path!r}"
            )
        if not os.path.isdir(cursor):
            raise UnsafeWorkspacePath(
                f"workspace parent is not a directory: {relative_path!r}"
            )
    parent = cursor
    if not _is_within(real_root, os.path.realpath(parent)):
        raise UnsafeWorkspacePath(
            f"workspace path escapes its root: {relative_path!r}"
        )
    root_after = os.lstat(root)
    if (
        _object_identity(root_before) != _object_identity(root_after)
        or not stat.S_ISDIR(root_after.st_mode)
        or os.path.islink(root)
        or is_junction(root)
    ):
        raise UnsafeWorkspacePath(
            "workspace root changed while resolving a protected operation"
        )
    return (
        os.path.join(root, *relative_path.split("/")),
        parent,
        root_before,
        os.stat(parent, follow_symlinks=False),
    )


def _verify_best_effort_parent(
    root: str,
    parent: str,
    expected_root: os.stat_result,
    expected_parent: os.stat_result,
) -> None:
    is_junction = getattr(os.path, "isjunction", lambda _path: False)
    observed_root = os.lstat(root)
    if (
        _object_identity(observed_root) != _object_identity(expected_root)
        or not stat.S_ISDIR(observed_root.st_mode)
        or os.path.islink(root)
        or is_junction(root)
    ):
        raise UnsafeWorkspacePath(
            "workspace root identity changed during a protected operation"
        )
    observed = os.stat(parent, follow_symlinks=False)
    if (
        _object_identity(observed) != _object_identity(expected_parent)
        or not stat.S_ISDIR(observed.st_mode)
        or os.path.islink(parent)
        or is_junction(parent)
    ):
        raise UnsafeWorkspacePath(
            "workspace parent identity changed during a protected operation"
        )
    if not _is_within(os.path.realpath(root), os.path.realpath(parent)):
        raise UnsafeWorkspacePath(
            "workspace parent escaped its root during a protected operation"
        )


def _atomic_write_at(parent_fd: int, leaf: str, content: str) -> None:
    existing_mode: int | None = None
    try:
        existing = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        if not (stat.S_ISREG(existing.st_mode) or stat.S_ISLNK(existing.st_mode)):
            raise UnsafeWorkspacePath(f"refusing to replace special path: {leaf!r}")
        if stat.S_ISREG(existing.st_mode):
            existing_mode = stat.S_IMODE(existing.st_mode)

    temporary = f".evoguard-write-{secrets.token_hex(12)}"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    fd = os.open(temporary, flags, 0o666, dir_fd=parent_fd)
    try:
        if existing_mode is not None:
            fchmod = getattr(os, "fchmod", None)
            if fchmod is None:
                raise UnsafeWorkspacePath("cannot preserve file mode on this platform")
            fchmod(fd, existing_mode)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = -1
            stream.write(content)
        # POSIX rename is an atomic replacement when source/destination share
        # the held parent directory. Unlike os.replace, os.rename is correctly
        # advertised through os.supports_dir_fd on CPython/Linux.
        os.rename(
            temporary,
            leaf,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
    finally:
        if fd >= 0:
            os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=parent_fd)


def write_text_within_root(root: str, relative_path: str, content: str) -> None:
    """Write UTF-8 text with atomic POSIX containment.

    The Windows fallback rejects reparse roots/parents and checks identities
    before and after use, but remains best-effort rather than atomic.
    """
    _require_posix_descriptor_support()
    if _HAS_DESCRIPTOR_RELATIVE:
        with _open_parent_dir_fd(root, relative_path, create=True) as opened:
            root_fd, parent_fd, leaf, components = opened
            _atomic_write_at(parent_fd, leaf, content)
            _verify_parent_still_bound(root, root_fd, parent_fd, components)
        return

    target, parent, root_identity, parent_identity = _best_effort_target(
        root, relative_path, create=True
    )
    _verify_best_effort_parent(root, parent, root_identity, parent_identity)
    existing_mode: int | None = None
    if os.path.lexists(target):
        existing = os.stat(target, follow_symlinks=False)
        if not (stat.S_ISREG(existing.st_mode) or stat.S_ISLNK(existing.st_mode)):
            raise UnsafeWorkspacePath(
                f"refusing to replace a non-file workspace path: {relative_path!r}"
            )
        if stat.S_ISREG(existing.st_mode):
            existing_mode = stat.S_IMODE(existing.st_mode)
    fd, temporary = tempfile.mkstemp(prefix=".evoguard-write-", dir=parent)
    raw_fd = fd
    try:
        stream = os.fdopen(raw_fd, "w", encoding="utf-8")
        raw_fd = -1
        with stream:
            stream.write(content)
        if existing_mode is not None:
            os.chmod(temporary, existing_mode)
        _verify_best_effort_parent(root, parent, root_identity, parent_identity)
        os.replace(temporary, target)
        temporary = ""
        _verify_best_effort_parent(root, parent, root_identity, parent_identity)
    finally:
        if raw_fd >= 0:
            os.close(raw_fd)
        if temporary:
            with contextlib.suppress(OSError):
                os.unlink(temporary)


def read_text_within_root(root: str, relative_path: str) -> str:
    """Read one regular UTF-8 file while binding its POSIX descriptor identity.

    Windows uses best-effort root/parent and pre/post file identity checks.
    """
    _require_posix_descriptor_support()
    if _HAS_DESCRIPTOR_RELATIVE:
        with _open_parent_dir_fd(root, relative_path, create=False) as opened:
            root_fd, parent_fd, leaf, components = opened
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            fd = os.open(leaf, flags, dir_fd=parent_fd)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                    raise UnsafeWorkspacePath(
                        f"workspace read requires one regular, unaliased file: {relative_path!r}"
                    )
                chunks: list[bytes] = []
                while chunk := os.read(fd, 1024 * 1024):
                    chunks.append(chunk)
                after = os.fstat(fd)
            finally:
                os.close(fd)
            current = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if (
                _stable_file_identity(before) != _stable_file_identity(after)
                or _object_identity(before) != _object_identity(current)
            ):
                raise UnsafeWorkspacePath(
                    f"workspace file changed while being read: {relative_path!r}"
                )
            _verify_parent_still_bound(root, root_fd, parent_fd, components)
        return b"".join(chunks).decode("utf-8")

    target, parent, root_identity, parent_identity = _best_effort_target(
        root, relative_path, create=False
    )
    before_path = os.lstat(target)
    if not stat.S_ISREG(before_path.st_mode) or before_path.st_nlink != 1:
        raise UnsafeWorkspacePath(
            f"workspace read requires one regular, unaliased file: {relative_path!r}"
        )
    fd = os.open(target, os.O_RDONLY)
    try:
        before = os.fstat(fd)
        chunks = []
        while chunk := os.read(fd, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    after_path = os.lstat(target)
    _verify_best_effort_parent(root, parent, root_identity, parent_identity)
    if not (
        _stable_file_identity(before) == _stable_file_identity(after)
        and _object_identity(before_path) == _object_identity(before)
        and _object_identity(after_path) == _object_identity(before)
    ):
        raise UnsafeWorkspacePath(
            f"workspace file changed while being read: {relative_path!r}"
        )
    return b"".join(chunks).decode("utf-8")


def _rmtree_at(parent_fd: int, leaf: str) -> None:
    """Recursively remove one POSIX directory without resolving path strings."""
    directory_fd = os.open(leaf, _directory_open_flags(), dir_fd=parent_fd)
    try:
        for name in sorted(os.listdir(directory_fd)):
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                _rmtree_at(directory_fd, name)
            else:
                os.unlink(name, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)
    os.rmdir(leaf, dir_fd=parent_fd)


def delete_path_within_root(root: str, relative_path: str) -> bool:
    """Delete one relative path with atomic POSIX containment.

    The leaf may itself be a symlink and is deleted without dereferencing it.
    Windows rejects reparse roots/parents and checks their identities before
    and after deletion, but this fallback is best-effort rather than atomic.

    Returns ``True`` when an existing entry was deleted and ``False`` when it
    was already absent. Other filesystem failures are intentionally propagated.
    """
    if not _is_safe_relative_path(relative_path):
        raise UnsafeWorkspacePath(
            f"unsafe deletion path is not a normalized relative path: "
            f"{relative_path!r}"
        )

    _require_posix_descriptor_support()
    if _HAS_DESCRIPTOR_RELATIVE:
        mutation_started = False
        try:
            with _open_parent_dir_fd(root, relative_path, create=False) as opened:
                root_fd, parent_fd, leaf, components = opened
                try:
                    info = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    _verify_parent_still_bound(root, root_fd, parent_fd, components)
                    return False
                mutation_started = True
                if stat.S_ISDIR(info.st_mode):
                    _rmtree_at(parent_fd, leaf)
                else:
                    os.unlink(leaf, dir_fd=parent_fd)
                _verify_parent_still_bound(root, root_fd, parent_fd, components)
                return True
        except FileNotFoundError as exc:
            if not mutation_started:
                return False
            raise UnsafeWorkspacePath(
                "workspace deletion changed after mutation began"
            ) from exc

    try:
        target, parent, root_identity, parent_identity = _best_effort_target(
            root, relative_path, create=False
        )
    except FileNotFoundError:
        return False
    _verify_best_effort_parent(root, parent, root_identity, parent_identity)
    if not os.path.lexists(target):
        return False
    if os.path.islink(target):
        os.unlink(target)
    elif getattr(os.path, "isjunction", lambda _path: False)(target):
        os.rmdir(target)
    elif os.path.isdir(target):
        shutil.rmtree(target)
    else:
        os.remove(target)
    _verify_best_effort_parent(root, parent, root_identity, parent_identity)
    return True
