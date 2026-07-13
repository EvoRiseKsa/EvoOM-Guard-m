# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Canonical identity of the fully prepared candidate runtime tree.

Unlike setup fidelity, this identity deliberately includes dependency, build,
cache, and adopter-declared setup-output paths.  It is captured after setup and
used to prove that a repo suite did not change the runtime later presented to a
repo-native verifier pack.

The default scan budget is intentionally generous for real dependency trees:
a cooperative 120-second deadline checked between filesystem calls, 500,000
entries, 128 MiB of canonical path bytes, 32 GiB of logical regular-file bytes,
and 8 GiB per regular file. A blocked kernel/filesystem call cannot be preempted
inside this process and still needs an outer job/process timeout. Hardlinks are
allowed and counted once per path; no timestamp shortcut replaces content reads.
"""

from __future__ import annotations

import hashlib
import os
import stat
import time
from dataclasses import dataclass
from typing import Protocol

RUNTIME_DIGEST_FORMAT = "EVOGUARD_RUNTIME_TREE_V1"
RUNTIME_IDENTITY_DEADLINE_SECONDS = 120.0
# Keep room for large dependency graphs; the separate path-byte ceiling bounds
# their variable-size record memory, while fixed per-entry payload is small.
RUNTIME_IDENTITY_MAX_ENTRIES = 500_000
RUNTIME_IDENTITY_MAX_PATH_BYTES = 128 * 1024**2
RUNTIME_IDENTITY_MAX_LOGICAL_BYTES = 32 * 1024**3
RUNTIME_IDENTITY_MAX_FILE_BYTES = 8 * 1024**3
RUNTIME_IDENTITY_MAX_REPORTED_CHANGES = 10_000
_HEADER = RUNTIME_DIGEST_FORMAT.encode("ascii") + b"\0"
_CHUNK_SIZE = 1024 * 1024


class RuntimeIdentityError(RuntimeError):
    """The judge could not obtain one stable, complete runtime-tree identity."""


class _Digest(Protocol):
    def update(self, data: bytes, /) -> None: ...


@dataclass(frozen=True)
class RuntimeEntry:
    """One canonical runtime-tree record."""

    path: str
    kind: str
    permissions: int
    size: int
    payload: str


@dataclass(frozen=True)
class RuntimeIdentity:
    """Content identity and the records needed for deterministic drift details."""

    sha256: str
    entries: int
    regular_bytes: int
    elapsed_ms: float
    records: tuple[RuntimeEntry, ...]
    digest_format: str = RUNTIME_DIGEST_FORMAT


@dataclass
class _ScanBudget:
    deadline: float
    max_entries: int
    max_path_bytes: int
    max_logical_bytes: int
    max_file_bytes: int
    discovered_entries: int = 0
    path_bytes: int = 0
    logical_bytes: int = 0

    def check_deadline(self) -> None:
        if time.perf_counter() > self.deadline:
            raise RuntimeIdentityError("runtime identity deadline exceeded")

    def discover_entry(self, path: str) -> None:
        self.check_deadline()
        if self.discovered_entries >= self.max_entries:
            raise RuntimeIdentityError(
                f"runtime identity entry budget exceeded ({self.max_entries})"
            )
        try:
            encoded_size = len(os.fsencode(path))
        except (UnicodeError, ValueError) as exc:
            raise RuntimeIdentityError(
                f"runtime path cannot be encoded canonically: {path!r}"
            ) from exc
        if self.path_bytes + encoded_size > self.max_path_bytes:
            raise RuntimeIdentityError(
                "runtime identity path-byte budget exceeded "
                f"({self.max_path_bytes} bytes)"
            )
        self.discovered_entries += 1
        self.path_bytes += encoded_size

    def reserve_file(self, path: str, size: int) -> None:
        self.check_deadline()
        if size < 0 or size > self.max_file_bytes:
            raise RuntimeIdentityError(
                f"runtime file exceeds per-file budget ({self.max_file_bytes} bytes): "
                f"{path!r} ({size} bytes)"
            )
        if self.logical_bytes + size > self.max_logical_bytes:
            raise RuntimeIdentityError(
                "runtime tree exceeds logical-byte budget "
                f"({self.max_logical_bytes} bytes)"
            )
        self.logical_bytes += size


def _time_ns(info: os.stat_result, name: str) -> int:
    return int(getattr(info, name, 0))


def _same_object(left: os.stat_result, right: os.stat_result) -> bool:
    if stat.S_IFMT(left.st_mode) != stat.S_IFMT(right.st_mode):
        return False
    left_inode = (int(left.st_dev), int(left.st_ino))
    right_inode = (int(right.st_dev), int(right.st_ino))
    # Some platforms/filesystems expose a zero inode. In that case the type and
    # the before/after metadata checks remain the portable race signal.
    return left_inode == right_inode or left.st_ino == 0 or right.st_ino == 0


def _same_metadata(
    left: os.stat_result,
    right: os.stat_result,
    *,
    cross_view: bool = False,
) -> bool:
    # On Windows lstat(path) and fstat(fd) can expose different ctime values for
    # one unchanged object. Normalize only that cross-view comparison; path to
    # path and descriptor to descriptor still bind the platform's full ctime.
    normalize_ctime = cross_view and os.name == "nt"
    return (
        _same_object(left, right)
        and stat.S_IMODE(left.st_mode) == stat.S_IMODE(right.st_mode)
        and int(left.st_nlink) == int(right.st_nlink)
        and int(left.st_size) == int(right.st_size)
        and _time_ns(left, "st_mtime_ns") == _time_ns(right, "st_mtime_ns")
        and (
            normalize_ctime
            or _time_ns(left, "st_ctime_ns") == _time_ns(right, "st_ctime_ns")
        )
    )


def _read_regular(
    path: str,
    initial: os.stat_result,
    budget: _ScanBudget,
    *,
    dir_fd: int | None = None,
) -> tuple[int, int, str]:
    if int(initial.st_size) > budget.max_file_bytes:
        raise RuntimeIdentityError(
            f"runtime file exceeds per-file budget ({budget.max_file_bytes} bytes): "
            f"{path!r} ({initial.st_size} bytes)"
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    if os.name == "posix":
        no_follow = getattr(os, "O_NOFOLLOW", None)
        non_block = getattr(os, "O_NONBLOCK", None)
        if no_follow is None or non_block is None:
            raise RuntimeIdentityError(
                "POSIX runtime lacks no-follow/non-blocking file-open support"
            )
        flags |= no_follow | non_block
    try:
        if dir_fd is None:
            descriptor = os.open(path, flags)
        else:
            descriptor = os.open(path, flags, dir_fd=dir_fd)
    except OSError as exc:
        raise RuntimeIdentityError(f"cannot open runtime file {path!r}: {exc}") from exc

    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not _same_metadata(initial, opened, cross_view=True)
        ):
            raise RuntimeIdentityError(f"runtime path changed while opening {path!r}")
        budget.reserve_file(path, int(opened.st_size))
        digest = hashlib.sha256()
        total = 0
        while True:
            budget.check_deadline()
            chunk = os.read(descriptor, _CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            if total > int(opened.st_size) or total > budget.max_file_bytes:
                raise RuntimeIdentityError(f"runtime file grew while reading {path!r}")
            digest.update(chunk)
        finished = os.fstat(descriptor)
        if not _same_metadata(opened, finished) or total != int(finished.st_size):
            raise RuntimeIdentityError(f"runtime file changed while reading {path!r}")
    except OSError as exc:
        raise RuntimeIdentityError(f"cannot read runtime file {path!r}: {exc}") from exc
    finally:
        os.close(descriptor)

    try:
        if dir_fd is None:
            final_path = os.lstat(path)
        else:
            final_path = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
    except OSError as exc:
        raise RuntimeIdentityError(f"runtime file disappeared after reading {path!r}: {exc}") from exc
    if not (
        _same_metadata(initial, final_path)
        and _same_metadata(finished, final_path, cross_view=True)
    ):
        raise RuntimeIdentityError(f"runtime path changed while reading {path!r}")
    return stat.S_IMODE(opened.st_mode), total, digest.hexdigest()


def _contained_symlink_target(root_real: str, path: str, target: str) -> None:
    if os.path.isabs(target):
        raise RuntimeIdentityError(f"absolute runtime symlink is not allowed: {path!r}")
    resolved = os.path.realpath(os.path.join(os.path.dirname(path), target))
    try:
        contained = os.path.normcase(os.path.commonpath((root_real, resolved))) == (
            os.path.normcase(root_real)
        )
    except ValueError:
        contained = False
    if not contained:
        raise RuntimeIdentityError(f"runtime symlink escapes the candidate tree: {path!r}")
    if not os.path.exists(path):
        raise RuntimeIdentityError(f"dangling runtime symlink is not allowed: {path!r}")


_DESCRIPTOR_SCAN_SUPPORTED = (
    os.name == "posix"
    and hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
    and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.readlink in os.supports_dir_fd
    and os.listdir in os.supports_fd
)


@dataclass(frozen=True)
class _WorkItem:
    action: str
    components: tuple[str, ...]
    rel: str
    expected: os.stat_result
    names: tuple[str, ...] = ()
    parent_expected: os.stat_result | None = None


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


def _open_directory_from_root(
    root_fd: int,
    components: tuple[str, ...],
    expected: os.stat_result,
) -> int:
    current = os.dup(root_fd)
    try:
        for component in components:
            next_fd = os.open(component, _directory_flags(), dir_fd=current)
            os.close(current)
            current = next_fd
        opened = os.fstat(current)
        if not stat.S_ISDIR(opened.st_mode) or not _same_metadata(
            expected, opened, cross_view=True
        ):
            raise RuntimeIdentityError(
                "runtime directory changed while being reopened: "
                + ("/".join(components) or ".")
            )
        return current
    except BaseException:
        os.close(current)
        raise


def _merge_relative_target(
    base: tuple[str, ...],
    target: str,
    tail: tuple[str, ...],
    display_path: str,
) -> list[str]:
    if os.path.isabs(target):
        raise RuntimeIdentityError(
            f"absolute runtime symlink is not allowed: {display_path!r}"
        )
    merged = list(base)
    for component in target.split("/"):
        if component in ("", "."):
            continue
        if component == "..":
            if not merged:
                raise RuntimeIdentityError(
                    f"runtime symlink escapes the candidate tree: {display_path!r}"
                )
            merged.pop()
        else:
            merged.append(component)
    merged.extend(tail)
    return merged


def _validate_contained_symlink_at(
    root_fd: int,
    parent_components: tuple[str, ...],
    target: str,
    display_path: str,
) -> None:
    pending = _merge_relative_target(parent_components, target, (), display_path)
    resolved: list[str] = []
    current = os.dup(root_fd)
    followed = 0
    try:
        while pending:
            component = pending.pop(0)
            try:
                initial = os.stat(
                    component, dir_fd=current, follow_symlinks=False
                )
            except OSError as exc:
                raise RuntimeIdentityError(
                    f"dangling runtime symlink is not allowed: {display_path!r}"
                ) from exc
            if stat.S_ISLNK(initial.st_mode):
                followed += 1
                if followed > 40:
                    raise RuntimeIdentityError(
                        f"runtime symlink resolution limit exceeded: {display_path!r}"
                    )
                nested_target = os.readlink(component, dir_fd=current)
                final = os.stat(
                    component, dir_fd=current, follow_symlinks=False
                )
                if not _same_metadata(initial, final):
                    raise RuntimeIdentityError(
                        f"runtime symlink changed while resolving: {display_path!r}"
                    )
                pending = _merge_relative_target(
                    tuple(resolved), nested_target, tuple(pending), display_path
                )
                os.close(current)
                current = os.dup(root_fd)
                resolved.clear()
                continue
            if pending:
                if not stat.S_ISDIR(initial.st_mode):
                    raise RuntimeIdentityError(
                        f"dangling runtime symlink is not allowed: {display_path!r}"
                    )
                next_fd = os.open(component, _directory_flags(), dir_fd=current)
                try:
                    opened = os.fstat(next_fd)
                except BaseException:
                    os.close(next_fd)
                    raise
                if not _same_metadata(initial, opened, cross_view=True):
                    os.close(next_fd)
                    raise RuntimeIdentityError(
                        f"runtime symlink target changed while resolving: {display_path!r}"
                    )
                os.close(current)
                current = next_fd
                resolved.append(component)
    finally:
        os.close(current)


def _descriptor_leaf_entry(
    root_fd: int,
    item: _WorkItem,
    budget: _ScanBudget,
) -> RuntimeEntry:
    assert item.parent_expected is not None
    parent_components = item.components[:-1]
    leaf = item.components[-1]
    parent_fd = _open_directory_from_root(
        root_fd, parent_components, item.parent_expected
    )
    try:
        initial = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_metadata(item.expected, initial):
            raise RuntimeIdentityError(
                f"runtime path changed before reading {item.rel!r}"
            )
        if stat.S_ISLNK(initial.st_mode):
            target = os.readlink(leaf, dir_fd=parent_fd)
            final = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if not _same_metadata(initial, final):
                raise RuntimeIdentityError(
                    f"runtime symlink changed while reading {item.rel!r}"
                )
            _validate_contained_symlink_at(
                root_fd, parent_components, target, item.rel
            )
            result = RuntimeEntry(
                item.rel, "link", stat.S_IMODE(initial.st_mode), 0, target
            )
        elif stat.S_ISREG(initial.st_mode):
            permissions, size, digest = _read_regular(
                leaf, initial, budget, dir_fd=parent_fd
            )
            result = RuntimeEntry(item.rel, "file", permissions, size, digest)
        else:
            raise RuntimeIdentityError(
                f"unsupported special runtime entry {item.rel!r}"
            )
        if not _same_metadata(item.parent_expected, os.fstat(parent_fd)):
            raise RuntimeIdentityError(
                f"runtime directory changed while scanning {item.rel!r}"
            )
        return result
    finally:
        os.close(parent_fd)


def _scan_tree_descriptors(
    root_fd: int,
    root_opened: os.stat_result,
    budget: _ScanBudget,
) -> list[RuntimeEntry]:
    records: list[RuntimeEntry] = []
    stack = [_WorkItem("enter", (), ".", root_opened)]
    budget.discover_entry(".")
    while stack:
        budget.check_deadline()
        item = stack.pop()
        if item.action == "leaf":
            records.append(_descriptor_leaf_entry(root_fd, item, budget))
            continue

        directory_fd = _open_directory_from_root(
            root_fd, item.components, item.expected
        )
        try:
            if item.action == "exit":
                names = tuple(sorted(os.listdir(directory_fd), key=os.fsencode))
                final = os.fstat(directory_fd)
                if item.names != names or not _same_metadata(item.expected, final):
                    raise RuntimeIdentityError(
                        f"runtime directory changed while scanning {item.rel!r}"
                    )
                continue

            before = os.fstat(directory_fd)
            names_before = tuple(
                sorted(os.listdir(directory_fd), key=os.fsencode)
            )
            children: list[tuple[str, str, os.stat_result]] = []
            for name in names_before:
                child_rel = name if item.rel == "." else f"{item.rel}/{name}"
                budget.discover_entry(child_rel)
                child_info = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )
                children.append((name, child_rel, child_info))
            names_after = tuple(
                sorted(os.listdir(directory_fd), key=os.fsencode)
            )
            after = os.fstat(directory_fd)
            if names_before != names_after or not _same_metadata(before, after):
                raise RuntimeIdentityError(
                    f"runtime directory namespace changed while scanning {item.rel!r}"
                )
            records.append(
                RuntimeEntry(item.rel, "dir", stat.S_IMODE(before.st_mode), 0, "")
            )
            stack.append(
                _WorkItem("exit", item.components, item.rel, before, names_before)
            )
            for name, child_rel, child_info in reversed(children):
                components = (*item.components, name)
                action = "enter" if stat.S_ISDIR(child_info.st_mode) else "leaf"
                stack.append(
                    _WorkItem(
                        action,
                        components,
                        child_rel,
                        child_info,
                        parent_expected=before,
                    )
                )
        finally:
            os.close(directory_fd)
    return records


def _is_unhandled_windows_reparse(info: os.stat_result) -> bool:
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    attributes = int(getattr(info, "st_file_attributes", 0))
    return bool(attributes & reparse_flag) and not stat.S_ISLNK(info.st_mode)


def _reject_windows_reparse_directory(path: str) -> None:
    is_junction = getattr(os.path, "isjunction", lambda _path: False)
    info = os.lstat(path)
    if os.path.islink(path) or is_junction(path) or _is_unhandled_windows_reparse(info):
        raise RuntimeIdentityError(
            f"runtime directory is a symlink, junction, or reparse point: {path!r}"
        )


def _best_effort_leaf_entry(
    root_real: str,
    root: str,
    item: _WorkItem,
    budget: _ScanBudget,
) -> RuntimeEntry:
    path = os.path.join(root, *item.components)
    initial = os.lstat(path)
    if not _same_metadata(item.expected, initial):
        raise RuntimeIdentityError(f"runtime path changed before reading {path!r}")
    if (
        getattr(os.path, "isjunction", lambda _path: False)(path)
        or _is_unhandled_windows_reparse(initial)
    ):
        raise RuntimeIdentityError(
            f"runtime junction/reparse point is not allowed: {path!r}"
        )
    if stat.S_ISLNK(initial.st_mode):
        target = os.readlink(path)
        final = os.lstat(path)
        if not _same_metadata(initial, final):
            raise RuntimeIdentityError(f"runtime symlink changed while reading {path!r}")
        _contained_symlink_target(root_real, path, target)
        return RuntimeEntry(
            item.rel, "link", stat.S_IMODE(initial.st_mode), 0, target
        )
    if stat.S_ISREG(initial.st_mode):
        permissions, size, digest = _read_regular(path, initial, budget)
        return RuntimeEntry(item.rel, "file", permissions, size, digest)
    raise RuntimeIdentityError(f"unsupported special runtime entry {path!r}")


def _scan_tree_best_effort(
    root: str,
    root_real: str,
    root_info: os.stat_result,
    budget: _ScanBudget,
) -> list[RuntimeEntry]:
    records: list[RuntimeEntry] = []
    stack = [_WorkItem("enter", (), ".", root_info)]
    budget.discover_entry(".")
    while stack:
        budget.check_deadline()
        item = stack.pop()
        path = os.path.join(root, *item.components)
        if item.action == "leaf":
            records.append(
                _best_effort_leaf_entry(root_real, root, item, budget)
            )
            continue

        before = os.lstat(path)
        if not stat.S_ISDIR(before.st_mode) or not _same_metadata(
            item.expected, before
        ):
            raise RuntimeIdentityError(
                f"runtime directory changed while scanning {path!r}"
            )
        _reject_windows_reparse_directory(path)
        if item.action == "exit":
            names = tuple(sorted(os.listdir(path), key=os.fsencode))
            final = os.lstat(path)
            if item.names != names or not _same_metadata(item.expected, final):
                raise RuntimeIdentityError(
                    f"runtime directory changed while scanning {path!r}"
                )
            continue

        names_before = tuple(sorted(os.listdir(path), key=os.fsencode))
        children: list[tuple[str, str, os.stat_result]] = []
        for name in names_before:
            child_rel = name if item.rel == "." else f"{item.rel}/{name}"
            budget.discover_entry(child_rel)
            child_path = os.path.join(path, name)
            child_info = os.lstat(child_path)
            if (
                getattr(os.path, "isjunction", lambda _path: False)(child_path)
                or _is_unhandled_windows_reparse(child_info)
            ):
                raise RuntimeIdentityError(
                    f"runtime junction/reparse point is not allowed: {child_path!r}"
                )
            children.append((name, child_rel, child_info))
        names_after = tuple(sorted(os.listdir(path), key=os.fsencode))
        after = os.lstat(path)
        if names_before != names_after or not _same_metadata(before, after):
            raise RuntimeIdentityError(
                f"runtime directory namespace changed while scanning {path!r}"
            )
        records.append(
            RuntimeEntry(item.rel, "dir", stat.S_IMODE(before.st_mode), 0, "")
        )
        stack.append(_WorkItem("exit", item.components, item.rel, before, names_before))
        for name, child_rel, child_info in reversed(children):
            components = (*item.components, name)
            action = "enter" if stat.S_ISDIR(child_info.st_mode) else "leaf"
            stack.append(_WorkItem(action, components, child_rel, child_info))
    return records


def _frame(digest: _Digest, value: bytes) -> None:
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def _digest_records(records: tuple[RuntimeEntry, ...]) -> str:
    digest = hashlib.sha256()
    digest.update(_HEADER)
    kind_codes = {"dir": b"D", "file": b"F", "link": b"L"}
    for record in records:
        digest.update(kind_codes[record.kind])
        _frame(digest, os.fsencode(record.path))
        digest.update(record.permissions.to_bytes(4, "big"))
        digest.update(record.size.to_bytes(8, "big"))
        payload = (
            bytes.fromhex(record.payload)
            if record.kind == "file"
            else os.fsencode(record.payload)
        )
        _frame(digest, payload)
    return digest.hexdigest()


def capture_runtime_identity(
    root: str,
    *,
    deadline_seconds: float = RUNTIME_IDENTITY_DEADLINE_SECONDS,
    max_entries: int = RUNTIME_IDENTITY_MAX_ENTRIES,
    max_path_bytes: int = RUNTIME_IDENTITY_MAX_PATH_BYTES,
    max_logical_bytes: int = RUNTIME_IDENTITY_MAX_LOGICAL_BYTES,
    max_file_bytes: int = RUNTIME_IDENTITY_MAX_FILE_BYTES,
) -> RuntimeIdentity:
    """Capture a complete, budgeted identity without setup-output exclusions."""
    started = time.perf_counter()
    if (
        deadline_seconds <= 0
        or max_entries <= 0
        or max_path_bytes <= 0
        or max_logical_bytes <= 0
        or max_file_bytes <= 0
    ):
        raise RuntimeIdentityError("runtime identity budgets must be positive")
    budget = _ScanBudget(
        deadline=started + deadline_seconds,
        max_entries=max_entries,
        max_path_bytes=max_path_bytes,
        max_logical_bytes=max_logical_bytes,
        max_file_bytes=max_file_bytes,
    )
    try:
        root_info = os.lstat(root)
    except OSError as exc:
        raise RuntimeIdentityError(f"cannot inspect runtime root {root!r}: {exc}") from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise RuntimeIdentityError(f"runtime root must be a real directory: {root!r}")

    try:
        if os.name == "posix" and not _DESCRIPTOR_SCAN_SUPPORTED:
            raise RuntimeIdentityError(
                "POSIX runtime lacks descriptor-relative/no-follow scan support"
            )
        if _DESCRIPTOR_SCAN_SUPPORTED:
            root_fd = os.open(root, _directory_flags())
            try:
                root_opened = os.fstat(root_fd)
                if not _same_metadata(root_info, root_opened, cross_view=True):
                    raise RuntimeIdentityError(
                        "runtime root changed while it was opened"
                    )
                gathered = _scan_tree_descriptors(root_fd, root_opened, budget)
                final_fd = os.fstat(root_fd)
                final_path = os.lstat(root)
                if not (
                    _same_metadata(root_opened, final_fd)
                    and _same_metadata(root_info, final_path)
                    and _same_metadata(final_fd, final_path, cross_view=True)
                ):
                    raise RuntimeIdentityError(
                        "runtime root changed while it was scanned"
                    )
            finally:
                os.close(root_fd)
        else:
            _reject_windows_reparse_directory(root)
            root_real = os.path.realpath(root)
            gathered = _scan_tree_best_effort(
                root, root_real, root_info, budget
            )
            final_root = os.lstat(root)
            _reject_windows_reparse_directory(root)
            if not _same_metadata(root_info, final_root):
                raise RuntimeIdentityError(
                    "runtime root changed while it was scanned"
                )

        # Traversal is canonical bytewise depth-first, so no second sorted copy
        # of attacker-sized records is needed before digesting.
        records = tuple(gathered)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return RuntimeIdentity(
            sha256=_digest_records(records),
            entries=len(records),
            regular_bytes=budget.logical_bytes,
            elapsed_ms=elapsed_ms,
            records=records,
        )
    except RuntimeIdentityError:
        raise
    except MemoryError as exc:
        raise RuntimeIdentityError(
            "runtime identity memory budget exhausted"
        ) from exc
    except OSError as exc:
        raise RuntimeIdentityError(f"cannot scan runtime tree: {exc}") from exc


def runtime_identity_changes(
    expected: RuntimeIdentity, observed: RuntimeIdentity
) -> list[str]:
    """Return deterministic paths whose type, mode, size, target, or bytes differ."""
    def key(record: RuntimeEntry) -> tuple[bytes, ...]:
        if record.path == ".":
            return ()
        return tuple(os.fsencode(part) for part in record.path.split("/"))

    changes: list[str] = []

    def changed(path: str) -> bool:
        if len(changes) >= RUNTIME_IDENTITY_MAX_REPORTED_CHANGES:
            changes.append("<runtime-change-list-truncated>")
            return True
        changes.append(path)
        return False

    try:
        before = expected.records
        after = observed.records
        left = right = 0
        while left < len(before) and right < len(after):
            left_record = before[left]
            right_record = after[right]
            if left_record.path == right_record.path:
                if left_record != right_record and changed(left_record.path):
                    return changes
                left += 1
                right += 1
                continue
            if key(left_record) < key(right_record):
                if changed(left_record.path):
                    return changes
                left += 1
            else:
                if changed(right_record.path):
                    return changes
                right += 1
        while left < len(before):
            if changed(before[left].path):
                return changes
            left += 1
        while right < len(after):
            if changed(after[right].path):
                return changes
            right += 1
    except MemoryError as exc:
        raise RuntimeIdentityError(
            "runtime identity comparison memory budget exhausted"
        ) from exc
    if not changes and expected.sha256 != observed.sha256:
        return ["<runtime-tree-digest>"]
    return changes


def verify_runtime_identity(
    root: str, expected: RuntimeIdentity
) -> tuple[RuntimeIdentity, list[str]]:
    """Capture ``root`` again and compare it with the accepted runtime identity."""
    observed = capture_runtime_identity(root)
    return observed, runtime_identity_changes(expected, observed)
