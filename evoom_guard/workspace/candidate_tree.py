# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Fail-closed base/head filesystem candidate derivation.

This module owns the complete candidate-tree snapshot transaction: root
validation, non-following traversal, Windows reparse classification, stable
regular-file identity, bounded descriptor reads/comparisons, changed-path
classification, and canonical FILE-block serialization.

The transaction binds each file read to the object and metadata observed while
that path was classified. It does not claim an atomic snapshot across the whole
tree; callers that need revision identity must use a quiescent checkout or the
raw-Git finalizer path.

Guard keeps its historical public/private facade and injects live providers on
every call. That preserves adopter monkeypatch seams without moving policy,
candidate admission, repository mutation, execution, evidence, or verdict
composition into this workspace owner.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class TreeEntry:
    """One non-ignored filesystem entry captured without following links."""

    full_path: str
    kind: str
    mode: int | None
    size: int | None
    link_target: str | None = None
    problem: str | None = None
    identity: tuple[int, ...] | None = None
    path_times: tuple[int, int] | None = None


class UnverifiableChangedPathsError(ValueError):
    """A base/head change cannot be represented safely as Guard file blocks."""

    def __init__(self, problems: list[tuple[str, str]]) -> None:
        self.problems = tuple(problems)
        listed = "; ".join(f"{path}: {reason}" for path, reason in problems)
        super().__init__(
            f"changed path(s) cannot be safely represented for verification ({listed})"
        )


class TreeEntryFactory(Protocol):
    """Constructor shape retained by Guard's private ``_TreeEntry`` facade."""

    def __call__(
        self,
        full_path: str,
        kind: str,
        mode: int | None,
        size: int | None,
        link_target: str | None = None,
        problem: str | None = None,
        identity: tuple[int, ...] | None = None,
        path_times: tuple[int, int] | None = None,
    ) -> TreeEntry: ...


class UnverifiableErrorFactory(Protocol):
    """Constructor shape for the changed-path aggregate error."""

    def __call__(
        self,
        problems: list[tuple[str, str]],
    ) -> UnverifiableChangedPathsError: ...


class BlocksFromDirs(Protocol):
    """Historical keyword-only shape of Guard's structured derivation facade."""

    def __call__(
        self,
        base_dir: str,
        head_dir: str,
        *,
        max_bytes: int = 1_000_000,
    ) -> tuple[dict[str, str], list[str]]: ...


WalkTreeEntries = Callable[[str], Mapping[str, TreeEntry]]
TreeEntryLookup = Callable[[str], TreeEntry]
DirectoryHasRegularDescendant = Callable[[Mapping[str, TreeEntry], str], bool]
EntriesChanged = Callable[
    [TreeEntry | None, TreeEntry],
    tuple[bool, str | None],
]
EntryProblem = Callable[[TreeEntry], str]
ReadChangedText = Callable[[TreeEntry, int], str]
RegularFilesEqual = Callable[[str, str, TreeEntry | None, TreeEntry | None], bool]
SerializeCandidateBlocks = Callable[[Mapping[str, str]], str]
WindowsReparseProbe = Callable[[str, os.stat_result], bool]
StatIdentity = Callable[[os.stat_result], tuple[int, ...]]
StatPathTimes = Callable[[os.stat_result], tuple[int, int]]
VerifyRegularSnapshot = Callable[
    [TreeEntry, os.stat_result, str, bool],
    None,
]
RegularSnapshotOpenFlags = Callable[[], int]
OpenRegularSnapshot = Callable[[TreeEntry], int]
VerifyOpenRegularSnapshot = Callable[[TreeEntry, int, str], None]
ReadFileDescriptor = Callable[[int, int], bytes]


def blocks_from_dirs(
    base_dir: str,
    head_dir: str,
    *,
    max_bytes: int = 1_000_000,
    tree_entry_lookup: TreeEntryLookup,
    walk_tree_entries: WalkTreeEntries,
    directory_has_regular_descendant: DirectoryHasRegularDescendant,
    entries_changed: EntriesChanged,
    entry_problem: EntryProblem,
    read_changed_text: ReadChangedText,
    unverifiable_error: UnverifiableErrorFactory = UnverifiableChangedPathsError,
) -> tuple[dict[str, str], list[str]]:
    """Derive structured text blocks and deletions from two filesystem trees.

    Both roots must be real directories. Every changed path is then either
    represented or reported through one aggregate fail-closed exception.
    """

    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")

    root_problems: list[tuple[str, str]] = []
    for label, root in (("<base-root>", base_dir), ("<head-root>", head_dir)):
        root_entry = tree_entry_lookup(root)
        if root_entry.kind != "directory":
            root_problems.append((label, entry_problem(root_entry)))
    if root_problems:
        raise unverifiable_error(root_problems)

    base_entries = walk_tree_entries(base_dir)
    head_entries = walk_tree_entries(head_dir)
    blocks: dict[str, str] = {}
    deleted = sorted(set(base_entries) - set(head_entries))
    problems: list[tuple[str, str]] = []

    for rel in sorted(head_entries):
        head = head_entries[rel]
        base = base_entries.get(rel)
        # Writing a file recreates its parent directories, but the FILE-block
        # grammar cannot represent an empty directory.
        if head.kind == "directory" and base is None:
            if not directory_has_regular_descendant(head_entries, rel):
                problems.append((rel, "new empty directory cannot be represented"))
            continue
        changed, comparison_problem = entries_changed(base, head)
        if comparison_problem:
            problems.append((rel, comparison_problem))
            continue
        if not changed:
            continue
        if head.kind != "regular":
            problems.append((rel, entry_problem(head)))
            continue
        try:
            blocks[rel] = read_changed_text(head, max_bytes)
        except OSError as exc:
            problems.append((rel, f"cannot read changed file ({exc.strerror or exc})"))
        except UnicodeDecodeError:
            problems.append((rel, "changed file is not valid UTF-8 text"))
        except ValueError as exc:
            problems.append((rel, str(exc)))

    if problems:
        raise unverifiable_error(problems)
    return blocks, deleted


def serialize_candidate_blocks(blocks: Mapping[str, str]) -> str:
    """Return the canonical textual identity for structured candidate blocks."""

    return "\n".join(f"<<<FILE: {rel}>>>\n{blocks[rel]}\n<<<END FILE>>>" for rel in sorted(blocks))


def candidate_from_dirs(
    base_dir: str,
    head_dir: str,
    *,
    max_bytes: int = 1_000_000,
    derive_blocks: BlocksFromDirs,
    serialize_blocks: SerializeCandidateBlocks,
) -> tuple[str, list[str]]:
    """Return Guard's historical text serialization plus explicit deletions."""

    blocks, deleted = derive_blocks(base_dir, head_dir, max_bytes=max_bytes)
    return serialize_blocks(blocks), deleted


def walk_tree_entries(
    root: str,
    *,
    copy_ignore: Iterable[str],
    tree_entry_lookup: TreeEntryLookup,
    entry_factory: TreeEntryFactory = TreeEntry,
) -> dict[str, TreeEntry]:
    """Return every non-ignored path without dropping non-text entries."""

    out: dict[str, TreeEntry] = {}
    ignore = set(copy_ignore) | {".git"}

    def walk_error(exc: OSError) -> None:
        # ``os.walk`` otherwise silently skips an unreadable directory.
        if not exc.filename:
            return
        try:
            rel = os.path.relpath(exc.filename, root).replace(os.sep, "/")
        except ValueError:
            return
        if rel in (".", "") or rel.startswith("../"):
            return
        out[rel] = entry_factory(
            exc.filename,
            "unreadable",
            None,
            None,
            problem=f"cannot walk directory ({exc.strerror or exc})",
        )

    for dirpath, dirnames, filenames in os.walk(root, onerror=walk_error):
        dirnames[:] = [name for name in dirnames if name not in ignore]
        traversable_dirs: list[str] = []
        for dirname in dirnames:
            full = os.path.join(dirpath, dirname)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            entry = tree_entry_lookup(full)
            out[rel] = entry
            # Reparse, symlink, and special entries are retained but not followed.
            if entry.kind == "directory":
                traversable_dirs.append(dirname)
        dirnames[:] = traversable_dirs
        for filename in filenames:
            full = os.path.join(dirpath, filename)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            out[rel] = tree_entry_lookup(full)
    return out


def tree_entry(
    full_path: str,
    *,
    entry_factory: TreeEntryFactory = TreeEntry,
    is_windows_reparse: WindowsReparseProbe,
    stat_identity: StatIdentity,
    stat_path_times: StatPathTimes,
) -> TreeEntry:
    """Describe a path without following a symlink or reading its payload."""

    try:
        info = os.lstat(full_path)
    except OSError as exc:
        return entry_factory(
            full_path,
            "unreadable",
            None,
            None,
            problem=f"cannot stat path ({exc.strerror or exc})",
        )

    mode = stat.S_IMODE(info.st_mode)
    if stat.S_ISLNK(info.st_mode):
        try:
            return entry_factory(
                full_path,
                "symlink",
                mode,
                None,
                os.readlink(full_path),
            )
        except OSError as exc:
            return entry_factory(
                full_path,
                "unreadable",
                mode,
                None,
                problem=f"cannot read symlink ({exc.strerror or exc})",
            )
    if is_windows_reparse(full_path, info):
        return entry_factory(
            full_path,
            "special",
            mode,
            None,
            problem="path is a Windows reparse point",
        )
    if stat.S_ISREG(info.st_mode):
        return entry_factory(
            full_path,
            "regular",
            mode,
            int(info.st_size),
            identity=stat_identity(info),
            path_times=stat_path_times(info),
        )
    if stat.S_ISDIR(info.st_mode):
        return entry_factory(full_path, "directory", mode, None)
    return entry_factory(
        full_path,
        "special",
        mode,
        None,
        problem="path is not a regular file or symlink",
    )


def is_windows_reparse(
    full_path: str,
    info: os.stat_result,
    *,
    platform_name: str | None = None,
    junction_probe: Callable[[str], bool] | None = None,
) -> bool:
    """Whether ``info`` names a Windows reparse object."""

    platform = os.name if platform_name is None else platform_name
    if platform != "nt":
        return False
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    attributes = int(getattr(info, "st_file_attributes", 0))
    if attributes & reparse_flag:
        return True
    probe = getattr(os.path, "isjunction", None) if junction_probe is None else junction_probe
    return bool(probe is not None and probe(full_path))


def stat_identity(info: os.stat_result) -> tuple[int, ...]:
    """Return object/type/mode/size identity stable across path/handle APIs."""

    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_nlink),
        int(info.st_size),
        int(getattr(info, "st_file_attributes", 0)),
        int(getattr(info, "st_reparse_tag", 0)),
    )


def stat_path_times(info: os.stat_result) -> tuple[int, int]:
    """Return mutation-sensitive times compared only across path observations."""

    return (int(info.st_mtime_ns), int(info.st_ctime_ns))


def verify_regular_snapshot(
    entry: TreeEntry,
    observed: os.stat_result,
    *,
    problem: str,
    path_observation: bool,
    stat_identity_provider: StatIdentity,
    stat_path_times_provider: StatPathTimes,
) -> None:
    """Reject a path/descriptor that no longer matches its captured ``lstat``."""

    if (
        entry.identity is None
        or not stat.S_ISREG(observed.st_mode)
        or stat_identity_provider(observed) != entry.identity
        or (
            path_observation
            and (entry.path_times is None or stat_path_times_provider(observed) != entry.path_times)
        )
    ):
        raise OSError(problem)


def regular_snapshot_open_flags(
    *,
    platform_name: str | None = None,
    flag_provider: Callable[[str], int | None] | None = None,
) -> int:
    """Build a non-following, non-blocking POSIX open contract."""

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    platform = os.name if platform_name is None else platform_name
    if platform == "posix":
        provider = (
            (lambda name: getattr(os, name, None)) if flag_provider is None else flag_provider
        )
        no_follow = provider("O_NOFOLLOW")
        non_block = provider("O_NONBLOCK")
        if no_follow is None or non_block is None:
            raise OSError("POSIX runtime lacks no-follow/non-blocking file-open support")
        flags |= no_follow | non_block
    return flags


def open_regular_snapshot(
    entry: TreeEntry,
    *,
    is_windows_reparse: WindowsReparseProbe,
    verify_regular_snapshot_provider: VerifyRegularSnapshot,
    open_flags: RegularSnapshotOpenFlags,
) -> int:
    """Open one classified regular file without accepting a name swap."""

    before = os.lstat(entry.full_path)
    if is_windows_reparse(entry.full_path, before):
        raise OSError("candidate file identity changed after it was classified")
    verify_regular_snapshot_provider(
        entry,
        before,
        "candidate file identity changed after it was classified",
        True,
    )
    descriptor = os.open(entry.full_path, open_flags())
    try:
        opened = os.fstat(descriptor)
        current = os.lstat(entry.full_path)
        if is_windows_reparse(entry.full_path, current):
            raise OSError("candidate file identity changed after it was classified")
        verify_regular_snapshot_provider(
            entry,
            opened,
            "candidate file identity changed after it was classified",
            False,
        )
        verify_regular_snapshot_provider(
            entry,
            current,
            "candidate file identity changed after it was classified",
            True,
        )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def verify_open_regular_snapshot(
    entry: TreeEntry,
    descriptor: int,
    *,
    operation: str,
    is_windows_reparse: WindowsReparseProbe,
    verify_regular_snapshot_provider: VerifyRegularSnapshot,
) -> None:
    """Bind a completed read/compare to both its descriptor and path name."""

    problem = f"candidate file changed while it was being {operation}"
    opened = os.fstat(descriptor)
    current = os.lstat(entry.full_path)
    if is_windows_reparse(entry.full_path, current):
        raise OSError(problem)
    verify_regular_snapshot_provider(entry, opened, problem, False)
    verify_regular_snapshot_provider(entry, current, problem, True)


def entries_changed(
    base: TreeEntry | None,
    head: TreeEntry,
    *,
    regular_files_equal: RegularFilesEqual,
    entry_problem: EntryProblem,
) -> tuple[bool, str | None]:
    """Return whether a path changed and whether that fact is unverifiable."""

    if base is None:
        return True, None
    if base.kind == "unreadable":
        return True, entry_problem(base)
    if head.kind == "unreadable":
        return True, entry_problem(head)
    if base.kind != head.kind:
        return True, f"path type changed from {base.kind} to {head.kind}"
    if base.mode != head.mode:
        return True, "path mode changed; Guard file blocks cannot preserve modes"
    if head.kind == "regular":
        try:
            return (
                not regular_files_equal(
                    base.full_path,
                    head.full_path,
                    base,
                    head,
                )
            ), None
        except OSError as exc:
            return True, f"cannot compare file content ({exc.strerror or exc})"
    if head.kind == "symlink":
        return base.link_target != head.link_target, None
    if head.kind == "directory":
        return False, None
    return True, entry_problem(head)


def regular_files_equal(
    base_path: str,
    head_path: str,
    *,
    base_snapshot: TreeEntry | None = None,
    head_snapshot: TreeEntry | None = None,
    tree_entry_lookup: TreeEntryLookup,
    open_regular_snapshot_provider: OpenRegularSnapshot,
    verify_open_regular_snapshot_provider: VerifyOpenRegularSnapshot,
) -> bool:
    """Compare two stable regular-file snapshots with bounded memory."""

    base_entry = base_snapshot or tree_entry_lookup(base_path)
    head_entry = head_snapshot or tree_entry_lookup(head_path)
    if base_entry.kind != "regular" or head_entry.kind != "regular":
        raise OSError("candidate file identity changed after it was classified")

    base_descriptor = open_regular_snapshot_provider(base_entry)
    try:
        head_descriptor = open_regular_snapshot_provider(head_entry)
    except BaseException:
        os.close(base_descriptor)
        raise
    try:
        equal = base_entry.size == head_entry.size
        while equal:
            left = os.read(base_descriptor, 1024 * 1024)
            right = os.read(head_descriptor, 1024 * 1024)
            if left != right:
                equal = False
                break
            if not left:
                break
        verify_open_regular_snapshot_provider(
            base_entry,
            base_descriptor,
            "compared",
        )
        verify_open_regular_snapshot_provider(
            head_entry,
            head_descriptor,
            "compared",
        )
        return equal
    finally:
        os.close(head_descriptor)
        os.close(base_descriptor)


def entry_problem(entry: TreeEntry) -> str:
    """Return the established diagnostic for an unrepresentable entry."""

    if entry.problem:
        return entry.problem
    if entry.kind == "symlink":
        return "path is a symlink, which Guard file blocks cannot represent"
    if entry.kind == "special":
        return "path is not a regular file"
    return "path cannot be represented safely"


def directory_has_regular_descendant(
    entries: Mapping[str, TreeEntry],
    directory: str,
) -> bool:
    """Whether FILE blocks implicitly recreate a newly added directory."""

    prefix = directory.rstrip("/") + "/"
    return any(
        path.startswith(prefix) and entry.kind == "regular" for path, entry in entries.items()
    )


def read_changed_text(
    entry: TreeEntry,
    max_bytes: int,
    *,
    open_regular_snapshot_provider: OpenRegularSnapshot,
    read_fd_bounded_provider: ReadFileDescriptor,
    verify_open_regular_snapshot_provider: VerifyOpenRegularSnapshot,
) -> str:
    """Read one changed regular text file, failing before it can be dropped."""

    if entry.size is None:
        raise ValueError("changed file has no stable size")
    if entry.size > max_bytes:
        raise ValueError(f"changed file is {entry.size} bytes, above the {max_bytes}-byte limit")
    descriptor = open_regular_snapshot_provider(entry)
    try:
        data = read_fd_bounded_provider(descriptor, max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(f"changed file grew above the {max_bytes}-byte limit while being read")
        verify_open_regular_snapshot_provider(entry, descriptor, "read")
    finally:
        os.close(descriptor)
    return data.decode("utf-8")


def read_fd_bounded(descriptor: int, maximum: int) -> bytes:
    """Read at most ``maximum`` bytes from a regular-file descriptor."""

    chunks: list[bytes] = []
    remaining = maximum
    while remaining:
        chunk = os.read(descriptor, min(remaining, 1024 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


__all__ = (
    "TreeEntry",
    "UnverifiableChangedPathsError",
    "blocks_from_dirs",
    "candidate_from_dirs",
    "directory_has_regular_descendant",
    "entries_changed",
    "entry_problem",
    "is_windows_reparse",
    "open_regular_snapshot",
    "read_changed_text",
    "read_fd_bounded",
    "regular_files_equal",
    "regular_snapshot_open_flags",
    "serialize_candidate_blocks",
    "stat_identity",
    "stat_path_times",
    "tree_entry",
    "verify_open_regular_snapshot",
    "verify_regular_snapshot",
    "walk_tree_entries",
)
