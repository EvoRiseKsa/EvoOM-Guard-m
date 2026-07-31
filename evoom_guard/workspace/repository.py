# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Low-level repository-copy and judge-workspace lifecycle contracts.

This dependency-free owner contains only repository-tree copying and cleanup
effects. It does not decide candidate admission, execute repository code,
interpret evidence, or compose a verdict. Compatibility facades inject their
live module globals at each call so existing monkeypatch seams keep their
historical timing.
"""

from __future__ import annotations

import os
import shutil
import stat
from collections.abc import Callable, Iterable
from dataclasses import dataclass

# Basenames never copied into a throwaway candidate working copy.
COPY_IGNORE = (
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    ".evo_runs",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
)
_MAX_WINDOWS_READONLY_REPAIRS = 1024

CopyTree = Callable[..., object]
CopyIgnore = Callable[[str, list[str]], Iterable[str]]
IgnorePatterns = Callable[..., CopyIgnore]
RemoveTree = Callable[[str], object]
NoteFailure = Callable[[BaseException, str], None]
PathAbsent = Callable[[str], bool]
UnsafeReparseProbe = Callable[[str], bool]


class UnsafeRepositoryTree(ValueError):
    """A source tree cannot be copied without following an unsafe path."""


class UnsafeOwnedWorkspace(RuntimeError):
    """A claimed judge workspace no longer has its captured path identity."""


class OwnedWorkspaceRemovalUnproven(RuntimeError):
    """Recursive removal returned without proving that the owned root is absent."""


@dataclass(frozen=True, slots=True)
class _PathIdentity:
    """Stable fields that identify one observed filesystem object."""

    device: int
    inode: int
    file_type: int

    @classmethod
    def capture(cls, observed: os.stat_result) -> _PathIdentity:
        return cls(
            device=int(observed.st_dev),
            inode=int(observed.st_ino),
            file_type=stat.S_IFMT(observed.st_mode),
        )


@dataclass(frozen=True, slots=True)
class _OwnedWorkspaceLease:
    """Allocation-time identity for one judge-created temporary directory."""

    root_path: str
    root_identity: _PathIdentity
    parent_path: str
    parent_identity: _PathIdentity
    platform_name: str


class _OwnedWorkspacePath(str):
    """String-compatible path carrying a nominal judge-ownership lease.

    This is capability separation inside the judge, not a Python sandbox:
    candidate code runs out of process and never receives this object. Keeping
    the concrete value string-compatible preserves the historical cleanup
    facade while distinguishing roots captured immediately after trusted
    allocation from arbitrary caller-supplied strings.
    """

    __slots__ = ("_owned_workspace_lease",)
    _owned_workspace_lease: _OwnedWorkspaceLease

    def __new__(
        cls,
        path: str,
        lease: _OwnedWorkspaceLease,
    ) -> _OwnedWorkspacePath:
        owned = str.__new__(cls, path)
        owned._owned_workspace_lease = lease
        return owned


def _windows_reparse_observed(observed: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(observed, "st_file_attributes", 0) & reparse_flag)


def _require_real_directory(
    path: str,
    observed: os.stat_result,
    *,
    platform_name: str,
    role: str,
) -> None:
    if (
        not stat.S_ISDIR(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or (platform_name == "nt" and _windows_reparse_observed(observed))
    ):
        raise UnsafeOwnedWorkspace(
            f"refusing {role} that is not a real directory: {path!r}"
        )


def _claim_owned_workspace(
    path: str,
    *,
    platform_name: str | None = None,
    expected_root_identity: _PathIdentity | None = None,
    expected_parent_identity: _PathIdentity | None = None,
) -> _OwnedWorkspacePath:
    """Capture one trusted allocator result as a judge-owned cleanup capability.

    This function is intentionally strict: callers must invoke it immediately
    after a trusted temporary-directory allocator returns.  It does not turn
    an arbitrary path into a general force-delete capability.
    """

    platform = os.name if platform_name is None else platform_name
    root_path = os.path.abspath(path)
    parent_path = os.path.dirname(root_path)
    root_observed = os.lstat(root_path)
    parent_observed = os.lstat(parent_path)
    _require_real_directory(
        root_path,
        root_observed,
        platform_name=platform,
        role="owned workspace root",
    )
    _require_real_directory(
        parent_path,
        parent_observed,
        platform_name=platform,
        role="owned workspace parent",
    )
    root_identity = _PathIdentity.capture(root_observed)
    parent_identity = _PathIdentity.capture(parent_observed)
    if (
        expected_root_identity is not None
        and root_identity != expected_root_identity
    ):
        raise UnsafeOwnedWorkspace(
            f"allocated workspace root identity changed: {root_path!r}"
        )
    if (
        expected_parent_identity is not None
        and parent_identity != expected_parent_identity
    ):
        raise UnsafeOwnedWorkspace(
            f"allocated workspace parent identity changed: {parent_path!r}"
        )
    return _OwnedWorkspacePath(
        root_path,
        _OwnedWorkspaceLease(
            root_path=root_path,
            root_identity=root_identity,
            parent_path=parent_path,
            parent_identity=parent_identity,
            platform_name=platform,
        ),
    )


def allocate_owned_workspace(
    *,
    prefix: str,
    create_workspace: Callable[..., str],
    platform_name: str | None = None,
) -> str:
    """Allocate and immediately claim one judge-owned temporary directory.

    The public operation accepts the trusted allocator capability and its
    prefix, not an arbitrary pre-existing path.  Its concrete result remains
    string-compatible for the historical repository-verifier facade.
    """

    path = os.path.abspath(create_workspace(prefix=prefix))
    parent_path = os.path.dirname(path)
    platform = os.name if platform_name is None else platform_name
    allocated_root_identity: _PathIdentity | None = None
    allocated_parent_identity: _PathIdentity | None = None
    try:
        root_observed = os.lstat(path)
        _require_real_directory(
            path,
            root_observed,
            platform_name=platform,
            role="allocated workspace root",
        )
        allocated_root_identity = _PathIdentity.capture(root_observed)
        parent_observed = os.lstat(parent_path)
        _require_real_directory(
            parent_path,
            parent_observed,
            platform_name=platform,
            role="allocated workspace parent",
        )
        allocated_parent_identity = _PathIdentity.capture(parent_observed)
        return _claim_owned_workspace(
            path,
            platform_name=platform,
            expected_root_identity=allocated_root_identity,
            expected_parent_identity=allocated_parent_identity,
        )
    except BaseException as primary:
        # Allocation has succeeded but no ownership capability can be
        # returned. An allocator result must still be empty at this point, so
        # rollback uses non-recursive rmdir. If the path was populated or
        # replaced before it could be claimed, fail closed and leave it for
        # operator inspection instead of recursively deleting an unowned tree.
        rollback_error: BaseException | None
        if (
            allocated_root_identity is None
            or allocated_parent_identity is None
        ):
            rollback_error = UnsafeOwnedWorkspace(
                "cannot roll back an unclaimed workspace without its "
                "allocation-time root and parent identities"
            )
        else:
            rollback_error = None
            try:
                parent_observed = os.lstat(parent_path)
                root_observed = os.lstat(path)
                _require_real_directory(
                    parent_path,
                    parent_observed,
                    platform_name=platform,
                    role="unclaimed workspace parent",
                )
                _require_real_directory(
                    path,
                    root_observed,
                    platform_name=platform,
                    role="unclaimed workspace root",
                )
                if not _same_path_identity(
                    allocated_parent_identity,
                    parent_observed,
                ):
                    raise UnsafeOwnedWorkspace(
                        "unclaimed workspace parent identity changed before "
                        f"rollback: {parent_path!r}"
                    )
                if not _same_path_identity(
                    allocated_root_identity,
                    root_observed,
                ):
                    raise UnsafeOwnedWorkspace(
                        "unclaimed workspace root identity changed before "
                        f"rollback: {path!r}"
                    )
                os.rmdir(path)
            except BaseException as exc:
                rollback_error = exc
        try:
            absent = repository_path_absent(path)
        except BaseException as proof_error:
            if rollback_error is not None:
                note_cleanup_failure(
                    primary,
                    "RepositoryWorkspaceAllocator rollback failed while "
                    "preserving the capture exception: "
                    + _cleanup_exception_summary(rollback_error),
                )
            note_cleanup_failure(
                primary,
                "RepositoryWorkspaceAllocator absence proof failed while "
                "preserving the capture exception: "
                + _cleanup_exception_summary(proof_error),
            )
        else:
            if absent is not True:
                if rollback_error is not None:
                    note_cleanup_failure(
                        primary,
                        "RepositoryWorkspaceAllocator rollback failed while "
                        "preserving the capture exception: "
                        + _cleanup_exception_summary(rollback_error),
                    )
                note_cleanup_failure(
                    primary,
                    "RepositoryWorkspaceAllocator rollback returned without "
                    "proving absence of the unclaimed workspace",
                )
        raise


def _same_path_identity(
    expected: _PathIdentity,
    observed: os.stat_result,
) -> bool:
    return expected == _PathIdentity.capture(observed)


def _validate_owned_workspace(lease: _OwnedWorkspaceLease) -> None:
    try:
        parent_observed = os.lstat(lease.parent_path)
        root_observed = os.lstat(lease.root_path)
    except OSError as exc:
        raise UnsafeOwnedWorkspace(
            "cannot re-establish the allocated workspace identity before cleanup"
        ) from exc

    _require_real_directory(
        lease.parent_path,
        parent_observed,
        platform_name=lease.platform_name,
        role="owned workspace parent",
    )
    _require_real_directory(
        lease.root_path,
        root_observed,
        platform_name=lease.platform_name,
        role="owned workspace root",
    )
    if not _same_path_identity(lease.parent_identity, parent_observed):
        raise UnsafeOwnedWorkspace(
            f"owned workspace parent identity changed: {lease.parent_path!r}"
        )
    if not _same_path_identity(lease.root_identity, root_observed):
        raise UnsafeOwnedWorkspace(
            f"owned workspace root identity changed: {lease.root_path!r}"
        )


def _canonical_cleanup_path(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _confined_workspace_components(
    lease: _OwnedWorkspaceLease,
    failed_path: str,
) -> tuple[str, ...]:
    root = _canonical_cleanup_path(lease.root_path)
    target = _canonical_cleanup_path(failed_path)
    try:
        common = os.path.commonpath((root, target))
    except ValueError as exc:
        raise UnsafeOwnedWorkspace(
            f"cleanup retry escaped the owned workspace: {failed_path!r}"
        ) from exc
    if common != root:
        raise UnsafeOwnedWorkspace(
            f"cleanup retry escaped the owned workspace: {failed_path!r}"
        )

    relative = os.path.relpath(target, root)
    if relative == os.curdir:
        return (lease.root_path,)
    components = [lease.root_path]
    current = lease.root_path
    for part in relative.split(os.sep):
        if part in {"", os.curdir, os.pardir}:
            raise UnsafeOwnedWorkspace(
                f"cleanup retry used an unsafe path component: {failed_path!r}"
            )
        current = os.path.join(current, part)
        components.append(current)
    return tuple(components)


def _repair_windows_readonly_entry(
    lease: _OwnedWorkspaceLease,
    failed_path: str,
) -> bool:
    """Clear READONLY only after revalidating a confined, non-reparse object.

    Windows does not provide ``os.chmod(..., follow_symlinks=False)`` on the
    supported Python versions.  The verifier therefore requires a quiescent
    process tree, revalidates every observed component, and fails closed on any
    symlink/reparse object.  This is a bounded best-effort check, not an atomic
    Win32 handle guarantee against a concurrent path-replacement race.
    """

    _validate_owned_workspace(lease)
    components = _confined_workspace_components(lease, failed_path)
    final_observed: os.stat_result | None = None
    for index, component in enumerate(components):
        try:
            observed = os.lstat(component)
        except OSError as exc:
            raise UnsafeOwnedWorkspace(
                f"cannot classify cleanup retry target: {failed_path!r}"
            ) from exc
        if stat.S_ISLNK(observed.st_mode) or _windows_reparse_observed(observed):
            raise UnsafeOwnedWorkspace(
                "refusing to repair a symlink, junction, or reparse object "
                f"during owned workspace cleanup: {component!r}"
            )
        if index < len(components) - 1 and not stat.S_ISDIR(observed.st_mode):
            raise UnsafeOwnedWorkspace(
                f"cleanup retry traversed a non-directory: {component!r}"
            )
        final_observed = observed

    assert final_observed is not None
    if not (
        stat.S_ISREG(final_observed.st_mode)
        or stat.S_ISDIR(final_observed.st_mode)
    ):
        raise UnsafeOwnedWorkspace(
            "refusing to repair a non-file, non-directory cleanup target: "
            f"{failed_path!r}"
        )
    if stat.S_ISREG(final_observed.st_mode) and final_observed.st_nlink != 1:
        raise UnsafeOwnedWorkspace(
            "refusing to repair a multiply linked file during owned workspace "
            f"cleanup: {failed_path!r}"
        )
    file_attributes = getattr(final_observed, "st_file_attributes", None)
    if file_attributes is None:
        readonly_observed = not bool(final_observed.st_mode & stat.S_IWRITE)
    else:
        readonly_flag = getattr(stat, "FILE_ATTRIBUTE_READONLY", 0x1)
        readonly_observed = bool(file_attributes & readonly_flag)
    if not readonly_observed:
        return False
    os.chmod(failed_path, final_observed.st_mode | stat.S_IWRITE)
    return True


def _remove_owned_workspace_tree(
    path: _OwnedWorkspacePath,
    *,
    remove_tree: RemoveTree,
    path_absent: PathAbsent,
) -> None:
    """Remove one claimed workspace, repair Windows READONLY, and prove absence."""

    if not isinstance(path, _OwnedWorkspacePath):
        raise TypeError("owned workspace removal requires an allocated lease")
    lease = path._owned_workspace_lease
    if path_absent(path) is True:
        return
    _validate_owned_workspace(lease)
    repaired_paths: set[str] = set()

    while True:
        try:
            remove_tree(path)
            break
        except PermissionError as exc:
            if lease.platform_name != "nt":
                raise
            failed_path = exc.filename
            if not isinstance(failed_path, str):
                raise
            canonical = _canonical_cleanup_path(failed_path)
            if canonical in repaired_paths:
                raise
            if len(repaired_paths) >= _MAX_WINDOWS_READONLY_REPAIRS:
                raise UnsafeOwnedWorkspace(
                    "owned workspace cleanup exceeded the bounded Windows "
                    "READONLY repair limit"
                ) from exc
            if not _repair_windows_readonly_entry(lease, failed_path):
                raise
            repaired_paths.add(canonical)

    if path_absent(path) is not True:
        raise OwnedWorkspaceRemovalUnproven(
            "recursive removal returned without proving absence of the "
            f"judge-owned workspace root: {lease.root_path!r}"
        )


def _unsafe_windows_copy_reparse(path: str) -> bool:
    """Whether ``copytree`` could dereference one non-symlink reparse object."""

    is_junction = getattr(os.path, "isjunction", None)
    try:
        if callable(is_junction) and is_junction(path):
            return True
        info = os.lstat(path)
    except OSError as exc:
        raise UnsafeRepositoryTree(
            f"cannot classify repository path before copying: {path!r} ({exc})"
        ) from exc

    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if not getattr(info, "st_file_attributes", 0) & reparse_flag:
        return False

    # A real Windows symlink is preserved by copytree(symlinks=True). Junctions
    # and other reparse tags are not guaranteed that treatment and therefore
    # must fail closed instead of materializing their targets.
    symlink_tag = getattr(stat, "IO_REPARSE_TAG_SYMLINK", 0xA000000C)
    return not (
        stat.S_ISLNK(info.st_mode)
        or getattr(info, "st_reparse_tag", None) == symlink_tag
    )


def _unsafe_windows_copy_root(path: str) -> bool:
    """Whether ``copytree`` would follow a Windows reparse/symlink root."""

    is_junction = getattr(os.path, "isjunction", None)
    try:
        if callable(is_junction) and is_junction(path):
            return True
        info = os.lstat(path)
    except OSError as exc:
        raise UnsafeRepositoryTree(
            f"cannot classify repository root before copying: {path!r} ({exc})"
        ) from exc

    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & reparse_flag
    )


def _guard_windows_copy_ignore(
    ignore: CopyIgnore,
    *,
    unsafe_reparse_probe: UnsafeReparseProbe,
) -> CopyIgnore:
    """Reject non-ignored reparse objects at each ``copytree`` directory visit."""

    def guarded(directory: str, names: list[str]) -> Iterable[str]:
        ignored = list(ignore(directory, names))
        ignored_names = set(ignored)
        for name in names:
            if name in ignored_names:
                continue
            path = os.path.join(directory, name)
            if unsafe_reparse_probe(path):
                raise UnsafeRepositoryTree(
                    "refusing to copy a Windows junction or non-symlink "
                    f"reparse object: {path!r}"
                )
        return ignored

    return guarded


def copy_repo_tree(
    src: str,
    dst: str,
    *,
    copy_ignore: tuple[str, ...] = COPY_IGNORE,
    platform_name: str | None = None,
    unsafe_reparse_probe: UnsafeReparseProbe | None = None,
    unsafe_root_reparse_probe: UnsafeReparseProbe | None = None,
    copytree: CopyTree | None = None,
    ignore_patterns: IgnorePatterns | None = None,
) -> None:
    """Copy retained repository entries into one throwaway working tree.

    ``symlinks=True`` preserves dangling links and prevents copying the contents
    of an absolute link target into the candidate tree. Regular-file metadata,
    including executable bits, continues to be copied through ``copytree``'s
    default ``copy2`` operation. On Windows, each visited directory rejects
    junctions and other non-symlink reparse objects before ``copytree`` can
    follow them. The repository root itself rejects every symlink/reparse
    object because ``copytree`` opens that root before child-link preservation
    applies.

    The source must remain quiescent for the duration of this operation. These
    path checks run at each ``copytree`` visit but are not an atomic filesystem
    snapshot and do not close a hostile scan-to-open replacement race.
    """

    copytree_provider: CopyTree = shutil.copytree if copytree is None else copytree
    ignore_patterns_provider: IgnorePatterns = (
        shutil.ignore_patterns if ignore_patterns is None else ignore_patterns
    )
    platform = os.name if platform_name is None else platform_name
    ignore = ignore_patterns_provider(*copy_ignore)
    if platform == "nt":
        probe = (
            _unsafe_windows_copy_reparse
            if unsafe_reparse_probe is None
            else unsafe_reparse_probe
        )
        if unsafe_root_reparse_probe is not None:
            root_probe = unsafe_root_reparse_probe
        elif unsafe_reparse_probe is not None:
            root_probe = probe
        else:
            root_probe = _unsafe_windows_copy_root
        if root_probe(src):
            raise UnsafeRepositoryTree(
                "refusing to follow a Windows symlink or reparse repository "
                f"root: {src!r}"
            )
        ignore = _guard_windows_copy_ignore(
            ignore,
            unsafe_reparse_probe=probe,
        )
    copytree_provider(
        src,
        dst,
        symlinks=True,
        ignore=ignore,
    )


def note_cleanup_failure(primary: BaseException, message: str) -> None:
    """Attach secondary cleanup diagnostics without replacing ``primary``."""

    try:
        message = _bounded_cleanup_diagnostic(message)
        add_note = getattr(primary, "add_note", None)
        if callable(add_note):
            add_note(message)
            return
        notes = getattr(primary, "__notes__", None)
        if isinstance(notes, list):
            notes.append(message)
        else:
            # Python 3.10 has no add_note(), but BaseException permits a
            # machine-readable notes attribute for callers and tests.
            primary.__dict__["__notes__"] = [message]
    except BaseException:
        # Cleanup diagnostics are secondary by contract. Even a hostile or
        # constrained exception object cannot replace the primary failure.
        pass


_MAX_CLEANUP_DIAGNOSTIC_CHARS = 2_000
_MAX_CALLBACK_FAILURE_SUFFIX_CHARS = 1_000
_CLEANUP_DIAGNOSTIC_ELLIPSIS = "..."


def _exact_cleanup_text(value: object) -> str:
    """Normalize arbitrary text to an exact built-in ``str`` without hooks."""

    try:
        if isinstance(value, str):
            normalized = value if type(value) is str else str.__str__(value)
        else:
            rendered = str(value)
            normalized = (
                rendered
                if type(rendered) is str
                else str.__str__(rendered)
            )
    except BaseException:
        return "<unprintable>"
    return normalized if type(normalized) is str else "<unprintable>"


def _bounded_cleanup_text(message: object, *, limit: int) -> str:
    """Return exact text truncated to ``limit`` without subclass hooks."""

    normalized = _exact_cleanup_text(message)
    if len(normalized) <= limit:
        return normalized
    retained = limit - len(_CLEANUP_DIAGNOSTIC_ELLIPSIS)
    if retained <= 0:
        return _CLEANUP_DIAGNOSTIC_ELLIPSIS[:limit]
    return normalized[:retained] + _CLEANUP_DIAGNOSTIC_ELLIPSIS


def _bounded_cleanup_diagnostic(message: object) -> str:
    """Return one deterministic, bounded cleanup diagnostic."""

    return _bounded_cleanup_text(
        message,
        limit=_MAX_CLEANUP_DIAGNOSTIC_CHARS,
    )


def _bounded_cleanup_diagnostic_with_suffix(
    message: object,
    suffix: object,
) -> str:
    """Bound a diagnostic while retaining a higher-priority suffix."""

    normalized_suffix = _bounded_cleanup_text(
        suffix,
        limit=_MAX_CALLBACK_FAILURE_SUFFIX_CHARS,
    )
    prefix_limit = _MAX_CLEANUP_DIAGNOSTIC_CHARS - len(normalized_suffix)
    normalized_message = _bounded_cleanup_text(message, limit=prefix_limit)
    return normalized_message + normalized_suffix


def _exception_type_name(error: BaseException) -> str:
    """Return an exception type name without consulting the exception instance."""

    try:
        name = type(error).__name__
    except BaseException:
        return "BaseException"
    return name if type(name) is str else "BaseException"


def _cleanup_exception_summary(error: BaseException) -> str:
    """Describe a cleanup failure without trusting its ``__str__`` method."""

    error_type = _exception_type_name(error)
    try:
        rendered = str(error)
        detail = _exact_cleanup_text(rendered)
    except BaseException as stringify_error:
        detail = (
            "<unprintable; __str__ raised "
            f"{_exception_type_name(stringify_error)}>"
        )
    return f"{error_type}: {detail}"


def _report_cleanup_failure(
    target: BaseException,
    message: str,
    *,
    note_failure: NoteFailure,
) -> None:
    """Report one bounded diagnostic without changing exception precedence."""

    diagnostic = _bounded_cleanup_diagnostic(message)
    try:
        note_failure(target, diagnostic)
    except BaseException as report_error:
        callback_suffix = (
            " [cleanup diagnostic callback failed: "
            + _cleanup_exception_summary(report_error)
            + "]"
        )
        fallback = _bounded_cleanup_diagnostic_with_suffix(
            diagnostic,
            callback_suffix,
        )
        try:
            # The built-in reporter is fail-safe, but retain this outer guard so
            # even a runtime rebind cannot replace the exception being reported.
            note_cleanup_failure(target, fallback)
        except BaseException:
            pass


def repository_path_absent(path: str) -> bool:
    """Return true only after one positive root-path absence observation."""

    try:
        os.lstat(path)
    except FileNotFoundError:
        return True
    except OSError:
        # Permission, malformed-path, and other lookup failures are doubt, not
        # proof that a judge-owned workspace disappeared.
        return False
    return False


def cleanup_repo_workspaces(
    workspaces: tuple[tuple[str, str | None], ...],
    *,
    primary: BaseException | None,
    remove_tree: RemoveTree | None = None,
    path_absent: PathAbsent | None = None,
    note_failure: NoteFailure | None = None,
    owner_name: str = "RepoVerifier",
) -> None:
    """Remove all owned workspaces with explicit exception precedence.

    Every path is attempted. With no active exception, the first cleanup
    failure remains visible and later failures are attached as notes. During
    exception unwinding, the exact active exception remains primary and
    receives one note per cleanup failure.
    """

    if remove_tree is None:
        remove_tree = shutil.rmtree
    if path_absent is None:
        # Resolve the module provider at call time so tests/adopters retain a
        # live seam around the new absence observation.
        path_absent = repository_path_absent
    if note_failure is None:
        note_failure = note_cleanup_failure

    safe_owner_name = _exact_cleanup_text(owner_name)
    failures: list[tuple[str, BaseException]] = []
    for label, path in workspaces:
        safe_label = _exact_cleanup_text(label)
        if path is None:
            continue
        try:
            if isinstance(path, _OwnedWorkspacePath):
                _remove_owned_workspace_tree(
                    path,
                    remove_tree=remove_tree,
                    path_absent=path_absent,
                )
            else:
                # Plain strings retain the historical compatibility seam.
                # Production allocation claims its roots before they reach
                # this branch; this is not an arbitrary-path force remover.
                remove_tree(path)
        except FileNotFoundError as exc:
            # rmtree can surface FileNotFoundError for a raced child while the
            # workspace root remains. Only a fresh positive root observation
            # makes this an idempotent-success case.
            try:
                if path_absent(path) is True:
                    continue
            except BaseException as proof_error:
                failures.append((safe_label, proof_error))
                continue
            failures.append((safe_label, exc))
        except BaseException as exc:
            failures.append((safe_label, exc))

    if not failures:
        return

    if primary is not None:
        for label, cleanup_error in failures:
            _report_cleanup_failure(
                primary,
                safe_owner_name
                + " "
                + label
                + " cleanup failed while preserving the primary exception: "
                + _cleanup_exception_summary(cleanup_error),
                note_failure=note_failure,
            )
        return

    first_label, first_error = failures[0]
    _report_cleanup_failure(
        first_error,
        safe_owner_name + " " + first_label + " cleanup failed",
        note_failure=note_failure,
    )
    for label, cleanup_error in failures[1:]:
        _report_cleanup_failure(
            first_error,
            "Additional "
            + safe_owner_name
            + " "
            + label
            + " cleanup failure: "
            + _cleanup_exception_summary(cleanup_error),
            note_failure=note_failure,
        )
    raise first_error


__all__ = (
    "COPY_IGNORE",
    "OwnedWorkspaceRemovalUnproven",
    "UnsafeRepositoryTree",
    "UnsafeOwnedWorkspace",
    "allocate_owned_workspace",
    "cleanup_repo_workspaces",
    "copy_repo_tree",
    "note_cleanup_failure",
    "repository_path_absent",
)
