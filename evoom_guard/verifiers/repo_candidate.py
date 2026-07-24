# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Repository-candidate admission and filesystem coordination.

This owner is deliberately narrower than :mod:`repo_verifier`.  It owns three
ordered operations:

* parse and admit candidate edits before any workspace is allocated;
* copy and materialize an admitted candidate after ``RepoVerifier`` allocates
  its workspace;
* apply admitted deletions only after ``RepoVerifier`` completes verifier-pack
  intake.

Workspace allocation, verifier-pack intake/execution, runtime identity,
repository-suite execution, final projection, and ``finally`` cleanup remain
with ``RepoVerifier``.  Every effect is injected through a provider so the
legacy facade resolves its historical monkeypatch seams at the original
operation site rather than snapshotting them at request construction.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

from evoom_guard.candidate import PatchBlock
from evoom_guard.contracts import VerdictResult


class ParseFileBlocks(Protocol):
    """Parse strict full-file candidate blocks."""

    def __call__(self, hypothesis: str) -> dict[str, str]: ...


class ParsePatchBlocks(Protocol):
    """Parse strict ordered patch blocks."""

    def __call__(self, hypothesis: str) -> list[PatchBlock]: ...


class ParseBlocksLenient(Protocol):
    """Recover candidate blocks from the historical lenient grammar."""

    def __call__(
        self,
        hypothesis: str,
        default_path: str | None = None,
    ) -> tuple[dict[str, str], list[PatchBlock]]: ...


class RejectCandidatePaths(Protocol):
    """Apply the established repository harness path policy."""

    def __call__(
        self,
        paths: Sequence[str],
        extra: Sequence[str],
        *,
        allow_new_tests: bool = False,
        new_paths: frozenset[str] = frozenset(),
        allow: Sequence[str] = (),
        local_action_dirs: Sequence[str] = (),
        strict_harness: bool = False,
    ) -> VerdictResult | None: ...


class ApplyCandidateEdits(Protocol):
    """Materialize candidate FILE/PATCH edits into one copied repository."""

    def __call__(
        self,
        root: str,
        file_blocks: dict[str, str],
        patch_blocks: list[PatchBlock],
    ) -> str | None: ...


@dataclass(frozen=True, slots=True)
class RepoCandidateAdmissionRequest:
    """Immutable top-level inputs to candidate admission."""

    hypothesis: str
    repo_path: str


@dataclass(frozen=True, slots=True)
class RepoCandidateAdmissionServices:
    """Live providers used by candidate parsing and policy admission."""

    is_directory: Callable[[], Callable[[str], bool]]
    deleted_paths: Callable[[], Iterable[object]]
    file_blocks_override: Callable[[], object]
    target_files: Callable[[], Iterable[object]]
    extra_protected: Callable[[], Sequence[str]]
    allow: Callable[[], Sequence[str]]
    allow_new_tests: Callable[[], bool]
    strict_harness: Callable[[], bool]
    parse_file_blocks: Callable[[], ParseFileBlocks]
    parse_patch_blocks: Callable[[], ParsePatchBlocks]
    parse_blocks_lenient: Callable[[], ParseBlocksLenient]
    discover_local_action_dirs: Callable[[], Callable[[str], Sequence[str]]]
    is_safe_relpath: Callable[[], Callable[[str], bool]]
    join_path: Callable[[], Callable[..., str]]
    path_exists: Callable[[], Callable[[str], bool]]
    reject_paths: Callable[[], RejectCandidatePaths]


@dataclass(frozen=True, slots=True)
class AdmittedRepoCandidate:
    """Owned, immutable candidate facts admitted for materialization."""

    repo_path: str
    file_blocks: Mapping[str, str]
    patch_blocks: tuple[PatchBlock, ...]
    deleted_paths: tuple[str, ...]
    files_changed: tuple[str, ...]
    strict_harness: bool


@dataclass(frozen=True, slots=True)
class RepoCandidateAdmissionOutcome:
    """Exactly one admitted candidate or terminal historical verdict."""

    candidate: AdmittedRepoCandidate | None = None
    terminal_result: VerdictResult | None = None

    def __post_init__(self) -> None:
        if (self.candidate is None) == (self.terminal_result is None):
            raise ValueError(
                "candidate admission requires exactly one candidate or terminal result"
            )


@dataclass(frozen=True, slots=True)
class RepoCandidateMaterializationRequest:
    """Immutable inputs to candidate copy/materialization."""

    candidate_copy: str
    candidate: AdmittedRepoCandidate


@dataclass(frozen=True, slots=True)
class RepoCandidateMaterializationServices:
    """Live repository-copy and edit-materialization providers."""

    copy_repo_tree: Callable[[], Callable[[str, str], None]]
    apply_candidate_edits: Callable[[], ApplyCandidateEdits]


@dataclass(frozen=True, slots=True)
class RepoCandidateMaterializationOutcome:
    """Exactly one materialized candidate or terminal historical verdict."""

    candidate: AdmittedRepoCandidate | None = None
    terminal_result: VerdictResult | None = None

    def __post_init__(self) -> None:
        if (self.candidate is None) == (self.terminal_result is None):
            raise ValueError(
                "candidate materialization requires exactly one candidate "
                "or terminal result"
            )


@dataclass(frozen=True, slots=True)
class RepoCandidateDeletionRequest:
    """Immutable inputs to post-pack candidate deletion application."""

    candidate_copy: str
    candidate: AdmittedRepoCandidate


@dataclass(frozen=True, slots=True)
class RepoCandidateDeletionServices:
    """Live contained-deletion providers."""

    is_safe_relpath: Callable[[], Callable[[str], bool]]
    delete_path: Callable[[], Callable[[str, str], bool]]
    deletion_errors: Callable[[], tuple[type[BaseException], ...]]


@dataclass(frozen=True, slots=True)
class RepoCandidateDeletionOutcome:
    """Exactly one deletion-complete candidate or terminal verdict."""

    candidate: AdmittedRepoCandidate | None = None
    terminal_result: VerdictResult | None = None

    def __post_init__(self) -> None:
        if (self.candidate is None) == (self.terminal_result is None):
            raise ValueError(
                "candidate deletion requires exactly one candidate or terminal result"
            )


def _terminal_admission(result: VerdictResult) -> RepoCandidateAdmissionOutcome:
    return RepoCandidateAdmissionOutcome(terminal_result=result)


def _owned_candidate(
    *,
    repo_path: str,
    file_blocks: Mapping[str, str],
    patch_blocks: Sequence[PatchBlock],
    deleted_paths: Sequence[str],
    files_changed: Sequence[str],
    strict_harness: bool,
) -> AdmittedRepoCandidate:
    return AdmittedRepoCandidate(
        repo_path=repo_path,
        file_blocks=MappingProxyType(dict(file_blocks)),
        patch_blocks=tuple(patch_blocks),
        deleted_paths=tuple(deleted_paths),
        files_changed=tuple(files_changed),
        strict_harness=strict_harness,
    )


def admit_repo_candidate(
    request: RepoCandidateAdmissionRequest,
    *,
    services: RepoCandidateAdmissionServices,
) -> RepoCandidateAdmissionOutcome:
    """Parse and admit a repository candidate before workspace allocation."""

    repo_path = request.repo_path
    if not repo_path or not services.is_directory()(repo_path):
        raise ValueError(
            f"problem['repo_path'] is not a directory: {repo_path!r}"
        )

    deleted_paths = [
        str(path)
        for path in services.deleted_paths()
        if str(path).strip()
    ]

    file_blocks_override = services.file_blocks_override()
    if isinstance(file_blocks_override, dict):
        # Mapping presence selects the structured transport even when it carries
        # no file writes.  Falling back to the hypothesis would let stale or
        # adversarial marker text override the caller's explicit candidate mode.
        file_blocks = {
            str(path): str(content)
            for path, content in file_blocks_override.items()
        }
        patch_blocks: list[PatchBlock] = []
    else:
        file_blocks = services.parse_file_blocks()(request.hypothesis)
        patch_blocks = services.parse_patch_blocks()(request.hypothesis)
        if not file_blocks and not patch_blocks:
            targets = [
                str(target)
                for target in services.target_files()
                if str(target).strip()
            ]
            default_path = targets[0] if len(targets) == 1 else None
            file_blocks, patch_blocks = services.parse_blocks_lenient()(
                request.hypothesis,
                default_path,
            )

    if not file_blocks and not patch_blocks and not deleted_paths:
        return _terminal_admission(
            VerdictResult(
                passed=False,
                score=0.02,
                diagnostics=(
                    "no parseable blocks; expected "
                    "<<<FILE: path>>> … <<<END FILE>>> or "
                    "<<<PATCH: path>>> <<<SEARCH>>> … <<<REPLACE>>> … <<<END PATCH>>>"
                ),
                artifact={"files_changed": []},
            )
        )

    extra = tuple(services.extra_protected())
    allow = tuple(services.allow())
    local_action_dirs = services.discover_local_action_dirs()(repo_path)
    changed = sorted(
        set(file_blocks) | {block.path for block in patch_blocks}
    )
    allow_new_tests = services.allow_new_tests()
    strict_harness = services.strict_harness()
    new_paths = frozenset(
        path
        for path in changed
        if services.is_safe_relpath()(path)
        and not services.path_exists()(
            services.join_path()(repo_path, path)
        )
    )
    rejection = services.reject_paths()(
        changed,
        extra,
        allow_new_tests=allow_new_tests,
        new_paths=new_paths,
        allow=allow,
        local_action_dirs=local_action_dirs,
        strict_harness=strict_harness,
    )
    if rejection is not None:
        return _terminal_admission(rejection)

    if deleted_paths:
        deletion_rejection = services.reject_paths()(
            deleted_paths,
            extra,
            allow=allow,
            local_action_dirs=local_action_dirs,
            strict_harness=strict_harness,
        )
        if deletion_rejection is not None:
            return _terminal_admission(deletion_rejection)

    return RepoCandidateAdmissionOutcome(
        candidate=_owned_candidate(
            repo_path=repo_path,
            file_blocks=file_blocks,
            patch_blocks=patch_blocks,
            deleted_paths=deleted_paths,
            files_changed=changed,
            strict_harness=strict_harness,
        )
    )


def materialize_repo_candidate(
    request: RepoCandidateMaterializationRequest,
    *,
    services: RepoCandidateMaterializationServices,
) -> RepoCandidateMaterializationOutcome:
    """Copy then apply one admitted candidate in the historical order."""

    candidate = request.candidate
    services.copy_repo_tree()(candidate.repo_path, request.candidate_copy)
    apply_error = services.apply_candidate_edits()(
        request.candidate_copy,
        dict(candidate.file_blocks),
        list(candidate.patch_blocks),
    )
    if apply_error is not None:
        return RepoCandidateMaterializationOutcome(
            terminal_result=VerdictResult(
                passed=False,
                score=0.08,
                diagnostics=apply_error,
                artifact={"files_changed": list(candidate.files_changed)},
            )
        )
    return RepoCandidateMaterializationOutcome(candidate=candidate)


def apply_repo_candidate_deletions(
    request: RepoCandidateDeletionRequest,
    *,
    services: RepoCandidateDeletionServices,
) -> RepoCandidateDeletionOutcome:
    """Apply admitted deletions after verifier-pack intake."""

    candidate = request.candidate
    try:
        for relative_path in candidate.deleted_paths:
            if not services.is_safe_relpath()(relative_path):
                continue
            services.delete_path()(request.candidate_copy, relative_path)
    except services.deletion_errors() as exc:
        return RepoCandidateDeletionOutcome(
            terminal_result=VerdictResult(
                passed=False,
                score=0.05,
                diagnostics=(
                    "candidate deletion could not be applied safely: "
                    f"{exc}"
                ),
                artifact={
                    "files_changed": list(candidate.files_changed),
                    "files_deleted": [],
                },
            )
        )
    return RepoCandidateDeletionOutcome(candidate=candidate)


__all__ = [
    "AdmittedRepoCandidate",
    "RepoCandidateAdmissionOutcome",
    "RepoCandidateAdmissionRequest",
    "RepoCandidateAdmissionServices",
    "RepoCandidateDeletionOutcome",
    "RepoCandidateDeletionRequest",
    "RepoCandidateDeletionServices",
    "RepoCandidateMaterializationOutcome",
    "RepoCandidateMaterializationRequest",
    "RepoCandidateMaterializationServices",
    "admit_repo_candidate",
    "apply_repo_candidate_deletions",
    "materialize_repo_candidate",
]
