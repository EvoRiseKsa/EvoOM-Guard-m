# ------------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# ------------------------------------------------------------------------------
"""Typed pre-execution admission for candidate repository paths.

This module classifies the complete candidate path set before any candidate
file is materialized or candidate-controlled command starts. It deliberately
owns only path admission: parsing, risk scoring, repository copying, process
execution, verdict composition, and evidence serialization remain with their
existing owners.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from evoom_guard.verifiers.harness_policy import (
    discover_local_action_dirs,
    is_addable_new_test,
    is_allowlist_exemptible,
    is_judge_autoexec,
    is_protected,
    is_protected_ci,
    is_protected_config,
    is_safe_relpath,
    matches_globs,
)

# Reserved namespace from the pre-3.4 in-tree verifier-pack mount. A candidate
# still may not pre-plant it; accepted packs live in a judge-owned snapshot.
VERIFIER_PACK_DIR = "evoguard_verifier_pack"


class _ProtectedConfigCheck(Protocol):
    def __call__(self, path: str, *, strict_harness: bool) -> bool: ...


class _ProtectedCiCheck(Protocol):
    def __call__(
        self, path: str, *, local_action_dirs: tuple[str, ...]
    ) -> bool: ...


class _AddableNewTestCheck(Protocol):
    def __call__(
        self,
        path: str,
        extra: tuple[str, ...],
        *,
        is_new: bool,
        local_action_dirs: tuple[str, ...],
        strict_harness: bool,
    ) -> bool: ...


class _AllowlistExemptibleCheck(Protocol):
    def __call__(
        self,
        path: str,
        *,
        local_action_dirs: tuple[str, ...],
        strict_harness: bool,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class CandidatePreflightRequest:
    """Owned inputs for one deterministic candidate path classification."""

    repo_path: str
    changed_paths: tuple[str, ...]
    deleted_paths: tuple[str, ...] = ()
    protected: tuple[str, ...] = ()
    allow: tuple[str, ...] = ()
    allow_new_tests: bool = False
    strict_harness: bool = False


@dataclass(frozen=True, slots=True)
class CandidatePreflightServices:
    """Injected historical call seams used by the Guard compatibility adapter."""

    path_exists: Callable[[str], bool]
    discover_local_action_dirs: Callable[[str], tuple[str, ...]]
    is_safe_relpath: Callable[[str], bool]
    is_judge_autoexec: Callable[[str], bool]
    is_protected_config: _ProtectedConfigCheck
    is_protected_ci: _ProtectedCiCheck
    is_protected: Callable[[str, tuple[str, ...]], bool]
    is_addable_new_test: _AddableNewTestCheck
    is_allowlist_exemptible: _AllowlistExemptibleCheck
    matches_globs: Callable[[str, tuple[str, ...]], bool]
    verifier_pack_dir: Callable[[], str]


@dataclass(frozen=True, slots=True)
class CandidatePreflight:
    """Immutable classification consumed by Guard before repository execution."""

    changed_paths: tuple[str, ...]
    all_touched_paths: tuple[str, ...]
    unsafe_paths: tuple[str, ...]
    protected_violations: tuple[str, ...]
    safe_deleted_paths: tuple[str, ...]
    new_paths: frozenset[str]
    local_action_dirs: tuple[str, ...]

    @property
    def may_execute(self) -> bool:
        """Whether path admission permits the verifier suite to start."""

        return (
            bool(self.all_touched_paths)
            and not self.unsafe_paths
            and not self.protected_violations
        )


def evaluate_candidate_preflight(
    request: CandidatePreflightRequest,
    *,
    services: CandidatePreflightServices | None = None,
) -> CandidatePreflight:
    """Classify candidate paths with the historical fail-closed ordering.

    ``repo_path`` is inspected only for base-tree path existence and literal
    local-Action references. Both happen before candidate materialization.
    Deletions are checked twice by design: first as part of the complete
    protected-path decision and again when deriving the exact safe deletion
    set passed to the repository verifier.
    """

    if services is None:
        services = CandidatePreflightServices(
            path_exists=lambda path: os.path.exists(path),
            discover_local_action_dirs=lambda repo: discover_local_action_dirs(repo),
            is_safe_relpath=lambda path: is_safe_relpath(path),
            is_judge_autoexec=lambda path: is_judge_autoexec(path),
            is_protected_config=lambda path, *, strict_harness: (
                is_protected_config(path, strict_harness=strict_harness)
            ),
            is_protected_ci=lambda path, *, local_action_dirs: is_protected_ci(
                path, local_action_dirs=local_action_dirs
            ),
            is_protected=lambda path, protected: is_protected(path, protected),
            is_addable_new_test=lambda path, extra, **kwargs: is_addable_new_test(
                path, extra, **kwargs
            ),
            is_allowlist_exemptible=(
                lambda path, **kwargs: is_allowlist_exemptible(path, **kwargs)
            ),
            matches_globs=lambda path, globs: matches_globs(path, globs),
            verifier_pack_dir=lambda: VERIFIER_PACK_DIR,
        )

    changed = request.changed_paths
    deleted = request.deleted_paths
    deleted_touched = tuple(path for path in deleted if path not in changed)
    all_touched = changed + deleted_touched
    unsafe = tuple(
        sorted(
            path
            for path in all_touched
            if not services.is_safe_relpath(path)
        )
    )
    new_paths = frozenset(
        path
        for path in changed
        if services.is_safe_relpath(path)
        and not services.path_exists(os.path.join(request.repo_path, path))
    )

    # Discover from the trusted base tree before candidate files are applied.
    local_action_dirs = services.discover_local_action_dirs(request.repo_path)

    def is_violation(path: str) -> bool:
        verifier_pack_dir = services.verifier_pack_dir()
        if path == verifier_pack_dir or path.startswith(verifier_pack_dir + "/"):
            return True
        if services.is_judge_autoexec(path):
            return True
        if services.is_protected_config(
            path,
            strict_harness=request.strict_harness,
        ) or services.is_protected_ci(path, local_action_dirs=local_action_dirs):
            return True
        if services.is_protected(path, request.protected):
            if request.allow_new_tests and services.is_addable_new_test(
                path,
                request.protected,
                is_new=path in new_paths,
                local_action_dirs=local_action_dirs,
                strict_harness=request.strict_harness,
            ):
                return False
            if not services.is_allowlist_exemptible(
                path,
                local_action_dirs=local_action_dirs,
                strict_harness=request.strict_harness,
            ):
                return True
            return not services.matches_globs(path, request.allow)
        return False

    violations = tuple(sorted(path for path in all_touched if is_violation(path)))
    safe_deleted = tuple(
        sorted(
            path
            for path in deleted
            if services.is_safe_relpath(path) and not is_violation(path)
        )
    )
    return CandidatePreflight(
        changed_paths=changed,
        all_touched_paths=all_touched,
        unsafe_paths=unsafe,
        protected_violations=violations,
        safe_deleted_paths=safe_deleted,
        new_paths=new_paths,
        local_action_dirs=local_action_dirs,
    )


__all__ = [
    "CandidatePreflight",
    "CandidatePreflightRequest",
    "CandidatePreflightServices",
    "VERIFIER_PACK_DIR",
    "evaluate_candidate_preflight",
]
