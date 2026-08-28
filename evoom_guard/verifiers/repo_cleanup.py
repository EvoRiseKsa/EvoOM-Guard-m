# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# -----------------------------------------------------------------------------
"""Repository-verification cleanup effect coordination.

The workspace package owns the cleanup algorithm and absence proof.
``RepoVerifier`` retains its historical facades and outer ``finally``. This
owner resolves the three live effect providers in their established order,
then invokes the workspace cleanup contract without absorbing repository
orchestration, path lifetime, or exception projection.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

CleanupTarget = tuple[str, str | None]
RemoveTree = Callable[[str], None]
NoteFailure = Callable[[BaseException, str], None]


class CleanupWorkspaces(Protocol):
    """Run the established all-workspace cleanup and precedence algorithm."""

    def __call__(
        self,
        workspaces: tuple[CleanupTarget, ...],
        *,
        primary: BaseException | None,
        remove_tree: RemoveTree,
        note_failure: NoteFailure,
        owner_name: str,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class RepoCleanupRequest:
    """The exact judgment-owned targets and active primary exception."""

    workspaces: tuple[CleanupTarget, ...]
    primary: BaseException | None


@dataclass(frozen=True, slots=True)
class RepoCleanupServices:
    """Live providers retained by the ``repo_verifier`` compatibility facade."""

    cleanup_workspaces_provider: Callable[[], CleanupWorkspaces]
    remove_tree_provider: Callable[[], RemoveTree]
    note_failure_provider: Callable[[], NoteFailure]


def cleanup_repo_verification(
    request: RepoCleanupRequest,
    *,
    services: RepoCleanupServices,
) -> None:
    """Resolve cleanup effects in historical order and run the owned contract."""

    cleanup_workspaces = services.cleanup_workspaces_provider()
    remove_tree = services.remove_tree_provider()
    note_failure = services.note_failure_provider()
    cleanup_workspaces(
        request.workspaces,
        primary=request.primary,
        remove_tree=remove_tree,
        note_failure=note_failure,
        owner_name="RepoVerifier",
    )


__all__ = [
    "RepoCleanupRequest",
    "RepoCleanupServices",
    "cleanup_repo_verification",
]
