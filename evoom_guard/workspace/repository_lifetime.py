# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# -----------------------------------------------------------------------------
"""Repository-verification workspace lifetime bookkeeping.

This dependency-free owner records only the judge-owned candidate and verifier-
pack workspace roots. Allocation and cleanup effects remain injected by the
``repo_verifier`` compatibility orchestrator, so provider lookup timing,
exception precedence, and cleanup behavior stay outside this module.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol


class WorkspaceFactory(Protocol):
    """Create one judge-owned workspace using the historical keyword shape."""

    def __call__(self, *, prefix: str) -> str: ...


JoinPath = Callable[[str, str], str]
CleanupTarget = tuple[str, str | None]


@dataclass(slots=True)
class RepositoryWorkspaceLifetime:
    """Paths owned by one repository-verification judgment."""

    candidate_root: str
    candidate_copy: str
    pack_root: str | None = None

    @classmethod
    def create(
        cls,
        *,
        prefix: str,
        create_workspace: WorkspaceFactory,
        join_path: JoinPath,
    ) -> RepositoryWorkspaceLifetime:
        """Allocate the candidate root before the verifier enters its ``try``."""

        candidate_root = create_workspace(prefix=prefix)
        candidate_copy = join_path(candidate_root, "repo")
        return cls(
            candidate_root=candidate_root,
            candidate_copy=candidate_copy,
        )

    def create_pack(
        self,
        prefix: str,
        *,
        create_workspace: WorkspaceFactory,
    ) -> str:
        """Allocate and register the pack root before snapshotting can start."""

        pack_root = create_workspace(prefix=prefix)
        self.pack_root = pack_root
        return pack_root

    def retain_pack_root(self, observed_root: str | None) -> None:
        """Preserve the historical ``observed or callback-created`` selection."""

        self.pack_root = observed_root or self.pack_root

    def cleanup_targets(self) -> tuple[CleanupTarget, CleanupTarget]:
        """Return the exact historical candidate-then-pack cleanup schedule."""

        return (
            ("candidate workspace", self.candidate_root),
            ("verifier-pack snapshot", self.pack_root),
        )


__all__ = ["RepositoryWorkspaceLifetime"]
