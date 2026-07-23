# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Dependency-free input contracts for one Guard judgment."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from evoom_guard.domain.policy import EffectivePolicy


@dataclass(frozen=True, slots=True)
class RepositoryInput:
    """The trusted base repository supplied to Guard."""

    path: str


@dataclass(frozen=True, slots=True)
class CandidateInput:
    """Candidate text plus structured edit/deletion inputs."""

    text: str
    deleted_paths: tuple[str, ...]
    file_blocks: Mapping[str, str] | None

    def __post_init__(self) -> None:
        """Own immutable snapshots of caller-supplied candidate collections."""

        object.__setattr__(self, "deleted_paths", tuple(self.deleted_paths))
        if self.file_blocks is not None:
            object.__setattr__(
                self,
                "file_blocks",
                MappingProxyType(dict(self.file_blocks)),
            )


@dataclass(frozen=True, slots=True)
class SourceIdentity:
    """Optional immutable source and tree identities bound into evidence."""

    base_sha: str | None
    head_sha: str | None
    base_tree_sha: str | None
    head_tree_sha: str | None


@dataclass(frozen=True, slots=True)
class GuardRequest:
    """Owned inputs captured after Guard's public scalar checks."""

    repository: RepositoryInput
    candidate: CandidateInput
    source: SourceIdentity
    policy: EffectivePolicy
    verifier_pack_path: str | None
    collect_diff_coverage: bool
