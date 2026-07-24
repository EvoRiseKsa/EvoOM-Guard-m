# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Typed ownership of accepted repository verifier-pack continuity.

This owner freezes the accepted pack identity, verifies the judge-owned
snapshot immediately before execution and after a completed execution, and
enforces a monotonic checkpoint sequence.  It does not execute the pack, read
JUnit, compose a verdict, project wire evidence, or clean a workspace.

The snapshot verifier is resolved at each operation so RepoVerifier's
historical monkeypatch seam remains live.  A controlled ``PackManifestError``
becomes sticky typed failure state.  Any other provider failure is re-raised
unchanged after the owner enters a terminal state, preserving the outer
workspace-cleanup and primary-exception contracts.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal, Protocol

from evoom_guard.pack_manifest import PackManifestError

PackContinuityCheckpoint = Literal[
    "before_execution",
    "after_execution",
]
PackContinuityPhase = Literal[
    "accepted",
    "pre_execution_verified",
    "delivered",
    "failed",
]
PackContinuityFailureKind = Literal["snapshot_changed"]
ConcretePackIdentity = tuple[str, dict[str, Any] | None]


class VerifyPackSnapshot(Protocol):
    """Verify one snapshot against its accepted concrete identity."""

    def __call__(
        self,
        snapshot: str,
        expected: ConcretePackIdentity,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class AcceptedRepoPackIdentity:
    """Immutable judgment-local copy of an admitted verifier-pack identity."""

    sha256: str
    manifest: Mapping[str, Any] | None

    def __post_init__(self) -> None:
        if self.manifest is None:
            return
        frozen = MappingProxyType(copy.deepcopy(dict(self.manifest)))
        object.__setattr__(self, "manifest", frozen)

    def concrete(self) -> ConcretePackIdentity:
        """Return an isolated value in ``verify_pack_snapshot``'s ABI shape."""

        manifest = (
            None
            if self.manifest is None
            else copy.deepcopy(dict(self.manifest))
        )
        return self.sha256, manifest


@dataclass(frozen=True, slots=True)
class RepoPackContinuityRequest:
    """The exact accepted snapshot and identity to bind around execution."""

    pack_snapshot: str
    identity: AcceptedRepoPackIdentity


@dataclass(frozen=True, slots=True)
class RepoPackContinuityServices:
    """Live judge-owned verifier provider."""

    verify_snapshot: Callable[[], VerifyPackSnapshot]


@dataclass(frozen=True, slots=True)
class RepoPackContinuityFailure:
    """One fail-closed accepted-pack continuity observation."""

    kind: PackContinuityFailureKind
    checkpoint: PackContinuityCheckpoint
    diagnostics: str


@dataclass(slots=True)
class RepoPackContinuity:
    """Mutable judgment-local accepted-pack checkpoint state."""

    request: RepoPackContinuityRequest
    services: RepoPackContinuityServices
    phase: PackContinuityPhase = field(init=False, default="accepted")
    failure: RepoPackContinuityFailure | None = field(
        init=False,
        default=None,
    )
    provider_failure: BaseException | None = field(
        init=False,
        default=None,
        repr=False,
    )

    @property
    def identity(self) -> AcceptedRepoPackIdentity:
        """Return the immutable accepted identity owned by this judgment."""

        return self.request.identity

    def _require_phase(
        self,
        expected: PackContinuityPhase,
        operation: str,
    ) -> None:
        if self.phase != expected:
            raise RuntimeError(
                f"repository pack continuity cannot {operation} from "
                f"phase {self.phase!r}; expected {expected!r}"
            )

    def _sticky_terminal(self) -> RepoPackContinuityFailure | None:
        if self.failure is not None:
            return self.failure
        if self.provider_failure is not None:
            raise self.provider_failure
        return None

    def _verify(
        self,
        *,
        checkpoint: PackContinuityCheckpoint,
        expected_phase: PackContinuityPhase,
        delivered_phase: PackContinuityPhase,
        diagnostics_prefix: str,
    ) -> RepoPackContinuityFailure | None:
        sticky = self._sticky_terminal()
        if sticky is not None:
            return sticky
        self._require_phase(expected_phase, f"verify {checkpoint.replace('_', ' ')}")
        try:
            self.services.verify_snapshot()(
                self.request.pack_snapshot,
                self.identity.concrete(),
            )
        except PackManifestError as exc:
            failure = RepoPackContinuityFailure(
                kind="snapshot_changed",
                checkpoint=checkpoint,
                diagnostics=f"{diagnostics_prefix}: {exc}",
            )
            self.failure = failure
            self.phase = "failed"
            return failure
        except BaseException as exc:
            self.provider_failure = exc
            self.phase = "failed"
            raise
        self.phase = delivered_phase
        return None

    def verify_before_execution(self) -> RepoPackContinuityFailure | None:
        """Bind the accepted snapshot immediately before pack execution."""

        return self._verify(
            checkpoint="before_execution",
            expected_phase="accepted",
            delivered_phase="pre_execution_verified",
            diagnostics_prefix="verifier pack was changed before execution",
        )

    def verify_after_execution(self) -> RepoPackContinuityFailure | None:
        """Bind the same snapshot after completed execution, before JUnit."""

        return self._verify(
            checkpoint="after_execution",
            expected_phase="pre_execution_verified",
            delivered_phase="delivered",
            diagnostics_prefix="verifier pack changed while executing",
        )


__all__ = [
    "AcceptedRepoPackIdentity",
    "RepoPackContinuity",
    "RepoPackContinuityFailure",
    "RepoPackContinuityRequest",
    "RepoPackContinuityServices",
]
