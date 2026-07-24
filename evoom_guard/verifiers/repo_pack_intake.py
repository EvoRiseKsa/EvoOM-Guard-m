# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Judge-owned verifier-pack intake for repository verification.

This module owns only admission of an optional verifier pack into a separate
snapshot, including the reserved mount collision and optional digest pin. It
does not execute the pack or the repository suite.

Filesystem observation, workspace allocation, and pack snapshotting are
injected. ``RepoVerifier`` supplies call-through adapters at the historical
operation sites so its established monkeypatch seams remain live.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal

from evoom_guard.pack_manifest import PackManifestError

PackManifest = Mapping[str, Any]
PackIdentity = tuple[str, dict[str, Any] | None]
FailureKind = Literal[
    "reserved_mount_collision",
    "pack_invalid",
    "pack_identity_missing",
    "pack_identity_mismatch",
]


@dataclass(frozen=True, slots=True)
class RepoPackIntakeRequest:
    """Immutable inputs to repository verifier-pack admission."""

    candidate_copy: str
    files_changed: tuple[str, ...]
    pack_dir: str
    expected_pack_sha256: str
    reserved_mount_name: str = "evoguard_verifier_pack"


@dataclass(frozen=True, slots=True)
class RepoPackIntakeServices:
    """Live judge-owned effects needed by pack admission."""

    lexists: Callable[[str], bool]
    create_workspace: Callable[[str], str]
    snapshot_pack: Callable[[str, str], PackIdentity]


@dataclass(frozen=True, slots=True)
class RepoPackIntakeFailure:
    """One historical fail-closed pack-admission outcome."""

    kind: FailureKind
    score: float
    diagnostics: str


@dataclass(frozen=True, slots=True)
class RepoPackIntakeResult:
    """Immutable result of accepting or rejecting the optional pack."""

    pack_workdir: str | None = None
    pack_snapshot: str | None = None
    pack_sha256: str | None = None
    pack_manifest: PackManifest | None = None
    failure: RepoPackIntakeFailure | None = None

    def identity(self) -> PackIdentity | None:
        """Return the accepted identity in the pack verifier's concrete shape."""

        if self.pack_sha256 is None:
            return None
        manifest = (
            None if self.pack_manifest is None else dict(self.pack_manifest)
        )
        return self.pack_sha256, manifest


def _result(
    *,
    pack_workdir: str | None = None,
    pack_snapshot: str | None = None,
    pack_sha256: str | None = None,
    pack_manifest: dict[str, Any] | None = None,
    failure: RepoPackIntakeFailure | None = None,
) -> RepoPackIntakeResult:
    immutable_manifest = (
        None
        if pack_manifest is None
        else MappingProxyType(dict(pack_manifest))
    )
    return RepoPackIntakeResult(
        pack_workdir=pack_workdir,
        pack_snapshot=pack_snapshot,
        pack_sha256=pack_sha256,
        pack_manifest=immutable_manifest,
        failure=failure,
    )


def intake_repo_pack(
    request: RepoPackIntakeRequest,
    *,
    services: RepoPackIntakeServices,
) -> RepoPackIntakeResult:
    """Admit the optional verifier pack without executing candidate code."""

    if request.expected_pack_sha256 and not request.pack_dir:
        return _result(
            failure=RepoPackIntakeFailure(
                kind="pack_identity_missing",
                score=0.0,
                diagnostics=(
                    "an expected verifier-pack SHA-256 was configured but no "
                    "verifier pack was supplied"
                ),
            )
        )
    if not request.pack_dir:
        return _result()

    reserved = os.path.join(request.candidate_copy, request.reserved_mount_name)
    if services.lexists(reserved):
        return _result(
            failure=RepoPackIntakeFailure(
                kind="reserved_mount_collision",
                score=0.05,
                diagnostics=(
                    "the repo already contains 'evoguard_verifier_pack/' — the "
                    "judge-owned pack mount point must not exist in the tree"
                ),
            )
        )

    pack_workdir = services.create_workspace("evo_pack_snapshot_")
    pack_snapshot = os.path.join(pack_workdir, "pack")
    try:
        pack_sha256, pack_manifest = services.snapshot_pack(
            request.pack_dir, pack_snapshot
        )
    except PackManifestError as exc:
        return _result(
            pack_workdir=pack_workdir,
            pack_snapshot=pack_snapshot,
            failure=RepoPackIntakeFailure(
                kind="pack_invalid",
                score=0.0,
                diagnostics=str(exc),
            ),
        )

    if (
        request.expected_pack_sha256
        and pack_sha256.lower() != request.expected_pack_sha256
    ):
        return _result(
            pack_workdir=pack_workdir,
            pack_snapshot=pack_snapshot,
            pack_sha256=pack_sha256,
            pack_manifest=pack_manifest,
            failure=RepoPackIntakeFailure(
                kind="pack_identity_mismatch",
                score=0.0,
                diagnostics=(
                    "verifier-pack identity mismatch: expected "
                    f"{request.expected_pack_sha256}, observed {pack_sha256}"
                ),
            ),
        )

    return _result(
        pack_workdir=pack_workdir,
        pack_snapshot=pack_snapshot,
        pack_sha256=pack_sha256,
        pack_manifest=pack_manifest,
    )


def rejection_artifact(
    request: RepoPackIntakeRequest,
    result: RepoPackIntakeResult,
) -> dict[str, Any]:
    """Build the exact historical artifact for a rejected intake."""

    if result.failure is None:
        raise ValueError("an accepted pack intake has no rejection artifact")
    artifact: dict[str, Any] = {"files_changed": list(request.files_changed)}
    if result.failure.kind == "pack_invalid":
        artifact["outcome"] = "pack_invalid"
    elif result.failure.kind in {
        "pack_identity_missing",
        "pack_identity_mismatch",
    }:
        artifact.update(
            outcome="pack_identity_mismatch",
            expected_verifier_pack_sha256=request.expected_pack_sha256,
        )
        if result.failure.kind == "pack_identity_mismatch":
            artifact.update(
                verifier_pack_sha256=result.pack_sha256,
                verifier_pack_manifest=(
                    None
                    if result.pack_manifest is None
                    else dict(result.pack_manifest)
                ),
            )
    return artifact


__all__ = [
    "RepoPackIntakeFailure",
    "RepoPackIntakeRequest",
    "RepoPackIntakeResult",
    "RepoPackIntakeServices",
    "intake_repo_pack",
    "rejection_artifact",
]
