# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# -----------------------------------------------------------------------------
"""Typed ownership of repository runtime-tree continuity.

This owner binds the fully prepared candidate tree only when a verifier pack is
configured, verifies that same identity after the repository suite and again
after the pack, accumulates identity-scan time, and projects the immutable
runtime evidence contract.  It deliberately does not execute a process or
container, inspect a pack snapshot, interpret JUnit, compose a verdict, own
sticky evidence, or clean a workspace.

Identity providers are resolved at each operation so the historical
``repo_verifier`` monkeypatch seams remain live.  Constructing this owner, and
even asking it to capture when no pack is configured, performs no provider
lookup.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal, Protocol

from evoom_guard.domain.evidence import RuntimeIdentityEvidence
from evoom_guard.runtime_identity import (
    RuntimeIdentity,
    RuntimeIdentityError,
)

RuntimeContinuityFailureKind = Literal[
    "capture_error",
    "verification_error",
    "suite_drift",
    "pack_drift",
]

# Directory names and file suffixes that a cooperative test runner writes into the
# tree as *derived, non-authoritative* bookkeeping (bytecode caches, the pytest
# cache, linter/type/property caches, coverage temp files). They are ignored ONLY
# on the pack-less ``require_suite_continuity`` path, whose sole job is to prove
# the suite did not rewrite a *judged* file (source / test / config) at runtime.
#
# Safety: the authoritative source, test, and config files are still hashed in
# full, so any mid-run rewrite of them remains ``suite_drift``. These entries are
# outputs derived from source the check still covers (a ``.pyc`` reflects its
# ``.py``; the pytest cache stores only nodeids/outcomes and is not executed by a
# fixed harness ``--test-command``), so tolerating their churn cannot hide a
# change to anything the verdict depends on. The verifier-pack path keeps the
# strict full-tree identity unchanged: a pack must judge the exact tree.
_BENIGN_RUNTIME_WRITE_SEGMENTS = frozenset(
    {
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".hypothesis",
    }
)
_BENIGN_RUNTIME_WRITE_SUFFIXES = (".pyc", ".pyo")


def _is_benign_runtime_write(path: str) -> bool:
    """Whether ``path`` is derived runner bookkeeping, not a judged file."""

    segments = path.replace("\\", "/").split("/")
    if _BENIGN_RUNTIME_WRITE_SEGMENTS.intersection(segments):
        return True
    basename = segments[-1] if segments else path
    if basename.endswith(_BENIGN_RUNTIME_WRITE_SUFFIXES):
        return True
    return basename == ".coverage" or basename.startswith(".coverage.")
RuntimeContinuityPhase = Literal[
    "not_required",
    "not_captured",
    "captured",
    "suite_verified",
    "delivered",
    "failed",
]


class RepoRuntimeTrace(Protocol):
    """Trace field changed while runtime identity is being observed."""

    execution_phase: str


class CaptureRuntimeIdentity(Protocol):
    """Capture one canonical candidate runtime identity."""

    def __call__(self, root: str) -> RuntimeIdentity: ...


class VerifyRuntimeIdentity(Protocol):
    """Re-capture and compare one canonical candidate runtime identity."""

    def __call__(
        self,
        root: str,
        expected: RuntimeIdentity,
    ) -> tuple[RuntimeIdentity, list[str]]: ...


@dataclass(frozen=True, slots=True)
class RepoRuntimeContinuityRequest:
    """Immutable inputs that determine whether and how continuity is claimed."""

    candidate_copy: str
    pack_configured: bool
    container_mode: bool
    setup_configured: bool
    trust_setup_on_host: bool
    require_suite_continuity: bool = False


@dataclass(frozen=True, slots=True)
class RepoRuntimeContinuityServices:
    """Live judge-owned identity operations."""

    trace: RepoRuntimeTrace
    capture_identity: Callable[[], CaptureRuntimeIdentity]
    verify_identity: Callable[[], VerifyRuntimeIdentity]


@dataclass(frozen=True, slots=True)
class RepoRuntimeContinuityFailure:
    """One fail-closed runtime observation awaiting verdict composition."""

    kind: RuntimeContinuityFailureKind
    diagnostics: str
    status: str
    changes: tuple[str, ...] = ()


@dataclass(slots=True)
class RepoRuntimeContinuity:
    """Mutable judgment-local runtime identity state."""

    request: RepoRuntimeContinuityRequest
    services: RepoRuntimeContinuityServices
    baseline: RuntimeIdentity | None = field(init=False, default=None)
    elapsed_ms: float = field(init=False, default=0.0)
    continuity: str = field(init=False, default="not_applicable")
    delivery: str = field(init=False, default="not_applicable")
    phase: RuntimeContinuityPhase = field(
        init=False,
        default="not_required",
    )
    failure: RepoRuntimeContinuityFailure | None = field(
        init=False,
        default=None,
    )

    def __post_init__(self) -> None:
        if not self.required:
            return
        self.phase = "not_captured"
        self.delivery = (
            "read_only_enforced"
            if self.request.container_mode
            and not (
                self.request.setup_configured
                and self.request.trust_setup_on_host
            )
            else "snapshot_boundary_checked"
        )

    @property
    def required(self) -> bool:
        """Whether runtime continuity is captured and verified for this run.

        A verifier pack always requires it: the pack must judge the exact tree
        the repository suite received. ``require_suite_continuity`` additionally
        opts a pack-less repo run into the same after-suite tree check, so a
        trusted repository can reject a suite that rewrites the judged tree at
        runtime even when no pack is configured.
        """

        return (
            self.request.pack_configured
            or self.request.require_suite_continuity
        )

    def evidence(self) -> RuntimeIdentityEvidence:
        """Freeze the currently observed runtime facts."""

        baseline = self.baseline
        return RuntimeIdentityEvidence(
            tree_sha256=baseline.sha256 if baseline else None,
            tree_digest_format=baseline.digest_format if baseline else None,
            tree_entries=baseline.entries if baseline else None,
            tree_bytes=baseline.regular_bytes if baseline else None,
            elapsed_ms=self.elapsed_ms,
            continuity=self.continuity,
        )

    def _require_phase(
        self,
        expected: RuntimeContinuityPhase,
        operation: str,
    ) -> None:
        if self.phase != expected:
            raise RuntimeError(
                f"repository runtime continuity cannot {operation} from "
                f"phase {self.phase!r}; expected {expected!r}"
            )

    def _record_failure(
        self,
        failure: RepoRuntimeContinuityFailure,
    ) -> RepoRuntimeContinuityFailure:
        self.failure = failure
        self.phase = "failed"
        self.continuity = failure.status
        return failure

    def capture_baseline(self) -> RepoRuntimeContinuityFailure | None:
        """Capture the fully prepared tree when a pack makes it mandatory."""

        if not self.required:
            return None
        if self.failure is not None:
            return self.failure
        self._require_phase("not_captured", "capture a baseline")
        self.services.trace.execution_phase = "runtime_verification"
        self.continuity = "unavailable"
        try:
            observed = self.services.capture_identity()(
                self.request.candidate_copy
            )
            self.baseline = observed
            self.elapsed_ms += observed.elapsed_ms
        except RuntimeIdentityError as exc:
            return self._record_failure(
                RepoRuntimeContinuityFailure(
                    kind="capture_error",
                    diagnostics=f"candidate runtime identity failed: {exc}",
                    status="unavailable",
                )
            )
        self.continuity = "incomplete"
        self.phase = "captured"
        return None

    def _verify(
        self,
    ) -> tuple[list[str] | None, RepoRuntimeContinuityFailure | None]:
        baseline = self.baseline
        if baseline is None:
            raise RuntimeError(
                "repository runtime continuity requires a captured baseline"
            )
        self.services.trace.execution_phase = "runtime_verification"
        try:
            observed, changes = self.services.verify_identity()(
                self.request.candidate_copy,
                baseline,
            )
            self.elapsed_ms += observed.elapsed_ms
        except RuntimeIdentityError as exc:
            return None, RepoRuntimeContinuityFailure(
                kind="verification_error",
                diagnostics=(
                    "candidate runtime identity verification failed: "
                    f"{exc}"
                ),
                status="verification_failed",
            )
        return changes, None

    def verify_after_suite(self) -> RepoRuntimeContinuityFailure | None:
        """Reject suite drift before pack snapshot checks or interpretation."""

        if self.failure is not None:
            return self.failure
        self._require_phase("captured", "verify after the repository suite")
        changes, failure = self._verify()
        if failure is not None:
            return self._record_failure(failure)
        assert changes is not None
        # A pack-less require_suite_continuity run only needs the suite to leave
        # every *judged* file untouched; tolerate derived runner bookkeeping so
        # the check is usable with real runners (pytest writes .pytest_cache).
        # The verifier-pack path keeps the exact-tree requirement (no filtering).
        if changes and not self.request.pack_configured:
            changes = [c for c in changes if not _is_benign_runtime_write(c)]
        if changes:
            return self._record_failure(
                RepoRuntimeContinuityFailure(
                    kind="suite_drift",
                    diagnostics=(
                        "repo suite modified the candidate tree before "
                        "verifier-pack execution: "
                        + ", ".join(changes[:20])
                    ),
                    status="verification_failed",
                    changes=tuple(changes),
                )
            )
        self.phase = "suite_verified"
        return None

    def finalize_suite_only(self) -> None:
        """Deliver continuity when the repository suite is the last judged phase.

        With a verifier pack, :meth:`verify_after_pack` performs the final
        identity check and marks delivery. A pack-less
        ``require_suite_continuity`` run has no pack phase, so a clean
        after-suite verification is itself the delivered boundary. This is a
        no-op whenever a pack is configured (the pack path owns delivery) or the
        after-suite verification has not completed.
        """

        if self.request.pack_configured:
            return
        if self.phase != "suite_verified":
            return
        self.continuity = self.delivery
        self.phase = "delivered"

    def verify_after_pack(self) -> RepoRuntimeContinuityFailure | None:
        """Reject pack drift before its JUnit report is interpreted."""

        if self.failure is not None:
            return self.failure
        self._require_phase("suite_verified", "verify after the verifier pack")
        changes, failure = self._verify()
        if failure is not None:
            return self._record_failure(failure)
        assert changes is not None
        if changes:
            return self._record_failure(
                RepoRuntimeContinuityFailure(
                    kind="pack_drift",
                    diagnostics=(
                        "verifier-pack execution modified the candidate tree: "
                        + ", ".join(changes[:20])
                    ),
                    status="verification_failed",
                    changes=tuple(changes),
                )
            )
        self.continuity = self.delivery
        self.phase = "delivered"
        return None


def runtime_identity_evidence_payload(
    evidence: RuntimeIdentityEvidence,
) -> dict[str, object]:
    """Project typed runtime evidence to the frozen repository artifact keys."""

    return {
        "runtime_tree_sha256": evidence.tree_sha256,
        "runtime_tree_digest_format": evidence.tree_digest_format,
        "runtime_tree_entries": evidence.tree_entries,
        "runtime_tree_bytes": evidence.tree_bytes,
        "runtime_identity_elapsed_ms": evidence.elapsed_ms,
        "runtime_continuity": evidence.continuity,
    }


__all__ = [
    "RepoRuntimeContinuity",
    "RepoRuntimeContinuityFailure",
    "RepoRuntimeContinuityRequest",
    "RepoRuntimeContinuityServices",
    "runtime_identity_evidence_payload",
]
