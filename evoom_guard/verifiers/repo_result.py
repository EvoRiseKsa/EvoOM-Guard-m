# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Typed, effect-free repository result and evidence projection.

This module owns the repository verifier's sticky pack/repository-phase facts,
the completed pack-phase fields, exact final artifact construction, and the
published presence-versus-null rules.  It performs no filesystem, process,
container, clock, provider, trace, or cleanup operation.

``RepoVerifier`` remains the lifetime/effect coordinator.  It records facts at
the same historical points and supplies already-observed execution/runtime
evidence to this owner for projection to the unchanged artifact wire shape.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from evoom_guard.contracts import VerdictResult
from evoom_guard.domain.execution import ExecutionPhaseResult, IsolationObservation
from evoom_guard.domain.verification import (
    CompositePhaseResult,
    PackPhaseResult,
    RepoPhaseResult,
)
from evoom_guard.verifiers.repo_execution import (
    execution_phase_payload,
    isolation_observation_payload,
)

FinalRepoPhase = RepoPhaseResult | CompositePhaseResult


@dataclass(frozen=True, slots=True)
class RepoPackIdentityArtifact:
    """One observed verifier-pack identity projected into result evidence."""

    sha256: str
    manifest: Mapping[str, Any] | None

    def __post_init__(self) -> None:
        if self.manifest is None:
            return
        frozen = MappingProxyType(copy.deepcopy(dict(self.manifest)))
        object.__setattr__(self, "manifest", frozen)

    def payload(self) -> dict[str, Any]:
        """Return the historical sticky identity keys in their exact order."""

        return {
            "verifier_pack_sha256": self.sha256,
            "verifier_pack_manifest": (
                None if self.manifest is None else copy.deepcopy(dict(self.manifest))
            ),
        }


@dataclass(frozen=True, slots=True)
class RepoSuitePhaseArtifact:
    """Repository-suite facts retained across a later mandatory-pack failure."""

    passed: bool | None
    tests_passed: int
    tests_total: int
    verdict_source: str | None
    returncode: int
    junit_sha256: str | None
    junit_digest_format: str | None

    @classmethod
    def from_phase(
        cls,
        phase: RepoPhaseResult,
    ) -> RepoSuitePhaseArtifact:
        """Freeze the completed repository phase without implying a verdict."""

        return cls(
            passed=phase.passed if phase.verdict_source is not None else None,
            tests_passed=phase.tests_passed,
            tests_total=phase.tests_total,
            verdict_source=phase.verdict_source,
            returncode=phase.returncode,
            junit_sha256=phase.junit_sha256,
            junit_digest_format=phase.junit_digest_format,
        )

    def payload(self) -> dict[str, Any]:
        """Return the exact sticky repository-phase artifact fields."""

        return {
            "repo_suite_started": True,
            "repo_suite_completed": True,
            "repo_suite_state": "repo_phase_completed",
            "repo_suite_passed": self.passed,
            "repo_suite_tests_passed": self.tests_passed,
            "repo_suite_tests_total": self.tests_total,
            "repo_suite_verdict_source": self.verdict_source,
            "repo_suite_returncode": self.returncode,
            "repo_suite_junit_sha256": self.junit_sha256,
            "repo_suite_junit_digest_format": self.junit_digest_format,
        }


@dataclass(frozen=True, slots=True)
class RepoPackPhaseArtifact:
    """Completed mandatory-pack fields included in a final artifact."""

    tests_passed: int
    tests_total: int
    junit_sha256: str | None
    junit_digest_format: str | None

    @classmethod
    def from_phase(
        cls,
        phase: PackPhaseResult,
    ) -> RepoPackPhaseArtifact:
        return cls(
            tests_passed=phase.tests_passed,
            tests_total=phase.tests_total,
            junit_sha256=phase.junit_sha256,
            junit_digest_format=phase.junit_digest_format,
        )


@dataclass(slots=True)
class RepoResultProjection:
    """Judgment-local typed builder for sticky result facts."""

    pack_identity: RepoPackIdentityArtifact | None = field(
        init=False,
        default=None,
    )
    repo_suite_phase: RepoSuitePhaseArtifact | None = field(
        init=False,
        default=None,
    )

    def bind_pack_identity(
        self,
        *,
        sha256: str,
        manifest: Mapping[str, Any] | None,
    ) -> None:
        """Record an observed pack identity for every later return path."""

        self.pack_identity = RepoPackIdentityArtifact(
            sha256=sha256,
            manifest=manifest,
        )

    def bind_repo_suite_phase(self, phase: RepoPhaseResult) -> None:
        """Record a completed repo phase before mandatory-pack execution."""

        self.repo_suite_phase = RepoSuitePhaseArtifact.from_phase(phase)

    def sticky_payload(self) -> dict[str, Any]:
        """Project currently bound sticky facts in historical insertion order."""

        payload: dict[str, Any] = {}
        if self.pack_identity is not None:
            payload.update(self.pack_identity.payload())
        if self.repo_suite_phase is not None:
            payload.update(self.repo_suite_phase.payload())
        return payload

    def finalize(
        self,
        result: VerdictResult,
        *,
        execution: ExecutionPhaseResult,
        verifier_pack_present: bool,
    ) -> VerdictResult:
        """Attach sticky/lifecycle facts with the frozen overwrite semantics."""

        result.artifact.update(self.sticky_payload())
        result.artifact.update(execution_phase_payload(execution))
        result.artifact.setdefault(
            "verifier_pack_present",
            verifier_pack_present,
        )
        return result


@dataclass(frozen=True, slots=True)
class RepoFinalArtifactRequest:
    """Already-observed values required for the completed artifact."""

    returncode: int
    elapsed_seconds: float
    phase: FinalRepoPhase
    files_changed: tuple[str, ...]
    files_deleted: tuple[str, ...]
    pack_identity: RepoPackIdentityArtifact | None
    expected_pack_sha256: str
    pack_phase: RepoPackPhaseArtifact | None
    pack_configured: bool
    setup_isolation: str | None
    setup_configured: bool
    runtime_evidence: Mapping[str, object]
    resolved_image: str | None
    suite_isolation_evidence: IsolationObservation
    container_mode: bool


def build_final_repo_artifact(
    request: RepoFinalArtifactRequest,
) -> dict[str, Any]:
    """Build the exact completed repository artifact without effects.

    A configured pack controls presence of its JUnit identity keys.  The
    remaining pack fields are always present and nullable, matching the
    published schema and the pre-extraction characterization vector.
    """

    phase = request.phase
    pack_identity = request.pack_identity
    pack_phase = request.pack_phase
    artifact: dict[str, Any] = {
        "returncode": request.returncode,
        "elapsed": request.elapsed_seconds,
        "tests_passed": phase.tests_passed,
        "tests_total": phase.tests_total,
        "files_changed": list(request.files_changed),
        "files_deleted": list(request.files_deleted),
        "verdict_source": phase.verdict_source,
        "outcome": phase.outcome,
        "tamper": phase.tampered,
        "junit_sha256": phase.junit_sha256,
        "junit_digest_format": phase.junit_digest_format,
        "verifier_pack_sha256": (pack_identity.sha256 if pack_identity is not None else None),
        "expected_verifier_pack_sha256": request.expected_pack_sha256 or None,
        "verifier_pack_manifest": (
            None
            if pack_identity is None or pack_identity.manifest is None
            else copy.deepcopy(dict(pack_identity.manifest))
        ),
        "verifier_pack_tests_passed": (pack_phase.tests_passed if pack_phase is not None else None),
        "verifier_pack_tests_total": (pack_phase.tests_total if pack_phase is not None else None),
    }
    if request.pack_configured:
        artifact.update(
            verifier_pack_junit_sha256=(
                pack_phase.junit_sha256 if pack_phase is not None else None
            ),
            verifier_pack_junit_digest_format=(
                pack_phase.junit_digest_format if pack_phase is not None else None
            ),
        )
    artifact.update(
        setup_isolation=request.setup_isolation,
        setup_fidelity=("verified" if request.setup_configured else "not_applicable"),
        candidate_fidelity=("verified" if request.pack_configured else "not_applicable"),
    )
    artifact.update(request.runtime_evidence)
    artifact.update(
        image_digest=request.resolved_image,
        isolation_evidence=(
            isolation_observation_payload(request.suite_isolation_evidence)
            if request.container_mode
            else None
        ),
    )
    return artifact


__all__ = [
    "FinalRepoPhase",
    "RepoFinalArtifactRequest",
    "RepoPackIdentityArtifact",
    "RepoPackPhaseArtifact",
    "RepoResultProjection",
    "RepoSuitePhaseArtifact",
    "build_final_repo_artifact",
]
