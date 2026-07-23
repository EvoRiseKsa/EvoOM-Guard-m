# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Dependency-free contracts for one repository-verification evidence set."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from evoom_guard.domain.execution import ExecutionPhaseResult


def _freeze_mapping(
    value: Mapping[str, object],
) -> Mapping[str, object]:
    return MappingProxyType(
        {key: _freeze_value(item) for key, item in value.items()}
    )


def _freeze_value(value: object) -> object:
    if isinstance(value, Mapping):
        return _freeze_mapping(value)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_value(item) for item in value)
    return value


@dataclass(frozen=True, slots=True)
class VerifierPackEvidence:
    """Identity and result evidence for an optional verifier pack."""

    present: bool | None
    sha256: str | None
    manifest: Mapping[str, object] | None
    tests_passed: int | None
    tests_total: int | None
    junit_sha256: str | None
    junit_digest_format: str | None
    started: bool | None
    completed: bool | None

    def __post_init__(self) -> None:
        """Own the manifest so later artifact mutation cannot rewrite evidence."""

        if self.manifest is not None:
            object.__setattr__(
                self,
                "manifest",
                _freeze_mapping(self.manifest),
            )


@dataclass(frozen=True, slots=True)
class IsolationPayloadEvidence:
    """Owned exact wire payloads alongside the typed execution observations."""

    primary: Mapping[str, object] | None
    setup: Mapping[str, object] | None
    repo_suite: Mapping[str, object] | None
    verifier_pack: Mapping[str, object] | None

    def __post_init__(self) -> None:
        for name in ("primary", "setup", "repo_suite", "verifier_pack"):
            payload = getattr(self, name)
            if payload is not None:
                object.__setattr__(
                    self,
                    name,
                    _freeze_mapping(payload),
                )


@dataclass(frozen=True, slots=True)
class RepositorySuiteEvidence:
    """The repository-suite phase preserved before optional pack composition."""

    started: bool | None
    completed: bool | None
    state: str | None
    passed: bool | None
    tests_passed: int | None
    tests_total: int | None
    verdict_source: str | None
    returncode: int | None
    junit_sha256: str | None
    junit_digest_format: str | None
    image_digest: str | None


@dataclass(frozen=True, slots=True)
class RuntimeIdentityEvidence:
    """Identity and continuity evidence for the prepared candidate runtime."""

    tree_sha256: str | None
    tree_digest_format: str | None
    tree_entries: int | None
    tree_bytes: int | None
    elapsed_ms: float | None
    continuity: str | None


@dataclass(frozen=True, slots=True)
class VerificationEvidence:
    """Immutable aggregate consumed by the repository judgment layer."""

    execution: ExecutionPhaseResult
    outcome: str | None
    tamper: bool | None
    tests_passed: int | None
    tests_total: int | None
    tests_passed_present: bool
    tests_total_present: bool
    verdict_source: str | None
    junit_sha256: str | None
    junit_digest_format: str | None
    setup_isolation: str | None
    isolation_payloads: IsolationPayloadEvidence
    verifier_pack: VerifierPackEvidence
    repo_suite: RepositorySuiteEvidence
    runtime: RuntimeIdentityEvidence


__all__ = [
    "IsolationPayloadEvidence",
    "RepositorySuiteEvidence",
    "RuntimeIdentityEvidence",
    "VerificationEvidence",
    "VerifierPackEvidence",
]
