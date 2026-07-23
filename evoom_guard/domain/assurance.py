# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Immutable assurance values with exact wire-payload projection."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class VerifierPackAssurance:
    """Facts about the configured verifier pack and its observed execution."""

    configured: bool
    present: bool | None
    integrity: str
    identity_verified: bool | None
    execution_state: str
    secrecy: str
    snapshot_sha256: str | None

    def __post_init__(self) -> None:
        if self.present is not None and type(self.present) is not bool:
            raise TypeError("present must be bool or None")
        if self.snapshot_sha256 is not None and not isinstance(self.snapshot_sha256, str):
            raise TypeError("snapshot_sha256 must be str or None")

    def to_payload(self) -> dict[str, object]:
        """Return the established assurance payload without retaining aliases."""

        return {
            "configured": self.configured,
            "present": self.present,
            "integrity": self.integrity,
            "identity_verified": self.identity_verified,
            "execution_state": self.execution_state,
            "secrecy": self.secrecy,
            "snapshot_sha256": self.snapshot_sha256,
        }


@dataclass(frozen=True, slots=True)
class AssuranceProfile:
    """One immutable description of the assurance actually delivered."""

    execution_state: str
    execution_phase: str
    harness_integrity: str
    report_integrity: str
    candidate_isolation: str
    suite_isolation: str
    setup_isolation: str | None
    runtime_continuity: str
    verifier_pack: VerifierPackAssurance | None
    overall_profile: str
    note: str
    repo_native_suite: str | None = None
    repo_native_suite_present: bool = False

    def to_payload(self) -> dict[str, object]:
        """Project the exact schema-1.11 key shape and ordering."""

        payload: dict[str, object] = {
            "execution_state": self.execution_state,
            "execution_phase": self.execution_phase,
            "harness_integrity": self.harness_integrity,
            "report_integrity": self.report_integrity,
            "candidate_isolation": self.candidate_isolation,
            "suite_isolation": self.suite_isolation,
            "setup_isolation": self.setup_isolation,
            "runtime_continuity": self.runtime_continuity,
            "verifier_pack": (
                self.verifier_pack.to_payload() if self.verifier_pack is not None else None
            ),
        }
        if self.repo_native_suite_present:
            payload["repo_native_suite"] = self.repo_native_suite
        payload["overall_profile"] = self.overall_profile
        payload["note"] = self.note
        return payload


__all__ = ["AssuranceProfile", "VerifierPackAssurance"]
