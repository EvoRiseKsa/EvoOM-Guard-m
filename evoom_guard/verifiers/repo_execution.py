# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Typed repository-verifier execution trace and wire-compatible projection."""

from __future__ import annotations

from dataclasses import dataclass

from evoom_guard.domain.execution import ExecutionPhaseResult, IsolationObservation


@dataclass(slots=True)
class RepoExecutionTrace:
    """Mutable verifier-local builder with an immutable domain snapshot."""

    execution_state: str = "not_started"
    execution_phase: str = "preflight"
    test_command_started: bool = False
    test_command_completed: bool = False
    verifier_pack_started: bool = False
    verifier_pack_completed: bool = False
    delivered_isolation: str = "not_run"
    setup_isolation_evidence: IsolationObservation | None = None
    repo_suite_isolation_evidence: IsolationObservation | None = None
    verifier_pack_isolation_evidence: IsolationObservation | None = None
    primary_isolation_evidence: IsolationObservation | None = None

    def snapshot(self) -> ExecutionPhaseResult:
        """Freeze the currently observed lifecycle facts."""

        return ExecutionPhaseResult(
            execution_state=self.execution_state,
            execution_phase=self.execution_phase,
            test_command_started=self.test_command_started,
            test_command_completed=self.test_command_completed,
            verifier_pack_started=self.verifier_pack_started,
            verifier_pack_completed=self.verifier_pack_completed,
            delivered_isolation=self.delivered_isolation,
            setup_isolation_evidence=self.setup_isolation_evidence,
            repo_suite_isolation_evidence=self.repo_suite_isolation_evidence,
            verifier_pack_isolation_evidence=self.verifier_pack_isolation_evidence,
            primary_isolation_evidence=self.primary_isolation_evidence,
        )


def isolation_observation_payload(
    observation: IsolationObservation,
) -> dict[str, object]:
    """Project one observation to the frozen evidence shape."""

    payload: dict[str, object] = {
        "requested": observation.requested,
        "delivered": observation.delivered,
        "image_digest": observation.image_digest,
        "network": observation.network,
        "runtime": observation.runtime,
    }
    if observation.note:
        payload["note"] = observation.note
    return payload


def execution_phase_payload(result: ExecutionPhaseResult) -> dict[str, object]:
    """Project a typed snapshot to the existing repository artifact keys."""

    payload: dict[str, object] = {
        "execution_state": result.execution_state,
        "execution_phase": result.execution_phase,
        "test_command_started": result.test_command_started,
        "test_command_completed": result.test_command_completed,
        "verifier_pack_started": result.verifier_pack_started,
        "verifier_pack_completed": result.verifier_pack_completed,
        "delivered_isolation": result.delivered_isolation,
        "setup_isolation_evidence": (
            isolation_observation_payload(result.setup_isolation_evidence)
            if result.setup_isolation_evidence is not None
            else None
        ),
        "repo_suite_isolation_evidence": (
            isolation_observation_payload(result.repo_suite_isolation_evidence)
            if result.repo_suite_isolation_evidence is not None
            else None
        ),
        "verifier_pack_isolation_evidence": (
            isolation_observation_payload(result.verifier_pack_isolation_evidence)
            if result.verifier_pack_isolation_evidence is not None
            else None
        ),
    }
    if result.primary_isolation_evidence is not None:
        payload["isolation_evidence"] = isolation_observation_payload(
            result.primary_isolation_evidence
        )
    return payload


__all__ = [
    "RepoExecutionTrace",
    "execution_phase_payload",
    "isolation_observation_payload",
]
