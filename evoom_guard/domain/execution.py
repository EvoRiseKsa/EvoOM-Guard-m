# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# -----------------------------------------------------------------------------
"""Dependency-free execution lifecycle and isolation evidence contracts."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IsolationObservation:
    """Observed delivery of one requested execution boundary."""

    requested: str
    delivered: str
    image_digest: str | None
    network: str | None
    runtime: str | None
    note: str | None = None


@dataclass(frozen=True, slots=True)
class ExecutionPhaseResult:
    """Immutable lifecycle snapshot for one repository-verifier judgment."""

    execution_state: str
    execution_phase: str
    test_command_started: bool
    test_command_completed: bool
    verifier_pack_started: bool
    verifier_pack_completed: bool
    delivered_isolation: str
    setup_isolation_evidence: IsolationObservation | None
    repo_suite_isolation_evidence: IsolationObservation | None
    verifier_pack_isolation_evidence: IsolationObservation | None
    primary_isolation_evidence: IsolationObservation | None = None


__all__ = ["ExecutionPhaseResult", "IsolationObservation"]
