# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Typed owner for the advisory change-attempt observation CLI projection."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

_Output = Callable[[str], None]


class _ObservationInspection(Protocol):
    @property
    def payload(self) -> dict[str, Any]: ...


class _VerifiedObservation(Protocol):
    @property
    def inspection(self) -> _ObservationInspection: ...

    @property
    def observation_sha256(self) -> str: ...


class _ProjectObservation(Protocol):
    def __call__(
        self,
        bundle_path: str,
        output_path: str,
        *,
        trusted_finalizer_public_key_path: str,
        expected_source: Mapping[str, Any],
        expected_context: Mapping[str, Any],
        force: bool = False,
    ) -> _VerifiedObservation: ...


@dataclass(frozen=True, slots=True)
class ProjectObservationServices:
    """Trusted inputs and effects required by the projection command."""

    read_external_object: Callable[..., dict[str, object]]
    project_observation: _ProjectObservation
    invalid_errors: tuple[type[Exception], ...]
    operational_errors: tuple[type[Exception], ...]
    machine_report: Callable[[_Output, dict[str, object]], None]
    absolute_path: Callable[[str], str]


def execute_project_change_attempt_observation(
    args: argparse.Namespace,
    *,
    services: ProjectObservationServices,
    out: _Output = print,
) -> int:
    """Authenticate one finalizer bundle and publish an advisory projection.

    Exit zero means projection succeeded, regardless of whether the authenticated
    finalizer decision was ``ALLOW`` or ``DENY``. This command is not a gate.
    """

    report_format = "EVOGUARD_CHANGE_ATTEMPT_OBSERVATION_PROJECTION_V1"
    try:
        expected_source = services.read_external_object(
            args.expected_source,
            label="expected source",
        )
        expected_context = services.read_external_object(
            args.expected_context,
            label="expected context",
        )
    except (OSError, UnicodeError, ValueError) as exc:
        services.machine_report(
            out,
            {
                "format": report_format,
                "ok": False,
                "verified": False,
                "status": "ERROR",
                "error": f"unusable trusted JSON input: {exc}",
            },
        )
        return 2

    try:
        verified = services.project_observation(
            args.finalizer_bundle,
            args.out,
            trusted_finalizer_public_key_path=args.trusted_pub,
            expected_source=expected_source,
            expected_context=expected_context,
            force=args.force,
        )
    except services.invalid_errors as exc:
        services.machine_report(
            out,
            {
                "format": report_format,
                "ok": False,
                "verified": False,
                "status": "INVALID",
                "error": str(exc),
            },
        )
        return 1
    except services.operational_errors as exc:
        services.machine_report(
            out,
            {
                "format": report_format,
                "ok": False,
                "verified": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2

    payload = verified.inspection.payload
    authority = payload["authority"]
    outcome = payload["outcome"]
    signed_evidence = payload["signed_evidence"]
    services.machine_report(
        out,
        {
            "format": report_format,
            "ok": True,
            "verified": True,
            "status": "PROJECTED",
            "authority": authority["mode"],
            "external_action": authority["external_action"],
            "decision": outcome["decision"],
            "verdict": outcome["verdict"],
            "observation": services.absolute_path(args.out),
            "observation_sha256": verified.observation_sha256,
            "bundle_sha256": signed_evidence["bundle_sha256"],
            "finalizer_key_id": signed_evidence["finalizer_key_id"],
        },
    )
    return 0


__all__ = [
    "ProjectObservationServices",
    "execute_project_change_attempt_observation",
]
