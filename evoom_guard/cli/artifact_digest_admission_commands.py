# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Typed stdlib-only owner for the Artifact Digest Admission V2 CLI pair.

The public :mod:`evoom_guard.cli` facade retains dependency lookup timing.
This module owns only the two command state machines and receives every domain
and reporting effect explicitly.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

_Output = Callable[[str], None]
_MachineReport = Callable[[_Output, dict[str, object]], None]


class _ReadExternalObject(Protocol):
    def __call__(self, path: str, *, label: str) -> dict[str, object]: ...


class _AsDictValue(Protocol):
    def as_dict(self) -> dict[str, Any]: ...


class _SealedArtifactDigestBinding(Protocol):
    @property
    def binding_path(self) -> str: ...

    @property
    def subject(self) -> _AsDictValue: ...

    @property
    def provenance_reference(self) -> _AsDictValue: ...

    @property
    def payload(self) -> Mapping[str, Any]: ...


class _SealArtifactDigestAdmission(Protocol):
    def __call__(
        self,
        subject_kind: str,
        subject_digest: str,
        provenance_path: str,
        provenance_identity: str,
        finalizer_bundle_path: str,
        output_path: str,
        *,
        trusted_finalizer_public_key_path: str,
        expected_finalizer_source: Mapping[str, Any],
        expected_finalizer_context: Mapping[str, Any],
        private_key_path: str,
        force: bool,
    ) -> _SealedArtifactDigestBinding: ...


class _InspectedArtifactDigestBinding(Protocol):
    @property
    def finalizer(self) -> Mapping[str, Any]: ...

    @property
    def payload(self) -> Mapping[str, Any]: ...


class _VerifiedArtifactDigestBinding(Protocol):
    @property
    def subject(self) -> _AsDictValue: ...

    @property
    def provenance_reference(self) -> _AsDictValue: ...

    @property
    def inspection(self) -> _InspectedArtifactDigestBinding: ...


class _VerifyArtifactDigestAdmission(Protocol):
    def __call__(
        self,
        binding_path: str,
        subject_kind: str,
        subject_digest: str,
        provenance_path: str,
        provenance_identity: str,
        finalizer_bundle_path: str,
        *,
        trusted_public_key_path: str,
        trusted_finalizer_public_key_path: str,
        expected_finalizer_source: Mapping[str, Any],
        expected_finalizer_context: Mapping[str, Any],
    ) -> _VerifiedArtifactDigestBinding: ...


@dataclass(frozen=True, slots=True)
class SealArtifactDigestAdmissionServices:
    """Entry-snapshotted domain values plus call-time facade seams."""

    binding_format: str
    artifact_error: type[Exception]
    signing_unavailable_error: type[Exception]
    seal_artifact_digest_admission: _SealArtifactDigestAdmission
    read_external_object_provider: Callable[[], _ReadExternalObject]
    machine_report_provider: Callable[[], _MachineReport]


@dataclass(frozen=True, slots=True)
class VerifyArtifactDigestAdmissionServices:
    """Entry-snapshotted verification values plus call-time facade seams."""

    binding_format: str
    artifact_error: type[Exception]
    signing_unavailable_error: type[Exception]
    verify_artifact_digest_admission: _VerifyArtifactDigestAdmission
    read_external_object_provider: Callable[[], _ReadExternalObject]
    machine_report_provider: Callable[[], _MachineReport]


def execute_seal_artifact_digest_admission(
    args: argparse.Namespace,
    *,
    services: SealArtifactDigestAdmissionServices,
    out: _Output = print,
) -> int:
    """Seal one immutable digest after an external Trusted Finalizer ALLOW."""

    if any(value == "-" for value in (args.finalizer_bundle, args.provenance)):
        services.machine_report_provider()(
            out,
            {
                "format": services.binding_format,
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": (
                    "finalizer bundle and provenance must be regular files, "
                    "not standard input"
                ),
            },
        )
        return 2
    try:
        expected_source = services.read_external_object_provider()(
            args.expected_source,
            label="expected source",
        )
        expected_context = services.read_external_object_provider()(
            args.expected_context,
            label="expected context",
        )
    except (OSError, UnicodeError, ValueError) as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.binding_format,
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": f"unusable external trust input: {exc}",
            },
        )
        return 2
    try:
        sealed = services.seal_artifact_digest_admission(
            args.subject_kind,
            args.subject_digest,
            args.provenance,
            args.provenance_identity,
            args.finalizer_bundle,
            args.out,
            trusted_finalizer_public_key_path=args.finalizer_pub,
            expected_finalizer_source=expected_source,
            expected_finalizer_context=expected_context,
            private_key_path=args.sign_key,
            force=args.force,
        )
    except services.artifact_error as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.binding_format,
                "ok": False,
                "sealed": False,
                "status": "INVALID_INPUT",
                "error": str(exc),
            },
        )
        return 1
    except (OSError, ValueError, services.signing_unavailable_error) as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.binding_format,
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2
    services.machine_report_provider()(
        out,
        {
            "format": services.binding_format,
            "ok": True,
            "sealed": True,
            "status": "SEALED",
            "decision": "ALLOW",
            "binding": sealed.binding_path,
            "subject": sealed.subject.as_dict(),
            "provenance_reference": sealed.provenance_reference.as_dict(),
            "finalizer": sealed.payload["finalizer"],
            "key_id": sealed.payload["authentication"]["key_id"],
        },
    )
    return 0


def execute_verify_artifact_digest_admission(
    args: argparse.Namespace,
    *,
    services: VerifyArtifactDigestAdmissionServices,
    out: _Output = print,
) -> int:
    """Verify V2 with external subject, provenance, and finalizer inputs."""

    if any(
        value == "-"
        for value in (args.binding, args.finalizer_bundle, args.provenance)
    ):
        services.machine_report_provider()(
            out,
            {
                "format": services.binding_format,
                "ok": False,
                "verified": False,
                "status": "ERROR",
                "error": (
                    "binding, finalizer bundle, and provenance must be regular "
                    "files, not standard input"
                ),
            },
        )
        return 2
    try:
        expected_source = services.read_external_object_provider()(
            args.expected_source,
            label="expected source",
        )
        expected_context = services.read_external_object_provider()(
            args.expected_context,
            label="expected context",
        )
    except (OSError, UnicodeError, ValueError) as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.binding_format,
                "ok": False,
                "verified": False,
                "status": "ERROR",
                "error": f"unusable external trust input: {exc}",
            },
        )
        return 2
    try:
        verified = services.verify_artifact_digest_admission(
            args.binding,
            args.subject_kind,
            args.subject_digest,
            args.provenance,
            args.provenance_identity,
            args.finalizer_bundle,
            trusted_public_key_path=args.trusted_pub,
            trusted_finalizer_public_key_path=args.finalizer_pub,
            expected_finalizer_source=expected_source,
            expected_finalizer_context=expected_context,
        )
    except services.artifact_error as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.binding_format,
                "ok": False,
                "verified": False,
                "status": "INVALID",
                "error": str(exc),
            },
        )
        return 1
    except (OSError, ValueError, services.signing_unavailable_error) as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.binding_format,
                "ok": False,
                "verified": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2
    services.machine_report_provider()(
        out,
        {
            "format": services.binding_format,
            "ok": True,
            "verified": True,
            "status": "VERIFIED",
            "decision": "ALLOW",
            "subject": verified.subject.as_dict(),
            "provenance_reference": verified.provenance_reference.as_dict(),
            "finalizer": verified.inspection.finalizer,
            "key_id": verified.inspection.payload["authentication"]["key_id"],
        },
    )
    return 0
