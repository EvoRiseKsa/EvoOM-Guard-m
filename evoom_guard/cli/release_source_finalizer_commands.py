# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Typed stdlib-only owner for the Release Source Finalizer CLI family.

The public :mod:`evoom_guard.cli` facade retains function-entry domain imports
and the historical live helper lookup points.  This module owns only the four
command state machines and receives every domain, filesystem-projection, and
reporting effect explicitly.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

_Output = Callable[[str], None]
_MachineReport = Callable[[_Output, dict[str, object]], None]


class _ReadExternalObject(Protocol):
    def __call__(self, path: str, *, label: str) -> dict[str, object]: ...


class _CreateReleaseSourceHandoff(Protocol):
    def __call__(
        self,
        verdict_path: str,
        output_path: str,
        *,
        source: Mapping[str, Any],
        context: Mapping[str, Any],
        force: bool,
    ) -> Mapping[str, Any]: ...


class _SealedReleaseSourceEvidence(Protocol):
    @property
    def decision(self) -> str: ...

    @property
    def bundle_path(self) -> str: ...

    @property
    def manifest(self) -> Mapping[str, Any]: ...


class _SealReleaseSourceBundle(Protocol):
    def __call__(
        self,
        handoff_path: str,
        verdict_path: str,
        output_path: str,
        *,
        expected_source: Mapping[str, Any],
        expected_context: Mapping[str, Any],
        git_repository: str,
        git_repository_is_bare: bool,
        private_key_path: str,
        prohibited_key_ids: Iterable[str],
        force: bool,
    ) -> _SealedReleaseSourceEvidence: ...


class _InspectedReleaseSourceEvidence(Protocol):
    @property
    def manifest(self) -> Mapping[str, Any]: ...


class _VerifiedReleaseSourceEvidence(Protocol):
    @property
    def decision(self) -> str: ...

    @property
    def bundle(self) -> _InspectedReleaseSourceEvidence: ...

    @property
    def record_report(self) -> Mapping[str, Any]: ...


class _VerifyReleaseSourceBundle(Protocol):
    def __call__(
        self,
        bundle_path: str,
        *,
        trusted_public_key_path: str,
        expected_source: Mapping[str, Any],
        expected_context: Mapping[str, Any],
        prohibited_key_ids: Iterable[str],
    ) -> _VerifiedReleaseSourceEvidence: ...


class _RecordSnapshot(Protocol):
    def __call__(
        self,
        path: str,
    ) -> tuple[bytes, dict[str, Any], dict[str, Any]]: ...


class _DerivedReleaseSourceBindings(Protocol):
    @property
    def source(self) -> dict[str, Any]: ...


class _DeriveReleaseSourceBindings(Protocol):
    def __call__(
        self,
        *,
        git_repository: str,
        source: Mapping[str, Any],
        git_repository_is_bare: bool,
    ) -> _DerivedReleaseSourceBindings: ...


class _ContextFromReleaseSourceBindings(Protocol):
    def __call__(
        self,
        bindings: Any,
        record: Mapping[str, Any],
    ) -> dict[str, Any]: ...


class _CanonicalJson(Protocol):
    def __call__(self, value: dict[str, Any]) -> bytes: ...


class _PublishBytes(Protocol):
    def __call__(
        self,
        path: str,
        data: bytes,
        *,
        force: bool,
        prefix: str,
        label: str,
    ) -> object: ...


@dataclass(frozen=True, slots=True)
class ReleaseSourceHandoffServices:
    """Entry-snapshotted handoff values plus call-time facade seams."""

    handoff_format: str
    finalizer_error: type[Exception]
    create_release_source_handoff: _CreateReleaseSourceHandoff
    read_external_object_provider: Callable[[], _ReadExternalObject]
    absolute_path_provider: Callable[[], Callable[[str], str]]
    machine_report_provider: Callable[[], _MachineReport]


@dataclass(frozen=True, slots=True)
class SealReleaseSourceFinalizerServices:
    """Entry-snapshotted sealing values plus call-time facade seams."""

    evidence_format: str
    finalizer_error: type[Exception]
    signing_unavailable_error: type[Exception]
    seal_release_source_bundle: _SealReleaseSourceBundle
    read_external_object_provider: Callable[[], _ReadExternalObject]
    machine_report_provider: Callable[[], _MachineReport]


@dataclass(frozen=True, slots=True)
class VerifyReleaseSourceFinalizedServices:
    """Entry-snapshotted verification values plus call-time facade seams."""

    evidence_format: str
    finalizer_error: type[Exception]
    signing_unavailable_error: type[Exception]
    verify_release_source_bundle: _VerifyReleaseSourceBundle
    read_external_object_provider: Callable[[], _ReadExternalObject]
    machine_report_provider: Callable[[], _MachineReport]


@dataclass(frozen=True, slots=True)
class DeriveReleaseSourceControlsServices:
    """Entry-snapshotted raw-Git operations plus call-time facade seams."""

    context_format: str
    finalizer_error: type[Exception]
    canonical_json: _CanonicalJson
    publish_bytes: _PublishBytes
    record_snapshot: _RecordSnapshot
    context_from_release_source_bindings: _ContextFromReleaseSourceBindings
    derive_release_source_bindings: _DeriveReleaseSourceBindings
    read_external_object_provider: Callable[[], _ReadExternalObject]
    absolute_path_provider: Callable[[], Callable[[str], str]]
    machine_report_provider: Callable[[], _MachineReport]


def execute_release_source_handoff(
    args: argparse.Namespace,
    *,
    services: ReleaseSourceHandoffServices,
    out: _Output = print,
) -> int:
    """Write an unsigned handoff for the separate protected-main contract."""

    if args.verdict == "-":
        services.machine_report_provider()(
            out,
            {
                "format": services.handoff_format,
                "ok": False,
                "status": "ERROR",
                "error": (
                    "release-source-handoff verdict must be a regular file, "
                    "not standard input"
                ),
            },
        )
        return 2
    try:
        source = services.read_external_object_provider()(
            args.source,
            label="release source",
        )
        context = services.read_external_object_provider()(
            args.context,
            label="release-source context",
        )
    except (OSError, UnicodeError, ValueError) as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.handoff_format,
                "ok": False,
                "status": "ERROR",
                "error": f"unusable trusted metadata: {exc}",
            },
        )
        return 2
    try:
        handoff = services.create_release_source_handoff(
            args.verdict,
            args.out,
            source=source,
            context=context,
            force=args.force,
        )
    except (OSError, ValueError, services.finalizer_error) as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.handoff_format,
                "ok": False,
                "status": "INVALID_INPUT",
                "error": str(exc),
            },
        )
        return 1
    services.machine_report_provider()(
        out,
        {
            "format": services.handoff_format,
            "ok": True,
            "status": "CREATED",
            "handoff": services.absolute_path_provider()(args.out),
            "record_sha256": handoff["record"]["sha256"],
            "source": handoff["source"],
            "context": handoff["context"],
        },
    )
    return 0


def execute_seal_release_source_finalizer(
    args: argparse.Namespace,
    *,
    services: SealReleaseSourceFinalizerServices,
    out: _Output = print,
) -> int:
    """Seal a protected-main handoff only after external source matching."""

    if args.verdict == "-":
        services.machine_report_provider()(
            out,
            {
                "format": services.evidence_format,
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": (
                    "seal-release-source-finalizer verdict must be a regular "
                    "file, not standard input"
                ),
            },
        )
        return 2
    try:
        source = services.read_external_object_provider()(
            args.expected_source,
            label="expected release source",
        )
        context = services.read_external_object_provider()(
            args.expected_context,
            label="expected release-source context",
        )
    except (OSError, UnicodeError, ValueError) as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.evidence_format,
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": f"unusable external trust input: {exc}",
            },
        )
        return 2
    try:
        sealed = services.seal_release_source_bundle(
            args.handoff,
            args.verdict,
            args.out,
            expected_source=source,
            expected_context=context,
            git_repository=args.git_repository,
            git_repository_is_bare=args.git_repository_bare,
            private_key_path=args.sign_key,
            prohibited_key_ids=args.must_differ_from_key_id,
            force=args.force,
        )
    except (OSError, ValueError, services.finalizer_error) as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.evidence_format,
                "ok": False,
                "sealed": False,
                "status": "INVALID_INPUT",
                "error": str(exc),
            },
        )
        return 1
    except services.signing_unavailable_error as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.evidence_format,
                "ok": False,
                "sealed": False,
                "status": "INCOMPLETE",
                "error": str(exc),
            },
        )
        return 2
    allowed = sealed.decision == "ALLOW"
    services.machine_report_provider()(
        out,
        {
            "format": services.evidence_format,
            "ok": allowed,
            "sealed": True,
            "status": "FINALIZED" if allowed else "DENIED",
            "decision": sealed.decision,
            "bundle": sealed.bundle_path,
            "record_sha256": sealed.manifest["record"]["sha256"],
            "key_id": sealed.manifest["authentication"]["key_id"],
        },
    )
    return 0 if allowed or args.allow_deny_evidence else 1


def execute_verify_release_source_finalized(
    args: argparse.Namespace,
    *,
    services: VerifyReleaseSourceFinalizedServices,
    out: _Output = print,
) -> int:
    """Verify a separate release-source envelope and external bindings."""

    try:
        source = services.read_external_object_provider()(
            args.expected_source,
            label="expected release source",
        )
        context = services.read_external_object_provider()(
            args.expected_context,
            label="expected release-source context",
        )
    except (OSError, UnicodeError, ValueError) as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.evidence_format,
                "ok": False,
                "verified": False,
                "status": "INCOMPLETE",
                "error": f"unusable external trust input: {exc}",
            },
        )
        return 2
    try:
        verified = services.verify_release_source_bundle(
            args.bundle,
            trusted_public_key_path=args.trusted_pub,
            expected_source=source,
            expected_context=context,
            prohibited_key_ids=args.must_differ_from_key_id,
        )
    except services.signing_unavailable_error as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.evidence_format,
                "ok": False,
                "verified": False,
                "status": "INCOMPLETE",
                "error": str(exc),
            },
        )
        return 2
    except (OSError, ValueError, services.finalizer_error) as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.evidence_format,
                "ok": False,
                "verified": False,
                "status": "INVALID",
                "error": str(exc),
            },
        )
        return 1
    allowed = verified.decision == "ALLOW"
    services.machine_report_provider()(
        out,
        {
            "format": services.evidence_format,
            "ok": allowed,
            "verified": True,
            "status": "VERIFIED" if allowed else "DENIED",
            "decision": verified.decision,
            "key_id": verified.bundle.manifest["authentication"]["key_id"],
            "record": verified.record_report,
        },
    )
    return 0 if allowed or args.allow_deny_evidence else 1


def execute_derive_release_source_controls(
    args: argparse.Namespace,
    *,
    services: DeriveReleaseSourceControlsServices,
    out: _Output = print,
) -> int:
    """Re-derive source/context from raw Git without making an admission claim."""

    if args.verdict == "-":
        services.machine_report_provider()(
            out,
            {
                "format": services.context_format,
                "ok": False,
                "status": "ERROR",
                "error": (
                    "derive-release-source-controls verdict must be a regular "
                    "file, not standard input"
                ),
            },
        )
        return 2
    try:
        source = services.read_external_object_provider()(
            args.source,
            label="release source",
        )
        _verdict_bytes, verdict, _record_report = services.record_snapshot(
            args.verdict
        )
        bindings = services.derive_release_source_bindings(
            git_repository=args.git_repository,
            source=source,
            git_repository_is_bare=args.git_repository_bare,
        )
        context = services.context_from_release_source_bindings(
            bindings,
            verdict,
        )
        services.publish_bytes(
            args.source_out,
            services.canonical_json(bindings.source),
            force=args.force,
            prefix=".evoguard-release-source-",
            label="verified release source",
        )
        services.publish_bytes(
            args.context_out,
            services.canonical_json(context),
            force=args.force,
            prefix=".evoguard-release-source-context-",
            label="verified release-source context",
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        services.finalizer_error,
    ) as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.context_format,
                "ok": False,
                "status": "REJECTED",
                "error": str(exc),
            },
        )
        return 1
    services.machine_report_provider()(
        out,
        {
            "format": services.context_format,
            "ok": True,
            "status": "RAW_GIT_CONTROLS_DERIVED",
            "source": services.absolute_path_provider()(args.source_out),
            "context": services.absolute_path_provider()(args.context_out),
            "decision": "NONE",
            "admission": False,
        },
    )
    return 0
