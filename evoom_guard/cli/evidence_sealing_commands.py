# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Typed application adapters for the platform evidence-sealing CLI family.

This module owns the deterministic command orchestration for the two
operator-side sealing commands: ``bundle-evidence`` (validated signed-envelope
creation) and ``finalize-record`` (trusted semantic-record finalization).
Both were extracted verbatim from :mod:`evoom_guard.cli.record_commands` so
the record family could become part of the Apache-licensed core while these
sealing handlers remain part of the EvoRise trust platform.  The
:mod:`evoom_guard.cli` package remains the compatibility facade and retains
the historical dependency lookup points.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

_Output = Callable[[str], None]
_ExpectedErrors = tuple[type[Exception], ...]
_RecordReport = dict[str, Any]


class _ReadBoundedBytes(Protocol):
    def __call__(self, path: str, *, limit: int, label: str) -> bytes: ...


class _EvidenceMaterialFactory(Protocol):
    def __call__(self, *, role: str, source_path: str) -> Any: ...


class _CreateEvidenceBundle(Protocol):
    def __call__(
        self,
        verdict_path: str,
        output_path: str,
        *,
        context: Mapping[str, Any],
        private_key_path: str,
        materials: Sequence[Any],
        force: bool,
        require_valid_record: bool,
    ) -> Mapping[str, Any]: ...


class _FinalizedEvidence(Protocol):
    @property
    def manifest(self) -> Mapping[str, Any]: ...

    @property
    def decision(self) -> str: ...

    @property
    def bundle_path(self) -> str: ...

    @property
    def record_report(self) -> Mapping[str, Any]: ...


class _FinalizeEvidenceBundle(Protocol):
    def __call__(
        self,
        verdict_path: str,
        output_path: str,
        *,
        expected_context: Mapping[str, Any],
        private_key_path: str,
        materials: Sequence[Any],
        force: bool,
    ) -> _FinalizedEvidence: ...


@dataclass(frozen=True)
class BundleEvidenceServices:
    """Dependencies for validated evidence-envelope creation."""

    read_bounded_bytes: _ReadBoundedBytes
    strict_json_loads: Callable[[str], Any]
    verify_record: Callable[[Any], _RecordReport]
    evidence_material: _EvidenceMaterialFactory
    create_evidence_bundle: _CreateEvidenceBundle
    invalid_input_errors: _ExpectedErrors
    operational_errors: _ExpectedErrors
    machine_report: Callable[[_Output, dict[str, object]], None]
    canonical_manifest_bytes: Callable[[Mapping[str, Any]], bytes]
    sha256_hex: Callable[[bytes], str]
    absolute_path: Callable[[str], str]
    max_record_bytes: int
    max_context_bytes: int


@dataclass(frozen=True)
class FinalizeRecordServices:
    """Dependencies for trusted semantic-record finalization."""

    read_bounded_bytes: _ReadBoundedBytes
    strict_json_loads: Callable[[str], Any]
    verify_record: Callable[[Any], _RecordReport]
    evidence_material: _EvidenceMaterialFactory
    finalize_evidence_bundle: _FinalizeEvidenceBundle
    invalid_input_errors: _ExpectedErrors
    operational_errors: _ExpectedErrors
    machine_report: Callable[[_Output, dict[str, object]], None]
    canonical_manifest_bytes: Callable[[Mapping[str, Any]], bytes]
    sha256_hex: Callable[[bytes], str]
    max_record_bytes: int
    max_context_bytes: int


def _parse_materials(
    specifications: Sequence[str],
    *,
    factory: _EvidenceMaterialFactory,
    report_format: str,
    finalized: bool | None,
    machine_report: Callable[[_Output, dict[str, object]], None],
    out: _Output,
) -> list[Any] | None:
    materials: list[Any] = []
    for specification in specifications:
        role, separator, path = specification.partition("=")
        if not separator or not role or not path:
            report: dict[str, object] = {
                "format": report_format,
                "ok": False,
            }
            if finalized is not None:
                report["finalized"] = finalized
            report.update(
                {
                    "status": "ERROR",
                    "error": (
                        f"invalid --material {specification!r}; expected ROLE=PATH"
                    ),
                }
            )
            machine_report(out, report)
            return None
        materials.append(factory(role=role, source_path=path))
    return materials


def execute_bundle_evidence(
    args: argparse.Namespace,
    *,
    services: BundleEvidenceServices,
    out: _Output = print,
) -> int:
    """Create a signed envelope only after semantic validation succeeds."""

    report_format = "EVOGUARD_EVIDENCE_CREATION_V1"
    try:
        verdict_bytes = services.read_bounded_bytes(
            args.verdict,
            limit=services.max_record_bytes,
            label="verdict",
        )
        context_bytes = services.read_bounded_bytes(
            args.context,
            limit=services.max_context_bytes,
            label="context",
        )
        verdict = services.strict_json_loads(verdict_bytes.decode("utf-8"))
        context = services.strict_json_loads(context_bytes.decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        services.machine_report(
            out,
            {
                "format": report_format,
                "ok": False,
                "status": "ERROR",
                "error": f"unusable JSON input: {exc}",
            },
        )
        return 2

    record_report = services.verify_record(verdict)
    record_is_valid = bool(record_report["ok"])
    if not record_is_valid:
        services.machine_report(
            out,
            {
                "format": report_format,
                "ok": False,
                "status": "INVALID_RECORD",
                "record": record_report,
            },
        )
        return 1
    if not isinstance(context, dict):
        services.machine_report(
            out,
            {
                "format": report_format,
                "ok": False,
                "status": "ERROR",
                "error": "context JSON must be an object",
            },
        )
        return 2

    materials = _parse_materials(
        args.material,
        factory=services.evidence_material,
        report_format=report_format,
        finalized=None,
        machine_report=services.machine_report,
        out=out,
    )
    if materials is None:
        return 2

    try:
        manifest = services.create_evidence_bundle(
            args.verdict,
            args.out,
            context=context,
            private_key_path=args.sign_key,
            materials=materials,
            force=args.force,
            require_valid_record=True,
        )
    except services.invalid_input_errors as exc:
        services.machine_report(
            out,
            {
                "format": report_format,
                "ok": False,
                "status": "INVALID_INPUT",
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
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2

    canonical_manifest = services.canonical_manifest_bytes(manifest)
    authentication = manifest["authentication"]
    record = manifest["record"]
    services.machine_report(
        out,
        {
            "format": report_format,
            "ok": True,
            "status": "CREATED",
            "bundle": services.absolute_path(args.out),
            "manifest_sha256": services.sha256_hex(canonical_manifest),
            "record_sha256": record["sha256"],
            "key_id": authentication["key_id"],
        },
    )
    return 0


def execute_finalize_record(
    args: argparse.Namespace,
    *,
    services: FinalizeRecordServices,
    out: _Output = print,
) -> int:
    """Seal a semantic record against externally derived trusted context."""

    report_format = "EVOGUARD_TRUSTED_FINALIZATION_V1"
    if args.verdict == "-":
        services.machine_report(
            out,
            {
                "format": report_format,
                "ok": False,
                "finalized": False,
                "status": "ERROR",
                "error": (
                    "finalize-record verdict must be a regular file, "
                    "not standard input"
                ),
            },
        )
        return 2

    try:
        verdict_bytes = services.read_bounded_bytes(
            args.verdict,
            limit=services.max_record_bytes,
            label="verdict",
        )
        context_bytes = services.read_bounded_bytes(
            args.expected_context,
            limit=services.max_context_bytes,
            label="expected context",
        )
        verdict = services.strict_json_loads(verdict_bytes.decode("utf-8"))
        expected_context = services.strict_json_loads(context_bytes.decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        services.machine_report(
            out,
            {
                "format": report_format,
                "ok": False,
                "finalized": False,
                "status": "ERROR",
                "error": f"unusable JSON input: {exc}",
            },
        )
        return 2
    if not isinstance(verdict, dict):
        services.machine_report(
            out,
            {
                "format": report_format,
                "ok": False,
                "finalized": False,
                "status": "INVALID_RECORD",
                "error": "verdict JSON must be an object",
            },
        )
        return 1

    record_report = services.verify_record(verdict)
    record_is_semantic = bool(record_report["ok"])
    if not record_is_semantic:
        services.machine_report(
            out,
            {
                "format": report_format,
                "ok": False,
                "finalized": False,
                "status": "INVALID_RECORD",
                "record": record_report,
            },
        )
        return 1
    if not isinstance(expected_context, dict):
        services.machine_report(
            out,
            {
                "format": report_format,
                "ok": False,
                "finalized": False,
                "status": "ERROR",
                "error": "expected context JSON must be an object",
            },
        )
        return 2

    materials = _parse_materials(
        args.material,
        factory=services.evidence_material,
        report_format=report_format,
        finalized=False,
        machine_report=services.machine_report,
        out=out,
    )
    if materials is None:
        return 2

    try:
        finalized = services.finalize_evidence_bundle(
            args.verdict,
            args.out,
            expected_context=expected_context,
            private_key_path=args.sign_key,
            materials=materials,
            force=args.force,
        )
    except services.invalid_input_errors as exc:
        services.machine_report(
            out,
            {
                "format": report_format,
                "ok": False,
                "finalized": False,
                "status": "INVALID_INPUT",
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
                "finalized": False,
                "status": "ERROR",
                "error": str(exc),
            },
        )
        return 2

    canonical_manifest = services.canonical_manifest_bytes(finalized.manifest)
    authentication = finalized.manifest["authentication"]
    record = finalized.manifest["record"]
    allowed = finalized.decision == "ALLOW"
    services.machine_report(
        out,
        {
            "format": report_format,
            "ok": allowed,
            "finalized": True,
            "status": "FINALIZED" if allowed else "DENIED",
            "decision": finalized.decision,
            "bundle": finalized.bundle_path,
            "manifest_sha256": services.sha256_hex(canonical_manifest),
            "record_sha256": record["sha256"],
            "key_id": authentication["key_id"],
            "record": finalized.record_report,
        },
    )
    return 0 if allowed or not args.require_pass else 1


__all__ = [
    "BundleEvidenceServices",
    "FinalizeRecordServices",
    "execute_bundle_evidence",
    "execute_finalize_record",
]
