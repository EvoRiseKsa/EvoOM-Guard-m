# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ─────────────────────────────────────────────────────────────────────────────
"""Typed application adapters for the core verdict/record verification CLI family.

The :mod:`evoom_guard.cli` package remains the compatibility facade and retains
the historical dependency lookup points.  This module owns the deterministic
command orchestration for exact-byte signature verification
(``verify-verdict``), semantic record verification (``verify-record``), and
ordered offline bundle verification (``verify-bundle``).  The platform-side
sealing commands (``bundle-evidence``/``finalize-record``) live in
:mod:`evoom_guard.cli.evidence_sealing_commands`.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

_Output = Callable[[str], None]
_ExpectedErrors = tuple[type[Exception], ...]
_RecordReport = dict[str, Any]


class _ReadBoundedBytes(Protocol):
    def __call__(self, path: str, *, limit: int, label: str) -> bytes: ...


class _VerifyBytes(Protocol):
    def __call__(
        self,
        payload: bytes,
        signature: bytes,
        public_key_path: str,
    ) -> bool: ...


class _InspectEvidenceBundle(Protocol):
    def __call__(self, path: str) -> Any: ...


class _VerifyBundleSignature(Protocol):
    def __call__(
        self,
        inspected: Any,
        *,
        trusted_public_key_path: str,
    ) -> None: ...


class _VerifyBundleContext(Protocol):
    def __call__(
        self,
        inspected: Any,
        *,
        expected_context: Mapping[str, Any],
    ) -> None: ...


@dataclass(frozen=True)
class VerifyVerdictServices:
    """Entry-time signature dependencies plus call-time facade seams."""

    read_bounded_bytes: _ReadBoundedBytes
    decode_signature: Callable[[bytes], bytes]
    verify_bytes: _VerifyBytes
    input_errors: _ExpectedErrors
    sha256_hex: Callable[[bytes], str]
    strict_json_loads_provider: Callable[[], Callable[[str], Any]]
    max_record_bytes: int
    max_signature_bytes: int


@dataclass(frozen=True)
class VerifyRecordServices:
    """Dependencies for structural and semantic record verification."""

    read_bounded_bytes: _ReadBoundedBytes
    strict_json_loads: Callable[[str], Any]
    verify_record: Callable[[Any], _RecordReport]
    invalid_json_report: Callable[[str], _RecordReport]
    sha256_hex: Callable[[bytes], str]
    render_report: Callable[[_RecordReport], str]
    max_record_bytes: int


@dataclass(frozen=True)
class VerifyBundleServices:
    """Dependencies for the ordered offline evidence verification pipeline."""

    read_bounded_bytes: _ReadBoundedBytes
    strict_json_loads: Callable[[str], Any]
    verify_record: Callable[[Any], _RecordReport]
    inspect_evidence_bundle: _InspectEvidenceBundle
    verify_bundle_signature: _VerifyBundleSignature
    verify_bundle_context: _VerifyBundleContext
    invalid_bundle_errors: _ExpectedErrors
    signature_operational_errors: _ExpectedErrors
    machine_report: Callable[[_Output, dict[str, object]], None]
    max_context_bytes: int


def execute_verify_verdict(
    args: argparse.Namespace,
    *,
    services: VerifyVerdictServices,
    out: _Output = print,
) -> int:
    """Verify exact verdict bytes, then optionally bind them to context."""

    signature_path = args.sig or (args.verdict + ".sig")
    try:
        payload_bytes = services.read_bounded_bytes(
            args.verdict,
            limit=services.max_record_bytes,
            label="verdict",
        )
        encoded_signature = services.read_bounded_bytes(
            signature_path,
            limit=services.max_signature_bytes,
            label="signature",
        ).strip()
        signature = services.decode_signature(encoded_signature)
        signature_valid = services.verify_bytes(payload_bytes, signature, args.pub)
    except services.input_errors as exc:
        out(f"unusable input: {exc}")
        return 2

    out(f"input sha256: {services.sha256_hex(payload_bytes)}")
    if not signature_valid:
        out("signature: INVALID — the verdict bytes changed after signing")
        return 1
    out("signature: VALID")

    expectations = (
        ("head_sha", getattr(args, "expect_head_sha", None)),
        ("base_sha", getattr(args, "expect_base_sha", None)),
        ("policy_sha256", getattr(args, "expect_policy_sha", None)),
        ("policy_id", getattr(args, "expect_policy_id", None)),
    )
    if not any(wanted for _field, wanted in expectations):
        return 0
    try:
        strict_json_loads = services.strict_json_loads_provider()
        payload = strict_json_loads(payload_bytes.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        out(f"context: UNCHECKABLE — the verdict is not readable JSON ({exc})")
        return 1
    if not isinstance(payload, dict):
        out("context: UNCHECKABLE - the verdict JSON root is not an object")
        return 1

    raw_attestation = payload.get("attestation")
    attestation = raw_attestation if isinstance(raw_attestation, dict) else {}
    failed = False
    for field, wanted in expectations:
        if not wanted:
            continue
        observed = attestation.get(field)
        if observed == wanted:
            out(f"context: {field} matches ({wanted})")
        else:
            out(f"context: MISMATCH — {field} is {observed!r}, expected {wanted!r}")
            failed = True
    if failed:
        out(
            "context: FAILED — the signature is valid but this verdict was not "
            "produced for the expected revision/policy"
        )
        return 1
    return 0


def execute_verify_record(
    args: argparse.Namespace,
    *,
    services: VerifyRecordServices,
    out: _Output = print,
) -> int:
    """Validate record semantics and emit one machine-readable report."""

    try:
        payload_bytes = services.read_bounded_bytes(
            args.verdict,
            limit=services.max_record_bytes,
            label="verdict",
        )
    except (OSError, ValueError) as exc:
        report = services.invalid_json_report(f"unusable JSON input: {exc}")
        out(services.render_report(report))
        return 2

    input_sha256 = services.sha256_hex(payload_bytes)
    try:
        payload = services.strict_json_loads(payload_bytes.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        report = services.invalid_json_report(f"unusable JSON input: {exc}")
        report["input_sha256"] = input_sha256
        report["input_size"] = len(payload_bytes)
        out(services.render_report(report))
        return 2

    report = services.verify_record(payload)
    report["input_sha256"] = input_sha256
    report["input_size"] = len(payload_bytes)
    out(services.render_report(report))
    return 0 if report["ok"] else 1


def execute_verify_bundle(
    args: argparse.Namespace,
    *,
    services: VerifyBundleServices,
    out: _Output = print,
) -> int:
    """Verify container, signature, context, and semantics in fixed order."""

    report_format = "EVOGUARD_EVIDENCE_VERIFICATION_V1"
    try:
        expected_context_bytes = services.read_bounded_bytes(
            args.expect_context,
            limit=services.max_context_bytes,
            label="expected context",
        )
        expected_context = services.strict_json_loads(
            expected_context_bytes.decode("utf-8")
        )
    except (OSError, UnicodeError, ValueError) as exc:
        services.machine_report(
            out,
            {
                "format": report_format,
                "ok": False,
                "verified": False,
                "status": "INCOMPLETE",
                "error": f"unusable expected context: {exc}",
            },
        )
        return 2
    if not isinstance(expected_context, dict):
        services.machine_report(
            out,
            {
                "format": report_format,
                "ok": False,
                "verified": False,
                "status": "INCOMPLETE",
                "error": "expected context JSON must be an object",
            },
        )
        return 2

    claims = {
        "canonical_container": "not_checked",
        "external_key_signature": "not_checked",
        "expected_context": "not_checked",
        "record_semantics": "not_checked",
    }
    try:
        inspected = services.inspect_evidence_bundle(args.bundle)
        claims["canonical_container"] = "pass"
    except services.invalid_bundle_errors as exc:
        claims["canonical_container"] = "fail"
        services.machine_report(
            out,
            {
                "format": report_format,
                "ok": False,
                "verified": False,
                "status": "INVALID",
                "claims": claims,
                "error": str(exc),
            },
        )
        return 1
    except OSError as exc:
        services.machine_report(
            out,
            {
                "format": report_format,
                "ok": False,
                "verified": False,
                "status": "ERROR",
                "claims": claims,
                "error": str(exc),
            },
        )
        return 2

    try:
        services.verify_bundle_signature(
            inspected,
            trusted_public_key_path=args.trusted_pub,
        )
        claims["external_key_signature"] = "pass"
    except services.invalid_bundle_errors as exc:
        claims["external_key_signature"] = "fail"
        services.machine_report(
            out,
            {
                "format": report_format,
                "ok": False,
                "verified": False,
                "status": "INVALID",
                "claims": claims,
                "error": str(exc),
            },
        )
        return 1
    except services.signature_operational_errors as exc:
        services.machine_report(
            out,
            {
                "format": report_format,
                "ok": False,
                "verified": False,
                "status": "INCOMPLETE",
                "claims": claims,
                "error": str(exc),
            },
        )
        return 2

    try:
        services.verify_bundle_context(
            inspected,
            expected_context=expected_context,
        )
        claims["expected_context"] = "pass"
    except services.invalid_bundle_errors as exc:
        claims["expected_context"] = "fail"
        services.machine_report(
            out,
            {
                "format": report_format,
                "ok": False,
                "verified": False,
                "status": "INVALID",
                "claims": claims,
                "error": str(exc),
            },
        )
        return 1

    verdict_record = inspected.verdict
    record_report = services.verify_record(verdict_record)
    claims["record_semantics"] = "pass" if record_report["ok"] else "fail"
    verified = bool(record_report["ok"])
    decision = {
        field: verdict_record.get(field)
        for field in ("verdict", "passed", "reason_code", "exit_code")
    }
    pass_gate = (
        verified
        and verdict_record.get("verdict") == "PASS"
        and verdict_record.get("passed") is True
    )
    require_pass = bool(getattr(args, "require_pass", False))
    ok = verified and (pass_gate or not require_pass)
    status = "VERIFIED" if ok else ("DENIED" if verified else "INVALID")
    authentication = inspected.manifest["authentication"]
    services.machine_report(
        out,
        {
            "format": report_format,
            "ok": ok,
            "verified": verified,
            "status": status,
            "claims": claims,
            "decision": decision,
            "pass_gate": "ALLOW" if pass_gate else "DENY",
            "key_id": authentication["key_id"],
            "context": inspected.manifest["context"],
            "record": record_report,
        },
    )
    return 0 if ok else 1


__all__ = [
    "VerifyBundleServices",
    "VerifyRecordServices",
    "VerifyVerdictServices",
    "execute_verify_bundle",
    "execute_verify_record",
    "execute_verify_verdict",
]
