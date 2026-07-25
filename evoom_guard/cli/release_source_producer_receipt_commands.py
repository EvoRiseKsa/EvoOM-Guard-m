# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Typed stdlib-only owner for the producer-receipt CLI family.

The public :mod:`evoom_guard.cli` facade retains function-entry domain imports,
the shared external-input helper, and the historical live reader, path, and
reporting lookup points. This module owns only the three non-admitting command
state machines and receives every domain and effectful operation explicitly.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

_Output = Callable[[str], None]
_MachineReport = Callable[[_Output, dict[str, object]], None]
_ExternalInputs = tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
]


class _ReadExternalObject(Protocol):
    def __call__(self, path: str, *, label: str) -> dict[str, object]: ...


class _ProducerReceiptExternalInputs(Protocol):
    def __call__(self, args: argparse.Namespace) -> _ExternalInputs: ...


class _CreateProducerReceipt(Protocol):
    def __call__(
        self,
        verdict_path: str,
        handoff_path: str,
        output_path: str,
        *,
        source: Mapping[str, Any],
        context: Mapping[str, Any],
        bootstrap_guard_sha256: str,
        producer: Mapping[str, Any],
        git_repository: str,
        git_repository_is_bare: bool,
        force: bool,
    ) -> Mapping[str, Any]: ...


class _InspectedProducerReceipt(Protocol):
    @property
    def payload(self) -> Mapping[str, Any]: ...


class _VerifiedProducerReceipt(Protocol):
    @property
    def receipt(self) -> _InspectedProducerReceipt: ...


class _VerifyProducerReceipt(Protocol):
    def __call__(
        self,
        receipt_path: str,
        handoff_path: str,
        verdict_path: str,
        *,
        expected_source: Mapping[str, Any],
        expected_context: Mapping[str, Any],
        expected_producer: Mapping[str, Any],
        expected_bootstrap_guard_sha256: str,
        git_repository: str,
        git_repository_is_bare: bool,
    ) -> _VerifiedProducerReceipt: ...


class _CreatedGitHubReceipt(Protocol):
    @property
    def receipt_path(self) -> str: ...

    @property
    def raw_output_path(self) -> str: ...


class _AttestedProducerReceipt(Protocol):
    @property
    def verified(self) -> _VerifiedProducerReceipt: ...

    @property
    def github_receipt(self) -> _CreatedGitHubReceipt: ...


class _ReverifyProducerReceipt(Protocol):
    def __call__(
        self,
        receipt_path: str,
        handoff_path: str,
        verdict_path: str,
        *,
        expected_source: Mapping[str, Any],
        expected_context: Mapping[str, Any],
        expected_producer: Mapping[str, Any],
        expected_bootstrap_guard_sha256: str,
        expected_github_policy: Mapping[str, Any],
        git_repository: str,
        git_repository_is_bare: bool,
        github_receipt_path: str,
        github_raw_output_path: str,
        gh_executable: str,
        timeout_seconds: int,
    ) -> _AttestedProducerReceipt: ...


@dataclass(frozen=True, slots=True)
class CreateProducerReceiptServices:
    """Entry snapshots plus the live create-command facade seams."""

    receipt_format: str
    producer_error: type[Exception]
    create_producer_receipt: _CreateProducerReceipt
    read_external_object_provider: Callable[[], _ReadExternalObject]
    absolute_path_provider: Callable[[], Callable[[str], str]]
    machine_report_provider: Callable[[], _MachineReport]


@dataclass(frozen=True, slots=True)
class VerifyProducerReceiptServices:
    """Entry snapshots plus the live local-verification facade seams."""

    receipt_format: str
    producer_error: type[Exception]
    verify_producer_receipt: _VerifyProducerReceipt
    external_inputs_provider: Callable[[], _ProducerReceiptExternalInputs]
    machine_report_provider: Callable[[], _MachineReport]


@dataclass(frozen=True, slots=True)
class ReverifyProducerReceiptServices:
    """Entry snapshots plus the live fresh-provider facade seams."""

    receipt_format: str
    producer_error: type[Exception]
    reverify_producer_receipt: _ReverifyProducerReceipt
    external_inputs_provider: Callable[[], _ProducerReceiptExternalInputs]
    read_external_object_provider: Callable[[], _ReadExternalObject]
    machine_report_provider: Callable[[], _MachineReport]


def execute_create_producer_receipt(
    args: argparse.Namespace,
    *,
    services: CreateProducerReceiptServices,
    out: _Output = print,
) -> int:
    """Create an unsigned canonical claim; it is never an admission decision."""

    if any(value == "-" for value in (args.verdict, args.handoff)):
        services.machine_report_provider()(
            out,
            {
                "format": services.receipt_format,
                "ok": False,
                "status": "ERROR",
                "error": (
                    "producer receipt verdict and handoff must be regular files, "
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
        producer = services.read_external_object_provider()(
            args.producer,
            label="producer identity",
        )
        receipt = services.create_producer_receipt(
            args.verdict,
            args.handoff,
            args.out,
            source=source,
            context=context,
            bootstrap_guard_sha256=args.bootstrap_guard_sha,
            producer=producer,
            git_repository=args.git_repository,
            git_repository_is_bare=args.git_repository_bare,
            force=args.force,
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        services.producer_error,
    ) as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.receipt_format,
                "ok": False,
                "status": "REJECTED",
                "error": str(exc),
            },
        )
        return 1
    services.machine_report_provider()(
        out,
        {
            "format": services.receipt_format,
            "ok": True,
            "status": "CANONICAL_CLAIM_CREATED",
            "receipt": services.absolute_path_provider()(args.out),
            "record_sha256": receipt["record"]["sha256"],
            "decision": "NONE",
            "admission": False,
            "requires": (
                "fresh-provider-gh-attestation-verify-before-any-future-admission"
            ),
        },
    )
    return 0


def execute_verify_producer_receipt(
    args: argparse.Namespace,
    *,
    services: VerifyProducerReceiptServices,
    out: _Output = print,
) -> int:
    """Verify local/raw-Git producer binding without treating it as provider proof."""

    if any(value == "-" for value in (args.receipt, args.handoff, args.verdict)):
        services.machine_report_provider()(
            out,
            {
                "format": services.receipt_format,
                "ok": False,
                "status": "ERROR",
                "error": (
                    "producer receipt, handoff, and verdict must be regular files, "
                    "not standard input"
                ),
            },
        )
        return 2
    try:
        source, context, producer = services.external_inputs_provider()(args)
        verified = services.verify_producer_receipt(
            args.receipt,
            args.handoff,
            args.verdict,
            expected_source=source,
            expected_context=context,
            expected_producer=producer,
            expected_bootstrap_guard_sha256=args.bootstrap_guard_sha,
            git_repository=args.git_repository,
            git_repository_is_bare=args.git_repository_bare,
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        services.producer_error,
    ) as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.receipt_format,
                "ok": False,
                "verified": False,
                "status": "REJECTED",
                "error": str(exc),
            },
        )
        return 1
    services.machine_report_provider()(
        out,
        {
            "format": services.receipt_format,
            "ok": False,
            "verified": True,
            "status": "NONADMITTING_LOCAL_AND_RAW_GIT_VERIFIED",
            "record_sha256": verified.receipt.payload["record"]["sha256"],
            "decision": "NONE",
            "admission": False,
            "provider_verified": False,
            "requires": (
                "explicit-allow-nonadmitting-evidence-for-archive-only-success"
            ),
        },
    )
    return 0 if args.allow_nonadmitting_evidence else 1


def execute_reverify_producer_receipt(
    args: argparse.Namespace,
    *,
    services: ReverifyProducerReceiptServices,
    out: _Output = print,
) -> int:
    """Make a fresh GitHub provider check after local/raw-Git verification."""

    if any(value == "-" for value in (args.receipt, args.handoff, args.verdict)):
        services.machine_report_provider()(
            out,
            {
                "format": services.receipt_format,
                "ok": False,
                "status": "ERROR",
                "error": (
                    "producer receipt, handoff, and verdict must be regular files, "
                    "not standard input"
                ),
            },
        )
        return 2
    try:
        source, context, producer = services.external_inputs_provider()(args)
        github_policy = services.read_external_object_provider()(
            args.github_policy,
            label="GitHub producer-attestation policy",
        )
        verified = services.reverify_producer_receipt(
            args.receipt,
            args.handoff,
            args.verdict,
            expected_source=source,
            expected_context=context,
            expected_producer=producer,
            expected_bootstrap_guard_sha256=args.bootstrap_guard_sha,
            expected_github_policy=github_policy,
            git_repository=args.git_repository,
            git_repository_is_bare=args.git_repository_bare,
            github_receipt_path=args.github_receipt_out,
            github_raw_output_path=args.github_raw_output_out,
            gh_executable=args.gh_executable,
            timeout_seconds=args.timeout_seconds,
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        services.producer_error,
    ) as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.receipt_format,
                "ok": False,
                "verified": False,
                "status": "REJECTED",
                "error": str(exc),
            },
        )
        return 1
    services.machine_report_provider()(
        out,
        {
            "format": services.receipt_format,
            "ok": False,
            "verified": True,
            "status": "NONADMITTING_FRESH_PROVIDER_VERIFIED",
            "record_sha256": verified.verified.receipt.payload["record"]["sha256"],
            "github_receipt": verified.github_receipt.receipt_path,
            "github_raw_output": verified.github_receipt.raw_output_path,
            "decision": "NONE",
            "admission": False,
            "requires": (
                "explicit-allow-nonadmitting-evidence-for-archive-only-success"
            ),
        },
    )
    return 0 if args.allow_nonadmitting_evidence else 1
