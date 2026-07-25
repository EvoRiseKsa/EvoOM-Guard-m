# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Typed stdlib-only owner for GitHub attestation receipt CLI commands.

The public :mod:`evoom_guard.cli` facade retains domain import and helper
lookup timing.  This module owns only the create, retained verification, and
fresh re-verification state machines, with every effect injected explicitly.
The retained verifier intentionally has no GitHub CLI or provider-isolation
service.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, TypedDict

_Output = Callable[[str], None]
_MachineReport = Callable[[_Output, dict[str, object]], None]


class _GitHubAttestationPolicyKwargs(TypedDict):
    repository: str
    signer_workflow: str
    signer_digest: str
    source_ref: str
    source_digest: str
    cert_oidc_issuer: str


class _PolicyKwargsBuilder(Protocol):
    def __call__(
        self,
        args: argparse.Namespace,
    ) -> _GitHubAttestationPolicyKwargs: ...


class _ProviderIsolationBuilder(Protocol):
    def __call__(self, args: argparse.Namespace) -> Any: ...


class _AsDictValue(Protocol):
    def as_dict(self) -> dict[str, Any]: ...


class _CreatedGitHubAttestationReceipt(Protocol):
    @property
    def receipt_path(self) -> str: ...

    @property
    def raw_output_path(self) -> str: ...

    @property
    def artifact(self) -> _AsDictValue: ...

    @property
    def policy(self) -> _AsDictValue: ...

    @property
    def verified_attestation_count(self) -> int: ...


class _CreateGitHubAttestationReceipt(Protocol):
    def __call__(
        self,
        artifact_path: str,
        receipt_path: str,
        raw_output_path: str,
        *,
        repository: str,
        signer_workflow: str,
        signer_digest: str,
        source_ref: str,
        source_digest: str,
        cert_oidc_issuer: str,
        gh_executable: str,
        timeout_seconds: int,
        provider_isolation: Any,
    ) -> _CreatedGitHubAttestationReceipt: ...


class _VerifiedGitHubAttestationReceipt(Protocol):
    @property
    def artifact(self) -> _AsDictValue: ...

    @property
    def policy(self) -> _AsDictValue: ...


class _VerifyGitHubAttestationReceipt(Protocol):
    def __call__(
        self,
        receipt_path: str,
        artifact_path: str,
        raw_output_path: str,
        *,
        repository: str,
        signer_workflow: str,
        signer_digest: str,
        source_ref: str,
        source_digest: str,
        cert_oidc_issuer: str,
    ) -> _VerifiedGitHubAttestationReceipt: ...


class _FreshGitHubAttestationVerification(Protocol):
    @property
    def artifact(self) -> _AsDictValue: ...

    @property
    def policy(self) -> _AsDictValue: ...

    @property
    def verified_attestation_count(self) -> int: ...


class _ReverifyGitHubAttestationReceipt(Protocol):
    def __call__(
        self,
        receipt_path: str,
        artifact_path: str,
        *,
        repository: str,
        signer_workflow: str,
        signer_digest: str,
        source_ref: str,
        source_digest: str,
        cert_oidc_issuer: str,
        gh_executable: str,
        timeout_seconds: int,
        provider_isolation: Any,
    ) -> _FreshGitHubAttestationVerification: ...


@dataclass(frozen=True, slots=True)
class CreateGitHubAttestationReceiptServices:
    """Entry snapshots plus live policy, isolation, and reporting seams."""

    receipt_format: str
    github_error: type[Exception]
    create_github_attestation_receipt: _CreateGitHubAttestationReceipt
    policy_kwargs_provider: Callable[[], _PolicyKwargsBuilder]
    provider_isolation_provider: Callable[[], _ProviderIsolationBuilder]
    machine_report_provider: Callable[[], _MachineReport]


@dataclass(frozen=True, slots=True)
class VerifyGitHubAttestationReceiptServices:
    """Retained-only verification dependencies with no connected seams."""

    receipt_format: str
    github_error: type[Exception]
    verify_github_attestation_receipt: _VerifyGitHubAttestationReceipt
    policy_kwargs_provider: Callable[[], _PolicyKwargsBuilder]
    machine_report_provider: Callable[[], _MachineReport]


@dataclass(frozen=True, slots=True)
class ReverifyGitHubAttestationReceiptServices:
    """Entry snapshots plus live policy, isolation, and reporting seams."""

    receipt_format: str
    github_error: type[Exception]
    reverify_github_attestation_receipt: _ReverifyGitHubAttestationReceipt
    policy_kwargs_provider: Callable[[], _PolicyKwargsBuilder]
    provider_isolation_provider: Callable[[], _ProviderIsolationBuilder]
    machine_report_provider: Callable[[], _MachineReport]


def execute_github_attestation_receipt(
    args: argparse.Namespace,
    *,
    services: CreateGitHubAttestationReceiptServices,
    out: _Output = print,
) -> int:
    """Run the narrow provider verifier and retain its exact bounded evidence."""

    try:
        created = services.create_github_attestation_receipt(
            args.artifact,
            args.receipt_out,
            args.raw_output_out,
            **services.policy_kwargs_provider()(args),
            gh_executable=args.gh_executable,
            timeout_seconds=args.timeout_seconds,
            provider_isolation=services.provider_isolation_provider()(args),
        )
    except services.github_error as exc:
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
    except (OSError, ValueError) as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.receipt_format,
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
            "format": services.receipt_format,
            "ok": True,
            "verified": True,
            "status": "PROVIDER_VERIFIED",
            "verification_scope": "fresh-provider-gh-attestation-verify",
            "receipt": created.receipt_path,
            "raw_output": created.raw_output_path,
            "artifact": created.artifact.as_dict(),
            "verification_policy": created.policy.as_dict(),
            "verified_attestation_count": created.verified_attestation_count,
        },
    )
    return 0


def execute_verify_github_attestation_receipt(
    args: argparse.Namespace,
    *,
    services: VerifyGitHubAttestationReceiptServices,
    out: _Output = print,
) -> int:
    """Check retained evidence continuity without making a live provider call."""

    try:
        verified = services.verify_github_attestation_receipt(
            args.receipt,
            args.artifact,
            args.raw_output,
            **services.policy_kwargs_provider()(args),
        )
    except services.github_error as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.receipt_format,
                "ok": False,
                "verified": False,
                "status": "INVALID",
                "error": str(exc),
            },
        )
        return 1
    except (OSError, ValueError) as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.receipt_format,
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
            "format": services.receipt_format,
            "ok": True,
            "verified": True,
            "status": "RETAINED_RECEIPT_VERIFIED",
            "verification_scope": "retained-byte-continuity-only",
            "live_provider_reverification": False,
            "artifact": verified.artifact.as_dict(),
            "verification_policy": verified.policy.as_dict(),
        },
    )
    return 0


def execute_reverify_github_attestation_receipt(
    args: argparse.Namespace,
    *,
    services: ReverifyGitHubAttestationReceiptServices,
    out: _Output = print,
) -> int:
    """Make a fresh constrained GitHub CLI verification for a retained receipt."""

    try:
        fresh = services.reverify_github_attestation_receipt(
            args.receipt,
            args.artifact,
            **services.policy_kwargs_provider()(args),
            gh_executable=args.gh_executable,
            timeout_seconds=args.timeout_seconds,
            provider_isolation=services.provider_isolation_provider()(args),
        )
    except services.github_error as exc:
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
    except (OSError, ValueError) as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.receipt_format,
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
            "format": services.receipt_format,
            "ok": True,
            "verified": True,
            "status": "FRESH_PROVIDER_REVERIFIED",
            "verification_scope": "fresh-provider-gh-attestation-verify",
            "artifact": fresh.artifact.as_dict(),
            "verification_policy": fresh.policy.as_dict(),
            "verified_attestation_count": fresh.verified_attestation_count,
            "reverification": "fresh-gh-attestation-verify",
        },
    )
    return 0
