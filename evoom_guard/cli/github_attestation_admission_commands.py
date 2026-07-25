# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Typed stdlib-only owner for GitHub attestation admission CLI commands.

The public :mod:`evoom_guard.cli` facade retains function-local domain imports
and every historically live helper lookup.  This module owns only the two
independent seal and retained-verification state machines.  The retained
verifier service structurally exposes no GitHub executable, provider isolation,
network, private-key/signing operation, or output-mutation seam.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
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


class _ReadExternalObject(Protocol):
    def __call__(self, path: str, *, label: str) -> dict[str, object]: ...


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


class _VerifiedGitHubAttestationReceipt(Protocol):
    @property
    def artifact(self) -> _AsDictValue: ...

    @property
    def policy(self) -> _AsDictValue: ...


class _SealedAdmission(Protocol):
    @property
    def binding_path(self) -> str: ...

    @property
    def subject(self) -> _AsDictValue: ...

    @property
    def provenance_reference(self) -> _AsDictValue: ...

    @property
    def payload(self) -> Mapping[str, Any]: ...


class _SealedGitHubAttestationAdmission(Protocol):
    @property
    def receipt(self) -> _CreatedGitHubAttestationReceipt: ...

    @property
    def admission(self) -> _SealedAdmission: ...


class _SealGitHubAttestationAdmission(Protocol):
    def __call__(
        self,
        artifact_path: str,
        receipt_path: str,
        raw_output_path: str,
        finalizer_bundle_path: str,
        output_path: str,
        *,
        repository: str,
        signer_workflow: str,
        signer_digest: str,
        source_ref: str,
        source_digest: str,
        cert_oidc_issuer: str,
        trusted_finalizer_public_key_path: str,
        expected_finalizer_source: Mapping[str, Any],
        expected_finalizer_context: Mapping[str, Any],
        private_key_path: str,
        gh_executable: str,
        timeout_seconds: int,
        provider_isolation: Any,
    ) -> _SealedGitHubAttestationAdmission: ...


class _InspectedAdmission(Protocol):
    @property
    def finalizer(self) -> Mapping[str, Any]: ...

    @property
    def payload(self) -> Mapping[str, Any]: ...


class _VerifiedAdmission(Protocol):
    @property
    def subject(self) -> _AsDictValue: ...

    @property
    def provenance_reference(self) -> _AsDictValue: ...

    @property
    def inspection(self) -> _InspectedAdmission: ...


class _VerifiedGitHubAttestationAdmission(Protocol):
    @property
    def receipt(self) -> _VerifiedGitHubAttestationReceipt: ...

    @property
    def admission(self) -> _VerifiedAdmission: ...


class _VerifyGitHubAttestationAdmission(Protocol):
    def __call__(
        self,
        binding_path: str,
        artifact_path: str,
        receipt_path: str,
        raw_output_path: str,
        finalizer_bundle_path: str,
        *,
        repository: str,
        signer_workflow: str,
        signer_digest: str,
        source_ref: str,
        source_digest: str,
        cert_oidc_issuer: str,
        trusted_public_key_path: str,
        trusted_finalizer_public_key_path: str,
        expected_finalizer_source: Mapping[str, Any],
        expected_finalizer_context: Mapping[str, Any],
    ) -> _VerifiedGitHubAttestationAdmission: ...


@dataclass(frozen=True, slots=True)
class SealGitHubAttestationAdmissionServices:
    """Entry snapshots plus live trusted-reader, policy, isolation, and report seams."""

    binding_format: str
    github_error: type[Exception]
    signing_unavailable_error: type[Exception]
    seal_github_attestation_admission: _SealGitHubAttestationAdmission
    read_external_object_provider: Callable[[], _ReadExternalObject]
    policy_kwargs_provider: Callable[[], _PolicyKwargsBuilder]
    provider_isolation_provider: Callable[[], _ProviderIsolationBuilder]
    machine_report_provider: Callable[[], _MachineReport]


@dataclass(frozen=True, slots=True)
class VerifyGitHubAttestationAdmissionServices:
    """Retained-only verification dependencies with no connected execution seam."""

    binding_format: str
    github_error: type[Exception]
    signing_unavailable_error: type[Exception]
    verify_github_attestation_admission: _VerifyGitHubAttestationAdmission
    read_external_object_provider: Callable[[], _ReadExternalObject]
    policy_kwargs_provider: Callable[[], _PolicyKwargsBuilder]
    machine_report_provider: Callable[[], _MachineReport]


def execute_seal_github_attestation_admission(
    args: argparse.Namespace,
    *,
    services: SealGitHubAttestationAdmissionServices,
    out: _Output = print,
) -> int:
    """Freshly verify provider evidence, then bind it to a finalizer ALLOW."""

    regular_paths = (
        args.artifact,
        args.finalizer_bundle,
        args.receipt_out,
        args.raw_output_out,
        args.out,
        args.finalizer_pub,
        args.sign_key,
    )
    if any(value == "-" for value in regular_paths):
        services.machine_report_provider()(
            out,
            {
                "format": services.binding_format,
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": (
                    "artifact, finalizer bundle, receipt, raw output, binding, and key "
                    "paths must be regular files, not standard input/output"
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
        sealed = services.seal_github_attestation_admission(
            args.artifact,
            args.receipt_out,
            args.raw_output_out,
            args.finalizer_bundle,
            args.out,
            **services.policy_kwargs_provider()(args),
            trusted_finalizer_public_key_path=args.finalizer_pub,
            expected_finalizer_source=expected_source,
            expected_finalizer_context=expected_context,
            private_key_path=args.sign_key,
            gh_executable=args.gh_executable,
            timeout_seconds=args.timeout_seconds,
            provider_isolation=services.provider_isolation_provider()(args),
        )
    except services.github_error as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.binding_format,
                "ok": False,
                "sealed": False,
                "status": "REJECTED",
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
            "verification_scope": (
                "fresh-provider-gh-attestation-verify-plus-trusted-finalizer-allow"
            ),
            "receipt": sealed.receipt.receipt_path,
            "raw_output": sealed.receipt.raw_output_path,
            "binding": sealed.admission.binding_path,
            "artifact": sealed.receipt.artifact.as_dict(),
            "verification_policy": sealed.receipt.policy.as_dict(),
            "subject": sealed.admission.subject.as_dict(),
            "provenance_reference": sealed.admission.provenance_reference.as_dict(),
            "finalizer": sealed.admission.payload["finalizer"],
            "key_id": sealed.admission.payload["authentication"]["key_id"],
        },
    )
    return 0


def execute_verify_github_attestation_admission(
    args: argparse.Namespace,
    *,
    services: VerifyGitHubAttestationAdmissionServices,
    out: _Output = print,
) -> int:
    """Verify retained provider bytes and their V2 finalizer-bound relation."""

    regular_paths = (
        args.binding,
        args.artifact,
        args.receipt,
        args.raw_output,
        args.finalizer_bundle,
        args.trusted_pub,
        args.finalizer_pub,
    )
    if any(value == "-" for value in regular_paths):
        services.machine_report_provider()(
            out,
            {
                "format": services.binding_format,
                "ok": False,
                "verified": False,
                "status": "ERROR",
                "error": (
                    "binding, artifact, receipt, raw output, finalizer bundle, and key "
                    "paths must be regular files, not standard input/output"
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
        verified = services.verify_github_attestation_admission(
            args.binding,
            args.artifact,
            args.receipt,
            args.raw_output,
            args.finalizer_bundle,
            **services.policy_kwargs_provider()(args),
            trusted_public_key_path=args.trusted_pub,
            trusted_finalizer_public_key_path=args.finalizer_pub,
            expected_finalizer_source=expected_source,
            expected_finalizer_context=expected_context,
        )
    except services.github_error as exc:
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
            "verification_scope": "retained-provider-bytes-plus-trusted-finalizer-allow",
            "live_provider_reverification": False,
            "artifact": verified.receipt.artifact.as_dict(),
            "verification_policy": verified.receipt.policy.as_dict(),
            "subject": verified.admission.subject.as_dict(),
            "provenance_reference": verified.admission.provenance_reference.as_dict(),
            "finalizer": verified.admission.inspection.finalizer,
            "key_id": verified.admission.inspection.payload["authentication"]["key_id"],
        },
    )
    return 0
