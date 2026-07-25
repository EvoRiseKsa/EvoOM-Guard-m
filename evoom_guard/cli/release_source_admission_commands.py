# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Typed stdlib-only owner for Release Source Admission CLI commands.

The sealing state machine receives only the explicit protected-runtime,
provider-verification, signing, trusted-input, and reporting seams it needs.
The detached verifier has a separate service bundle and structurally exposes
no environment, Git/GitHub execution, provider isolation, private key,
preflight mutation, or output-publication capability.

Function-local domain imports remain in :mod:`evoom_guard.cli`, preserving
their historical entry-snapshot semantics.  Trusted readers, facade helpers,
ambient-environment lookup, and reporting remain live at their original use
sites through zero-argument providers.
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


class _ProducerInputs(Protocol):
    def __call__(
        self,
        args: argparse.Namespace,
    ) -> tuple[
        Mapping[str, Any],
        Mapping[str, Any],
        Mapping[str, Any],
    ]: ...


class _KeySeparation(Protocol):
    def __call__(self, args: argparse.Namespace) -> dict[str, str]: ...


class _Preflight(Protocol):
    def __call__(self, args: argparse.Namespace) -> None: ...


class _PublicKeyId(Protocol):
    def __call__(self, public_key_path: str) -> str: ...


class _GitExecutablePin(Protocol):
    def __call__(self, path: str, expected_sha256: str, /) -> Any: ...


class _ProviderIsolation(Protocol):
    def __call__(
        self,
        executable_path: str,
        executable_sha256: str,
        *,
        uid: int,
        gid: int,
    ) -> Any: ...


class _VerifyAdmitterWorkflow(Protocol):
    def __call__(
        self,
        *,
        source: Mapping[str, Any],
        producer: Mapping[str, Any],
        admitter: Mapping[str, Any],
        git_repository: str,
        git_repository_is_bare: bool,
        git_executable: Any,
    ) -> Any: ...


class _ValidateAdmitterRuntime(Protocol):
    def __call__(
        self,
        admitter: Any,
        producer: Mapping[str, Any],
        *,
        environment: Mapping[str, str],
        event_payload: Mapping[str, Any],
    ) -> Any: ...


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
        provider_isolation: Any,
        protected_signing_key_path: str,
        git_executable: Any,
    ) -> Any: ...


class _SealedReleaseSourceAdmission(Protocol):
    @property
    def bundle_path(self) -> str: ...

    @property
    def manifest(self) -> Mapping[str, Any]: ...

    @property
    def decision(self) -> str: ...


class _SealReleaseSourceAdmission(Protocol):
    def __call__(
        self,
        attested: Any,
        output_path: str,
        *,
        admitter: Any,
        key_separation: Mapping[str, Any],
        git_repository: str,
        git_repository_is_bare: bool,
        git_executable: Any,
        provider_isolation: Any,
        private_key_path: str,
        signing_public_key_path: str,
        expected_signing_key_id: str,
        force: bool,
    ) -> _SealedReleaseSourceAdmission: ...


class _VerifiedBundle(Protocol):
    @property
    def manifest(self) -> Mapping[str, Any]: ...


class _VerifiedReleaseSourceAdmission(Protocol):
    @property
    def bundle(self) -> _VerifiedBundle: ...

    @property
    def decision(self) -> str: ...


class _VerifyReleaseSourceAdmission(Protocol):
    def __call__(
        self,
        bundle_path: str,
        *,
        trusted_public_key_path: str,
        expected_source: Mapping[str, Any],
        expected_context: Mapping[str, Any],
        expected_producer: Mapping[str, Any],
        expected_admitter: Mapping[str, Any],
        expected_bootstrap_guard_sha256: str,
        expected_github_policy: Mapping[str, Any],
        expected_key_separation: Mapping[str, Any],
        expected_git_executable_sha256: str,
        expected_github_cli_executable_sha256: str,
        expected_provider_isolation_uid: int,
        expected_provider_isolation_gid: int,
    ) -> _VerifiedReleaseSourceAdmission: ...


@dataclass(frozen=True, slots=True)
class SealReleaseSourceAdmissionServices:
    """Entry snapshots plus explicitly live protected sealing seams."""

    admission_format: str
    release_source_error: type[Exception]
    producer_receipt_error: type[Exception]
    github_error: type[Exception]
    finalizer_error: type[Exception]
    signing_unavailable_error: type[Exception]
    git_executable_pin: _GitExecutablePin
    provider_isolation: _ProviderIsolation
    verify_admitter_workflow: _VerifyAdmitterWorkflow
    validate_admitter_runtime: _ValidateAdmitterRuntime
    reverify_producer_receipt: _ReverifyProducerReceipt
    seal_release_source_admission: _SealReleaseSourceAdmission
    public_key_id: _PublicKeyId
    producer_inputs_provider: Callable[[], _ProducerInputs]
    read_external_object_provider: Callable[[], _ReadExternalObject]
    key_separation_provider: Callable[[], _KeySeparation]
    preflight_provider: Callable[[], _Preflight]
    environment_provider: Callable[[], Mapping[str, str]]
    machine_report_provider: Callable[[], _MachineReport]


@dataclass(frozen=True, slots=True)
class VerifyReleaseSourceAdmissionServices:
    """Detached verification dependencies with no connected execution seam."""

    admission_format: str
    release_source_error: type[Exception]
    signing_unavailable_error: type[Exception]
    verify_release_source_admission: _VerifyReleaseSourceAdmission
    read_external_object_provider: Callable[[], _ReadExternalObject]
    key_separation_provider: Callable[[], _KeySeparation]
    machine_report_provider: Callable[[], _MachineReport]


def execute_seal_release_source_admission(
    args: argparse.Namespace,
    *,
    services: SealReleaseSourceAdmissionServices,
    out: _Output = print,
) -> int:
    """Freshly verify the protected producer relation, then sign one V2 ALLOW."""

    if any(value == "-" for value in (args.receipt, args.handoff, args.verdict)):
        services.machine_report_provider()(
            out,
            {
                "format": services.admission_format,
                "ok": False,
                "sealed": False,
                "status": "ERROR",
                "error": (
                    "producer receipt, handoff, and verdict must be regular "
                    "files, not standard input"
                ),
            },
        )
        return 2
    try:
        source, context, producer = services.producer_inputs_provider()(args)
        admitter = services.read_external_object_provider()(
            args.admitter,
            label="expected release-source admitter",
        )
        github_policy = services.read_external_object_provider()(
            args.github_policy,
            label="GitHub producer-attestation policy",
        )
        key_separation = services.key_separation_provider()(args)
        expected_signing_key_id = services.public_key_id(args.sign_pub)
        if expected_signing_key_id in set(key_separation.values()):
            raise ValueError(
                "release-source admission public key belongs to another "
                "configured trust domain"
            )
        services.preflight_provider()(args)
        git_executable = services.git_executable_pin(
            args.git_executable,
            args.git_executable_sha256,
        )
        provider_isolation = services.provider_isolation(
            args.gh_executable,
            args.gh_executable_sha256,
            uid=args.provider_isolation_uid,
            gid=args.provider_isolation_gid,
        )
        admitter = services.verify_admitter_workflow(
            source=source,
            producer=producer,
            admitter=admitter,
            git_repository=args.git_repository,
            git_repository_is_bare=args.git_repository_bare,
            git_executable=git_executable,
        )
        event_path = services.environment_provider().get("GITHUB_EVENT_PATH")
        if not event_path:
            raise ValueError(
                "seal-release-source-admission requires GitHub Actions "
                "GITHUB_EVENT_PATH"
            )
        event_payload = services.read_external_object_provider()(
            event_path,
            label="GitHub Actions workflow_run event payload",
        )
        runtime_admitter = services.validate_admitter_runtime(
            admitter,
            producer,
            environment=services.environment_provider(),
            event_payload=event_payload,
        )
        attested = services.reverify_producer_receipt(
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
            provider_isolation=provider_isolation,
            protected_signing_key_path=args.sign_key,
            git_executable=git_executable,
        )
        sealed = services.seal_release_source_admission(
            attested,
            args.out,
            admitter=runtime_admitter,
            key_separation=key_separation,
            git_repository=args.git_repository,
            git_repository_is_bare=args.git_repository_bare,
            git_executable=git_executable,
            provider_isolation=provider_isolation,
            private_key_path=args.sign_key,
            signing_public_key_path=args.sign_pub,
            expected_signing_key_id=expected_signing_key_id,
            force=args.force,
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        services.release_source_error,
        services.producer_receipt_error,
        services.github_error,
        services.finalizer_error,
        services.signing_unavailable_error,
    ) as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.admission_format,
                "ok": False,
                "sealed": False,
                "status": "REJECTED",
                "error": str(exc),
            },
        )
        return 1
    services.machine_report_provider()(
        out,
        {
            "format": services.admission_format,
            "ok": True,
            "sealed": True,
            "verified": True,
            "status": "SEALED",
            "bundle": sealed.bundle_path,
            "key_id": sealed.manifest["authentication"]["key_id"],
            "record_sha256": sealed.manifest["record"]["sha256"],
            "producer_receipt_sha256": (
                sealed.manifest["producer_receipt"]["sha256"]
            ),
            "decision": sealed.decision,
            "admission": True,
            "provider_verified": True,
        },
    )
    return 0


def execute_verify_release_source_admission(
    args: argparse.Namespace,
    *,
    services: VerifyReleaseSourceAdmissionServices,
    out: _Output = print,
) -> int:
    """Verify a V2 source authorization using only external trust roots."""

    if args.bundle == "-":
        services.machine_report_provider()(
            out,
            {
                "format": services.admission_format,
                "ok": False,
                "verified": False,
                "status": "ERROR",
                "error": (
                    "release-source admission bundle must be a regular file, "
                    "not standard input"
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
        producer = services.read_external_object_provider()(
            args.expected_producer,
            label="expected producer identity",
        )
        admitter = services.read_external_object_provider()(
            args.expected_admitter,
            label="expected protected C workflow identity",
        )
        github_policy = services.read_external_object_provider()(
            args.expected_github_policy,
            label="expected GitHub producer-attestation policy",
        )
        key_separation = services.key_separation_provider()(args)
        verified = services.verify_release_source_admission(
            args.bundle,
            trusted_public_key_path=args.trusted_pub,
            expected_source=source,
            expected_context=context,
            expected_producer=producer,
            expected_admitter=admitter,
            expected_bootstrap_guard_sha256=args.expected_bootstrap_guard_sha,
            expected_github_policy=github_policy,
            expected_key_separation=key_separation,
            expected_git_executable_sha256=args.expected_git_executable_sha256,
            expected_github_cli_executable_sha256=(
                args.expected_gh_executable_sha256
            ),
            expected_provider_isolation_uid=args.expected_provider_isolation_uid,
            expected_provider_isolation_gid=args.expected_provider_isolation_gid,
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        services.release_source_error,
        services.signing_unavailable_error,
    ) as exc:
        services.machine_report_provider()(
            out,
            {
                "format": services.admission_format,
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
            "format": services.admission_format,
            "ok": True,
            "verified": True,
            "status": "VERIFIED",
            "key_id": verified.bundle.manifest["authentication"]["key_id"],
            "record_sha256": verified.bundle.manifest["record"]["sha256"],
            "producer_receipt_sha256": (
                verified.bundle.manifest["producer_receipt"]["sha256"]
            ),
            "decision": verified.decision,
            "admission": True,
        },
    )
    return 0
