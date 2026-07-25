# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Typed stdlib-only owner for Release Artifact Admission CLI commands.

The public :mod:`evoom_guard.cli` facade retains function-entry snapshots of
the domain callables, formats, and exception classes.  This module owns only
the online seal and detached offline verification state machines.  Every
historically live environment, preflight, trust-reader, nested-expectation,
key-registry, and reporting lookup remains an explicit call-time provider.

The detached verifier service deliberately has no environment, Git executable,
GitHub CLI, provider-isolation, private-key, signing-operation, repository, or
output-mutation capability.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

_Output = Callable[[str], None]
_MachineReport = Callable[[_Output, dict[str, object]], None]
_NestedValues = tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
]


class _Environment(Protocol):
    def get(self, key: str) -> str | None: ...


class _ReadExternalObject(Protocol):
    def __call__(self, path: str, *, label: str) -> dict[str, object]: ...


class _NestedExpectations(Protocol):
    def __call__(self, args: argparse.Namespace) -> _NestedValues: ...


class _PreflightPaths(Protocol):
    def __call__(
        self,
        args: argparse.Namespace,
        *,
        event_path: str,
    ) -> None: ...


class _KeySeparation(Protocol):
    def __call__(self, args: argparse.Namespace) -> dict[str, str]: ...


class _PublicKeyId(Protocol):
    def __call__(self, public_key_path: str) -> str: ...


class _GitExecutablePin(Protocol):
    def __call__(
        self,
        executable_path: str,
        executable_sha256: str,
    ) -> Any: ...


class _ProviderIsolation(Protocol):
    def __call__(
        self,
        executable_path: str,
        executable_sha256: str,
        *,
        uid: int,
        gid: int,
    ) -> Any: ...


class _BindRuntimeAdmitter(Protocol):
    def __call__(
        self,
        builder: Mapping[str, Any],
        admitter: Mapping[str, Any],
        *,
        source: Mapping[str, Any],
        environment: Any,
        event_payload: Mapping[str, Any],
    ) -> Any: ...


class _AsDictValue(Protocol):
    def as_dict(self) -> dict[str, Any]: ...


class _SealedReleaseArtifactAdmission(Protocol):
    @property
    def bundle_path(self) -> str: ...

    @property
    def artifact(self) -> _AsDictValue: ...

    @property
    def manifest(self) -> Mapping[str, Any]: ...

    @property
    def decision(self) -> str: ...


class _SealReleaseArtifactAdmission(Protocol):
    def __call__(
        self,
        release_source_admission_path: str,
        artifact_path: str,
        output_path: str,
        *,
        admitter: Any,
        trusted_release_source_public_key_path: str,
        expected_release_source: Mapping[str, Any],
        expected_release_source_context: Mapping[str, Any],
        expected_release_source_producer: Mapping[str, Any],
        expected_release_source_admitter: Mapping[str, Any],
        expected_release_source_bootstrap_guard_sha256: str,
        expected_release_source_github_policy: Mapping[str, Any],
        expected_release_source_git_executable_sha256: str,
        expected_release_source_github_cli_executable_sha256: str,
        expected_release_source_provider_isolation_uid: int,
        expected_release_source_provider_isolation_gid: int,
        key_separation: Mapping[str, Any],
        git_repository: str,
        git_repository_is_bare: bool,
        git_executable: Any,
        provider_isolation: Any,
        private_key_path: str,
        signing_public_key_path: str,
        expected_signing_key_id: str,
        gh_executable: str,
        timeout_seconds: int,
    ) -> _SealedReleaseArtifactAdmission: ...


class _InspectedReleaseArtifactAdmission(Protocol):
    @property
    def manifest(self) -> Mapping[str, Any]: ...


class _VerifiedReleaseArtifactAdmission(Protocol):
    @property
    def bundle(self) -> _InspectedReleaseArtifactAdmission: ...

    @property
    def artifact(self) -> _AsDictValue: ...

    @property
    def decision(self) -> str: ...


class _VerifyReleaseArtifactAdmission(Protocol):
    def __call__(
        self,
        bundle_path: str,
        artifact_path: str,
        *,
        trusted_public_key_path: str,
        trusted_release_source_public_key_path: str,
        expected_release_source: Mapping[str, Any],
        expected_release_source_context: Mapping[str, Any],
        expected_release_source_producer: Mapping[str, Any],
        expected_release_source_admitter: Mapping[str, Any],
        expected_release_source_bootstrap_guard_sha256: str,
        expected_release_source_github_policy: Mapping[str, Any],
        expected_release_source_git_executable_sha256: str,
        expected_release_source_github_cli_executable_sha256: str,
        expected_release_source_provider_isolation_uid: int,
        expected_release_source_provider_isolation_gid: int,
        expected_builder: Mapping[str, Any],
        expected_admitter: Mapping[str, Any],
        expected_key_separation: Mapping[str, Any],
        expected_git_executable_sha256: str,
        expected_github_cli_executable_sha256: str,
        expected_provider_isolation_uid: int,
        expected_provider_isolation_gid: int,
    ) -> _VerifiedReleaseArtifactAdmission: ...


@dataclass(frozen=True, slots=True)
class SealGitHubReleaseArtifactAdmissionServices:
    """Online seal snapshots plus historically live facade seams."""

    admission_format: str
    release_artifact_error: type[Exception]
    github_error: type[Exception]
    finalizer_error: type[Exception]
    signing_unavailable_error: type[Exception]
    bind_runtime_admitter: _BindRuntimeAdmitter
    seal_release_artifact_admission: _SealReleaseArtifactAdmission
    public_key_id: _PublicKeyId
    git_executable_pin: _GitExecutablePin
    provider_isolation: _ProviderIsolation
    environment_provider: Callable[[], _Environment]
    preflight_provider: Callable[[], _PreflightPaths]
    nested_expectations_provider: Callable[[], _NestedExpectations]
    read_external_object_provider: Callable[[], _ReadExternalObject]
    key_separation_provider: Callable[[], _KeySeparation]
    machine_report_provider: Callable[[], _MachineReport]


@dataclass(frozen=True, slots=True)
class VerifyGitHubReleaseArtifactAdmissionServices:
    """Detached verification dependencies with no connected execution seam."""

    admission_format: str
    release_artifact_error: type[Exception]
    signing_unavailable_error: type[Exception]
    verify_release_artifact_admission: _VerifyReleaseArtifactAdmission
    nested_expectations_provider: Callable[[], _NestedExpectations]
    read_external_object_provider: Callable[[], _ReadExternalObject]
    key_separation_provider: Callable[[], _KeySeparation]
    machine_report_provider: Callable[[], _MachineReport]


def execute_seal_github_release_artifact_admission(
    args: argparse.Namespace,
    *,
    services: SealGitHubReleaseArtifactAdmissionServices,
    out: _Output = print,
) -> int:
    """Bind the live F job to E, freshly verify GitHub, then seal one RAAE."""

    try:
        event_path = services.environment_provider().get("GITHUB_EVENT_PATH")
        if not event_path:
            raise ValueError(
                "seal-github-release-artifact-admission requires GitHub Actions GITHUB_EVENT_PATH"
            )
        services.preflight_provider()(args, event_path=event_path)
        source, context, producer, source_admitter, source_policy = (
            services.nested_expectations_provider()(args)
        )
        builder = services.read_external_object_provider()(
            args.builder,
            label="protected release-artifact builder identity",
        )
        admitter = services.read_external_object_provider()(
            args.admitter,
            label="protected release-artifact admitter identity",
        )
        event_payload = services.read_external_object_provider()(
            event_path,
            label="GitHub Actions release-artifact workflow_run event payload",
        )
        runtime_admitter = services.bind_runtime_admitter(
            builder,
            admitter,
            source=source,
            environment=services.environment_provider(),
            event_payload=event_payload,
        )
        key_separation = services.key_separation_provider()(args)
        expected_signing_key_id = services.public_key_id(args.sign_pub)
        if expected_signing_key_id in set(key_separation.values()):
            raise ValueError(
                "release-artifact admission public key belongs to an earlier "
                "configured trust domain"
            )
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
        sealed = services.seal_release_artifact_admission(
            args.release_source_admission,
            args.artifact,
            args.out,
            admitter=runtime_admitter,
            trusted_release_source_public_key_path=(args.release_source_admission_v2_pub),
            expected_release_source=source,
            expected_release_source_context=context,
            expected_release_source_producer=producer,
            expected_release_source_admitter=source_admitter,
            expected_release_source_bootstrap_guard_sha256=(
                args.expected_release_source_bootstrap_guard_sha
            ),
            expected_release_source_github_policy=source_policy,
            expected_release_source_git_executable_sha256=(
                args.expected_release_source_git_executable_sha256
            ),
            expected_release_source_github_cli_executable_sha256=(
                args.expected_release_source_gh_executable_sha256
            ),
            expected_release_source_provider_isolation_uid=(
                args.expected_release_source_provider_isolation_uid
            ),
            expected_release_source_provider_isolation_gid=(
                args.expected_release_source_provider_isolation_gid
            ),
            key_separation=key_separation,
            git_repository=args.git_repository,
            git_repository_is_bare=args.git_repository_bare,
            git_executable=git_executable,
            provider_isolation=provider_isolation,
            private_key_path=args.sign_key,
            signing_public_key_path=args.sign_pub,
            expected_signing_key_id=expected_signing_key_id,
            gh_executable=args.gh_executable,
            timeout_seconds=args.timeout_seconds,
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        services.release_artifact_error,
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
            "artifact": sealed.artifact.as_dict(),
            "release_source": sealed.manifest["release_source"],
            "builder": sealed.manifest["builder"],
            "admitter": sealed.manifest["admitter"],
            "key_id": sealed.manifest["authentication"]["key_id"],
            "decision": sealed.decision,
            "admission": True,
            "provider_verified": True,
            "live_provider_reverification": True,
        },
    )
    return 0


def execute_verify_github_release_artifact_admission(
    args: argparse.Namespace,
    *,
    services: VerifyGitHubReleaseArtifactAdmissionServices,
    out: _Output = print,
) -> int:
    """Verify one RAAE, its artifact, nested RSAE, and all six roots offline."""

    try:
        if args.bundle == "-" or args.artifact == "-":
            raise ValueError(
                "release-artifact admission bundle and artifact must be regular "
                "files, not standard input"
            )
        source, context, producer, source_admitter, source_policy = (
            services.nested_expectations_provider()(args)
        )
        builder = services.read_external_object_provider()(
            args.expected_builder,
            label="expected protected release-artifact builder identity",
        )
        admitter = services.read_external_object_provider()(
            args.expected_admitter,
            label="expected protected release-artifact admitter identity",
        )
        key_separation = services.key_separation_provider()(args)
        verified = services.verify_release_artifact_admission(
            args.bundle,
            args.artifact,
            trusted_public_key_path=args.trusted_pub,
            trusted_release_source_public_key_path=(args.release_source_admission_v2_pub),
            expected_release_source=source,
            expected_release_source_context=context,
            expected_release_source_producer=producer,
            expected_release_source_admitter=source_admitter,
            expected_release_source_bootstrap_guard_sha256=(
                args.expected_release_source_bootstrap_guard_sha
            ),
            expected_release_source_github_policy=source_policy,
            expected_release_source_git_executable_sha256=(
                args.expected_release_source_git_executable_sha256
            ),
            expected_release_source_github_cli_executable_sha256=(
                args.expected_release_source_gh_executable_sha256
            ),
            expected_release_source_provider_isolation_uid=(
                args.expected_release_source_provider_isolation_uid
            ),
            expected_release_source_provider_isolation_gid=(
                args.expected_release_source_provider_isolation_gid
            ),
            expected_builder=builder,
            expected_admitter=admitter,
            expected_key_separation=key_separation,
            expected_git_executable_sha256=args.expected_git_executable_sha256,
            expected_github_cli_executable_sha256=(args.expected_gh_executable_sha256),
            expected_provider_isolation_uid=args.expected_provider_isolation_uid,
            expected_provider_isolation_gid=args.expected_provider_isolation_gid,
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        services.release_artifact_error,
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
    manifest = verified.bundle.manifest
    services.machine_report_provider()(
        out,
        {
            "format": services.admission_format,
            "ok": True,
            "verified": True,
            "status": "VERIFIED",
            "decision": verified.decision,
            "admission": True,
            "artifact": verified.artifact.as_dict(),
            "release_source": manifest["release_source"],
            "builder": manifest["builder"],
            "admitter": manifest["admitter"],
            "key_id": manifest["authentication"]["key_id"],
            "verification_scope": "detached-offline-retained-provider-evidence",
            "live_provider_reverification": False,
        },
    )
    return 0
