# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
# DORMANT — NOT ON ANY SHIPPING PATH.
# This module is not reached by the evo-guard CLI dispatch or by any release
# workflow; it is retained only under tests (and trust-assurance mutation
# coverage). Do NOT treat it as an active trust boundary. It is a
# maintenance/admission lane kept for reference and scheduled for removal or an
# explicit experimental namespace in a post-v4.7.0 refactor. See the review plan.
"""Provider-specific OCI admission layered over the immutable V2 binding.

``EVOGUARD_ARTIFACT_PROVIDER_RECEIPT_V3`` is a canonical receipt for one
deliberately narrow provider relation: a digest-qualified public GHCR subject
whose GitHub Artifact Attestation was freshly verified for one exact direct
workflow, source revision, and workflow-run attempt.  The receipt has no trust
root by itself.  Its exact bytes become the V2 provenance reference, so the
separate V2 signature binds the provider result, immutable OCI digest, and an
externally verified Trusted Finalizer ``ALLOW`` without changing V1/V2 wire
semantics.

``public GHCR`` names the deliberately supported registry/repository subset;
it is not a claim that ``gh`` can access OCI anonymously.  GitHub CLI requires
registry authentication for OCI input, while the isolated provider environment
does not inherit ambient Docker configuration.  A compatible protected
registry-auth mechanism and a live pilot remain integration prerequisites.

The provider remains GitHub CLI/GitHub/Sigstore, not EvoOM Guard.  This module
does not claim SLSA compliance, reproducibility, image safety, registry
retention, publication, deployment, or runtime identity.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from evoom_guard.artifact_digest_admission import (
    ArtifactDigestAdmissionError,
    SealedArtifactDigestBinding,
    VerifiedArtifactDigestBinding,
    seal_artifact_digest_admission,
    verify_artifact_digest_admission,
)
from evoom_guard.evidence_bundle import (
    EvidenceBundleError,
    canonical_json_bytes,
    read_regular_file_bytes,
)
from evoom_guard.github_attestation import (
    DEFAULT_GITHUB_ATTESTATION_TIMEOUT_SECONDS,
    GITHUB_ATTESTATION_PREDICATE_TYPE,
    MAX_GITHUB_ATTESTATION_OUTPUT_BYTES,
    GitHubAttestationError,
    GitHubAttestationPolicy,
    GitHubAttestationProviderIsolation,
    VerifiedGitHubAttestationOutput,
    github_attestation_policy,
    load_github_attestation_verifier_output,
    run_github_oci_attestation_verify,
    validate_github_oci_attestation_verifier_output,
    validate_provider_isolated_signing_key_path,
)
from evoom_guard.strict_json import strict_json_loads

ARTIFACT_PROVIDER_RECEIPT_FORMAT = "EVOGUARD_ARTIFACT_PROVIDER_RECEIPT_V3"
ARTIFACT_PROVIDER_NAME = "github-artifact-attestation"
ARTIFACT_PROVIDER_SUBJECT_KIND = "oci-manifest-or-index"
ARTIFACT_PROVIDER_REGISTRY = "ghcr.io"
ARTIFACT_PROVIDER_BUNDLE_SOURCE = "oci-registry"
ARTIFACT_PROVIDER_PROVENANCE_PREFIX = "artifact-provider-v3:sha256:"

MAX_ARTIFACT_PROVIDER_RECEIPT_BYTES = 128 * 1024

_RECEIPT_KEYS = {
    "format",
    "provider",
    "subject",
    "build",
    "verification_policy",
    "verification_output",
}
_PROVIDER_KEYS = {"name", "bundle_source"}
_SUBJECT_KEYS = {"kind", "registry_repository", "digest"}
_BUILD_KEYS = {"workflow_run_id", "workflow_run_attempt"}
_OUTPUT_KEYS = {"sha256", "size", "verified_attestation_count"}
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SHA256_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GHCR_REPOSITORY = re.compile(
    r"ghcr\.io/(?P<namespace>[a-z0-9]+(?:[._-][a-z0-9]+)*)"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+\Z"
)


class ArtifactProviderV3Error(ValueError):
    """A V3 provider input, receipt, or admission relation is invalid."""


@dataclass(frozen=True)
class ArtifactProviderV3Subject:
    """One exact public GHCR manifest-or-index subject."""

    registry_repository: str
    digest: str

    @property
    def immutable_uri(self) -> str:
        return f"oci://{self.registry_repository}@{self.digest}"

    def as_dict(self) -> dict[str, str]:
        return {
            "kind": ARTIFACT_PROVIDER_SUBJECT_KIND,
            "registry_repository": self.registry_repository,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class CreatedArtifactProviderV3Receipt:
    """One freshly verified provider result retained with no-clobber writes."""

    receipt_path: str
    raw_output_path: str
    subject: ArtifactProviderV3Subject
    policy: GitHubAttestationPolicy
    workflow_run_id: str
    workflow_run_attempt: int


@dataclass(frozen=True)
class VerifiedArtifactProviderV3Receipt:
    """Retained-byte continuity under exact external provider expectations."""

    receipt: dict[str, Any]
    subject: ArtifactProviderV3Subject
    policy: GitHubAttestationPolicy
    workflow_run_id: str
    workflow_run_attempt: int


@dataclass(frozen=True)
class FreshArtifactProviderV3Verification:
    """One new live provider verification of the exact immutable OCI subject."""

    subject: ArtifactProviderV3Subject
    policy: GitHubAttestationPolicy
    provider_result: VerifiedGitHubAttestationOutput


@dataclass(frozen=True)
class SealedArtifactProviderV3Admission:
    """A V3 provider receipt bound by a distinct V2 admission signature."""

    receipt: CreatedArtifactProviderV3Receipt
    admission: SealedArtifactDigestBinding


@dataclass(frozen=True)
class VerifiedArtifactProviderV3Admission:
    """A provider receipt and V2/finalizer relation verified from external roots."""

    receipt: VerifiedArtifactProviderV3Receipt
    admission: VerifiedArtifactDigestBinding


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ArtifactProviderV3Error(
            f"{label} keys are not canonical "
            f"(missing={sorted(expected - actual)}, unknown={sorted(actual - expected)})"
        )


def artifact_provider_v3_subject(
    registry_repository: str,
    digest: str,
) -> ArtifactProviderV3Subject:
    """Validate one immutable GHCR subject with no tag or URL authority."""

    if not isinstance(registry_repository, str):
        raise ArtifactProviderV3Error("provider V3 registry repository must be a string")
    match = _GHCR_REPOSITORY.fullmatch(registry_repository)
    if match is None:
        raise ArtifactProviderV3Error(
            "provider V3 registry repository must be canonical lowercase "
            "ghcr.io/<owner>/<image> with no scheme, tag, digest, query, or fragment"
        )
    if not isinstance(digest, str) or _SHA256_DIGEST.fullmatch(digest) is None:
        raise ArtifactProviderV3Error(
            "provider V3 subject digest must be exact lowercase sha256:<64-hex>"
        )
    return ArtifactProviderV3Subject(
        registry_repository=registry_repository,
        digest=digest,
    )


def _validate_subject(value: Mapping[str, Any]) -> ArtifactProviderV3Subject:
    subject = dict(value)
    _require_exact_keys(subject, _SUBJECT_KEYS, "provider V3 subject")
    if subject.get("kind") != ARTIFACT_PROVIDER_SUBJECT_KIND:
        raise ArtifactProviderV3Error(
            f"provider V3 subject.kind must be {ARTIFACT_PROVIDER_SUBJECT_KIND!r}"
        )
    return artifact_provider_v3_subject(
        subject.get("registry_repository"),  # type: ignore[arg-type]
        subject.get("digest"),  # type: ignore[arg-type]
    )


def _validate_build(value: Mapping[str, Any]) -> tuple[str, int]:
    build = dict(value)
    _require_exact_keys(build, _BUILD_KEYS, "provider V3 build")
    run_id = build.get("workflow_run_id")
    attempt = build.get("workflow_run_attempt")
    if (
        not isinstance(run_id, str)
        or not run_id.isdecimal()
        or run_id.startswith("0")
        or len(run_id) > 256
    ):
        raise ArtifactProviderV3Error(
            "provider V3 workflow run ID must be a non-zero decimal string"
        )
    if type(attempt) is not int or not 1 <= attempt <= 2_147_483_647:
        raise ArtifactProviderV3Error(
            "provider V3 workflow run attempt must be an integer from 1 through 2147483647"
        )
    return run_id, attempt


def _validate_provider(value: Mapping[str, Any]) -> dict[str, str]:
    provider = dict(value)
    _require_exact_keys(provider, _PROVIDER_KEYS, "provider V3 provider")
    if provider.get("name") != ARTIFACT_PROVIDER_NAME:
        raise ArtifactProviderV3Error("provider V3 provider name is unsupported")
    if provider.get("bundle_source") != ARTIFACT_PROVIDER_BUNDLE_SOURCE:
        raise ArtifactProviderV3Error(
            "provider V3 attestation bundle source must be the OCI registry"
        )
    return {
        "name": ARTIFACT_PROVIDER_NAME,
        "bundle_source": ARTIFACT_PROVIDER_BUNDLE_SOURCE,
    }


def _validate_output(value: Mapping[str, Any]) -> dict[str, object]:
    output = dict(value)
    _require_exact_keys(output, _OUTPUT_KEYS, "provider V3 verification output")
    digest = output.get("sha256")
    size = output.get("size")
    count = output.get("verified_attestation_count")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise ArtifactProviderV3Error(
            "provider V3 verification output SHA-256 must be 64 lowercase hex characters"
        )
    if type(size) is not int or not 2 <= size <= MAX_GITHUB_ATTESTATION_OUTPUT_BYTES:
        raise ArtifactProviderV3Error(
            "provider V3 verification output size is outside the bounded range"
        )
    if type(count) is not int or count != 1:
        raise ArtifactProviderV3Error(
            "provider V3 verification output must describe exactly one attestation"
        )
    return {"sha256": digest, "size": size, "verified_attestation_count": 1}


def _policy_from_mapping(value: Mapping[str, Any]) -> GitHubAttestationPolicy:
    policy = dict(value)
    expected_keys = {
        "repository",
        "signer_workflow",
        "signer_digest",
        "source_ref",
        "source_digest",
        "cert_oidc_issuer",
        "predicate_type",
        "deny_self_hosted_runners",
        "attestation_limit",
    }
    _require_exact_keys(policy, expected_keys, "provider V3 verification policy")
    if policy.get("predicate_type") != GITHUB_ATTESTATION_PREDICATE_TYPE:
        raise ArtifactProviderV3Error("provider V3 predicate type is unsupported")
    if policy.get("deny_self_hosted_runners") is not True:
        raise ArtifactProviderV3Error("provider V3 must deny self-hosted runners")
    if type(policy.get("attestation_limit")) is not int or policy.get(
        "attestation_limit"
    ) != 1:
        raise ArtifactProviderV3Error("provider V3 attestation limit must be one")
    try:
        return github_attestation_policy(
            policy.get("repository"),  # type: ignore[arg-type]
            policy.get("signer_workflow"),  # type: ignore[arg-type]
            policy.get("source_digest"),  # type: ignore[arg-type]
            signer_digest=policy.get("signer_digest"),  # type: ignore[arg-type]
            source_ref=policy.get("source_ref"),  # type: ignore[arg-type]
            cert_oidc_issuer=policy.get("cert_oidc_issuer"),  # type: ignore[arg-type]
        )
    except GitHubAttestationError as exc:
        raise ArtifactProviderV3Error(str(exc)) from exc


def _validate_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    receipt = dict(value)
    _require_exact_keys(receipt, _RECEIPT_KEYS, "provider V3 receipt")
    if receipt.get("format") != ARTIFACT_PROVIDER_RECEIPT_FORMAT:
        raise ArtifactProviderV3Error("provider V3 receipt format is unsupported")
    for key in (
        "provider",
        "subject",
        "build",
        "verification_policy",
        "verification_output",
    ):
        if not isinstance(receipt.get(key), dict):
            raise ArtifactProviderV3Error(f"provider V3 receipt.{key} must be an object")
    subject = _validate_subject(receipt["subject"])
    run_id, run_attempt = _validate_build(receipt["build"])
    return {
        "format": ARTIFACT_PROVIDER_RECEIPT_FORMAT,
        "provider": _validate_provider(receipt["provider"]),
        "subject": subject.as_dict(),
        "build": {
            "workflow_run_id": run_id,
            "workflow_run_attempt": run_attempt,
        },
        "verification_policy": _policy_from_mapping(
            receipt["verification_policy"]
        ).as_dict(),
        "verification_output": _validate_output(receipt["verification_output"]),
    }


def _output_descriptor(data: bytes) -> dict[str, object]:
    try:
        entries = load_github_attestation_verifier_output(data)
    except GitHubAttestationError as exc:
        raise ArtifactProviderV3Error(str(exc)) from exc
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "verified_attestation_count": len(entries),
    }


def _read_bounded(path: str, *, limit: int, label: str) -> bytes:
    try:
        return read_regular_file_bytes(path, limit=limit, label=label)
    except EvidenceBundleError as exc:
        raise ArtifactProviderV3Error(str(exc)) from exc


def _read_receipt(path: str) -> dict[str, Any]:
    data = _read_bounded(
        path,
        limit=MAX_ARTIFACT_PROVIDER_RECEIPT_BYTES,
        label="provider V3 receipt",
    )
    try:
        decoded = strict_json_loads(data.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise ArtifactProviderV3Error(
            f"provider V3 receipt is not strict UTF-8 JSON: {exc}"
        ) from exc
    if not isinstance(decoded, dict):
        raise ArtifactProviderV3Error("provider V3 receipt must be a JSON object")
    checked = _validate_receipt(decoded)
    if canonical_json_bytes(checked) != data:
        raise ArtifactProviderV3Error("provider V3 receipt is not canonical JSON")
    return checked


def _write_new_file(path: str, data: bytes, *, label: str) -> str:
    absolute = os.path.abspath(path)
    if path == "-" or os.path.isdir(absolute):
        raise ArtifactProviderV3Error(f"{label} must be a new regular path")
    parent = os.path.dirname(absolute) or os.curdir
    os.makedirs(parent, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(absolute, flags, 0o600)
    except FileExistsError as exc:
        raise ArtifactProviderV3Error(
            f"refusing to overwrite existing {label}: {absolute}"
        ) from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(absolute, 0o600)
    except BaseException:
        try:
            os.unlink(absolute)
        except OSError:
            pass
        raise
    return absolute


def _provider_policy(
    *,
    repository: str,
    signer_workflow: str,
    signer_digest: str,
    source_ref: str,
    source_digest: str,
    cert_oidc_issuer: str,
) -> GitHubAttestationPolicy:
    try:
        policy = github_attestation_policy(
            repository,
            signer_workflow,
            source_digest,
            signer_digest=signer_digest,
            source_ref=source_ref,
            cert_oidc_issuer=cert_oidc_issuer,
        )
    except GitHubAttestationError as exc:
        raise ArtifactProviderV3Error(str(exc)) from exc
    if not policy.source_ref.startswith("refs/heads/"):
        raise ArtifactProviderV3Error(
            "provider V3 source ref must be an exact branch ref, not a tag"
        )
    if policy.signer_digest != policy.source_digest:
        raise ArtifactProviderV3Error(
            "provider V3 supports only a direct same-revision signer workflow"
        )
    return policy


def _require_external_relation(
    subject: ArtifactProviderV3Subject,
    policy: GitHubAttestationPolicy,
    workflow_run_id: str,
    workflow_run_attempt: int,
    expected_finalizer_context: Mapping[str, Any],
) -> None:
    checked_run_id, checked_attempt = _validate_build(
        {
            "workflow_run_id": workflow_run_id,
            "workflow_run_attempt": workflow_run_attempt,
        }
    )
    if expected_finalizer_context.get("repository") != policy.repository:
        raise ArtifactProviderV3Error(
            "provider V3 repository must match expected finalizer context.repository"
        )
    if expected_finalizer_context.get("head_sha") != policy.source_digest:
        raise ArtifactProviderV3Error(
            "provider V3 source digest must match expected finalizer context.head_sha"
        )
    namespace = _GHCR_REPOSITORY.fullmatch(subject.registry_repository)
    assert namespace is not None
    if namespace.group("namespace") != policy.repository.split("/", 1)[0].lower():
        raise ArtifactProviderV3Error(
            "provider V3 GHCR namespace must match the attested repository owner"
        )
    if (
        expected_finalizer_context.get("run_id") == checked_run_id
        and expected_finalizer_context.get("run_attempt") == checked_attempt
    ):
        raise ArtifactProviderV3Error(
            "provider V3 build invocation must differ from the finalizer invocation"
        )


def artifact_provider_v3_provenance_identity(
    subject: ArtifactProviderV3Subject,
    policy: GitHubAttestationPolicy,
    workflow_run_id: str,
    workflow_run_attempt: int,
) -> str:
    """Commit the V3 identity label to every authority-bearing provider pin."""

    run_id, run_attempt = _validate_build(
        {
            "workflow_run_id": workflow_run_id,
            "workflow_run_attempt": workflow_run_attempt,
        }
    )
    identity = {
        "format": ARTIFACT_PROVIDER_RECEIPT_FORMAT,
        "provider": {
            "name": ARTIFACT_PROVIDER_NAME,
            "bundle_source": ARTIFACT_PROVIDER_BUNDLE_SOURCE,
        },
        "subject": subject.as_dict(),
        "build": {
            "workflow_run_id": run_id,
            "workflow_run_attempt": run_attempt,
        },
        "verification_policy": policy.as_dict(),
    }
    return ARTIFACT_PROVIDER_PROVENANCE_PREFIX + hashlib.sha256(
        canonical_json_bytes(identity)
    ).hexdigest()


def create_artifact_provider_v3_receipt(
    registry_repository: str,
    digest: str,
    receipt_path: str,
    raw_output_path: str,
    *,
    repository: str,
    signer_workflow: str,
    signer_digest: str,
    source_ref: str,
    source_digest: str,
    cert_oidc_issuer: str,
    workflow_run_id: str,
    workflow_run_attempt: int,
    expected_finalizer_context: Mapping[str, Any],
    gh_executable: str = "gh",
    timeout_seconds: int = DEFAULT_GITHUB_ATTESTATION_TIMEOUT_SECONDS,
    provider_isolation: GitHubAttestationProviderIsolation,
) -> CreatedArtifactProviderV3Receipt:
    """Freshly verify one OCI subject and retain canonical provider evidence."""

    subject = artifact_provider_v3_subject(registry_repository, digest)
    policy = _provider_policy(
        repository=repository,
        signer_workflow=signer_workflow,
        signer_digest=signer_digest,
        source_ref=source_ref,
        source_digest=source_digest,
        cert_oidc_issuer=cert_oidc_issuer,
    )
    _require_external_relation(
        subject,
        policy,
        workflow_run_id,
        workflow_run_attempt,
        expected_finalizer_context,
    )
    if type(provider_isolation) is not GitHubAttestationProviderIsolation:
        raise ArtifactProviderV3Error(
            "provider V3 live verification requires GitHubAttestationProviderIsolation"
        )
    if os.path.abspath(receipt_path) == os.path.abspath(raw_output_path):
        raise ArtifactProviderV3Error(
            "provider V3 receipt and raw-output paths must differ"
        )
    try:
        output = run_github_oci_attestation_verify(
            subject.immutable_uri,
            policy,
            gh_executable=gh_executable,
            timeout_seconds=timeout_seconds,
            provider_isolation=provider_isolation,
        )
        provider_result = validate_github_oci_attestation_verifier_output(
            output,
            subject_name=subject.registry_repository,
            subject_digest=subject.digest,
            policy=policy,
            expected_workflow_run_id=workflow_run_id,
            expected_workflow_run_attempt=workflow_run_attempt,
        )
    except GitHubAttestationError as exc:
        raise ArtifactProviderV3Error(str(exc)) from exc
    receipt = _validate_receipt(
        {
            "format": ARTIFACT_PROVIDER_RECEIPT_FORMAT,
            "provider": {
                "name": ARTIFACT_PROVIDER_NAME,
                "bundle_source": ARTIFACT_PROVIDER_BUNDLE_SOURCE,
            },
            "subject": subject.as_dict(),
            "build": {
                "workflow_run_id": provider_result.workflow_run_id,
                "workflow_run_attempt": provider_result.workflow_run_attempt,
            },
            "verification_policy": policy.as_dict(),
            "verification_output": _output_descriptor(output),
        }
    )
    canonical_receipt = canonical_json_bytes(receipt)
    if len(canonical_receipt) > MAX_ARTIFACT_PROVIDER_RECEIPT_BYTES:
        raise ArtifactProviderV3Error("provider V3 canonical receipt exceeds its size limit")
    raw_absolute = _write_new_file(
        raw_output_path, output, label="provider V3 raw output"
    )
    try:
        receipt_absolute = _write_new_file(
            receipt_path, canonical_receipt, label="provider V3 receipt"
        )
    except BaseException:
        try:
            os.unlink(raw_absolute)
        except OSError:
            pass
        raise
    return CreatedArtifactProviderV3Receipt(
        receipt_path=receipt_absolute,
        raw_output_path=raw_absolute,
        subject=subject,
        policy=policy,
        workflow_run_id=provider_result.workflow_run_id,
        workflow_run_attempt=provider_result.workflow_run_attempt,
    )


def verify_artifact_provider_v3_receipt(
    receipt_path: str,
    raw_output_path: str,
    registry_repository: str,
    digest: str,
    *,
    repository: str,
    signer_workflow: str,
    signer_digest: str,
    source_ref: str,
    source_digest: str,
    cert_oidc_issuer: str,
    workflow_run_id: str,
    workflow_run_attempt: int,
    expected_finalizer_context: Mapping[str, Any],
) -> VerifiedArtifactProviderV3Receipt:
    """Verify retained evidence continuity; do not contact a registry/provider."""

    subject = artifact_provider_v3_subject(registry_repository, digest)
    policy = _provider_policy(
        repository=repository,
        signer_workflow=signer_workflow,
        signer_digest=signer_digest,
        source_ref=source_ref,
        source_digest=source_digest,
        cert_oidc_issuer=cert_oidc_issuer,
    )
    _require_external_relation(
        subject,
        policy,
        workflow_run_id,
        workflow_run_attempt,
        expected_finalizer_context,
    )
    receipt = _read_receipt(receipt_path)
    expected = {
        "subject": subject.as_dict(),
        "build": {
            "workflow_run_id": workflow_run_id,
            "workflow_run_attempt": workflow_run_attempt,
        },
        "verification_policy": policy.as_dict(),
    }
    for key, expected_value in expected.items():
        if receipt[key] != expected_value:
            raise ArtifactProviderV3Error(
                f"provider V3 receipt {key} does not match external expectations"
            )
    raw_output = _read_bounded(
        raw_output_path,
        limit=MAX_GITHUB_ATTESTATION_OUTPUT_BYTES,
        label="provider V3 raw output",
    )
    try:
        validate_github_oci_attestation_verifier_output(
            raw_output,
            subject_name=subject.registry_repository,
            subject_digest=subject.digest,
            policy=policy,
            expected_workflow_run_id=workflow_run_id,
            expected_workflow_run_attempt=workflow_run_attempt,
        )
    except GitHubAttestationError as exc:
        raise ArtifactProviderV3Error(str(exc)) from exc
    if _output_descriptor(raw_output) != receipt["verification_output"]:
        raise ArtifactProviderV3Error(
            "provider V3 raw output does not match the retained receipt descriptor"
        )
    return VerifiedArtifactProviderV3Receipt(
        receipt=receipt,
        subject=subject,
        policy=policy,
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
    )


def reverify_artifact_provider_v3_receipt(
    receipt_path: str,
    registry_repository: str,
    digest: str,
    *,
    repository: str,
    signer_workflow: str,
    signer_digest: str,
    source_ref: str,
    source_digest: str,
    cert_oidc_issuer: str,
    workflow_run_id: str,
    workflow_run_attempt: int,
    expected_finalizer_context: Mapping[str, Any],
    gh_executable: str = "gh",
    timeout_seconds: int = DEFAULT_GITHUB_ATTESTATION_TIMEOUT_SECONDS,
    provider_isolation: GitHubAttestationProviderIsolation,
) -> FreshArtifactProviderV3Verification:
    """Repeat the live registry/provider verification under the exact receipt policy."""

    receipt = _read_receipt(receipt_path)
    subject = artifact_provider_v3_subject(registry_repository, digest)
    policy = _provider_policy(
        repository=repository,
        signer_workflow=signer_workflow,
        signer_digest=signer_digest,
        source_ref=source_ref,
        source_digest=source_digest,
        cert_oidc_issuer=cert_oidc_issuer,
    )
    _require_external_relation(
        subject,
        policy,
        workflow_run_id,
        workflow_run_attempt,
        expected_finalizer_context,
    )
    if receipt["subject"] != subject.as_dict():
        raise ArtifactProviderV3Error(
            "provider V3 receipt subject does not match external expectations"
        )
    if receipt["verification_policy"] != policy.as_dict():
        raise ArtifactProviderV3Error(
            "provider V3 receipt policy does not match external expectations"
        )
    if receipt["build"] != {
        "workflow_run_id": workflow_run_id,
        "workflow_run_attempt": workflow_run_attempt,
    }:
        raise ArtifactProviderV3Error(
            "provider V3 receipt build does not match external expectations"
        )
    if type(provider_isolation) is not GitHubAttestationProviderIsolation:
        raise ArtifactProviderV3Error(
            "provider V3 live reverification requires GitHubAttestationProviderIsolation"
        )
    try:
        output = run_github_oci_attestation_verify(
            subject.immutable_uri,
            policy,
            gh_executable=gh_executable,
            timeout_seconds=timeout_seconds,
            provider_isolation=provider_isolation,
        )
        provider_result = validate_github_oci_attestation_verifier_output(
            output,
            subject_name=subject.registry_repository,
            subject_digest=subject.digest,
            policy=policy,
            expected_workflow_run_id=workflow_run_id,
            expected_workflow_run_attempt=workflow_run_attempt,
        )
    except GitHubAttestationError as exc:
        raise ArtifactProviderV3Error(str(exc)) from exc
    return FreshArtifactProviderV3Verification(
        subject=subject,
        policy=policy,
        provider_result=provider_result,
    )


def seal_artifact_provider_v3_admission(
    registry_repository: str,
    digest: str,
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
    workflow_run_id: str,
    workflow_run_attempt: int,
    trusted_finalizer_public_key_path: str,
    expected_finalizer_source: Mapping[str, Any],
    expected_finalizer_context: Mapping[str, Any],
    private_key_path: str,
    gh_executable: str = "gh",
    timeout_seconds: int = DEFAULT_GITHUB_ATTESTATION_TIMEOUT_SECONDS,
    provider_isolation: GitHubAttestationProviderIsolation,
) -> SealedArtifactProviderV3Admission:
    """Freshly verify provider evidence, then bind it and finalizer ALLOW via V2."""

    if type(provider_isolation) is not GitHubAttestationProviderIsolation:
        raise ArtifactProviderV3Error(
            "provider V3 sealing requires GitHubAttestationProviderIsolation"
        )
    try:
        validate_provider_isolated_signing_key_path(
            private_key_path, provider_isolation
        )
    except GitHubAttestationError as exc:
        raise ArtifactProviderV3Error(
            f"provider V3 isolation does not protect the admission key: {exc}"
        ) from exc
    all_paths = (
        receipt_path,
        raw_output_path,
        finalizer_bundle_path,
        output_path,
        trusted_finalizer_public_key_path,
        private_key_path,
    )
    if any(path == "-" for path in all_paths) or len(
        {os.path.abspath(path) for path in all_paths}
    ) != len(all_paths):
        raise ArtifactProviderV3Error(
            "provider V3 receipt, raw output, finalizer, binding, and key paths must differ"
        )
    created = create_artifact_provider_v3_receipt(
        registry_repository,
        digest,
        receipt_path,
        raw_output_path,
        repository=repository,
        signer_workflow=signer_workflow,
        signer_digest=signer_digest,
        source_ref=source_ref,
        source_digest=source_digest,
        cert_oidc_issuer=cert_oidc_issuer,
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
        expected_finalizer_context=expected_finalizer_context,
        gh_executable=gh_executable,
        timeout_seconds=timeout_seconds,
        provider_isolation=provider_isolation,
    )
    identity = artifact_provider_v3_provenance_identity(
        created.subject,
        created.policy,
        created.workflow_run_id,
        created.workflow_run_attempt,
    )
    try:
        admission = seal_artifact_digest_admission(
            ARTIFACT_PROVIDER_SUBJECT_KIND,
            created.subject.digest,
            created.receipt_path,
            identity,
            finalizer_bundle_path,
            output_path,
            trusted_finalizer_public_key_path=trusted_finalizer_public_key_path,
            expected_finalizer_source=expected_finalizer_source,
            expected_finalizer_context=expected_finalizer_context,
            private_key_path=private_key_path,
            force=False,
        )
    except (ArtifactDigestAdmissionError, OSError, ValueError) as exc:
        raise ArtifactProviderV3Error(
            f"cannot seal provider V3 admission: {exc}"
        ) from exc
    return SealedArtifactProviderV3Admission(receipt=created, admission=admission)


def verify_artifact_provider_v3_admission(
    binding_path: str,
    registry_repository: str,
    digest: str,
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
    workflow_run_id: str,
    workflow_run_attempt: int,
    trusted_public_key_path: str,
    trusted_finalizer_public_key_path: str,
    expected_finalizer_source: Mapping[str, Any],
    expected_finalizer_context: Mapping[str, Any],
) -> VerifiedArtifactProviderV3Admission:
    """Verify retained V3/V2/finalizer evidence without a live provider call."""

    receipt = verify_artifact_provider_v3_receipt(
        receipt_path,
        raw_output_path,
        registry_repository,
        digest,
        repository=repository,
        signer_workflow=signer_workflow,
        signer_digest=signer_digest,
        source_ref=source_ref,
        source_digest=source_digest,
        cert_oidc_issuer=cert_oidc_issuer,
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
        expected_finalizer_context=expected_finalizer_context,
    )
    identity = artifact_provider_v3_provenance_identity(
        receipt.subject,
        receipt.policy,
        receipt.workflow_run_id,
        receipt.workflow_run_attempt,
    )
    try:
        admission = verify_artifact_digest_admission(
            binding_path,
            ARTIFACT_PROVIDER_SUBJECT_KIND,
            receipt.subject.digest,
            receipt_path,
            identity,
            finalizer_bundle_path,
            trusted_public_key_path=trusted_public_key_path,
            trusted_finalizer_public_key_path=trusted_finalizer_public_key_path,
            expected_finalizer_source=expected_finalizer_source,
            expected_finalizer_context=expected_finalizer_context,
        )
    except (ArtifactDigestAdmissionError, OSError, ValueError) as exc:
        raise ArtifactProviderV3Error(
            f"cannot verify provider V3 admission: {exc}"
        ) from exc
    return VerifiedArtifactProviderV3Admission(receipt=receipt, admission=admission)
