# -----------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Bounded adapter for GitHub CLI artifact-attestation verification.

This module deliberately does **not** implement Sigstore, DSSE, SLSA, or
GitHub's certificate validation itself.  Instead, a protected caller invokes
``gh attestation verify`` with a narrow, caller-supplied policy and preserves a
canonical receipt of that successful external verification.  The receipt can
then be bound by the separate V2 artifact-admission key.

The important boundary is intentional:

* a success means the configured ``gh`` executable returned success while
  verifying an immutable snapshot under the recorded repository, signer
  workflow, source digest, SLSA predicate, and no-self-hosted-runner policy;
* the resulting receipt is an audit and admission input, not a replacement for
  GitHub/Sigstore verification; rechecking a retained receipt does not contact
  GitHub or independently revalidate a signature; and
* EvoGuard independently binds a narrow set of signed ``verificationResult``
  facts to the artifact and recorded policy: subject digest, predicate type,
  repository, signer workflow/digest, source ref/digest, OIDC issuer, hosted
  runner, and the canonical workflow-run URI.  Other predicate/metadata fields
  remain untrusted and are ignored.

Call this only in a protected post-build / post-merge-candidate workflow.  The
caller still trusts the configured ``gh`` binary, the GitHub API and
attestation service, the runner boundary, and the admission key custody.
When the default bare ``gh`` command is used, that protected job must be a
fresh/clean runner that has not executed candidate code. Otherwise the caller
must supply a reviewed absolute executable path; this adapter does not attest
the executable selected from ``PATH``.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from evoom_guard.artifact_admission import MAX_ARTIFACT_FILE_BYTES
from evoom_guard.artifact_digest_admission import (
    ArtifactDigestAdmissionError,
    SealedArtifactDigestBinding,
    VerifiedArtifactDigestBinding,
    seal_artifact_digest_admission,
    verify_artifact_digest_admission,
)
from evoom_guard.evidence_bundle import EvidenceBundleError, _canonical_json, _read_regular_file
from evoom_guard.execution import (
    ProcessLimits,
    process_group_popen_kwargs,
    terminate_process_tree,
)
from evoom_guard.strict_json import strict_json_loads

GITHUB_ATTESTATION_RECEIPT_FORMAT = "EVOGUARD_GITHUB_ATTESTATION_RECEIPT_V1"
GITHUB_ATTESTATION_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
GITHUB_ATTESTATION_CERT_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_ATTESTATION_PROVENANCE_IDENTITY_PREFIX = "github-attestation-receipt-v1:"

MAX_GITHUB_ATTESTATION_RECEIPT_BYTES = 64 * 1024
MAX_GITHUB_ATTESTATION_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_GITHUB_ATTESTATION_EXECUTABLE_BYTES = 256 * 1024 * 1024
MAX_GITHUB_ATTESTATION_TIMEOUT_SECONDS = 600
DEFAULT_GITHUB_ATTESTATION_TIMEOUT_SECONDS = 120
_STREAM_CHUNK_BYTES = 1024 * 1024
_GITHUB_ATTESTATION_STDERR_BYTES = 64 * 1024
_GITHUB_ATTESTATION_PROCESS_POLL_SECONDS = 0.02
_GITHUB_ATTESTATION_KILL_REAP_SECONDS = 3.0
_GITHUB_ATTESTATION_READER_JOIN_SECONDS = 2.0
_GITHUB_ATTESTATION_PROCESS_LIMITS = ProcessLimits(
    max_output_bytes=MAX_GITHUB_ATTESTATION_OUTPUT_BYTES,
    read_chunk_bytes=_STREAM_CHUNK_BYTES,
    termination_grace_seconds=1.0,
    kill_grace_seconds=_GITHUB_ATTESTATION_KILL_REAP_SECONDS,
    reader_join_seconds=_GITHUB_ATTESTATION_READER_JOIN_SECONDS,
)

_RECEIPT_KEYS = {
    "format",
    "artifact",
    "verification_policy",
    "verification_output",
}
_ARTIFACT_KEYS = {"sha256", "size"}
_POLICY_KEYS = {
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
_OUTPUT_KEYS = {"sha256", "size", "verified_attestation_count"}
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_DIGEST = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_WORKFLOW_PATH_SUFFIX = r"(?P<workflow_path>\.github/workflows/[A-Za-z0-9][A-Za-z0-9_.-]*\.ya?ml)\Z"
_WORKFLOW_PATH = re.compile(r"(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/" + _WORKFLOW_PATH_SUFFIX)
_WORKFLOW_HOST_PATH = re.compile(
    r"github\.com/(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/" + _WORKFLOW_PATH_SUFFIX
)
_WORKFLOW_URL = re.compile(
    r"https://github\.com/(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/"
    + _WORKFLOW_PATH_SUFFIX
)
_SOURCE_REF = re.compile(r"refs/(?:heads|tags)/[A-Za-z0-9][A-Za-z0-9._/-]*\Z")
_RUN_INVOCATION_URI = re.compile(
    r"https://github\.com/(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/"
    r"actions/runs/(?P<run_id>[1-9][0-9]*)/attempts/(?P<run_attempt>[1-9][0-9]*)\Z"
)
_IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
_GITHUB_HOSTED_RUNNER = "github-hosted"


class GitHubAttestationError(ValueError):
    """A GitHub attestation boundary input, receipt, or verifier run is invalid."""


@dataclass(frozen=True)
class GitHubAttestationProviderIsolation:
    """Enforceable POSIX identity and executable pins for one provider run.

    Supplying this configuration is an explicit request for a stronger
    provider boundary.  It never silently falls back to the historical
    same-identity/PATH execution.  The caller must start EvoGuard as root and
    choose a distinct, non-root UID and GID used only for the ``gh`` process.
    """

    executable_path: str
    executable_sha256: str
    uid: int
    gid: int


@dataclass(frozen=True)
class GitHubAttestationPolicy:
    """The exact external verification policy supplied to ``gh``."""

    repository: str
    signer_workflow: str
    signer_digest: str
    source_ref: str
    source_digest: str
    cert_oidc_issuer: str

    def as_dict(self) -> dict[str, object]:
        return {
            "repository": self.repository,
            "signer_workflow": self.signer_workflow,
            "signer_digest": self.signer_digest,
            "source_ref": self.source_ref,
            "source_digest": self.source_digest,
            "cert_oidc_issuer": self.cert_oidc_issuer,
            "predicate_type": GITHUB_ATTESTATION_PREDICATE_TYPE,
            "deny_self_hosted_runners": True,
            "attestation_limit": 1,
        }


@dataclass(frozen=True)
class GitHubAttestationArtifact:
    """A stable local snapshot that was supplied to the external verifier."""

    sha256: str
    size: int

    def as_dict(self) -> dict[str, object]:
        return {"sha256": self.sha256, "size": self.size}


@dataclass(frozen=True)
class VerifiedGitHubAttestationOutput:
    """Signed semantic identity extracted from one successful ``gh`` result."""

    workflow_run_id: str
    workflow_run_attempt: int


@dataclass(frozen=True)
class CreatedGitHubAttestationReceipt:
    """Receipt and raw external-verifier output written with no-clobber semantics."""

    receipt_path: str
    raw_output_path: str
    artifact: GitHubAttestationArtifact
    policy: GitHubAttestationPolicy
    verified_attestation_count: int


@dataclass(frozen=True)
class VerifiedGitHubAttestationReceipt:
    """A retained receipt whose bytes and external expectations match exactly.

    This type is intentionally about retained-byte continuity.  It does not
    rerun GitHub CLI or independently validate the original signature.
    """

    receipt: dict[str, Any]
    artifact: GitHubAttestationArtifact
    policy: GitHubAttestationPolicy


@dataclass(frozen=True)
class FreshGitHubAttestationVerification:
    """A new live GitHub CLI verification of the artifact named by a receipt.

    This is the independent re-verification operation.  It intentionally does
    not require fresh output bytes to equal a historic raw output: transparency
    data and server-side representation may evolve while the signed subject and
    policy remain verifiable.
    """

    artifact: GitHubAttestationArtifact
    policy: GitHubAttestationPolicy
    verified_attestation_count: int


@dataclass(frozen=True)
class SealedGitHubAttestationAdmission:
    """A V2 admission whose opaque provenance is a GitHub verifier receipt."""

    receipt: CreatedGitHubAttestationReceipt
    admission: SealedArtifactDigestBinding


@dataclass(frozen=True)
class VerifiedGitHubAttestationAdmission:
    """A V2 admission plus matching retained GitHub receipt bytes.

    This verifies the admission signature/finalizer relation and the retained
    receipt bytes.  It does not make a fresh GitHub/Sigstore verification.
    """

    receipt: VerifiedGitHubAttestationReceipt
    admission: VerifiedArtifactDigestBinding


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise GitHubAttestationError(
            f"{label} keys are not canonical "
            f"(missing={sorted(expected - actual)}, unknown={sorted(actual - expected)})"
        )


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0) or 0
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0) or 0
    return bool(reparse_flag and attributes & reparse_flag)


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def github_attestation_provider_isolation(
    executable_path: str,
    executable_sha256: str,
    *,
    uid: int,
    gid: int,
) -> GitHubAttestationProviderIsolation:
    """Build the opt-in fail-closed provider-isolation contract.

    Filesystem identity and the executable digest are checked again from a
    stable descriptor immediately before each launch.  This constructor keeps
    the scalar contract usable by future high-trust CLI commands without
    changing the default behavior of existing provider commands.
    """

    if (
        not isinstance(executable_path, str)
        or not executable_path
        or len(executable_path) > 4096
        or not os.path.isabs(executable_path)
    ):
        raise GitHubAttestationError(
            "isolated GitHub CLI executable must be an absolute path"
        )
    if os.path.normpath(executable_path) != executable_path:
        raise GitHubAttestationError(
            "isolated GitHub CLI executable path must be canonical"
        )
    if not isinstance(executable_sha256, str) or _SHA256.fullmatch(
        executable_sha256
    ) is None:
        raise GitHubAttestationError(
            "isolated GitHub CLI executable SHA-256 must be lowercase 64-hex"
        )
    if type(uid) is not int or not 1 <= uid <= 2_147_483_647:
        raise GitHubAttestationError(
            "isolated GitHub CLI UID must be a non-root integer from 1 through 2147483647"
        )
    if type(gid) is not int or not 1 <= gid <= 2_147_483_647:
        raise GitHubAttestationError(
            "isolated GitHub CLI GID must be a non-root integer from 1 through 2147483647"
        )
    return GitHubAttestationProviderIsolation(
        executable_path=executable_path,
        executable_sha256=executable_sha256,
        uid=uid,
        gid=gid,
    )


def _provider_posix_identity() -> tuple[int, int]:
    """Return the effective POSIX identity through one testable boundary."""

    get_effective_uid = getattr(os, "geteuid", None)
    get_effective_gid = getattr(os, "getegid", None)
    if (
        os.name != "posix"
        or not callable(get_effective_uid)
        or not callable(get_effective_gid)
    ):
        raise GitHubAttestationError(
            "isolated GitHub provider execution requires POSIX UID/GID support"
        )
    return get_effective_uid(), get_effective_gid()


def _validate_provider_isolation(
    value: GitHubAttestationProviderIsolation,
    *,
    gh_executable: str,
) -> GitHubAttestationProviderIsolation:
    if type(value) is not GitHubAttestationProviderIsolation:
        raise GitHubAttestationError(
            "provider isolation must be GitHubAttestationProviderIsolation"
        )
    checked = github_attestation_provider_isolation(
        value.executable_path,
        value.executable_sha256,
        uid=value.uid,
        gid=value.gid,
    )
    if gh_executable not in {"gh", checked.executable_path}:
        raise GitHubAttestationError(
            "isolated GitHub CLI executable conflicts with the configured executable path"
        )
    effective_uid, effective_gid = _provider_posix_identity()
    if effective_uid != 0:
        raise GitHubAttestationError(
            "isolated GitHub provider execution must start with effective UID 0"
        )
    if checked.uid == effective_uid or checked.gid == effective_gid:
        raise GitHubAttestationError(
            "isolated GitHub provider UID and GID must both differ from the caller identity"
        )
    return checked


def validate_provider_isolated_signing_key_path(
    path: str,
    isolation: GitHubAttestationProviderIsolation,
) -> str:
    """Prove that the lowered provider identity cannot reach the signing key.

    This deliberately performs metadata-only inspection and never opens the
    key contents.  The key must be a canonical absolute, regular, non-symlink
    file owned by root/the caller with mode exactly ``0600``.  Every directory
    from its parent through the filesystem root must also be non-symlink and
    non-writable by the provider UID/GID.  Provider launches clear all
    supplementary groups, so the proof needs only owner, primary-group, and
    other mode bits.
    """

    checked = _validate_provider_isolation(
        isolation,
        gh_executable=isolation.executable_path,
    )
    if not isinstance(path, str) or not path or not os.path.isabs(path):
        raise GitHubAttestationError(
            "isolated provider signing-key path must be absolute"
        )
    absolute = os.path.normpath(path)
    if absolute != path or os.path.realpath(absolute) != absolute:
        raise GitHubAttestationError(
            "isolated provider signing-key path must be canonical and must not traverse symlinks"
        )
    caller_uid, _caller_gid = _provider_posix_identity()
    try:
        key_metadata = os.lstat(absolute)
    except OSError as exc:
        raise GitHubAttestationError(
            f"cannot inspect isolated provider signing key {absolute!r}: {exc}"
        ) from exc
    if (
        stat.S_ISLNK(key_metadata.st_mode)
        or _is_reparse_point(key_metadata)
        or not stat.S_ISREG(key_metadata.st_mode)
    ):
        raise GitHubAttestationError(
            "isolated provider signing key must be a regular non-symlink file"
        )
    if key_metadata.st_uid not in {0, caller_uid}:
        raise GitHubAttestationError(
            "isolated provider signing key must be owned by root/the caller"
        )
    if stat.S_IMODE(key_metadata.st_mode) != 0o600:
        raise GitHubAttestationError(
            "isolated provider signing key mode must be exactly 0600"
        )

    parent = os.path.dirname(absolute)
    while True:
        try:
            metadata = os.lstat(parent)
        except OSError as exc:
            raise GitHubAttestationError(
                f"cannot inspect signing-key parent {parent!r}: {exc}"
            ) from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or _is_reparse_point(metadata)
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise GitHubAttestationError(
                "every isolated provider signing-key parent must be a non-symlink directory"
            )
        mode = stat.S_IMODE(metadata.st_mode)
        if metadata.st_uid == checked.uid:
            provider_writable = bool(mode & stat.S_IWUSR)
        elif metadata.st_gid == checked.gid:
            provider_writable = bool(mode & stat.S_IWGRP)
        else:
            provider_writable = bool(mode & stat.S_IWOTH)
        if provider_writable:
            raise GitHubAttestationError(
                "isolated provider signing-key parent is writable by the lowered identity: "
                f"{parent}"
            )
        next_parent = os.path.dirname(parent)
        if next_parent == parent:
            break
        parent = next_parent
    return absolute


def _validate_repository(value: object) -> str:
    if not isinstance(value, str) or len(value) > 256 or _REPOSITORY.fullmatch(value) is None:
        raise GitHubAttestationError(
            "GitHub attestation repository must be canonical owner/repository ASCII text"
        )
    return value


def _validate_signer_workflow(value: object, *, repository: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise GitHubAttestationError(
            "GitHub attestation signer workflow must be a non-empty string of at most 512 characters"
        )
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise GitHubAttestationError(
            "GitHub attestation signer workflow must be ASCII"
        ) from exc
    if any(byte <= 0x20 or byte == 0x7F for byte in encoded):
        raise GitHubAttestationError(
            "GitHub attestation signer workflow must not contain whitespace or controls"
        )
    match = (
        _WORKFLOW_PATH.fullmatch(value)
        or _WORKFLOW_HOST_PATH.fullmatch(value)
        or _WORKFLOW_URL.fullmatch(value)
    )
    if match is None:
        raise GitHubAttestationError(
            "GitHub attestation signer workflow must be a canonical GitHub path or URL "
            "to .github/workflows/<file>.yml or .yaml"
        )
    if match.group("repository") != repository:
        raise GitHubAttestationError(
            "GitHub attestation signer workflow must be bound to the exact verification repository"
        )
    # gh accepts the repository-relative canonical path, not an https URL.
    # Normalize every accepted alias before it reaches gh or a retained receipt.
    return f"{match.group('repository')}/{match.group('workflow_path')}"


def _validate_git_digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _GIT_DIGEST.fullmatch(value) is None:
        raise GitHubAttestationError(
            f"GitHub attestation {label} must be an exact lowercase 40- or 64-hex Git digest"
        )
    return value


def _validate_source_ref(value: object) -> str:
    if not isinstance(value, str) or _SOURCE_REF.fullmatch(value) is None:
        raise GitHubAttestationError(
            "GitHub attestation source ref must be a canonical refs/heads/... or refs/tags/... value"
        )
    suffix = value.removeprefix("refs/heads/").removeprefix("refs/tags/")
    if "//" in suffix or suffix.endswith("/") or any(
        part in {".", ".."} for part in suffix.split("/")
    ):
        raise GitHubAttestationError(
            "GitHub attestation source ref must not contain empty, dot, or dot-dot path segments"
        )
    return value


def _validate_cert_oidc_issuer(value: object) -> str:
    if value != GITHUB_ATTESTATION_CERT_OIDC_ISSUER:
        raise GitHubAttestationError(
            "GitHub attestation certificate OIDC issuer must be "
            f"{GITHUB_ATTESTATION_CERT_OIDC_ISSUER!r}"
        )
    return GITHUB_ATTESTATION_CERT_OIDC_ISSUER


def github_attestation_policy(
    repository: str,
    signer_workflow: str,
    source_digest: str,
    *,
    signer_digest: str,
    source_ref: str,
    cert_oidc_issuer: str,
) -> GitHubAttestationPolicy:
    """Create the only policy shape this adapter allows.

    The SLSA v1 predicate and ``--deny-self-hosted-runners`` are fixed.  A
    caller that needs another provider/predicate must add a separately scoped
    adapter rather than weakening this one through free-form CLI flags.
    """

    return GitHubAttestationPolicy(
        repository=(checked_repository := _validate_repository(repository)),
        signer_workflow=_validate_signer_workflow(
            signer_workflow, repository=checked_repository
        ),
        signer_digest=_validate_git_digest(signer_digest, label="signer digest"),
        source_ref=_validate_source_ref(source_ref),
        source_digest=_validate_git_digest(source_digest, label="source digest"),
        cert_oidc_issuer=_validate_cert_oidc_issuer(cert_oidc_issuer),
    )


def _validate_artifact(value: Mapping[str, Any], *, label: str) -> GitHubAttestationArtifact:
    artifact = dict(value)
    _require_exact_keys(artifact, _ARTIFACT_KEYS, label)
    digest = artifact.get("sha256")
    size = artifact.get("size")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise GitHubAttestationError(f"{label}.sha256 must be a lowercase SHA-256 digest")
    if type(size) is not int or size < 0 or size > MAX_ARTIFACT_FILE_BYTES:
        raise GitHubAttestationError(
            f"{label}.size must be an integer from 0 through {MAX_ARTIFACT_FILE_BYTES}"
        )
    return GitHubAttestationArtifact(sha256=digest, size=size)


def _validate_policy(value: Mapping[str, Any], *, label: str) -> GitHubAttestationPolicy:
    policy = dict(value)
    _require_exact_keys(policy, _POLICY_KEYS, label)
    if policy.get("predicate_type") != GITHUB_ATTESTATION_PREDICATE_TYPE:
        raise GitHubAttestationError(f"{label}.predicate_type is unsupported")
    if policy.get("deny_self_hosted_runners") is not True:
        raise GitHubAttestationError(f"{label}.deny_self_hosted_runners must be true")
    if policy.get("attestation_limit") != 1:
        raise GitHubAttestationError(f"{label}.attestation_limit must be 1")
    return GitHubAttestationPolicy(
        repository=(repository := _validate_repository(policy.get("repository"))),
        signer_workflow=_validate_signer_workflow(
            policy.get("signer_workflow"), repository=repository
        ),
        signer_digest=_validate_git_digest(policy.get("signer_digest"), label="signer digest"),
        source_ref=_validate_source_ref(policy.get("source_ref")),
        source_digest=_validate_git_digest(policy.get("source_digest"), label="source digest"),
        cert_oidc_issuer=_validate_cert_oidc_issuer(policy.get("cert_oidc_issuer")),
    )


def _validate_output(value: Mapping[str, Any], *, label: str) -> dict[str, object]:
    output = dict(value)
    _require_exact_keys(output, _OUTPUT_KEYS, label)
    digest = output.get("sha256")
    size = output.get("size")
    count = output.get("verified_attestation_count")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise GitHubAttestationError(f"{label}.sha256 must be a lowercase SHA-256 digest")
    if type(size) is not int or size < 2 or size > MAX_GITHUB_ATTESTATION_OUTPUT_BYTES:
        raise GitHubAttestationError(
            f"{label}.size must be an integer from 2 through "
            f"{MAX_GITHUB_ATTESTATION_OUTPUT_BYTES}"
        )
    if type(count) is not int or count < 1 or count > 1:
        raise GitHubAttestationError(f"{label}.verified_attestation_count must be exactly one")
    return {"sha256": digest, "size": size, "verified_attestation_count": count}


def _validate_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    receipt = dict(value)
    _require_exact_keys(receipt, _RECEIPT_KEYS, "GitHub attestation receipt")
    if receipt.get("format") != GITHUB_ATTESTATION_RECEIPT_FORMAT:
        raise GitHubAttestationError(
            f"unsupported GitHub attestation receipt format: {receipt.get('format')!r}"
        )
    artifact = receipt.get("artifact")
    policy = receipt.get("verification_policy")
    output = receipt.get("verification_output")
    if not isinstance(artifact, dict) or not isinstance(policy, dict) or not isinstance(output, dict):
        raise GitHubAttestationError(
            "GitHub attestation receipt artifact, verification_policy, and verification_output must be objects"
        )
    checked_artifact = _validate_artifact(artifact, label="GitHub attestation receipt artifact")
    checked_policy = _validate_policy(policy, label="GitHub attestation receipt verification_policy")
    checked_output = _validate_output(output, label="GitHub attestation receipt verification_output")
    return {
        "format": GITHUB_ATTESTATION_RECEIPT_FORMAT,
        "artifact": checked_artifact.as_dict(),
        "verification_policy": checked_policy.as_dict(),
        "verification_output": checked_output,
    }


def _snapshot_regular_artifact(path: str, directory: str) -> tuple[str, GitHubAttestationArtifact]:
    """Freeze one stable file descriptor to a private snapshot and hash it.

    ``gh`` receives the snapshot rather than the caller's pathname, preventing
    a post-hash path swap from making the receipt refer to different bytes.
    """

    try:
        before = os.lstat(path)
    except OSError as exc:
        raise GitHubAttestationError(f"cannot inspect artifact {path!r}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or _is_reparse_point(before) or not stat.S_ISREG(before.st_mode):
        raise GitHubAttestationError(f"artifact must be a regular non-symlink file: {path!r}")
    if before.st_size > MAX_ARTIFACT_FILE_BYTES:
        raise GitHubAttestationError(
            f"artifact exceeds the {MAX_ARTIFACT_FILE_BYTES}-byte size limit: {path!r}"
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise GitHubAttestationError(f"cannot open artifact {path!r}: {exc}") from exc
    snapshot_descriptor = -1
    snapshot_path = ""
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _is_reparse_point(opened):
            raise GitHubAttestationError(f"artifact changed to a non-regular file: {path!r}")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise GitHubAttestationError(f"artifact changed while it was being opened: {path!r}")
        if opened.st_size > MAX_ARTIFACT_FILE_BYTES:
            raise GitHubAttestationError(
                f"artifact exceeds the {MAX_ARTIFACT_FILE_BYTES}-byte size limit: {path!r}"
            )
        snapshot_descriptor, snapshot_path = tempfile.mkstemp(prefix="artifact-", dir=directory)
        digest = hashlib.sha256()
        bytes_read = 0
        with os.fdopen(descriptor, "rb", closefd=False) as source, os.fdopen(
            snapshot_descriptor, "wb", closefd=False
        ) as destination:
            while True:
                chunk = source.read(_STREAM_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
                destination.write(chunk)
                bytes_read += len(chunk)
            destination.flush()
            os.fsync(destination.fileno())
        after = os.fstat(descriptor)
        if _file_identity(after) != _file_identity(opened):
            raise GitHubAttestationError(f"artifact changed while it was being read: {path!r}")
        if bytes_read != opened.st_size:
            raise GitHubAttestationError(
                f"artifact read length does not match its stable size: {path!r}"
            )
        os.chmod(snapshot_path, 0o600)
        return snapshot_path, GitHubAttestationArtifact(
            sha256=digest.hexdigest(), size=bytes_read
        )
    except BaseException:
        if snapshot_path:
            try:
                os.unlink(snapshot_path)
            except OSError:
                pass
        raise
    finally:
        if snapshot_descriptor >= 0:
            try:
                os.close(snapshot_descriptor)
            except OSError:
                pass
        os.close(descriptor)


def _read_bounded_file(path: str, *, limit: int, label: str) -> bytes:
    try:
        return _read_regular_file(path, limit=limit, label=label)
    except EvidenceBundleError as exc:
        raise GitHubAttestationError(str(exc)) from exc


def _load_attestation_output(data: bytes) -> list[dict[str, Any]]:
    try:
        decoded = strict_json_loads(data.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise GitHubAttestationError(
            f"GitHub attestation verifier output is not strict UTF-8 JSON: {exc}"
        ) from exc
    if not isinstance(decoded, list) or len(decoded) != 1:
        raise GitHubAttestationError(
            "GitHub attestation verifier output must contain exactly one verified attestation"
        )
    if not isinstance(decoded[0], dict):
        raise GitHubAttestationError(
            "GitHub attestation verifier output entry must be an object"
        )
    entry = decoded[0]
    verification_result = entry.get("verificationResult")
    if not isinstance(verification_result, dict):
        raise GitHubAttestationError(
            "GitHub attestation verifier output entry must contain verificationResult"
        )
    if not isinstance(verification_result.get("statement"), dict):
        raise GitHubAttestationError(
            "GitHub attestation verificationResult must contain a statement object"
        )
    return [entry]


def _required_mapping(
    value: Mapping[str, Any], key: str, *, label: str
) -> dict[str, Any]:
    child = value.get(key)
    if not isinstance(child, dict):
        raise GitHubAttestationError(f"{label}.{key} must be an object")
    return child


def _required_string(value: Mapping[str, Any], key: str, *, label: str) -> str:
    child = value.get(key)
    if not isinstance(child, str) or not child:
        raise GitHubAttestationError(f"{label}.{key} must be a non-empty string")
    return child


def _require_semantic_match(actual: object, expected: object, *, label: str) -> None:
    if actual != expected:
        raise GitHubAttestationError(
            f"GitHub attestation verifier output {label} does not match the expected policy"
        )


def _validate_expected_workflow_run(
    run_id: str | None,
    run_attempt: int | None,
) -> tuple[str, int] | None:
    if (run_id is None) != (run_attempt is None):
        raise GitHubAttestationError(
            "expected workflow run ID and attempt must be supplied together"
        )
    if run_id is None:
        return None
    if (
        not isinstance(run_id, str)
        or not run_id.isdecimal()
        or run_id.startswith("0")
        or len(run_id) > 256
    ):
        raise GitHubAttestationError(
            "expected workflow run ID must be a non-zero decimal string"
        )
    if type(run_attempt) is not int or not 1 <= run_attempt <= 2_147_483_647:
        raise GitHubAttestationError(
            "expected workflow run attempt must be an integer from 1 through 2147483647"
        )
    return run_id, run_attempt


def validate_github_attestation_verifier_output(
    data: bytes,
    *,
    artifact: GitHubAttestationArtifact,
    policy: GitHubAttestationPolicy,
    expected_workflow_run_id: str | None = None,
    expected_workflow_run_attempt: int | None = None,
) -> VerifiedGitHubAttestationOutput:
    """Bind one successful ``gh`` JSON result to exact external expectations.

    GitHub CLI remains responsible for Sigstore/DSSE/certificate verification.
    This function independently interprets only the narrow signed result fields
    needed by EvoGuard.  Required fields fail closed; unknown fields at every
    level are retained in raw evidence but ignored for forward compatibility.
    """

    if type(artifact) is not GitHubAttestationArtifact:
        raise GitHubAttestationError(
            "expected GitHub attestation artifact must be GitHubAttestationArtifact"
        )
    if type(policy) is not GitHubAttestationPolicy:
        raise GitHubAttestationError(
            "expected GitHub attestation policy must be GitHubAttestationPolicy"
        )
    checked_artifact = _validate_artifact(
        artifact.as_dict(), label="expected GitHub attestation artifact"
    )
    checked_policy = _validate_policy(
        policy.as_dict(), label="expected GitHub attestation policy"
    )
    expected_run = _validate_expected_workflow_run(
        expected_workflow_run_id, expected_workflow_run_attempt
    )

    entry = _load_attestation_output(data)[0]
    result = _required_mapping(entry, "verificationResult", label="verification result")
    signature = _required_mapping(result, "signature", label="verification result")
    certificate = _required_mapping(signature, "certificate", label="verification signature")
    statement = _required_mapping(result, "statement", label="verification result")

    repository_url = f"https://github.com/{checked_policy.repository}"
    expected_signer_base = f"https://github.com/{checked_policy.signer_workflow}@"
    allowed_signer_uris = {
        expected_signer_base + checked_policy.signer_digest,
        expected_signer_base + checked_policy.source_ref,
    }
    signer_uri = _required_string(
        certificate, "buildSignerURI", label="verification certificate"
    )
    if signer_uri not in allowed_signer_uris:
        raise GitHubAttestationError(
            "GitHub attestation verifier output signer workflow URI does not match "
            "the expected workflow and signer digest/ref"
        )
    for key, expected in (
        ("subjectAlternativeName", signer_uri),
        ("issuer", checked_policy.cert_oidc_issuer),
        ("githubWorkflowRepository", checked_policy.repository),
        ("githubWorkflowSHA", checked_policy.source_digest),
        ("githubWorkflowRef", checked_policy.source_ref),
        ("buildSignerDigest", checked_policy.signer_digest),
        ("runnerEnvironment", _GITHUB_HOSTED_RUNNER),
        ("sourceRepositoryURI", repository_url),
        ("sourceRepositoryDigest", checked_policy.source_digest),
        ("sourceRepositoryRef", checked_policy.source_ref),
    ):
        _require_semantic_match(
            _required_string(certificate, key, label="verification certificate"),
            expected,
            label=f"certificate.{key}",
        )

    run_uri = _required_string(
        certificate, "runInvocationURI", label="verification certificate"
    )
    run_match = _RUN_INVOCATION_URI.fullmatch(run_uri)
    if run_match is None or run_match.group("repository") != checked_policy.repository:
        raise GitHubAttestationError(
            "GitHub attestation verifier output runInvocationURI is not a canonical "
            "workflow run in the expected repository"
        )
    workflow_run_id = run_match.group("run_id")
    workflow_run_attempt = int(run_match.group("run_attempt"))
    if workflow_run_attempt > 2_147_483_647:
        raise GitHubAttestationError(
            "GitHub attestation verifier output workflow run attempt is outside its range"
        )
    if expected_run is not None and (workflow_run_id, workflow_run_attempt) != expected_run:
        raise GitHubAttestationError(
            "GitHub attestation verifier output workflow run ID/attempt does not match "
            "the external expectation"
        )

    _require_semantic_match(
        statement.get("_type"),
        _IN_TOTO_STATEMENT_TYPE,
        label="statement._type",
    )
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1:
        raise GitHubAttestationError(
            "GitHub attestation verifier output statement must contain exactly one subject"
        )
    subject = subjects[0]
    if not isinstance(subject, dict):
        raise GitHubAttestationError(
            "GitHub attestation verifier output statement subject must be an object"
        )
    subject_digest = _required_mapping(subject, "digest", label="statement subject")
    _require_semantic_match(
        _required_string(subject_digest, "sha256", label="statement subject digest"),
        checked_artifact.sha256,
        label="statement subject SHA-256",
    )
    _require_semantic_match(
        statement.get("predicateType"),
        GITHUB_ATTESTATION_PREDICATE_TYPE,
        label="statement predicateType",
    )

    predicate = _required_mapping(statement, "predicate", label="statement")
    build_definition = _required_mapping(predicate, "buildDefinition", label="predicate")
    external_parameters = _required_mapping(
        build_definition, "externalParameters", label="predicate buildDefinition"
    )
    external_workflow = _required_mapping(
        external_parameters, "workflow", label="predicate externalParameters"
    )
    _require_semantic_match(
        external_workflow.get("repository"),
        repository_url,
        label="predicate workflow repository",
    )
    _require_semantic_match(
        external_workflow.get("ref"),
        checked_policy.source_ref,
        label="predicate workflow ref",
    )
    internal_parameters = _required_mapping(
        build_definition, "internalParameters", label="predicate buildDefinition"
    )
    github_parameters = _required_mapping(
        internal_parameters, "github", label="predicate internalParameters"
    )
    _require_semantic_match(
        github_parameters.get("runner_environment"),
        _GITHUB_HOSTED_RUNNER,
        label="predicate runner environment",
    )
    resolved_dependencies = build_definition.get("resolvedDependencies")
    expected_dependency = {
        "uri": f"git+{repository_url}@{checked_policy.source_ref}",
        "digest": {"gitCommit": checked_policy.source_digest},
    }
    if not isinstance(resolved_dependencies, list) or not any(
        isinstance(dependency, dict)
        and dependency.get("uri") == expected_dependency["uri"]
        and isinstance(dependency.get("digest"), dict)
        and dependency["digest"].get("gitCommit") == checked_policy.source_digest
        for dependency in resolved_dependencies
    ):
        raise GitHubAttestationError(
            "GitHub attestation verifier output has no resolved dependency for the "
            "expected source repository/ref/digest"
        )

    run_details = _required_mapping(predicate, "runDetails", label="predicate")
    builder = _required_mapping(run_details, "builder", label="predicate runDetails")
    metadata = _required_mapping(run_details, "metadata", label="predicate runDetails")
    _require_semantic_match(
        builder.get("id"), signer_uri, label="predicate builder identity"
    )
    _require_semantic_match(
        metadata.get("invocationId"), run_uri, label="predicate invocation URI"
    )
    verified_identity = _required_mapping(
        result, "verifiedIdentity", label="verification result"
    )
    _require_semantic_match(
        verified_identity.get("runnerEnvironment"),
        _GITHUB_HOSTED_RUNNER,
        label="verified identity runner environment",
    )
    return VerifiedGitHubAttestationOutput(
        workflow_run_id=workflow_run_id,
        workflow_run_attempt=workflow_run_attempt,
    )


def validate_github_attestation_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the closed-world canonical provider-receipt object."""

    return _validate_receipt(value)


def load_github_attestation_verifier_output(data: bytes) -> list[dict[str, Any]]:
    """Load one structurally recognizable ``gh attestation verify`` result."""

    return _load_attestation_output(data)


def _output_descriptor(data: bytes) -> dict[str, object]:
    parsed = _load_attestation_output(data)
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "verified_attestation_count": len(parsed),
    }


def _write_new_file(path: str, data: bytes, *, label: str) -> str:
    absolute = os.path.abspath(path)
    if os.path.isdir(absolute):
        raise GitHubAttestationError(f"{label} output is a directory: {absolute}")
    parent = os.path.dirname(absolute) or os.curdir
    os.makedirs(parent, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(absolute, flags, 0o600)
    except FileExistsError as exc:
        raise GitHubAttestationError(
            f"refusing to overwrite existing {label} output: {absolute}"
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


def _set_provider_path_access(
    path: str,
    *,
    uid: int,
    gid: int,
    mode: int,
    label: str,
) -> None:
    """Set and prove one POSIX ownership/mode contract without following links."""

    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode) or _is_reparse_point(before):
            raise GitHubAttestationError(f"{label} must not be a symlink")
        change_owner = getattr(os, "chown", None)
        if not callable(change_owner):
            raise GitHubAttestationError(
                "isolated provider ownership changes are unavailable"
            )
        change_owner(path, uid, gid, follow_symlinks=False)
        os.chmod(path, mode, follow_symlinks=False)
        after = os.lstat(path)
    except (NotImplementedError, OSError) as exc:
        raise GitHubAttestationError(
            f"cannot prepare isolated provider access for {label}: {exc}"
        ) from exc
    if (
        stat.S_ISLNK(after.st_mode)
        or _is_reparse_point(after)
        or after.st_uid != uid
        or after.st_gid != gid
        or stat.S_IMODE(after.st_mode) != mode
    ):
        raise GitHubAttestationError(
            f"isolated provider access contract was not established for {label}"
        )


def _remove_provider_snapshot(path: str) -> None:
    """Best-effort removal that also handles Windows read-only mode mapping."""

    try:
        os.unlink(path)
        return
    except FileNotFoundError:
        return
    except PermissionError:
        try:
            os.chmod(path, 0o700, follow_symlinks=False)
        except (NotImplementedError, TypeError):
            try:
                os.chmod(path, 0o700)
            except OSError:
                return
        except OSError:
            return
    except OSError:
        return
    try:
        os.unlink(path)
    except OSError:
        pass


def _snapshot_pinned_provider_executable(
    isolation: GitHubAttestationProviderIsolation,
    directory: str,
    *,
    owner_uid: int,
    owner_gid: int,
) -> str:
    """Copy the reviewed executable from one stable descriptor and pin its hash."""

    source_path = isolation.executable_path
    if os.path.realpath(source_path) != source_path:
        raise GitHubAttestationError(
            "isolated GitHub CLI executable path must not traverse symlinks"
        )
    try:
        before = os.lstat(source_path)
    except OSError as exc:
        raise GitHubAttestationError(
            f"cannot inspect isolated GitHub CLI executable {source_path!r}: {exc}"
        ) from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or _is_reparse_point(before)
        or not stat.S_ISREG(before.st_mode)
    ):
        raise GitHubAttestationError(
            "isolated GitHub CLI executable must be a regular non-symlink file"
        )
    if before.st_size > MAX_GITHUB_ATTESTATION_EXECUTABLE_BYTES:
        raise GitHubAttestationError(
            "isolated GitHub CLI executable exceeds its bounded size limit"
        )
    if os.name == "posix" and stat.S_IMODE(before.st_mode) & 0o111 == 0:
        raise GitHubAttestationError(
            "isolated GitHub CLI executable must have an execute permission bit"
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_descriptor = os.open(source_path, flags)
    except OSError as exc:
        raise GitHubAttestationError(
            f"cannot open isolated GitHub CLI executable {source_path!r}: {exc}"
        ) from exc
    snapshot_descriptor = -1
    snapshot_path = os.path.join(directory, "gh-pinned")
    completed = False
    try:
        opened = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse_point(opened)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise GitHubAttestationError(
                "isolated GitHub CLI executable changed while it was being opened"
            )
        if opened.st_size > MAX_GITHUB_ATTESTATION_EXECUTABLE_BYTES:
            raise GitHubAttestationError(
                "isolated GitHub CLI executable exceeds its bounded size limit"
            )
        snapshot_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
        )
        snapshot_descriptor = os.open(snapshot_path, snapshot_flags, 0o500)
        digest = hashlib.sha256()
        copied = 0
        with os.fdopen(source_descriptor, "rb", closefd=False) as source, os.fdopen(
            snapshot_descriptor, "wb", closefd=False
        ) as destination:
            while True:
                chunk = source.read(_STREAM_CHUNK_BYTES)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > MAX_GITHUB_ATTESTATION_EXECUTABLE_BYTES:
                    raise GitHubAttestationError(
                        "isolated GitHub CLI executable exceeds its bounded size limit"
                    )
                digest.update(chunk)
                destination.write(chunk)
            destination.flush()
            os.fsync(destination.fileno())
        after = os.fstat(source_descriptor)
        if _file_identity(after) != _file_identity(opened) or copied != opened.st_size:
            raise GitHubAttestationError(
                "isolated GitHub CLI executable changed while it was being copied"
            )
        if digest.hexdigest() != isolation.executable_sha256:
            raise GitHubAttestationError(
                "isolated GitHub CLI executable SHA-256 does not match the pinned digest"
            )
        _set_provider_path_access(
            snapshot_path,
            uid=owner_uid,
            gid=owner_gid,
            mode=0o555,
            label="pinned GitHub CLI executable snapshot",
        )
        completed = True
        return snapshot_path
    finally:
        if snapshot_descriptor >= 0:
            try:
                os.close(snapshot_descriptor)
            except OSError:
                pass
        os.close(source_descriptor)
        if not completed:
            _remove_provider_snapshot(snapshot_path)


def _isolated_gh_environment(
    directory: str,
    isolation: GitHubAttestationProviderIsolation,
) -> dict[str, str]:
    """Build a provider environment without inheriting ambient secrets."""

    config_directory = os.path.join(directory, "gh-config")
    try:
        os.mkdir(config_directory, mode=0o700)
    except OSError as exc:
        raise GitHubAttestationError(
            f"cannot create isolated GitHub CLI config directory: {exc}"
        ) from exc
    _set_provider_path_access(
        config_directory,
        uid=isolation.uid,
        gid=isolation.gid,
        mode=0o700,
        label="isolated GitHub CLI config directory",
    )
    environment = {
        name: os.environ[name]
        for name in ("GH_TOKEN", "GITHUB_TOKEN")
        if name in os.environ
    }
    environment.update(
        {
            "GH_CONFIG_DIR": config_directory,
            "HOME": config_directory,
            "TMPDIR": config_directory,
            "NO_COLOR": "1",
            "CLICOLOR": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _prepare_provider_isolation(
    isolation: GitHubAttestationProviderIsolation,
    *,
    gh_executable: str,
    snapshot_path: str,
    directory: str,
) -> tuple[str, dict[str, str], dict[str, object]]:
    """Prepare a pinned executable, accessible inputs, and a dropped identity."""

    checked = _validate_provider_isolation(isolation, gh_executable=gh_executable)
    effective_uid, effective_gid = _provider_posix_identity()
    pinned_executable = _snapshot_pinned_provider_executable(
        checked,
        directory,
        owner_uid=effective_uid,
        owner_gid=effective_gid,
    )
    try:
        _set_provider_path_access(
            snapshot_path,
            uid=checked.uid,
            gid=checked.gid,
            mode=0o400,
            label="GitHub attestation artifact snapshot",
        )
        environment = _isolated_gh_environment(directory, checked)
        _set_provider_path_access(
            directory,
            uid=effective_uid,
            gid=checked.gid,
            mode=0o710,
            label="isolated GitHub provider workspace",
        )
    except BaseException:
        _remove_provider_snapshot(pinned_executable)
        raise
    return (
        pinned_executable,
        environment,
        {
            "user": checked.uid,
            "group": checked.gid,
            "extra_groups": (),
            "umask": 0o077,
        },
    )


def _gh_environment(directory: str) -> dict[str, str]:
    """Forward only GitHub auth tokens, never ambient GitHub CLI controls.

    Every inherited ``GH_*`` control except ``GH_TOKEN`` is removed, including
    config routing, debug, pager, prompt, and host selection. ``GITHUB_TOKEN``
    remains available because a protected GitHub Actions job can use either
    documented token variable. The caller remains responsible for supplying a
    trusted executable path/PATH in that protected job.
    """

    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("GH_") or name == "GH_TOKEN"
    }
    environment["GH_CONFIG_DIR"] = os.path.join(directory, "gh-config")
    os.makedirs(environment["GH_CONFIG_DIR"], mode=0o700, exist_ok=True)
    environment["NO_COLOR"] = "1"
    environment["CLICOLOR"] = "0"
    return environment


def _terminate_gh_process_tree(process: subprocess.Popen[Any]) -> bool:
    """Terminate the verifier's managed process group and prove cleanup."""

    return terminate_process_tree(process, _GITHUB_ATTESTATION_PROCESS_LIMITS)


def _join_and_close_gh_readers(
    readers: list[threading.Thread],
    streams: list[Any],
) -> bool:
    """Boundedly join attempted readers and close only streams proven safe."""

    stopped: list[bool] = []
    first_error: BaseException | None = None
    deadline = time.monotonic() + _GITHUB_ATTESTATION_READER_JOIN_SECONDS
    for reader in readers:
        try:
            reader.join(max(0.0, deadline - time.monotonic()))
            stopped.append(not reader.is_alive())
        except BaseException as exc:
            # start() can raise after a native thread exists. A failed join is
            # therefore not proof that the corresponding pipe is safe to close.
            stopped.append(False)
            if first_error is None:
                first_error = exc

    streams_closed = True
    for index, stream in enumerate(streams):
        safe_to_close = index >= len(stopped) or stopped[index]
        if not safe_to_close:
            streams_closed = False
            continue
        try:
            stream.close()
        except (OSError, ValueError):
            streams_closed = False
        except BaseException as exc:
            streams_closed = False
            if first_error is None:
                first_error = exc
    if first_error is not None:
        raise first_error
    return all(stopped) and streams_closed


def _execute_gh_attestation_command(
    command: list[str],
    *,
    gh_executable: str,
    timeout_seconds: int,
    directory: str,
    environment: Mapping[str, str] | None = None,
    provider_launch_kwargs: Mapping[str, object] | None = None,
) -> bytes:
    """Execute the trusted CLI with raw, separately bounded output streams."""

    process: subprocess.Popen[Any] | None = None
    streams: list[Any] = []
    reader_start_attempts: list[threading.Thread] = []
    cleanup_proven = False
    readers_closed = False
    try:
        try:
            launch_kwargs: dict[str, object] = dict(process_group_popen_kwargs())
            if provider_launch_kwargs is not None:
                launch_kwargs.update(provider_launch_kwargs)
            process = subprocess.Popen(  # type: ignore[call-overload]
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=directory,
                env=(
                    dict(environment)
                    if environment is not None
                    else _gh_environment(directory)
                ),
                shell=False,
                **launch_kwargs,
            )
        except FileNotFoundError as exc:
            raise GitHubAttestationError(
                f"GitHub CLI executable was not found: {gh_executable!r}"
            ) from exc
        except OSError as exc:
            raise GitHubAttestationError(
                f"cannot run GitHub attestation verifier: {exc}"
            ) from exc

        stdout_stream = process.stdout
        stderr_stream = process.stderr
        streams = [stream for stream in (stdout_stream, stderr_stream) if stream is not None]
        if stdout_stream is None or stderr_stream is None:
            raise GitHubAttestationError(
                "GitHub attestation verifier did not provide output pipes"
            )

        stdout = bytearray()
        stderr = bytearray()
        overflow: set[str] = set()
        read_errors: list[BaseException] = []
        reader_signal = threading.Event()

        def drain(stream: Any, *, maximum: int, target: bytearray, label: str) -> None:
            try:
                read = getattr(stream, "read1", None)
                if not callable(read):
                    read = stream.read
                while True:
                    chunk = read(_STREAM_CHUNK_BYTES)
                    if not chunk:
                        return
                    remaining = maximum + 1 - len(target)
                    if remaining > 0:
                        target.extend(chunk[:remaining])
                    if len(target) > maximum:
                        overflow.add(label)
                        reader_signal.set()
            except BaseException as exc:
                read_errors.append(exc)
                reader_signal.set()

        readers = [
            threading.Thread(
                target=drain,
                args=(stdout_stream,),
                kwargs={
                    "maximum": MAX_GITHUB_ATTESTATION_OUTPUT_BYTES,
                    "target": stdout,
                    "label": "stdout",
                },
                daemon=True,
            ),
            threading.Thread(
                target=drain,
                args=(stderr_stream,),
                kwargs={
                    "maximum": _GITHUB_ATTESTATION_STDERR_BYTES,
                    "target": stderr,
                    "label": "stderr",
                },
                daemon=True,
            ),
        ]
        for reader in readers:
            # Record before start(): start can fail after a native thread exists.
            reader_start_attempts.append(reader)
            reader.start()

        deadline = time.monotonic() + timeout_seconds
        timed_out = False
        while True:
            if read_errors or overflow:
                break
            if process.poll() is not None:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            reader_signal.wait(min(_GITHUB_ATTESTATION_PROCESS_POLL_SECONDS, remaining))

        interrupted = timed_out or bool(read_errors) or bool(overflow)
        if interrupted:
            root_exited_on_windows = os.name == "nt" and process.poll() is not None
            if not root_exited_on_windows:
                if not _terminate_gh_process_tree(process):
                    root_exited_on_windows = (
                        os.name == "nt" and process.poll() is not None
                    )
                    if not root_exited_on_windows:
                        raise GitHubAttestationError(
                            "GitHub attestation verifier process cleanup could not be proven"
                        )
                else:
                    cleanup_proven = True
            returncode = process.returncode
        else:
            try:
                returncode = process.wait(timeout=_GITHUB_ATTESTATION_KILL_REAP_SECONDS)
            except BaseException:
                try:
                    cleanup_proven = _terminate_gh_process_tree(process)
                except BaseException:
                    pass
                raise
            if os.name == "posix":
                if not _terminate_gh_process_tree(process):
                    raise GitHubAttestationError(
                        "GitHub attestation verifier process cleanup could not be proven"
                    )
                cleanup_proven = True

        if not _join_and_close_gh_readers(reader_start_attempts, streams):
            raise GitHubAttestationError(
                "GitHub attestation verifier left output pipes open past its bounded timeout"
            )
        readers_closed = True

        if overflow:
            raise GitHubAttestationError(
                "GitHub attestation verifier exceeded its bounded standard-output or "
                "standard-error limit"
            )
        if timed_out:
            raise GitHubAttestationError(
                f"GitHub attestation verification exceeded {timeout_seconds} seconds"
            )
        if read_errors:
            raise GitHubAttestationError(
                f"GitHub attestation verifier output could not be read: {read_errors[0]}"
            ) from read_errors[0]
        if returncode is None:  # pragma: no cover - defensive process-state invariant
            raise GitHubAttestationError(
                "GitHub attestation verifier has no terminal exit status"
            )

        stdout_bytes = bytes(stdout)
        stderr_bytes = bytes(stderr)
        if returncode != 0:
            error = stderr_bytes.decode("utf-8", errors="backslashreplace").strip()
            if len(error) > 2000:
                error = error[:2000] + "…"
            raise GitHubAttestationError(
                "GitHub attestation verification failed"
                + (f": {error}" if error else f" (exit {returncode})")
            )
        _load_attestation_output(stdout_bytes)
        return stdout_bytes
    except BaseException:
        # Preserve the active exception while attempting bounded cleanup.
        if process is not None:
            if not cleanup_proven:
                try:
                    cleanup_proven = _terminate_gh_process_tree(process)
                except BaseException:
                    pass
            if not readers_closed:
                try:
                    readers_closed = _join_and_close_gh_readers(
                        reader_start_attempts,
                        streams,
                    )
                except BaseException:
                    pass
        raise


def _run_gh_attestation_verify(
    snapshot_path: str,
    policy: GitHubAttestationPolicy,
    *,
    gh_executable: str,
    timeout_seconds: int,
    directory: str,
    provider_isolation: GitHubAttestationProviderIsolation | None = None,
) -> bytes:
    if not isinstance(gh_executable, str) or not gh_executable or len(gh_executable) > 4096:
        raise GitHubAttestationError("gh executable must be a non-empty path or command")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= MAX_GITHUB_ATTESTATION_TIMEOUT_SECONDS:
        raise GitHubAttestationError(
            f"GitHub attestation timeout must be an integer from 1 through "
            f"{MAX_GITHUB_ATTESTATION_TIMEOUT_SECONDS} seconds"
        )
    effective_executable = gh_executable
    environment: dict[str, str] | None = None
    provider_launch_kwargs: dict[str, object] | None = None
    pinned_executable = ""
    if provider_isolation is not None:
        (
            pinned_executable,
            environment,
            provider_launch_kwargs,
        ) = _prepare_provider_isolation(
            provider_isolation,
            gh_executable=gh_executable,
            snapshot_path=snapshot_path,
            directory=directory,
        )
        effective_executable = pinned_executable
    command = [
        effective_executable,
        "attestation",
        "verify",
        snapshot_path,
        "--repo",
        policy.repository,
        "--signer-workflow",
        policy.signer_workflow,
        "--signer-digest",
        policy.signer_digest,
        "--source-ref",
        policy.source_ref,
        "--source-digest",
        policy.source_digest,
        "--cert-oidc-issuer",
        policy.cert_oidc_issuer,
        "--predicate-type",
        GITHUB_ATTESTATION_PREDICATE_TYPE,
        "--deny-self-hosted-runners",
        "--limit",
        "1",
        "--format",
        "json",
    ]
    try:
        return _execute_gh_attestation_command(
            command,
            gh_executable=gh_executable,
            timeout_seconds=timeout_seconds,
            directory=directory,
            environment=environment,
            provider_launch_kwargs=provider_launch_kwargs,
        )
    finally:
        if pinned_executable:
            _remove_provider_snapshot(pinned_executable)

def create_github_attestation_receipt(
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
    gh_executable: str = "gh",
    timeout_seconds: int = DEFAULT_GITHUB_ATTESTATION_TIMEOUT_SECONDS,
    expected_workflow_run_id: str | None = None,
    expected_workflow_run_attempt: int | None = None,
    provider_isolation: GitHubAttestationProviderIsolation | None = None,
) -> CreatedGitHubAttestationReceipt:
    """Run a strict GitHub CLI attestation verification and retain its receipt.

    The receipt is intentionally unsigned.  Its function is to preserve the
    successful external-verifier event and exact output so a separate
    artifact-admission key can bind it.  It must not be treated as an
    independently portable proof before it is sealed by that separate key.
    """

    policy = github_attestation_policy(
        repository,
        signer_workflow,
        source_digest,
        signer_digest=signer_digest,
        source_ref=source_ref,
        cert_oidc_issuer=cert_oidc_issuer,
    )
    if os.path.abspath(receipt_path) == os.path.abspath(raw_output_path):
        raise GitHubAttestationError("receipt and raw-output paths must differ")
    if any(value == "-" for value in (artifact_path, receipt_path, raw_output_path)):
        raise GitHubAttestationError(
            "artifact, receipt, and raw-output paths must be regular paths, not standard input/output"
        )
    with tempfile.TemporaryDirectory(prefix=".evoguard-github-attestation-") as directory:
        snapshot_path, artifact = _snapshot_regular_artifact(artifact_path, directory)
        try:
            output = _run_gh_attestation_verify(
                snapshot_path,
                policy,
                gh_executable=gh_executable,
                timeout_seconds=timeout_seconds,
                directory=directory,
                provider_isolation=provider_isolation,
            )
            validate_github_attestation_verifier_output(
                output,
                artifact=artifact,
                policy=policy,
                expected_workflow_run_id=expected_workflow_run_id,
                expected_workflow_run_attempt=expected_workflow_run_attempt,
            )
        finally:
            try:
                os.unlink(snapshot_path)
            except OSError:
                pass
    output_descriptor = _output_descriptor(output)
    receipt = {
        "format": GITHUB_ATTESTATION_RECEIPT_FORMAT,
        "artifact": artifact.as_dict(),
        "verification_policy": policy.as_dict(),
        "verification_output": output_descriptor,
    }
    canonical_receipt = _canonical_json(_validate_receipt(receipt))
    if len(canonical_receipt) > MAX_GITHUB_ATTESTATION_RECEIPT_BYTES:
        raise GitHubAttestationError("canonical GitHub attestation receipt exceeds its size limit")
    raw_absolute = _write_new_file(raw_output_path, output, label="GitHub attestation raw output")
    try:
        receipt_absolute = _write_new_file(
            receipt_path,
            canonical_receipt,
            label="GitHub attestation receipt",
        )
    except BaseException:
        try:
            os.unlink(raw_absolute)
        except OSError:
            pass
        raise
    return CreatedGitHubAttestationReceipt(
        receipt_path=receipt_absolute,
        raw_output_path=raw_absolute,
        artifact=artifact,
        policy=policy,
        verified_attestation_count=1,
    )


def _read_receipt(path: str) -> dict[str, Any]:
    data = _read_bounded_file(
        path,
        limit=MAX_GITHUB_ATTESTATION_RECEIPT_BYTES,
        label="GitHub attestation receipt",
    )
    try:
        decoded = strict_json_loads(data.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise GitHubAttestationError(f"invalid GitHub attestation receipt JSON: {exc}") from exc
    if not isinstance(decoded, dict):
        raise GitHubAttestationError("GitHub attestation receipt must be a JSON object")
    checked = _validate_receipt(decoded)
    if _canonical_json(checked) != data:
        raise GitHubAttestationError("GitHub attestation receipt is not canonical JSON")
    return checked


def _hash_regular_artifact(path: str) -> GitHubAttestationArtifact:
    """Hash a stable regular file for receipt rechecking without executing it."""

    with tempfile.TemporaryDirectory(prefix=".evoguard-github-attestation-check-") as directory:
        snapshot_path, artifact = _snapshot_regular_artifact(path, directory)
        try:
            return artifact
        finally:
            try:
                os.unlink(snapshot_path)
            except OSError:
                pass


def verify_github_attestation_receipt(
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
    expected_workflow_run_id: str | None = None,
    expected_workflow_run_attempt: int | None = None,
) -> VerifiedGitHubAttestationReceipt:
    """Check retained receipt/output bytes against external expected policy.

    This function does not invoke ``gh``.  It verifies byte continuity for a
    prior successful external verification; callers requiring a fresh
    cryptographic GitHub check must call :func:`create_github_attestation_receipt`.
    """

    receipt = _read_receipt(receipt_path)
    policy = github_attestation_policy(
        repository,
        signer_workflow,
        source_digest,
        signer_digest=signer_digest,
        source_ref=source_ref,
        cert_oidc_issuer=cert_oidc_issuer,
    )
    receipt_policy = _validate_policy(
        receipt["verification_policy"], label="GitHub attestation receipt verification_policy"
    )
    if receipt_policy != policy:
        raise GitHubAttestationError(
            "GitHub attestation receipt policy does not exactly match external expected policy"
        )
    artifact = _hash_regular_artifact(artifact_path)
    receipt_artifact = _validate_artifact(receipt["artifact"], label="GitHub attestation receipt artifact")
    if artifact != receipt_artifact:
        raise GitHubAttestationError(
            "GitHub attestation receipt artifact does not match the external artifact bytes"
        )
    raw_output = _read_bounded_file(
        raw_output_path,
        limit=MAX_GITHUB_ATTESTATION_OUTPUT_BYTES,
        label="GitHub attestation raw output",
    )
    validate_github_attestation_verifier_output(
        raw_output,
        artifact=artifact,
        policy=policy,
        expected_workflow_run_id=expected_workflow_run_id,
        expected_workflow_run_attempt=expected_workflow_run_attempt,
    )
    output = _output_descriptor(raw_output)
    if output != _validate_output(
        receipt["verification_output"], label="GitHub attestation receipt verification_output"
    ):
        raise GitHubAttestationError(
            "GitHub attestation receipt output does not match retained raw verifier output"
        )
    return VerifiedGitHubAttestationReceipt(receipt=receipt, artifact=artifact, policy=policy)


def reverify_github_attestation_receipt(
    receipt_path: str,
    artifact_path: str,
    *,
    repository: str,
    signer_workflow: str,
    signer_digest: str,
    source_ref: str,
    source_digest: str,
    cert_oidc_issuer: str,
    gh_executable: str = "gh",
    timeout_seconds: int = DEFAULT_GITHUB_ATTESTATION_TIMEOUT_SECONDS,
    expected_workflow_run_id: str | None = None,
    expected_workflow_run_attempt: int | None = None,
    provider_isolation: GitHubAttestationProviderIsolation | None = None,
) -> FreshGitHubAttestationVerification:
    """Perform a fresh GitHub CLI cryptographic verification for a receipt.

    Unlike :func:`verify_github_attestation_receipt`, this does contact the
    configured GitHub attestation service through ``gh``.  It validates that
    the external policy and current artifact bytes match the retained receipt
    before invoking the same strict external-verifier policy again.
    """

    receipt = _read_receipt(receipt_path)
    policy = github_attestation_policy(
        repository,
        signer_workflow,
        source_digest,
        signer_digest=signer_digest,
        source_ref=source_ref,
        cert_oidc_issuer=cert_oidc_issuer,
    )
    receipt_policy = _validate_policy(
        receipt["verification_policy"], label="GitHub attestation receipt verification_policy"
    )
    if receipt_policy != policy:
        raise GitHubAttestationError(
            "GitHub attestation receipt policy does not exactly match external expected policy"
        )
    with tempfile.TemporaryDirectory(prefix=".evoguard-github-attestation-reverify-") as directory:
        snapshot_path, artifact = _snapshot_regular_artifact(artifact_path, directory)
        try:
            receipt_artifact = _validate_artifact(
                receipt["artifact"], label="GitHub attestation receipt artifact"
            )
            if artifact != receipt_artifact:
                raise GitHubAttestationError(
                    "GitHub attestation receipt artifact does not match the external artifact bytes"
                )
            output = _run_gh_attestation_verify(
                snapshot_path,
                policy,
                gh_executable=gh_executable,
                timeout_seconds=timeout_seconds,
                directory=directory,
                provider_isolation=provider_isolation,
            )
            validate_github_attestation_verifier_output(
                output,
                artifact=artifact,
                policy=policy,
                expected_workflow_run_id=expected_workflow_run_id,
                expected_workflow_run_attempt=expected_workflow_run_attempt,
            )
        finally:
            try:
                os.unlink(snapshot_path)
            except OSError:
                pass
    _output_descriptor(output)
    return FreshGitHubAttestationVerification(
        artifact=artifact,
        policy=policy,
        verified_attestation_count=1,
    )


def github_attestation_provenance_identity(policy: GitHubAttestationPolicy) -> str:
    """Stable, bounded V2 identity that commits to every provider-policy pin."""

    policy_digest = hashlib.sha256(_canonical_json(policy.as_dict())).hexdigest()
    return (
        f"{GITHUB_ATTESTATION_PROVENANCE_IDENTITY_PREFIX}{policy.repository}:"
        f"{policy.source_digest}:{policy_digest}"
    )


def _require_finalizer_head_context(
    policy: GitHubAttestationPolicy,
    expected_finalizer_context: Mapping[str, Any],
) -> None:
    head_sha = expected_finalizer_context.get("head_sha")
    if head_sha != policy.source_digest:
        raise GitHubAttestationError(
            "GitHub attestation source digest must exactly match expected finalizer context.head_sha"
        )


def seal_github_attestation_admission(
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
    gh_executable: str = "gh",
    timeout_seconds: int = DEFAULT_GITHUB_ATTESTATION_TIMEOUT_SECONDS,
    provider_isolation: GitHubAttestationProviderIsolation | None = None,
    force: bool = False,
) -> SealedGitHubAttestationAdmission:
    """Verify GitHub attestation now, then bind its receipt through V2 admission.

    No candidate-controlled value selects the subject: the subject is the SHA-256
    of the exact snapshot passed to ``gh``.  The required source digest also
    has to equal the caller's expected finalizer head before the admission key
    is opened.
    """

    policy = github_attestation_policy(
        repository,
        signer_workflow,
        source_digest,
        signer_digest=signer_digest,
        source_ref=source_ref,
        cert_oidc_issuer=cert_oidc_issuer,
    )
    _require_finalizer_head_context(policy, expected_finalizer_context)
    receipt = create_github_attestation_receipt(
        artifact_path,
        receipt_path,
        raw_output_path,
        repository=policy.repository,
        signer_workflow=policy.signer_workflow,
        signer_digest=policy.signer_digest,
        source_ref=policy.source_ref,
        source_digest=policy.source_digest,
        cert_oidc_issuer=policy.cert_oidc_issuer,
        gh_executable=gh_executable,
        timeout_seconds=timeout_seconds,
        provider_isolation=provider_isolation,
    )
    try:
        admission = seal_artifact_digest_admission(
            "artifact-sha256",
            f"sha256:{receipt.artifact.sha256}",
            receipt.receipt_path,
            github_attestation_provenance_identity(policy),
            finalizer_bundle_path,
            output_path,
            trusted_finalizer_public_key_path=trusted_finalizer_public_key_path,
            expected_finalizer_source=expected_finalizer_source,
            expected_finalizer_context=expected_finalizer_context,
            private_key_path=private_key_path,
            force=force,
        )
    except (ArtifactDigestAdmissionError, OSError, ValueError) as exc:
        raise GitHubAttestationError(f"cannot seal GitHub attestation admission: {exc}") from exc
    return SealedGitHubAttestationAdmission(receipt=receipt, admission=admission)


def verify_github_attestation_admission(
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
) -> VerifiedGitHubAttestationAdmission:
    """Verify a retained V2 GitHub-attestation admission without a live recheck."""

    policy = github_attestation_policy(
        repository,
        signer_workflow,
        source_digest,
        signer_digest=signer_digest,
        source_ref=source_ref,
        cert_oidc_issuer=cert_oidc_issuer,
    )
    _require_finalizer_head_context(policy, expected_finalizer_context)
    receipt = verify_github_attestation_receipt(
        receipt_path,
        artifact_path,
        raw_output_path,
        repository=policy.repository,
        signer_workflow=policy.signer_workflow,
        signer_digest=policy.signer_digest,
        source_ref=policy.source_ref,
        source_digest=policy.source_digest,
        cert_oidc_issuer=policy.cert_oidc_issuer,
    )
    try:
        admission = verify_artifact_digest_admission(
            binding_path,
            "artifact-sha256",
            f"sha256:{receipt.artifact.sha256}",
            receipt_path,
            github_attestation_provenance_identity(policy),
            finalizer_bundle_path,
            trusted_public_key_path=trusted_public_key_path,
            trusted_finalizer_public_key_path=trusted_finalizer_public_key_path,
            expected_finalizer_source=expected_finalizer_source,
            expected_finalizer_context=expected_finalizer_context,
        )
    except (ArtifactDigestAdmissionError, OSError, ValueError) as exc:
        raise GitHubAttestationError(f"cannot verify GitHub attestation admission: {exc}") from exc
    return VerifiedGitHubAttestationAdmission(receipt=receipt, admission=admission)
