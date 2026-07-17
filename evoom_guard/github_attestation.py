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
* data inside the attestation statement predicate is not interpreted as a
  trusted EvoGuard fact.  Only the external verifier's success under the
  recorded policy is carried forward.

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
from evoom_guard.strict_json import strict_json_loads

GITHUB_ATTESTATION_RECEIPT_FORMAT = "EVOGUARD_GITHUB_ATTESTATION_RECEIPT_V1"
GITHUB_ATTESTATION_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
GITHUB_ATTESTATION_CERT_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_ATTESTATION_PROVENANCE_IDENTITY_PREFIX = "github-attestation-receipt-v1:"

MAX_GITHUB_ATTESTATION_RECEIPT_BYTES = 64 * 1024
MAX_GITHUB_ATTESTATION_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_GITHUB_ATTESTATION_TIMEOUT_SECONDS = 600
DEFAULT_GITHUB_ATTESTATION_TIMEOUT_SECONDS = 120
_STREAM_CHUNK_BYTES = 1024 * 1024

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


class GitHubAttestationError(ValueError):
    """A GitHub attestation boundary input, receipt, or verifier run is invalid."""


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
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


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


def _load_attestation_output(data: bytes) -> list[object]:
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
    return decoded


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


def _drain_bounded_process_stream(
    stream: Any,
    *,
    limit: int,
    data: bytearray,
    limit_exceeded: threading.Event,
    process: subprocess.Popen[bytes],
) -> None:
    """Drain a child pipe while holding no more than its declared byte limit.

    A child inherits an OS pipe, so sending stdout directly to a temporary file
    would allow it to fill the filesystem before a post-run size check.  This
    reader kills the child once its output exceeds the fixed bound, then keeps
    draining to let the other pipe and process close cleanly.
    """

    try:
        read = getattr(stream, "read1", stream.read)
        while True:
            try:
                chunk = read(_STREAM_CHUNK_BYTES)
            except (OSError, ValueError):
                return
            if not chunk:
                return
            remaining = limit - len(data)
            if remaining <= 0 or len(chunk) > remaining:
                if remaining > 0:
                    data.extend(chunk[:remaining])
                limit_exceeded.set()
                try:
                    process.kill()
                except (OSError, ProcessLookupError):
                    pass
                # Do not retain anything further, but keep consuming the pipe
                # so an already-running sibling stream cannot deadlock.
                continue
            data.extend(chunk)
    finally:
        try:
            stream.close()
        except (OSError, ValueError):
            pass


def _close_process_pipes(process: subprocess.Popen[bytes]) -> None:
    """Close inherited pipe endpoints without waiting on untrusted descendants."""

    for stream in (process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except (OSError, ValueError):
                pass


def _run_gh_attestation_verify(
    snapshot_path: str,
    policy: GitHubAttestationPolicy,
    *,
    gh_executable: str,
    timeout_seconds: int,
    directory: str,
) -> bytes:
    if not isinstance(gh_executable, str) or not gh_executable or len(gh_executable) > 4096:
        raise GitHubAttestationError("gh executable must be a non-empty path or command")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= MAX_GITHUB_ATTESTATION_TIMEOUT_SECONDS:
        raise GitHubAttestationError(
            f"GitHub attestation timeout must be an integer from 1 through "
            f"{MAX_GITHUB_ATTESTATION_TIMEOUT_SECONDS} seconds"
        )
    command = [
        gh_executable,
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
    stdout = bytearray()
    stderr = bytearray()
    output_limit_exceeded = threading.Event()
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=directory,
            env=_gh_environment(directory),
            shell=False,
        )
    except FileNotFoundError as exc:
        raise GitHubAttestationError(
            f"GitHub CLI executable was not found: {gh_executable!r}"
        ) from exc
    except OSError as exc:
        raise GitHubAttestationError(f"cannot run GitHub attestation verifier: {exc}") from exc

    if process.stdout is None or process.stderr is None:  # pragma: no cover - subprocess invariant
        raise GitHubAttestationError("GitHub attestation verifier did not provide output pipes")
    readers = (
        threading.Thread(
            target=_drain_bounded_process_stream,
            kwargs={
                "stream": process.stdout,
                "limit": MAX_GITHUB_ATTESTATION_OUTPUT_BYTES,
                "data": stdout,
                "limit_exceeded": output_limit_exceeded,
                "process": process,
            },
            daemon=True,
        ),
        threading.Thread(
            target=_drain_bounded_process_stream,
            kwargs={
                "stream": process.stderr,
                "limit": 64 * 1024,
                "data": stderr,
                "limit_exceeded": output_limit_exceeded,
                "process": process,
            },
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    returncode: int | None = None
    pipes_left_open = False
    try:
        returncode = process.wait(timeout=max(0.001, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            process.kill()
        except (OSError, ProcessLookupError):
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
    finally:
        for reader in readers:
            remaining = deadline - time.monotonic()
            if remaining > 0:
                reader.join(timeout=remaining)
        pipes_left_open = any(reader.is_alive() for reader in readers)
        if pipes_left_open:
            _close_process_pipes(process)
            for reader in readers:
                reader.join(timeout=0.1)

    if output_limit_exceeded.is_set():
        raise GitHubAttestationError(
            "GitHub attestation verifier exceeded its bounded standard-output or standard-error limit"
        )
    if timed_out:
        raise GitHubAttestationError(
            f"GitHub attestation verification exceeded {timeout_seconds} seconds"
        )
    if pipes_left_open:
        raise GitHubAttestationError(
            "GitHub attestation verifier left output pipes open past its bounded timeout"
        )
    if returncode is None:  # pragma: no cover - defensive process-state invariant
        raise GitHubAttestationError("GitHub attestation verifier has no terminal exit status")
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
