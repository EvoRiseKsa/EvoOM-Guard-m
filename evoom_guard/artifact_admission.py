# -----------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Artifact admission bound to an already verified Trusted Finalizer ALLOW.

This deliberately narrow primitive binds one *regular-file* digest to the
exact finalizer evidence that admitted a pre-merge pull-request head. It is
not build provenance: it neither runs a build nor proves that the file was
produced from that head, released, deployed, reproduced, scanned, or selected
by a mutable name. A later provider-specific provenance boundary must
establish those relations before a consumer treats this record as release or
deployment proof.

The ``.eab`` container holds canonical ``binding.json`` and a detached Ed25519
``binding.sig``.  Its signature has a domain distinct from verdict/evidence
envelopes, so a valid signature for one format cannot be replayed as another.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import os
import re
import stat
import tempfile
import zipfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from evoom_guard.evidence_bundle import (
    MAX_ARCHIVE_BYTES,
    EvidenceBundleError,
    _archive_bytes,
    _canonical_json,
    _load_json_object,
    _preflight_zip,
    _read_regular_file,
    _validate_member_metadata,
    validate_evidence_context,
)
from evoom_guard.trusted_finalizer import (
    FinalizerHandoffError,
    VerifiedFinalizedBundle,
    _validate_source,
    _validate_source_context,
    verify_finalized_bundle,
)

ARTIFACT_BINDING_FORMAT = "EVOGUARD_ARTIFACT_BINDING_V1"
ARTIFACT_BINDING_DOMAIN = ARTIFACT_BINDING_FORMAT.encode("ascii") + b"\0"
ARTIFACT_BINDING_PURPOSE = "evoguard-artifact-admission"
ARTIFACT_BINDING_PATH = "binding.json"
ARTIFACT_SIGNATURE_PATH = "binding.sig"

MAX_ARTIFACT_BINDING_BYTES = 128 * 1024
MAX_ARTIFACT_BINDING_ARCHIVE_BYTES = MAX_ARTIFACT_BINDING_BYTES + 4 * 1024
MAX_ARTIFACT_FILE_BYTES = 4 * 1024 * 1024 * 1024
_STREAM_CHUNK_BYTES = 1024 * 1024

_BINDING_KEYS = {"format", "decision", "subject", "finalizer", "authentication"}
_SUBJECT_KEYS = {"kind", "sha256", "size"}
_FINALIZER_KEYS = {"bundle_sha256", "record_sha256", "key_id", "source", "context"}
_AUTHENTICATION_KEYS = {"algorithm", "key_id", "purpose", "signature_path"}
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_KEY_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")


class ArtifactAdmissionError(ValueError):
    """An artifact binding is malformed, unauthenticated, or replayed."""


@dataclass(frozen=True)
class ArtifactSubject:
    """The sole immutable regular-file subject of an artifact binding."""

    sha256: str
    size: int

    def as_dict(self) -> dict[str, object]:
        return {"kind": "file", "sha256": self.sha256, "size": self.size}


@dataclass(frozen=True)
class InspectedArtifactBinding:
    """A canonical binding container after structural checks only."""

    binding_bytes: bytes
    signature: bytes

    @property
    def payload(self) -> dict[str, Any]:
        """Return a fresh validated view, never mutable inspection state."""

        try:
            return _validate_payload(_load_json_object(self.binding_bytes, "artifact binding"))
        except EvidenceBundleError as exc:  # defensive: bytes were checked at inspection
            raise ArtifactAdmissionError(f"invalid artifact binding: {exc}") from exc

    @property
    def subject(self) -> dict[str, Any]:
        value = self.payload["subject"]
        return dict(value) if isinstance(value, dict) else {}

    @property
    def finalizer(self) -> dict[str, Any]:
        value = self.payload["finalizer"]
        return dict(value) if isinstance(value, dict) else {}


@dataclass(frozen=True)
class SealedArtifactBinding:
    """One newly signed file-subject admission binding."""

    binding_path: str
    payload: dict[str, Any]
    subject: ArtifactSubject


@dataclass(frozen=True)
class VerifiedArtifactBinding:
    """A binding whose artifact and finalizer inputs matched externally."""

    inspection: InspectedArtifactBinding
    subject: ArtifactSubject
    finalizer: VerifiedFinalizedBundle


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ArtifactAdmissionError(
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


def hash_regular_artifact(path: str) -> ArtifactSubject:
    """Hash one bounded regular file without trusting a mutable path twice.

    The result authenticates the bytes read from one stable file descriptor, not
    whatever a caller might later read through the same pathname. Consumers
    that act on a pathname must verify it immediately before consumption or use
    their own immutable/content-addressed storage boundary.
    """

    try:
        before = os.lstat(path)
    except OSError as exc:
        raise ArtifactAdmissionError(f"cannot inspect artifact {path!r}: {exc}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or _is_reparse_point(before)
        or not stat.S_ISREG(before.st_mode)
    ):
        raise ArtifactAdmissionError(f"artifact must be a regular non-symlink file: {path!r}")
    if before.st_size > MAX_ARTIFACT_FILE_BYTES:
        raise ArtifactAdmissionError(
            f"artifact exceeds the {MAX_ARTIFACT_FILE_BYTES}-byte size limit: {path!r}"
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ArtifactAdmissionError(f"cannot open artifact {path!r}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _is_reparse_point(opened):
            raise ArtifactAdmissionError(f"artifact changed to a non-regular file: {path!r}")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ArtifactAdmissionError(f"artifact changed while it was being opened: {path!r}")
        if opened.st_size > MAX_ARTIFACT_FILE_BYTES:
            raise ArtifactAdmissionError(
                f"artifact exceeds the {MAX_ARTIFACT_FILE_BYTES}-byte size limit: {path!r}"
            )
        digest = hashlib.sha256()
        bytes_read = 0
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            while True:
                chunk = handle.read(_STREAM_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
                bytes_read += len(chunk)
        after = os.fstat(descriptor)
        if _file_identity(after) != _file_identity(opened):
            raise ArtifactAdmissionError(f"artifact changed while it was being read: {path!r}")
        if bytes_read != opened.st_size:
            raise ArtifactAdmissionError(
                f"artifact read length does not match its stable size: {path!r}"
            )
    finally:
        os.close(descriptor)
    return ArtifactSubject(sha256=digest.hexdigest(), size=opened.st_size)


def _validate_subject(value: Mapping[str, Any]) -> ArtifactSubject:
    subject = dict(value)
    _require_exact_keys(subject, _SUBJECT_KEYS, "artifact subject")
    if subject.get("kind") != "file":
        raise ArtifactAdmissionError("artifact subject.kind must be 'file'")
    digest = subject.get("sha256")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise ArtifactAdmissionError("artifact subject.sha256 must be a lowercase SHA-256 digest")
    size = subject.get("size")
    if type(size) is not int or size < 0 or size > MAX_ARTIFACT_FILE_BYTES:
        raise ArtifactAdmissionError(
            f"artifact subject.size must be an integer from 0 through {MAX_ARTIFACT_FILE_BYTES}"
        )
    return ArtifactSubject(sha256=digest, size=size)


def _validate_finalizer(value: Mapping[str, Any]) -> dict[str, Any]:
    finalizer = dict(value)
    _require_exact_keys(finalizer, _FINALIZER_KEYS, "artifact binding finalizer")
    for field in ("bundle_sha256", "record_sha256"):
        digest = finalizer.get(field)
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise ArtifactAdmissionError(
                f"artifact binding finalizer.{field} must be a lowercase SHA-256 digest"
            )
    key_id = finalizer.get("key_id")
    if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
        raise ArtifactAdmissionError(
            "artifact binding finalizer.key_id must be sha256:<lowercase DER-SPKI digest>"
        )
    source = finalizer.get("source")
    context = finalizer.get("context")
    if not isinstance(source, dict) or not isinstance(context, dict):
        raise ArtifactAdmissionError(
            "artifact binding finalizer.source and context must be objects"
        )
    try:
        verified_source = _validate_source(source)
        verified_context = validate_evidence_context(context, verdict=None)
        _validate_source_context(verified_source, verified_context)
    except (EvidenceBundleError, FinalizerHandoffError) as exc:
        raise ArtifactAdmissionError(f"invalid artifact binding finalizer: {exc}") from exc
    return {
        "bundle_sha256": finalizer["bundle_sha256"],
        "record_sha256": finalizer["record_sha256"],
        "key_id": finalizer["key_id"],
        "source": verified_source,
        "context": verified_context,
    }


def _validate_authentication(value: Mapping[str, Any]) -> dict[str, str]:
    authentication = dict(value)
    _require_exact_keys(authentication, _AUTHENTICATION_KEYS, "artifact binding authentication")
    if authentication.get("algorithm") != "Ed25519":
        raise ArtifactAdmissionError("artifact binding authentication.algorithm must be Ed25519")
    if authentication.get("purpose") != ARTIFACT_BINDING_PURPOSE:
        raise ArtifactAdmissionError(
            f"artifact binding authentication.purpose must be {ARTIFACT_BINDING_PURPOSE!r}"
        )
    if authentication.get("signature_path") != ARTIFACT_SIGNATURE_PATH:
        raise ArtifactAdmissionError(
            f"artifact binding authentication.signature_path must be {ARTIFACT_SIGNATURE_PATH!r}"
        )
    key_id = authentication.get("key_id")
    if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
        raise ArtifactAdmissionError(
            "artifact binding authentication.key_id must be sha256:<lowercase DER-SPKI digest>"
        )
    return authentication


def _validate_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(value)
    _require_exact_keys(payload, _BINDING_KEYS, "artifact binding")
    if payload.get("format") != ARTIFACT_BINDING_FORMAT:
        raise ArtifactAdmissionError(
            f"unsupported artifact binding format: {payload.get('format')!r}"
        )
    if payload.get("decision") != "ALLOW":
        raise ArtifactAdmissionError("artifact binding decision must be ALLOW")
    subject = payload.get("subject")
    finalizer = payload.get("finalizer")
    authentication = payload.get("authentication")
    if (
        not isinstance(subject, dict)
        or not isinstance(finalizer, dict)
        or not isinstance(authentication, dict)
    ):
        raise ArtifactAdmissionError(
            "artifact binding subject, finalizer, and authentication must be objects"
        )
    verified_subject = _validate_subject(subject)
    verified_finalizer = _validate_finalizer(finalizer)
    verified_authentication = _validate_authentication(authentication)
    if verified_authentication["key_id"] == verified_finalizer["key_id"]:
        raise ArtifactAdmissionError(
            "artifact-admission authentication key must differ from the finalizer key"
        )
    return {
        "format": ARTIFACT_BINDING_FORMAT,
        "decision": "ALLOW",
        "subject": verified_subject.as_dict(),
        "finalizer": verified_finalizer,
        "authentication": verified_authentication,
    }


def _decode_signature(data: bytes) -> bytes:
    if len(data) != 88 or any(byte > 0x7F for byte in data):
        raise ArtifactAdmissionError("artifact binding signature must be 88 ASCII base64 bytes")
    try:
        signature = base64.b64decode(data, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ArtifactAdmissionError("artifact binding signature is not canonical base64") from exc
    if len(signature) != 64 or base64.b64encode(signature) != data:
        raise ArtifactAdmissionError(
            "artifact binding signature is not one canonical Ed25519 signature"
        )
    return signature


def _read_binding_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    limit: int,
) -> bytes:
    if info.file_size > limit:
        raise ArtifactAdmissionError(f"artifact binding member exceeds its limit: {info.filename}")
    try:
        with archive.open(info, "r") as handle:
            data = handle.read(limit + 1)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise ArtifactAdmissionError(
            f"cannot read artifact binding member {info.filename}: {exc}"
        ) from exc
    if len(data) > limit or len(data) != info.file_size:
        raise ArtifactAdmissionError(
            f"artifact binding member size is inconsistent: {info.filename}"
        )
    return data


def inspect_artifact_binding(path: str) -> InspectedArtifactBinding:
    """Inspect a canonical ``.eab`` without treating its key as trusted."""

    try:
        snapshot = _read_regular_file(
            path,
            limit=MAX_ARTIFACT_BINDING_ARCHIVE_BYTES,
            label="artifact binding",
        )
    except EvidenceBundleError as exc:
        raise ArtifactAdmissionError(str(exc)) from exc
    try:
        declared_entry_count = _preflight_zip(snapshot)
    except EvidenceBundleError as exc:
        raise ArtifactAdmissionError(str(exc)) from exc
    if declared_entry_count != 2:
        raise ArtifactAdmissionError("artifact binding must contain exactly two archive members")
    try:
        archive = zipfile.ZipFile(io.BytesIO(snapshot), "r")
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise ArtifactAdmissionError(f"cannot parse artifact binding: {exc}") from exc
    with archive:
        if archive.comment:
            raise ArtifactAdmissionError("artifact binding archive comment is not allowed")
        infos = archive.infolist()
        if [info.filename for info in infos] != [ARTIFACT_BINDING_PATH, ARTIFACT_SIGNATURE_PATH]:
            raise ArtifactAdmissionError("artifact binding archive members are not canonical")
        for info in infos:
            try:
                _validate_member_metadata(info)
            except EvidenceBundleError as exc:
                raise ArtifactAdmissionError(str(exc)) from exc
        binding_bytes = _read_binding_member(
            archive,
            infos[0],
            limit=MAX_ARTIFACT_BINDING_BYTES,
        )
        signature_bytes = _read_binding_member(archive, infos[1], limit=88)
    try:
        payload = _load_json_object(binding_bytes, "artifact binding")
        verified_payload = _validate_payload(payload)
        canonical = _canonical_json(verified_payload)
    except EvidenceBundleError as exc:
        raise ArtifactAdmissionError(f"invalid artifact binding: {exc}") from exc
    if canonical != binding_bytes:
        raise ArtifactAdmissionError("artifact binding is not canonical JSON")
    signature = _decode_signature(signature_bytes)
    if (
        _archive_bytes(
            ((ARTIFACT_BINDING_PATH, binding_bytes), (ARTIFACT_SIGNATURE_PATH, signature_bytes))
        )
        != snapshot
    ):
        raise ArtifactAdmissionError("artifact binding container bytes are not canonical")
    return InspectedArtifactBinding(
        binding_bytes=binding_bytes,
        signature=signature,
    )


def _write_binding(path: str, payload: dict[str, Any], signature: bytes, *, force: bool) -> str:
    if len(signature) != 64:
        raise ArtifactAdmissionError("Ed25519 signer returned a non-canonical signature length")
    binding_bytes = _canonical_json(payload)
    if len(binding_bytes) > MAX_ARTIFACT_BINDING_BYTES:
        raise ArtifactAdmissionError("canonical artifact binding exceeds its size limit")
    signature_bytes = base64.b64encode(signature)
    if len(signature_bytes) != 88:
        raise ArtifactAdmissionError("artifact binding signature did not encode to 88 base64 bytes")
    archive_bytes = _archive_bytes(
        ((ARTIFACT_BINDING_PATH, binding_bytes), (ARTIFACT_SIGNATURE_PATH, signature_bytes))
    )
    if len(archive_bytes) > MAX_ARTIFACT_BINDING_ARCHIVE_BYTES:
        raise ArtifactAdmissionError("generated artifact binding exceeds its archive limit")

    absolute_output = os.path.abspath(path)
    parent = os.path.dirname(absolute_output) or os.curdir
    if os.path.isdir(absolute_output):
        raise ArtifactAdmissionError(f"artifact binding output is a directory: {absolute_output}")
    os.makedirs(parent, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".evoguard-artifact-binding-", dir=parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(archive_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        if force:
            os.replace(temporary, absolute_output)
        else:
            try:
                os.link(temporary, absolute_output, follow_symlinks=False)
            except FileExistsError as exc:
                raise ArtifactAdmissionError(
                    f"refusing to overwrite existing artifact binding: {absolute_output}"
                ) from exc
            except OSError as exc:
                raise ArtifactAdmissionError(
                    "cannot publish artifact binding with atomic no-clobber semantics; "
                    "use a filesystem that supports hard links or pass force=True explicitly"
                ) from exc
            os.unlink(temporary)
        os.chmod(absolute_output, 0o644)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return absolute_output


@contextmanager
def _finalizer_bundle_snapshot(path: str) -> Iterator[tuple[str, str]]:
    """Freeze verified finalizer bytes before deriving their binding identity."""

    try:
        data = _read_regular_file(path, limit=MAX_ARCHIVE_BYTES, label="finalizer bundle")
    except EvidenceBundleError as exc:
        raise ArtifactAdmissionError(str(exc)) from exc
    with tempfile.TemporaryDirectory(prefix=".evoguard-artifact-finalizer-") as directory:
        descriptor, snapshot_path = tempfile.mkstemp(prefix="finalizer-", dir=directory)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(snapshot_path, 0o600)
        yield snapshot_path, hashlib.sha256(data).hexdigest()


def _verified_finalizer_descriptor(
    bundle_path: str,
    *,
    trusted_public_key_path: str,
    expected_source: Mapping[str, Any],
    expected_context: Mapping[str, Any],
) -> tuple[VerifiedFinalizedBundle, dict[str, Any]]:
    with _finalizer_bundle_snapshot(bundle_path) as (snapshot_path, bundle_sha256):
        try:
            verified = verify_finalized_bundle(
                snapshot_path,
                trusted_public_key_path=trusted_public_key_path,
                expected_source=expected_source,
                expected_context=expected_context,
            )
        except FinalizerHandoffError as exc:
            raise ArtifactAdmissionError(f"finalizer prerequisite is invalid: {exc}") from exc
    if verified.decision != "ALLOW":
        raise ArtifactAdmissionError("artifact admission requires a verified finalizer ALLOW")
    finalizer = {
        "bundle_sha256": bundle_sha256,
        "record_sha256": verified.bundle.manifest["record"]["sha256"],
        "key_id": verified.bundle.manifest["authentication"]["key_id"],
        "source": verified.handoff.source,
        "context": verified.handoff.context,
    }
    return verified, _validate_finalizer(finalizer)


def seal_artifact_admission(
    artifact_path: str,
    finalizer_bundle_path: str,
    output_path: str,
    *,
    trusted_finalizer_public_key_path: str,
    expected_finalizer_source: Mapping[str, Any],
    expected_finalizer_context: Mapping[str, Any],
    private_key_path: str,
    force: bool = False,
) -> SealedArtifactBinding:
    """Seal one file only after its finalizer ALLOW is externally verified.

    The caller must execute this in a protected post-build job which never
    executes candidate code.  This function intentionally makes no claim that
    the file came from a particular build, release, registry, or deployment.
    """

    _verified, finalizer = _verified_finalizer_descriptor(
        finalizer_bundle_path,
        trusted_public_key_path=trusted_finalizer_public_key_path,
        expected_source=expected_finalizer_source,
        expected_context=expected_finalizer_context,
    )
    subject = hash_regular_artifact(artifact_path)

    from evoom_guard.signing import _load_private_key_snapshot, _sign_bytes_with_key_id

    signing_key = _load_private_key_snapshot(private_key_path)
    if signing_key.key_id == finalizer["key_id"]:
        raise ArtifactAdmissionError(
            "artifact-admission signing key must differ from the finalizer key"
        )
    authentication = {
        "algorithm": "Ed25519",
        "key_id": signing_key.key_id,
        "purpose": ARTIFACT_BINDING_PURPOSE,
        "signature_path": ARTIFACT_SIGNATURE_PATH,
    }
    payload = {
        "format": ARTIFACT_BINDING_FORMAT,
        "decision": "ALLOW",
        "subject": subject.as_dict(),
        "finalizer": finalizer,
        "authentication": authentication,
    }
    canonical_payload = _canonical_json(payload)
    signature, key_id = _sign_bytes_with_key_id(
        ARTIFACT_BINDING_DOMAIN + canonical_payload, signing_key
    )
    if key_id != authentication["key_id"]:
        raise ArtifactAdmissionError("artifact binding signer key_id changed before publication")
    binding_path = _write_binding(output_path, payload, signature, force=force)
    inspected = inspect_artifact_binding(binding_path)
    if inspected.payload != payload:
        raise ArtifactAdmissionError("published artifact binding differs from the signed payload")
    return SealedArtifactBinding(binding_path=binding_path, payload=payload, subject=subject)


def verify_artifact_admission(
    binding_path: str,
    artifact_path: str,
    finalizer_bundle_path: str,
    *,
    trusted_public_key_path: str,
    trusted_finalizer_public_key_path: str,
    expected_finalizer_source: Mapping[str, Any],
    expected_finalizer_context: Mapping[str, Any],
) -> VerifiedArtifactBinding:
    """Authenticate a binding and independently match artifact/finalizer inputs."""

    inspected = inspect_artifact_binding(binding_path)
    from evoom_guard.signing import verify_bytes_with_key_id

    verified_signature, trusted_key_id = verify_bytes_with_key_id(
        ARTIFACT_BINDING_DOMAIN + inspected.binding_bytes,
        inspected.signature,
        trusted_public_key_path,
    )
    if inspected.payload["authentication"]["key_id"] != trusted_key_id:
        raise ArtifactAdmissionError(
            "artifact binding key_id does not match the externally trusted public key"
        )
    if not verified_signature:
        raise ArtifactAdmissionError(
            "artifact binding signature is invalid under the trusted public key"
        )

    verified_finalizer, finalizer = _verified_finalizer_descriptor(
        finalizer_bundle_path,
        trusted_public_key_path=trusted_finalizer_public_key_path,
        expected_source=expected_finalizer_source,
        expected_context=expected_finalizer_context,
    )
    if inspected.finalizer != finalizer:
        raise ArtifactAdmissionError(
            "artifact binding finalizer does not exactly match external finalizer evidence"
        )
    subject = hash_regular_artifact(artifact_path)
    if inspected.subject != subject.as_dict():
        raise ArtifactAdmissionError(
            "artifact binding subject does not exactly match the artifact file"
        )
    return VerifiedArtifactBinding(
        inspection=inspected,
        subject=subject,
        finalizer=verified_finalizer,
    )
