# -----------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Digest-only V2 artifact admission bound to a Trusted Finalizer ALLOW.

EVOGUARD_ARTIFACT_BINDING_V2 is deliberately separate from the released
regular-file-only V1 format. It binds exactly one immutable SHA-256 subject:
either a generic artifact digest or an OCI manifest-or-index digest. It also
binds the exact bytes and a caller-supplied identity label for an external
provenance document.

This module does not contact an OCI registry, parse a provenance statement,
verify a builder identity, prove a media type, or prove that the artifact was
built from the admitted source. The provenance field is an exact
identity-and-digest relation only. A protected, provider-specific verifier is
still required before this record may support a release, deployment, SLSA, or
build-provenance claim.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import os
import re
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

ARTIFACT_DIGEST_BINDING_FORMAT = "EVOGUARD_ARTIFACT_BINDING_V2"
ARTIFACT_DIGEST_BINDING_DOMAIN = ARTIFACT_DIGEST_BINDING_FORMAT.encode("ascii") + b"\0"
ARTIFACT_DIGEST_BINDING_PURPOSE = "evoguard-artifact-digest-admission"
ARTIFACT_DIGEST_BINDING_PATH = "binding.json"
ARTIFACT_DIGEST_SIGNATURE_PATH = "binding.sig"
OPAQUE_PROVENANCE_REFERENCE_FORMAT = "EVOGUARD_OPAQUE_PROVENANCE_REFERENCE_V1"

ARTIFACT_DIGEST_SUBJECT_KINDS = frozenset(
    {
        "artifact-sha256",
        "oci-manifest-or-index",
    }
)

MAX_ARTIFACT_DIGEST_BINDING_BYTES = 128 * 1024
MAX_ARTIFACT_DIGEST_BINDING_ARCHIVE_BYTES = MAX_ARTIFACT_DIGEST_BINDING_BYTES + 4 * 1024
MAX_PROVENANCE_REFERENCE_BYTES = 8 * 1024 * 1024
MAX_PROVENANCE_IDENTITY_CHARS = 512

_BINDING_KEYS = {
    "format",
    "decision",
    "subject",
    "provenance_reference",
    "finalizer",
    "authentication",
}
_SUBJECT_KEYS = {"kind", "digest"}
_PROVENANCE_REFERENCE_KEYS = {"format", "identity", "sha256", "size"}
_FINALIZER_KEYS = {"bundle_sha256", "record_sha256", "key_id", "source", "context"}
_AUTHENTICATION_KEYS = {"algorithm", "key_id", "purpose", "signature_path"}
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SHA256_WITH_ALGORITHM = re.compile(r"sha256:[0-9a-f]{64}\Z")
_KEY_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")


class ArtifactDigestAdmissionError(ValueError):
    """A V2 artifact-digest binding is malformed, unauthenticated, or replayed."""


@dataclass(frozen=True)
class ArtifactDigestSubject:
    """One immutable digest subject, with no mutable registry/tag authority."""

    kind: str
    digest: str

    def as_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "digest": self.digest}


@dataclass(frozen=True)
class OpaqueProvenanceReference:
    """Exact opaque provenance bytes plus an external caller-provided identity."""

    identity: str
    sha256: str
    size: int

    def as_dict(self) -> dict[str, object]:
        return {
            "format": OPAQUE_PROVENANCE_REFERENCE_FORMAT,
            "identity": self.identity,
            "sha256": self.sha256,
            "size": self.size,
        }


@dataclass(frozen=True)
class InspectedArtifactDigestBinding:
    """A canonical V2 container after structural checks only."""

    binding_bytes: bytes
    signature: bytes

    @property
    def payload(self) -> dict[str, Any]:
        try:
            return _validate_payload(
                _load_json_object(self.binding_bytes, "artifact digest binding")
            )
        except EvidenceBundleError as exc:
            raise ArtifactDigestAdmissionError(
                f"invalid artifact digest binding: {exc}"
            ) from exc

    @property
    def subject(self) -> dict[str, str]:
        value = self.payload["subject"]
        return dict(value) if isinstance(value, dict) else {}

    @property
    def provenance_reference(self) -> dict[str, object]:
        value = self.payload["provenance_reference"]
        return dict(value) if isinstance(value, dict) else {}

    @property
    def finalizer(self) -> dict[str, Any]:
        value = self.payload["finalizer"]
        return dict(value) if isinstance(value, dict) else {}


@dataclass(frozen=True)
class SealedArtifactDigestBinding:
    """One newly signed V2 immutable-digest admission binding."""

    binding_path: str
    payload: dict[str, Any]
    subject: ArtifactDigestSubject
    provenance_reference: OpaqueProvenanceReference


@dataclass(frozen=True)
class VerifiedArtifactDigestBinding:
    """A V2 binding with external subject, provenance, and finalizer matches."""

    inspection: InspectedArtifactDigestBinding
    subject: ArtifactDigestSubject
    provenance_reference: OpaqueProvenanceReference
    finalizer: VerifiedFinalizedBundle


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ArtifactDigestAdmissionError(
            f"{label} keys are not canonical "
            f"(missing={sorted(expected - actual)}, unknown={sorted(actual - expected)})"
        )


def _bounded_identity(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_PROVENANCE_IDENTITY_CHARS:
        raise ArtifactDigestAdmissionError(
            "provenance reference identity must be a non-empty Unicode string of at most "
            f"{MAX_PROVENANCE_IDENTITY_CHARS} characters"
        )
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ArtifactDigestAdmissionError(
            "provenance reference identity must not contain an unpaired surrogate"
        ) from exc
    if any(ord(character) < 0x20 for character in value):
        raise ArtifactDigestAdmissionError(
            "provenance reference identity must not contain control characters"
        )
    return value


def artifact_digest_subject(kind: str, digest: str) -> ArtifactDigestSubject:
    """Validate one exact V2 subject.

    oci-manifest-or-index describes only the caller's immutable OCI digest
    expectation. This function does not fetch the digest or inspect its media
    type, registry, repository, tag, or content.
    """

    if kind not in ARTIFACT_DIGEST_SUBJECT_KINDS:
        choices = ", ".join(sorted(ARTIFACT_DIGEST_SUBJECT_KINDS))
        raise ArtifactDigestAdmissionError(
            f"artifact digest subject.kind must be one of: {choices}"
        )
    if _SHA256_WITH_ALGORITHM.fullmatch(digest) is None:
        raise ArtifactDigestAdmissionError(
            "artifact digest subject.digest must be an exact lowercase sha256:<64-hex> digest"
        )
    return ArtifactDigestSubject(kind=kind, digest=digest)


def _validate_subject(value: Mapping[str, Any]) -> ArtifactDigestSubject:
    subject = dict(value)
    _require_exact_keys(subject, _SUBJECT_KEYS, "artifact digest subject")
    kind = subject.get("kind")
    digest = subject.get("digest")
    if not isinstance(kind, str) or not isinstance(digest, str):
        raise ArtifactDigestAdmissionError(
            "artifact digest subject.kind and digest must be strings"
        )
    return artifact_digest_subject(kind, digest)


def provenance_reference_from_file(path: str, identity: str) -> OpaqueProvenanceReference:
    """Hash one bounded, stable provenance file without interpreting its content.

    A matching digest proves only that the same bytes were supplied at seal and
    verification time. It does not validate a SLSA statement, signature,
    builder, predicate, or relationship to source.
    """

    checked_identity = _bounded_identity(identity)
    try:
        data = _read_regular_file(
            path,
            limit=MAX_PROVENANCE_REFERENCE_BYTES,
            label="provenance reference",
        )
    except EvidenceBundleError as exc:
        raise ArtifactDigestAdmissionError(str(exc)) from exc
    return OpaqueProvenanceReference(
        identity=checked_identity,
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
    )


def _validate_provenance_reference(value: Mapping[str, Any]) -> OpaqueProvenanceReference:
    reference = dict(value)
    _require_exact_keys(
        reference,
        _PROVENANCE_REFERENCE_KEYS,
        "artifact digest provenance reference",
    )
    if reference.get("format") != OPAQUE_PROVENANCE_REFERENCE_FORMAT:
        raise ArtifactDigestAdmissionError(
            "artifact digest provenance reference format is unsupported"
        )
    identity = _bounded_identity(reference.get("identity"))
    digest = reference.get("sha256")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise ArtifactDigestAdmissionError(
            "artifact digest provenance reference sha256 must be a lowercase SHA-256 digest"
        )
    size = reference.get("size")
    if type(size) is not int or size < 0 or size > MAX_PROVENANCE_REFERENCE_BYTES:
        raise ArtifactDigestAdmissionError(
            "artifact digest provenance reference size must be an integer from 0 through "
            f"{MAX_PROVENANCE_REFERENCE_BYTES}"
        )
    return OpaqueProvenanceReference(identity=identity, sha256=digest, size=size)


def _validate_finalizer(value: Mapping[str, Any]) -> dict[str, Any]:
    finalizer = dict(value)
    _require_exact_keys(finalizer, _FINALIZER_KEYS, "artifact digest binding finalizer")
    for field in ("bundle_sha256", "record_sha256"):
        digest = finalizer.get(field)
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise ArtifactDigestAdmissionError(
                f"artifact digest binding finalizer.{field} must be a lowercase SHA-256 digest"
            )
    key_id = finalizer.get("key_id")
    if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
        raise ArtifactDigestAdmissionError(
            "artifact digest binding finalizer.key_id must be sha256:<lowercase DER-SPKI digest>"
        )
    source = finalizer.get("source")
    context = finalizer.get("context")
    if not isinstance(source, dict) or not isinstance(context, dict):
        raise ArtifactDigestAdmissionError(
            "artifact digest binding finalizer.source and context must be objects"
        )
    try:
        verified_source = _validate_source(source)
        verified_context = validate_evidence_context(context, verdict=None)
        _validate_source_context(verified_source, verified_context)
    except (EvidenceBundleError, FinalizerHandoffError) as exc:
        raise ArtifactDigestAdmissionError(
            f"invalid artifact digest binding finalizer: {exc}"
        ) from exc
    return {
        "bundle_sha256": finalizer["bundle_sha256"],
        "record_sha256": finalizer["record_sha256"],
        "key_id": finalizer["key_id"],
        "source": verified_source,
        "context": verified_context,
    }


def _validate_authentication(value: Mapping[str, Any]) -> dict[str, str]:
    authentication = dict(value)
    _require_exact_keys(
        authentication,
        _AUTHENTICATION_KEYS,
        "artifact digest binding authentication",
    )
    if authentication.get("algorithm") != "Ed25519":
        raise ArtifactDigestAdmissionError(
            "artifact digest binding authentication.algorithm must be Ed25519"
        )
    if authentication.get("purpose") != ARTIFACT_DIGEST_BINDING_PURPOSE:
        raise ArtifactDigestAdmissionError(
            "artifact digest binding authentication.purpose must be "
            f"{ARTIFACT_DIGEST_BINDING_PURPOSE!r}"
        )
    if authentication.get("signature_path") != ARTIFACT_DIGEST_SIGNATURE_PATH:
        raise ArtifactDigestAdmissionError(
            "artifact digest binding authentication.signature_path must be "
            f"{ARTIFACT_DIGEST_SIGNATURE_PATH!r}"
        )
    key_id = authentication.get("key_id")
    if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
        raise ArtifactDigestAdmissionError(
            "artifact digest binding authentication.key_id must be "
            "sha256:<lowercase DER-SPKI digest>"
        )
    return authentication


def _validate_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(value)
    _require_exact_keys(payload, _BINDING_KEYS, "artifact digest binding")
    if payload.get("format") != ARTIFACT_DIGEST_BINDING_FORMAT:
        raise ArtifactDigestAdmissionError(
            f"unsupported artifact digest binding format: {payload.get('format')!r}"
        )
    if payload.get("decision") != "ALLOW":
        raise ArtifactDigestAdmissionError("artifact digest binding decision must be ALLOW")
    subject = payload.get("subject")
    provenance_reference = payload.get("provenance_reference")
    finalizer = payload.get("finalizer")
    authentication = payload.get("authentication")
    if (
        not isinstance(subject, dict)
        or not isinstance(provenance_reference, dict)
        or not isinstance(finalizer, dict)
        or not isinstance(authentication, dict)
    ):
        raise ArtifactDigestAdmissionError(
            "artifact digest binding subject, provenance_reference, finalizer, and "
            "authentication must be objects"
        )
    verified_subject = _validate_subject(subject)
    verified_provenance_reference = _validate_provenance_reference(provenance_reference)
    verified_finalizer = _validate_finalizer(finalizer)
    verified_authentication = _validate_authentication(authentication)
    if verified_authentication["key_id"] == verified_finalizer["key_id"]:
        raise ArtifactDigestAdmissionError(
            "artifact-digest-admission authentication key must differ from the finalizer key"
        )
    return {
        "format": ARTIFACT_DIGEST_BINDING_FORMAT,
        "decision": "ALLOW",
        "subject": verified_subject.as_dict(),
        "provenance_reference": verified_provenance_reference.as_dict(),
        "finalizer": verified_finalizer,
        "authentication": verified_authentication,
    }


def _decode_signature(data: bytes) -> bytes:
    if len(data) != 88 or any(byte > 0x7F for byte in data):
        raise ArtifactDigestAdmissionError(
            "artifact digest binding signature must be 88 ASCII base64 bytes"
        )
    try:
        signature = base64.b64decode(data, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ArtifactDigestAdmissionError(
            "artifact digest binding signature is not canonical base64"
        ) from exc
    if len(signature) != 64 or base64.b64encode(signature) != data:
        raise ArtifactDigestAdmissionError(
            "artifact digest binding signature is not one canonical Ed25519 signature"
        )
    return signature


def _read_binding_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    limit: int,
) -> bytes:
    if info.file_size > limit:
        raise ArtifactDigestAdmissionError(
            f"artifact digest binding member exceeds its limit: {info.filename}"
        )
    try:
        with archive.open(info, "r") as handle:
            data = handle.read(limit + 1)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise ArtifactDigestAdmissionError(
            f"cannot read artifact digest binding member {info.filename}: {exc}"
        ) from exc
    if len(data) > limit or len(data) != info.file_size:
        raise ArtifactDigestAdmissionError(
            f"artifact digest binding member size is inconsistent: {info.filename}"
        )
    return data


def inspect_artifact_digest_binding(path: str) -> InspectedArtifactDigestBinding:
    """Inspect canonical V2 bytes without treating any embedded value as trusted."""

    try:
        snapshot = _read_regular_file(
            path,
            limit=MAX_ARTIFACT_DIGEST_BINDING_ARCHIVE_BYTES,
            label="artifact digest binding",
        )
    except EvidenceBundleError as exc:
        raise ArtifactDigestAdmissionError(str(exc)) from exc
    try:
        declared_entry_count = _preflight_zip(snapshot)
    except EvidenceBundleError as exc:
        raise ArtifactDigestAdmissionError(str(exc)) from exc
    if declared_entry_count != 2:
        raise ArtifactDigestAdmissionError(
            "artifact digest binding must contain exactly two archive members"
        )
    try:
        archive = zipfile.ZipFile(io.BytesIO(snapshot), "r")
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise ArtifactDigestAdmissionError(
            f"cannot parse artifact digest binding: {exc}"
        ) from exc
    with archive:
        if archive.comment:
            raise ArtifactDigestAdmissionError(
                "artifact digest binding archive comment is not allowed"
            )
        infos = archive.infolist()
        if [info.filename for info in infos] != [
            ARTIFACT_DIGEST_BINDING_PATH,
            ARTIFACT_DIGEST_SIGNATURE_PATH,
        ]:
            raise ArtifactDigestAdmissionError(
                "artifact digest binding archive members are not canonical"
            )
        for info in infos:
            try:
                _validate_member_metadata(info)
            except EvidenceBundleError as exc:
                raise ArtifactDigestAdmissionError(str(exc)) from exc
        binding_bytes = _read_binding_member(
            archive,
            infos[0],
            limit=MAX_ARTIFACT_DIGEST_BINDING_BYTES,
        )
        signature_bytes = _read_binding_member(archive, infos[1], limit=88)
    try:
        payload = _load_json_object(binding_bytes, "artifact digest binding")
        verified_payload = _validate_payload(payload)
        canonical = _canonical_json(verified_payload)
    except EvidenceBundleError as exc:
        raise ArtifactDigestAdmissionError(
            f"invalid artifact digest binding: {exc}"
        ) from exc
    if canonical != binding_bytes:
        raise ArtifactDigestAdmissionError("artifact digest binding is not canonical JSON")
    signature = _decode_signature(signature_bytes)
    if (
        _archive_bytes(
            (
                (ARTIFACT_DIGEST_BINDING_PATH, binding_bytes),
                (ARTIFACT_DIGEST_SIGNATURE_PATH, signature_bytes),
            )
        )
        != snapshot
    ):
        raise ArtifactDigestAdmissionError(
            "artifact digest binding container bytes are not canonical"
        )
    return InspectedArtifactDigestBinding(
        binding_bytes=binding_bytes,
        signature=signature,
    )


def _write_binding(path: str, payload: dict[str, Any], signature: bytes, *, force: bool) -> str:
    if len(signature) != 64:
        raise ArtifactDigestAdmissionError(
            "Ed25519 signer returned a non-canonical signature length"
        )
    binding_bytes = _canonical_json(payload)
    if len(binding_bytes) > MAX_ARTIFACT_DIGEST_BINDING_BYTES:
        raise ArtifactDigestAdmissionError(
            "canonical artifact digest binding exceeds its size limit"
        )
    signature_bytes = base64.b64encode(signature)
    if len(signature_bytes) != 88:
        raise ArtifactDigestAdmissionError(
            "artifact digest binding signature did not encode to 88 base64 bytes"
        )
    archive_bytes = _archive_bytes(
        (
            (ARTIFACT_DIGEST_BINDING_PATH, binding_bytes),
            (ARTIFACT_DIGEST_SIGNATURE_PATH, signature_bytes),
        )
    )
    if len(archive_bytes) > MAX_ARTIFACT_DIGEST_BINDING_ARCHIVE_BYTES:
        raise ArtifactDigestAdmissionError(
            "generated artifact digest binding exceeds its archive limit"
        )

    absolute_output = os.path.abspath(path)
    parent = os.path.dirname(absolute_output) or os.curdir
    if os.path.isdir(absolute_output):
        raise ArtifactDigestAdmissionError(
            f"artifact digest binding output is a directory: {absolute_output}"
        )
    os.makedirs(parent, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".evoguard-artifact-digest-binding-", dir=parent)
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
                raise ArtifactDigestAdmissionError(
                    "refusing to overwrite existing artifact digest binding: "
                    f"{absolute_output}"
                ) from exc
            except OSError as exc:
                raise ArtifactDigestAdmissionError(
                    "cannot publish artifact digest binding with atomic no-clobber "
                    "semantics; use a filesystem that supports hard links or pass "
                    "force=True explicitly"
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
        raise ArtifactDigestAdmissionError(str(exc)) from exc
    with tempfile.TemporaryDirectory(prefix=".evoguard-artifact-digest-finalizer-") as directory:
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
            raise ArtifactDigestAdmissionError(
                f"finalizer prerequisite is invalid: {exc}"
            ) from exc
    if verified.decision != "ALLOW":
        raise ArtifactDigestAdmissionError(
            "artifact digest admission requires a verified finalizer ALLOW"
        )
    finalizer = {
        "bundle_sha256": bundle_sha256,
        "record_sha256": verified.bundle.manifest["record"]["sha256"],
        "key_id": verified.bundle.manifest["authentication"]["key_id"],
        "source": verified.handoff.source,
        "context": verified.handoff.context,
    }
    return verified, _validate_finalizer(finalizer)


def seal_artifact_digest_admission(
    subject_kind: str,
    subject_digest: str,
    provenance_path: str,
    provenance_identity: str,
    finalizer_bundle_path: str,
    output_path: str,
    *,
    trusted_finalizer_public_key_path: str,
    expected_finalizer_source: Mapping[str, Any],
    expected_finalizer_context: Mapping[str, Any],
    private_key_path: str,
    force: bool = False,
) -> SealedArtifactDigestBinding:
    """Seal one immutable digest after an external finalizer ALLOW.

    The protected caller must derive the digest and obtain the provenance file
    from its own trusted build/release boundary. This function only binds those
    exact external inputs; it does not authenticate registry or provenance
    semantics.
    """

    _verified, finalizer = _verified_finalizer_descriptor(
        finalizer_bundle_path,
        trusted_public_key_path=trusted_finalizer_public_key_path,
        expected_source=expected_finalizer_source,
        expected_context=expected_finalizer_context,
    )
    subject = artifact_digest_subject(subject_kind, subject_digest)
    provenance_reference = provenance_reference_from_file(provenance_path, provenance_identity)

    from evoom_guard.signing import _load_private_key_snapshot, _sign_bytes_with_key_id

    signing_key = _load_private_key_snapshot(private_key_path)
    if signing_key.key_id == finalizer["key_id"]:
        raise ArtifactDigestAdmissionError(
            "artifact-digest-admission signing key must differ from the finalizer key"
        )
    authentication = {
        "algorithm": "Ed25519",
        "key_id": signing_key.key_id,
        "purpose": ARTIFACT_DIGEST_BINDING_PURPOSE,
        "signature_path": ARTIFACT_DIGEST_SIGNATURE_PATH,
    }
    payload = {
        "format": ARTIFACT_DIGEST_BINDING_FORMAT,
        "decision": "ALLOW",
        "subject": subject.as_dict(),
        "provenance_reference": provenance_reference.as_dict(),
        "finalizer": finalizer,
        "authentication": authentication,
    }
    canonical_payload = _canonical_json(payload)
    signature, key_id = _sign_bytes_with_key_id(
        ARTIFACT_DIGEST_BINDING_DOMAIN + canonical_payload,
        signing_key,
    )
    if key_id != authentication["key_id"]:
        raise ArtifactDigestAdmissionError(
            "artifact digest binding signer key_id changed before publication"
        )
    binding_path = _write_binding(output_path, payload, signature, force=force)
    inspected = inspect_artifact_digest_binding(binding_path)
    if inspected.payload != payload:
        raise ArtifactDigestAdmissionError(
            "published artifact digest binding differs from the signed payload"
        )
    return SealedArtifactDigestBinding(
        binding_path=binding_path,
        payload=payload,
        subject=subject,
        provenance_reference=provenance_reference,
    )


def verify_artifact_digest_admission(
    binding_path: str,
    subject_kind: str,
    subject_digest: str,
    provenance_path: str,
    provenance_identity: str,
    finalizer_bundle_path: str,
    *,
    trusted_public_key_path: str,
    trusted_finalizer_public_key_path: str,
    expected_finalizer_source: Mapping[str, Any],
    expected_finalizer_context: Mapping[str, Any],
) -> VerifiedArtifactDigestBinding:
    """Authenticate V2 against externally supplied finalizer, subject, and provenance.

    The expected digest and provenance bytes are caller inputs, never values
    recovered from the binding as a trust root. Any mismatch is rejected.
    """

    inspected = inspect_artifact_digest_binding(binding_path)
    from evoom_guard.signing import verify_bytes_with_key_id

    verified_signature, trusted_key_id = verify_bytes_with_key_id(
        ARTIFACT_DIGEST_BINDING_DOMAIN + inspected.binding_bytes,
        inspected.signature,
        trusted_public_key_path,
    )
    if inspected.payload["authentication"]["key_id"] != trusted_key_id:
        raise ArtifactDigestAdmissionError(
            "artifact digest binding key_id does not match the externally trusted public key"
        )
    if not verified_signature:
        raise ArtifactDigestAdmissionError(
            "artifact digest binding signature is invalid under the trusted public key"
        )

    subject = artifact_digest_subject(subject_kind, subject_digest)
    verified_finalizer, finalizer = _verified_finalizer_descriptor(
        finalizer_bundle_path,
        trusted_public_key_path=trusted_finalizer_public_key_path,
        expected_source=expected_finalizer_source,
        expected_context=expected_finalizer_context,
    )
    if inspected.finalizer != finalizer:
        raise ArtifactDigestAdmissionError(
            "artifact digest binding finalizer does not exactly match external finalizer evidence"
        )
    provenance_reference = provenance_reference_from_file(provenance_path, provenance_identity)
    if inspected.subject != subject.as_dict():
        raise ArtifactDigestAdmissionError(
            "artifact digest binding subject does not exactly match the external digest"
        )
    if inspected.provenance_reference != provenance_reference.as_dict():
        raise ArtifactDigestAdmissionError(
            "artifact digest binding provenance reference does not exactly match "
            "external provenance bytes and identity"
        )
    return VerifiedArtifactDigestBinding(
        inspection=inspected,
        subject=subject,
        provenance_reference=provenance_reference,
        finalizer=verified_finalizer,
    )
