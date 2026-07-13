# -----------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Deterministic, bounded envelopes for portable Guard evidence.

An evidence bundle does not make runtime observations true. It preserves the
exact verdict bytes and optional supporting material in one content-addressed
container so a separate consumer can check record semantics, signatures, and
whatever material bindings it has enough input to recompute.

The format deliberately uses stored ZIP members, canonical JSON, fixed metadata,
strict path rules, and small hard limits. Verification never extracts members to
the filesystem, so path traversal and symlink archive entries are rejected rather
than "sanitised" after the fact.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import stat
import struct
import tempfile
import zipfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from evoom_guard.strict_json import strict_json_loads

BUNDLE_FORMAT = "EVOGUARD_EVIDENCE_BUNDLE_V1"
MANIFEST_PATH = "bundle.json"
SIGNATURE_PATH = "bundle.sig"
VERDICT_PATH = "record/verdict.json"
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
SIGNING_DOMAIN = BUNDLE_FORMAT.encode("ascii") + b"\0"
SIGNATURE_PURPOSE = "evoguard-evidence-envelope"

MAX_MANIFEST_BYTES = 1 * 1024 * 1024
MAX_VERDICT_BYTES = 8 * 1024 * 1024
MAX_MATERIAL_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = MAX_TOTAL_BYTES + MAX_MANIFEST_BYTES + (1 * 1024 * 1024)
MAX_MATERIALS = 32
MAX_ARCHIVE_MEMBERS = MAX_MATERIALS + 3
MAX_CENTRAL_DIRECTORY_BYTES = 64 * 1024

_ROLE = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_KEY_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_MANIFEST_KEYS = {"format", "context", "authentication", "record", "materials"}
_AUTHENTICATION_KEYS = {"algorithm", "key_id", "purpose", "signature_path"}
_CONTEXT_KEYS = {
    "repository",
    "repository_id",
    "run_id",
    "run_attempt",
    "base_sha",
    "head_sha",
    "base_tree_sha",
    "head_tree_sha",
    "candidate_sha256",
    "policy_sha256",
    "verifier_pack_sha256",
    "guard_artifact_sha256",
}
_RECORD_KEYS = {"path", "sha256", "size", "schema_version", "tool", "tool_version"}
_MATERIAL_KEYS = {"role", "path", "sha256", "size"}


class EvidenceBundleError(ValueError):
    """The bundle is unsafe, malformed, inconsistent, or exceeds its limits."""


@dataclass(frozen=True)
class EvidenceMaterial:
    """One explicitly supplied regular file to include under a semantic role."""

    role: str
    source_path: str


@dataclass(frozen=True)
class VerifiedMaterial:
    role: str
    archive_path: str
    sha256: str
    size: int
    data: bytes


@dataclass(frozen=True)
class InspectedBundle:
    """Canonical bundle bytes after structural/content checks only.

    Parsed dictionaries are returned as fresh values so mutating a caller-owned
    view cannot change what later signature, context, or semantic checks read.
    """

    manifest_bytes: bytes
    signature: bytes
    verdict_bytes: bytes
    materials: tuple[VerifiedMaterial, ...]

    @property
    def manifest(self) -> dict[str, Any]:
        return _load_json_object(self.manifest_bytes, "bundle manifest")

    @property
    def verdict(self) -> dict[str, Any]:
        return _load_json_object(self.verdict_bytes, "bundled verdict")

    def materials_for(self, role: str) -> tuple[VerifiedMaterial, ...]:
        return tuple(item for item in self.materials if item.role == role)


@dataclass(frozen=True)
class AuthenticatedBundle:
    """An inspection authenticated by an external key and exact context."""

    inspection: InspectedBundle

    @property
    def manifest(self) -> dict[str, Any]:
        return self.inspection.manifest

    @property
    def verdict(self) -> dict[str, Any]:
        return self.inspection.verdict


@dataclass(frozen=True)
class VerifiedBundle:
    """A fully authenticated bundle whose verdict semantics also passed."""

    authenticated: AuthenticatedBundle
    record_report: dict[str, Any]

    @property
    def inspection(self) -> InspectedBundle:
        return self.authenticated.inspection

    @property
    def manifest(self) -> dict[str, Any]:
        return self.inspection.manifest

    @property
    def verdict(self) -> dict[str, Any]:
        return self.inspection.verdict

    @property
    def materials(self) -> tuple[VerifiedMaterial, ...]:
        return self.inspection.materials

    def materials_for(self, role: str) -> tuple[VerifiedMaterial, ...]:
        return self.inspection.materials_for(role)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: dict[str, Any]) -> bytes:
    try:
        encoded = (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("ascii")
        strict_json_loads(encoded.decode("ascii"))
        return encoded
    except (RecursionError, UnicodeError, ValueError) as exc:
        raise EvidenceBundleError(f"value cannot be encoded as canonical JSON: {exc}") from exc


def _load_json_object(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = strict_json_loads(data.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise EvidenceBundleError(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceBundleError(f"{label} must be a JSON object")
    return value


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _read_regular_file(path: str, *, limit: int, label: str) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise EvidenceBundleError(f"cannot inspect {label} {path!r}: {exc}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or _is_reparse_point(before)
        or not stat.S_ISREG(before.st_mode)
    ):
        raise EvidenceBundleError(f"{label} must be a regular non-symlink file: {path!r}")
    if before.st_size > limit:
        raise EvidenceBundleError(f"{label} exceeds the {limit}-byte limit: {path!r}")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EvidenceBundleError(f"cannot open {label} {path!r}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _is_reparse_point(opened):
            raise EvidenceBundleError(f"{label} changed to a non-regular file: {path!r}")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise EvidenceBundleError(f"{label} changed while it was being opened: {path!r}")
        if opened.st_size > limit:
            raise EvidenceBundleError(f"{label} exceeds the {limit}-byte limit: {path!r}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(limit + 1)
        after = os.fstat(descriptor)
        identity_before = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_after != identity_before:
            raise EvidenceBundleError(f"{label} changed while it was being read: {path!r}")
    finally:
        os.close(descriptor)
    if len(data) > limit:
        raise EvidenceBundleError(f"{label} exceeded the {limit}-byte limit while reading")
    if len(data) != opened.st_size:
        raise EvidenceBundleError(f"{label} size changed while it was being read: {path!r}")
    return data


def _require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        unknown = sorted(set(value) - expected)
        raise EvidenceBundleError(
            f"{label} keys are not canonical (missing={missing}, unknown={unknown})"
        )


def _required_bounded_string(value: object, *, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise EvidenceBundleError(
            f"{label} must be a non-empty Unicode string of at most {maximum} characters"
        )
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise EvidenceBundleError(f"{label} must not contain an unpaired surrogate") from exc
    if any(ord(character) < 0x20 for character in value):
        raise EvidenceBundleError(f"{label} must not contain control characters")
    return value


def _validate_context(
    value: Mapping[str, Any],
    *,
    verdict: dict[str, Any] | None,
) -> dict[str, Any]:
    context = dict(value)
    _require_exact_keys(context, _CONTEXT_KEYS, "bundle context")
    _required_bounded_string(context.get("repository"), label="context.repository", maximum=512)
    _required_bounded_string(
        context.get("repository_id"), label="context.repository_id", maximum=256
    )
    _required_bounded_string(context.get("run_id"), label="context.run_id", maximum=256)
    run_attempt = context.get("run_attempt")
    if type(run_attempt) is not int or run_attempt < 1 or run_attempt > 2_147_483_647:
        raise EvidenceBundleError(
            "context.run_attempt must be an integer from 1 through 2147483647"
        )

    for field in ("base_sha", "head_sha", "base_tree_sha", "head_tree_sha"):
        item = context.get(field)
        if item is not None and (not isinstance(item, str) or _GIT_SHA.fullmatch(item) is None):
            raise EvidenceBundleError(
                f"context.{field} must be null or a lowercase 40/64-character Git digest"
            )
    for field in ("candidate_sha256", "policy_sha256", "guard_artifact_sha256"):
        item = context.get(field)
        if not isinstance(item, str) or _SHA256.fullmatch(item) is None:
            raise EvidenceBundleError(f"context.{field} must be a lowercase SHA-256 digest")
    pack_digest = context.get("verifier_pack_sha256")
    if pack_digest is not None and (
        not isinstance(pack_digest, str) or _SHA256.fullmatch(pack_digest) is None
    ):
        raise EvidenceBundleError(
            "context.verifier_pack_sha256 must be null or a lowercase SHA-256 digest"
        )

    if verdict is not None:
        attestation = verdict.get("attestation")
        if not isinstance(attestation, dict):
            raise EvidenceBundleError("verdict.attestation must be an object")
        bindings = {
            "candidate_sha256": "candidate_sha256",
            "policy_sha256": "policy_sha256",
            "verifier_pack_sha256": "verifier_pack_sha256",
        }
        for context_key, record_key in bindings.items():
            if context[context_key] != attestation.get(record_key):
                raise EvidenceBundleError(
                    f"context.{context_key} does not match verdict.attestation.{record_key}"
                )
        for field in ("base_sha", "head_sha", "base_tree_sha", "head_tree_sha"):
            record_value = attestation.get(field)
            if record_value is not None and context[field] != record_value:
                raise EvidenceBundleError(
                    f"context.{field} does not match the non-null verdict attestation"
                )
    return context


def _validate_role(role: str) -> None:
    if not isinstance(role, str) or _ROLE.fullmatch(role) is None:
        raise EvidenceBundleError(
            "material role must match [a-z][a-z0-9_.-]{0,63}"
        )


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=ZIP_TIMESTAMP)
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.compress_type = zipfile.ZIP_STORED
    return info


def _archive_bytes(members: Iterable[tuple[str, bytes]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(
        output,
        "w",
        compression=zipfile.ZIP_STORED,
        allowZip64=False,
    ) as archive:
        for name, payload in members:
            archive.writestr(_zip_info(name), payload)
    return output.getvalue()


def _validate_authentication(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise EvidenceBundleError("bundle authentication must be an object")
    _require_exact_keys(value, _AUTHENTICATION_KEYS, "bundle authentication")
    if value.get("algorithm") != "Ed25519":
        raise EvidenceBundleError("bundle authentication algorithm must be Ed25519")
    if value.get("purpose") != SIGNATURE_PURPOSE:
        raise EvidenceBundleError(
            f"bundle authentication purpose must be {SIGNATURE_PURPOSE!r}"
        )
    if value.get("signature_path") != SIGNATURE_PATH:
        raise EvidenceBundleError(
            f"bundle authentication signature_path must be {SIGNATURE_PATH!r}"
        )
    key_id = value.get("key_id")
    if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
        raise EvidenceBundleError(
            "bundle authentication key_id must be sha256:<lowercase DER-SPKI digest>"
        )
    return value


def _record_manifest(verdict: dict[str, Any], payload: bytes) -> dict[str, Any]:
    schema_version = verdict.get("schema_version")
    tool = verdict.get("tool")
    tool_version = verdict.get("tool_version")
    if not all(isinstance(value, str) and value for value in (schema_version, tool, tool_version)):
        raise EvidenceBundleError(
            "verdict must contain non-empty schema_version, tool, and tool_version strings"
        )
    return {
        "path": VERDICT_PATH,
        "sha256": _sha256(payload),
        "size": len(payload),
        "schema_version": schema_version,
        "tool": tool,
        "tool_version": tool_version,
    }


def create_evidence_bundle(
    verdict_path: str,
    output_path: str,
    *,
    context: Mapping[str, Any],
    private_key_path: str,
    materials: Iterable[EvidenceMaterial] = (),
    force: bool = False,
    require_valid_record: bool = True,
) -> dict[str, Any]:
    """Create one deterministic, authenticated evidence bundle.

    Inputs are read as exact bytes. Semantic record verification is fail-closed
    by default; forensic tooling must opt out explicitly. Material order does not affect the archive;
    entries are sorted by role and content identity. Existing outputs are refused
    atomically unless ``force`` is explicit. The Ed25519 key belongs in a trusted
    post-run finalizer, never in the untrusted candidate job.
    """

    from evoom_guard.signing import (
        _load_private_key_snapshot,
        _sign_bytes_with_key_id,
    )

    verdict_bytes = _read_regular_file(
        verdict_path, limit=MAX_VERDICT_BYTES, label="verdict"
    )
    verdict = _load_json_object(verdict_bytes, "verdict")
    if require_valid_record:
        from evoom_guard.record_verifier import verify_record

        semantic_report = verify_record(verdict)
        if not semantic_report["ok"]:
            failed_checks = [
                item["id"]
                for item in semantic_report["checks"]
                if item["status"] == "fail"
            ]
            raise EvidenceBundleError(
                "verdict record is semantically invalid: " + ", ".join(failed_checks)
            )
    verified_context = _validate_context(context, verdict=verdict)

    logical_total = len(verdict_bytes)
    if logical_total > MAX_TOTAL_BYTES:
        raise EvidenceBundleError(
            f"bundle payload exceeds the {MAX_TOTAL_BYTES}-byte total limit"
        )

    material_rows: list[tuple[str, str, int, bytes]] = []
    for material in materials:
        if len(material_rows) >= MAX_MATERIALS:
            raise EvidenceBundleError(f"bundle permits at most {MAX_MATERIALS} materials")
        _validate_role(material.role)
        remaining = MAX_TOTAL_BYTES - logical_total
        data = _read_regular_file(
            material.source_path,
            limit=min(MAX_MATERIAL_BYTES, remaining),
            label=f"material {material.role!r}",
        )
        logical_total += len(data)
        material_rows.append((material.role, _sha256(data), len(data), data))

    material_rows.sort(key=lambda row: (row[0], row[1], row[2]))
    roles = [role for role, _digest, _size, _data in material_rows]
    if len(roles) != len(set(roles)):
        raise EvidenceBundleError("each evidence material role may appear at most once")
    identities = [(role, digest, size) for role, digest, size, _data in material_rows]
    if len(identities) != len(set(identities)):
        raise EvidenceBundleError("the same material role/content was supplied more than once")

    material_manifest: list[dict[str, Any]] = []
    archive_members: list[tuple[str, bytes]] = []
    for index, (role, digest, size, data) in enumerate(material_rows):
        archive_path = f"materials/{index:03d}-{role}"
        material_manifest.append(
            {"role": role, "path": archive_path, "sha256": digest, "size": size}
        )
        archive_members.append((archive_path, data))

    signing_key = _load_private_key_snapshot(private_key_path)
    authentication = {
        "algorithm": "Ed25519",
        "key_id": signing_key.key_id,
        "purpose": SIGNATURE_PURPOSE,
        "signature_path": SIGNATURE_PATH,
    }
    manifest = {
        "format": BUNDLE_FORMAT,
        "context": verified_context,
        "authentication": authentication,
        "record": _record_manifest(verdict, verdict_bytes),
        "materials": material_manifest,
    }
    manifest_bytes = _canonical_json(manifest)
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise EvidenceBundleError("canonical bundle manifest exceeds its size limit")
    signature, actual_key_id = _sign_bytes_with_key_id(
        SIGNING_DOMAIN + manifest_bytes,
        signing_key,
    )
    if actual_key_id != authentication["key_id"]:
        raise EvidenceBundleError("signer key_id changed before bundle publication")
    if len(signature) != 64:
        raise EvidenceBundleError("Ed25519 signer returned a non-canonical signature length")
    signature_bytes = base64.b64encode(signature)
    if len(signature_bytes) != 88:
        raise EvidenceBundleError("Ed25519 signature did not encode to 88 base64 bytes")

    absolute_output = os.path.abspath(output_path)
    parent = os.path.dirname(absolute_output) or os.curdir
    if os.path.isdir(absolute_output):
        raise EvidenceBundleError(f"evidence bundle output is a directory: {absolute_output}")
    os.makedirs(parent, exist_ok=True)

    descriptor, temporary = tempfile.mkstemp(prefix=".evoguard-bundle-", dir=parent)
    try:
        with os.fdopen(descriptor, "w+b") as raw:
            members = [
                (MANIFEST_PATH, manifest_bytes),
                (SIGNATURE_PATH, signature_bytes),
                (VERDICT_PATH, verdict_bytes),
                *archive_members,
            ]
            archive_payload = _archive_bytes(members)
            if len(archive_payload) > MAX_ARCHIVE_BYTES:
                raise EvidenceBundleError("generated evidence bundle exceeds its archive limit")
            raw.write(archive_payload)
            raw.flush()
            os.fsync(raw.fileno())
        if force:
            os.replace(temporary, absolute_output)
        else:
            try:
                os.link(temporary, absolute_output, follow_symlinks=False)
            except FileExistsError as exc:
                raise EvidenceBundleError(
                    f"refusing to overwrite existing evidence bundle: {absolute_output}"
                ) from exc
            except OSError as exc:
                raise EvidenceBundleError(
                    "cannot publish evidence bundle with atomic no-clobber semantics; "
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
    return manifest


def _safe_member_name(name: str) -> bool:
    if not name or "\\" in name or "\x00" in name or ":" in name:
        return False
    path = PurePosixPath(name)
    return (
        not path.is_absolute()
        and path.as_posix() == name
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _validate_member_metadata(info: zipfile.ZipInfo) -> None:
    if not _safe_member_name(info.filename):
        raise EvidenceBundleError(f"unsafe archive member path: {info.filename!r}")
    if info.flag_bits != 0:
        raise EvidenceBundleError(
            f"archive member general-purpose flags must be zero: {info.filename}"
        )
    if info.compress_type != zipfile.ZIP_STORED:
        raise EvidenceBundleError(f"compressed archive member is not allowed: {info.filename}")
    if info.extra or info.comment:
        raise EvidenceBundleError(f"archive member metadata must be empty: {info.filename}")
    mode = info.external_attr >> 16
    if info.create_system != 3 or stat.S_IFMT(mode) != stat.S_IFREG:
        raise EvidenceBundleError(f"archive member is not a canonical regular file: {info.filename}")
    if stat.S_IMODE(mode) != 0o644 or info.date_time != ZIP_TIMESTAMP:
        raise EvidenceBundleError(f"archive member metadata is not canonical: {info.filename}")


def _read_archive_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    limit: int,
) -> bytes:
    if info.file_size > limit:
        raise EvidenceBundleError(f"archive member exceeds its limit: {info.filename}")
    try:
        with archive.open(info, "r") as handle:
            data = handle.read(limit + 1)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise EvidenceBundleError(f"cannot read archive member {info.filename}: {exc}") from exc
    if len(data) > limit or len(data) != info.file_size:
        raise EvidenceBundleError(f"archive member size is inconsistent: {info.filename}")
    return data


def _preflight_zip(snapshot: bytes) -> int:
    """Bound the central directory before ``ZipFile`` allocates per-entry objects."""

    if len(snapshot) < 22 or snapshot[:4] != b"PK\x03\x04":
        raise EvidenceBundleError("evidence bundle is not a canonical ZIP archive")
    eocd_offset = len(snapshot) - 22
    try:
        (
            signature,
            disk_number,
            directory_disk,
            entries_on_disk,
            total_entries,
            directory_size,
            directory_offset,
            comment_size,
        ) = struct.unpack("<4s4H2LH", snapshot[eocd_offset:])
    except struct.error as exc:  # pragma: no cover - length is checked above
        raise EvidenceBundleError("evidence bundle has a truncated end record") from exc
    if signature != b"PK\x05\x06" or comment_size != 0:
        raise EvidenceBundleError(
            "evidence bundle must end at one comment-free ZIP end record"
        )
    if disk_number != 0 or directory_disk != 0 or entries_on_disk != total_entries:
        raise EvidenceBundleError("multi-disk evidence bundles are not allowed")
    if total_entries == 0 or total_entries > MAX_ARCHIVE_MEMBERS:
        raise EvidenceBundleError("evidence bundle has too many archive members")
    if directory_offset + directory_size != eocd_offset:
        raise EvidenceBundleError(
            "evidence bundle has a prefix, suffix, ZIP64 marker, or inconsistent directory"
        )
    if directory_size > MAX_CENTRAL_DIRECTORY_BYTES:
        raise EvidenceBundleError("evidence bundle central directory exceeds its size limit")
    if snapshot[directory_offset : directory_offset + 4] != b"PK\x01\x02":
        raise EvidenceBundleError("evidence bundle central directory is malformed")
    return total_entries


def _validate_digest_row(value: dict[str, Any], label: str) -> None:
    digest = value.get("sha256")
    size = value.get("size")
    path = value.get("path")
    if not isinstance(path, str) or not _safe_member_name(path):
        raise EvidenceBundleError(f"{label}.path is unsafe or missing")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise EvidenceBundleError(f"{label}.sha256 must be 64 lowercase hex characters")
    if type(size) is not int or size < 0:
        raise EvidenceBundleError(f"{label}.size must be a non-negative integer")


def inspect_evidence_bundle(path: str) -> InspectedBundle:
    """Verify structural/content consistency without making an authenticity claim."""

    snapshot = _read_regular_file(
        path,
        limit=MAX_ARCHIVE_BYTES,
        label="evidence bundle",
    )
    declared_entry_count = _preflight_zip(snapshot)
    try:
        archive = zipfile.ZipFile(io.BytesIO(snapshot), "r")
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise EvidenceBundleError(f"cannot parse evidence bundle: {exc}") from exc
    with archive:
        if archive.comment:
            raise EvidenceBundleError("archive comment is not allowed")
        infos = archive.infolist()
        if len(infos) != declared_entry_count:
            raise EvidenceBundleError("ZIP end-record entry count is inconsistent")
        if not infos or infos[0].filename != MANIFEST_PATH:
            raise EvidenceBundleError("bundle.json must be the first archive member")
        if len(infos) > MAX_ARCHIVE_MEMBERS:
            raise EvidenceBundleError("evidence bundle has too many archive members")
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise EvidenceBundleError("duplicate archive member names are not allowed")
        for info in infos:
            _validate_member_metadata(info)

        by_name = {info.filename: info for info in infos}
        manifest_bytes = _read_archive_member(
            archive, by_name[MANIFEST_PATH], limit=MAX_MANIFEST_BYTES
        )
        manifest = _load_json_object(manifest_bytes, "bundle manifest")
        if _canonical_json(manifest) != manifest_bytes:
            raise EvidenceBundleError("bundle manifest is not canonical JSON")
        _require_exact_keys(manifest, _MANIFEST_KEYS, "bundle manifest")
        if manifest.get("format") != BUNDLE_FORMAT:
            raise EvidenceBundleError(f"unsupported evidence bundle format: {manifest.get('format')!r}")

        context = manifest.get("context")
        if not isinstance(context, dict):
            raise EvidenceBundleError("bundle context must be an object")
        _validate_context(context, verdict=None)
        authentication = _validate_authentication(manifest.get("authentication"))

        record = manifest.get("record")
        materials = manifest.get("materials")
        if not isinstance(record, dict) or not isinstance(materials, list):
            raise EvidenceBundleError("bundle manifest record/materials have invalid types")
        _require_exact_keys(record, _RECORD_KEYS, "bundle record")
        _validate_digest_row(record, "bundle record")
        if record.get("path") != VERDICT_PATH:
            raise EvidenceBundleError("bundle record must use record/verdict.json")
        for field in ("schema_version", "tool", "tool_version"):
            if not isinstance(record.get(field), str) or not record[field]:
                raise EvidenceBundleError(f"bundle record.{field} must be a non-empty string")
        if record["size"] > MAX_VERDICT_BYTES:
            raise EvidenceBundleError("bundle verdict exceeds its size limit")

        declared_paths = {MANIFEST_PATH, SIGNATURE_PATH, VERDICT_PATH}
        expected_order: list[tuple[str, str, int]] = []
        material_rows: list[dict[str, Any]] = []
        for index, item in enumerate(materials):
            if not isinstance(item, dict):
                raise EvidenceBundleError(f"bundle material {index} must be an object")
            _require_exact_keys(item, _MATERIAL_KEYS, f"bundle material {index}")
            _validate_digest_row(item, f"bundle material {index}")
            role = item.get("role")
            if not isinstance(role, str):
                raise EvidenceBundleError(f"bundle material {index}.role must be a string")
            _validate_role(role)
            expected_path = f"materials/{index:03d}-{role}"
            if item.get("path") != expected_path:
                raise EvidenceBundleError(
                    f"bundle material {index} path must be {expected_path!r}"
                )
            if item["size"] > MAX_MATERIAL_BYTES:
                raise EvidenceBundleError(f"bundle material {index} exceeds its size limit")
            if item["path"] in declared_paths:
                raise EvidenceBundleError(f"duplicate declared bundle path: {item['path']}")
            declared_paths.add(item["path"])
            expected_order.append((role, item["sha256"], item["size"]))
            material_rows.append(item)
        if len(material_rows) > MAX_MATERIALS:
            raise EvidenceBundleError("bundle declares too many materials")
        if expected_order != sorted(expected_order):
            raise EvidenceBundleError("bundle materials are not in canonical order")
        declared_roles = [role for role, _digest, _size in expected_order]
        if len(declared_roles) != len(set(declared_roles)):
            raise EvidenceBundleError("each evidence material role may appear at most once")
        if len(expected_order) != len(set(expected_order)):
            raise EvidenceBundleError("bundle declares duplicate material identities")
        if set(names) != declared_paths:
            raise EvidenceBundleError("archive members do not exactly match the manifest")
        expected_names = [
            MANIFEST_PATH,
            SIGNATURE_PATH,
            VERDICT_PATH,
            *(item["path"] for item in material_rows),
        ]
        if names != expected_names:
            raise EvidenceBundleError("archive members are not in canonical order")

        logical_total = record["size"] + sum(item["size"] for item in material_rows)
        if logical_total > MAX_TOTAL_BYTES:
            raise EvidenceBundleError("bundle payload exceeds its total size limit")

        verdict_bytes = _read_archive_member(
            archive, by_name[VERDICT_PATH], limit=MAX_VERDICT_BYTES
        )
        if len(verdict_bytes) != record["size"] or _sha256(verdict_bytes) != record["sha256"]:
            raise EvidenceBundleError("verdict bytes do not match the bundle manifest")
        verdict = _load_json_object(verdict_bytes, "bundled verdict")
        if _record_manifest(verdict, verdict_bytes) != record:
            raise EvidenceBundleError("bundled verdict metadata does not match the manifest")
        _validate_context(context, verdict=verdict)

        encoded_signature = _read_archive_member(
            archive,
            by_name[authentication["signature_path"]],
            limit=88,
        )
        if len(encoded_signature) != 88 or any(byte > 0x7F for byte in encoded_signature):
            raise EvidenceBundleError("bundle.sig must be exactly 88 ASCII base64 bytes")
        try:
            signature = base64.b64decode(encoded_signature, validate=True)
        except ValueError as exc:
            raise EvidenceBundleError("bundle.sig is not canonical base64") from exc
        if len(signature) != 64 or base64.b64encode(signature) != encoded_signature:
            raise EvidenceBundleError("bundle.sig is not one canonical Ed25519 signature")

        verified_materials: list[VerifiedMaterial] = []
        canonical_members = [
            (MANIFEST_PATH, manifest_bytes),
            (SIGNATURE_PATH, encoded_signature),
            (VERDICT_PATH, verdict_bytes),
        ]
        for item in material_rows:
            data = _read_archive_member(
                archive, by_name[item["path"]], limit=MAX_MATERIAL_BYTES
            )
            if len(data) != item["size"] or _sha256(data) != item["sha256"]:
                raise EvidenceBundleError(
                    f"material bytes do not match the manifest: {item['path']}"
                )
            verified_materials.append(
                VerifiedMaterial(
                    role=item["role"],
                    archive_path=item["path"],
                    sha256=item["sha256"],
                    size=item["size"],
                    data=data,
                )
            )
            canonical_members.append((item["path"], data))

        if _archive_bytes(canonical_members) != snapshot:
            raise EvidenceBundleError(
                "evidence bundle container bytes are not canonical (headers, flags, or layout differ)"
            )

    return InspectedBundle(
        manifest_bytes=manifest_bytes,
        signature=signature,
        verdict_bytes=verdict_bytes,
        materials=tuple(verified_materials),
    )


def verify_bundle_context(
    inspected: InspectedBundle,
    *,
    expected_context: Mapping[str, Any],
) -> None:
    """Require an exact, externally supplied context match."""

    expected = _validate_context(expected_context, verdict=inspected.verdict)
    if inspected.manifest["context"] != expected:
        raise EvidenceBundleError("bundle context does not exactly match expected context")


def verify_bundle_signature(
    inspected: InspectedBundle,
    *,
    trusted_public_key_path: str,
) -> None:
    """Authenticate one inspected bundle with an externally trusted key.

    A public key copied from the bundle itself is not a trust root.
    """

    from evoom_guard.signing import verify_bytes_with_key_id

    verified, trusted_key_id = verify_bytes_with_key_id(
        SIGNING_DOMAIN + inspected.manifest_bytes,
        inspected.signature,
        trusted_public_key_path,
    )
    claimed_key_id = inspected.manifest["authentication"]["key_id"]
    if trusted_key_id != claimed_key_id:
        raise EvidenceBundleError("bundle key_id does not match the externally trusted key")
    if not verified:
        raise EvidenceBundleError("bundle signature is invalid under the trusted public key")


def authenticate_evidence_bundle(
    inspected: InspectedBundle,
    *,
    trusted_public_key_path: str,
    expected_context: Mapping[str, Any],
) -> AuthenticatedBundle:
    """Authenticate an inspected bundle against external trust and exact context.

    Both inputs are deliberately external. Neither may be sourced from the
    bundle when this result controls merge, release, or deployment admission.
    """

    verify_bundle_signature(inspected, trusted_public_key_path=trusted_public_key_path)
    verify_bundle_context(inspected, expected_context=expected_context)
    return AuthenticatedBundle(inspection=inspected)


def verify_evidence_bundle(
    path: str,
    *,
    trusted_public_key_path: str,
    expected_context: Mapping[str, Any],
) -> VerifiedBundle:
    """Run full admission verification: structure, trust, context, and semantics."""

    authenticated = authenticate_evidence_bundle(
        inspect_evidence_bundle(path),
        trusted_public_key_path=trusted_public_key_path,
        expected_context=expected_context,
    )
    from evoom_guard.record_verifier import verify_record

    semantic_report = verify_record(authenticated.verdict)
    if not semantic_report["ok"]:
        failed_checks = [
            item["id"]
            for item in semantic_report["checks"]
            if item["status"] == "fail"
        ]
        raise EvidenceBundleError(
            "bundled verdict record is semantically invalid: " + ", ".join(failed_checks)
        )
    return VerifiedBundle(authenticated=authenticated, record_report=semantic_report)
