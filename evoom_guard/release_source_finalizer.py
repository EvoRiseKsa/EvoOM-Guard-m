# -----------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""A distinct finalizer contract for an exact protected release source.

``trusted_finalizer`` is intentionally a pull-request contract: it binds a
base/head pair and a pull-request re-verification run.  A squash merge creates
a different commit on the protected branch, so treating that PR contract as a
release verdict would be a semantic lie.  This module consequently has a
separate source schema, envelope format, signing domain, material role, and
signature purpose.

V1 binds only the *current exact* ``refs/heads/main`` source described by an
external trusted control plane **and re-derived from a trusted raw-Git object
store before the signing key is opened**.  It intentionally never returns an
admission ``ALLOW``: a structurally valid record is still an untrusted producer
artifact unless a later trusted re-verification workflow authenticates its
execution.  It does not prove that branch protection is enabled, that a
draft/tag is immutable, that an artifact was built from the source, or that
GitHub UI publication was blocked.  Those are separate governance and
artifact-admission boundaries.

The safe use is a split workflow:

* an unprivileged re-verification job writes a canonical handoff;
* a privileged job gets source/run metadata from the GitHub API, independently
  derives the source/context from a trusted raw immutable Git object store; and
* only after every exact comparison succeeds does the privileged job open its
  **release-source-only** signing key.

No PR source shape is accepted here.  In particular, there is no
``pull_request_number``, ``base_sha`` or ``head_sha`` in the source contract.
"""

from __future__ import annotations

import base64
import io
import os
import re
import tempfile
import zipfile
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from evoom_guard.evidence_bundle import (
    MAX_ARCHIVE_BYTES,
    MAX_VERDICT_BYTES,
    EvidenceBundleError,
    _archive_bytes,
    _canonical_json,
    _load_json_object,
    _preflight_zip,
    _read_archive_member,
    _read_regular_file,
    _sha256,
    _validate_member_metadata,
)
from evoom_guard.record_verifier import verify_record

RELEASE_SOURCE_HANDOFF_FORMAT = "EVOGUARD_RELEASE_SOURCE_FINALIZER_HANDOFF_V1"
RELEASE_SOURCE_CONTEXT_FORMAT = "EVOGUARD_RELEASE_SOURCE_CONTEXT_V1"
RELEASE_SOURCE_DERIVATION_FORMAT = "EVOGUARD_RELEASE_SOURCE_GIT_BINDINGS_V1"
RELEASE_SOURCE_EVIDENCE_FORMAT = "EVOGUARD_RELEASE_SOURCE_EVIDENCE_V1"
RELEASE_SOURCE_SIGNATURE_PURPOSE = "evoguard-release-source-finalizer"
RELEASE_SOURCE_KEY_DOMAIN = "release-source-finalizer-v1"
RELEASE_SOURCE_EVIDENCE_DOMAIN = RELEASE_SOURCE_EVIDENCE_FORMAT.encode("ascii") + b"\0"
RELEASE_SOURCE_HANDOFF_ROLE = "release-source-finalizer-handoff"

RELEASE_SOURCE_MANIFEST_PATH = "bundle.json"
RELEASE_SOURCE_SIGNATURE_PATH = "bundle.sig"
RELEASE_SOURCE_VERDICT_PATH = "record/verdict.json"
RELEASE_SOURCE_HANDOFF_PATH = f"materials/{RELEASE_SOURCE_HANDOFF_ROLE}"

MAX_RELEASE_SOURCE_HANDOFF_BYTES = 512 * 1024
MAX_RELEASE_SOURCE_MANIFEST_BYTES = 1 * 1024 * 1024
MAX_RELEASE_SOURCE_ARCHIVE_BYTES = MAX_ARCHIVE_BYTES

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_KEY_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}\Z")
_NUMERIC_ID = re.compile(r"[1-9][0-9]{0,255}\Z")

_SOURCE_KEYS = {
    "repository",
    "repository_id",
    "default_branch",
    "workflow_run_id",
    "workflow_run_attempt",
    "protected_ref",
    "target_commit_sha",
    "target_tree_sha",
}
_CONTEXT_KEYS = {
    "format",
    "repository",
    "repository_id",
    "run_id",
    "run_attempt",
    "protected_ref",
    "target_commit_sha",
    "target_tree_sha",
    "parent_commit_sha",
    "parent_tree_sha",
    "candidate_sha256",
    "policy_sha256",
    "verifier_pack_sha256",
}
_DERIVATION_KEYS = {
    "format",
    "source",
    "parent_commit_sha",
    "parent_tree_sha",
    "candidate_sha256",
    "policy_sha256",
    "verifier_pack_sha256",
}
_HANDOFF_KEYS = {"format", "source", "context", "record"}
_RECORD_DESCRIPTOR_KEYS = {"sha256", "size"}
_EVIDENCE_MANIFEST_KEYS = {
    "format",
    "source",
    "context",
    "record",
    "handoff",
    "decision",
    "authentication",
}
_EVIDENCE_DESCRIPTOR_KEYS = {"path", "sha256", "size"}
_AUTHENTICATION_KEYS = {"algorithm", "key_id", "purpose", "key_domain", "signature_path"}


class ReleaseSourceFinalizerError(ValueError):
    """A release-source handoff or signed evidence object is unsafe or mismatched."""


@dataclass(frozen=True)
class InspectedReleaseSourceHandoff:
    """Canonical, structurally valid handoff bytes that are not trusted yet."""

    handoff_bytes: bytes
    payload: dict[str, Any]

    @property
    def source(self) -> dict[str, Any]:
        return dict(self.payload["source"])

    @property
    def context(self) -> dict[str, Any]:
        return dict(self.payload["context"])

    @property
    def record(self) -> dict[str, Any]:
        return dict(self.payload["record"])


@dataclass(frozen=True)
class DerivedReleaseSourceBindings:
    """Raw-Git-derived source values required before release-source signing.

    This object is a local verification result, not a trust root.  The sealing
    API derives it from an object store itself; callers must not be allowed to
    replace it with a JSON assertion after the key-bearing job starts.
    """

    payload: dict[str, Any]

    @property
    def source(self) -> dict[str, Any]:
        return dict(self.payload["source"])


@dataclass(frozen=True)
class VerifiedReleaseSourceHandoff:
    """Handoff bytes matched exactly to external source/context and verdict bytes."""

    inspection: InspectedReleaseSourceHandoff
    verdict_bytes: bytes
    verdict: dict[str, Any]
    record_report: dict[str, Any]

    @property
    def source(self) -> dict[str, Any]:
        return self.inspection.source

    @property
    def context(self) -> dict[str, Any]:
        return self.inspection.context


@dataclass(frozen=True)
class InspectedReleaseSourceBundle:
    """A structurally verified release-source envelope, before trust is established."""

    manifest_bytes: bytes
    signature: bytes
    verdict_bytes: bytes
    handoff_bytes: bytes

    @property
    def manifest(self) -> dict[str, Any]:
        try:
            return _validate_evidence_manifest(
                _load_json_object(self.manifest_bytes, "release-source bundle manifest")
            )
        except EvidenceBundleError as exc:
            raise ReleaseSourceFinalizerError(str(exc)) from exc


@dataclass(frozen=True)
class SealedReleaseSourceEvidence:
    """One signed release-source evidence envelope and its matched handoff."""

    bundle_path: str
    manifest: dict[str, Any]
    handoff: VerifiedReleaseSourceHandoff
    decision: str


@dataclass(frozen=True)
class VerifiedReleaseSourceEvidence:
    """A signed release-source envelope that passed all external anti-replay checks."""

    bundle: InspectedReleaseSourceBundle
    handoff: VerifiedReleaseSourceHandoff
    record_report: dict[str, Any]
    decision: str


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ReleaseSourceFinalizerError(
            f"{label} keys are not canonical "
            f"(missing={sorted(expected - actual)}, unknown={sorted(actual - expected)})"
        )


def _bounded_string(value: object, *, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ReleaseSourceFinalizerError(
            f"{label} must be a non-empty Unicode string of at most {maximum} characters"
        )
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ReleaseSourceFinalizerError(f"{label} must not contain an unpaired surrogate") from exc
    if any(ord(character) < 0x20 for character in value):
        raise ReleaseSourceFinalizerError(f"{label} must not contain control characters")
    return value


def _validate_numeric_id(value: object, *, label: str) -> str:
    checked = _bounded_string(value, label=label, maximum=256)
    if _NUMERIC_ID.fullmatch(checked) is None:
        raise ReleaseSourceFinalizerError(f"{label} must be a non-zero decimal identifier")
    return checked


def _validate_git_sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise ReleaseSourceFinalizerError(
            f"{label} must be a lowercase 40/64-character immutable Git digest"
        )
    return value


def _validate_sha256(value: object, *, label: str, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        suffix = " or null" if nullable else ""
        raise ReleaseSourceFinalizerError(
            f"{label} must be a lowercase SHA-256 digest{suffix}"
        )
    return value


def validate_release_source(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the V1 protected-release source descriptor.

    V1 is intentionally constrained to the exact current ``main`` ref.  A tag
    is not an authority here: tags can be created or moved by a different
    control plane, and publication/tag verification belongs to a later stage.
    """

    source = dict(value)
    _require_exact_keys(source, _SOURCE_KEYS, "release source")
    repository = _bounded_string(source.get("repository"), label="source.repository", maximum=512)
    if _REPOSITORY.fullmatch(repository) is None:
        raise ReleaseSourceFinalizerError("source.repository must be a canonical owner/repository")
    repository_id = _validate_numeric_id(source.get("repository_id"), label="source.repository_id")
    default_branch = source.get("default_branch")
    if default_branch != "main":
        raise ReleaseSourceFinalizerError("V1 release source default_branch must be exactly 'main'")
    protected_ref = source.get("protected_ref")
    if protected_ref != "refs/heads/main":
        raise ReleaseSourceFinalizerError(
            "V1 release source protected_ref must be exactly 'refs/heads/main'"
        )
    workflow_run_id = _validate_numeric_id(
        source.get("workflow_run_id"), label="source.workflow_run_id"
    )
    workflow_run_attempt = source.get("workflow_run_attempt")
    if type(workflow_run_attempt) is not int or not 1 <= workflow_run_attempt <= 2_147_483_647:
        raise ReleaseSourceFinalizerError(
            "source.workflow_run_attempt must be an integer from 1 through 2147483647"
        )
    return {
        "repository": repository,
        "repository_id": repository_id,
        "default_branch": "main",
        "workflow_run_id": workflow_run_id,
        "workflow_run_attempt": workflow_run_attempt,
        "protected_ref": "refs/heads/main",
        "target_commit_sha": _validate_git_sha(
            source.get("target_commit_sha"), label="source.target_commit_sha"
        ),
        "target_tree_sha": _validate_git_sha(
            source.get("target_tree_sha"), label="source.target_tree_sha"
        ),
    }


def validate_release_source_context(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the V1 context independently from the PR evidence context."""

    context = dict(value)
    _require_exact_keys(context, _CONTEXT_KEYS, "release-source context")
    if context.get("format") != RELEASE_SOURCE_CONTEXT_FORMAT:
        raise ReleaseSourceFinalizerError(
            f"release-source context format must be {RELEASE_SOURCE_CONTEXT_FORMAT!r}"
        )
    repository = _bounded_string(context.get("repository"), label="context.repository", maximum=512)
    if _REPOSITORY.fullmatch(repository) is None:
        raise ReleaseSourceFinalizerError("context.repository must be a canonical owner/repository")
    repository_id = _validate_numeric_id(context.get("repository_id"), label="context.repository_id")
    run_id = _validate_numeric_id(context.get("run_id"), label="context.run_id")
    run_attempt = context.get("run_attempt")
    if type(run_attempt) is not int or not 1 <= run_attempt <= 2_147_483_647:
        raise ReleaseSourceFinalizerError(
            "context.run_attempt must be an integer from 1 through 2147483647"
        )
    if context.get("protected_ref") != "refs/heads/main":
        raise ReleaseSourceFinalizerError(
            "V1 release-source context protected_ref must be exactly 'refs/heads/main'"
        )
    return {
        "format": RELEASE_SOURCE_CONTEXT_FORMAT,
        "repository": repository,
        "repository_id": repository_id,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "protected_ref": "refs/heads/main",
        "target_commit_sha": _validate_git_sha(
            context.get("target_commit_sha"), label="context.target_commit_sha"
        ),
        "target_tree_sha": _validate_git_sha(
            context.get("target_tree_sha"), label="context.target_tree_sha"
        ),
        "parent_commit_sha": _validate_git_sha(
            context.get("parent_commit_sha"), label="context.parent_commit_sha"
        ),
        "parent_tree_sha": _validate_git_sha(
            context.get("parent_tree_sha"), label="context.parent_tree_sha"
        ),
        "candidate_sha256": _validate_sha256(
            context.get("candidate_sha256"), label="context.candidate_sha256"
        ),
        "policy_sha256": _validate_sha256(
            context.get("policy_sha256"), label="context.policy_sha256"
        ),
        "verifier_pack_sha256": _validate_sha256(
            context.get("verifier_pack_sha256"),
            label="context.verifier_pack_sha256",
            nullable=True,
        ),
    }


def _validate_source_context(source: Mapping[str, Any], context: Mapping[str, Any]) -> None:
    comparisons = {
        "repository": "repository",
        "repository_id": "repository_id",
        "workflow_run_id": "run_id",
        "workflow_run_attempt": "run_attempt",
        "protected_ref": "protected_ref",
        "target_commit_sha": "target_commit_sha",
        "target_tree_sha": "target_tree_sha",
    }
    for source_key, context_key in comparisons.items():
        if source[source_key] != context[context_key]:
            raise ReleaseSourceFinalizerError(
                f"release source.{source_key} does not match context.{context_key}"
            )
    if context["parent_commit_sha"] == context["target_commit_sha"]:
        raise ReleaseSourceFinalizerError("context parent_commit_sha must differ from target_commit_sha")


def _validate_record_descriptor(value: Mapping[str, Any]) -> dict[str, Any]:
    descriptor = dict(value)
    _require_exact_keys(descriptor, _RECORD_DESCRIPTOR_KEYS, "release-source handoff record")
    digest = _validate_sha256(descriptor.get("sha256"), label="record.sha256")
    size = descriptor.get("size")
    if type(size) is not int or not 1 <= size <= MAX_VERDICT_BYTES:
        raise ReleaseSourceFinalizerError(
            f"record.size must be an integer from 1 through {MAX_VERDICT_BYTES}"
        )
    return {"sha256": digest, "size": size}


def _validate_record_context(record: Mapping[str, Any], context: Mapping[str, Any]) -> None:
    attestation = record.get("attestation")
    if not isinstance(attestation, dict):
        raise ReleaseSourceFinalizerError(
            "release-source finalization requires a non-null verdict.attestation object"
        )
    expected = {
        "base_sha": "parent_commit_sha",
        "head_sha": "target_commit_sha",
        "base_tree_sha": "parent_tree_sha",
        "head_tree_sha": "target_tree_sha",
        "candidate_sha256": "candidate_sha256",
        "policy_sha256": "policy_sha256",
        "verifier_pack_sha256": "verifier_pack_sha256",
    }
    for record_key, context_key in expected.items():
        if attestation.get(record_key) != context[context_key]:
            raise ReleaseSourceFinalizerError(
                f"verdict.attestation.{record_key} does not match context.{context_key}"
            )


def _validate_release_source_derivation(
    value: Mapping[str, Any],
) -> DerivedReleaseSourceBindings:
    payload = dict(value)
    _require_exact_keys(payload, _DERIVATION_KEYS, "release-source raw-Git derivation")
    if payload.get("format") != RELEASE_SOURCE_DERIVATION_FORMAT:
        raise ReleaseSourceFinalizerError(
            "release-source raw-Git derivation has an unsupported format"
        )
    source = payload.get("source")
    if not isinstance(source, dict):
        raise ReleaseSourceFinalizerError("release-source raw-Git derivation source must be an object")
    verified_source = validate_release_source(source)
    parent_commit = _validate_git_sha(
        payload.get("parent_commit_sha"), label="release-source derivation parent_commit_sha"
    )
    parent_tree = _validate_git_sha(
        payload.get("parent_tree_sha"), label="release-source derivation parent_tree_sha"
    )
    if parent_commit == verified_source["target_commit_sha"]:
        raise ReleaseSourceFinalizerError(
            "release-source raw-Git derivation parent_commit_sha must differ from target"
        )
    return DerivedReleaseSourceBindings(
        payload={
            "format": RELEASE_SOURCE_DERIVATION_FORMAT,
            "source": verified_source,
            "parent_commit_sha": parent_commit,
            "parent_tree_sha": parent_tree,
            "candidate_sha256": _validate_sha256(
                payload.get("candidate_sha256"),
                label="release-source derivation candidate_sha256",
            ),
            "policy_sha256": _validate_sha256(
                payload.get("policy_sha256"),
                label="release-source derivation policy_sha256",
            ),
            "verifier_pack_sha256": _validate_sha256(
                payload.get("verifier_pack_sha256"),
                label="release-source derivation verifier_pack_sha256",
                nullable=True,
            ),
        }
    )


def derive_release_source_bindings(
    *,
    git_repository: str,
    source: Mapping[str, Any],
    git_repository_is_bare: bool = False,
) -> DerivedReleaseSourceBindings:
    """Derive the release source and Guard material from raw Git before signing.

    ``git_repository`` must be the object store fetched by the privileged
    workflow from the authoritative repository.  This function intentionally
    does not accept a precomputed context: it resolves ``refs/heads/main`` and
    the single parent itself, then recomputes the candidate, policy, and pack
    identity from immutable blobs without checking out or executing the target.
    """

    verified_source = validate_release_source(source)
    try:
        from evoom_guard.finalizer_derivation import (
            FinalizerDerivationError,
            derive_raw_evaluation_bindings,
            derive_raw_ref_parent_pair,
        )

        target, target_tree, parent, parent_tree = derive_raw_ref_parent_pair(
            repository=git_repository,
            ref="refs/heads/main",
            bare=git_repository_is_bare,
        )
        if (
            verified_source["target_commit_sha"] != target
            or verified_source["target_tree_sha"] != target_tree
        ):
            raise ReleaseSourceFinalizerError(
                "trusted raw-Git refs/heads/main does not match the expected release source"
            )
        raw = derive_raw_evaluation_bindings(
            base_repo=git_repository,
            head_repo=git_repository,
            base_sha=parent,
            head_sha=target,
            base_tree_sha=parent_tree,
            head_tree_sha=target_tree,
            base_is_bare=git_repository_is_bare,
            head_is_bare=git_repository_is_bare,
        )
    except FinalizerDerivationError as exc:
        raise ReleaseSourceFinalizerError(
            f"release-source raw-Git derivation failed: {exc}"
        ) from exc
    return _validate_release_source_derivation(
        {
            "format": RELEASE_SOURCE_DERIVATION_FORMAT,
            "source": verified_source,
            "parent_commit_sha": parent,
            "parent_tree_sha": parent_tree,
            "candidate_sha256": raw["candidate_sha256"],
            "policy_sha256": raw["policy_sha256"],
            "verifier_pack_sha256": raw["verifier_pack_sha256"],
        }
    )


def context_from_release_source_bindings(
    bindings: DerivedReleaseSourceBindings,
    record: Mapping[str, Any],
) -> dict[str, Any]:
    """Form a context only if the verdict attestation matches raw-Git values."""

    verified = _validate_release_source_derivation(bindings.payload)
    source = verified.source
    context = {
        "format": RELEASE_SOURCE_CONTEXT_FORMAT,
        "repository": source["repository"],
        "repository_id": source["repository_id"],
        "run_id": source["workflow_run_id"],
        "run_attempt": source["workflow_run_attempt"],
        "protected_ref": source["protected_ref"],
        "target_commit_sha": source["target_commit_sha"],
        "target_tree_sha": source["target_tree_sha"],
        "parent_commit_sha": verified.payload["parent_commit_sha"],
        "parent_tree_sha": verified.payload["parent_tree_sha"],
        "candidate_sha256": verified.payload["candidate_sha256"],
        "policy_sha256": verified.payload["policy_sha256"],
        "verifier_pack_sha256": verified.payload["verifier_pack_sha256"],
    }
    context = validate_release_source_context(context)
    _validate_record_context(record, context)
    return context


def _record_snapshot(path: str) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    try:
        verdict_bytes = _read_regular_file(path, limit=MAX_VERDICT_BYTES, label="verdict")
        verdict = _load_json_object(verdict_bytes, "verdict")
    except EvidenceBundleError as exc:
        raise ReleaseSourceFinalizerError(str(exc)) from exc
    record_report = verify_record(verdict)
    if not record_report["ok"]:
        failed = ", ".join(
            str(item["id"])
            for item in record_report["checks"]
            if item.get("status") == "fail"
        )
        raise ReleaseSourceFinalizerError("verdict record is semantically invalid: " + failed)
    return verdict_bytes, verdict, record_report


def _publish_bytes(path: str, data: bytes, *, force: bool, prefix: str, label: str) -> str:
    absolute = os.path.abspath(path)
    parent = os.path.dirname(absolute) or os.curdir
    if os.path.isdir(absolute):
        raise ReleaseSourceFinalizerError(f"{label} output is a directory: {absolute}")
    os.makedirs(parent, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=prefix, dir=parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if force:
            os.replace(temporary, absolute)
        else:
            try:
                os.link(temporary, absolute, follow_symlinks=False)
            except FileExistsError as exc:
                raise ReleaseSourceFinalizerError(
                    f"refusing to overwrite existing {label}: {absolute}"
                ) from exc
            except OSError as exc:
                raise ReleaseSourceFinalizerError(
                    f"cannot publish {label} with atomic no-clobber semantics; "
                    "use a filesystem that supports hard links or pass force=True explicitly"
                ) from exc
            os.unlink(temporary)
        os.chmod(absolute, 0o644)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return absolute


def create_release_source_handoff(
    verdict_path: str,
    output_path: str,
    *,
    source: Mapping[str, Any],
    context: Mapping[str, Any],
    force: bool = False,
) -> dict[str, Any]:
    """Write an unsigned canonical release-source descriptor.

    The writer is usable in an unprivileged job.  Its output carries no trust
    by itself; a privileged finalizer must independently provide exact expected
    source/context metadata before it can sign anything.
    """

    verified_source = validate_release_source(source)
    verified_context = validate_release_source_context(context)
    _validate_source_context(verified_source, verified_context)
    verdict_bytes, verdict, _report = _record_snapshot(verdict_path)
    _validate_record_context(verdict, verified_context)
    payload = {
        "format": RELEASE_SOURCE_HANDOFF_FORMAT,
        "source": verified_source,
        "context": verified_context,
        "record": {"sha256": _sha256(verdict_bytes), "size": len(verdict_bytes)},
    }
    try:
        encoded = _canonical_json(payload)
    except EvidenceBundleError as exc:
        raise ReleaseSourceFinalizerError(str(exc)) from exc
    if len(encoded) > MAX_RELEASE_SOURCE_HANDOFF_BYTES:
        raise ReleaseSourceFinalizerError("canonical release-source handoff exceeds its size limit")
    _publish_bytes(
        output_path,
        encoded,
        force=force,
        prefix=".evoguard-release-source-handoff-",
        label="release-source handoff",
    )
    return payload


def inspect_release_source_handoff(path: str) -> InspectedReleaseSourceHandoff:
    """Inspect canonical handoff bytes without treating them as trusted input."""

    try:
        handoff_bytes = _read_regular_file(
            path,
            limit=MAX_RELEASE_SOURCE_HANDOFF_BYTES,
            label="release-source handoff",
        )
        payload = _load_json_object(handoff_bytes, "release-source handoff")
        if _canonical_json(payload) != handoff_bytes:
            raise ReleaseSourceFinalizerError("release-source handoff is not canonical JSON")
    except EvidenceBundleError as exc:
        raise ReleaseSourceFinalizerError(str(exc)) from exc
    _require_exact_keys(payload, _HANDOFF_KEYS, "release-source handoff")
    if payload.get("format") != RELEASE_SOURCE_HANDOFF_FORMAT:
        raise ReleaseSourceFinalizerError(
            f"unsupported release-source handoff format: {payload.get('format')!r}"
        )
    source = payload.get("source")
    context = payload.get("context")
    record = payload.get("record")
    if not isinstance(source, dict) or not isinstance(context, dict) or not isinstance(record, dict):
        raise ReleaseSourceFinalizerError(
            "release-source handoff source, context, and record must be objects"
        )
    verified_source = validate_release_source(source)
    verified_context = validate_release_source_context(context)
    _validate_source_context(verified_source, verified_context)
    _validate_record_descriptor(record)
    return InspectedReleaseSourceHandoff(handoff_bytes=handoff_bytes, payload=payload)


def verify_release_source_handoff(
    inspected: InspectedReleaseSourceHandoff,
    *,
    verdict_path: str,
    expected_source: Mapping[str, Any],
    expected_context: Mapping[str, Any],
) -> VerifiedReleaseSourceHandoff:
    """Require exact trusted control-plane source/context and verdict bytes."""

    source = validate_release_source(expected_source)
    context = validate_release_source_context(expected_context)
    _validate_source_context(source, context)
    if inspected.source != source:
        raise ReleaseSourceFinalizerError(
            "release-source handoff source does not exactly match expected source"
        )
    if inspected.context != context:
        raise ReleaseSourceFinalizerError(
            "release-source handoff context does not exactly match expected context"
        )
    verdict_bytes, verdict, report = _record_snapshot(verdict_path)
    descriptor = _validate_record_descriptor(inspected.record)
    if descriptor != {"sha256": _sha256(verdict_bytes), "size": len(verdict_bytes)}:
        raise ReleaseSourceFinalizerError(
            "release-source handoff record does not match exact verdict bytes"
        )
    _validate_record_context(verdict, context)
    return VerifiedReleaseSourceHandoff(
        inspection=inspected,
        verdict_bytes=verdict_bytes,
        verdict=verdict,
        record_report=report,
    )


def release_source_decision(record: Mapping[str, Any]) -> str:
    """Return the V1 decision without treating a producer record as authority.

    Raw Git derivation proves that the source, policy and pack fingerprints in
    a record match immutable objects.  It cannot prove that the process which
    wrote that record actually executed Guard: an untrusted job can construct
    a syntactically valid ``PASS`` document with equally plausible assurance
    fields.  V1 therefore preserves the record as audit material but signs a
    denial in every case.  A future admitting version must verify a distinct,
    trusted re-verification receipt that binds the exact source, raw-derived
    context, record digest, runtime digest, run/attempt and producer identity
    before it reaches this release signing key.
    """

    del record
    return "DENY"


def _validate_key_ids(values: Iterable[str]) -> frozenset[str]:
    checked: set[str] = set()
    for value in values:
        if not isinstance(value, str) or _KEY_ID.fullmatch(value) is None:
            raise ReleaseSourceFinalizerError(
                "prohibited signing key IDs must be sha256:<lowercase DER-SPKI digest>"
            )
        checked.add(value)
    return frozenset(checked)


def _descriptor(path: str, data: bytes) -> dict[str, Any]:
    return {"path": path, "sha256": _sha256(data), "size": len(data)}


def _validate_evidence_descriptor(value: Mapping[str, Any], *, label: str, path: str, limit: int) -> dict[str, Any]:
    descriptor = dict(value)
    _require_exact_keys(descriptor, _EVIDENCE_DESCRIPTOR_KEYS, label)
    if descriptor.get("path") != path:
        raise ReleaseSourceFinalizerError(f"{label}.path must be {path!r}")
    digest = _validate_sha256(descriptor.get("sha256"), label=f"{label}.sha256")
    size = descriptor.get("size")
    if type(size) is not int or not 1 <= size <= limit:
        raise ReleaseSourceFinalizerError(f"{label}.size is outside the permitted range")
    return {"path": path, "sha256": digest, "size": size}


def _validate_authentication(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ReleaseSourceFinalizerError("release-source authentication must be an object")
    authentication = dict(value)
    _require_exact_keys(authentication, _AUTHENTICATION_KEYS, "release-source authentication")
    if authentication.get("algorithm") != "Ed25519":
        raise ReleaseSourceFinalizerError("release-source authentication algorithm must be Ed25519")
    if authentication.get("purpose") != RELEASE_SOURCE_SIGNATURE_PURPOSE:
        raise ReleaseSourceFinalizerError(
            f"release-source authentication purpose must be {RELEASE_SOURCE_SIGNATURE_PURPOSE!r}"
        )
    if authentication.get("key_domain") != RELEASE_SOURCE_KEY_DOMAIN:
        raise ReleaseSourceFinalizerError(
            f"release-source authentication key_domain must be {RELEASE_SOURCE_KEY_DOMAIN!r}"
        )
    if authentication.get("signature_path") != RELEASE_SOURCE_SIGNATURE_PATH:
        raise ReleaseSourceFinalizerError(
            f"release-source authentication signature_path must be {RELEASE_SOURCE_SIGNATURE_PATH!r}"
        )
    key_id = authentication.get("key_id")
    if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
        raise ReleaseSourceFinalizerError(
            "release-source authentication key_id must be sha256:<lowercase DER-SPKI digest>"
        )
    return {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "purpose": RELEASE_SOURCE_SIGNATURE_PURPOSE,
        "key_domain": RELEASE_SOURCE_KEY_DOMAIN,
        "signature_path": RELEASE_SOURCE_SIGNATURE_PATH,
    }


def _validate_evidence_manifest(value: Mapping[str, Any]) -> dict[str, Any]:
    manifest = dict(value)
    _require_exact_keys(manifest, _EVIDENCE_MANIFEST_KEYS, "release-source evidence manifest")
    if manifest.get("format") != RELEASE_SOURCE_EVIDENCE_FORMAT:
        raise ReleaseSourceFinalizerError(
            f"unsupported release-source evidence format: {manifest.get('format')!r}"
        )
    source = manifest.get("source")
    context = manifest.get("context")
    record = manifest.get("record")
    handoff = manifest.get("handoff")
    if (
        not isinstance(source, dict)
        or not isinstance(context, dict)
        or not isinstance(record, dict)
        or not isinstance(handoff, dict)
    ):
        raise ReleaseSourceFinalizerError(
            "release-source evidence source, context, record, and handoff must be objects"
        )
    verified_source = validate_release_source(source)
    verified_context = validate_release_source_context(context)
    _validate_source_context(verified_source, verified_context)
    verified_record = _validate_evidence_descriptor(
        record,
        label="release-source evidence record",
        path=RELEASE_SOURCE_VERDICT_PATH,
        limit=MAX_VERDICT_BYTES,
    )
    verified_handoff = _validate_evidence_descriptor(
        handoff,
        label="release-source evidence handoff",
        path=RELEASE_SOURCE_HANDOFF_PATH,
        limit=MAX_RELEASE_SOURCE_HANDOFF_BYTES,
    )
    decision = manifest.get("decision")
    if decision != "DENY":
        raise ReleaseSourceFinalizerError(
            "release-source evidence V1 is deny-only until a trusted producer receipt exists"
        )
    return {
        "format": RELEASE_SOURCE_EVIDENCE_FORMAT,
        "source": verified_source,
        "context": verified_context,
        "record": verified_record,
        "handoff": verified_handoff,
        "decision": decision,
        "authentication": _validate_authentication(manifest.get("authentication")),
    }


def _decode_signature(data: bytes) -> bytes:
    if len(data) != 88 or any(byte > 0x7F for byte in data):
        raise ReleaseSourceFinalizerError(
            "release-source bundle.sig must be exactly 88 ASCII base64 bytes"
        )
    try:
        signature = base64.b64decode(data, validate=True)
    except ValueError as exc:
        raise ReleaseSourceFinalizerError("release-source bundle.sig is not canonical base64") from exc
    if len(signature) != 64 or base64.b64encode(signature) != data:
        raise ReleaseSourceFinalizerError(
            "release-source bundle.sig is not one canonical Ed25519 signature"
        )
    return signature


def seal_release_source_bundle(
    handoff_path: str,
    verdict_path: str,
    output_path: str,
    *,
    expected_source: Mapping[str, Any],
    expected_context: Mapping[str, Any],
    git_repository: str,
    git_repository_is_bare: bool = False,
    private_key_path: str,
    prohibited_key_ids: Iterable[str] = (),
    force: bool = False,
) -> SealedReleaseSourceEvidence:
    """Sign only a release handoff that exactly matches external source truth.

    Validation and raw-Git derivation run before the signing key is opened.
    ``prohibited_key_ids`` is mandatory for this operation: the integrator must
    mechanically supply the PR-finalizer and artifact-admission identities
    that the release-source key must not equal.  The separate signature domain
    additionally prevents envelope replay across contracts.
    """

    source = validate_release_source(expected_source)
    context = validate_release_source_context(expected_context)
    _validate_source_context(source, context)
    prohibited = _validate_key_ids(prohibited_key_ids)
    if not prohibited:
        raise ReleaseSourceFinalizerError(
            "release-source sealing requires one or more prohibited non-release key IDs"
        )
    bindings = derive_release_source_bindings(
        git_repository=git_repository,
        source=source,
        git_repository_is_bare=git_repository_is_bare,
    )
    inspected_handoff = inspect_release_source_handoff(handoff_path)
    handoff = verify_release_source_handoff(
        inspected_handoff,
        verdict_path=verdict_path,
        expected_source=source,
        expected_context=context,
    )
    derived_context = context_from_release_source_bindings(bindings, handoff.verdict)
    if derived_context != context:
        raise ReleaseSourceFinalizerError(
            "trusted raw-Git derivation does not exactly match the expected release context"
        )
    from evoom_guard.signing import _load_private_key_snapshot, _sign_bytes_with_key_id

    signing_key = _load_private_key_snapshot(private_key_path)
    if signing_key.key_id in prohibited:
        raise ReleaseSourceFinalizerError(
            "release-source signing key is prohibited because it belongs to another trust domain"
        )
    decision = release_source_decision(handoff.verdict)
    authentication = {
        "algorithm": "Ed25519",
        "key_id": signing_key.key_id,
        "purpose": RELEASE_SOURCE_SIGNATURE_PURPOSE,
        "key_domain": RELEASE_SOURCE_KEY_DOMAIN,
        "signature_path": RELEASE_SOURCE_SIGNATURE_PATH,
    }
    manifest = {
        "format": RELEASE_SOURCE_EVIDENCE_FORMAT,
        "source": handoff.source,
        "context": handoff.context,
        "record": _descriptor(RELEASE_SOURCE_VERDICT_PATH, handoff.verdict_bytes),
        "handoff": _descriptor(RELEASE_SOURCE_HANDOFF_PATH, inspected_handoff.handoff_bytes),
        "decision": decision,
        "authentication": authentication,
    }
    try:
        manifest_bytes = _canonical_json(manifest)
    except EvidenceBundleError as exc:
        raise ReleaseSourceFinalizerError(str(exc)) from exc
    if len(manifest_bytes) > MAX_RELEASE_SOURCE_MANIFEST_BYTES:
        raise ReleaseSourceFinalizerError("release-source evidence manifest exceeds its size limit")
    signature, actual_key_id = _sign_bytes_with_key_id(
        RELEASE_SOURCE_EVIDENCE_DOMAIN + manifest_bytes,
        signing_key,
    )
    if actual_key_id != signing_key.key_id or len(signature) != 64:
        raise ReleaseSourceFinalizerError("release-source signer returned inconsistent key identity or signature")
    signature_bytes = base64.b64encode(signature)
    if len(signature_bytes) != 88:
        raise ReleaseSourceFinalizerError("release-source signature did not encode canonically")
    archive = _archive_bytes(
        (
            (RELEASE_SOURCE_MANIFEST_PATH, manifest_bytes),
            (RELEASE_SOURCE_SIGNATURE_PATH, signature_bytes),
            (RELEASE_SOURCE_VERDICT_PATH, handoff.verdict_bytes),
            (RELEASE_SOURCE_HANDOFF_PATH, inspected_handoff.handoff_bytes),
        )
    )
    if len(archive) > MAX_RELEASE_SOURCE_ARCHIVE_BYTES:
        raise ReleaseSourceFinalizerError("release-source evidence archive exceeds its size limit")
    bundle_path = _publish_bytes(
        output_path,
        archive,
        force=force,
        prefix=".evoguard-release-source-bundle-",
        label="release-source evidence bundle",
    )
    # Re-inspect the published archive.  The private-key path intentionally
    # does not imply a public-key path, so authenticity remains an external
    # consumer operation; this post-write check still catches publication or
    # container corruption before the caller treats the output as complete.
    published = inspect_release_source_bundle(bundle_path)
    if (
        published.manifest["source"] != handoff.source
        or published.manifest["context"] != handoff.context
        or published.manifest["decision"] != decision
    ):
        raise ReleaseSourceFinalizerError(
            "published release-source evidence does not preserve verified source/context/decision"
        )
    return SealedReleaseSourceEvidence(
        bundle_path=bundle_path,
        manifest=published.manifest,
        handoff=handoff,
        decision=decision,
    )


def inspect_release_source_bundle(path: str) -> InspectedReleaseSourceBundle:
    """Check canonical archive/content structure without authenticating its signer."""

    try:
        snapshot = _read_regular_file(
            path,
            limit=MAX_RELEASE_SOURCE_ARCHIVE_BYTES,
            label="release-source evidence bundle",
        )
        declared_entries = _preflight_zip(snapshot)
        archive = zipfile.ZipFile(io.BytesIO(snapshot), "r")
    except (EvidenceBundleError, OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise ReleaseSourceFinalizerError(f"cannot inspect release-source evidence bundle: {exc}") from exc
    with archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        expected_names = [
            RELEASE_SOURCE_MANIFEST_PATH,
            RELEASE_SOURCE_SIGNATURE_PATH,
            RELEASE_SOURCE_VERDICT_PATH,
            RELEASE_SOURCE_HANDOFF_PATH,
        ]
        if archive.comment or declared_entries != 4 or len(infos) != 4 or names != expected_names:
            raise ReleaseSourceFinalizerError(
                "release-source evidence archive members are not the exact canonical four-member layout"
            )
        if len(names) != len(set(names)):
            raise ReleaseSourceFinalizerError("release-source evidence archive has duplicate members")
        try:
            for info in infos:
                _validate_member_metadata(info)
            by_name = {info.filename: info for info in infos}
            manifest_bytes = _read_archive_member(
                archive, by_name[RELEASE_SOURCE_MANIFEST_PATH], limit=MAX_RELEASE_SOURCE_MANIFEST_BYTES
            )
            manifest_raw = _load_json_object(manifest_bytes, "release-source bundle manifest")
            if _canonical_json(manifest_raw) != manifest_bytes:
                raise ReleaseSourceFinalizerError("release-source evidence manifest is not canonical JSON")
            manifest = _validate_evidence_manifest(manifest_raw)
            verdict_bytes = _read_archive_member(
                archive, by_name[RELEASE_SOURCE_VERDICT_PATH], limit=MAX_VERDICT_BYTES
            )
            handoff_bytes = _read_archive_member(
                archive, by_name[RELEASE_SOURCE_HANDOFF_PATH], limit=MAX_RELEASE_SOURCE_HANDOFF_BYTES
            )
            if manifest["record"] != _descriptor(RELEASE_SOURCE_VERDICT_PATH, verdict_bytes):
                raise ReleaseSourceFinalizerError(
                    "release-source evidence verdict bytes do not match the manifest"
                )
            if manifest["handoff"] != _descriptor(RELEASE_SOURCE_HANDOFF_PATH, handoff_bytes):
                raise ReleaseSourceFinalizerError(
                    "release-source evidence handoff bytes do not match the manifest"
                )
            verdict = _load_json_object(verdict_bytes, "release-source bundled verdict")
            _validate_record_context(verdict, manifest["context"])
            inspected_handoff = inspect_release_source_handoff_bytes(handoff_bytes)
            if inspected_handoff.source != manifest["source"] or inspected_handoff.context != manifest["context"]:
                raise ReleaseSourceFinalizerError(
                    "release-source evidence handoff source/context do not match the manifest"
                )
            encoded_signature = _read_archive_member(
                archive, by_name[RELEASE_SOURCE_SIGNATURE_PATH], limit=88
            )
            signature = _decode_signature(encoded_signature)
            if _archive_bytes(
                (
                    (RELEASE_SOURCE_MANIFEST_PATH, manifest_bytes),
                    (RELEASE_SOURCE_SIGNATURE_PATH, encoded_signature),
                    (RELEASE_SOURCE_VERDICT_PATH, verdict_bytes),
                    (RELEASE_SOURCE_HANDOFF_PATH, handoff_bytes),
                )
            ) != snapshot:
                raise ReleaseSourceFinalizerError(
                    "release-source evidence archive bytes are not canonical"
                )
        except EvidenceBundleError as exc:
            raise ReleaseSourceFinalizerError(str(exc)) from exc
    return InspectedReleaseSourceBundle(
        manifest_bytes=manifest_bytes,
        signature=signature,
        verdict_bytes=verdict_bytes,
        handoff_bytes=handoff_bytes,
    )


def inspect_release_source_handoff_bytes(handoff_bytes: bytes) -> InspectedReleaseSourceHandoff:
    """Inspect already captured handoff bytes without reopening their source path."""

    if len(handoff_bytes) > MAX_RELEASE_SOURCE_HANDOFF_BYTES:
        raise ReleaseSourceFinalizerError("release-source handoff exceeds its size limit")
    try:
        payload = _load_json_object(handoff_bytes, "release-source handoff")
        if _canonical_json(payload) != handoff_bytes:
            raise ReleaseSourceFinalizerError("release-source handoff is not canonical JSON")
    except EvidenceBundleError as exc:
        raise ReleaseSourceFinalizerError(str(exc)) from exc
    _require_exact_keys(payload, _HANDOFF_KEYS, "release-source handoff")
    if payload.get("format") != RELEASE_SOURCE_HANDOFF_FORMAT:
        raise ReleaseSourceFinalizerError(
            f"unsupported release-source handoff format: {payload.get('format')!r}"
        )
    source = payload.get("source")
    context = payload.get("context")
    record = payload.get("record")
    if not isinstance(source, dict) or not isinstance(context, dict) or not isinstance(record, dict):
        raise ReleaseSourceFinalizerError(
            "release-source handoff source, context, and record must be objects"
        )
    verified_source = validate_release_source(source)
    verified_context = validate_release_source_context(context)
    _validate_source_context(verified_source, verified_context)
    _validate_record_descriptor(record)
    return InspectedReleaseSourceHandoff(handoff_bytes=handoff_bytes, payload=payload)


@contextmanager
def _verified_snapshots(
    *,
    verdict_bytes: bytes,
    handoff_bytes: bytes,
) -> Iterator[tuple[str, str]]:
    """Materialise already verified bytes privately for exact handoff rechecking."""

    with tempfile.TemporaryDirectory(prefix=".evoguard-release-source-") as directory:
        paths: list[str] = []
        for label, data in (("record", verdict_bytes), ("handoff", handoff_bytes)):
            descriptor, path = tempfile.mkstemp(prefix=f"{label}-", dir=directory)
            paths.append(path)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(path, 0o600)
        yield paths[0], paths[1]


def verify_release_source_bundle(
    bundle_path: str,
    *,
    trusted_public_key_path: str,
    expected_source: Mapping[str, Any],
    expected_context: Mapping[str, Any],
    prohibited_key_ids: Iterable[str] = (),
) -> VerifiedReleaseSourceEvidence:
    """Verify release-source signature, exact context, record and handoff bytes."""

    source = validate_release_source(expected_source)
    context = validate_release_source_context(expected_context)
    _validate_source_context(source, context)
    prohibited = _validate_key_ids(prohibited_key_ids)
    if not prohibited:
        raise ReleaseSourceFinalizerError(
            "release-source verification requires one or more prohibited non-release key IDs"
        )
    bundle = inspect_release_source_bundle(bundle_path)
    manifest = bundle.manifest
    if manifest["source"] != source or manifest["context"] != context:
        raise ReleaseSourceFinalizerError(
            "release-source evidence source/context do not exactly match external expectations"
        )
    from evoom_guard.signing import verify_bytes_with_key_id

    verified, trusted_key_id = verify_bytes_with_key_id(
        RELEASE_SOURCE_EVIDENCE_DOMAIN + bundle.manifest_bytes,
        bundle.signature,
        trusted_public_key_path,
    )
    if trusted_key_id in prohibited:
        raise ReleaseSourceFinalizerError(
            "release-source trusted public key is prohibited because it belongs to another trust domain"
        )
    if manifest["authentication"]["key_id"] != trusted_key_id:
        raise ReleaseSourceFinalizerError(
            "release-source evidence key_id does not match the externally trusted public key"
        )
    if not verified:
        raise ReleaseSourceFinalizerError(
            "release-source evidence signature is invalid under the trusted public key"
        )
    verdict = _load_json_object(bundle.verdict_bytes, "release-source bundled verdict")
    report = verify_record(verdict)
    if not report["ok"]:
        raise ReleaseSourceFinalizerError("release-source evidence contains an invalid verdict record")
    with _verified_snapshots(
        verdict_bytes=bundle.verdict_bytes,
        handoff_bytes=bundle.handoff_bytes,
    ) as (verdict_snapshot, handoff_snapshot):
        handoff = verify_release_source_handoff(
            inspect_release_source_handoff(handoff_snapshot),
            verdict_path=verdict_snapshot,
            expected_source=source,
            expected_context=context,
        )
    decision = release_source_decision(verdict)
    if manifest["decision"] != decision:
        raise ReleaseSourceFinalizerError(
            "release-source evidence decision is inconsistent with its verdict"
        )
    return VerifiedReleaseSourceEvidence(
        bundle=bundle,
        handoff=handoff,
        record_report=report,
        decision=decision,
    )
