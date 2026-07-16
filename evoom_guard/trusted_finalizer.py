# -----------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Strict handoff and sealing primitives for a split trusted finalizer.

The handoff is deliberately *not* an assertion that candidate code executed
safely.  It is a bounded, canonical descriptor that lets a separate sealing job
compare a re-verification record to independently supplied control-plane
metadata before it opens a signing key.  A secure deployment still needs a
workflow that keeps candidate execution unprivileged and isolated, then makes
the sealing job avoid candidate checkout and execution entirely.
"""

from __future__ import annotations

import os
import re
import tempfile
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from evoom_guard.evidence_bundle import (
    MAX_VERDICT_BYTES,
    AuthenticatedBundle,
    EvidenceBundleError,
    EvidenceMaterial,
    FinalizedEvidence,
    VerifiedBundle,
    _canonical_json,
    _load_json_object,
    _read_regular_file,
    _sha256,
    finalize_evidence_bundle,
    inspect_evidence_bundle,
    validate_evidence_context,
    verify_bundle_context,
    verify_bundle_signature,
)
from evoom_guard.record_verifier import verify_record

FINALIZER_HANDOFF_FORMAT = "EVOGUARD_TRUSTED_FINALIZER_HANDOFF_V1"
FINALIZER_HANDOFF_ROLE = "trusted-finalizer-handoff"
MAX_FINALIZER_HANDOFF_BYTES = 512 * 1024

_HANDOFF_KEYS = {"format", "source", "context", "record"}
_SOURCE_KEYS = {
    "pull_request_number",
    "workflow_run_id",
    "workflow_run_attempt",
    "base_sha",
    "head_sha",
}
_RECORD_KEYS = {"sha256", "size"}
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


class FinalizerHandoffError(ValueError):
    """A finalizer handoff is malformed, replayed, or mismatched."""


@dataclass(frozen=True)
class InspectedFinalizerHandoff:
    """A canonical handoff whose structure was checked, but not trusted yet."""

    handoff_bytes: bytes
    payload: dict[str, Any]

    @property
    def source(self) -> dict[str, Any]:
        value = self.payload["source"]
        return dict(value) if isinstance(value, dict) else {}

    @property
    def context(self) -> dict[str, Any]:
        value = self.payload["context"]
        return dict(value) if isinstance(value, dict) else {}

    @property
    def record(self) -> dict[str, Any]:
        value = self.payload["record"]
        return dict(value) if isinstance(value, dict) else {}


@dataclass(frozen=True)
class VerifiedFinalizerHandoff:
    """A handoff matched to external source/context and exact record bytes."""

    inspection: InspectedFinalizerHandoff
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
class FinalizedTrustedEvidence:
    """A signed evidence bundle plus the externally matched handoff."""

    finalized: FinalizedEvidence
    handoff: VerifiedFinalizerHandoff

    @property
    def decision(self) -> str:
        return self.finalized.decision


@dataclass(frozen=True)
class VerifiedFinalizedBundle:
    """A signed bundle whose mandatory finalizer handoff also matched externally."""

    bundle: VerifiedBundle
    handoff: VerifiedFinalizerHandoff
    decision: str


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise FinalizerHandoffError(
            f"{label} keys are not canonical "
            f"(missing={sorted(expected - actual)}, unknown={sorted(actual - expected)})"
        )


def _bounded_string(value: object, *, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise FinalizerHandoffError(
            f"{label} must be a non-empty Unicode string of at most {maximum} characters"
        )
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise FinalizerHandoffError(f"{label} must not contain an unpaired surrogate") from exc
    if any(ord(character) < 0x20 for character in value):
        raise FinalizerHandoffError(f"{label} must not contain control characters")
    return value


def _validate_source(value: Mapping[str, Any]) -> dict[str, Any]:
    source = dict(value)
    _require_exact_keys(source, _SOURCE_KEYS, "finalizer source")
    pr_number = source.get("pull_request_number")
    if type(pr_number) is not int or pr_number < 1 or pr_number > 2_147_483_647:
        raise FinalizerHandoffError(
            "source.pull_request_number must be an integer from 1 through 2147483647"
        )
    _bounded_string(source.get("workflow_run_id"), label="source.workflow_run_id", maximum=256)
    run_attempt = source.get("workflow_run_attempt")
    if type(run_attempt) is not int or run_attempt < 1 or run_attempt > 2_147_483_647:
        raise FinalizerHandoffError(
            "source.workflow_run_attempt must be an integer from 1 through 2147483647"
        )
    for field in ("base_sha", "head_sha"):
        item = source.get(field)
        if not isinstance(item, str) or _GIT_SHA.fullmatch(item) is None:
            raise FinalizerHandoffError(
                f"source.{field} must be a lowercase 40/64-character Git digest"
            )
    return source


def _validate_record_descriptor(value: Mapping[str, Any]) -> dict[str, Any]:
    record = dict(value)
    _require_exact_keys(record, _RECORD_KEYS, "finalizer handoff record")
    digest = record.get("sha256")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise FinalizerHandoffError(
            "finalizer handoff record.sha256 must be 64 lowercase hexadecimal characters"
        )
    size = record.get("size")
    if type(size) is not int or size < 1 or size > MAX_VERDICT_BYTES:
        raise FinalizerHandoffError(
            f"finalizer handoff record.size must be an integer from 1 through {MAX_VERDICT_BYTES}"
        )
    return record


def _validate_source_context(source: Mapping[str, Any], context: Mapping[str, Any]) -> None:
    for field in ("base_sha", "head_sha"):
        if context.get(field) != source.get(field):
            raise FinalizerHandoffError(
                f"source.{field} must exactly match context.{field}"
            )


def _record_snapshot(path: str) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    verdict_bytes = _read_regular_file(path, limit=MAX_VERDICT_BYTES, label="verdict")
    verdict = _load_json_object(verdict_bytes, "verdict")
    record_report = verify_record(verdict)
    if not record_report["ok"]:
        failed = [
            item["id"]
            for item in record_report["checks"]
            if item.get("status") == "fail"
        ]
        raise FinalizerHandoffError(
            "verdict record is semantically invalid: " + ", ".join(failed)
        )
    return verdict_bytes, verdict, record_report


def _write_canonical_handoff(path: str, payload: dict[str, Any], *, force: bool) -> str:
    absolute_output = os.path.abspath(path)
    parent = os.path.dirname(absolute_output) or os.curdir
    if os.path.isdir(absolute_output):
        raise FinalizerHandoffError(f"finalizer handoff output is a directory: {absolute_output}")
    os.makedirs(parent, exist_ok=True)
    data = _canonical_json(payload)
    if len(data) > MAX_FINALIZER_HANDOFF_BYTES:
        raise FinalizerHandoffError("canonical finalizer handoff exceeds its size limit")

    descriptor, temporary = tempfile.mkstemp(prefix=".evoguard-handoff-", dir=parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if force:
            os.replace(temporary, absolute_output)
        else:
            try:
                os.link(temporary, absolute_output, follow_symlinks=False)
            except FileExistsError as exc:
                raise FinalizerHandoffError(
                    f"refusing to overwrite existing finalizer handoff: {absolute_output}"
                ) from exc
            except OSError as exc:
                raise FinalizerHandoffError(
                    "cannot publish finalizer handoff with atomic no-clobber semantics; "
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


def create_finalizer_handoff(
    verdict_path: str,
    output_path: str,
    *,
    source: Mapping[str, Any],
    context: Mapping[str, Any],
    force: bool = False,
) -> dict[str, Any]:
    """Write a canonical descriptor that binds a record to trusted metadata.

    The caller must get ``source`` and the non-record portions of ``context``
    from a trusted control plane.  This writer validates record/context
    consistency, but does not treat the output as authenticated by itself.
    """

    verdict_bytes, verdict, _record_report = _record_snapshot(verdict_path)
    verified_context = validate_evidence_context(context, verdict=verdict)
    verified_source = _validate_source(source)
    _validate_source_context(verified_source, verified_context)
    payload = {
        "format": FINALIZER_HANDOFF_FORMAT,
        "source": verified_source,
        "context": verified_context,
        "record": {"sha256": _sha256(verdict_bytes), "size": len(verdict_bytes)},
    }
    _write_canonical_handoff(output_path, payload, force=force)
    return payload


def inspect_finalizer_handoff(path: str) -> InspectedFinalizerHandoff:
    """Check canonical handoff structure without treating it as trusted input."""

    handoff_bytes = _read_regular_file(
        path, limit=MAX_FINALIZER_HANDOFF_BYTES, label="finalizer handoff"
    )
    payload = _load_json_object(handoff_bytes, "finalizer handoff")
    if _canonical_json(payload) != handoff_bytes:
        raise FinalizerHandoffError("finalizer handoff is not canonical JSON")
    _require_exact_keys(payload, _HANDOFF_KEYS, "finalizer handoff")
    if payload.get("format") != FINALIZER_HANDOFF_FORMAT:
        raise FinalizerHandoffError(
            f"unsupported finalizer handoff format: {payload.get('format')!r}"
        )
    source = payload.get("source")
    context = payload.get("context")
    record = payload.get("record")
    if not isinstance(source, dict) or not isinstance(context, dict) or not isinstance(record, dict):
        raise FinalizerHandoffError("finalizer handoff source, context, and record must be objects")
    verified_source = _validate_source(source)
    try:
        verified_context = validate_evidence_context(context, verdict=None)
    except EvidenceBundleError as exc:
        raise FinalizerHandoffError(f"invalid finalizer handoff context: {exc}") from exc
    _validate_record_descriptor(record)
    _validate_source_context(verified_source, verified_context)
    return InspectedFinalizerHandoff(handoff_bytes=handoff_bytes, payload=payload)


def verify_finalizer_handoff(
    inspected: InspectedFinalizerHandoff,
    *,
    verdict_path: str,
    expected_source: Mapping[str, Any],
    expected_context: Mapping[str, Any],
) -> VerifiedFinalizerHandoff:
    """Require exact external source/context and exact semantic record bytes."""

    verified_source = _validate_source(expected_source)
    try:
        preliminary_context = validate_evidence_context(expected_context, verdict=None)
    except EvidenceBundleError as exc:
        raise FinalizerHandoffError(f"invalid expected finalizer context: {exc}") from exc
    _validate_source_context(verified_source, preliminary_context)
    if inspected.source != verified_source:
        raise FinalizerHandoffError("finalizer handoff source does not exactly match expected source")
    if inspected.context != preliminary_context:
        raise FinalizerHandoffError("finalizer handoff context does not exactly match expected context")

    verdict_bytes, verdict, record_report = _record_snapshot(verdict_path)
    descriptor = inspected.record
    if descriptor["sha256"] != _sha256(verdict_bytes) or descriptor["size"] != len(verdict_bytes):
        raise FinalizerHandoffError("finalizer handoff record does not match exact verdict bytes")
    try:
        verified_context = validate_evidence_context(preliminary_context, verdict=verdict)
        handoff_context = validate_evidence_context(inspected.context, verdict=verdict)
    except EvidenceBundleError as exc:
        raise FinalizerHandoffError(f"finalizer context does not bind the verdict: {exc}") from exc
    if handoff_context != verified_context:
        raise FinalizerHandoffError("finalizer handoff context changed during verification")
    return VerifiedFinalizerHandoff(
        inspection=inspected,
        verdict_bytes=verdict_bytes,
        verdict=verdict,
        record_report=record_report,
    )


def finalizer_decision(record: Mapping[str, Any]) -> str:
    """Return ``ALLOW`` only for a semantic Guard PASS; deny every other result."""

    return "ALLOW" if record.get("verdict") == "PASS" and record.get("passed") is True else "DENY"


@contextmanager
def _sealed_snapshots(
    *,
    verdict_bytes: bytes,
    handoff_bytes: bytes,
) -> Iterator[tuple[str, str]]:
    """Materialize already-verified bytes for the bundle writer without reuse.

    The files live in a private system temporary directory and are removed
    immediately after use. This prevents a sealing call from reopening an
    attacker-controlled artifact path after verification and lets an offline
    verifier authenticate a bundle stored in a read-only directory.
    """

    with tempfile.TemporaryDirectory(prefix=".evoguard-finalizer-") as directory:
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


def seal_finalizer_bundle(
    handoff_path: str,
    verdict_path: str,
    output_path: str,
    *,
    expected_source: Mapping[str, Any],
    expected_context: Mapping[str, Any],
    private_key_path: str,
    expected_derivation: Mapping[str, Any] | None = None,
    materials: Iterable[EvidenceMaterial] = (),
    force: bool = False,
) -> FinalizedTrustedEvidence:
    """Validate the handoff first, then seal its exact record and descriptor.

    The Ed25519 key is reached only inside :func:`finalize_evidence_bundle`,
    after both the external control-plane data and the record bytes passed every
    binding check.  Call this from a job that never checks out or executes the
    candidate; this library cannot enforce that workflow boundary itself.
    """

    inspected = inspect_finalizer_handoff(handoff_path)
    handoff = verify_finalizer_handoff(
        inspected,
        verdict_path=verdict_path,
        expected_source=expected_source,
        expected_context=expected_context,
    )
    if expected_derivation is not None:
        from evoom_guard.finalizer_derivation import (
            FinalizerDerivationError,
            context_from_verified_bindings,
            validate_finalizer_bindings,
        )

        try:
            derived_source, derived_context = context_from_verified_bindings(
                validate_finalizer_bindings(expected_derivation), handoff.verdict
            )
        except FinalizerDerivationError as exc:
            raise FinalizerHandoffError(
                f"independent finalizer derivation did not bind the record: {exc}"
            ) from exc
        if derived_source != dict(expected_source) or derived_context != dict(expected_context):
            raise FinalizerHandoffError(
                "independent finalizer derivation does not exactly match expected metadata"
            )
    caller_materials = tuple(materials)
    if any(material.role == FINALIZER_HANDOFF_ROLE for material in caller_materials):
        raise FinalizerHandoffError(
            f"material role {FINALIZER_HANDOFF_ROLE!r} is reserved for the verified handoff"
        )

    with _sealed_snapshots(
        verdict_bytes=handoff.verdict_bytes,
        handoff_bytes=inspected.handoff_bytes,
    ) as (record_snapshot, handoff_snapshot):
        try:
            finalized = finalize_evidence_bundle(
                record_snapshot,
                output_path,
                expected_context=expected_context,
                private_key_path=private_key_path,
                materials=(
                    EvidenceMaterial(
                        role=FINALIZER_HANDOFF_ROLE,
                        source_path=handoff_snapshot,
                    ),
                    *caller_materials,
                ),
                force=force,
            )
        except EvidenceBundleError as exc:
            raise FinalizerHandoffError(f"could not seal finalizer evidence bundle: {exc}") from exc

    sealed = inspect_evidence_bundle(finalized.bundle_path)
    try:
        verify_bundle_context(sealed, expected_context=expected_context)
    except EvidenceBundleError as exc:
        raise FinalizerHandoffError(f"sealed bundle context mismatch: {exc}") from exc
    handoff_materials = sealed.materials_for(FINALIZER_HANDOFF_ROLE)
    if len(handoff_materials) != 1 or handoff_materials[0].data != inspected.handoff_bytes:
        raise FinalizerHandoffError("sealed bundle did not preserve the exact verified handoff")
    if sealed.verdict_bytes != handoff.verdict_bytes:
        raise FinalizerHandoffError("sealed bundle verdict differs from the verified handoff record")
    if finalized.decision != finalizer_decision(handoff.verdict):
        raise FinalizerHandoffError("sealed bundle admission decision is inconsistent with its verdict")
    return FinalizedTrustedEvidence(finalized=finalized, handoff=handoff)


def verify_finalized_bundle(
    bundle_path: str,
    *,
    trusted_public_key_path: str,
    expected_source: Mapping[str, Any],
    expected_context: Mapping[str, Any],
) -> VerifiedFinalizedBundle:
    """Verify signature, context, exact handoff, record, and admission decision."""

    try:
        inspected_bundle = inspect_evidence_bundle(bundle_path)
        verify_bundle_signature(inspected_bundle, trusted_public_key_path=trusted_public_key_path)
        verify_bundle_context(inspected_bundle, expected_context=expected_context)
    except EvidenceBundleError as exc:
        raise FinalizerHandoffError(f"finalized evidence bundle is invalid: {exc}") from exc
    record_report = verify_record(inspected_bundle.verdict)
    if not record_report["ok"]:
        raise FinalizerHandoffError("finalized evidence bundle contains an invalid verdict record")
    handoff_materials = inspected_bundle.materials_for(FINALIZER_HANDOFF_ROLE)
    if len(handoff_materials) != 1:
        raise FinalizerHandoffError(
            f"finalized evidence bundle must contain exactly one {FINALIZER_HANDOFF_ROLE!r} material"
        )

    with _sealed_snapshots(
        verdict_bytes=inspected_bundle.verdict_bytes,
        handoff_bytes=handoff_materials[0].data,
    ) as (record_snapshot, handoff_snapshot):
        handoff = verify_finalizer_handoff(
            inspect_finalizer_handoff(handoff_snapshot),
            verdict_path=record_snapshot,
            expected_source=expected_source,
            expected_context=expected_context,
        )
    return VerifiedFinalizedBundle(
        bundle=VerifiedBundle(
            authenticated=AuthenticatedBundle(inspection=inspected_bundle),
            record_report=record_report,
        ),
        handoff=handoff,
        decision=finalizer_decision(inspected_bundle.verdict),
    )
