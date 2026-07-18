# -----------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Authenticated-producer receipt primitives for protected-main source evidence.

This module deliberately does **not** turn
``release_source_finalizer`` V1 into an admitting gate.  A canonical receipt is
only a claim until a separate, protected workflow obtains a *fresh* GitHub
Artifact Attestation verification for its exact bytes.  The safe topology is:

``unprivileged reverify`` -> ``workflow_run receipt producer`` ->
``provider attestation`` -> ``future separately-keyed admission finalizer``.

The candidate-executing job never receives ``id-token: write``,
``attestations: write``, a producer key, or an admission key.  The producer
workflow re-derives raw Git bindings and validates the record before it creates
the canonical receipt.  A future admission finalizer must repeat those checks
and freshly reverify the provider attestation before it opens an admission key.

The functions here implement the first two, non-admitting pieces.  They make a
future ``ALLOW`` *possible* without making a local JSON file authority today.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from evoom_guard.evidence_bundle import (
    MAX_VERDICT_BYTES,
    EvidenceBundleError,
    _canonical_json,
    _load_json_object,
    _read_regular_file,
)
from evoom_guard.evidence_bundle import (
    _sha256 as _sha256_bytes,
)
from evoom_guard.github_attestation import (
    GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
    CreatedGitHubAttestationReceipt,
    GitHubAttestationError,
    GitHubAttestationPolicy,
    create_github_attestation_receipt,
    github_attestation_policy,
)
from evoom_guard.release_source_finalizer import (
    MAX_RELEASE_SOURCE_HANDOFF_BYTES,
    DerivedReleaseSourceBindings,
    ReleaseSourceFinalizerError,
    VerifiedReleaseSourceHandoff,
    _publish_bytes,
    _validate_source_context,
    context_from_release_source_bindings,
    derive_release_source_bindings,
    inspect_release_source_handoff,
    validate_release_source,
    validate_release_source_context,
    verify_release_source_handoff,
)

RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT = "EVOGUARD_RELEASE_SOURCE_PRODUCER_RECEIPT_V1"
RELEASE_SOURCE_PRODUCER_RUNTIME_FORMAT = "EVOGUARD_GUARD_ZIPAPP_SHA256_V1"

MAX_RELEASE_SOURCE_PRODUCER_RECEIPT_BYTES = 512 * 1024

_RECEIPT_KEYS = {
    "format",
    "source",
    "context",
    "record",
    "handoff",
    "bootstrap",
    "execution",
    "producer",
}
_DESCRIPTOR_KEYS = {"sha256", "size"}
_BOOTSTRAP_KEYS = {"runtime_identity_format", "guard_artifact_sha256"}
_EXECUTION_KEYS = {
    "outcome",
    "guard_exit_code",
    "candidate_isolation",
    "network",
    "report_integrity",
    "overall_profile",
}
_PRODUCER_KEYS = {
    "workflow_repository",
    "workflow_repository_id",
    "workflow_id",
    "workflow_path",
    "workflow_blob_sha",
    "workflow_run_id",
    "workflow_run_attempt",
    "workflow_event",
    "workflow_ref",
    "workflow_commit_sha",
    "trigger_workflow_id",
    "trigger_workflow_path",
    "trigger_workflow_blob_sha",
    "trigger_workflow_run_id",
    "trigger_workflow_run_attempt",
    "runner_class",
}


class ReleaseSourceProducerReceiptError(ValueError):
    """A producer receipt, its evidence, or its provider policy is unsafe."""


@dataclass(frozen=True)
class InspectedReleaseSourceProducerReceipt:
    """Canonical receipt bytes which have not yet been provider-authenticated."""

    receipt_bytes: bytes
    payload: dict[str, Any]

    @property
    def source(self) -> dict[str, Any]:
        return dict(self.payload["source"])

    @property
    def context(self) -> dict[str, Any]:
        return dict(self.payload["context"])

    @property
    def producer(self) -> dict[str, Any]:
        return dict(self.payload["producer"])


@dataclass(frozen=True)
class VerifiedReleaseSourceProducerReceipt:
    """Receipt whose bytes, raw Git, source, verdict and producer pins agree.

    This is deliberately still not a release ``ALLOW``.  It says that all local
    and raw-Git comparisons passed.  ``AttestedReleaseSourceProducerReceipt``
    additionally records a fresh provider verification of this exact receipt.
    """

    receipt: InspectedReleaseSourceProducerReceipt
    handoff: VerifiedReleaseSourceHandoff
    bindings: DerivedReleaseSourceBindings


@dataclass(frozen=True)
class AttestedReleaseSourceProducerReceipt:
    """A locally verified receipt plus one fresh GitHub provider verification."""

    verified: VerifiedReleaseSourceProducerReceipt
    github_receipt: CreatedGitHubAttestationReceipt


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ReleaseSourceProducerReceiptError(
            f"{label} keys are not canonical "
            f"(missing={sorted(expected - actual)}, unknown={sorted(actual - expected)})"
        )


def _validate_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ReleaseSourceProducerReceiptError(f"{label} must be a lowercase SHA-256 digest")
    if any(character not in "0123456789abcdef" for character in value):
        raise ReleaseSourceProducerReceiptError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _numeric_id(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256 or not value.isascii():
        raise ReleaseSourceProducerReceiptError(f"{label} must be a non-zero decimal identifier")
    if not value.isdecimal() or value.startswith("0"):
        raise ReleaseSourceProducerReceiptError(f"{label} must be a non-zero decimal identifier")
    return value


def _validated_attempt(value: object, *, label: str) -> int:
    if type(value) is not int or not 1 <= value <= 2_147_483_647:
        raise ReleaseSourceProducerReceiptError(
            f"{label} must be an integer from 1 through 2147483647"
        )
    return value


def _git_sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or len(value) not in {40, 64}:
        raise ReleaseSourceProducerReceiptError(
            f"{label} must be a lowercase 40/64-character immutable Git digest"
        )
    if any(character not in "0123456789abcdef" for character in value):
        raise ReleaseSourceProducerReceiptError(
            f"{label} must be a lowercase 40/64-character immutable Git digest"
        )
    return value


def _bounded_text(value: object, *, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ReleaseSourceProducerReceiptError(
            f"{label} must be a non-empty string of at most {maximum} characters"
        )
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ReleaseSourceProducerReceiptError(f"{label} has invalid Unicode") from exc
    if any(ord(character) < 0x20 for character in value):
        raise ReleaseSourceProducerReceiptError(f"{label} must not contain control characters")
    return value


def _workflow_path(value: object, *, label: str) -> str:
    path = _bounded_text(value, label=label, maximum=256)
    if not path.startswith(".github/workflows/") or not path.endswith((".yml", ".yaml")):
        raise ReleaseSourceProducerReceiptError(
            f"{label} must be a canonical .github/workflows/*.yml path"
        )
    if any(part in {"", ".", ".."} for part in path.split("/")):
        raise ReleaseSourceProducerReceiptError(f"{label} has an unsafe path segment")
    return path


def _descriptor(value: Mapping[str, Any], *, label: str, maximum_size: int) -> dict[str, Any]:
    descriptor = dict(value)
    _require_exact_keys(descriptor, _DESCRIPTOR_KEYS, label)
    size = descriptor.get("size")
    if type(size) is not int or not 1 <= size <= maximum_size:
        raise ReleaseSourceProducerReceiptError(
            f"{label}.size must be an integer from 1 through {maximum_size}"
        )
    return {
        "sha256": _validate_sha256(descriptor.get("sha256"), label=f"{label}.sha256"),
        "size": size,
    }


def _validate_bootstrap(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ReleaseSourceProducerReceiptError("producer receipt bootstrap must be an object")
    bootstrap = dict(value)
    _require_exact_keys(bootstrap, _BOOTSTRAP_KEYS, "producer receipt bootstrap")
    if bootstrap.get("runtime_identity_format") != RELEASE_SOURCE_PRODUCER_RUNTIME_FORMAT:
        raise ReleaseSourceProducerReceiptError(
            f"producer receipt bootstrap.runtime_identity_format must be "
            f"{RELEASE_SOURCE_PRODUCER_RUNTIME_FORMAT!r}"
        )
    return {
        "runtime_identity_format": RELEASE_SOURCE_PRODUCER_RUNTIME_FORMAT,
        "guard_artifact_sha256": _validate_sha256(
            bootstrap.get("guard_artifact_sha256"),
            label="producer receipt bootstrap.guard_artifact_sha256",
        ),
    }


def validate_release_source_producer(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate an exact workflow identity expected by a protected finalizer."""

    producer = dict(value)
    _require_exact_keys(producer, _PRODUCER_KEYS, "release-source producer")
    workflow_path = _workflow_path(producer.get("workflow_path"), label="producer.workflow_path")
    trigger_workflow_path = _workflow_path(
        producer.get("trigger_workflow_path"), label="producer.trigger_workflow_path"
    )
    if producer.get("workflow_event") != "workflow_run":
        raise ReleaseSourceProducerReceiptError(
            "producer.workflow_event must be exactly 'workflow_run'"
        )
    if producer.get("workflow_ref") != "refs/heads/main":
        raise ReleaseSourceProducerReceiptError(
            "producer.workflow_ref must be exactly 'refs/heads/main'"
        )
    if producer.get("runner_class") != "github-hosted":
        raise ReleaseSourceProducerReceiptError(
            "producer.runner_class must be exactly 'github-hosted'"
        )
    attempt = _validated_attempt(
        producer.get("workflow_run_attempt"), label="producer.workflow_run_attempt"
    )
    return {
        "workflow_repository": _bounded_text(
            producer.get("workflow_repository"), label="producer.workflow_repository", maximum=512
        ),
        "workflow_repository_id": _numeric_id(
            producer.get("workflow_repository_id"), label="producer.workflow_repository_id"
        ),
        "workflow_id": _numeric_id(producer.get("workflow_id"), label="producer.workflow_id"),
        "workflow_path": workflow_path,
        "workflow_blob_sha": _git_sha(
            producer.get("workflow_blob_sha"), label="producer.workflow_blob_sha"
        ),
        "workflow_run_id": _numeric_id(
            producer.get("workflow_run_id"), label="producer.workflow_run_id"
        ),
        "workflow_run_attempt": attempt,
        "workflow_event": "workflow_run",
        "workflow_ref": "refs/heads/main",
        "workflow_commit_sha": _git_sha(
            producer.get("workflow_commit_sha"), label="producer.workflow_commit_sha"
        ),
        "trigger_workflow_id": _numeric_id(
            producer.get("trigger_workflow_id"), label="producer.trigger_workflow_id"
        ),
        "trigger_workflow_path": trigger_workflow_path,
        "trigger_workflow_blob_sha": _git_sha(
            producer.get("trigger_workflow_blob_sha"),
            label="producer.trigger_workflow_blob_sha",
        ),
        "trigger_workflow_run_id": _numeric_id(
            producer.get("trigger_workflow_run_id"),
            label="producer.trigger_workflow_run_id",
        ),
        "trigger_workflow_run_attempt": _validated_attempt(
            producer.get("trigger_workflow_run_attempt"),
            label="producer.trigger_workflow_run_attempt",
        ),
        "runner_class": "github-hosted",
    }


def _validate_execution(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseSourceProducerReceiptError("producer receipt execution must be an object")
    execution = dict(value)
    _require_exact_keys(execution, _EXECUTION_KEYS, "producer receipt execution")
    if execution.get("outcome") != "PASS" or execution.get("guard_exit_code") != 0:
        raise ReleaseSourceProducerReceiptError(
            "producer receipt execution must record outcome PASS and guard_exit_code 0"
        )
    isolation = execution.get("candidate_isolation")
    if isolation not in {"docker", "gvisor"}:
        raise ReleaseSourceProducerReceiptError(
            "producer receipt execution.candidate_isolation must be docker or gvisor"
        )
    if execution.get("network") != "none":
        raise ReleaseSourceProducerReceiptError("producer receipt execution.network must be 'none'")
    if execution.get("report_integrity") != "external_process_isolated":
        raise ReleaseSourceProducerReceiptError(
            "producer receipt execution.report_integrity must be external_process_isolated"
        )
    if execution.get("overall_profile") != "black_box_external_judge":
        raise ReleaseSourceProducerReceiptError(
            "producer receipt execution.overall_profile must be black_box_external_judge"
        )
    return {
        "outcome": "PASS",
        "guard_exit_code": 0,
        "candidate_isolation": isolation,
        "network": "none",
        "report_integrity": "external_process_isolated",
        "overall_profile": "black_box_external_judge",
    }


def _validate_allow_record(record: Mapping[str, Any], context: Mapping[str, Any]) -> dict[str, Any]:
    """Require the strong execution profile that a future admission could use.

    This checks the semantic record in addition to the receipt's own execution
    claim.  It still cannot authenticate who wrote the record; that is what the
    separate provider attestation and topology are for.
    """

    if record.get("verdict") != "PASS":
        raise ReleaseSourceProducerReceiptError("producer receipt requires verdict PASS")
    attestation = record.get("attestation")
    assurance = record.get("assurance")
    if not isinstance(attestation, dict) or not isinstance(assurance, dict):
        raise ReleaseSourceProducerReceiptError(
            "producer receipt requires verdict attestation and assurance objects"
        )
    effective_policy = attestation.get("effective_policy")
    if not isinstance(effective_policy, dict):
        raise ReleaseSourceProducerReceiptError(
            "producer receipt requires a complete effective policy object"
        )
    required_policy = {
        "blackbox": True,
        "blackbox_only": True,
        "require_report_integrity": "external_process_isolated",
        "docker_network": "none",
    }
    for field, expected in required_policy.items():
        if effective_policy.get(field) != expected:
            raise ReleaseSourceProducerReceiptError(
                f"producer receipt requires effective_policy.{field}={expected!r}"
            )
    isolation = assurance.get("candidate_isolation")
    if isolation not in {"docker", "gvisor"}:
        raise ReleaseSourceProducerReceiptError(
            "producer receipt requires docker or gvisor candidate isolation"
        )
    required_assurance = {
        "execution_state": "completed",
        "execution_phase": "blackbox_pack",
        "suite_isolation": isolation,
        "report_integrity": "external_process_isolated",
        "overall_profile": "black_box_external_judge",
    }
    for field, expected in required_assurance.items():
        if assurance.get(field) != expected:
            raise ReleaseSourceProducerReceiptError(
                f"producer receipt requires assurance.{field}={expected!r}"
            )
    pack = assurance.get("verifier_pack")
    if not isinstance(pack, dict):
        raise ReleaseSourceProducerReceiptError("producer receipt requires a verifier-pack assurance")
    for field, expected in {
        "configured": True,
        "present": True,
        "identity_verified": True,
        "execution_state": "completed",
        "secrecy": "unmounted_from_candidate",
    }.items():
        if pack.get(field) != expected:
            raise ReleaseSourceProducerReceiptError(
                f"producer receipt requires verifier_pack.{field}={expected!r}"
            )
    if pack.get("snapshot_sha256") != context["verifier_pack_sha256"]:
        raise ReleaseSourceProducerReceiptError(
            "producer receipt verifier-pack snapshot does not match release-source context"
        )
    return {
        "candidate_isolation": isolation,
        "network": "none",
        "report_integrity": "external_process_isolated",
        "overall_profile": "black_box_external_judge",
    }


def _validate_source_context_producer(
    source: Mapping[str, Any], context: Mapping[str, Any], producer: Mapping[str, Any]
) -> None:
    _validate_source_context(source, context)
    pairs = {
        "repository": "workflow_repository",
        "repository_id": "workflow_repository_id",
        "workflow_run_id": "trigger_workflow_run_id",
        "workflow_run_attempt": "trigger_workflow_run_attempt",
        "target_commit_sha": "workflow_commit_sha",
    }
    for source_key, producer_key in pairs.items():
        if source[source_key] != producer[producer_key]:
            raise ReleaseSourceProducerReceiptError(
                f"release source.{source_key} does not match producer.{producer_key}"
            )
    if producer["workflow_id"] == producer["trigger_workflow_id"]:
        raise ReleaseSourceProducerReceiptError(
            "producer workflow must be distinct from the unprivileged reverify workflow"
        )
    if producer["workflow_path"] == producer["trigger_workflow_path"]:
        raise ReleaseSourceProducerReceiptError(
            "producer workflow path must be distinct from the unprivileged reverify workflow"
        )
    if producer["workflow_run_id"] == producer["trigger_workflow_run_id"]:
        raise ReleaseSourceProducerReceiptError(
            "producer workflow run must be distinct from the unprivileged reverify run"
        )


def _verify_producer_workflow_blobs(
    *,
    source: Mapping[str, Any],
    producer: Mapping[str, Any],
    git_repository: str,
    git_repository_is_bare: bool,
) -> None:
    """Bind both workflow definitions to the raw protected-main tree.

    The receipt producer (B) and the candidate-executing reverify workflow (A)
    have distinct numeric IDs, paths, and raw-Git blobs.  Names alone are not
    selectors.  Their paths' *bytes* are resolved from the same immutable tree
    used for the release-source derivation; no checkout/import/execution is
    involved here.
    """

    try:
        from evoom_guard.finalizer_derivation import FinalizerDerivationError, _GitReader

        reader = _GitReader(git_repository, bare=git_repository_is_bare)
        tree = reader.tree(str(source["target_tree_sha"]))
    except FinalizerDerivationError as exc:
        raise ReleaseSourceProducerReceiptError(
            f"could not resolve producer workflow from raw Git: {exc}"
        ) from exc
    for role, path_key, blob_key in (
        ("producer", "workflow_path", "workflow_blob_sha"),
        ("trigger", "trigger_workflow_path", "trigger_workflow_blob_sha"),
    ):
        entry = tree.get(str(producer[path_key]))
        if entry is None or not entry.regular:
            raise ReleaseSourceProducerReceiptError(
                f"{role} workflow path is not a regular blob in the protected-main tree"
            )
        if entry.object_id != producer[blob_key]:
            raise ReleaseSourceProducerReceiptError(
                f"{role} workflow blob does not match the protected-main raw Git tree"
            )


def validate_release_source_producer_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the closed-world canonical receipt shape without trusting it."""

    receipt = dict(value)
    _require_exact_keys(receipt, _RECEIPT_KEYS, "release-source producer receipt")
    if receipt.get("format") != RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT:
        raise ReleaseSourceProducerReceiptError(
            f"unsupported producer receipt format: {receipt.get('format')!r}"
        )
    source_value = receipt.get("source")
    context_value = receipt.get("context")
    record_value = receipt.get("record")
    handoff_value = receipt.get("handoff")
    producer_value = receipt.get("producer")
    if not (
        isinstance(source_value, dict)
        and isinstance(context_value, dict)
        and isinstance(record_value, dict)
        and isinstance(handoff_value, dict)
        and isinstance(producer_value, dict)
    ):
        raise ReleaseSourceProducerReceiptError(
            "producer receipt source, context, record, handoff, and producer must be objects"
        )
    source = validate_release_source(source_value)
    context = validate_release_source_context(context_value)
    producer = validate_release_source_producer(producer_value)
    _validate_source_context_producer(source, context, producer)
    return {
        "format": RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT,
        "source": source,
        "context": context,
        "record": _descriptor(record_value, label="producer receipt record", maximum_size=MAX_VERDICT_BYTES),
        "handoff": _descriptor(
            handoff_value,
            label="producer receipt handoff",
            maximum_size=MAX_RELEASE_SOURCE_HANDOFF_BYTES,
        ),
        "bootstrap": _validate_bootstrap(receipt.get("bootstrap")),
        "execution": _validate_execution(receipt.get("execution")),
        "producer": producer,
    }


def inspect_release_source_producer_receipt(path: str) -> InspectedReleaseSourceProducerReceipt:
    """Read canonical producer-receipt bytes without treating them as authority."""

    try:
        receipt_bytes = _read_regular_file(
            path,
            limit=MAX_RELEASE_SOURCE_PRODUCER_RECEIPT_BYTES,
            label="release-source producer receipt",
        )
        payload = _load_json_object(receipt_bytes, "release-source producer receipt")
        checked = validate_release_source_producer_receipt(payload)
        if _canonical_json(checked) != receipt_bytes:
            raise ReleaseSourceProducerReceiptError(
                "release-source producer receipt is not canonical JSON"
            )
    except (EvidenceBundleError, ReleaseSourceFinalizerError) as exc:
        raise ReleaseSourceProducerReceiptError(str(exc)) from exc
    except ValueError as exc:
        raise ReleaseSourceProducerReceiptError(str(exc)) from exc
    return InspectedReleaseSourceProducerReceipt(receipt_bytes=receipt_bytes, payload=checked)


def create_release_source_producer_receipt(
    verdict_path: str,
    handoff_path: str,
    output_path: str,
    *,
    source: Mapping[str, Any],
    context: Mapping[str, Any],
    bootstrap_guard_sha256: str,
    producer: Mapping[str, Any],
    git_repository: str,
    git_repository_is_bare: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    """Create an unsigned canonical producer claim for a clean receipt job.

    The function intentionally has no signing-key parameter.  Calling it from a
    hostile context yields only data; the protected receipt workflow must later
    attest its exact bytes with GitHub and a future finalizer must freshly verify
    that provider assertion before any admission key is available.
    """

    checked_source = validate_release_source(source)
    checked_context = validate_release_source_context(context)
    checked_producer = validate_release_source_producer(producer)
    _validate_source_context_producer(checked_source, checked_context, checked_producer)
    try:
        bindings = derive_release_source_bindings(
            git_repository=git_repository,
            source=checked_source,
            git_repository_is_bare=git_repository_is_bare,
        )
        inspected_handoff = inspect_release_source_handoff(handoff_path)
        handoff = verify_release_source_handoff(
            inspected_handoff,
            verdict_path=verdict_path,
            expected_source=checked_source,
            expected_context=checked_context,
        )
    except ReleaseSourceFinalizerError as exc:
        raise ReleaseSourceProducerReceiptError(str(exc)) from exc
    derived_context = context_from_release_source_bindings(bindings, handoff.verdict)
    if derived_context != checked_context:
        raise ReleaseSourceProducerReceiptError(
            "trusted raw-Git derivation does not exactly match release-source context"
        )
    _verify_producer_workflow_blobs(
        source=checked_source,
        producer=checked_producer,
        git_repository=git_repository,
        git_repository_is_bare=git_repository_is_bare,
    )
    profile = _validate_allow_record(handoff.verdict, checked_context)
    payload = {
        "format": RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT,
        "source": checked_source,
        "context": checked_context,
        "record": {
            "sha256": _sha256_bytes(handoff.verdict_bytes),
            "size": len(handoff.verdict_bytes),
        },
        "handoff": {
            "sha256": _sha256_bytes(inspected_handoff.handoff_bytes),
            "size": len(inspected_handoff.handoff_bytes),
        },
        "bootstrap": {
            "runtime_identity_format": RELEASE_SOURCE_PRODUCER_RUNTIME_FORMAT,
            "guard_artifact_sha256": _validate_sha256(
                bootstrap_guard_sha256, label="bootstrap guard artifact SHA-256"
            ),
        },
        "execution": {
            "outcome": "PASS",
            "guard_exit_code": 0,
            **profile,
        },
        "producer": checked_producer,
    }
    checked = validate_release_source_producer_receipt(payload)
    try:
        encoded = _canonical_json(checked)
    except ValueError as exc:
        raise ReleaseSourceProducerReceiptError(str(exc)) from exc
    if len(encoded) > MAX_RELEASE_SOURCE_PRODUCER_RECEIPT_BYTES:
        raise ReleaseSourceProducerReceiptError("canonical producer receipt exceeds its size limit")
    _publish_bytes(
        output_path,
        encoded,
        force=force,
        prefix=".evoguard-release-source-producer-receipt-",
        label="release-source producer receipt",
    )
    return checked


def verify_release_source_producer_receipt(
    receipt_path: str,
    handoff_path: str,
    verdict_path: str,
    *,
    expected_source: Mapping[str, Any],
    expected_context: Mapping[str, Any],
    expected_producer: Mapping[str, Any],
    expected_bootstrap_guard_sha256: str,
    git_repository: str,
    git_repository_is_bare: bool = False,
) -> VerifiedReleaseSourceProducerReceipt:
    """Repeat all source/record/raw-Git checks before a provider or key boundary."""

    source = validate_release_source(expected_source)
    context = validate_release_source_context(expected_context)
    producer = validate_release_source_producer(expected_producer)
    _validate_source_context_producer(source, context, producer)
    try:
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
    except ReleaseSourceFinalizerError as exc:
        raise ReleaseSourceProducerReceiptError(str(exc)) from exc
    if derived_context != context:
        raise ReleaseSourceProducerReceiptError(
            "trusted raw-Git derivation does not exactly match expected release-source context"
        )
    _verify_producer_workflow_blobs(
        source=source,
        producer=producer,
        git_repository=git_repository,
        git_repository_is_bare=git_repository_is_bare,
    )
    receipt = inspect_release_source_producer_receipt(receipt_path)
    if receipt.source != source or receipt.context != context or receipt.producer != producer:
        raise ReleaseSourceProducerReceiptError(
            "producer receipt does not exactly match expected source, context, or producer identity"
        )
    if receipt.payload["record"] != {
        "sha256": _sha256_bytes(handoff.verdict_bytes),
        "size": len(handoff.verdict_bytes),
    }:
        raise ReleaseSourceProducerReceiptError(
            "producer receipt record does not match exact verdict bytes"
        )
    if receipt.payload["handoff"] != {
        "sha256": _sha256_bytes(inspected_handoff.handoff_bytes),
        "size": len(inspected_handoff.handoff_bytes),
    }:
        raise ReleaseSourceProducerReceiptError(
            "producer receipt handoff does not match exact handoff bytes"
        )
    if receipt.payload["bootstrap"]["guard_artifact_sha256"] != _validate_sha256(
        expected_bootstrap_guard_sha256, label="expected bootstrap guard artifact SHA-256"
    ):
        raise ReleaseSourceProducerReceiptError(
            "producer receipt bootstrap runtime does not match the protected expected runtime"
        )
    profile = _validate_allow_record(handoff.verdict, context)
    expected_execution = {
        "outcome": "PASS",
        "guard_exit_code": 0,
        **profile,
    }
    if receipt.payload["execution"] != expected_execution:
        raise ReleaseSourceProducerReceiptError(
            "producer receipt execution claim does not match the exact semantic record"
        )
    return VerifiedReleaseSourceProducerReceipt(
        receipt=receipt,
        handoff=handoff,
        bindings=bindings,
    )


def _github_policy_from_mapping(value: Mapping[str, Any]) -> GitHubAttestationPolicy:
    policy = dict(value)
    expected = {
        "repository",
        "signer_workflow",
        "signer_digest",
        "source_ref",
        "source_digest",
        "cert_oidc_issuer",
    }
    _require_exact_keys(policy, expected, "expected GitHub producer-attestation policy")
    try:
        return github_attestation_policy(
            policy["repository"],
            policy["signer_workflow"],
            policy["source_digest"],
            signer_digest=policy["signer_digest"],
            source_ref=policy["source_ref"],
            cert_oidc_issuer=policy["cert_oidc_issuer"],
        )
    except GitHubAttestationError as exc:
        raise ReleaseSourceProducerReceiptError(str(exc)) from exc


def reverify_attested_release_source_producer_receipt(
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
    github_receipt_path: str,
    github_raw_output_path: str,
    git_repository_is_bare: bool = False,
    gh_executable: str = "gh",
    timeout_seconds: int = 120,
) -> AttestedReleaseSourceProducerReceipt:
    """Freshly verify the provider attestation only after exact local checks.

    No signing key is accepted or opened here.  The caller can use the returned
    object as a prerequisite for a future, separately scoped admission key.
    """

    verified = verify_release_source_producer_receipt(
        receipt_path,
        handoff_path,
        verdict_path,
        expected_source=expected_source,
        expected_context=expected_context,
        expected_producer=expected_producer,
        expected_bootstrap_guard_sha256=expected_bootstrap_guard_sha256,
        git_repository=git_repository,
        git_repository_is_bare=git_repository_is_bare,
    )
    policy = _github_policy_from_mapping(expected_github_policy)
    receipt = verified.receipt
    if policy.repository != receipt.source["repository"]:
        raise ReleaseSourceProducerReceiptError(
            "GitHub producer-attestation repository does not match receipt source"
        )
    if policy.source_ref != "refs/heads/main" or policy.source_digest != receipt.source[
        "target_commit_sha"
    ]:
        raise ReleaseSourceProducerReceiptError(
            "GitHub producer-attestation source pin does not match protected-main source"
        )
    expected_workflow = (
        f"{receipt.producer['workflow_repository']}/{receipt.producer['workflow_path']}"
    )
    if policy.signer_workflow != expected_workflow:
        raise ReleaseSourceProducerReceiptError(
            "GitHub producer-attestation signer workflow does not match receipt producer"
        )
    if policy.signer_digest != receipt.producer["workflow_commit_sha"]:
        raise ReleaseSourceProducerReceiptError(
            "GitHub producer-attestation signer digest does not match receipt producer"
        )
    if policy.cert_oidc_issuer != GITHUB_ATTESTATION_CERT_OIDC_ISSUER:
        raise ReleaseSourceProducerReceiptError("GitHub producer-attestation OIDC issuer is unsupported")
    try:
        github_receipt = create_github_attestation_receipt(
            receipt_path,
            github_receipt_path,
            github_raw_output_path,
            repository=policy.repository,
            signer_workflow=policy.signer_workflow,
            signer_digest=policy.signer_digest,
            source_ref=policy.source_ref,
            source_digest=policy.source_digest,
            cert_oidc_issuer=policy.cert_oidc_issuer,
            gh_executable=gh_executable,
            timeout_seconds=timeout_seconds,
        )
    except GitHubAttestationError as exc:
        raise ReleaseSourceProducerReceiptError(str(exc)) from exc
    return AttestedReleaseSourceProducerReceipt(verified=verified, github_receipt=github_receipt)
