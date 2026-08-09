# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Canonical authenticated-producer receipt V2 for maintenance sources.

The receipt is an attestation subject, not an EvoGuard admission.  Its subject
contains the maintenance base and target source, while the producer identity is
bound to workflow bytes from the separately trusted default-branch object.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from evoom_guard.maintenance_bindings import (
    MAX_HANDOFF_BYTES,
    MAX_VERDICT_BYTES,
    MaintenanceBindingError,
    canonical_validated_bytes,
    require_trusted_workflow_material_v2,
    validate_release_source_context_v2,
    validate_release_source_v2,
    validate_run,
)

RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT_V2 = "EVOGUARD_RELEASE_SOURCE_PRODUCER_RECEIPT_V2"
RELEASE_SOURCE_PRODUCER_RUNTIME_FORMAT_V2 = "EVOGUARD_GUARD_ZIPAPP_SHA256_V2"

_GIT_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_NUMERIC_ID = re.compile(r"[1-9][0-9]{0,255}\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}\Z")
_WORKFLOW_PATH = re.compile(r"\.github/workflows/[A-Za-z0-9][A-Za-z0-9_.-]*\.ya?ml\Z")

_RECEIPT_KEYS = {
    "format",
    "subject",
    "context",
    "upstream",
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
    "workflow_tree_sha",
    "upstream_run_id",
    "upstream_run_attempt",
    "runner_class",
}


class ReleaseSourceProducerReceiptV2Error(MaintenanceBindingError):
    """A maintenance producer receipt is structurally unsafe or mismatched."""


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseSourceProducerReceiptV2Error(f"{label} must be an object")
    return dict(value)


def _exact(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ReleaseSourceProducerReceiptV2Error(f"{label} keys are not exact")


def _matched(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ReleaseSourceProducerReceiptV2Error(f"{label} is not canonical")
    return value


def _descriptor(value: object, *, label: str, maximum_size: int) -> dict[str, Any]:
    descriptor = _object(value, label)
    _exact(descriptor, _DESCRIPTOR_KEYS, label)
    size = descriptor["size"]
    if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= maximum_size:
        raise ReleaseSourceProducerReceiptV2Error(f"{label}.size is outside the supported range")
    return {
        "sha256": _matched(descriptor["sha256"], _SHA256, f"{label}.sha256"),
        "size": size,
    }


def _bootstrap(value: object) -> dict[str, str]:
    bootstrap = _object(value, "producer receipt V2 bootstrap")
    _exact(bootstrap, _BOOTSTRAP_KEYS, "producer receipt V2 bootstrap")
    if bootstrap["runtime_identity_format"] != RELEASE_SOURCE_PRODUCER_RUNTIME_FORMAT_V2:
        raise ReleaseSourceProducerReceiptV2Error(
            "producer receipt V2 bootstrap runtime format is not V2"
        )
    return {
        "runtime_identity_format": RELEASE_SOURCE_PRODUCER_RUNTIME_FORMAT_V2,
        "guard_artifact_sha256": _matched(
            bootstrap["guard_artifact_sha256"],
            _SHA256,
            "producer receipt V2 bootstrap.guard_artifact_sha256",
        ),
    }


def _execution(value: object) -> dict[str, Any]:
    execution = _object(value, "producer receipt V2 execution")
    _exact(execution, _EXECUTION_KEYS, "producer receipt V2 execution")
    expected = {
        "outcome": "PASS",
        "guard_exit_code": 0,
        "network": "none",
        "report_integrity": "external_process_isolated",
        "overall_profile": "black_box_external_judge",
    }
    for key, wanted in expected.items():
        if (
            execution[key] != wanted
            or isinstance(execution[key], bool)
            and key == "guard_exit_code"
        ):
            raise ReleaseSourceProducerReceiptV2Error(
                f"producer receipt V2 execution.{key} is not {wanted!r}"
            )
    isolation = execution["candidate_isolation"]
    if isolation not in {"docker", "gvisor"}:
        raise ReleaseSourceProducerReceiptV2Error(
            "producer receipt V2 candidate isolation must be docker or gvisor"
        )
    return {**expected, "candidate_isolation": isolation}


def validate_release_source_producer_v2(
    value: Mapping[str, Any], *, source: Mapping[str, Any], upstream: Mapping[str, Any]
) -> dict[str, Any]:
    producer = _object(value, "release-source producer V2")
    _exact(producer, _PRODUCER_KEYS, "release-source producer V2")
    attempt = producer["workflow_run_attempt"]
    upstream_attempt = producer["upstream_run_attempt"]
    for raw, label in (
        (attempt, "producer.workflow_run_attempt"),
        (upstream_attempt, "producer.upstream_run_attempt"),
    ):
        if isinstance(raw, bool) or not isinstance(raw, int) or not 1 <= raw <= 2_147_483_647:
            raise ReleaseSourceProducerReceiptV2Error(f"{label} is outside the supported range")
    checked = {
        "workflow_repository": _matched(
            producer["workflow_repository"], _REPOSITORY, "producer.workflow_repository"
        ),
        "workflow_repository_id": _matched(
            producer["workflow_repository_id"], _NUMERIC_ID, "producer.workflow_repository_id"
        ),
        "workflow_id": _matched(producer["workflow_id"], _NUMERIC_ID, "producer.workflow_id"),
        "workflow_path": _matched(
            producer["workflow_path"], _WORKFLOW_PATH, "producer.workflow_path"
        ),
        "workflow_blob_sha": _matched(
            producer["workflow_blob_sha"], _GIT_SHA, "producer.workflow_blob_sha"
        ),
        "workflow_run_id": _matched(
            producer["workflow_run_id"], _NUMERIC_ID, "producer.workflow_run_id"
        ),
        "workflow_run_attempt": attempt,
        "workflow_event": producer["workflow_event"],
        "workflow_ref": producer["workflow_ref"],
        "workflow_commit_sha": _matched(
            producer["workflow_commit_sha"], _GIT_SHA, "producer.workflow_commit_sha"
        ),
        "workflow_tree_sha": _matched(
            producer["workflow_tree_sha"], _GIT_SHA, "producer.workflow_tree_sha"
        ),
        "upstream_run_id": _matched(
            producer["upstream_run_id"], _NUMERIC_ID, "producer.upstream_run_id"
        ),
        "upstream_run_attempt": upstream_attempt,
        "runner_class": producer["runner_class"],
    }
    fixed = {
        "workflow_repository": source["repository"],
        "workflow_repository_id": source["repository_id"],
        "workflow_event": "workflow_run",
        "workflow_ref": source["trusted_workflow_ref"],
        "workflow_commit_sha": source["trusted_workflow_sha"],
        "workflow_tree_sha": source["trusted_workflow_tree"],
        "upstream_run_id": upstream["run_id"],
        "upstream_run_attempt": upstream["run_attempt"],
        "runner_class": "github-hosted",
    }
    for key, wanted in fixed.items():
        if checked[key] != wanted:
            raise ReleaseSourceProducerReceiptV2Error(
                f"producer.{key} does not match trusted source/upstream identity"
            )
    return checked


def validate_release_source_producer_receipt_v2(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    receipt = _object(value, "release-source producer receipt V2")
    _exact(receipt, _RECEIPT_KEYS, "release-source producer receipt V2")
    if receipt["format"] != RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT_V2:
        raise ReleaseSourceProducerReceiptV2Error(
            "unsupported release-source producer receipt V2 format"
        )
    try:
        source = validate_release_source_v2(_object(receipt["subject"], "receipt.subject"))
        context = validate_release_source_context_v2(_object(receipt["context"], "receipt.context"))
        upstream = validate_run(
            _object(receipt["upstream"], "receipt.upstream"), label="receipt.upstream"
        )
    except MaintenanceBindingError as exc:
        raise ReleaseSourceProducerReceiptV2Error(str(exc)) from exc
    if context["source"] != source:
        raise ReleaseSourceProducerReceiptV2Error(
            "producer receipt V2 subject does not match context source"
        )
    if context["evaluation"] != upstream:
        raise ReleaseSourceProducerReceiptV2Error(
            "producer receipt V2 upstream does not match evaluation"
        )
    producer = validate_release_source_producer_v2(
        _object(receipt["producer"], "receipt.producer"),
        source=source,
        upstream=upstream,
    )
    try:
        require_trusted_workflow_material_v2(
            workflow_path=producer["workflow_path"],
            workflow_blob_sha=producer["workflow_blob_sha"],
            trusted_inputs=context["trusted_inputs"],
            label="producer",
        )
    except MaintenanceBindingError as exc:
        raise ReleaseSourceProducerReceiptV2Error(str(exc)) from exc
    return {
        "format": RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT_V2,
        "subject": source,
        "context": context,
        "upstream": upstream,
        "record": _descriptor(
            receipt["record"], label="receipt.record", maximum_size=MAX_VERDICT_BYTES
        ),
        "handoff": _descriptor(
            receipt["handoff"], label="receipt.handoff", maximum_size=MAX_HANDOFF_BYTES
        ),
        "bootstrap": _bootstrap(receipt["bootstrap"]),
        "execution": _execution(receipt["execution"]),
        "producer": producer,
    }


def canonical_release_source_producer_receipt_v2_bytes(
    value: Mapping[str, Any],
) -> bytes:
    return canonical_validated_bytes(value, validator=validate_release_source_producer_receipt_v2)
