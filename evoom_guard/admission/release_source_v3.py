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
"""Release Source Admission V3 protocol for a separated maintenance lane.

This module validates canonical manifests and cross-material bindings only.  It
does not call GitHub, inspect branch protection, open a signing key, or publish
anything.  A provider assertion must name the trusted workflow commit as both
``signer_digest`` and ``source_digest``; the maintenance target remains inside
the exact producer-receipt subject instead of masquerading as workflow source.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

from evoom_guard.maintenance_bindings import (
    MaintenanceBindingError,
    canonical_validated_bytes,
    require_canonical_bytes,
    require_trusted_workflow_material_v2,
    validate_release_source_context_v2,
    validate_release_source_v2,
    validate_run,
)
from evoom_guard.release_source_producer_receipt_v2 import (
    validate_release_source_producer_receipt_v2,
    validate_release_source_producer_v2,
)

RELEASE_SOURCE_ADMISSION_FORMAT_V3 = "EVOGUARD_RELEASE_SOURCE_ADMISSION_V3"
RELEASE_SOURCE_ADMISSION_SIGNATURE_PURPOSE_V3 = "evoguard-release-source-admission-v3"
RELEASE_SOURCE_ADMISSION_KEY_DOMAIN_V3 = "release-source-admission-v3"
RELEASE_SOURCE_ADMISSION_SIGNATURE_DOMAIN_V3 = (
    RELEASE_SOURCE_ADMISSION_FORMAT_V3.encode("ascii") + b"\0"
)

RELEASE_SOURCE_ADMISSION_SIGNATURE_PATH_V3 = "admission.sig"
RELEASE_SOURCE_ADMISSION_PRODUCER_RECEIPT_PATH_V3 = "materials/producer-receipt-v2.json"
RELEASE_SOURCE_ADMISSION_GITHUB_RECEIPT_PATH_V3 = "provider/github-attestation-receipt.json"
RELEASE_SOURCE_ADMISSION_GITHUB_OUTPUT_PATH_V3 = "provider/github-attestation-output.json"

MAX_PRODUCER_RECEIPT_BYTES_V2 = 512 * 1024
MAX_PROVIDER_RECEIPT_BYTES = 64 * 1024
MAX_PROVIDER_OUTPUT_BYTES = 4 * 1024 * 1024

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_KEY_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}\Z")

_MANIFEST_KEYS = {
    "format",
    "decision",
    "source",
    "context",
    "upstream",
    "producer",
    "admitter",
    "producer_receipt",
    "provider",
    "toolchain",
    "replay",
    "key_separation",
    "authentication",
}
_DESCRIPTOR_KEYS = {"path", "sha256", "size"}
_BYTE_DESCRIPTOR_KEYS = {"sha256", "size"}
_PROVIDER_KEYS = {
    "name",
    "artifact",
    "policy",
    "verified_attestation_count",
    "receipt",
    "raw_output",
}
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
_TOOLCHAIN_KEYS = {"git_sha256", "github_cli_sha256", "provider_isolation"}
_ISOLATION_KEYS = {"platform", "uid", "gid"}
_REPLAY_KEYS = {"evaluation", "producer", "admitter"}
_KEY_SEPARATION_KEYS = {
    "trusted_finalizer",
    "artifact_admission_v1",
    "artifact_digest_admission_v2",
    "release_source_finalizer_v1",
    "release_source_admission_v2",
    "release_source_finalizer_v2",
}
_AUTHENTICATION_KEYS = {
    "algorithm",
    "key_id",
    "purpose",
    "key_domain",
    "signature_path",
}


class ReleaseSourceAdmissionV3Error(MaintenanceBindingError):
    """A Release Source Admission V3 manifest or binding is unsafe."""


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseSourceAdmissionV3Error(f"{label} must be an object")
    return dict(value)


def _exact(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ReleaseSourceAdmissionV3Error(f"{label} keys are not exact")


def _matched(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ReleaseSourceAdmissionV3Error(f"{label} is not canonical")
    return value


def _size(value: object, *, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ReleaseSourceAdmissionV3Error(f"{label} is outside the supported range")
    return value


def _descriptor(
    value: object, *, label: str, path: str, maximum_size: int, minimum_size: int = 1
) -> dict[str, Any]:
    descriptor = _object(value, label)
    _exact(descriptor, _DESCRIPTOR_KEYS, label)
    if descriptor["path"] != path:
        raise ReleaseSourceAdmissionV3Error(f"{label}.path is not literal {path}")
    return {
        "path": path,
        "sha256": _matched(descriptor["sha256"], _SHA256, f"{label}.sha256"),
        "size": _size(
            descriptor["size"],
            label=f"{label}.size",
            minimum=minimum_size,
            maximum=maximum_size,
        ),
    }


def _byte_descriptor(value: object, *, label: str) -> dict[str, Any]:
    descriptor = _object(value, label)
    _exact(descriptor, _BYTE_DESCRIPTOR_KEYS, label)
    return {
        "sha256": _matched(descriptor["sha256"], _SHA256, f"{label}.sha256"),
        "size": _size(
            descriptor["size"],
            label=f"{label}.size",
            minimum=1,
            maximum=MAX_PRODUCER_RECEIPT_BYTES_V2,
        ),
    }


def _provider(
    value: object,
    *,
    source: Mapping[str, Any],
    producer: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    provider = _object(value, "release-source admission V3 provider")
    _exact(provider, _PROVIDER_KEYS, "release-source admission V3 provider")
    if provider["name"] != "github-artifact-attestations":
        raise ReleaseSourceAdmissionV3Error("provider name is not GitHub Artifact Attestations")
    artifact = _byte_descriptor(provider["artifact"], label="provider.artifact")
    if artifact != {"sha256": receipt["sha256"], "size": receipt["size"]}:
        raise ReleaseSourceAdmissionV3Error(
            "provider artifact does not bind the exact producer-receipt bytes"
        )
    if type(provider["verified_attestation_count"]) is not int or (
        provider["verified_attestation_count"] != 1
    ):
        raise ReleaseSourceAdmissionV3Error("provider must verify exactly one attestation")
    policy = _object(provider["policy"], "provider.policy")
    _exact(policy, _POLICY_KEYS, "provider.policy")
    checked_policy = {
        "repository": _matched(policy["repository"], _REPOSITORY, "provider.policy.repository"),
        "signer_workflow": policy["signer_workflow"],
        "signer_digest": _matched(
            policy["signer_digest"], _GIT_SHA, "provider.policy.signer_digest"
        ),
        "source_ref": policy["source_ref"],
        "source_digest": _matched(
            policy["source_digest"], _GIT_SHA, "provider.policy.source_digest"
        ),
        "cert_oidc_issuer": policy["cert_oidc_issuer"],
        "predicate_type": policy["predicate_type"],
        "deny_self_hosted_runners": policy["deny_self_hosted_runners"],
        "attestation_limit": policy["attestation_limit"],
    }
    if type(checked_policy["deny_self_hosted_runners"]) is not bool:
        raise ReleaseSourceAdmissionV3Error(
            "provider.policy.deny_self_hosted_runners must be a boolean"
        )
    if type(checked_policy["attestation_limit"]) is not int:
        raise ReleaseSourceAdmissionV3Error(
            "provider.policy.attestation_limit must be an integer"
        )
    fixed = {
        "repository": source["repository"],
        "signer_workflow": f"{source['repository']}/{producer['workflow_path']}",
        "signer_digest": source["trusted_workflow_sha"],
        "source_ref": source["trusted_workflow_ref"],
        "source_digest": source["trusted_workflow_sha"],
        "cert_oidc_issuer": "https://token.actions.githubusercontent.com",
        "predicate_type": "https://slsa.dev/provenance/v1",
        "deny_self_hosted_runners": True,
        "attestation_limit": 1,
    }
    if checked_policy != fixed:
        raise ReleaseSourceAdmissionV3Error(
            "provider policy is not bound to the trusted producer workflow commit"
        )
    return {
        "name": "github-artifact-attestations",
        "artifact": artifact,
        "policy": checked_policy,
        "verified_attestation_count": 1,
        "receipt": _descriptor(
            provider["receipt"],
            label="provider.receipt",
            path=RELEASE_SOURCE_ADMISSION_GITHUB_RECEIPT_PATH_V3,
            maximum_size=MAX_PROVIDER_RECEIPT_BYTES,
        ),
        "raw_output": _descriptor(
            provider["raw_output"],
            label="provider.raw_output",
            path=RELEASE_SOURCE_ADMISSION_GITHUB_OUTPUT_PATH_V3,
            maximum_size=MAX_PROVIDER_OUTPUT_BYTES,
            minimum_size=2,
        ),
    }


def _toolchain(value: object) -> dict[str, Any]:
    toolchain = _object(value, "release-source admission V3 toolchain")
    _exact(toolchain, _TOOLCHAIN_KEYS, "release-source admission V3 toolchain")
    isolation = _object(toolchain["provider_isolation"], "toolchain.provider_isolation")
    _exact(isolation, _ISOLATION_KEYS, "toolchain.provider_isolation")
    if isolation["platform"] != "posix":
        raise ReleaseSourceAdmissionV3Error("provider isolation platform must be posix")
    for key in ("uid", "gid"):
        _size(isolation[key], label=f"provider_isolation.{key}", minimum=1, maximum=2_147_483_647)
    return {
        "git_sha256": _matched(toolchain["git_sha256"], _SHA256, "toolchain.git_sha256"),
        "github_cli_sha256": _matched(
            toolchain["github_cli_sha256"], _SHA256, "toolchain.github_cli_sha256"
        ),
        "provider_isolation": dict(isolation),
    }


def _key_separation(value: object) -> dict[str, str]:
    separation = _object(value, "release-source admission V3 key separation")
    _exact(separation, _KEY_SEPARATION_KEYS, "release-source admission V3 key separation")
    checked = {
        key: _matched(separation[key], _KEY_ID, f"key_separation.{key}")
        for key in sorted(_KEY_SEPARATION_KEYS)
    }
    if len(set(checked.values())) != len(checked):
        raise ReleaseSourceAdmissionV3Error("configured trust-domain key IDs are not distinct")
    return checked


def _authentication(value: object, *, prohibited: set[str]) -> dict[str, str]:
    authentication = _object(value, "release-source admission V3 authentication")
    _exact(authentication, _AUTHENTICATION_KEYS, "release-source admission V3 authentication")
    checked = {
        "algorithm": authentication["algorithm"],
        "key_id": _matched(authentication["key_id"], _KEY_ID, "authentication.key_id"),
        "purpose": authentication["purpose"],
        "key_domain": authentication["key_domain"],
        "signature_path": authentication["signature_path"],
    }
    expected = {
        "algorithm": "Ed25519",
        "purpose": RELEASE_SOURCE_ADMISSION_SIGNATURE_PURPOSE_V3,
        "key_domain": RELEASE_SOURCE_ADMISSION_KEY_DOMAIN_V3,
        "signature_path": RELEASE_SOURCE_ADMISSION_SIGNATURE_PATH_V3,
    }
    if any(checked[key] != wanted for key, wanted in expected.items()):
        raise ReleaseSourceAdmissionV3Error(
            "release-source admission V3 authentication domain is wrong"
        )
    if checked["key_id"] in prohibited:
        raise ReleaseSourceAdmissionV3Error(
            "release-source admission V3 key belongs to another trust domain"
        )
    return checked


def validate_release_source_admission_v3(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    manifest = _object(value, "release-source admission V3")
    _exact(manifest, _MANIFEST_KEYS, "release-source admission V3")
    if manifest["format"] != RELEASE_SOURCE_ADMISSION_FORMAT_V3:
        raise ReleaseSourceAdmissionV3Error("unsupported release-source admission V3 format")
    if manifest["decision"] != "ALLOW":
        raise ReleaseSourceAdmissionV3Error("release-source admission V3 decision must be ALLOW")
    try:
        source = validate_release_source_v2(_object(manifest["source"], "admission.source"))
        context = validate_release_source_context_v2(
            _object(manifest["context"], "admission.context")
        )
        upstream = validate_run(
            _object(manifest["upstream"], "admission.upstream"), label="admission.upstream"
        )
    except MaintenanceBindingError as exc:
        raise ReleaseSourceAdmissionV3Error(str(exc)) from exc
    if context["source"] != source or context["evaluation"] != upstream:
        raise ReleaseSourceAdmissionV3Error(
            "release-source admission V3 source/upstream does not match context"
        )
    producer = validate_release_source_producer_v2(
        _object(manifest["producer"], "admission.producer"),
        source=source,
        upstream=upstream,
    )
    producer_run = {
        "run_id": producer["workflow_run_id"],
        "run_attempt": producer["workflow_run_attempt"],
    }
    admitter = validate_release_source_producer_v2(
        _object(manifest["admitter"], "admission.admitter"),
        source=source,
        upstream=producer_run,
    )
    try:
        for label, actor in (("producer", producer), ("admitter", admitter)):
            require_trusted_workflow_material_v2(
                workflow_path=actor["workflow_path"],
                workflow_blob_sha=actor["workflow_blob_sha"],
                trusted_inputs=context["trusted_inputs"],
                label=label,
            )
    except MaintenanceBindingError as exc:
        raise ReleaseSourceAdmissionV3Error(str(exc)) from exc
    workflow_ids = {
        producer["workflow_id"],
        admitter["workflow_id"],
    }
    workflow_paths = {
        source["trusted_workflow_path"],
        producer["workflow_path"],
        admitter["workflow_path"],
    }
    workflow_blobs = {
        source["trusted_workflow_blob_sha"],
        producer["workflow_blob_sha"],
        admitter["workflow_blob_sha"],
    }
    if len(workflow_ids) != 2 or len(workflow_paths) != 3 or len(workflow_blobs) != 3:
        raise ReleaseSourceAdmissionV3Error(
            "trusted finalizer, producer, and admitter workflow roles must be distinct"
        )
    receipt = _descriptor(
        manifest["producer_receipt"],
        label="admission.producer_receipt",
        path=RELEASE_SOURCE_ADMISSION_PRODUCER_RECEIPT_PATH_V3,
        maximum_size=MAX_PRODUCER_RECEIPT_BYTES_V2,
    )
    replay = _object(manifest["replay"], "admission.replay")
    _exact(replay, _REPLAY_KEYS, "admission.replay")
    checked_replay = {
        key: validate_run(_object(replay[key], f"replay.{key}"), label=f"replay.{key}")
        for key in sorted(_REPLAY_KEYS)
    }
    expected_replay = {
        "evaluation": upstream,
        "producer": producer_run,
        "admitter": {
            "run_id": admitter["workflow_run_id"],
            "run_attempt": admitter["workflow_run_attempt"],
        },
    }
    if checked_replay != expected_replay:
        raise ReleaseSourceAdmissionV3Error(
            "release-source admission V3 replay chain is inconsistent"
        )
    if len({run["run_id"] for run in expected_replay.values()}) != len(expected_replay):
        raise ReleaseSourceAdmissionV3Error(
            "evaluation, producer, and admitter run IDs must be pairwise distinct"
        )
    separation = _key_separation(manifest["key_separation"])
    return {
        "format": RELEASE_SOURCE_ADMISSION_FORMAT_V3,
        "decision": "ALLOW",
        "source": source,
        "context": context,
        "upstream": upstream,
        "producer": producer,
        "admitter": admitter,
        "producer_receipt": receipt,
        "provider": _provider(
            manifest["provider"], source=source, producer=producer, receipt=receipt
        ),
        "toolchain": _toolchain(manifest["toolchain"]),
        "replay": checked_replay,
        "key_separation": separation,
        "authentication": _authentication(
            manifest["authentication"], prohibited=set(separation.values())
        ),
    }


def bind_release_source_admission_v3_to_receipt(
    value: Mapping[str, Any],
    receipt_value: Mapping[str, Any],
    *,
    receipt_bytes: bytes,
) -> dict[str, Any]:
    """Require a manifest to bind exact canonical V2 receipt bytes and identities."""

    manifest = validate_release_source_admission_v3(value)
    if type(receipt_bytes) is not bytes:
        raise ReleaseSourceAdmissionV3Error(
            "release-source admission V3 receipt bytes must be immutable bytes"
        )
    receipt_size = len(receipt_bytes)
    if receipt_size < 1 or receipt_size > MAX_PRODUCER_RECEIPT_BYTES_V2:
        raise ReleaseSourceAdmissionV3Error(
            "release-source admission V3 receipt bytes size is outside bounds"
        )
    try:
        receipt_from_value = validate_release_source_producer_receipt_v2(receipt_value)
        receipt = require_canonical_bytes(
            receipt_bytes,
            validator=validate_release_source_producer_receipt_v2,
            label="release-source producer receipt V2",
        )
    except MaintenanceBindingError as exc:
        raise ReleaseSourceAdmissionV3Error(str(exc)) from exc
    if receipt != receipt_from_value:
        raise ReleaseSourceAdmissionV3Error(
            "producer receipt mapping does not match its exact canonical bytes"
        )
    expected_descriptor = {
        "path": RELEASE_SOURCE_ADMISSION_PRODUCER_RECEIPT_PATH_V3,
        "sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "size": receipt_size,
    }
    if manifest["producer_receipt"] != expected_descriptor:
        raise ReleaseSourceAdmissionV3Error(
            "release-source admission V3 descriptor does not match canonical receipt bytes"
        )
    if (
        manifest["source"] != receipt["subject"]
        or manifest["context"] != receipt["context"]
        or manifest["upstream"] != receipt["upstream"]
        or manifest["producer"] != receipt["producer"]
    ):
        raise ReleaseSourceAdmissionV3Error(
            "release-source admission V3 identities do not match its producer receipt"
        )
    return manifest


def canonical_release_source_admission_v3_bytes(
    value: Mapping[str, Any],
) -> bytes:
    return canonical_validated_bytes(value, validator=validate_release_source_admission_v3)


def release_source_admission_v3_signature_message(value: Mapping[str, Any]) -> bytes:
    return RELEASE_SOURCE_ADMISSION_SIGNATURE_DOMAIN_V3 + (
        canonical_release_source_admission_v3_bytes(value)
    )
