# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Release Artifact Admission V2 manifest for maintenance-source admission V3.

The format is intentionally unrelated to Release Artifact Admission V1.  It
retains the three-way workflow/base/target separation from the source admission
and binds the provider's source identity to trusted workflow bytes, not to the
maintenance candidate.  Validation alone is not publication or deployment
authority.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

from evoom_guard.admission.release_source_v3 import (
    RELEASE_SOURCE_ADMISSION_FORMAT_V3,
    ReleaseSourceAdmissionV3Error,
    validate_release_source_admission_v3,
)
from evoom_guard.maintenance_bindings import (
    MaintenanceBindingError,
    canonical_validated_bytes,
    require_trusted_workflow_material_v2,
    validate_run,
    validate_trusted_inputs_v2,
)

RELEASE_ARTIFACT_ADMISSION_FORMAT_V2 = "EVOGUARD_RELEASE_ARTIFACT_ADMISSION_V2"
RELEASE_ARTIFACT_ADMISSION_SIGNATURE_PURPOSE_V2 = "evoguard-release-artifact-admission-v2"
RELEASE_ARTIFACT_ADMISSION_KEY_DOMAIN_V2 = "release-artifact-admission-v2"
RELEASE_ARTIFACT_ADMISSION_SIGNATURE_DOMAIN_V2 = (
    RELEASE_ARTIFACT_ADMISSION_FORMAT_V2.encode("ascii") + b"\0"
)

RELEASE_ARTIFACT_ADMISSION_SIGNATURE_PATH_V2 = "admission.sig"
RELEASE_ARTIFACT_SOURCE_ADMISSION_PATH_V2 = "materials/release-source-admission-v3.rsae"
RELEASE_ARTIFACT_GITHUB_RECEIPT_PATH_V2 = "provider/github-attestation-receipt.json"
RELEASE_ARTIFACT_GITHUB_OUTPUT_PATH_V2 = "provider/github-attestation-output.json"

MAX_SOURCE_ADMISSION_BYTES = 70 * 1024 * 1024
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024
MAX_PROVIDER_RECEIPT_BYTES = 64 * 1024
MAX_PROVIDER_OUTPUT_BYTES = 4 * 1024 * 1024

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_KEY_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NUMERIC_ID = re.compile(r"[1-9][0-9]{0,255}\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}\Z")
_WORKFLOW_PATH = re.compile(r"\.github/workflows/[A-Za-z0-9][A-Za-z0-9_.-]*\.ya?ml\Z")

_MANIFEST_KEYS = {
    "format",
    "decision",
    "release_source",
    "artifact",
    "builder",
    "admitter",
    "provider",
    "toolchain",
    "replay",
    "key_separation",
    "authentication",
}
_SOURCE_KEYS = {
    "format",
    "decision",
    "bundle",
    "key_id",
    "repository",
    "repository_id",
    "trusted_workflow_sha",
    "trusted_workflow_tree",
    "maintenance_base_sha",
    "maintenance_base_tree",
    "target_source_sha",
    "target_source_tree",
    "trusted_inputs",
    "admission_run_id",
    "admission_run_attempt",
}
_DESCRIPTOR_KEYS = {"path", "sha256", "size"}
_ARTIFACT_KEYS = {"kind", "sha256", "size"}
_ACTOR_KEYS = {
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
_REPLAY_KEYS = {"source_admitter", "builder", "artifact_admitter"}
_KEY_SEPARATION_KEYS = {
    "trusted_finalizer",
    "artifact_admission_v1",
    "artifact_digest_admission_v2",
    "release_source_finalizer_v1",
    "release_source_admission_v2",
    "release_source_finalizer_v2",
    "release_source_admission_v3",
}
_AUTHENTICATION_KEYS = {
    "algorithm",
    "key_id",
    "purpose",
    "key_domain",
    "signature_path",
}


class ReleaseArtifactAdmissionV2Error(MaintenanceBindingError):
    """A Release Artifact Admission V2 manifest or source binding is unsafe."""


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseArtifactAdmissionV2Error(f"{label} must be an object")
    return dict(value)


def _exact(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ReleaseArtifactAdmissionV2Error(f"{label} keys are not exact")


def _matched(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ReleaseArtifactAdmissionV2Error(f"{label} is not canonical")
    return value


def _size(value: object, *, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ReleaseArtifactAdmissionV2Error(f"{label} is outside the supported range")
    return value


def _descriptor(value: object, *, label: str, path: str, maximum: int) -> dict[str, Any]:
    descriptor = _object(value, label)
    _exact(descriptor, _DESCRIPTOR_KEYS, label)
    if descriptor["path"] != path:
        raise ReleaseArtifactAdmissionV2Error(f"{label}.path is not literal {path}")
    return {
        "path": path,
        "sha256": _matched(descriptor["sha256"], _SHA256, f"{label}.sha256"),
        "size": _size(descriptor["size"], label=f"{label}.size", minimum=1, maximum=maximum),
    }


def _release_source(value: object) -> dict[str, Any]:
    source = _object(value, "release artifact V2 source")
    _exact(source, _SOURCE_KEYS, "release artifact V2 source")
    if source["format"] != RELEASE_SOURCE_ADMISSION_FORMAT_V3 or source["decision"] != "ALLOW":
        raise ReleaseArtifactAdmissionV2Error(
            "release artifact V2 requires an ALLOW Release Source Admission V3"
        )
    attempt = source["admission_run_attempt"]
    _size(attempt, label="release_source.admission_run_attempt", minimum=1, maximum=2_147_483_647)
    checked: dict[str, Any] = {
        "format": RELEASE_SOURCE_ADMISSION_FORMAT_V3,
        "decision": "ALLOW",
        "bundle": _descriptor(
            source["bundle"],
            label="release_source.bundle",
            path=RELEASE_ARTIFACT_SOURCE_ADMISSION_PATH_V2,
            maximum=MAX_SOURCE_ADMISSION_BYTES,
        ),
        "key_id": _matched(source["key_id"], _KEY_ID, "release_source.key_id"),
        "repository": _matched(source["repository"], _REPOSITORY, "release_source.repository"),
        "repository_id": _matched(
            source["repository_id"], _NUMERIC_ID, "release_source.repository_id"
        ),
        "trusted_workflow_sha": _matched(
            source["trusted_workflow_sha"], _GIT_SHA, "release_source.trusted_workflow_sha"
        ),
        "trusted_workflow_tree": _matched(
            source["trusted_workflow_tree"], _GIT_SHA, "release_source.trusted_workflow_tree"
        ),
        "maintenance_base_sha": _matched(
            source["maintenance_base_sha"], _GIT_SHA, "release_source.maintenance_base_sha"
        ),
        "maintenance_base_tree": _matched(
            source["maintenance_base_tree"], _GIT_SHA, "release_source.maintenance_base_tree"
        ),
        "target_source_sha": _matched(
            source["target_source_sha"], _GIT_SHA, "release_source.target_source_sha"
        ),
        "target_source_tree": _matched(
            source["target_source_tree"], _GIT_SHA, "release_source.target_source_tree"
        ),
        "admission_run_id": _matched(
            source["admission_run_id"], _NUMERIC_ID, "release_source.admission_run_id"
        ),
        "admission_run_attempt": attempt,
    }
    try:
        checked["trusted_inputs"] = validate_trusted_inputs_v2(
            _object(source["trusted_inputs"], "release_source.trusted_inputs"),
            source=checked,
        )
    except MaintenanceBindingError as exc:
        raise ReleaseArtifactAdmissionV2Error(str(exc)) from exc
    return checked


def _artifact(value: object) -> dict[str, Any]:
    artifact = _object(value, "release artifact V2 subject")
    _exact(artifact, _ARTIFACT_KEYS, "release artifact V2 subject")
    if artifact["kind"] != "file":
        raise ReleaseArtifactAdmissionV2Error("release artifact V2 kind must be file")
    return {
        "kind": "file",
        "sha256": _matched(artifact["sha256"], _SHA256, "artifact.sha256"),
        "size": _size(
            artifact["size"], label="artifact.size", minimum=0, maximum=MAX_ARTIFACT_BYTES
        ),
    }


def _actor(
    value: object,
    *,
    label: str,
    source: Mapping[str, Any],
    upstream: Mapping[str, Any],
    event: str,
) -> dict[str, Any]:
    actor = _object(value, label)
    _exact(actor, _ACTOR_KEYS, label)
    checked = {
        "workflow_repository": _matched(
            actor["workflow_repository"], _REPOSITORY, f"{label}.repository"
        ),
        "workflow_repository_id": _matched(
            actor["workflow_repository_id"], _NUMERIC_ID, f"{label}.repository_id"
        ),
        "workflow_id": _matched(actor["workflow_id"], _NUMERIC_ID, f"{label}.workflow_id"),
        "workflow_path": _matched(actor["workflow_path"], _WORKFLOW_PATH, f"{label}.workflow_path"),
        "workflow_blob_sha": _matched(
            actor["workflow_blob_sha"], _GIT_SHA, f"{label}.workflow_blob_sha"
        ),
        "workflow_run_id": _matched(actor["workflow_run_id"], _NUMERIC_ID, f"{label}.run_id"),
        "workflow_run_attempt": _size(
            actor["workflow_run_attempt"],
            label=f"{label}.run_attempt",
            minimum=1,
            maximum=2_147_483_647,
        ),
        "workflow_event": actor["workflow_event"],
        "workflow_ref": actor["workflow_ref"],
        "workflow_commit_sha": _matched(
            actor["workflow_commit_sha"], _GIT_SHA, f"{label}.workflow_commit_sha"
        ),
        "workflow_tree_sha": _matched(
            actor["workflow_tree_sha"], _GIT_SHA, f"{label}.workflow_tree_sha"
        ),
        "upstream_run_id": _matched(
            actor["upstream_run_id"], _NUMERIC_ID, f"{label}.upstream_run_id"
        ),
        "upstream_run_attempt": _size(
            actor["upstream_run_attempt"],
            label=f"{label}.upstream_run_attempt",
            minimum=1,
            maximum=2_147_483_647,
        ),
        "runner_class": actor["runner_class"],
    }
    expected = {
        "workflow_repository": source["repository"],
        "workflow_repository_id": source["repository_id"],
        "workflow_event": event,
        "workflow_ref": "refs/heads/main",
        "workflow_commit_sha": source["trusted_workflow_sha"],
        "workflow_tree_sha": source["trusted_workflow_tree"],
        "upstream_run_id": upstream["run_id"],
        "upstream_run_attempt": upstream["run_attempt"],
        "runner_class": "github-hosted",
    }
    if any(checked[key] != wanted for key, wanted in expected.items()):
        raise ReleaseArtifactAdmissionV2Error(f"{label} is not bound to trusted source/upstream")
    return checked


def _provider(
    value: object,
    *,
    source: Mapping[str, Any],
    builder: Mapping[str, Any],
    artifact: Mapping[str, Any],
) -> dict[str, Any]:
    provider = _object(value, "release artifact V2 provider")
    _exact(provider, _PROVIDER_KEYS, "release artifact V2 provider")
    if (
        provider["name"] != "github-artifact-attestations"
        or provider["verified_attestation_count"] != 1
    ):
        raise ReleaseArtifactAdmissionV2Error("artifact provider identity/count is not exact")
    provider_artifact = _object(provider["artifact"], "provider.artifact")
    if set(provider_artifact) != {"sha256", "size"} or provider_artifact != {
        "sha256": artifact["sha256"],
        "size": artifact["size"],
    }:
        raise ReleaseArtifactAdmissionV2Error(
            "artifact provider does not bind exact artifact bytes"
        )
    policy = _object(provider["policy"], "provider.policy")
    _exact(policy, _POLICY_KEYS, "provider.policy")
    expected_policy = {
        "repository": source["repository"],
        "signer_workflow": f"{source['repository']}/{builder['workflow_path']}",
        "signer_digest": source["trusted_workflow_sha"],
        "source_ref": "refs/heads/main",
        "source_digest": source["trusted_workflow_sha"],
        "cert_oidc_issuer": "https://token.actions.githubusercontent.com",
        "predicate_type": "https://slsa.dev/provenance/v1",
        "deny_self_hosted_runners": True,
        "attestation_limit": 1,
    }
    if policy != expected_policy:
        raise ReleaseArtifactAdmissionV2Error(
            "artifact provider policy is not bound to the trusted builder workflow commit"
        )
    return {
        "name": "github-artifact-attestations",
        "artifact": dict(provider_artifact),
        "policy": dict(policy),
        "verified_attestation_count": 1,
        "receipt": _descriptor(
            provider["receipt"],
            label="provider.receipt",
            path=RELEASE_ARTIFACT_GITHUB_RECEIPT_PATH_V2,
            maximum=MAX_PROVIDER_RECEIPT_BYTES,
        ),
        "raw_output": _descriptor(
            provider["raw_output"],
            label="provider.raw_output",
            path=RELEASE_ARTIFACT_GITHUB_OUTPUT_PATH_V2,
            maximum=MAX_PROVIDER_OUTPUT_BYTES,
        ),
    }


def _toolchain(value: object) -> dict[str, Any]:
    toolchain = _object(value, "release artifact V2 toolchain")
    _exact(toolchain, _TOOLCHAIN_KEYS, "release artifact V2 toolchain")
    isolation = _object(toolchain["provider_isolation"], "toolchain.provider_isolation")
    _exact(isolation, _ISOLATION_KEYS, "toolchain.provider_isolation")
    if isolation["platform"] != "posix":
        raise ReleaseArtifactAdmissionV2Error("provider isolation platform must be posix")
    for key in ("uid", "gid"):
        _size(isolation[key], label=f"provider_isolation.{key}", minimum=1, maximum=2_147_483_647)
    return {
        "git_sha256": _matched(toolchain["git_sha256"], _SHA256, "toolchain.git_sha256"),
        "github_cli_sha256": _matched(
            toolchain["github_cli_sha256"], _SHA256, "toolchain.github_cli_sha256"
        ),
        "provider_isolation": dict(isolation),
    }


def _separation(value: object) -> dict[str, str]:
    separation = _object(value, "release artifact V2 key separation")
    _exact(separation, _KEY_SEPARATION_KEYS, "release artifact V2 key separation")
    checked = {
        key: _matched(separation[key], _KEY_ID, f"key_separation.{key}")
        for key in sorted(_KEY_SEPARATION_KEYS)
    }
    if len(set(checked.values())) != len(checked):
        raise ReleaseArtifactAdmissionV2Error("configured trust-domain key IDs are not distinct")
    return checked


def _authentication(value: object, *, prohibited: set[str]) -> dict[str, str]:
    authentication = _object(value, "release artifact V2 authentication")
    _exact(authentication, _AUTHENTICATION_KEYS, "release artifact V2 authentication")
    checked = {
        "algorithm": authentication["algorithm"],
        "key_id": _matched(authentication["key_id"], _KEY_ID, "authentication.key_id"),
        "purpose": authentication["purpose"],
        "key_domain": authentication["key_domain"],
        "signature_path": authentication["signature_path"],
    }
    expected = {
        "algorithm": "Ed25519",
        "purpose": RELEASE_ARTIFACT_ADMISSION_SIGNATURE_PURPOSE_V2,
        "key_domain": RELEASE_ARTIFACT_ADMISSION_KEY_DOMAIN_V2,
        "signature_path": RELEASE_ARTIFACT_ADMISSION_SIGNATURE_PATH_V2,
    }
    if any(checked[key] != wanted for key, wanted in expected.items()):
        raise ReleaseArtifactAdmissionV2Error("release artifact V2 authentication domain is wrong")
    if checked["key_id"] in prohibited:
        raise ReleaseArtifactAdmissionV2Error(
            "release artifact V2 key belongs to another trust domain"
        )
    return checked


def validate_release_artifact_admission_v2(value: Mapping[str, Any]) -> dict[str, Any]:
    manifest = _object(value, "release artifact admission V2")
    _exact(manifest, _MANIFEST_KEYS, "release artifact admission V2")
    if manifest["format"] != RELEASE_ARTIFACT_ADMISSION_FORMAT_V2:
        raise ReleaseArtifactAdmissionV2Error("unsupported release artifact admission V2 format")
    if manifest["decision"] != "ALLOW":
        raise ReleaseArtifactAdmissionV2Error(
            "release artifact admission V2 decision must be ALLOW"
        )
    source = _release_source(manifest["release_source"])
    source_run = {
        "run_id": source["admission_run_id"],
        "run_attempt": source["admission_run_attempt"],
    }
    builder = _actor(
        manifest["builder"],
        label="builder",
        source=source,
        upstream=source_run,
        event="workflow_dispatch",
    )
    builder_run = {
        "run_id": builder["workflow_run_id"],
        "run_attempt": builder["workflow_run_attempt"],
    }
    admitter = _actor(
        manifest["admitter"],
        label="artifact_admitter",
        source=source,
        upstream=builder_run,
        event="workflow_run",
    )
    try:
        for label, actor in (("builder", builder), ("artifact_admitter", admitter)):
            require_trusted_workflow_material_v2(
                workflow_path=actor["workflow_path"],
                workflow_blob_sha=actor["workflow_blob_sha"],
                trusted_inputs=source["trusted_inputs"],
                label=label,
            )
    except MaintenanceBindingError as exc:
        raise ReleaseArtifactAdmissionV2Error(str(exc)) from exc
    if admitter["workflow_path"] == builder["workflow_path"]:
        raise ReleaseArtifactAdmissionV2Error(
            "builder and admitter workflows must be role-separated"
        )
    artifact = _artifact(manifest["artifact"])
    replay = _object(manifest["replay"], "release artifact V2 replay")
    _exact(replay, _REPLAY_KEYS, "release artifact V2 replay")
    checked_replay = {
        key: validate_run(_object(replay[key], f"replay.{key}"), label=f"replay.{key}")
        for key in sorted(_REPLAY_KEYS)
    }
    expected_replay = {
        "source_admitter": source_run,
        "builder": builder_run,
        "artifact_admitter": {
            "run_id": admitter["workflow_run_id"],
            "run_attempt": admitter["workflow_run_attempt"],
        },
    }
    if checked_replay != expected_replay:
        raise ReleaseArtifactAdmissionV2Error("release artifact V2 replay chain is inconsistent")
    separation = _separation(manifest["key_separation"])
    return {
        "format": RELEASE_ARTIFACT_ADMISSION_FORMAT_V2,
        "decision": "ALLOW",
        "release_source": source,
        "artifact": artifact,
        "builder": builder,
        "admitter": admitter,
        "provider": _provider(
            manifest["provider"], source=source, builder=builder, artifact=artifact
        ),
        "toolchain": _toolchain(manifest["toolchain"]),
        "replay": checked_replay,
        "key_separation": separation,
        "authentication": _authentication(
            manifest["authentication"], prohibited=set(separation.values())
        ),
    }


def bind_release_artifact_v2_to_source_admission(
    value: Mapping[str, Any],
    source_admission_value: Mapping[str, Any],
    *,
    source_bundle_bytes: bytes,
) -> dict[str, Any]:
    """Require the artifact manifest to bind exact V3 source-admission bytes."""

    manifest = validate_release_artifact_admission_v2(value)
    try:
        source_admission = validate_release_source_admission_v3(source_admission_value)
    except ReleaseSourceAdmissionV3Error as exc:
        raise ReleaseArtifactAdmissionV2Error(str(exc)) from exc
    summary = manifest["release_source"]
    descriptor = {
        "path": RELEASE_ARTIFACT_SOURCE_ADMISSION_PATH_V2,
        "sha256": hashlib.sha256(source_bundle_bytes).hexdigest(),
        "size": len(source_bundle_bytes),
    }
    if summary["bundle"] != descriptor:
        raise ReleaseArtifactAdmissionV2Error(
            "release artifact V2 source descriptor does not match exact bundle bytes"
        )
    source = source_admission["source"]
    expected = {
        "format": RELEASE_SOURCE_ADMISSION_FORMAT_V3,
        "decision": "ALLOW",
        "bundle": descriptor,
        "key_id": source_admission["authentication"]["key_id"],
        "repository": source["repository"],
        "repository_id": source["repository_id"],
        "trusted_workflow_sha": source["trusted_workflow_sha"],
        "trusted_workflow_tree": source["trusted_workflow_tree"],
        "maintenance_base_sha": source["maintenance_base_sha"],
        "maintenance_base_tree": source["maintenance_base_tree"],
        "target_source_sha": source["target_source_sha"],
        "target_source_tree": source["target_source_tree"],
        "trusted_inputs": source_admission["context"]["trusted_inputs"],
        "admission_run_id": source_admission["admitter"]["workflow_run_id"],
        "admission_run_attempt": source_admission["admitter"]["workflow_run_attempt"],
    }
    if summary != expected:
        raise ReleaseArtifactAdmissionV2Error(
            "release artifact V2 source summary does not match Release Source Admission V3"
        )
    return manifest


def canonical_release_artifact_admission_v2_bytes(
    value: Mapping[str, Any],
) -> bytes:
    return canonical_validated_bytes(value, validator=validate_release_artifact_admission_v2)


def release_artifact_admission_v2_signature_message(value: Mapping[str, Any]) -> bytes:
    return RELEASE_ARTIFACT_ADMISSION_SIGNATURE_DOMAIN_V2 + (
        canonical_release_artifact_admission_v2_bytes(value)
    )
