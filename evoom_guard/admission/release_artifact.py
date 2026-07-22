# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Source-available - see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Release-artifact admission rooted in a verified protected-main decision.

``EVOGUARD_RELEASE_ARTIFACT_ADMISSION_V1`` is deliberately a new trust
domain.  It does not reinterpret the older PR artifact bindings.  A release
artifact can be admitted only after all of the following have succeeded:

* one exact ``EVOGUARD_RELEASE_SOURCE_ADMISSION_V2`` (``.rsae``) snapshot is
  verified as ``ALLOW`` against externally supplied trust roots and replay
  selectors;
* one external regular-file artifact is hashed from a stable descriptor;
* the protected builder identity is matched to the release source, its
  workflow blob is resolved from the immutable raw-Git tree, and the current
  admitting workflow is bound to the successful ``workflow_run`` event;
* a fresh, isolated GitHub Artifact Attestation verification binds that exact
  artifact, source commit, workflow, and run attempt; and
* a sixth Ed25519 key, distinct from every earlier admission/finalizer key,
  signs the canonical retained evidence.

The artifact bytes are intentionally not copied into the envelope.  Detached
verification re-hashes an externally supplied regular file and verifies the
embedded provider evidence offline.  GitHub/Sigstore freshness is established
when sealing; a later caller that requires current provider state must perform
an additional live re-verification outside this detached operation.
"""

from __future__ import annotations

import base64
import io
import os
import re
import tempfile
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Any

from evoom_guard.admission.release_source import (
    MAX_RELEASE_SOURCE_ADMISSION_ARCHIVE_BYTES,
    RELEASE_SOURCE_ADMISSION_FORMAT,
    ReleaseSourceAdmissionError,
    VerifiedReleaseSourceAdmission,
    inspect_release_source_admission,
    verify_release_source_admission,
)
from evoom_guard.artifact_admission import (
    ArtifactAdmissionError,
    ArtifactSubject,
    hash_regular_artifact,
)
from evoom_guard.evidence_bundle import (
    EvidenceBundleError,
    canonical_archive_bytes,
    canonical_json_bytes,
    load_json_object_bytes,
    preflight_canonical_zip,
    read_archive_member_bytes,
    read_regular_file_bytes,
    sha256_bytes,
    validate_canonical_archive_member,
)
from evoom_guard.finalizer_derivation import (
    GitExecutablePin,
    resolve_raw_git_regular_blob,
)
from evoom_guard.github_attestation import (
    DEFAULT_GITHUB_ATTESTATION_TIMEOUT_SECONDS,
    GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
    MAX_GITHUB_ATTESTATION_OUTPUT_BYTES,
    MAX_GITHUB_ATTESTATION_RECEIPT_BYTES,
    CreatedGitHubAttestationReceipt,
    GitHubAttestationArtifact,
    GitHubAttestationError,
    GitHubAttestationPolicy,
    GitHubAttestationProviderIsolation,
    create_github_attestation_receipt,
    github_attestation_policy,
    validate_github_attestation_receipt,
    validate_github_attestation_verifier_output,
    validate_provider_isolated_signing_key_path,
)
from evoom_guard.release_source_finalizer import (
    ReleaseSourceFinalizerError,
    validate_release_source,
)

RELEASE_ARTIFACT_ADMISSION_FORMAT = "EVOGUARD_RELEASE_ARTIFACT_ADMISSION_V1"
RELEASE_ARTIFACT_ADMISSION_EXTENSION = ".raae"
RELEASE_ARTIFACT_ADMISSION_SIGNATURE_PURPOSE = (
    "evoguard-release-artifact-admission-v1"
)
RELEASE_ARTIFACT_ADMISSION_KEY_DOMAIN = "release-artifact-admission-v1"
RELEASE_ARTIFACT_ADMISSION_SIGNATURE_DOMAIN = (
    RELEASE_ARTIFACT_ADMISSION_FORMAT.encode("ascii") + b"\0"
)

RELEASE_ARTIFACT_ADMISSION_MANIFEST_PATH = "admission.json"
RELEASE_ARTIFACT_ADMISSION_SIGNATURE_PATH = "admission.sig"
RELEASE_ARTIFACT_ADMISSION_SOURCE_PATH = (
    "materials/release-source-admission.rsae"
)
RELEASE_ARTIFACT_ADMISSION_GITHUB_RECEIPT_PATH = (
    "provider/github-attestation-receipt.json"
)
RELEASE_ARTIFACT_ADMISSION_GITHUB_RAW_OUTPUT_PATH = (
    "provider/github-attestation-output.json"
)

MAX_RELEASE_ARTIFACT_ADMISSION_MANIFEST_BYTES = 1 * 1024 * 1024
MAX_RELEASE_ARTIFACT_ADMISSION_ARCHIVE_BYTES = (
    MAX_RELEASE_SOURCE_ADMISSION_ARCHIVE_BYTES
    + MAX_GITHUB_ATTESTATION_OUTPUT_BYTES
    + MAX_GITHUB_ATTESTATION_RECEIPT_BYTES
    + MAX_RELEASE_ARTIFACT_ADMISSION_MANIFEST_BYTES
    + 2 * 1024 * 1024
)

RELEASE_ARTIFACT_ADMISSION_DISTINCT_KEY_DOMAINS = frozenset(
    {
        "trusted_finalizer",
        "artifact_admission_v1",
        "artifact_digest_admission_v2",
        "release_source_finalizer_v1",
        "release_source_admission_v2",
    }
)

_RUNTIME_BUILDER_CAPABILITY = object()
_KEY_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_WORKFLOW_PATH = re.compile(
    r"\.github/workflows/[A-Za-z0-9][A-Za-z0-9_.-]*\.ya?ml\Z"
)

_DESCRIPTOR_KEYS = {"path", "sha256", "size"}
_ARTIFACT_KEYS = {"kind", "sha256", "size"}
_BUILDER_KEYS = {
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
    "runner_class",
}
_ADMITTER_KEYS = set(_BUILDER_KEYS)
_SOURCE_KEYS = {
    "format",
    "decision",
    "bundle",
    "key_id",
    "repository",
    "repository_id",
    "target_commit_sha",
    "target_tree_sha",
    "bootstrap_guard_sha256",
}
_PROVIDER_KEYS = {
    "name",
    "artifact",
    "policy",
    "verified_attestation_count",
    "receipt",
    "raw_output",
}
_TOOLCHAIN_KEYS = {"git", "github_cli", "provider_isolation"}
_TOOL_KEYS = {"sha256"}
_ISOLATION_KEYS = {"platform", "uid", "gid"}
_AUTHENTICATION_KEYS = {
    "algorithm",
    "key_id",
    "purpose",
    "key_domain",
    "signature_path",
}
_MANIFEST_KEYS = {
    "format",
    "decision",
    "release_source",
    "artifact",
    "builder",
    "admitter",
    "provider",
    "toolchain",
    "key_separation",
    "authentication",
}
_ARCHIVE_PATHS = (
    RELEASE_ARTIFACT_ADMISSION_MANIFEST_PATH,
    RELEASE_ARTIFACT_ADMISSION_SIGNATURE_PATH,
    RELEASE_ARTIFACT_ADMISSION_SOURCE_PATH,
    RELEASE_ARTIFACT_ADMISSION_GITHUB_RECEIPT_PATH,
    RELEASE_ARTIFACT_ADMISSION_GITHUB_RAW_OUTPUT_PATH,
)


class ReleaseArtifactAdmissionError(ValueError):
    """A release-artifact admission input or trust binding is unsafe."""


@dataclass(frozen=True)
class RuntimeBoundReleaseArtifactAdmitter:
    """Opaque proof binding the current key-bearing job to one builder run."""

    builder: dict[str, Any]
    admitter: dict[str, Any]
    _capability: object = dataclass_field(
        default=None, init=False, repr=False, compare=False
    )


@dataclass(frozen=True)
class InspectedReleaseArtifactAdmission:
    """Canonical retained bytes whose signing key is not trusted yet."""

    manifest_bytes: bytes
    signature: bytes
    release_source_admission_bytes: bytes
    github_receipt_bytes: bytes
    github_raw_output_bytes: bytes

    @property
    def manifest(self) -> dict[str, Any]:
        try:
            return _validate_manifest(
                load_json_object_bytes(
                    self.manifest_bytes, "release-artifact admission manifest"
                )
            )
        except EvidenceBundleError as exc:
            raise ReleaseArtifactAdmissionError(str(exc)) from exc


@dataclass(frozen=True)
class SealedReleaseArtifactAdmission:
    """A newly sealed release-artifact ALLOW envelope."""

    bundle_path: str
    manifest: dict[str, Any]
    artifact: ArtifactSubject
    decision: str


@dataclass(frozen=True)
class VerifiedReleaseArtifactAdmission:
    """A detached artifact and embedded RSAE verified against external roots."""

    bundle: InspectedReleaseArtifactAdmission
    release_source: VerifiedReleaseSourceAdmission
    artifact: ArtifactSubject
    decision: str


def _require_exact_keys(
    value: Mapping[str, Any], expected: set[str], label: str
) -> None:
    actual = set(value)
    if actual != expected:
        raise ReleaseArtifactAdmissionError(
            f"{label} keys are not canonical "
            f"(missing={sorted(expected - actual)}, unknown={sorted(actual - expected)})"
        )


def _numeric_id(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or not value.isascii()
        or not value.isdecimal()
        or value.startswith("0")
    ):
        raise ReleaseArtifactAdmissionError(
            f"{label} must be a non-zero decimal identifier"
        )
    return value


def _git_sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise ReleaseArtifactAdmissionError(
            f"{label} must be a lowercase 40/64-character immutable Git digest"
        )
    return value


def _descriptor(path: str, data: bytes) -> dict[str, Any]:
    return {"path": path, "sha256": sha256_bytes(data), "size": len(data)}


def _validate_descriptor(
    value: object,
    *,
    label: str,
    path: str,
    maximum: int,
    minimum: int = 1,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseArtifactAdmissionError(f"{label} must be an object")
    descriptor = dict(value)
    _require_exact_keys(descriptor, _DESCRIPTOR_KEYS, label)
    if descriptor.get("path") != path:
        raise ReleaseArtifactAdmissionError(f"{label}.path must be {path!r}")
    digest = descriptor.get("sha256")
    size = descriptor.get("size")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise ReleaseArtifactAdmissionError(
            f"{label}.sha256 must be a lowercase SHA-256 digest"
        )
    if type(size) is not int or not minimum <= size <= maximum:
        raise ReleaseArtifactAdmissionError(
            f"{label}.size is outside the permitted range"
        )
    return {"path": path, "sha256": digest, "size": size}


def _validate_artifact(value: object) -> ArtifactSubject:
    if not isinstance(value, dict):
        raise ReleaseArtifactAdmissionError(
            "release-artifact admission artifact must be an object"
        )
    artifact = dict(value)
    _require_exact_keys(artifact, _ARTIFACT_KEYS, "release-artifact artifact")
    if artifact.get("kind") != "file":
        raise ReleaseArtifactAdmissionError(
            "release-artifact artifact.kind must be 'file'"
        )
    digest = artifact.get("sha256")
    size = artifact.get("size")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise ReleaseArtifactAdmissionError(
            "release-artifact artifact.sha256 must be a lowercase SHA-256 digest"
        )
    if type(size) is not int or not 0 <= size <= 4 * 1024 * 1024 * 1024:
        raise ReleaseArtifactAdmissionError(
            "release-artifact artifact.size is outside the permitted range"
        )
    return ArtifactSubject(sha256=digest, size=size)


def _validate_release_artifact_workflow(
    value: Mapping[str, Any], *, role: str, expected_event: str
) -> dict[str, Any]:
    workflow = dict(value)
    expected_keys = _BUILDER_KEYS if role == "builder" else _ADMITTER_KEYS
    _require_exact_keys(workflow, expected_keys, f"release-artifact {role}")
    repository = workflow.get("workflow_repository")
    path = workflow.get("workflow_path")
    if (
        not isinstance(repository, str)
        or len(repository) > 256
        or _REPOSITORY.fullmatch(repository) is None
    ):
        raise ReleaseArtifactAdmissionError(
            f"{role}.workflow_repository must be canonical owner/repository ASCII text"
        )
    if (
        not isinstance(path, str)
        or len(path) > 256
        or _WORKFLOW_PATH.fullmatch(path) is None
    ):
        raise ReleaseArtifactAdmissionError(
            f"{role}.workflow_path must be a canonical .github/workflows/*.yml path"
        )
    if workflow.get("workflow_event") != expected_event:
        raise ReleaseArtifactAdmissionError(
            f"{role}.workflow_event must be exactly {expected_event!r}"
        )
    if workflow.get("workflow_ref") != "refs/heads/main":
        raise ReleaseArtifactAdmissionError(
            f"{role}.workflow_ref must be exactly 'refs/heads/main'"
        )
    if workflow.get("runner_class") != "github-hosted":
        raise ReleaseArtifactAdmissionError(
            f"{role}.runner_class must be exactly 'github-hosted'"
        )
    attempt = workflow.get("workflow_run_attempt")
    if type(attempt) is not int or not 1 <= attempt <= 2_147_483_647:
        raise ReleaseArtifactAdmissionError(
            f"{role}.workflow_run_attempt must be an integer from 1 through 2147483647"
        )
    return {
        "workflow_repository": repository,
        "workflow_repository_id": _numeric_id(
            workflow.get("workflow_repository_id"),
            label=f"{role}.workflow_repository_id",
        ),
        "workflow_id": _numeric_id(
            workflow.get("workflow_id"), label=f"{role}.workflow_id"
        ),
        "workflow_path": path,
        "workflow_blob_sha": _git_sha(
            workflow.get("workflow_blob_sha"), label=f"{role}.workflow_blob_sha"
        ),
        "workflow_run_id": _numeric_id(
            workflow.get("workflow_run_id"), label=f"{role}.workflow_run_id"
        ),
        "workflow_run_attempt": attempt,
        "workflow_event": expected_event,
        "workflow_ref": "refs/heads/main",
        "workflow_commit_sha": _git_sha(
            workflow.get("workflow_commit_sha"),
            label=f"{role}.workflow_commit_sha",
        ),
        "runner_class": "github-hosted",
    }


def validate_release_artifact_builder(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the exact protected-main builder identity admitted by V1."""

    return _validate_release_artifact_workflow(
        value, role="builder", expected_event="workflow_dispatch"
    )


def validate_release_artifact_admitter(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the exact key-bearing workflow identity admitted by V1."""

    return _validate_release_artifact_workflow(
        value, role="admitter", expected_event="workflow_run"
    )


def _validate_workflow_source_binding(
    workflow: Mapping[str, Any], source: Mapping[str, Any], *, role: str
) -> None:
    checked_workflow = (
        validate_release_artifact_builder(workflow)
        if role == "builder"
        else validate_release_artifact_admitter(workflow)
    )
    try:
        checked_source = validate_release_source(source)
    except ReleaseSourceFinalizerError as exc:
        raise ReleaseArtifactAdmissionError(str(exc)) from exc
    if checked_workflow["workflow_repository"] != checked_source["repository"]:
        raise ReleaseArtifactAdmissionError(
            f"{role} repository does not match the release source"
        )
    if (
        checked_workflow["workflow_repository_id"]
        != checked_source["repository_id"]
    ):
        raise ReleaseArtifactAdmissionError(
            f"{role} repository ID does not match the release source"
        )
    if (
        checked_workflow["workflow_commit_sha"]
        != checked_source["target_commit_sha"]
    ):
        raise ReleaseArtifactAdmissionError(
            f"{role} workflow commit does not match the protected-main source"
        )


def bind_release_artifact_admitter_runtime(
    builder: Mapping[str, Any],
    admitter: Mapping[str, Any],
    *,
    source: Mapping[str, Any],
    environment: Mapping[str, str],
    event_payload: Mapping[str, Any],
) -> RuntimeBoundReleaseArtifactAdmitter:
    """Bind the key-bearing workflow and its triggering builder run.

    GitHub's non-overridable default variables and event payload are compared
    to every selector used later by the attestation adapter.  The admitting
    workflow and GitHub-hosted runner remain explicit trust roots.
    """

    checked_builder = validate_release_artifact_builder(builder)
    checked_admitter = validate_release_artifact_admitter(admitter)
    try:
        checked_source = validate_release_source(source)
    except ReleaseSourceFinalizerError as exc:
        raise ReleaseArtifactAdmissionError(str(exc)) from exc
    _validate_workflow_source_binding(checked_builder, checked_source, role="builder")
    _validate_workflow_source_binding(checked_admitter, checked_source, role="admitter")
    for field in ("workflow_id", "workflow_path", "workflow_run_id"):
        if checked_builder[field] == checked_admitter[field]:
            raise ReleaseArtifactAdmissionError(
                f"release-artifact admitter {field} must differ from the builder"
            )
    expected_environment = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": checked_admitter["workflow_repository"],
        "GITHUB_REPOSITORY_ID": checked_admitter["workflow_repository_id"],
        "GITHUB_RUN_ID": checked_admitter["workflow_run_id"],
        "GITHUB_RUN_ATTEMPT": str(checked_admitter["workflow_run_attempt"]),
        "GITHUB_EVENT_NAME": checked_admitter["workflow_event"],
        "GITHUB_REF": checked_admitter["workflow_ref"],
        "GITHUB_SHA": checked_admitter["workflow_commit_sha"],
        "GITHUB_WORKFLOW_REF": (
            f"{checked_admitter['workflow_repository']}/"
            f"{checked_admitter['workflow_path']}@{checked_admitter['workflow_ref']}"
        ),
        "GITHUB_WORKFLOW_SHA": checked_admitter["workflow_commit_sha"],
        "RUNNER_ENVIRONMENT": checked_admitter["runner_class"],
    }
    for name, expected in expected_environment.items():
        if environment.get(name) != expected:
            raise ReleaseArtifactAdmissionError(
                f"release-artifact admission runtime {name} does not match its protected source"
            )
    repository = event_payload.get("repository")
    workflow_run = event_payload.get("workflow_run")
    if not isinstance(repository, dict) or not isinstance(workflow_run, dict):
        raise ReleaseArtifactAdmissionError(
            "release-artifact admission workflow_run event payload is incomplete"
        )
    head_repository = workflow_run.get("head_repository")
    if not isinstance(head_repository, dict):
        raise ReleaseArtifactAdmissionError(
            "release-artifact builder workflow_run head repository is incomplete"
        )
    expectations: tuple[tuple[Mapping[str, Any], str, object], ...] = (
        (repository, "full_name", checked_builder["workflow_repository"]),
        (repository, "id", int(checked_builder["workflow_repository_id"])),
        (head_repository, "full_name", checked_builder["workflow_repository"]),
        (head_repository, "id", int(checked_builder["workflow_repository_id"])),
        (workflow_run, "id", int(checked_builder["workflow_run_id"])),
        (
            workflow_run,
            "run_attempt",
            checked_builder["workflow_run_attempt"],
        ),
        (workflow_run, "workflow_id", int(checked_builder["workflow_id"])),
        (workflow_run, "path", checked_builder["workflow_path"]),
        (workflow_run, "head_sha", checked_builder["workflow_commit_sha"]),
        (workflow_run, "head_branch", "main"),
        (workflow_run, "event", checked_builder["workflow_event"]),
        (workflow_run, "status", "completed"),
        (workflow_run, "conclusion", "success"),
    )
    for container, name, expected in expectations:
        if container.get(name) != expected:
            raise ReleaseArtifactAdmissionError(
                f"release-artifact builder workflow_run event {name} does not match"
            )
    bound = RuntimeBoundReleaseArtifactAdmitter(
        builder=dict(checked_builder), admitter=dict(checked_admitter)
    )
    capability = (
        _RUNTIME_BUILDER_CAPABILITY,
        canonical_json_bytes(dict(checked_builder)),
        canonical_json_bytes(dict(checked_admitter)),
        canonical_json_bytes(dict(checked_source)),
    )
    object.__setattr__(bound, "_capability", capability)
    return bound


def _require_runtime_bound_admitter(
    value: object, *, source: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    if type(value) is not RuntimeBoundReleaseArtifactAdmitter:
        raise ReleaseArtifactAdmissionError(
            "release-artifact ALLOW requires a RuntimeBoundReleaseArtifactAdmitter"
        )
    assert isinstance(value, RuntimeBoundReleaseArtifactAdmitter)
    checked_builder = validate_release_artifact_builder(value.builder)
    checked_admitter = validate_release_artifact_admitter(value.admitter)
    try:
        checked_source = validate_release_source(source)
    except ReleaseSourceFinalizerError as exc:
        raise ReleaseArtifactAdmissionError(str(exc)) from exc
    expected = (
        _RUNTIME_BUILDER_CAPABILITY,
        canonical_json_bytes(dict(checked_builder)),
        canonical_json_bytes(dict(checked_admitter)),
        canonical_json_bytes(dict(checked_source)),
    )
    capability = value._capability
    if (
        not isinstance(capability, tuple)
        or len(capability) != 4
        or capability[0] is not expected[0]
        or capability[1:] != expected[1:]
    ):
        raise ReleaseArtifactAdmissionError(
            "release-artifact builder was not bound to this exact protected runtime/source"
        )
    _validate_workflow_source_binding(checked_builder, checked_source, role="builder")
    _validate_workflow_source_binding(checked_admitter, checked_source, role="admitter")
    return checked_builder, checked_admitter


def _validate_key_separation(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ReleaseArtifactAdmissionError(
            "release-artifact key separation must be an object"
        )
    separation = dict(value)
    _require_exact_keys(
        separation,
        set(RELEASE_ARTIFACT_ADMISSION_DISTINCT_KEY_DOMAINS),
        "release-artifact key separation",
    )
    checked: dict[str, str] = {}
    for domain in sorted(RELEASE_ARTIFACT_ADMISSION_DISTINCT_KEY_DOMAINS):
        key_id = separation.get(domain)
        if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
            raise ReleaseArtifactAdmissionError(
                f"release-artifact key separation.{domain} must be "
                "sha256:<lowercase DER-SPKI digest>"
            )
        checked[domain] = key_id
    if len(set(checked.values())) != len(checked):
        raise ReleaseArtifactAdmissionError(
            "release-artifact trust domains must use mutually distinct keys"
        )
    return checked


def _validate_toolchain(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseArtifactAdmissionError(
            "release-artifact toolchain must be an object"
        )
    toolchain = dict(value)
    _require_exact_keys(toolchain, _TOOLCHAIN_KEYS, "release-artifact toolchain")
    checked: dict[str, dict[str, str]] = {}
    for name in ("git", "github_cli"):
        item = toolchain.get(name)
        if not isinstance(item, dict):
            raise ReleaseArtifactAdmissionError(
                f"release-artifact toolchain.{name} must be an object"
            )
        tool = dict(item)
        _require_exact_keys(tool, _TOOL_KEYS, f"release-artifact toolchain.{name}")
        digest = tool.get("sha256")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise ReleaseArtifactAdmissionError(
                f"release-artifact toolchain.{name}.sha256 must be lowercase SHA-256"
            )
        checked[name] = {"sha256": digest}
    raw_isolation = toolchain.get("provider_isolation")
    if not isinstance(raw_isolation, dict):
        raise ReleaseArtifactAdmissionError(
            "release-artifact toolchain.provider_isolation must be an object"
        )
    isolation = dict(raw_isolation)
    _require_exact_keys(
        isolation,
        _ISOLATION_KEYS,
        "release-artifact toolchain.provider_isolation",
    )
    uid = isolation.get("uid")
    gid = isolation.get("gid")
    if isolation.get("platform") != "posix":
        raise ReleaseArtifactAdmissionError(
            "release-artifact provider isolation platform must be 'posix'"
        )
    if type(uid) is not int or not 1 <= uid <= 2_147_483_647:
        raise ReleaseArtifactAdmissionError(
            "release-artifact provider isolation UID is invalid"
        )
    if type(gid) is not int or not 1 <= gid <= 2_147_483_647:
        raise ReleaseArtifactAdmissionError(
            "release-artifact provider isolation GID is invalid"
        )
    return {
        "git": checked["git"],
        "github_cli": checked["github_cli"],
        "provider_isolation": {"platform": "posix", "uid": uid, "gid": gid},
    }


def _expected_toolchain(
    *,
    git_executable_sha256: str,
    github_cli_executable_sha256: str,
    provider_isolation_uid: int,
    provider_isolation_gid: int,
) -> dict[str, Any]:
    return _validate_toolchain(
        {
            "git": {"sha256": git_executable_sha256},
            "github_cli": {"sha256": github_cli_executable_sha256},
            "provider_isolation": {
                "platform": "posix",
                "uid": provider_isolation_uid,
                "gid": provider_isolation_gid,
            },
        }
    )


def _validate_source_summary(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseArtifactAdmissionError(
            "release-artifact release_source must be an object"
        )
    source = dict(value)
    _require_exact_keys(source, _SOURCE_KEYS, "release-artifact release_source")
    if source.get("format") != RELEASE_SOURCE_ADMISSION_FORMAT:
        raise ReleaseArtifactAdmissionError(
            "release-artifact prerequisite format is unsupported"
        )
    if source.get("decision") != "ALLOW":
        raise ReleaseArtifactAdmissionError(
            "release-artifact prerequisite decision must be ALLOW"
        )
    key_id = source.get("key_id")
    repository = source.get("repository")
    repository_id = source.get("repository_id")
    bootstrap = source.get("bootstrap_guard_sha256")
    if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
        raise ReleaseArtifactAdmissionError(
            "release-artifact prerequisite key_id is invalid"
        )
    if (
        not isinstance(repository, str)
        or _REPOSITORY.fullmatch(repository) is None
    ):
        raise ReleaseArtifactAdmissionError(
            "release-artifact prerequisite repository is invalid"
        )
    _numeric_id(repository_id, label="release_source.repository_id")
    target_commit = _git_sha(
        source.get("target_commit_sha"), label="release_source.target_commit_sha"
    )
    target_tree = _git_sha(
        source.get("target_tree_sha"), label="release_source.target_tree_sha"
    )
    if not isinstance(bootstrap, str) or _SHA256.fullmatch(bootstrap) is None:
        raise ReleaseArtifactAdmissionError(
            "release-artifact prerequisite bootstrap digest is invalid"
        )
    return {
        "format": RELEASE_SOURCE_ADMISSION_FORMAT,
        "decision": "ALLOW",
        "bundle": _validate_descriptor(
            source.get("bundle"),
            label="release-artifact prerequisite bundle",
            path=RELEASE_ARTIFACT_ADMISSION_SOURCE_PATH,
            maximum=MAX_RELEASE_SOURCE_ADMISSION_ARCHIVE_BYTES,
        ),
        "key_id": key_id,
        "repository": repository,
        "repository_id": repository_id,
        "target_commit_sha": target_commit,
        "target_tree_sha": target_tree,
        "bootstrap_guard_sha256": bootstrap,
    }


def _validate_github_policy(value: object) -> GitHubAttestationPolicy:
    if not isinstance(value, dict):
        raise ReleaseArtifactAdmissionError(
            "release-artifact provider policy must be an object"
        )
    policy = dict(value)
    required = {
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
    _require_exact_keys(policy, required, "release-artifact provider policy")
    try:
        checked = github_attestation_policy(
            str(policy.get("repository")),
            str(policy.get("signer_workflow")),
            str(policy.get("source_digest")),
            signer_digest=str(policy.get("signer_digest")),
            source_ref=str(policy.get("source_ref")),
            cert_oidc_issuer=str(policy.get("cert_oidc_issuer")),
        )
    except GitHubAttestationError as exc:
        raise ReleaseArtifactAdmissionError(str(exc)) from exc
    if checked.as_dict() != policy:
        raise ReleaseArtifactAdmissionError(
            "release-artifact provider policy is not canonical"
        )
    return checked


def _policy_for_builder(
    builder: Mapping[str, Any], source: Mapping[str, Any]
) -> GitHubAttestationPolicy:
    try:
        return github_attestation_policy(
            str(builder["workflow_repository"]),
            f"{builder['workflow_repository']}/{builder['workflow_path']}",
            str(source["target_commit_sha"]),
            signer_digest=str(builder["workflow_commit_sha"]),
            source_ref=str(builder["workflow_ref"]),
            cert_oidc_issuer=GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
        )
    except GitHubAttestationError as exc:
        raise ReleaseArtifactAdmissionError(str(exc)) from exc


def _validate_provider(
    value: object, *, artifact: ArtifactSubject, builder: Mapping[str, Any], source: Mapping[str, Any]
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseArtifactAdmissionError(
            "release-artifact provider must be an object"
        )
    provider = dict(value)
    _require_exact_keys(provider, _PROVIDER_KEYS, "release-artifact provider")
    if provider.get("name") != "github-artifact-attestations":
        raise ReleaseArtifactAdmissionError(
            "release-artifact provider name is unsupported"
        )
    if provider.get("verified_attestation_count") != 1:
        raise ReleaseArtifactAdmissionError(
            "release-artifact provider must verify exactly one attestation"
        )
    if provider.get("artifact") != {
        "sha256": artifact.sha256,
        "size": artifact.size,
    }:
        raise ReleaseArtifactAdmissionError(
            "release-artifact provider subject does not match the signed artifact"
        )
    policy = _validate_github_policy(provider.get("policy"))
    if policy != _policy_for_builder(builder, source):
        raise ReleaseArtifactAdmissionError(
            "release-artifact provider policy is not bound to the exact builder/source"
        )
    return {
        "name": "github-artifact-attestations",
        "artifact": {"sha256": artifact.sha256, "size": artifact.size},
        "policy": policy.as_dict(),
        "verified_attestation_count": 1,
        "receipt": _validate_descriptor(
            provider.get("receipt"),
            label="release-artifact provider receipt",
            path=RELEASE_ARTIFACT_ADMISSION_GITHUB_RECEIPT_PATH,
            maximum=MAX_GITHUB_ATTESTATION_RECEIPT_BYTES,
        ),
        "raw_output": _validate_descriptor(
            provider.get("raw_output"),
            label="release-artifact provider raw output",
            path=RELEASE_ARTIFACT_ADMISSION_GITHUB_RAW_OUTPUT_PATH,
            maximum=MAX_GITHUB_ATTESTATION_OUTPUT_BYTES,
            minimum=2,
        ),
    }


def _validate_authentication(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ReleaseArtifactAdmissionError(
            "release-artifact authentication must be an object"
        )
    authentication = dict(value)
    _require_exact_keys(
        authentication, _AUTHENTICATION_KEYS, "release-artifact authentication"
    )
    if (
        authentication.get("algorithm") != "Ed25519"
        or authentication.get("purpose")
        != RELEASE_ARTIFACT_ADMISSION_SIGNATURE_PURPOSE
        or authentication.get("key_domain")
        != RELEASE_ARTIFACT_ADMISSION_KEY_DOMAIN
        or authentication.get("signature_path")
        != RELEASE_ARTIFACT_ADMISSION_SIGNATURE_PATH
    ):
        raise ReleaseArtifactAdmissionError(
            "release-artifact authentication has the wrong algorithm, purpose, domain, or path"
        )
    key_id = authentication.get("key_id")
    if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
        raise ReleaseArtifactAdmissionError(
            "release-artifact key_id must be sha256:<lowercase DER-SPKI digest>"
        )
    return {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "purpose": RELEASE_ARTIFACT_ADMISSION_SIGNATURE_PURPOSE,
        "key_domain": RELEASE_ARTIFACT_ADMISSION_KEY_DOMAIN,
        "signature_path": RELEASE_ARTIFACT_ADMISSION_SIGNATURE_PATH,
    }


def _validate_manifest(value: Mapping[str, Any]) -> dict[str, Any]:
    manifest = dict(value)
    _require_exact_keys(manifest, _MANIFEST_KEYS, "release-artifact manifest")
    if manifest.get("format") != RELEASE_ARTIFACT_ADMISSION_FORMAT:
        raise ReleaseArtifactAdmissionError(
            f"unsupported release-artifact admission format: {manifest.get('format')!r}"
        )
    if manifest.get("decision") != "ALLOW":
        raise ReleaseArtifactAdmissionError(
            "release-artifact admission decision must be ALLOW"
        )
    source = _validate_source_summary(manifest.get("release_source"))
    artifact = _validate_artifact(manifest.get("artifact"))
    builder_value = manifest.get("builder")
    admitter_value = manifest.get("admitter")
    if not isinstance(builder_value, dict) or not isinstance(admitter_value, dict):
        raise ReleaseArtifactAdmissionError(
            "release-artifact builder and admitter must be objects"
        )
    builder = validate_release_artifact_builder(builder_value)
    admitter = validate_release_artifact_admitter(admitter_value)
    for role, workflow in (("builder", builder), ("admitter", admitter)):
        if (
            workflow["workflow_repository"] != source["repository"]
            or workflow["workflow_repository_id"] != source["repository_id"]
            or workflow["workflow_commit_sha"] != source["target_commit_sha"]
        ):
            raise ReleaseArtifactAdmissionError(
                f"release-artifact {role} is not bound to the summarized protected source"
            )
    for field in ("workflow_id", "workflow_path", "workflow_run_id"):
        if builder[field] == admitter[field]:
            raise ReleaseArtifactAdmissionError(
                f"release-artifact admitter {field} must differ from the builder"
            )
    separation = _validate_key_separation(manifest.get("key_separation"))
    if separation["release_source_admission_v2"] != source["key_id"]:
        raise ReleaseArtifactAdmissionError(
            "release-artifact key registry does not name the embedded RSAE signer"
        )
    authentication = _validate_authentication(manifest.get("authentication"))
    if authentication["key_id"] in set(separation.values()):
        raise ReleaseArtifactAdmissionError(
            "release-artifact signing key belongs to an earlier trust domain"
        )
    return {
        "format": RELEASE_ARTIFACT_ADMISSION_FORMAT,
        "decision": "ALLOW",
        "release_source": source,
        "artifact": {
            "kind": "file",
            "sha256": artifact.sha256,
            "size": artifact.size,
        },
        "builder": builder,
        "admitter": admitter,
        "provider": _validate_provider(
            manifest.get("provider"),
            artifact=artifact,
            builder=builder,
            source=source,
        ),
        "toolchain": _validate_toolchain(manifest.get("toolchain")),
        "key_separation": separation,
        "authentication": authentication,
    }


def _decode_signature(data: bytes) -> bytes:
    if len(data) != 88 or any(byte > 0x7F for byte in data):
        raise ReleaseArtifactAdmissionError(
            "release-artifact signature must be exactly 88 ASCII base64 bytes"
        )
    try:
        signature = base64.b64decode(data, validate=True)
    except ValueError as exc:
        raise ReleaseArtifactAdmissionError(
            "release-artifact signature is not canonical base64"
        ) from exc
    if len(signature) != 64 or base64.b64encode(signature) != data:
        raise ReleaseArtifactAdmissionError(
            "release-artifact signature is not one canonical Ed25519 signature"
        )
    return signature


def _verify_descriptor(
    descriptor: Mapping[str, Any], data: bytes, *, label: str
) -> None:
    if descriptor != _descriptor(str(descriptor["path"]), data):
        raise ReleaseArtifactAdmissionError(
            f"{label} bytes do not match their signed descriptor"
        )


def _source_summary(
    verified: VerifiedReleaseSourceAdmission, source_bytes: bytes
) -> dict[str, Any]:
    manifest = verified.bundle.manifest
    source = manifest["source"]
    return _validate_source_summary(
        {
            "format": RELEASE_SOURCE_ADMISSION_FORMAT,
            "decision": verified.decision,
            "bundle": _descriptor(
                RELEASE_ARTIFACT_ADMISSION_SOURCE_PATH, source_bytes
            ),
            "key_id": manifest["authentication"]["key_id"],
            "repository": source["repository"],
            "repository_id": source["repository_id"],
            "target_commit_sha": source["target_commit_sha"],
            "target_tree_sha": source["target_tree_sha"],
            "bootstrap_guard_sha256": manifest["bootstrap"][
                "guard_artifact_sha256"
            ],
        }
    )


def _expected_release_source_key_separation(
    separation: Mapping[str, str],
) -> dict[str, str]:
    return {
        name: separation[name]
        for name in (
            "trusted_finalizer",
            "artifact_admission_v1",
            "artifact_digest_admission_v2",
            "release_source_finalizer_v1",
        )
    }


def _verify_release_source_snapshot(
    source_bytes: bytes,
    *,
    trusted_public_key_path: str,
    expected_source: Mapping[str, Any],
    expected_context: Mapping[str, Any],
    expected_producer: Mapping[str, Any],
    expected_admitter: Mapping[str, Any],
    expected_bootstrap_guard_sha256: str,
    expected_github_policy: Mapping[str, Any],
    expected_key_separation: Mapping[str, str],
    expected_git_executable_sha256: str,
    expected_github_cli_executable_sha256: str,
    expected_provider_isolation_uid: int,
    expected_provider_isolation_gid: int,
) -> VerifiedReleaseSourceAdmission:
    with tempfile.TemporaryDirectory(
        prefix=".evoguard-release-artifact-source-"
    ) as directory:
        path = os.path.join(directory, "source.rsae")
        with open(path, "xb") as handle:
            handle.write(source_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            verified = verify_release_source_admission(
                path,
                trusted_public_key_path=trusted_public_key_path,
                expected_source=expected_source,
                expected_context=expected_context,
                expected_producer=expected_producer,
                expected_admitter=expected_admitter,
                expected_bootstrap_guard_sha256=expected_bootstrap_guard_sha256,
                expected_github_policy=expected_github_policy,
                expected_key_separation=_expected_release_source_key_separation(
                    expected_key_separation
                ),
                expected_git_executable_sha256=expected_git_executable_sha256,
                expected_github_cli_executable_sha256=(
                    expected_github_cli_executable_sha256
                ),
                expected_provider_isolation_uid=expected_provider_isolation_uid,
                expected_provider_isolation_gid=expected_provider_isolation_gid,
            )
        except ReleaseSourceAdmissionError as exc:
            raise ReleaseArtifactAdmissionError(
                f"release-source admission prerequisite is invalid: {exc}"
            ) from exc
    if verified.decision != "ALLOW":
        raise ReleaseArtifactAdmissionError(
            "release-artifact admission requires a verified release-source ALLOW"
        )
    return verified


def _verify_workflow_blob(
    *,
    source: Mapping[str, Any],
    workflow: Mapping[str, Any],
    role: str,
    git_repository: str,
    git_repository_is_bare: bool,
    git_executable: GitExecutablePin,
) -> None:
    try:
        from evoom_guard.finalizer_derivation import FinalizerDerivationError

        object_id = resolve_raw_git_regular_blob(
            repository=git_repository,
            treeish=str(source["target_tree_sha"]),
            path=str(workflow["workflow_path"]),
            bare=git_repository_is_bare,
            git_executable=git_executable,
        )
    except FinalizerDerivationError as exc:
        raise ReleaseArtifactAdmissionError(
            f"could not resolve {role} workflow from raw Git: {exc}"
        ) from exc
    if object_id != workflow["workflow_blob_sha"]:
        raise ReleaseArtifactAdmissionError(
            f"{role} workflow blob does not match the protected-main raw Git tree"
        )


def _validate_role_separation(
    builder: Mapping[str, Any],
    admitter: Mapping[str, Any],
    release_source_manifest: Mapping[str, Any],
) -> None:
    identities: list[tuple[object, object, object]] = []
    for role in ("producer", "admitter"):
        item = release_source_manifest[role]
        identities.append(
            (item["workflow_id"], item["workflow_path"], item["workflow_run_id"])
        )
    producer = release_source_manifest["producer"]
    identities.append(
        (
            producer["trigger_workflow_id"],
            producer["trigger_workflow_path"],
            producer["trigger_workflow_run_id"],
        )
    )
    for role, workflow in (("builder", builder), ("admitter", admitter)):
        candidate = (
            workflow["workflow_id"],
            workflow["workflow_path"],
            workflow["workflow_run_id"],
        )
        if any(
            candidate[index] == identity[index]
            for identity in identities
            for index in range(3)
        ):
            raise ReleaseArtifactAdmissionError(
                f"{role} workflow ID, path, and run must be distinct from every release-source role"
            )
    for field in ("workflow_id", "workflow_path", "workflow_run_id"):
        if builder[field] == admitter[field]:
            raise ReleaseArtifactAdmissionError(
                f"release-artifact admitter {field} must differ from the builder"
            )


def _verify_github_materials(
    *,
    receipt_bytes: bytes,
    raw_output_bytes: bytes,
    artifact: ArtifactSubject,
    policy: GitHubAttestationPolicy,
    builder: Mapping[str, Any],
) -> None:
    github_artifact = GitHubAttestationArtifact(
        sha256=artifact.sha256, size=artifact.size
    )
    try:
        verified_output = validate_github_attestation_verifier_output(
            raw_output_bytes,
            artifact=github_artifact,
            policy=policy,
            expected_workflow_run_id=str(builder["workflow_run_id"]),
            expected_workflow_run_attempt=int(builder["workflow_run_attempt"]),
        )
        receipt = validate_github_attestation_receipt(
            load_json_object_bytes(receipt_bytes, "GitHub attestation receipt")
        )
        if canonical_json_bytes(receipt) != receipt_bytes:
            raise ReleaseArtifactAdmissionError(
                "GitHub attestation receipt is not canonical JSON"
            )
    except (EvidenceBundleError, GitHubAttestationError) as exc:
        raise ReleaseArtifactAdmissionError(str(exc)) from exc
    if (
        verified_output.workflow_run_id != builder["workflow_run_id"]
        or verified_output.workflow_run_attempt != builder["workflow_run_attempt"]
    ):
        raise ReleaseArtifactAdmissionError(
            "GitHub attestation output does not name the exact builder run"
        )
    if receipt["artifact"] != github_artifact.as_dict():
        raise ReleaseArtifactAdmissionError(
            "GitHub attestation receipt does not name the exact artifact"
        )
    if receipt["verification_policy"] != policy.as_dict():
        raise ReleaseArtifactAdmissionError(
            "GitHub attestation receipt does not contain the exact provider policy"
        )
    expected_output = {
        "sha256": sha256_bytes(raw_output_bytes),
        "size": len(raw_output_bytes),
        "verified_attestation_count": 1,
    }
    if receipt["verification_output"] != expected_output:
        raise ReleaseArtifactAdmissionError(
            "GitHub attestation receipt does not bind the exact raw verifier output"
        )


def _snapshot_created_provider_evidence(
    created: CreatedGitHubAttestationReceipt,
    *,
    artifact: ArtifactSubject,
    policy: GitHubAttestationPolicy,
    builder: Mapping[str, Any],
) -> tuple[bytes, bytes, dict[str, Any]]:
    if type(created) is not CreatedGitHubAttestationReceipt:
        raise ReleaseArtifactAdmissionError(
            "release-artifact admission requires a fresh CreatedGitHubAttestationReceipt"
        )
    if created.verified_attestation_count != 1:
        raise ReleaseArtifactAdmissionError(
            "fresh provider verification count must be exactly one"
        )
    if created.artifact.as_dict() != {
        "sha256": artifact.sha256,
        "size": artifact.size,
    }:
        raise ReleaseArtifactAdmissionError(
            "fresh provider verification subject is not the exact artifact"
        )
    if created.policy != policy:
        raise ReleaseArtifactAdmissionError(
            "fresh provider verification policy is not the expected builder policy"
        )
    if os.path.abspath(created.receipt_path) == os.path.abspath(
        created.raw_output_path
    ):
        raise ReleaseArtifactAdmissionError(
            "GitHub receipt and raw-output paths must differ"
        )
    try:
        receipt_bytes = read_regular_file_bytes(
            created.receipt_path,
            limit=MAX_GITHUB_ATTESTATION_RECEIPT_BYTES,
            label="fresh GitHub attestation receipt",
        )
        raw_output_bytes = read_regular_file_bytes(
            created.raw_output_path,
            limit=MAX_GITHUB_ATTESTATION_OUTPUT_BYTES,
            label="fresh GitHub attestation raw output",
        )
    except EvidenceBundleError as exc:
        raise ReleaseArtifactAdmissionError(str(exc)) from exc
    _verify_github_materials(
        receipt_bytes=receipt_bytes,
        raw_output_bytes=raw_output_bytes,
        artifact=artifact,
        policy=policy,
        builder=builder,
    )
    provider = _validate_provider(
        {
            "name": "github-artifact-attestations",
            "artifact": {"sha256": artifact.sha256, "size": artifact.size},
            "policy": policy.as_dict(),
            "verified_attestation_count": 1,
            "receipt": _descriptor(
                RELEASE_ARTIFACT_ADMISSION_GITHUB_RECEIPT_PATH, receipt_bytes
            ),
            "raw_output": _descriptor(
                RELEASE_ARTIFACT_ADMISSION_GITHUB_RAW_OUTPUT_PATH,
                raw_output_bytes,
            ),
        },
        artifact=artifact,
        builder=builder,
        source={"target_commit_sha": policy.source_digest},
    )
    return receipt_bytes, raw_output_bytes, provider


def _path_identity(path: str) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(path)))


def _validate_seal_paths(
    *,
    release_source_admission_path: str,
    artifact_path: str,
    output_path: str,
    trusted_release_source_public_key_path: str,
    private_key_path: str,
    signing_public_key_path: str,
) -> None:
    paths = {
        "release-source admission": release_source_admission_path,
        "artifact": artifact_path,
        "output": output_path,
        "trusted release-source public key": trusted_release_source_public_key_path,
        "private key": private_key_path,
        "signing public key": signing_public_key_path,
    }
    if any(value == "-" for value in paths.values()):
        raise ReleaseArtifactAdmissionError(
            "release-artifact inputs, output, and keys must be regular paths"
        )
    if not output_path.endswith(RELEASE_ARTIFACT_ADMISSION_EXTENSION):
        raise ReleaseArtifactAdmissionError(
            f"release-artifact output must use {RELEASE_ARTIFACT_ADMISSION_EXTENSION!r}"
        )
    identities = {name: _path_identity(path) for name, path in paths.items()}
    if len(set(identities.values())) != len(identities):
        raise ReleaseArtifactAdmissionError(
            "release-artifact source, artifact, output, and key paths must all differ"
        )
    output = os.path.abspath(output_path)
    if os.path.isdir(output):
        raise ReleaseArtifactAdmissionError(
            f"release-artifact output is a directory: {output}"
        )


def _inspect_embedded_source(
    source_bytes: bytes,
    summary: Mapping[str, Any],
    separation: Mapping[str, str],
    *,
    builder: Mapping[str, Any],
    admitter: Mapping[str, Any],
) -> None:
    with tempfile.TemporaryDirectory(
        prefix=".evoguard-release-artifact-inspect-source-"
    ) as directory:
        path = os.path.join(directory, "source.rsae")
        with open(path, "xb") as handle:
            handle.write(source_bytes)
        try:
            inspected = inspect_release_source_admission(path)
            manifest = inspected.manifest
        except ReleaseSourceAdmissionError as exc:
            raise ReleaseArtifactAdmissionError(
                f"embedded release-source admission is invalid: {exc}"
            ) from exc
    source = manifest["source"]
    expected = {
        "format": RELEASE_SOURCE_ADMISSION_FORMAT,
        "decision": manifest["decision"],
        "bundle": _descriptor(RELEASE_ARTIFACT_ADMISSION_SOURCE_PATH, source_bytes),
        "key_id": manifest["authentication"]["key_id"],
        "repository": source["repository"],
        "repository_id": source["repository_id"],
        "target_commit_sha": source["target_commit_sha"],
        "target_tree_sha": source["target_tree_sha"],
        "bootstrap_guard_sha256": manifest["bootstrap"]["guard_artifact_sha256"],
    }
    if dict(summary) != expected:
        raise ReleaseArtifactAdmissionError(
            "embedded release-source admission does not match its signed summary"
        )
    if manifest["key_separation"] != _expected_release_source_key_separation(
        separation
    ):
        raise ReleaseArtifactAdmissionError(
            "embedded release-source admission key registry does not match RAAE"
        )
    if (
        manifest["authentication"]["key_id"]
        != separation["release_source_admission_v2"]
    ):
        raise ReleaseArtifactAdmissionError(
            "embedded release-source signer does not match the RAAE key registry"
        )
    _validate_role_separation(builder, admitter, manifest)


def inspect_release_artifact_admission(
    path: str,
) -> InspectedReleaseArtifactAdmission:
    """Inspect canonical RAAE bytes without trusting its signing key."""

    try:
        snapshot = read_regular_file_bytes(
            path,
            limit=MAX_RELEASE_ARTIFACT_ADMISSION_ARCHIVE_BYTES,
            label="release-artifact admission bundle",
        )
        declared = preflight_canonical_zip(snapshot)
        with zipfile.ZipFile(io.BytesIO(snapshot), mode="r") as archive:
            infos = archive.infolist()
            if declared != len(_ARCHIVE_PATHS) or len(infos) != len(
                _ARCHIVE_PATHS
            ):
                raise ReleaseArtifactAdmissionError(
                    "release-artifact admission archive must contain exactly five members"
                )
            if tuple(info.filename for info in infos) != _ARCHIVE_PATHS:
                raise ReleaseArtifactAdmissionError(
                    "release-artifact archive member names/order are not canonical"
                )
            for info in infos:
                validate_canonical_archive_member(info)
            limits = (
                MAX_RELEASE_ARTIFACT_ADMISSION_MANIFEST_BYTES,
                88,
                MAX_RELEASE_SOURCE_ADMISSION_ARCHIVE_BYTES,
                MAX_GITHUB_ATTESTATION_RECEIPT_BYTES,
                MAX_GITHUB_ATTESTATION_OUTPUT_BYTES,
            )
            values = tuple(
                read_archive_member_bytes(archive, info, limit=limit)
                for info, limit in zip(infos, limits, strict=True)
            )
    except (EvidenceBundleError, OSError, zipfile.BadZipFile) as exc:
        raise ReleaseArtifactAdmissionError(str(exc)) from exc
    (
        manifest_bytes,
        signature_bytes,
        source_bytes,
        receipt_bytes,
        raw_output_bytes,
    ) = values
    try:
        manifest = _validate_manifest(
            load_json_object_bytes(
                manifest_bytes, "release-artifact admission manifest"
            )
        )
        if canonical_json_bytes(manifest) != manifest_bytes:
            raise ReleaseArtifactAdmissionError(
                "release-artifact admission manifest is not canonical JSON"
            )
    except EvidenceBundleError as exc:
        raise ReleaseArtifactAdmissionError(str(exc)) from exc
    signature = _decode_signature(signature_bytes)
    _verify_descriptor(
        manifest["release_source"]["bundle"],
        source_bytes,
        label="release-source admission",
    )
    _verify_descriptor(
        manifest["provider"]["receipt"], receipt_bytes, label="provider receipt"
    )
    _verify_descriptor(
        manifest["provider"]["raw_output"],
        raw_output_bytes,
        label="provider raw output",
    )
    artifact = _validate_artifact(manifest["artifact"])
    policy = _validate_github_policy(manifest["provider"]["policy"])
    _verify_github_materials(
        receipt_bytes=receipt_bytes,
        raw_output_bytes=raw_output_bytes,
        artifact=artifact,
        policy=policy,
        builder=manifest["builder"],
    )
    _inspect_embedded_source(
        source_bytes,
        manifest["release_source"],
        manifest["key_separation"],
        builder=manifest["builder"],
        admitter=manifest["admitter"],
    )
    if (
        canonical_archive_bytes(
            (
                (RELEASE_ARTIFACT_ADMISSION_MANIFEST_PATH, manifest_bytes),
                (RELEASE_ARTIFACT_ADMISSION_SIGNATURE_PATH, signature_bytes),
                (RELEASE_ARTIFACT_ADMISSION_SOURCE_PATH, source_bytes),
                (
                    RELEASE_ARTIFACT_ADMISSION_GITHUB_RECEIPT_PATH,
                    receipt_bytes,
                ),
                (
                    RELEASE_ARTIFACT_ADMISSION_GITHUB_RAW_OUTPUT_PATH,
                    raw_output_bytes,
                ),
            )
        )
        != snapshot
    ):
        raise ReleaseArtifactAdmissionError(
            "release-artifact admission archive bytes are not canonical"
        )
    return InspectedReleaseArtifactAdmission(
        manifest_bytes=manifest_bytes,
        signature=signature,
        release_source_admission_bytes=source_bytes,
        github_receipt_bytes=receipt_bytes,
        github_raw_output_bytes=raw_output_bytes,
    )


def _publish_verified_release_artifact_admission(
    output_path: str,
    archive_bytes: bytes,
    *,
    expected_manifest: Mapping[str, Any],
    signing_public_key_path: str,
    expected_signing_key_id: str,
    force: bool,
) -> tuple[str, InspectedReleaseArtifactAdmission]:
    absolute = os.path.abspath(output_path)
    parent = os.path.dirname(absolute) or os.curdir
    os.makedirs(parent, exist_ok=True)
    descriptor, staging = tempfile.mkstemp(
        prefix=".evoguard-release-artifact-admission-", dir=parent
    )
    promoted = False
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(archive_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(staging, 0o600)
        published = inspect_release_artifact_admission(staging)
        if published.manifest != dict(expected_manifest):
            raise ReleaseArtifactAdmissionError(
                "staged release-artifact admission changed its verified manifest"
            )
        from evoom_guard.signing import verify_bytes_with_key_id

        verified, key_id = verify_bytes_with_key_id(
            RELEASE_ARTIFACT_ADMISSION_SIGNATURE_DOMAIN
            + published.manifest_bytes,
            published.signature,
            signing_public_key_path,
        )
        if key_id != expected_signing_key_id or not verified:
            raise ReleaseArtifactAdmissionError(
                "staged release-artifact admission failed cryptographic verification"
            )
        if force:
            os.replace(staging, absolute)
        else:
            try:
                os.link(staging, absolute, follow_symlinks=False)
            except FileExistsError as exc:
                raise ReleaseArtifactAdmissionError(
                    f"refusing to overwrite existing release-artifact admission: {absolute}"
                ) from exc
            except OSError as exc:
                raise ReleaseArtifactAdmissionError(
                    "cannot publish release-artifact admission with atomic no-clobber "
                    "semantics; use a filesystem supporting hard links or pass force=True"
                ) from exc
            os.unlink(staging)
        promoted = True
        os.chmod(absolute, 0o644)
        return absolute, published
    except OSError as exc:
        raise ReleaseArtifactAdmissionError(
            f"cannot stage or publish release-artifact admission: {exc}"
        ) from exc
    finally:
        if not promoted:
            try:
                os.unlink(staging)
            except OSError:
                pass


def seal_release_artifact_admission(
    release_source_admission_path: str,
    artifact_path: str,
    output_path: str,
    *,
    admitter: RuntimeBoundReleaseArtifactAdmitter,
    trusted_release_source_public_key_path: str,
    expected_release_source: Mapping[str, Any],
    expected_release_source_context: Mapping[str, Any],
    expected_release_source_producer: Mapping[str, Any],
    expected_release_source_admitter: Mapping[str, Any],
    expected_release_source_bootstrap_guard_sha256: str,
    expected_release_source_github_policy: Mapping[str, Any],
    expected_release_source_git_executable_sha256: str,
    expected_release_source_github_cli_executable_sha256: str,
    expected_release_source_provider_isolation_uid: int,
    expected_release_source_provider_isolation_gid: int,
    key_separation: Mapping[str, Any],
    git_repository: str,
    git_repository_is_bare: bool = False,
    git_executable: GitExecutablePin,
    provider_isolation: GitHubAttestationProviderIsolation,
    private_key_path: str,
    signing_public_key_path: str,
    expected_signing_key_id: str,
    gh_executable: str = "gh",
    timeout_seconds: int = DEFAULT_GITHUB_ATTESTATION_TIMEOUT_SECONDS,
    force: bool = False,
) -> SealedReleaseArtifactAdmission:
    """Freshly verify and seal a protected-main release artifact.

    The private key is opened only after the provider process has exited, its
    temporary files have been cleaned, and every source/artifact/builder/
    receipt check has succeeded.
    """

    _validate_seal_paths(
        release_source_admission_path=release_source_admission_path,
        artifact_path=artifact_path,
        output_path=output_path,
        trusted_release_source_public_key_path=(
            trusted_release_source_public_key_path
        ),
        private_key_path=private_key_path,
        signing_public_key_path=signing_public_key_path,
    )
    output_absolute = os.path.abspath(output_path)
    if os.path.lexists(output_absolute) and not force:
        raise ReleaseArtifactAdmissionError(
            f"refusing to overwrite existing release-artifact admission: {output_absolute}"
        )
    separation = _validate_key_separation(key_separation)
    if (
        not isinstance(expected_signing_key_id, str)
        or _KEY_ID.fullmatch(expected_signing_key_id) is None
    ):
        raise ReleaseArtifactAdmissionError(
            "expected release-artifact signing key ID must be sha256:<DER-SPKI digest>"
        )
    if expected_signing_key_id in set(separation.values()):
        raise ReleaseArtifactAdmissionError(
            "expected release-artifact signing key belongs to an earlier trust domain"
        )
    if type(git_executable) is not GitExecutablePin:
        raise ReleaseArtifactAdmissionError(
            "release-artifact raw-Git reader requires an exact GitExecutablePin"
        )
    if type(provider_isolation) is not GitHubAttestationProviderIsolation:
        raise ReleaseArtifactAdmissionError(
            "release-artifact provider requires GitHubAttestationProviderIsolation"
        )
    from evoom_guard.signing import public_key_id

    try:
        if public_key_id(signing_public_key_path) != expected_signing_key_id:
            raise ReleaseArtifactAdmissionError(
                "release-artifact signing public key does not match its external key ID"
            )
    except (OSError, ValueError) as exc:
        raise ReleaseArtifactAdmissionError(
            f"cannot validate release-artifact signing public key: {exc}"
        ) from exc
    try:
        validate_provider_isolated_signing_key_path(
            private_key_path, provider_isolation
        )
    except GitHubAttestationError as exc:
        raise ReleaseArtifactAdmissionError(
            f"provider isolation does not protect the release-artifact key: {exc}"
        ) from exc
    try:
        source_bytes = read_regular_file_bytes(
            release_source_admission_path,
            limit=MAX_RELEASE_SOURCE_ADMISSION_ARCHIVE_BYTES,
            label="release-source admission prerequisite",
        )
    except EvidenceBundleError as exc:
        raise ReleaseArtifactAdmissionError(str(exc)) from exc
    verified_source = _verify_release_source_snapshot(
        source_bytes,
        trusted_public_key_path=trusted_release_source_public_key_path,
        expected_source=expected_release_source,
        expected_context=expected_release_source_context,
        expected_producer=expected_release_source_producer,
        expected_admitter=expected_release_source_admitter,
        expected_bootstrap_guard_sha256=(
            expected_release_source_bootstrap_guard_sha256
        ),
        expected_github_policy=expected_release_source_github_policy,
        expected_key_separation=separation,
        expected_git_executable_sha256=(
            expected_release_source_git_executable_sha256
        ),
        expected_github_cli_executable_sha256=(
            expected_release_source_github_cli_executable_sha256
        ),
        expected_provider_isolation_uid=(
            expected_release_source_provider_isolation_uid
        ),
        expected_provider_isolation_gid=(
            expected_release_source_provider_isolation_gid
        ),
    )
    source_manifest = verified_source.bundle.manifest
    if (
        source_manifest["authentication"]["key_id"]
        != separation["release_source_admission_v2"]
    ):
        raise ReleaseArtifactAdmissionError(
            "verified release-source signer does not match the RAAE key registry"
        )
    checked_builder, checked_admitter = _require_runtime_bound_admitter(
        admitter, source=source_manifest["source"]
    )
    _validate_role_separation(checked_builder, checked_admitter, source_manifest)
    for role, workflow in (
        ("builder", checked_builder),
        ("admitter", checked_admitter),
    ):
        _verify_workflow_blob(
            source=source_manifest["source"],
            workflow=workflow,
            role=role,
            git_repository=git_repository,
            git_repository_is_bare=git_repository_is_bare,
            git_executable=git_executable,
        )
    try:
        artifact = hash_regular_artifact(artifact_path)
    except ArtifactAdmissionError as exc:
        raise ReleaseArtifactAdmissionError(str(exc)) from exc
    policy = _policy_for_builder(checked_builder, source_manifest["source"])

    # Provider output is intentionally confined to a temporary directory.  It
    # is copied to immutable bytes and the directory is removed before the
    # private signing key is opened below.
    with tempfile.TemporaryDirectory(
        prefix=".evoguard-release-artifact-provider-"
    ) as provider_directory:
        receipt_path = os.path.join(provider_directory, "receipt.json")
        raw_output_path = os.path.join(provider_directory, "output.json")
        try:
            created = create_github_attestation_receipt(
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
                expected_workflow_run_id=checked_builder["workflow_run_id"],
                expected_workflow_run_attempt=checked_builder[
                    "workflow_run_attempt"
                ],
                provider_isolation=provider_isolation,
            )
        except GitHubAttestationError as exc:
            raise ReleaseArtifactAdmissionError(
                f"fresh GitHub artifact attestation verification failed: {exc}"
            ) from exc
        receipt_bytes, raw_output_bytes, provider = (
            _snapshot_created_provider_evidence(
                created,
                artifact=artifact,
                policy=policy,
                builder=checked_builder,
            )
        )

    source_summary = _source_summary(verified_source, source_bytes)
    toolchain = _expected_toolchain(
        git_executable_sha256=git_executable.executable_sha256,
        github_cli_executable_sha256=provider_isolation.executable_sha256,
        provider_isolation_uid=provider_isolation.uid,
        provider_isolation_gid=provider_isolation.gid,
    )

    # This is the first private-key read in the operation.  Every untrusted
    # input and the isolated provider lifecycle have completed above.
    from evoom_guard.signing import load_signing_key_snapshot, sign_bytes_with_snapshot

    signing_key = load_signing_key_snapshot(private_key_path)
    if signing_key.key_id != expected_signing_key_id:
        raise ReleaseArtifactAdmissionError(
            "release-artifact private key does not match the externally expected public key"
        )
    if signing_key.key_id in set(separation.values()):
        raise ReleaseArtifactAdmissionError(
            "release-artifact signing key belongs to an earlier trust domain"
        )
    manifest = {
        "format": RELEASE_ARTIFACT_ADMISSION_FORMAT,
        "decision": "ALLOW",
        "release_source": source_summary,
        "artifact": {
            "kind": "file",
            "sha256": artifact.sha256,
            "size": artifact.size,
        },
        "builder": checked_builder,
        "admitter": checked_admitter,
        "provider": provider,
        "toolchain": toolchain,
        "key_separation": separation,
        "authentication": {
            "algorithm": "Ed25519",
            "key_id": signing_key.key_id,
            "purpose": RELEASE_ARTIFACT_ADMISSION_SIGNATURE_PURPOSE,
            "key_domain": RELEASE_ARTIFACT_ADMISSION_KEY_DOMAIN,
            "signature_path": RELEASE_ARTIFACT_ADMISSION_SIGNATURE_PATH,
        },
    }
    checked_manifest = _validate_manifest(manifest)
    try:
        manifest_bytes = canonical_json_bytes(checked_manifest)
    except EvidenceBundleError as exc:
        raise ReleaseArtifactAdmissionError(str(exc)) from exc
    if len(manifest_bytes) > MAX_RELEASE_ARTIFACT_ADMISSION_MANIFEST_BYTES:
        raise ReleaseArtifactAdmissionError(
            "release-artifact admission manifest exceeds its size limit"
        )
    signature, actual_key_id = sign_bytes_with_snapshot(
        RELEASE_ARTIFACT_ADMISSION_SIGNATURE_DOMAIN + manifest_bytes,
        signing_key,
    )
    if actual_key_id != signing_key.key_id or len(signature) != 64:
        raise ReleaseArtifactAdmissionError(
            "release-artifact signer returned inconsistent identity or signature"
        )
    signature_bytes = base64.b64encode(signature)
    archive = canonical_archive_bytes(
        (
            (RELEASE_ARTIFACT_ADMISSION_MANIFEST_PATH, manifest_bytes),
            (RELEASE_ARTIFACT_ADMISSION_SIGNATURE_PATH, signature_bytes),
            (RELEASE_ARTIFACT_ADMISSION_SOURCE_PATH, source_bytes),
            (RELEASE_ARTIFACT_ADMISSION_GITHUB_RECEIPT_PATH, receipt_bytes),
            (
                RELEASE_ARTIFACT_ADMISSION_GITHUB_RAW_OUTPUT_PATH,
                raw_output_bytes,
            ),
        )
    )
    if len(archive) > MAX_RELEASE_ARTIFACT_ADMISSION_ARCHIVE_BYTES:
        raise ReleaseArtifactAdmissionError(
            "release-artifact admission archive exceeds its size limit"
        )
    bundle_path, published = _publish_verified_release_artifact_admission(
        output_path,
        archive,
        expected_manifest=checked_manifest,
        signing_public_key_path=signing_public_key_path,
        expected_signing_key_id=expected_signing_key_id,
        force=force,
    )
    return SealedReleaseArtifactAdmission(
        bundle_path=bundle_path,
        manifest=published.manifest,
        artifact=artifact,
        decision="ALLOW",
    )


def verify_release_artifact_admission(
    bundle_path: str,
    artifact_path: str,
    *,
    trusted_public_key_path: str,
    trusted_release_source_public_key_path: str,
    expected_release_source: Mapping[str, Any],
    expected_release_source_context: Mapping[str, Any],
    expected_release_source_producer: Mapping[str, Any],
    expected_release_source_admitter: Mapping[str, Any],
    expected_release_source_bootstrap_guard_sha256: str,
    expected_release_source_github_policy: Mapping[str, Any],
    expected_release_source_git_executable_sha256: str,
    expected_release_source_github_cli_executable_sha256: str,
    expected_release_source_provider_isolation_uid: int,
    expected_release_source_provider_isolation_gid: int,
    expected_builder: Mapping[str, Any],
    expected_admitter: Mapping[str, Any],
    expected_key_separation: Mapping[str, Any],
    expected_git_executable_sha256: str,
    expected_github_cli_executable_sha256: str,
    expected_provider_isolation_uid: int,
    expected_provider_isolation_gid: int,
) -> VerifiedReleaseArtifactAdmission:
    """Verify one RAAE and detached artifact entirely offline."""

    separation = _validate_key_separation(expected_key_separation)
    builder = validate_release_artifact_builder(expected_builder)
    admitter = validate_release_artifact_admitter(expected_admitter)
    try:
        source = validate_release_source(expected_release_source)
    except ReleaseSourceFinalizerError as exc:
        raise ReleaseArtifactAdmissionError(str(exc)) from exc
    _validate_workflow_source_binding(builder, source, role="builder")
    _validate_workflow_source_binding(admitter, source, role="admitter")
    toolchain = _expected_toolchain(
        git_executable_sha256=expected_git_executable_sha256,
        github_cli_executable_sha256=expected_github_cli_executable_sha256,
        provider_isolation_uid=expected_provider_isolation_uid,
        provider_isolation_gid=expected_provider_isolation_gid,
    )
    try:
        artifact = hash_regular_artifact(artifact_path)
    except ArtifactAdmissionError as exc:
        raise ReleaseArtifactAdmissionError(str(exc)) from exc
    bundle = inspect_release_artifact_admission(bundle_path)
    manifest = bundle.manifest
    if (
        manifest["artifact"]
        != {"kind": "file", "sha256": artifact.sha256, "size": artifact.size}
        or manifest["builder"] != builder
        or manifest["admitter"] != admitter
        or manifest["toolchain"] != toolchain
        or manifest["key_separation"] != separation
    ):
        raise ReleaseArtifactAdmissionError(
            "release-artifact admission does not match external artifact/builder/tool/key expectations"
        )
    from evoom_guard.signing import verify_bytes_with_key_id

    verified_signature, trusted_key_id = verify_bytes_with_key_id(
        RELEASE_ARTIFACT_ADMISSION_SIGNATURE_DOMAIN + bundle.manifest_bytes,
        bundle.signature,
        trusted_public_key_path,
    )
    if trusted_key_id in set(separation.values()):
        raise ReleaseArtifactAdmissionError(
            "release-artifact public key belongs to an earlier trust domain"
        )
    if manifest["authentication"]["key_id"] != trusted_key_id:
        raise ReleaseArtifactAdmissionError(
            "release-artifact key_id does not match the externally trusted public key"
        )
    if not verified_signature:
        raise ReleaseArtifactAdmissionError(
            "release-artifact signature is invalid under the trusted public key"
        )
    verified_source = _verify_release_source_snapshot(
        bundle.release_source_admission_bytes,
        trusted_public_key_path=trusted_release_source_public_key_path,
        expected_source=source,
        expected_context=expected_release_source_context,
        expected_producer=expected_release_source_producer,
        expected_admitter=expected_release_source_admitter,
        expected_bootstrap_guard_sha256=(
            expected_release_source_bootstrap_guard_sha256
        ),
        expected_github_policy=expected_release_source_github_policy,
        expected_key_separation=separation,
        expected_git_executable_sha256=(
            expected_release_source_git_executable_sha256
        ),
        expected_github_cli_executable_sha256=(
            expected_release_source_github_cli_executable_sha256
        ),
        expected_provider_isolation_uid=(
            expected_release_source_provider_isolation_uid
        ),
        expected_provider_isolation_gid=(
            expected_release_source_provider_isolation_gid
        ),
    )
    if manifest["release_source"] != _source_summary(
        verified_source, bundle.release_source_admission_bytes
    ):
        raise ReleaseArtifactAdmissionError(
            "release-artifact signed source summary does not match the verified RSAE"
        )
    _validate_role_separation(
        builder, admitter, verified_source.bundle.manifest
    )
    policy = _policy_for_builder(builder, source)
    if manifest["provider"]["policy"] != policy.as_dict():
        raise ReleaseArtifactAdmissionError(
            "release-artifact provider policy does not match external source/builder"
        )
    _verify_github_materials(
        receipt_bytes=bundle.github_receipt_bytes,
        raw_output_bytes=bundle.github_raw_output_bytes,
        artifact=artifact,
        policy=policy,
        builder=builder,
    )
    return VerifiedReleaseArtifactAdmission(
        bundle=bundle,
        release_source=verified_source,
        artifact=artifact,
        decision="ALLOW",
    )
