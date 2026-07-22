# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Separately keyed release-source admission after fresh provider verification.

V1 release-source evidence remains DENY-only.  This module defines a distinct
V2 envelope whose only sealing input is an
``AttestedReleaseSourceProducerReceipt``.  That value is returned after the
local receipt, raw-Git, workflow-blob, verdict/handoff, bootstrap, and fresh
GitHub Artifact Attestation checks have all succeeded.

The envelope preserves every byte needed to audit that transition.  The V2
format, signature purpose, key domain, and signing domain are intentionally
unrelated to the V1 release finalizer, PR finalizer, and artifact-admission
contracts.  Callers must additionally prohibit the public-key IDs assigned to
those other trust domains through the exact closed-world key registry.  The V2
signature includes the protected key-bearing workflow identity and run attempt
after the admitting CLI has matched them to raw Git, the current ``GITHUB_*``
context, and the triggering ``workflow_run`` event.  GitHub's control plane,
the reviewed workflow, the pinned verifier tools, and the signing key remain
trust roots; the envelope is not independent proof of GitHub itself.
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
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from evoom_guard.finalizer_derivation import GitExecutablePin

from evoom_guard.evidence_bundle import (
    MAX_ARCHIVE_BYTES,
    MAX_VERDICT_BYTES,
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
from evoom_guard.github_attestation import (
    GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
    MAX_GITHUB_ATTESTATION_OUTPUT_BYTES,
    MAX_GITHUB_ATTESTATION_RECEIPT_BYTES,
    CreatedGitHubAttestationReceipt,
    GitHubAttestationArtifact,
    GitHubAttestationError,
    GitHubAttestationPolicy,
    GitHubAttestationProviderIsolation,
    github_attestation_policy,
    validate_github_attestation_receipt,
    validate_github_attestation_verifier_output,
)
from evoom_guard.record_verifier import verify_record
from evoom_guard.release_source_finalizer import (
    MAX_RELEASE_SOURCE_HANDOFF_BYTES,
    ReleaseSourceFinalizerError,
    context_from_release_source_bindings,
    inspect_release_source_handoff_bytes,
    validate_release_source,
    validate_release_source_context,
    validate_release_source_context_binding,
    verify_release_source_handoff,
)
from evoom_guard.release_source_producer_receipt import (
    MAX_RELEASE_SOURCE_PRODUCER_RECEIPT_BYTES,
    RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT,
    RELEASE_SOURCE_PRODUCER_RUNTIME_FORMAT,
    AttestedReleaseSourceProducerReceipt,
    ReleaseSourceProducerReceiptError,
    RuntimeBoundReleaseSourceAdmitter,
    is_admission_capable_attested_release_source_producer_receipt,
    is_fresh_attested_release_source_producer_receipt,
    require_runtime_bound_release_source_admitter,
    validate_release_source_admitter,
    validate_release_source_admitter_binding,
    validate_release_source_allow_record,
    validate_release_source_context_producer_binding,
    validate_release_source_producer,
    validate_release_source_producer_receipt,
    verify_release_source_admitter_workflow_blob,
)

RELEASE_SOURCE_ADMISSION_FORMAT = "EVOGUARD_RELEASE_SOURCE_ADMISSION_V2"
RELEASE_SOURCE_ADMISSION_SIGNATURE_PURPOSE = "evoguard-release-source-admission-v2"
RELEASE_SOURCE_ADMISSION_KEY_DOMAIN = "release-source-admission-v2"
RELEASE_SOURCE_ADMISSION_SIGNATURE_DOMAIN = (
    RELEASE_SOURCE_ADMISSION_FORMAT.encode("ascii") + b"\0"
)

RELEASE_SOURCE_ADMISSION_MANIFEST_PATH = "admission.json"
RELEASE_SOURCE_ADMISSION_SIGNATURE_PATH = "admission.sig"
RELEASE_SOURCE_ADMISSION_VERDICT_PATH = "record/verdict.json"
RELEASE_SOURCE_ADMISSION_HANDOFF_PATH = "materials/release-source-handoff.json"
RELEASE_SOURCE_ADMISSION_PRODUCER_RECEIPT_PATH = "materials/producer-receipt.json"
RELEASE_SOURCE_ADMISSION_GITHUB_RECEIPT_PATH = "provider/github-attestation-receipt.json"
RELEASE_SOURCE_ADMISSION_GITHUB_RAW_OUTPUT_PATH = "provider/github-attestation-output.json"

MAX_RELEASE_SOURCE_ADMISSION_MANIFEST_BYTES = 1 * 1024 * 1024
MAX_RELEASE_SOURCE_ADMISSION_ARCHIVE_BYTES = MAX_ARCHIVE_BYTES

_KEY_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_DESCRIPTOR_KEYS = {"path", "sha256", "size"}
_AUTHENTICATION_KEYS = {"algorithm", "key_id", "purpose", "key_domain", "signature_path"}
_MANIFEST_KEYS = {
    "format",
    "decision",
    "source",
    "context",
    "producer",
    "admitter",
    "bootstrap",
    "execution",
    "replay",
    "record",
    "handoff",
    "producer_receipt",
    "provider",
    "toolchain",
    "key_separation",
    "authentication",
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
_PROVIDER_ISOLATION_KEYS = {"platform", "uid", "gid"}
_REPLAY_KEYS = {"evaluation", "producer", "trigger", "admitter"}
_RUN_KEYS = {"run_id", "run_attempt"}
_BOOTSTRAP_KEYS = {"runtime_identity_format", "guard_artifact_sha256"}
_EXECUTION_KEYS = {
    "outcome",
    "guard_exit_code",
    "candidate_isolation",
    "network",
    "report_integrity",
    "overall_profile",
}
_GITHUB_POLICY_KEYS = {
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
_EXPECTED_GITHUB_POLICY_KEYS = {
    "repository",
    "signer_workflow",
    "signer_digest",
    "source_ref",
    "source_digest",
    "cert_oidc_issuer",
}
_ARCHIVE_PATHS = (
    RELEASE_SOURCE_ADMISSION_MANIFEST_PATH,
    RELEASE_SOURCE_ADMISSION_SIGNATURE_PATH,
    RELEASE_SOURCE_ADMISSION_VERDICT_PATH,
    RELEASE_SOURCE_ADMISSION_HANDOFF_PATH,
    RELEASE_SOURCE_ADMISSION_PRODUCER_RECEIPT_PATH,
    RELEASE_SOURCE_ADMISSION_GITHUB_RECEIPT_PATH,
    RELEASE_SOURCE_ADMISSION_GITHUB_RAW_OUTPUT_PATH,
)

RELEASE_SOURCE_ADMISSION_DISTINCT_KEY_DOMAINS = frozenset(
    {
        "trusted_finalizer",
        "artifact_admission_v1",
        "artifact_digest_admission_v2",
        "release_source_finalizer_v1",
    }
)


class ReleaseSourceAdmissionError(ValueError):
    """A V2 release-source admission or one of its trust bindings is unsafe."""


@dataclass(frozen=True)
class InspectedReleaseSourceAdmission:
    """Canonical V2 bytes whose signing key has not yet been trusted."""

    manifest_bytes: bytes
    signature: bytes
    verdict_bytes: bytes
    handoff_bytes: bytes
    producer_receipt_bytes: bytes
    github_receipt_bytes: bytes
    github_raw_output_bytes: bytes

    @property
    def manifest(self) -> dict[str, Any]:
        try:
            return _validate_manifest(
                load_json_object_bytes(
                    self.manifest_bytes, "release-source admission manifest"
                )
            )
        except EvidenceBundleError as exc:
            raise ReleaseSourceAdmissionError(str(exc)) from exc


@dataclass(frozen=True)
class SealedReleaseSourceAdmission:
    """A newly sealed V2 release-source ALLOW envelope."""

    bundle_path: str
    manifest: dict[str, Any]
    decision: str


@dataclass(frozen=True)
class VerifiedReleaseSourceAdmission:
    """A V2 envelope verified against an external key and anti-replay policy."""

    bundle: InspectedReleaseSourceAdmission
    record_report: dict[str, Any]
    decision: str


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ReleaseSourceAdmissionError(
            f"{label} keys are not canonical "
            f"(missing={sorted(expected - actual)}, unknown={sorted(actual - expected)})"
        )


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
        raise ReleaseSourceAdmissionError(f"{label} must be an object")
    descriptor = dict(value)
    _require_exact_keys(descriptor, _DESCRIPTOR_KEYS, label)
    if descriptor.get("path") != path:
        raise ReleaseSourceAdmissionError(f"{label}.path must be {path!r}")
    digest = descriptor.get("sha256")
    size = descriptor.get("size")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise ReleaseSourceAdmissionError(f"{label}.sha256 must be a lowercase SHA-256 digest")
    if type(size) is not int or not minimum <= size <= maximum:
        raise ReleaseSourceAdmissionError(f"{label}.size is outside the permitted range")
    return {"path": path, "sha256": digest, "size": size}


def _validate_key_separation(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ReleaseSourceAdmissionError(
            "release-source admission key separation must be an object"
        )
    separation = dict(value)
    _require_exact_keys(
        separation,
        set(RELEASE_SOURCE_ADMISSION_DISTINCT_KEY_DOMAINS),
        "release-source admission key separation",
    )
    checked: dict[str, str] = {}
    for domain in sorted(RELEASE_SOURCE_ADMISSION_DISTINCT_KEY_DOMAINS):
        key_id = separation.get(domain)
        if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
            raise ReleaseSourceAdmissionError(
                f"release-source admission key separation.{domain} must be "
                "sha256:<lowercase DER-SPKI digest>"
            )
        checked[domain] = key_id
    if len(set(checked.values())) != len(checked):
        raise ReleaseSourceAdmissionError(
            "release-source admission trust domains must use mutually distinct keys"
        )
    return checked


def _validate_toolchain(value: object) -> dict[str, Any]:
    """Validate the portable executable and provider-isolation trust pins."""

    if not isinstance(value, dict):
        raise ReleaseSourceAdmissionError(
            "release-source admission toolchain must be an object"
        )
    toolchain = dict(value)
    _require_exact_keys(toolchain, _TOOLCHAIN_KEYS, "release-source admission toolchain")
    checked_tools: dict[str, dict[str, str]] = {}
    for name in ("git", "github_cli"):
        raw = toolchain.get(name)
        if not isinstance(raw, dict):
            raise ReleaseSourceAdmissionError(
                f"release-source admission toolchain.{name} must be an object"
            )
        tool = dict(raw)
        _require_exact_keys(
            tool,
            _TOOL_KEYS,
            f"release-source admission toolchain.{name}",
        )
        digest = tool.get("sha256")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise ReleaseSourceAdmissionError(
                f"release-source admission toolchain.{name}.sha256 must be a lowercase SHA-256 digest"
            )
        checked_tools[name] = {"sha256": digest}
    raw_isolation = toolchain.get("provider_isolation")
    if not isinstance(raw_isolation, dict):
        raise ReleaseSourceAdmissionError(
            "release-source admission toolchain.provider_isolation must be an object"
        )
    isolation = dict(raw_isolation)
    _require_exact_keys(
        isolation,
        _PROVIDER_ISOLATION_KEYS,
        "release-source admission toolchain.provider_isolation",
    )
    uid = isolation.get("uid")
    gid = isolation.get("gid")
    if isolation.get("platform") != "posix":
        raise ReleaseSourceAdmissionError(
            "release-source admission provider isolation platform must be 'posix'"
        )
    if type(uid) is not int or not 1 <= uid <= 2_147_483_647:
        raise ReleaseSourceAdmissionError(
            "release-source admission provider isolation UID is invalid"
        )
    if type(gid) is not int or not 1 <= gid <= 2_147_483_647:
        raise ReleaseSourceAdmissionError(
            "release-source admission provider isolation GID is invalid"
        )
    return {
        "git": checked_tools["git"],
        "github_cli": checked_tools["github_cli"],
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


def _validate_bootstrap(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ReleaseSourceAdmissionError("release-source admission bootstrap must be an object")
    bootstrap = dict(value)
    _require_exact_keys(bootstrap, _BOOTSTRAP_KEYS, "release-source admission bootstrap")
    if bootstrap.get("runtime_identity_format") != RELEASE_SOURCE_PRODUCER_RUNTIME_FORMAT:
        raise ReleaseSourceAdmissionError("release-source admission runtime identity is unsupported")
    digest = bootstrap.get("guard_artifact_sha256")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise ReleaseSourceAdmissionError(
            "release-source admission guard artifact must be a lowercase SHA-256 digest"
        )
    return {
        "runtime_identity_format": RELEASE_SOURCE_PRODUCER_RUNTIME_FORMAT,
        "guard_artifact_sha256": digest,
    }


def _validate_execution(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseSourceAdmissionError("release-source admission execution must be an object")
    execution = dict(value)
    _require_exact_keys(execution, _EXECUTION_KEYS, "release-source admission execution")
    isolation = execution.get("candidate_isolation")
    if (
        execution.get("outcome") != "PASS"
        or execution.get("guard_exit_code") != 0
        or isolation not in {"docker", "gvisor"}
        or execution.get("network") != "none"
        or execution.get("report_integrity") != "external_process_isolated"
        or execution.get("overall_profile") != "black_box_external_judge"
    ):
        raise ReleaseSourceAdmissionError(
            "release-source admission execution is not the required isolated PASS profile"
        )
    return {
        "outcome": "PASS",
        "guard_exit_code": 0,
        "candidate_isolation": isolation,
        "network": "none",
        "report_integrity": "external_process_isolated",
        "overall_profile": "black_box_external_judge",
    }


def _validate_run(value: object, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseSourceAdmissionError(f"{label} must be an object")
    run = dict(value)
    _require_exact_keys(run, _RUN_KEYS, label)
    run_id = run.get("run_id")
    run_attempt = run.get("run_attempt")
    if (
        not isinstance(run_id, str)
        or not run_id.isdecimal()
        or run_id.startswith("0")
        or type(run_attempt) is not int
        or not 1 <= run_attempt <= 2_147_483_647
    ):
        raise ReleaseSourceAdmissionError(f"{label} has an invalid run ID or attempt")
    return {"run_id": run_id, "run_attempt": run_attempt}


def _replay_binding(
    source: Mapping[str, Any],
    producer: Mapping[str, Any],
    admitter: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "evaluation": {
            "run_id": source["workflow_run_id"],
            "run_attempt": source["workflow_run_attempt"],
        },
        "producer": {
            "run_id": producer["workflow_run_id"],
            "run_attempt": producer["workflow_run_attempt"],
        },
        "trigger": {
            "run_id": producer["trigger_workflow_run_id"],
            "run_attempt": producer["trigger_workflow_run_attempt"],
        },
        "admitter": {
            "run_id": admitter["workflow_run_id"],
            "run_attempt": admitter["workflow_run_attempt"],
        },
    }


def _validate_replay(
    value: object,
    *,
    source: Mapping[str, Any],
    producer: Mapping[str, Any],
    admitter: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseSourceAdmissionError("release-source admission replay binding must be an object")
    replay = dict(value)
    _require_exact_keys(replay, _REPLAY_KEYS, "release-source admission replay binding")
    checked = {
        key: _validate_run(replay.get(key), label=f"release-source admission replay.{key}")
        for key in ("evaluation", "producer", "trigger", "admitter")
    }
    expected = {
        "evaluation": {
            "run_id": source["workflow_run_id"],
            "run_attempt": source["workflow_run_attempt"],
        },
        "producer": {
            "run_id": producer["workflow_run_id"],
            "run_attempt": producer["workflow_run_attempt"],
        },
        "trigger": {
            "run_id": producer["trigger_workflow_run_id"],
            "run_attempt": producer["trigger_workflow_run_attempt"],
        },
        "admitter": {
            "run_id": admitter["workflow_run_id"],
            "run_attempt": admitter["workflow_run_attempt"],
        },
    }
    if checked != expected:
        raise ReleaseSourceAdmissionError(
            "release-source admission run/attempt replay binding is inconsistent"
        )
    return checked


def _validate_github_policy(value: object) -> GitHubAttestationPolicy:
    if not isinstance(value, dict):
        raise ReleaseSourceAdmissionError("release-source admission provider policy must be an object")
    policy = dict(value)
    _require_exact_keys(policy, _GITHUB_POLICY_KEYS, "release-source admission provider policy")
    repository = policy.get("repository")
    signer_workflow = policy.get("signer_workflow")
    source_digest = policy.get("source_digest")
    signer_digest = policy.get("signer_digest")
    source_ref = policy.get("source_ref")
    cert_oidc_issuer = policy.get("cert_oidc_issuer")
    if not all(
        isinstance(item, str)
        for item in (
            repository,
            signer_workflow,
            source_digest,
            signer_digest,
            source_ref,
            cert_oidc_issuer,
        )
    ):
        raise ReleaseSourceAdmissionError(
            "release-source admission provider policy pins must be strings"
        )
    assert isinstance(repository, str)
    assert isinstance(signer_workflow, str)
    assert isinstance(source_digest, str)
    assert isinstance(signer_digest, str)
    assert isinstance(source_ref, str)
    assert isinstance(cert_oidc_issuer, str)
    try:
        checked = github_attestation_policy(
            repository,
            signer_workflow,
            source_digest,
            signer_digest=signer_digest,
            source_ref=source_ref,
            cert_oidc_issuer=cert_oidc_issuer,
        )
    except GitHubAttestationError as exc:
        raise ReleaseSourceAdmissionError(str(exc)) from exc
    if checked.as_dict() != policy:
        raise ReleaseSourceAdmissionError("release-source admission provider policy is not canonical")
    return checked


def _github_policy_from_expected(value: Mapping[str, Any]) -> GitHubAttestationPolicy:
    policy = dict(value)
    _require_exact_keys(
        policy,
        _EXPECTED_GITHUB_POLICY_KEYS,
        "expected release-source GitHub provider policy",
    )
    expanded = {
        **policy,
        "predicate_type": "https://slsa.dev/provenance/v1",
        "deny_self_hosted_runners": True,
        "attestation_limit": 1,
    }
    return _validate_github_policy(expanded)


def _validate_provider(
    value: object,
    *,
    source: Mapping[str, Any],
    producer: Mapping[str, Any],
    producer_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseSourceAdmissionError("release-source admission provider must be an object")
    provider = dict(value)
    _require_exact_keys(provider, _PROVIDER_KEYS, "release-source admission provider")
    if provider.get("name") != "github-artifact-attestations":
        raise ReleaseSourceAdmissionError("release-source admission provider name is unsupported")
    if provider.get("verified_attestation_count") != 1:
        raise ReleaseSourceAdmissionError(
            "release-source admission requires exactly one verified provider attestation"
        )
    artifact = provider.get("artifact")
    if not isinstance(artifact, dict):
        raise ReleaseSourceAdmissionError("release-source admission provider artifact must be an object")
    _require_exact_keys(artifact, {"sha256", "size"}, "release-source admission provider artifact")
    if artifact != {"sha256": producer_receipt["sha256"], "size": producer_receipt["size"]}:
        raise ReleaseSourceAdmissionError(
            "release-source admission provider subject is not the exact producer receipt"
        )
    policy = _validate_github_policy(provider.get("policy"))
    expected_workflow = f"{producer['workflow_repository']}/{producer['workflow_path']}"
    if (
        policy.repository != source["repository"]
        or policy.signer_workflow != expected_workflow
        or policy.signer_digest != producer["workflow_commit_sha"]
        or policy.source_ref != "refs/heads/main"
        or policy.source_digest != source["target_commit_sha"]
        or policy.cert_oidc_issuer != GITHUB_ATTESTATION_CERT_OIDC_ISSUER
    ):
        raise ReleaseSourceAdmissionError(
            "release-source admission provider policy is not bound to the exact protected producer"
        )
    return {
        "name": "github-artifact-attestations",
        "artifact": dict(artifact),
        "policy": policy.as_dict(),
        "verified_attestation_count": 1,
        "receipt": _validate_descriptor(
            provider.get("receipt"),
            label="release-source admission provider receipt",
            path=RELEASE_SOURCE_ADMISSION_GITHUB_RECEIPT_PATH,
            maximum=MAX_GITHUB_ATTESTATION_RECEIPT_BYTES,
        ),
        "raw_output": _validate_descriptor(
            provider.get("raw_output"),
            label="release-source admission provider raw output",
            path=RELEASE_SOURCE_ADMISSION_GITHUB_RAW_OUTPUT_PATH,
            maximum=MAX_GITHUB_ATTESTATION_OUTPUT_BYTES,
            minimum=2,
        ),
    }


def _validate_authentication(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ReleaseSourceAdmissionError("release-source admission authentication must be an object")
    authentication = dict(value)
    _require_exact_keys(
        authentication, _AUTHENTICATION_KEYS, "release-source admission authentication"
    )
    if (
        authentication.get("algorithm") != "Ed25519"
        or authentication.get("purpose") != RELEASE_SOURCE_ADMISSION_SIGNATURE_PURPOSE
        or authentication.get("key_domain") != RELEASE_SOURCE_ADMISSION_KEY_DOMAIN
        or authentication.get("signature_path") != RELEASE_SOURCE_ADMISSION_SIGNATURE_PATH
    ):
        raise ReleaseSourceAdmissionError(
            "release-source admission authentication has the wrong algorithm, purpose, domain, or path"
        )
    key_id = authentication.get("key_id")
    if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
        raise ReleaseSourceAdmissionError(
            "release-source admission key_id must be sha256:<lowercase DER-SPKI digest>"
        )
    return {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "purpose": RELEASE_SOURCE_ADMISSION_SIGNATURE_PURPOSE,
        "key_domain": RELEASE_SOURCE_ADMISSION_KEY_DOMAIN,
        "signature_path": RELEASE_SOURCE_ADMISSION_SIGNATURE_PATH,
    }


def _validate_manifest(value: Mapping[str, Any]) -> dict[str, Any]:
    manifest = dict(value)
    _require_exact_keys(manifest, _MANIFEST_KEYS, "release-source admission manifest")
    if manifest.get("format") != RELEASE_SOURCE_ADMISSION_FORMAT:
        raise ReleaseSourceAdmissionError(
            f"unsupported release-source admission format: {manifest.get('format')!r}"
        )
    if manifest.get("decision") != "ALLOW":
        raise ReleaseSourceAdmissionError("release-source admission V2 decision must be ALLOW")
    source_value = manifest.get("source")
    context_value = manifest.get("context")
    producer_value = manifest.get("producer")
    admitter_value = manifest.get("admitter")
    if not isinstance(source_value, dict) or not isinstance(context_value, dict):
        raise ReleaseSourceAdmissionError("release-source admission source/context must be objects")
    if not isinstance(producer_value, dict):
        raise ReleaseSourceAdmissionError("release-source admission producer must be an object")
    if not isinstance(admitter_value, dict):
        raise ReleaseSourceAdmissionError("release-source admission admitter must be an object")
    try:
        source = validate_release_source(source_value)
        context = validate_release_source_context(context_value)
        producer = validate_release_source_producer(producer_value)
        admitter = validate_release_source_admitter(admitter_value)
        validate_release_source_context_binding(source, context)
        validate_release_source_context_producer_binding(source, context, producer)
        validate_release_source_admitter_binding(source, producer, admitter)
    except (ReleaseSourceFinalizerError, ReleaseSourceProducerReceiptError) as exc:
        raise ReleaseSourceAdmissionError(str(exc)) from exc
    record = _validate_descriptor(
        manifest.get("record"),
        label="release-source admission record",
        path=RELEASE_SOURCE_ADMISSION_VERDICT_PATH,
        maximum=MAX_VERDICT_BYTES,
    )
    handoff = _validate_descriptor(
        manifest.get("handoff"),
        label="release-source admission handoff",
        path=RELEASE_SOURCE_ADMISSION_HANDOFF_PATH,
        maximum=MAX_RELEASE_SOURCE_HANDOFF_BYTES,
    )
    producer_receipt = _validate_descriptor(
        manifest.get("producer_receipt"),
        label="release-source admission producer receipt",
        path=RELEASE_SOURCE_ADMISSION_PRODUCER_RECEIPT_PATH,
        maximum=MAX_RELEASE_SOURCE_PRODUCER_RECEIPT_BYTES,
    )
    key_separation = _validate_key_separation(manifest.get("key_separation"))
    authentication = _validate_authentication(manifest.get("authentication"))
    if authentication["key_id"] in set(key_separation.values()):
        raise ReleaseSourceAdmissionError(
            "release-source admission key belongs to another configured trust domain"
        )
    return {
        "format": RELEASE_SOURCE_ADMISSION_FORMAT,
        "decision": "ALLOW",
        "source": source,
        "context": context,
        "producer": producer,
        "admitter": admitter,
        "bootstrap": _validate_bootstrap(manifest.get("bootstrap")),
        "execution": _validate_execution(manifest.get("execution")),
        "replay": _validate_replay(
            manifest.get("replay"),
            source=source,
            producer=producer,
            admitter=admitter,
        ),
        "record": record,
        "handoff": handoff,
        "producer_receipt": producer_receipt,
        "provider": _validate_provider(
            manifest.get("provider"),
            source=source,
            producer=producer,
            producer_receipt=producer_receipt,
        ),
        "toolchain": _validate_toolchain(manifest.get("toolchain")),
        "key_separation": key_separation,
        "authentication": authentication,
    }


def _decode_signature(data: bytes) -> bytes:
    if len(data) != 88 or any(byte > 0x7F for byte in data):
        raise ReleaseSourceAdmissionError(
            "release-source admission signature must be exactly 88 ASCII base64 bytes"
        )
    try:
        signature = base64.b64decode(data, validate=True)
    except ValueError as exc:
        raise ReleaseSourceAdmissionError(
            "release-source admission signature is not canonical base64"
        ) from exc
    if len(signature) != 64 or base64.b64encode(signature) != data:
        raise ReleaseSourceAdmissionError(
            "release-source admission signature is not one canonical Ed25519 signature"
        )
    return signature


def _verify_material_descriptor(
    descriptor: Mapping[str, Any], data: bytes, *, label: str
) -> None:
    if descriptor != _descriptor(str(descriptor["path"]), data):
        raise ReleaseSourceAdmissionError(f"{label} bytes do not match their signed descriptor")


def _verify_github_materials(
    *,
    producer_receipt_bytes: bytes,
    github_receipt_bytes: bytes,
    github_raw_output_bytes: bytes,
    policy: Mapping[str, Any],
    producer: Mapping[str, Any],
) -> None:
    artifact = GitHubAttestationArtifact(
        sha256=sha256_bytes(producer_receipt_bytes),
        size=len(producer_receipt_bytes),
    )
    try:
        checked_policy = _validate_github_policy(policy)
        validate_github_attestation_verifier_output(
            github_raw_output_bytes,
            artifact=artifact,
            policy=checked_policy,
            expected_workflow_run_id=str(producer["workflow_run_id"]),
            expected_workflow_run_attempt=int(producer["workflow_run_attempt"]),
        )
        receipt = validate_github_attestation_receipt(
            load_json_object_bytes(github_receipt_bytes, "GitHub attestation receipt")
        )
        if canonical_json_bytes(receipt) != github_receipt_bytes:
            raise ReleaseSourceAdmissionError("GitHub attestation receipt is not canonical JSON")
    except (EvidenceBundleError, GitHubAttestationError) as exc:
        raise ReleaseSourceAdmissionError(str(exc)) from exc
    if receipt["artifact"] != artifact.as_dict():
        raise ReleaseSourceAdmissionError(
            "GitHub attestation receipt does not name the exact producer-receipt bytes"
        )
    if receipt["verification_policy"] != dict(policy):
        raise ReleaseSourceAdmissionError(
            "GitHub attestation receipt does not contain the exact provider policy"
        )
    output = receipt["verification_output"]
    if output != {
        "sha256": sha256_bytes(github_raw_output_bytes),
        "size": len(github_raw_output_bytes),
        "verified_attestation_count": 1,
    }:
        raise ReleaseSourceAdmissionError(
            "GitHub attestation receipt does not bind the exact raw verifier output"
        )


def _verify_receipt_materials(
    *,
    producer_receipt_bytes: bytes,
    verdict_bytes: bytes,
    handoff_bytes: bytes,
    source: Mapping[str, Any],
    context: Mapping[str, Any],
    producer: Mapping[str, Any],
    bootstrap: Mapping[str, Any],
    execution: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        receipt = validate_release_source_producer_receipt(
            load_json_object_bytes(
                producer_receipt_bytes, "release-source producer receipt"
            )
        )
        if canonical_json_bytes(receipt) != producer_receipt_bytes:
            raise ReleaseSourceAdmissionError("release-source producer receipt is not canonical JSON")
    except (EvidenceBundleError, ReleaseSourceProducerReceiptError) as exc:
        raise ReleaseSourceAdmissionError(str(exc)) from exc
    expected_receipt = {
        "format": RELEASE_SOURCE_PRODUCER_RECEIPT_FORMAT,
        "source": dict(source),
        "context": dict(context),
        "record": {"sha256": sha256_bytes(verdict_bytes), "size": len(verdict_bytes)},
        "handoff": {"sha256": sha256_bytes(handoff_bytes), "size": len(handoff_bytes)},
        "bootstrap": dict(bootstrap),
        "execution": dict(execution),
        "producer": dict(producer),
    }
    if receipt != expected_receipt:
        raise ReleaseSourceAdmissionError(
            "producer receipt does not bind the exact admission source, context, evidence, runtime, and producer"
        )
    try:
        verdict = load_json_object_bytes(verdict_bytes, "release-source admission verdict")
        report = verify_record(verdict)
        if not report["ok"]:
            raise ReleaseSourceAdmissionError(
                "release-source admission contains an invalid verdict record"
            )
        validate_release_source_allow_record(verdict, context)
        inspected_handoff = inspect_release_source_handoff_bytes(handoff_bytes)
        with tempfile.TemporaryDirectory(prefix=".evoguard-release-source-admission-") as directory:
            verdict_path = os.path.join(directory, "verdict.json")
            with open(verdict_path, "xb") as handle:
                handle.write(verdict_bytes)
            verify_release_source_handoff(
                inspected_handoff,
                verdict_path=verdict_path,
                expected_source=source,
                expected_context=context,
            )
    except (EvidenceBundleError, ReleaseSourceFinalizerError, ReleaseSourceProducerReceiptError) as exc:
        raise ReleaseSourceAdmissionError(str(exc)) from exc
    return report


def _attested_snapshot(
    attested: AttestedReleaseSourceProducerReceipt,
    *,
    private_key_path: str,
    git_executable: GitExecutablePin,
    provider_isolation: GitHubAttestationProviderIsolation,
) -> tuple[bytes, bytes, bytes, bytes, bytes, dict[str, Any], dict[str, Any]]:
    if not is_fresh_attested_release_source_producer_receipt(attested):
        raise ReleaseSourceAdmissionError(
            "release-source ALLOW requires a freshly verified AttestedReleaseSourceProducerReceipt"
        )
    if not is_admission_capable_attested_release_source_producer_receipt(
        attested,
        private_key_path=private_key_path,
        git_executable=git_executable,
        provider_isolation=provider_isolation,
    ):
        raise ReleaseSourceAdmissionError(
            "release-source ALLOW requires isolated provider verification bound "
            "to this exact protected signing-key path"
        )
    verified = attested.verified
    receipt_bytes = verified.receipt.receipt_bytes
    verdict_bytes = verified.handoff.verdict_bytes
    handoff_bytes = verified.handoff.inspection.handoff_bytes
    payload = verified.receipt.payload
    if not all(type(value) is bytes for value in (receipt_bytes, verdict_bytes, handoff_bytes)):
        raise ReleaseSourceAdmissionError("attested release-source materials must be immutable bytes")
    try:
        checked_payload = validate_release_source_producer_receipt(payload)
        if canonical_json_bytes(checked_payload) != receipt_bytes:
            raise ReleaseSourceAdmissionError(
                "attested producer receipt object does not preserve its exact canonical bytes"
            )
        derived_context = context_from_release_source_bindings(verified.bindings, verified.handoff.verdict)
    except (EvidenceBundleError, ReleaseSourceFinalizerError, ReleaseSourceProducerReceiptError) as exc:
        raise ReleaseSourceAdmissionError(str(exc)) from exc
    if derived_context != checked_payload["context"] or verified.bindings.source != checked_payload["source"]:
        raise ReleaseSourceAdmissionError(
            "attested raw-Git bindings do not match the producer receipt"
        )
    github = attested.github_receipt
    if type(github) is not CreatedGitHubAttestationReceipt:
        raise ReleaseSourceAdmissionError(
            "release-source admission requires a fresh CreatedGitHubAttestationReceipt"
        )
    if github.verified_attestation_count != 1:
        raise ReleaseSourceAdmissionError("fresh provider verification count must be exactly one")
    if os.path.abspath(github.receipt_path) == os.path.abspath(github.raw_output_path):
        raise ReleaseSourceAdmissionError("GitHub receipt and raw-output paths must differ")
    try:
        github_receipt_bytes = read_regular_file_bytes(
            github.receipt_path,
            limit=MAX_GITHUB_ATTESTATION_RECEIPT_BYTES,
            label="fresh GitHub attestation receipt",
        )
        github_raw_output_bytes = read_regular_file_bytes(
            github.raw_output_path,
            limit=MAX_GITHUB_ATTESTATION_OUTPUT_BYTES,
            label="fresh GitHub attestation raw output",
        )
    except EvidenceBundleError as exc:
        raise ReleaseSourceAdmissionError(str(exc)) from exc
    artifact = {"sha256": sha256_bytes(receipt_bytes), "size": len(receipt_bytes)}
    if github.artifact.as_dict() != artifact:
        raise ReleaseSourceAdmissionError(
            "fresh provider verification subject is not the exact producer receipt"
        )
    policy = github.policy.as_dict()
    _verify_github_materials(
        producer_receipt_bytes=receipt_bytes,
        github_receipt_bytes=github_receipt_bytes,
        github_raw_output_bytes=github_raw_output_bytes,
        policy=policy,
        producer=checked_payload["producer"],
    )
    _verify_receipt_materials(
        producer_receipt_bytes=receipt_bytes,
        verdict_bytes=verdict_bytes,
        handoff_bytes=handoff_bytes,
        source=checked_payload["source"],
        context=checked_payload["context"],
        producer=checked_payload["producer"],
        bootstrap=checked_payload["bootstrap"],
        execution=checked_payload["execution"],
    )
    provider = _validate_provider(
        {
            "name": "github-artifact-attestations",
            "artifact": artifact,
            "policy": policy,
            "verified_attestation_count": 1,
            "receipt": _descriptor(
                RELEASE_SOURCE_ADMISSION_GITHUB_RECEIPT_PATH, github_receipt_bytes
            ),
            "raw_output": _descriptor(
                RELEASE_SOURCE_ADMISSION_GITHUB_RAW_OUTPUT_PATH, github_raw_output_bytes
            ),
        },
        source=checked_payload["source"],
        producer=checked_payload["producer"],
        producer_receipt=_descriptor(RELEASE_SOURCE_ADMISSION_PRODUCER_RECEIPT_PATH, receipt_bytes),
    )
    return (
        verdict_bytes,
        handoff_bytes,
        receipt_bytes,
        github_receipt_bytes,
        github_raw_output_bytes,
        provider,
        checked_payload,
    )


def seal_release_source_admission(
    attested: AttestedReleaseSourceProducerReceipt,
    output_path: str,
    *,
    admitter: RuntimeBoundReleaseSourceAdmitter,
    key_separation: Mapping[str, Any],
    git_repository: str,
    git_repository_is_bare: bool = False,
    git_executable: GitExecutablePin,
    provider_isolation: GitHubAttestationProviderIsolation,
    private_key_path: str,
    signing_public_key_path: str,
    expected_signing_key_id: str,
    force: bool = False,
) -> SealedReleaseSourceAdmission:
    """Seal one ALLOW only after the typed local/raw-Git/provider result exists.

    All receipt and provider files are captured and cross-checked before the
    admission private key is opened.  V1 evidence is neither accepted nor
    modified by this operation.  The resulting signature delegates to the
    protected key-bearing workflow.  Its signed C run/attempt was checked
    against the current GitHub Actions context, but is not independent proof of
    GitHub's control plane.
    """

    separation = _validate_key_separation(key_separation)
    if not isinstance(expected_signing_key_id, str) or _KEY_ID.fullmatch(
        expected_signing_key_id
    ) is None:
        raise ReleaseSourceAdmissionError(
            "expected release-source admission signing key ID must be "
            "sha256:<lowercase DER-SPKI digest>"
        )
    if expected_signing_key_id in set(separation.values()):
        raise ReleaseSourceAdmissionError(
            "expected release-source admission signing key belongs to another configured trust domain"
        )
    if output_path == "-" or private_key_path == "-" or signing_public_key_path == "-":
        raise ReleaseSourceAdmissionError(
            "release-source admission output and signing keys must be regular paths"
        )
    output_absolute = os.path.abspath(output_path)
    private_key_absolute = os.path.abspath(private_key_path)
    output_identity = os.path.normcase(os.path.realpath(output_absolute))
    private_key_identity = os.path.normcase(os.path.realpath(private_key_absolute))
    public_key_identity = os.path.normcase(
        os.path.realpath(os.path.abspath(signing_public_key_path))
    )
    if output_identity in {private_key_identity, public_key_identity}:
        raise ReleaseSourceAdmissionError(
            "release-source admission output must differ from its signing-key paths"
        )
    if private_key_identity == public_key_identity:
        raise ReleaseSourceAdmissionError(
            "release-source admission private and public key paths must differ"
        )
    if os.path.isdir(output_absolute):
        raise ReleaseSourceAdmissionError(
            f"release-source admission output is a directory: {output_absolute}"
        )
    if os.path.lexists(output_absolute) and not force:
        raise ReleaseSourceAdmissionError(
            f"refusing to overwrite existing release-source admission bundle: {output_absolute}"
        )
    (
        verdict_bytes,
        handoff_bytes,
        producer_receipt_bytes,
        github_receipt_bytes,
        github_raw_output_bytes,
        provider,
        payload,
    ) = _attested_snapshot(
        attested,
        private_key_path=private_key_path,
        git_executable=git_executable,
        provider_isolation=provider_isolation,
    )
    try:
        runtime_admitter = require_runtime_bound_release_source_admitter(
            admitter,
            expected_producer=payload["producer"],
        )
        checked_admitter = verify_release_source_admitter_workflow_blob(
            source=payload["source"],
            producer=payload["producer"],
            admitter=runtime_admitter,
            git_repository=git_repository,
            git_repository_is_bare=git_repository_is_bare,
            git_executable=git_executable,
        )
    except ReleaseSourceProducerReceiptError as exc:
        raise ReleaseSourceAdmissionError(str(exc)) from exc
    provider_paths = {
        os.path.normcase(os.path.realpath(os.path.abspath(attested.github_receipt.receipt_path))),
        os.path.normcase(
            os.path.realpath(os.path.abspath(attested.github_receipt.raw_output_path))
        ),
    }
    if output_identity in provider_paths:
        raise ReleaseSourceAdmissionError(
            "release-source admission output must differ from retained provider evidence paths"
        )
    # All A/B/C replay selectors are derived and validated before the private
    # key is opened, then signed as part of the admission manifest.
    replay = _validate_replay(
        _replay_binding(payload["source"], payload["producer"], checked_admitter),
        source=payload["source"],
        producer=payload["producer"],
        admitter=checked_admitter,
    )

    from evoom_guard.signing import load_signing_key_snapshot, sign_bytes_with_snapshot

    signing_key = load_signing_key_snapshot(private_key_path)
    if signing_key.key_id != expected_signing_key_id:
        raise ReleaseSourceAdmissionError(
            "release-source admission private key does not match the externally expected public key"
        )
    if signing_key.key_id in set(separation.values()):
        raise ReleaseSourceAdmissionError(
            "release-source admission signing key belongs to another configured trust domain"
        )
    manifest = {
        "format": RELEASE_SOURCE_ADMISSION_FORMAT,
        "decision": "ALLOW",
        "source": payload["source"],
        "context": payload["context"],
        "producer": payload["producer"],
        "admitter": checked_admitter,
        "bootstrap": payload["bootstrap"],
        "execution": payload["execution"],
        "replay": replay,
        "record": _descriptor(RELEASE_SOURCE_ADMISSION_VERDICT_PATH, verdict_bytes),
        "handoff": _descriptor(RELEASE_SOURCE_ADMISSION_HANDOFF_PATH, handoff_bytes),
        "producer_receipt": _descriptor(
            RELEASE_SOURCE_ADMISSION_PRODUCER_RECEIPT_PATH, producer_receipt_bytes
        ),
        "provider": provider,
        "toolchain": _expected_toolchain(
            git_executable_sha256=git_executable.executable_sha256,
            github_cli_executable_sha256=provider_isolation.executable_sha256,
            provider_isolation_uid=provider_isolation.uid,
            provider_isolation_gid=provider_isolation.gid,
        ),
        "key_separation": separation,
        "authentication": {
            "algorithm": "Ed25519",
            "key_id": signing_key.key_id,
            "purpose": RELEASE_SOURCE_ADMISSION_SIGNATURE_PURPOSE,
            "key_domain": RELEASE_SOURCE_ADMISSION_KEY_DOMAIN,
            "signature_path": RELEASE_SOURCE_ADMISSION_SIGNATURE_PATH,
        },
    }
    checked = _validate_manifest(manifest)
    try:
        manifest_bytes = canonical_json_bytes(checked)
    except EvidenceBundleError as exc:
        raise ReleaseSourceAdmissionError(str(exc)) from exc
    if len(manifest_bytes) > MAX_RELEASE_SOURCE_ADMISSION_MANIFEST_BYTES:
        raise ReleaseSourceAdmissionError("release-source admission manifest exceeds its size limit")
    signature, actual_key_id = sign_bytes_with_snapshot(
        RELEASE_SOURCE_ADMISSION_SIGNATURE_DOMAIN + manifest_bytes,
        signing_key,
    )
    if actual_key_id != signing_key.key_id or len(signature) != 64:
        raise ReleaseSourceAdmissionError(
            "release-source admission signer returned inconsistent key identity or signature"
        )
    signature_bytes = base64.b64encode(signature)
    archive = canonical_archive_bytes(
        (
            (RELEASE_SOURCE_ADMISSION_MANIFEST_PATH, manifest_bytes),
            (RELEASE_SOURCE_ADMISSION_SIGNATURE_PATH, signature_bytes),
            (RELEASE_SOURCE_ADMISSION_VERDICT_PATH, verdict_bytes),
            (RELEASE_SOURCE_ADMISSION_HANDOFF_PATH, handoff_bytes),
            (RELEASE_SOURCE_ADMISSION_PRODUCER_RECEIPT_PATH, producer_receipt_bytes),
            (RELEASE_SOURCE_ADMISSION_GITHUB_RECEIPT_PATH, github_receipt_bytes),
            (RELEASE_SOURCE_ADMISSION_GITHUB_RAW_OUTPUT_PATH, github_raw_output_bytes),
        )
    )
    if len(archive) > MAX_RELEASE_SOURCE_ADMISSION_ARCHIVE_BYTES:
        raise ReleaseSourceAdmissionError("release-source admission archive exceeds its size limit")
    bundle_path, published = _publish_verified_release_source_admission(
        output_path,
        archive,
        expected_manifest=checked,
        signing_public_key_path=signing_public_key_path,
        expected_signing_key_id=expected_signing_key_id,
        force=force,
    )
    return SealedReleaseSourceAdmission(
        bundle_path=bundle_path,
        manifest=published.manifest,
        decision="ALLOW",
    )


def _publish_verified_release_source_admission(
    output_path: str,
    archive_bytes: bytes,
    *,
    expected_manifest: Mapping[str, Any],
    signing_public_key_path: str,
    expected_signing_key_id: str,
    force: bool,
) -> tuple[str, InspectedReleaseSourceAdmission]:
    """Verify a same-directory staging file before one atomic promotion.

    With ``force=True`` an existing output is left untouched unless the new
    staged bundle has passed canonical inspection and Ed25519 verification.
    This prevents a failed post-write check from destroying a previously valid
    admission bundle.
    """

    absolute = os.path.abspath(output_path)
    parent = os.path.dirname(absolute) or os.curdir
    os.makedirs(parent, exist_ok=True)
    descriptor, staging = tempfile.mkstemp(
        prefix=".evoguard-release-source-admission-",
        dir=parent,
    )
    promoted = False
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(archive_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(staging, 0o600)
        published = inspect_release_source_admission(staging)
        if published.manifest != dict(expected_manifest):
            raise ReleaseSourceAdmissionError(
                "staged release-source admission does not preserve its verified manifest"
            )
        from evoom_guard.signing import verify_bytes_with_key_id

        signature_verified, published_key_id = verify_bytes_with_key_id(
            RELEASE_SOURCE_ADMISSION_SIGNATURE_DOMAIN + published.manifest_bytes,
            published.signature,
            signing_public_key_path,
        )
        if published_key_id != expected_signing_key_id or not signature_verified:
            raise ReleaseSourceAdmissionError(
                "staged release-source admission failed cryptographic verification"
            )
        if force:
            os.replace(staging, absolute)
        else:
            try:
                os.link(staging, absolute, follow_symlinks=False)
            except FileExistsError as exc:
                raise ReleaseSourceAdmissionError(
                    f"refusing to overwrite existing release-source admission bundle: {absolute}"
                ) from exc
            except OSError as exc:
                raise ReleaseSourceAdmissionError(
                    "cannot publish release-source admission bundle with atomic "
                    "no-clobber semantics; use a filesystem that supports hard links "
                    "or pass force=True explicitly"
                ) from exc
            os.unlink(staging)
        promoted = True
        os.chmod(absolute, 0o644)
        return absolute, published
    except OSError as exc:
        raise ReleaseSourceAdmissionError(
            f"cannot stage or publish release-source admission bundle: {exc}"
        ) from exc
    finally:
        if not promoted:
            try:
                os.unlink(staging)
            except OSError:
                pass


def inspect_release_source_admission(path: str) -> InspectedReleaseSourceAdmission:
    """Inspect canonical archive bytes and every signed content descriptor."""

    try:
        snapshot = read_regular_file_bytes(
            path,
            limit=MAX_RELEASE_SOURCE_ADMISSION_ARCHIVE_BYTES,
            label="release-source admission bundle",
        )
        declared = preflight_canonical_zip(snapshot)
        with zipfile.ZipFile(io.BytesIO(snapshot), mode="r") as archive:
            infos = archive.infolist()
            if declared != len(_ARCHIVE_PATHS) or len(infos) != len(_ARCHIVE_PATHS):
                raise ReleaseSourceAdmissionError(
                    "release-source admission archive must contain exactly seven members"
                )
            if tuple(info.filename for info in infos) != _ARCHIVE_PATHS:
                raise ReleaseSourceAdmissionError(
                    "release-source admission archive member names/order are not canonical"
                )
            for info in infos:
                validate_canonical_archive_member(info)
            limits = (
                MAX_RELEASE_SOURCE_ADMISSION_MANIFEST_BYTES,
                88,
                MAX_VERDICT_BYTES,
                MAX_RELEASE_SOURCE_HANDOFF_BYTES,
                MAX_RELEASE_SOURCE_PRODUCER_RECEIPT_BYTES,
                MAX_GITHUB_ATTESTATION_RECEIPT_BYTES,
                MAX_GITHUB_ATTESTATION_OUTPUT_BYTES,
            )
            values = tuple(
                read_archive_member_bytes(archive, info, limit=limit)
                for info, limit in zip(infos, limits, strict=True)
            )
    except (EvidenceBundleError, OSError, zipfile.BadZipFile) as exc:
        raise ReleaseSourceAdmissionError(str(exc)) from exc
    (
        manifest_bytes,
        signature_bytes,
        verdict_bytes,
        handoff_bytes,
        producer_receipt_bytes,
        github_receipt_bytes,
        github_raw_output_bytes,
    ) = values
    try:
        manifest = _validate_manifest(
            load_json_object_bytes(manifest_bytes, "release-source admission manifest")
        )
        if canonical_json_bytes(manifest) != manifest_bytes:
            raise ReleaseSourceAdmissionError(
                "release-source admission manifest is not canonical JSON"
            )
    except EvidenceBundleError as exc:
        raise ReleaseSourceAdmissionError(str(exc)) from exc
    signature = _decode_signature(signature_bytes)
    for label, descriptor, data in (
        ("record", manifest["record"], verdict_bytes),
        ("handoff", manifest["handoff"], handoff_bytes),
        ("producer receipt", manifest["producer_receipt"], producer_receipt_bytes),
        ("provider receipt", manifest["provider"]["receipt"], github_receipt_bytes),
        ("provider raw output", manifest["provider"]["raw_output"], github_raw_output_bytes),
    ):
        _verify_material_descriptor(descriptor, data, label=label)
    _verify_github_materials(
        producer_receipt_bytes=producer_receipt_bytes,
        github_receipt_bytes=github_receipt_bytes,
        github_raw_output_bytes=github_raw_output_bytes,
        policy=manifest["provider"]["policy"],
        producer=manifest["producer"],
    )
    if (
        canonical_archive_bytes(
            (
                (RELEASE_SOURCE_ADMISSION_MANIFEST_PATH, manifest_bytes),
                (RELEASE_SOURCE_ADMISSION_SIGNATURE_PATH, signature_bytes),
                (RELEASE_SOURCE_ADMISSION_VERDICT_PATH, verdict_bytes),
                (RELEASE_SOURCE_ADMISSION_HANDOFF_PATH, handoff_bytes),
                (RELEASE_SOURCE_ADMISSION_PRODUCER_RECEIPT_PATH, producer_receipt_bytes),
                (RELEASE_SOURCE_ADMISSION_GITHUB_RECEIPT_PATH, github_receipt_bytes),
                (RELEASE_SOURCE_ADMISSION_GITHUB_RAW_OUTPUT_PATH, github_raw_output_bytes),
            )
        )
        != snapshot
    ):
        raise ReleaseSourceAdmissionError(
            "release-source admission archive bytes are not canonical"
        )
    return InspectedReleaseSourceAdmission(
        manifest_bytes=manifest_bytes,
        signature=signature,
        verdict_bytes=verdict_bytes,
        handoff_bytes=handoff_bytes,
        producer_receipt_bytes=producer_receipt_bytes,
        github_receipt_bytes=github_receipt_bytes,
        github_raw_output_bytes=github_raw_output_bytes,
    )


def verify_release_source_admission(
    bundle_path: str,
    *,
    trusted_public_key_path: str,
    expected_source: Mapping[str, Any],
    expected_context: Mapping[str, Any],
    expected_producer: Mapping[str, Any],
    expected_admitter: Mapping[str, Any],
    expected_bootstrap_guard_sha256: str,
    expected_github_policy: Mapping[str, Any],
    expected_key_separation: Mapping[str, Any],
    expected_git_executable_sha256: str,
    expected_github_cli_executable_sha256: str,
    expected_provider_isolation_uid: int,
    expected_provider_isolation_gid: int,
) -> VerifiedReleaseSourceAdmission:
    """Verify V2 signature, byte evidence, provider policy, and anti-replay pins.

    This is an offline verification of the provider output captured during the
    key-bearing sealing operation.  It proves that the separately trusted V2
    signer admitted those exact bytes after a fresh check; it does not contact
    GitHub again.
    """

    separation = _validate_key_separation(expected_key_separation)
    try:
        source = validate_release_source(expected_source)
        context = validate_release_source_context(expected_context)
        producer = validate_release_source_producer(expected_producer)
        admitter = validate_release_source_admitter(expected_admitter)
        validate_release_source_context_binding(source, context)
        validate_release_source_context_producer_binding(source, context, producer)
        validate_release_source_admitter_binding(source, producer, admitter)
    except (ReleaseSourceFinalizerError, ReleaseSourceProducerReceiptError) as exc:
        raise ReleaseSourceAdmissionError(str(exc)) from exc
    policy = _github_policy_from_expected(expected_github_policy)
    toolchain = _expected_toolchain(
        git_executable_sha256=expected_git_executable_sha256,
        github_cli_executable_sha256=expected_github_cli_executable_sha256,
        provider_isolation_uid=expected_provider_isolation_uid,
        provider_isolation_gid=expected_provider_isolation_gid,
    )
    bootstrap = _validate_bootstrap(
        {
            "runtime_identity_format": RELEASE_SOURCE_PRODUCER_RUNTIME_FORMAT,
            "guard_artifact_sha256": expected_bootstrap_guard_sha256,
        }
    )
    bundle = inspect_release_source_admission(bundle_path)
    manifest = bundle.manifest
    if (
        manifest["source"] != source
        or manifest["context"] != context
        or manifest["producer"] != producer
        or manifest["admitter"] != admitter
        or manifest["bootstrap"] != bootstrap
        or manifest["provider"]["policy"] != policy.as_dict()
        or manifest["toolchain"] != toolchain
        or manifest["replay"] != _replay_binding(source, producer, admitter)
        or manifest["key_separation"] != separation
    ):
        raise ReleaseSourceAdmissionError(
            "release-source admission does not match external source/context/producer/runtime/policy expectations"
        )
    from evoom_guard.signing import verify_bytes_with_key_id

    verified, trusted_key_id = verify_bytes_with_key_id(
        RELEASE_SOURCE_ADMISSION_SIGNATURE_DOMAIN + bundle.manifest_bytes,
        bundle.signature,
        trusted_public_key_path,
    )
    if trusted_key_id in set(separation.values()):
        raise ReleaseSourceAdmissionError(
            "release-source admission public key belongs to another configured trust domain"
        )
    if manifest["authentication"]["key_id"] != trusted_key_id:
        raise ReleaseSourceAdmissionError(
            "release-source admission key_id does not match the externally trusted public key"
        )
    if not verified:
        raise ReleaseSourceAdmissionError(
            "release-source admission signature is invalid under the trusted public key"
        )
    report = _verify_receipt_materials(
        producer_receipt_bytes=bundle.producer_receipt_bytes,
        verdict_bytes=bundle.verdict_bytes,
        handoff_bytes=bundle.handoff_bytes,
        source=source,
        context=context,
        producer=producer,
        bootstrap=bootstrap,
        execution=manifest["execution"],
    )
    return VerifiedReleaseSourceAdmission(
        bundle=bundle,
        record_report=report,
        decision="ALLOW",
    )
