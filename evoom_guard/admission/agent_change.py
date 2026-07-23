# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Source-available - see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Fail-closed admission profile for changes proposed by automated agents.

An agent proposal is never an authority.  This module compares its canonical
claims with facts re-derived from raw Git, applies a separately signed
control-plane authorization, and only then lets the existing Trusted Finalizer
seal an ALLOW bundle.  The frozen finalizer handoff and evidence-context formats
remain unchanged; proposal, authorization, and raw-Git bindings are signed as
mandatory evidence materials inside the finalizer bundle.
"""

from __future__ import annotations

import base64
import binascii
import io
import os
import re
import tempfile
import zipfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, replace
from typing import Any

from evoom_guard.evidence_bundle import (
    EvidenceMaterial,
    canonical_archive_bytes,
    canonical_json_bytes,
    load_json_object_bytes,
    preflight_canonical_zip,
    read_archive_member_bytes,
    read_regular_file_bytes,
    validate_canonical_archive_member,
)
from evoom_guard.finalizer_derivation import (
    AGENT_CHANGE_GIT_BINDINGS_ROLE,
    MAX_BINDINGS_BYTES,
    DerivedAgentChangeBindings,
    FinalizerDerivationError,
    GitExecutablePin,
    agent_change_bindings_bytes,
    derive_agent_change_bindings,
    validate_agent_change_bindings,
)
from evoom_guard.trusted_finalizer import (
    FinalizedTrustedEvidence,
    FinalizerHandoffError,
    VerifiedFinalizedBundle,
    finalizer_decision,
    inspect_finalizer_handoff,
    seal_finalizer_bundle,
    verify_finalized_bundle,
    verify_finalizer_handoff,
)
from evoom_guard.verifiers.harness_policy import (
    is_judge_autoexec,
    is_protected,
    is_protected_ci,
    is_protected_config,
    is_safe_relpath,
)

AGENT_CHANGE_PROPOSAL_FORMAT = "EVOGUARD_AGENT_CHANGE_PROPOSAL_V1"
AGENT_CHANGE_AUTHORIZATION_FORMAT = "EVOGUARD_AGENT_CHANGE_AUTHORIZATION_V1"
AGENT_CHANGE_AUTHORIZATION_PURPOSE = "evoguard-agent-change-authorization-v1"
AGENT_CHANGE_AUTHORIZATION_KEY_DOMAIN = "agent-change-authorization-v1"
AGENT_CHANGE_AUTHORIZATION_SIGNATURE_DOMAIN = (
    AGENT_CHANGE_AUTHORIZATION_FORMAT.encode("ascii") + b"\0"
)

AGENT_CHANGE_PROPOSAL_ROLE = "agent-change-proposal"
AGENT_CHANGE_AUTHORIZATION_ROLE = "agent-change-authorization"

AUTHORIZATION_MANIFEST_PATH = "authorization.json"
AUTHORIZATION_SIGNATURE_PATH = "authorization.sig"

MAX_PROPOSAL_BYTES = 1 * 1024 * 1024
MAX_AUTHORIZATION_BYTES = 1 * 1024 * 1024
MAX_AUTHORIZATION_ARCHIVE_BYTES = 2 * 1024 * 1024
MAX_AGENT_ID_LENGTH = 256
MAX_SUMMARY_LENGTH = 4096
MAX_PATHS = 10_000
MAX_SCOPE_PATTERNS = 256
MAX_CLAIMS = 128

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_KEY_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_CLAIM_ID = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")

_PROPOSAL_KEYS = {
    "format",
    "producer",
    "source",
    "intent",
    "change",
    "observed_policy",
    "claims",
}
_PRODUCER_KEYS = {"id", "kind", "version"}
_PROPOSAL_SOURCE_KEYS = {
    "repository",
    "pull_request_number",
    "base_sha",
    "head_sha",
}
_INTENT_KEYS = {"summary", "declared_paths"}
_CHANGE_KEYS = {
    "candidate_sha256",
    "candidate_size",
    "changed_paths",
    "deleted_paths",
    "touched_paths",
}
_POLICY_KEYS = {"policy_sha256", "verifier_pack_sha256"}
_CLAIM_KEYS = {"id", "outcome", "evidence_sha256"}

_AUTHORIZATION_KEYS = {"format", "source", "scope", "required", "authentication"}
_AUTHORIZATION_SOURCE_KEYS = {
    "repository",
    "repository_id",
    "pull_request_number",
    "authorization_run_id",
    "authorization_run_attempt",
    "base_sha",
    "head_sha",
    "base_tree_sha",
    "head_tree_sha",
}
_SCOPE_KEYS = {
    "allowed_patterns",
    "maximum_touched_paths",
    "maximum_candidate_bytes",
    "allow_deletions",
}
_REQUIRED_KEYS = {"policy_sha256", "verifier_pack_sha256"}
_AUTHENTICATION_KEYS = {
    "algorithm",
    "key_id",
    "purpose",
    "key_domain",
    "signature_path",
}


class AgentChangeAdmissionError(ValueError):
    """An Agent Change proposal, authorization, or admission is unsafe."""


@dataclass(frozen=True)
class InspectedAgentChangeProposal:
    """Canonical untrusted proposal bytes after structural validation."""

    proposal_bytes: bytes
    payload: dict[str, Any]


@dataclass(frozen=True)
class InspectedAgentChangeAuthorization:
    """Canonical signed authorization whose key is not trusted yet."""

    archive_bytes: bytes
    manifest_bytes: bytes
    signature: bytes
    payload: dict[str, Any]


@dataclass(frozen=True)
class VerifiedAgentChangeAuthorization:
    """Authorization authenticated by an externally trusted control key."""

    inspection: InspectedAgentChangeAuthorization
    key_id: str

    @property
    def payload(self) -> dict[str, Any]:
        return dict(self.inspection.payload)


@dataclass(frozen=True)
class VerifiedAgentChangeContract:
    """Proposal, authorization, and raw-Git facts that agree exactly."""

    proposal: InspectedAgentChangeProposal
    authorization: VerifiedAgentChangeAuthorization
    bindings: DerivedAgentChangeBindings


@dataclass(frozen=True)
class FinalizedAgentChangeAdmission:
    """Trusted Finalizer ALLOW bundle carrying the mandatory profile materials."""

    finalized: FinalizedTrustedEvidence
    contract: VerifiedAgentChangeContract

    @property
    def decision(self) -> str:
        return self.finalized.decision


@dataclass(frozen=True)
class VerifiedAgentChangeAdmission:
    """Offline-verified Agent Change admission profile."""

    finalized: VerifiedFinalizedBundle
    contract: VerifiedAgentChangeContract

    @property
    def decision(self) -> str:
        return self.finalized.decision


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise AgentChangeAdmissionError(
            f"{label} keys are not canonical "
            f"(missing={sorted(expected - actual)}, unknown={sorted(actual - expected)})"
        )


def _bounded_string(value: object, *, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise AgentChangeAdmissionError(
            f"{label} must be a non-empty string of at most {maximum} characters"
        )
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise AgentChangeAdmissionError(f"{label} must not contain an unpaired surrogate") from exc
    if any(ord(character) < 0x20 for character in value):
        raise AgentChangeAdmissionError(f"{label} must not contain control characters")
    return value


def _sha256(value: object, *, label: str, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise AgentChangeAdmissionError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _git_sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise AgentChangeAdmissionError(f"{label} must be a lowercase 40/64-character Git digest")
    return value


def _path_list(value: object, *, label: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(path, str) or not is_safe_relpath(path) for path in value
    ):
        raise AgentChangeAdmissionError(f"{label} must contain safe relative paths")
    if not allow_empty and not value:
        raise AgentChangeAdmissionError(f"{label} must not be empty")
    if len(value) > MAX_PATHS:
        raise AgentChangeAdmissionError(f"{label} exceeds the path limit")
    if value != sorted(set(value)):
        raise AgentChangeAdmissionError(f"{label} must be sorted and unique")
    return list(value)


def _validate_proposal_source(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AgentChangeAdmissionError("proposal source must be an object")
    source = dict(value)
    _require_exact_keys(source, _PROPOSAL_SOURCE_KEYS, "proposal source")
    repository = _bounded_string(
        source.get("repository"), label="proposal source.repository", maximum=512
    )
    pr = source.get("pull_request_number")
    if type(pr) is not int or not 1 <= pr <= 2_147_483_647:
        raise AgentChangeAdmissionError(
            "proposal source.pull_request_number must be a positive integer"
        )
    return {
        "repository": repository,
        "pull_request_number": pr,
        "base_sha": _git_sha(source.get("base_sha"), label="proposal source.base_sha"),
        "head_sha": _git_sha(source.get("head_sha"), label="proposal source.head_sha"),
    }


def _validate_change(value: object, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AgentChangeAdmissionError(f"{label} must be an object")
    change = dict(value)
    _require_exact_keys(change, _CHANGE_KEYS, label)
    size = change.get("candidate_size")
    if type(size) is not int or not 1 <= size <= 64 * 1024 * 1024:
        raise AgentChangeAdmissionError(f"{label}.candidate_size is outside the limit")
    changed = _path_list(
        change.get("changed_paths"), label=f"{label}.changed_paths", allow_empty=True
    )
    deleted = _path_list(
        change.get("deleted_paths"), label=f"{label}.deleted_paths", allow_empty=True
    )
    touched = _path_list(change.get("touched_paths"), label=f"{label}.touched_paths")
    if set(changed) & set(deleted) or touched != sorted(set(changed) | set(deleted)):
        raise AgentChangeAdmissionError(
            f"{label}.touched_paths must be the disjoint changed/deleted union"
        )
    return {
        "candidate_sha256": _sha256(
            change.get("candidate_sha256"), label=f"{label}.candidate_sha256"
        ),
        "candidate_size": size,
        "changed_paths": changed,
        "deleted_paths": deleted,
        "touched_paths": touched,
    }


def _validate_policy(value: object, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AgentChangeAdmissionError(f"{label} must be an object")
    policy = dict(value)
    _require_exact_keys(policy, _POLICY_KEYS, label)
    return {
        "policy_sha256": _sha256(policy.get("policy_sha256"), label=f"{label}.policy_sha256"),
        "verifier_pack_sha256": _sha256(
            policy.get("verifier_pack_sha256"),
            label=f"{label}.verifier_pack_sha256",
            optional=True,
        ),
    }


def validate_agent_change_proposal(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a proposal without treating any producer field as trusted."""

    proposal = dict(value)
    _require_exact_keys(proposal, _PROPOSAL_KEYS, "agent-change proposal")
    if proposal.get("format") != AGENT_CHANGE_PROPOSAL_FORMAT:
        raise AgentChangeAdmissionError("unsupported agent-change proposal format")
    producer_raw = proposal.get("producer")
    if not isinstance(producer_raw, dict):
        raise AgentChangeAdmissionError("proposal producer must be an object")
    producer = dict(producer_raw)
    _require_exact_keys(producer, _PRODUCER_KEYS, "proposal producer")
    checked_producer = {
        field: _bounded_string(
            producer.get(field), label=f"proposal producer.{field}", maximum=MAX_AGENT_ID_LENGTH
        )
        for field in ("id", "kind", "version")
    }
    intent_raw = proposal.get("intent")
    if not isinstance(intent_raw, dict):
        raise AgentChangeAdmissionError("proposal intent must be an object")
    intent = dict(intent_raw)
    _require_exact_keys(intent, _INTENT_KEYS, "proposal intent")
    declared = _path_list(intent.get("declared_paths"), label="proposal intent.declared_paths")
    change = _validate_change(proposal.get("change"), label="proposal change")
    if declared != change["touched_paths"]:
        raise AgentChangeAdmissionError(
            "proposal declared_paths must exactly equal its touched_paths"
        )
    claims_raw = proposal.get("claims")
    if not isinstance(claims_raw, list) or not 1 <= len(claims_raw) <= MAX_CLAIMS:
        raise AgentChangeAdmissionError("proposal claims must contain between 1 and 128 entries")
    claims: list[dict[str, Any]] = []
    for index, raw in enumerate(claims_raw):
        if not isinstance(raw, dict):
            raise AgentChangeAdmissionError(f"proposal claims[{index}] must be an object")
        claim = dict(raw)
        _require_exact_keys(claim, _CLAIM_KEYS, f"proposal claims[{index}]")
        claim_id = claim.get("id")
        outcome = claim.get("outcome")
        if not isinstance(claim_id, str) or _CLAIM_ID.fullmatch(claim_id) is None:
            raise AgentChangeAdmissionError(f"proposal claims[{index}].id is invalid")
        if not isinstance(outcome, str) or outcome not in {
            "PASS",
            "FAIL",
            "NOT_RUN",
            "UNKNOWN",
        }:
            raise AgentChangeAdmissionError(f"proposal claims[{index}].outcome is invalid")
        evidence = _sha256(
            claim.get("evidence_sha256"),
            label=f"proposal claims[{index}].evidence_sha256",
            optional=True,
        )
        if (outcome in {"PASS", "FAIL"}) != (evidence is not None):
            raise AgentChangeAdmissionError(
                f"proposal claims[{index}] must bind evidence exactly for PASS/FAIL"
            )
        claims.append({"id": claim_id, "outcome": outcome, "evidence_sha256": evidence})
    if claims != sorted(claims, key=lambda item: item["id"]) or len(
        {item["id"] for item in claims}
    ) != len(claims):
        raise AgentChangeAdmissionError("proposal claims must be sorted by unique id")
    return {
        "format": AGENT_CHANGE_PROPOSAL_FORMAT,
        "producer": checked_producer,
        "source": _validate_proposal_source(proposal.get("source")),
        "intent": {
            "summary": _bounded_string(
                intent.get("summary"), label="proposal intent.summary", maximum=MAX_SUMMARY_LENGTH
            ),
            "declared_paths": declared,
        },
        "change": change,
        "observed_policy": _validate_policy(
            proposal.get("observed_policy"), label="proposal observed_policy"
        ),
        "claims": claims,
    }


def inspect_agent_change_proposal_bytes(data: bytes) -> InspectedAgentChangeProposal:
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_PROPOSAL_BYTES:
        raise AgentChangeAdmissionError("agent-change proposal is outside the size limit")
    try:
        value = load_json_object_bytes(data, "agent-change proposal")
    except ValueError as exc:
        raise AgentChangeAdmissionError(str(exc)) from exc
    checked = validate_agent_change_proposal(value)
    if canonical_json_bytes(checked) != data:
        raise AgentChangeAdmissionError("agent-change proposal is not canonical JSON")
    return InspectedAgentChangeProposal(proposal_bytes=data, payload=checked)


def inspect_agent_change_proposal(path: str) -> InspectedAgentChangeProposal:
    try:
        data = read_regular_file_bytes(
            path, limit=MAX_PROPOSAL_BYTES, label="agent-change proposal"
        )
    except ValueError as exc:
        raise AgentChangeAdmissionError(str(exc)) from exc
    return inspect_agent_change_proposal_bytes(data)


def _publish_bytes(path: str, data: bytes, *, label: str, force: bool) -> str:
    absolute = os.path.abspath(path)
    parent = os.path.dirname(absolute) or os.curdir
    if os.path.isdir(absolute):
        raise AgentChangeAdmissionError(f"{label} output is a directory: {absolute}")
    os.makedirs(parent, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".evoguard-agent-change-", dir=parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        if force:
            os.replace(temporary, absolute)
        else:
            try:
                os.link(temporary, absolute, follow_symlinks=False)
            except FileExistsError as exc:
                raise AgentChangeAdmissionError(
                    f"refusing to overwrite existing {label}: {absolute}"
                ) from exc
            except OSError as exc:
                raise AgentChangeAdmissionError(
                    f"cannot publish {label} with atomic no-clobber semantics"
                ) from exc
            os.unlink(temporary)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return absolute


def write_agent_change_proposal(
    value: Mapping[str, Any], output_path: str, *, force: bool = False
) -> InspectedAgentChangeProposal:
    checked = validate_agent_change_proposal(value)
    data = canonical_json_bytes(checked)
    if len(data) > MAX_PROPOSAL_BYTES:
        raise AgentChangeAdmissionError("canonical proposal exceeds the size limit")
    _publish_bytes(output_path, data, label="agent-change proposal", force=force)
    return inspect_agent_change_proposal(output_path)


def _validate_authorization_source(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AgentChangeAdmissionError("authorization source must be an object")
    source = dict(value)
    _require_exact_keys(source, _AUTHORIZATION_SOURCE_KEYS, "authorization source")
    pr = source.get("pull_request_number")
    attempt = source.get("authorization_run_attempt")
    if type(pr) is not int or not 1 <= pr <= 2_147_483_647:
        raise AgentChangeAdmissionError(
            "authorization source.pull_request_number must be a positive integer"
        )
    if type(attempt) is not int or not 1 <= attempt <= 2_147_483_647:
        raise AgentChangeAdmissionError(
            "authorization source.authorization_run_attempt must be positive"
        )
    return {
        "repository": _bounded_string(
            source.get("repository"), label="authorization source.repository", maximum=512
        ),
        "repository_id": _bounded_string(
            source.get("repository_id"),
            label="authorization source.repository_id",
            maximum=256,
        ),
        "pull_request_number": pr,
        "authorization_run_id": _bounded_string(
            source.get("authorization_run_id"),
            label="authorization source.authorization_run_id",
            maximum=256,
        ),
        "authorization_run_attempt": attempt,
        "base_sha": _git_sha(source.get("base_sha"), label="authorization source.base_sha"),
        "head_sha": _git_sha(source.get("head_sha"), label="authorization source.head_sha"),
        "base_tree_sha": _git_sha(
            source.get("base_tree_sha"), label="authorization source.base_tree_sha"
        ),
        "head_tree_sha": _git_sha(
            source.get("head_tree_sha"), label="authorization source.head_tree_sha"
        ),
    }


def _scope_pattern(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise AgentChangeAdmissionError(f"{label} must be a non-empty path pattern")
    if value.endswith("/**"):
        root = value[:-3]
        if not is_safe_relpath(root):
            raise AgentChangeAdmissionError(f"{label} has an unsafe directory prefix")
        return value
    if "*" in value or "?" in value or "[" in value or not is_safe_relpath(value):
        raise AgentChangeAdmissionError(
            f"{label} must be one literal path or a directory ending in '/**'"
        )
    return value


def _validate_scope(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AgentChangeAdmissionError("authorization scope must be an object")
    scope = dict(value)
    _require_exact_keys(scope, _SCOPE_KEYS, "authorization scope")
    patterns_raw = scope.get("allowed_patterns")
    if not isinstance(patterns_raw, list) or not 1 <= len(patterns_raw) <= MAX_SCOPE_PATTERNS:
        raise AgentChangeAdmissionError(
            "authorization scope.allowed_patterns must contain between 1 and 256 entries"
        )
    patterns = [
        _scope_pattern(item, label=f"authorization scope.allowed_patterns[{index}]")
        for index, item in enumerate(patterns_raw)
    ]
    if patterns != sorted(set(patterns)):
        raise AgentChangeAdmissionError(
            "authorization scope.allowed_patterns must be sorted and unique"
        )
    maximum_paths = scope.get("maximum_touched_paths")
    maximum_bytes = scope.get("maximum_candidate_bytes")
    if type(maximum_paths) is not int or not 1 <= maximum_paths <= MAX_PATHS:
        raise AgentChangeAdmissionError(
            "authorization scope.maximum_touched_paths is outside the limit"
        )
    if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= 64 * 1024 * 1024:
        raise AgentChangeAdmissionError(
            "authorization scope.maximum_candidate_bytes is outside the limit"
        )
    allow_deletions = scope.get("allow_deletions")
    if type(allow_deletions) is not bool:
        raise AgentChangeAdmissionError("authorization scope.allow_deletions must be a boolean")
    return {
        "allowed_patterns": patterns,
        "maximum_touched_paths": maximum_paths,
        "maximum_candidate_bytes": maximum_bytes,
        "allow_deletions": allow_deletions,
    }


def _validate_required(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AgentChangeAdmissionError("authorization required must be an object")
    required = dict(value)
    _require_exact_keys(required, _REQUIRED_KEYS, "authorization required")
    return {
        "policy_sha256": _sha256(
            required.get("policy_sha256"), label="authorization required.policy_sha256"
        ),
        "verifier_pack_sha256": _sha256(
            required.get("verifier_pack_sha256"),
            label="authorization required.verifier_pack_sha256",
            optional=True,
        ),
    }


def _validate_authentication(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise AgentChangeAdmissionError("authorization authentication must be an object")
    authentication = dict(value)
    _require_exact_keys(authentication, _AUTHENTICATION_KEYS, "authorization authentication")
    expected = {
        "algorithm": "Ed25519",
        "purpose": AGENT_CHANGE_AUTHORIZATION_PURPOSE,
        "key_domain": AGENT_CHANGE_AUTHORIZATION_KEY_DOMAIN,
        "signature_path": AUTHORIZATION_SIGNATURE_PATH,
    }
    for field, item in expected.items():
        if authentication.get(field) != item:
            raise AgentChangeAdmissionError(
                f"authorization authentication.{field} must be {item!r}"
            )
    key_id = authentication.get("key_id")
    if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
        raise AgentChangeAdmissionError("authorization authentication.key_id is invalid")
    return {**expected, "key_id": key_id}


def validate_agent_change_authorization(value: Mapping[str, Any]) -> dict[str, Any]:
    authorization = dict(value)
    _require_exact_keys(authorization, _AUTHORIZATION_KEYS, "agent-change authorization")
    if authorization.get("format") != AGENT_CHANGE_AUTHORIZATION_FORMAT:
        raise AgentChangeAdmissionError("unsupported agent-change authorization format")
    return {
        "format": AGENT_CHANGE_AUTHORIZATION_FORMAT,
        "source": _validate_authorization_source(authorization.get("source")),
        "scope": _validate_scope(authorization.get("scope")),
        "required": _validate_required(authorization.get("required")),
        "authentication": _validate_authentication(authorization.get("authentication")),
    }


def _decode_signature(data: bytes) -> bytes:
    if len(data) != 88 or any(byte in b" \t\r\n" for byte in data):
        raise AgentChangeAdmissionError(
            "authorization signature is not one canonical Ed25519 signature"
        )
    try:
        signature = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AgentChangeAdmissionError("authorization signature is not canonical base64") from exc
    if len(signature) != 64 or base64.b64encode(signature) != data:
        raise AgentChangeAdmissionError(
            "authorization signature is not one canonical Ed25519 signature"
        )
    return signature


def seal_agent_change_authorization(
    output_path: str,
    *,
    source: Mapping[str, Any],
    scope: Mapping[str, Any],
    required: Mapping[str, Any],
    private_key_path: str,
    force: bool = False,
) -> InspectedAgentChangeAuthorization:
    """Create one signed, canonical control-plane authorization archive."""

    checked_source = _validate_authorization_source(dict(source))
    checked_scope = _validate_scope(dict(scope))
    checked_required = _validate_required(dict(required))
    # No key material is opened until every caller-controlled semantic field is
    # known to be bounded and canonical.
    from evoom_guard.signing import load_signing_key_snapshot, sign_bytes_with_snapshot

    signing_key = load_signing_key_snapshot(private_key_path)
    payload = validate_agent_change_authorization(
        {
            "format": AGENT_CHANGE_AUTHORIZATION_FORMAT,
            "source": checked_source,
            "scope": checked_scope,
            "required": checked_required,
            "authentication": {
                "algorithm": "Ed25519",
                "key_id": signing_key.key_id,
                "purpose": AGENT_CHANGE_AUTHORIZATION_PURPOSE,
                "key_domain": AGENT_CHANGE_AUTHORIZATION_KEY_DOMAIN,
                "signature_path": AUTHORIZATION_SIGNATURE_PATH,
            },
        }
    )
    manifest_bytes = canonical_json_bytes(payload)
    if len(manifest_bytes) > MAX_AUTHORIZATION_BYTES:
        raise AgentChangeAdmissionError(
            "canonical agent-change authorization exceeds the size limit"
        )
    signature, actual_key_id = sign_bytes_with_snapshot(
        AGENT_CHANGE_AUTHORIZATION_SIGNATURE_DOMAIN + manifest_bytes,
        signing_key,
    )
    if actual_key_id != signing_key.key_id or len(signature) != 64:
        raise AgentChangeAdmissionError(
            "authorization signing key changed or returned a non-canonical signature"
        )
    signature_bytes = base64.b64encode(signature)
    archive = canonical_archive_bytes(
        (
            (AUTHORIZATION_MANIFEST_PATH, manifest_bytes),
            (AUTHORIZATION_SIGNATURE_PATH, signature_bytes),
        )
    )
    if len(archive) > MAX_AUTHORIZATION_ARCHIVE_BYTES:
        raise AgentChangeAdmissionError("authorization archive exceeds the size limit")
    _publish_bytes(
        output_path,
        archive,
        label="agent-change authorization",
        force=force,
    )
    return inspect_agent_change_authorization(output_path)


def inspect_agent_change_authorization_bytes(
    snapshot: bytes,
) -> InspectedAgentChangeAuthorization:
    if not isinstance(snapshot, bytes) or not 1 <= len(snapshot) <= MAX_AUTHORIZATION_ARCHIVE_BYTES:
        raise AgentChangeAdmissionError("authorization archive is outside the size limit")
    try:
        preflight_canonical_zip(snapshot)
        with zipfile.ZipFile(io.BytesIO(snapshot), "r") as archive:
            infos = archive.infolist()
            if len(infos) != 2:
                raise AgentChangeAdmissionError(
                    "authorization archive must contain exactly two members"
                )
            for info in infos:
                validate_canonical_archive_member(info)
            names = [info.filename for info in infos]
            expected_names = [AUTHORIZATION_MANIFEST_PATH, AUTHORIZATION_SIGNATURE_PATH]
            if names != expected_names:
                raise AgentChangeAdmissionError("authorization archive members are not canonical")
            manifest_bytes = read_archive_member_bytes(
                archive,
                infos[0],
                limit=MAX_AUTHORIZATION_BYTES,
            )
            signature_bytes = read_archive_member_bytes(
                archive,
                infos[1],
                limit=88,
            )
    except AgentChangeAdmissionError:
        raise
    except (ValueError, zipfile.BadZipFile, OSError) as exc:
        raise AgentChangeAdmissionError(f"authorization archive is invalid: {exc}") from exc
    try:
        value = load_json_object_bytes(manifest_bytes, "authorization manifest")
    except ValueError as exc:
        raise AgentChangeAdmissionError(str(exc)) from exc
    payload = validate_agent_change_authorization(value)
    if canonical_json_bytes(payload) != manifest_bytes:
        raise AgentChangeAdmissionError("authorization manifest is not canonical JSON")
    signature = _decode_signature(signature_bytes)
    canonical = canonical_archive_bytes(
        (
            (AUTHORIZATION_MANIFEST_PATH, manifest_bytes),
            (AUTHORIZATION_SIGNATURE_PATH, signature_bytes),
        )
    )
    if canonical != snapshot:
        raise AgentChangeAdmissionError("authorization archive bytes are not canonical")
    return InspectedAgentChangeAuthorization(
        archive_bytes=snapshot,
        manifest_bytes=manifest_bytes,
        signature=signature,
        payload=payload,
    )


def inspect_agent_change_authorization(path: str) -> InspectedAgentChangeAuthorization:
    try:
        snapshot = read_regular_file_bytes(
            path,
            limit=MAX_AUTHORIZATION_ARCHIVE_BYTES,
            label="agent-change authorization",
        )
    except ValueError as exc:
        raise AgentChangeAdmissionError(str(exc)) from exc
    return inspect_agent_change_authorization_bytes(snapshot)


def verify_agent_change_authorization(
    inspected: InspectedAgentChangeAuthorization,
    *,
    trusted_public_key_path: str,
    expected_source: Mapping[str, Any],
) -> VerifiedAgentChangeAuthorization:
    expected = _validate_authorization_source(dict(expected_source))
    if inspected.payload["source"] != expected:
        raise AgentChangeAdmissionError(
            "authorization source does not exactly match external control-plane source"
        )
    from evoom_guard.signing import verify_bytes_with_key_id

    verified, key_id = verify_bytes_with_key_id(
        AGENT_CHANGE_AUTHORIZATION_SIGNATURE_DOMAIN + inspected.manifest_bytes,
        inspected.signature,
        trusted_public_key_path,
    )
    if not verified:
        raise AgentChangeAdmissionError("authorization signature is invalid")
    if key_id != inspected.payload["authentication"]["key_id"]:
        raise AgentChangeAdmissionError(
            "authorization key_id does not match the externally trusted key"
        )
    return VerifiedAgentChangeAuthorization(inspection=inspected, key_id=key_id)


def _matches_scope(path: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        if pattern.endswith("/**"):
            root = pattern[:-3]
            if path == root or path.startswith(root + "/"):
                return True
        elif path == pattern:
            return True
    return False


def _is_forbidden_control_path(path: str) -> bool:
    return (
        is_protected(path)
        or is_protected_config(path, strict_harness=True)
        or is_protected_ci(path)
        or is_judge_autoexec(path)
    )


def _validated_bindings(
    bindings: DerivedAgentChangeBindings,
) -> DerivedAgentChangeBindings:
    if type(bindings) is not DerivedAgentChangeBindings:
        raise AgentChangeAdmissionError(
            "agent-change bindings must be independently derived raw-Git bindings"
        )
    try:
        checked = validate_agent_change_bindings(bindings.payload)
        agent_change_bindings_bytes(checked)
    except FinalizerDerivationError as exc:
        raise AgentChangeAdmissionError(str(exc)) from exc
    return checked


def inspect_agent_change_bindings_bytes(data: bytes) -> DerivedAgentChangeBindings:
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_BINDINGS_BYTES:
        raise AgentChangeAdmissionError("agent-change bindings are outside the size limit")
    try:
        value = load_json_object_bytes(data, "agent-change bindings")
        bindings = validate_agent_change_bindings(value)
        canonical = agent_change_bindings_bytes(bindings)
    except (ValueError, FinalizerDerivationError) as exc:
        raise AgentChangeAdmissionError(str(exc)) from exc
    if canonical != data:
        raise AgentChangeAdmissionError("agent-change bindings are not canonical JSON")
    return bindings


def verify_agent_change_contract(
    proposal: InspectedAgentChangeProposal,
    authorization: VerifiedAgentChangeAuthorization,
    bindings: DerivedAgentChangeBindings,
    *,
    expected_finalizer_source: Mapping[str, Any],
    expected_context: Mapping[str, Any],
) -> VerifiedAgentChangeContract:
    """Require exact agreement between untrusted claims and trusted facts."""

    checked_bindings = _validated_bindings(bindings)
    source = dict(expected_finalizer_source)
    context = dict(expected_context)
    auth = authorization.inspection.payload
    auth_source = auth["source"]
    proposal_source = proposal.payload["source"]
    binding = checked_bindings.payload

    required_source = {
        "pull_request_number",
        "workflow_run_id",
        "workflow_run_attempt",
        "base_sha",
        "head_sha",
    }
    if set(source) != required_source:
        raise AgentChangeAdmissionError("expected finalizer source has non-canonical keys")
    required_context = {
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
    if set(context) != required_context:
        raise AgentChangeAdmissionError("expected finalizer context has non-canonical keys")

    if (
        auth_source["repository"] != context["repository"]
        or auth_source["repository_id"] != context["repository_id"]
        or auth_source["pull_request_number"] != source["pull_request_number"]
        or auth_source["base_sha"] != source["base_sha"]
        or auth_source["head_sha"] != source["head_sha"]
        or auth_source["base_tree_sha"] != context["base_tree_sha"]
        or auth_source["head_tree_sha"] != context["head_tree_sha"]
    ):
        raise AgentChangeAdmissionError(
            "authorization source does not bind the finalizer source/context"
        )
    if proposal_source != {
        "repository": context["repository"],
        "pull_request_number": source["pull_request_number"],
        "base_sha": source["base_sha"],
        "head_sha": source["head_sha"],
    }:
        raise AgentChangeAdmissionError(
            "proposal source does not bind the finalizer source/context"
        )
    for field in ("base_sha", "head_sha", "base_tree_sha", "head_tree_sha"):
        expected = source[field] if field in {"base_sha", "head_sha"} else context[field]
        if binding[field] != expected:
            raise AgentChangeAdmissionError(
                f"raw-Git agent-change {field} differs from finalizer context"
            )

    proposal_change = proposal.payload["change"]
    for field in (
        "candidate_sha256",
        "candidate_size",
        "changed_paths",
        "deleted_paths",
        "touched_paths",
    ):
        if proposal_change[field] != binding[field]:
            raise AgentChangeAdmissionError(f"proposal {field} differs from raw-Git derivation")
    if context["candidate_sha256"] != binding["candidate_sha256"]:
        raise AgentChangeAdmissionError(
            "finalizer candidate digest differs from agent-change raw-Git derivation"
        )
    proposal_policy = proposal.payload["observed_policy"]
    required = auth["required"]
    for field in ("policy_sha256", "verifier_pack_sha256"):
        if (
            proposal_policy[field] != binding[field]
            or required[field] != binding[field]
            or context[field] != binding[field]
        ):
            raise AgentChangeAdmissionError(
                f"proposal/authorization/finalizer {field} binding mismatch"
            )

    scope = auth["scope"]
    touched = checked_bindings.touched_paths
    if len(touched) > scope["maximum_touched_paths"]:
        raise AgentChangeAdmissionError("agent change exceeds the authorized path-count limit")
    if binding["candidate_size"] > scope["maximum_candidate_bytes"]:
        raise AgentChangeAdmissionError("agent change exceeds the authorized candidate-size limit")
    if checked_bindings.deleted_paths and not scope["allow_deletions"]:
        raise AgentChangeAdmissionError("agent change contains unauthorized deletions")
    for path in touched:
        if _is_forbidden_control_path(path):
            raise AgentChangeAdmissionError(
                f"agent authorization cannot permit judge-owned path: {path}"
            )
        if not _matches_scope(path, scope["allowed_patterns"]):
            raise AgentChangeAdmissionError(
                f"agent change path is outside its trusted authorization: {path}"
            )
    return VerifiedAgentChangeContract(
        proposal=proposal,
        authorization=authorization,
        bindings=checked_bindings,
    )


@contextmanager
def _material_snapshots(
    contract: VerifiedAgentChangeContract,
) -> Iterator[tuple[EvidenceMaterial, ...]]:
    materials = (
        (
            AGENT_CHANGE_PROPOSAL_ROLE,
            contract.proposal.proposal_bytes,
        ),
        (
            AGENT_CHANGE_AUTHORIZATION_ROLE,
            contract.authorization.inspection.archive_bytes,
        ),
        (
            AGENT_CHANGE_GIT_BINDINGS_ROLE,
            agent_change_bindings_bytes(contract.bindings),
        ),
    )
    with tempfile.TemporaryDirectory(prefix=".evoguard-agent-change-materials-") as directory:
        paths: list[EvidenceMaterial] = []
        for role, data in materials:
            descriptor, path = tempfile.mkstemp(prefix=f"{role}-", dir=directory)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(path, 0o600)
            paths.append(EvidenceMaterial(role=role, source_path=path))
        yield tuple(paths)


def _material_bytes(finalized: VerifiedFinalizedBundle, role: str) -> bytes:
    matches = finalized.bundle.materials_for(role)
    if len(matches) != 1:
        raise AgentChangeAdmissionError(
            f"agent-change finalizer bundle must contain exactly one {role!r} material"
        )
    return matches[0].data


def seal_agent_change_finalizer_bundle(
    proposal_path: str,
    authorization_path: str,
    handoff_path: str,
    verdict_path: str,
    output_path: str,
    *,
    base_repo: str,
    head_repo: str,
    git_executable: GitExecutablePin,
    base_is_bare: bool = False,
    head_is_bare: bool = False,
    expected_authorization_source: Mapping[str, Any],
    authorization_public_key_path: str,
    expected_finalizer_source: Mapping[str, Any],
    expected_context: Mapping[str, Any],
    finalizer_private_key_path: str,
    finalizer_public_key_path: str,
    expected_derivation: Mapping[str, Any] | None = None,
    force: bool = False,
) -> FinalizedAgentChangeAdmission:
    """Derive raw Git inside the sealer, then publish only a verified ALLOW.

    ``base_repo`` and ``head_repo`` are trusted finalizer object stores.  A
    caller-supplied bindings file is deliberately not accepted here: validated
    JSON is still only data, not proof that it represents immutable Git truth.
    """

    source = dict(expected_finalizer_source)
    context = dict(expected_context)
    base_sha = _git_sha(source.get("base_sha"), label="expected finalizer source.base_sha")
    head_sha = _git_sha(source.get("head_sha"), label="expected finalizer source.head_sha")
    base_tree_sha = _git_sha(
        context.get("base_tree_sha"), label="expected finalizer context.base_tree_sha"
    )
    head_tree_sha = _git_sha(
        context.get("head_tree_sha"), label="expected finalizer context.head_tree_sha"
    )
    try:
        bindings = derive_agent_change_bindings(
            base_repo=base_repo,
            head_repo=head_repo,
            base_sha=base_sha,
            head_sha=head_sha,
            base_tree_sha=base_tree_sha,
            head_tree_sha=head_tree_sha,
            base_is_bare=base_is_bare,
            head_is_bare=head_is_bare,
            git_executable=git_executable,
        )
    except FinalizerDerivationError as exc:
        raise AgentChangeAdmissionError(
            f"could not independently derive Agent Change Git truth: {exc}"
        ) from exc

    proposal = inspect_agent_change_proposal(proposal_path)
    authorization = verify_agent_change_authorization(
        inspect_agent_change_authorization(authorization_path),
        trusted_public_key_path=authorization_public_key_path,
        expected_source=expected_authorization_source,
    )
    contract = verify_agent_change_contract(
        proposal,
        authorization,
        bindings,
        expected_finalizer_source=expected_finalizer_source,
        expected_context=expected_context,
    )

    # A control-plane authorization key and the finalizer decision key are
    # separate trust domains. Reading public keys here does not expose the
    # signing key; all semantic checks above finish before the private key opens.
    from evoom_guard.signing import public_key_id

    finalizer_key_id = public_key_id(finalizer_public_key_path)
    if finalizer_key_id == authorization.key_id:
        raise AgentChangeAdmissionError(
            "authorization and Trusted Finalizer must use distinct keys"
        )

    try:
        handoff = verify_finalizer_handoff(
            inspect_finalizer_handoff(handoff_path),
            verdict_path=verdict_path,
            expected_source=expected_finalizer_source,
            expected_context=expected_context,
        )
    except FinalizerHandoffError as exc:
        raise AgentChangeAdmissionError(str(exc)) from exc
    if finalizer_decision(handoff.verdict) != "ALLOW":
        raise AgentChangeAdmissionError(
            "Agent Change admission requires a verified Trusted Finalizer ALLOW"
        )

    absolute_output = os.path.abspath(output_path)
    parent = os.path.dirname(absolute_output) or os.curdir
    if os.path.isdir(absolute_output):
        raise AgentChangeAdmissionError(
            f"Agent Change bundle output is a directory: {absolute_output}"
        )
    os.makedirs(parent, exist_ok=True)

    # The generic finalizer correctly publishes its own result atomically, but
    # this stricter profile has one more obligation: verify the result with the
    # externally trusted public key before *any* admission side effect.  Seal
    # into a private sibling directory, verify there, and only then atomically
    # publish the exact staged inode.  With force=True an old output remains
    # untouched unless every check succeeds.
    with tempfile.TemporaryDirectory(prefix=".evoguard-agent-change-stage-", dir=parent) as stage:
        staged_output = os.path.join(stage, "agent-change.evb")
        with _material_snapshots(contract) as materials:
            try:
                finalized = seal_finalizer_bundle(
                    handoff_path,
                    verdict_path,
                    staged_output,
                    expected_source=expected_finalizer_source,
                    expected_context=expected_context,
                    private_key_path=finalizer_private_key_path,
                    expected_derivation=expected_derivation,
                    materials=materials,
                    force=False,
                )
            except FinalizerHandoffError as exc:
                raise AgentChangeAdmissionError(str(exc)) from exc
        if finalized.decision != "ALLOW":
            raise AgentChangeAdmissionError(
                "Trusted Finalizer did not produce an ALLOW admission"
            )
        verified = verify_agent_change_finalized_bundle(
            staged_output,
            trusted_finalizer_public_key_path=finalizer_public_key_path,
            authorization_public_key_path=authorization_public_key_path,
            expected_authorization_source=expected_authorization_source,
            expected_finalizer_source=expected_finalizer_source,
            expected_context=expected_context,
            expected_bindings=bindings,
        )
        try:
            # Set final permissions while the artifact is still private.  No
            # fallible metadata operation may run after publication.
            os.chmod(staged_output, 0o644)
            if force:
                os.replace(staged_output, absolute_output)
            else:
                os.link(staged_output, absolute_output, follow_symlinks=False)
        except FileExistsError as exc:
            raise AgentChangeAdmissionError(
                f"refusing to overwrite existing Agent Change bundle: {absolute_output}"
            ) from exc
        except OSError as exc:
            raise AgentChangeAdmissionError(
                "cannot atomically publish verified Agent Change bundle"
            ) from exc

    finalized = FinalizedTrustedEvidence(
        finalized=replace(finalized.finalized, bundle_path=absolute_output),
        handoff=finalized.handoff,
    )
    return FinalizedAgentChangeAdmission(
        finalized=finalized,
        contract=verified.contract,
    )


def verify_agent_change_finalized_bundle(
    bundle_path: str,
    *,
    trusted_finalizer_public_key_path: str,
    authorization_public_key_path: str,
    expected_authorization_source: Mapping[str, Any],
    expected_finalizer_source: Mapping[str, Any],
    expected_context: Mapping[str, Any],
    expected_bindings: DerivedAgentChangeBindings,
) -> VerifiedAgentChangeAdmission:
    """Verify the complete profile offline without executing candidate code."""

    try:
        finalized = verify_finalized_bundle(
            bundle_path,
            trusted_public_key_path=trusted_finalizer_public_key_path,
            expected_source=expected_finalizer_source,
            expected_context=expected_context,
        )
    except FinalizerHandoffError as exc:
        raise AgentChangeAdmissionError(str(exc)) from exc
    if finalized.decision != "ALLOW":
        raise AgentChangeAdmissionError("Agent Change admission requires a Trusted Finalizer ALLOW")
    proposal = inspect_agent_change_proposal_bytes(
        _material_bytes(finalized, AGENT_CHANGE_PROPOSAL_ROLE)
    )
    authorization = verify_agent_change_authorization(
        inspect_agent_change_authorization_bytes(
            _material_bytes(finalized, AGENT_CHANGE_AUTHORIZATION_ROLE)
        ),
        trusted_public_key_path=authorization_public_key_path,
        expected_source=expected_authorization_source,
    )
    embedded_bindings = inspect_agent_change_bindings_bytes(
        _material_bytes(finalized, AGENT_CHANGE_GIT_BINDINGS_ROLE)
    )
    expected = _validated_bindings(expected_bindings)
    if embedded_bindings.payload != expected.payload:
        raise AgentChangeAdmissionError(
            "embedded agent-change bindings differ from external raw-Git derivation"
        )
    finalizer_key_id = finalized.bundle.manifest["authentication"]["key_id"]
    if finalizer_key_id == authorization.key_id:
        raise AgentChangeAdmissionError("authorization and Trusted Finalizer use the same key")
    contract = verify_agent_change_contract(
        proposal,
        authorization,
        expected,
        expected_finalizer_source=expected_finalizer_source,
        expected_context=expected_context,
    )
    return VerifiedAgentChangeAdmission(finalized=finalized, contract=contract)
