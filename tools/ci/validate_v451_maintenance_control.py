#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Validate the inert Phase-0 model for the one-time v4.5.1 lane.

The checked-in contract is intentionally not an operational publication gate
and cannot activate itself. The optional observation helper checks closed test
shapes only; it performs no API authentication, Git derivation, cryptography,
artifact-byte verification, temporal binding, or retirement verification. The
CLI checks only that the source contract remains inert.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import hashlib
import json
import os
import re
import stat
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "security" / "v4.5.1-maintenance-lane.json"
MAX_CONTROL_BYTES = 2 * 1024 * 1024
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
FINGERPRINT_PATTERN = re.compile(r"^(?:[0-9A-F]{40}|[0-9A-F]{64}|SHA256:[A-Za-z0-9+/]{43}=?)$")
UTC_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
PLACEHOLDER = "POST_MERGE_REQUIRED"
TAG_MAX_DECODED_BYTES = 32_768
SIGNING_KEY_PATH = "security/v4.5.1-maintainer-signing.pub"
SIGNING_KEY_MODE = "100644"
RUN_PHASES: tuple[str, ...] = ("A", "B", "CD", "E", "F", "G", "H")
WORKFLOW_ROLES: tuple[str, ...] = tuple(f"workflow-{phase}" for phase in RUN_PHASES)
REQUIRED_CHECKS: tuple[tuple[str, int], ...] = (
    ("test (3.10)", 15368),
    ("test (3.11)", 15368),
    ("test (3.12)", 15368),
    ("e2e-runners", 15368),
    ("blackbox-docker-e2e", 15368),
    ("smoke", 15368),
    ("analyze", 15368),
    ("CodeQL", 57789),
    ("project-status", 15368),
    ("fuzz (address)", 15368),
    ("fuzz (undefined)", 15368),
)
RUN_JOBS: dict[str, tuple[str, ...]] = {
    "A": ("metadata", "reverify"),
    "B": ("preflight", "receipt"),
    "CD": ("preflight", "seal", "detached-verify"),
    "E": ("preflight", "build", "attest"),
    "F": ("preflight", "verify-attestations", "seal"),
    "G": ("detached-verify",),
    "H": ("preflight", "draft", "publish"),
}
RAW_ENTRY_PINS: dict[str, tuple[str, str]] = {
    ".github/workflows/evoguard-release-source-reverify.yml": (
        "workflow-A",
        "00288a7792f2aec5954d1e7ff72024e312f813e8",
    ),
    ".github/workflows/evoguard-produce-release-source-receipt.yml": (
        "workflow-B",
        "48ace886b9757440749b1e237760ed2ab5817860",
    ),
    ".github/workflows/evoguard-admit-release-source.yml": (
        "workflow-CD",
        "8b38f5d2a7957782f3945b671bd877e047f8598d",
    ),
    ".github/workflows/evoguard-build-release-artifact.yml": (
        "workflow-E",
        "7906b615a5b88f605b005d157c1196fe56c902bf",
    ),
    ".github/workflows/evoguard-admit-release-artifact.yml": (
        "workflow-F",
        "c85117813d93d8d1e148345ed444994ace4be468",
    ),
    ".github/workflows/evoguard-verify-release-artifact.yml": (
        "workflow-G",
        "3fd1aa0f274900c5aa877d473f6fdb6f87e8bc4c",
    ),
    ".github/workflows/evoguard-publish-admitted-release.yml": (
        "workflow-H",
        "bc6e41645b151775c339af17e3941851c15e2d3f",
    ),
    ".github/CODEOWNERS": ("control", "fb67147621b6ab64bb406fc856bb57857b18a093"),
    ".evoguard.json": ("policy", "7988a6a7d6f1df0ebd14028eba29f2257b2b1d2c"),
    "security/release-pipeline-bootstrap.json": (
        "control",
        "44d4f0b87129f00aee1005d96830bc203013521e",
    ),
    "security/release-source-pack/pack.json": (
        "pack",
        "a05bb0d113cfc9675e06c9480590496dbf841b82",
    ),
    "security/release-source-pack/test_release_protocol.py": (
        "pack",
        "f8f6d9369d295171ad78c87dff424840a800de3e",
    ),
    "security/judge-requirements.lock": (
        "control",
        "8d173d39ba87c7a075fcac42c8fabe692263cbf6",
    ),
}
VALIDATOR_PATH = "tools/ci/validate_v451_maintenance_control.py"
ENVIRONMENT_PINS: dict[str, tuple[int, int]] = {
    "evoguard-release-source-v2": (18718844374, 55562429),
    "evoguard-release-artifact-v1": (18718845035, 55562431),
    "evoguard-release-draft": (18718845676, 55562435),
    "evoguard-release-publication": (18718846349, 55562438),
}
PUBLICATION_ENVIRONMENT = "evoguard-release-publication"
PUBLICATION_ENVIRONMENT_ID = 18718846349
PUBLICATION_SECRET_NAME = "EVOGUARD_RELEASE_TAG_DEPLOY_KEY"
PUBLICATION_KEY_TITLE = "EvoOM Guard v4.5.1 temporary release tag authority"
REQUIRED_BLOCKER_IDS: frozenset[str] = frozenset(
    {
        "post_merge_workflow_pins_absent",
        "maintenance_branch_protection_absent",
        "release_candidate_pr_absent",
        "maintainer_signing_root_unpinned",
        "owner_control_plane_collector_unimplemented",
        "publication_deploy_key_unpinned",
        "publication_secret_binding_unimplemented",
        "independent_release_byte_receipts_unimplemented",
        "workflow_target_identity_split_unimplemented",
        "annotated_tag_object_publication_unimplemented",
        "raw_tag_object_variable_absent",
        "canonical_tag_parser_unimplemented",
        "per_run_temporal_binding_unimplemented",
        "publication_authority_retirement_unimplemented",
    }
)


class MaintenanceControlError(ValueError):
    """The model or trusted observation is outside the reviewed contract."""


def _fail(message: str) -> NoReturn:
    raise MaintenanceControlError(message)


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(f"{label} must be an array")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be a non-empty string")
    return value


def _integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        _fail(f"{label} must be a positive integer")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        _fail(f"{label} must be a boolean")
    return value


def _sha(value: Any, label: str, *, allow_placeholder: bool = False) -> str:
    text = _string(value, label)
    if allow_placeholder and text == PLACEHOLDER:
        return PLACEHOLDER
    if SHA_PATTERN.fullmatch(text) is None:
        _fail(f"{label} must be one lowercase 40-hex Git object ID")
    return text


def _sha256(value: Any, label: str) -> str:
    text = _string(value, label)
    if SHA256_PATTERN.fullmatch(text) is None:
        _fail(f"{label} must be one lowercase SHA-256 digest")
    return text


def _timestamp(value: Any, label: str, *, allow_placeholder: bool = False) -> str:
    text = _string(value, label)
    if allow_placeholder and text == PLACEHOLDER:
        return PLACEHOLDER
    if UTC_PATTERN.fullmatch(text) is None:
        _fail(f"{label} must be a whole-second UTC timestamp")
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise MaintenanceControlError(
            f"{label} must be a real whole-second UTC RFC3339 timestamp"
        ) from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != text or parsed.utcoffset() is None:
        _fail(f"{label} must be a canonical whole-second UTC RFC3339 timestamp")
    return text


def _positive_id_or_placeholder(value: Any, label: str, *, activated: bool) -> int | str:
    if not activated and value == PLACEHOLDER:
        return PLACEHOLDER
    return _integer(value, label)


def _safe_repo_path(value: Any, label: str) -> str:
    """Return one normalized relative POSIX repository path or fail closed."""

    path = _string(value, label)
    segments = path.split("/")
    if (
        path.startswith("/")
        or path.endswith("/")
        or "\\" in path
        or re.match(r"^[A-Za-z]:", path) is not None
        or any(segment in {"", ".", ".."} for segment in segments)
    ):
        _fail(f"{label} must be a safe normalized relative POSIX repository path")
    return path


def _openssh_ed25519_fingerprint(value: Any, label: str) -> str:
    """Derive an OpenSSH SHA256 fingerprint from one canonical Ed25519 key."""

    text = _string(value, label)
    parts = text.split()
    if len(parts) != 2 or parts[0] != "ssh-ed25519":
        _fail(f"{label} must be one comment-free ssh-ed25519 public key")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MaintenanceControlError(f"{label} is not canonical base64") from exc
    try:
        algorithm_length = struct.unpack(">I", blob[:4])[0]
        offset = 4
        algorithm = blob[offset : offset + algorithm_length]
        offset += algorithm_length
        key_length = struct.unpack(">I", blob[offset : offset + 4])[0]
        offset += 4
        key = blob[offset : offset + key_length]
        offset += key_length
    except (struct.error, ValueError) as exc:
        raise MaintenanceControlError(f"{label} has an invalid SSH wire encoding") from exc
    if algorithm != b"ssh-ed25519" or key_length != 32 or len(key) != 32 or offset != len(blob):
        _fail(f"{label} is not one canonical 32-byte Ed25519 public key")
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        _fail(
            f"{label} keys are not closed: missing={sorted(expected - actual)!r}, "
            f"unexpected={sorted(actual - expected)!r}"
        )


def _unique_strings(value: Any, label: str) -> tuple[str, ...]:
    items = tuple(_string(item, f"{label} item") for item in _array(value, label))
    if len(items) != len(set(items)):
        _fail(f"{label} entries must be unique")
    return items


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MaintenanceControlError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    raise MaintenanceControlError(f"non-finite JSON number is forbidden: {value}")


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(stat.S_IFMT(metadata.st_mode)),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(flag and attributes & flag)


def load_json(path: Path) -> dict[str, Any]:
    """Read one stable, bounded, duplicate-free regular JSON file."""

    try:
        before = os.lstat(path)
    except OSError as exc:
        raise MaintenanceControlError(f"cannot inspect JSON input: {path}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or _is_reparse_point(before)
        or not stat.S_ISREG(before.st_mode)
        or int(before.st_nlink) != 1
    ):
        _fail("JSON input must be one regular non-link file")
    if before.st_size < 2 or before.st_size > MAX_CONTROL_BYTES:
        _fail(f"JSON input is outside the 2-{MAX_CONTROL_BYTES} byte bound")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise MaintenanceControlError(f"cannot open JSON input safely: {path}") from exc
    chunks: list[bytes] = []
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse_point(opened)
            or int(opened.st_nlink) != 1
            or _identity(opened) != _identity(before)
        ):
            _fail("JSON input changed while it was opened")
        total = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_CONTROL_BYTES:
                _fail("JSON input exceeded its byte bound while being read")
            chunks.append(chunk)
        if _identity(os.fstat(descriptor)) != _identity(opened):
            _fail("JSON input changed while it was read")
    finally:
        os.close(descriptor)
    try:
        after = os.lstat(path)
    except OSError as exc:
        raise MaintenanceControlError("cannot re-inspect JSON input") from exc
    if _identity(after) != _identity(before):
        _fail("JSON input path changed during validation")
    raw = b"".join(chunks)
    if len(raw) != before.st_size:
        _fail("JSON input size changed while it was read")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MaintenanceControlError("JSON input is not canonical UTF-8 JSON") from exc
    return _object(value, "JSON input")


def _validate_protection(value: Any, label: str) -> dict[str, Any]:
    protection = _object(value, label)
    expected = {
        "strict_status_checks",
        "required_checks",
        "dismiss_stale_reviews",
        "require_code_owner_reviews",
        "require_last_push_approval",
        "required_approving_review_count",
        "required_signatures",
        "enforce_admins",
        "required_linear_history",
        "allow_force_pushes",
        "allow_deletions",
        "block_creations",
        "required_conversation_resolution",
        "lock_branch",
        "allow_fork_syncing",
    }
    _exact_keys(protection, expected, label)
    true_fields = {
        "strict_status_checks",
        "dismiss_stale_reviews",
        "require_code_owner_reviews",
        "require_last_push_approval",
        "enforce_admins",
        "required_conversation_resolution",
    }
    false_fields = (
        expected
        - true_fields
        - {
            "required_checks",
            "required_approving_review_count",
        }
    )
    for field in true_fields:
        if _boolean(protection[field], f"{label} {field}") is not True:
            _fail(f"{label} {field} must be true")
    for field in false_fields:
        if _boolean(protection[field], f"{label} {field}") is not False:
            _fail(f"{label} {field} must be false")
    if protection["required_approving_review_count"] != 1:
        _fail(f"{label} approving-review count must be literal 1")
    checks: list[tuple[str, int]] = []
    for index, raw in enumerate(_array(protection["required_checks"], "required checks")):
        check = _object(raw, f"required check {index}")
        _exact_keys(check, {"context", "app_id"}, f"required check {index}")
        checks.append(
            (
                _string(check["context"], "required check context"),
                _integer(check["app_id"], "required check App ID"),
            )
        )
    if tuple(checks) != REQUIRED_CHECKS:
        _fail("branch protection must pin the literal ordered 11 check/App-ID pairs")
    return protection


def _validate_raw_entries(value: Any, *, activated: bool) -> dict[str, Any]:
    raw_git = _object(value, "trusted raw-Git contract")
    _exact_keys(
        raw_git,
        {"trusted_workflow_sha", "trusted_workflow_tree", "required_entries"},
        "trusted raw-Git contract",
    )
    _sha(
        raw_git["trusted_workflow_sha"],
        "trusted workflow SHA",
        allow_placeholder=not activated,
    )
    _sha(
        raw_git["trusted_workflow_tree"],
        "trusted workflow tree",
        allow_placeholder=not activated,
    )
    entries = _object(raw_git["required_entries"], "required raw-Git entries")
    if set(entries) != {*RAW_ENTRY_PINS, VALIDATOR_PATH}:
        _fail("trusted raw-Git entry inventory is not literal")
    roles: list[str] = []
    for path, raw in entries.items():
        _safe_repo_path(path, "raw-Git path")
        entry = _object(raw, f"raw-Git entry {path}")
        _exact_keys(entry, {"role", "mode", "blob_sha"}, f"raw-Git entry {path}")
        role = _string(entry["role"], f"raw-Git role {path}")
        roles.append(role)
        if entry["mode"] != "100644":
            _fail(f"raw-Git entry {path} must be a literal 100644 blob")
        _sha(entry["blob_sha"], f"raw-Git blob {path}", allow_placeholder=not activated)
        if (
            path in RAW_ENTRY_PINS
            and (
                role,
                entry["blob_sha"],
            )
            != RAW_ENTRY_PINS[path]
        ):
            _fail(f"raw-Git role/blob pin differs from the reviewed baseline: {path}")
        if path == VALIDATOR_PATH and role != "control-validator":
            _fail("raw-Git validator entry role is not literal")
    if set(WORKFLOW_ROLES) - set(roles):
        _fail("trusted raw-Git entries do not contain the seven workflow roles")
    if len([role for role in roles if role in WORKFLOW_ROLES]) != 7:
        _fail("trusted raw-Git workflow roles must each occur exactly once")
    return raw_git


def _expected_observed_raw_entries(contract: dict[str, Any]) -> dict[str, Any]:
    """Bind the dynamic signing root to a literal blob in the trusted tree shape."""

    raw_git = _object(contract["trusted_raw_git"], "trusted raw-Git contract")
    expected = copy.deepcopy(_object(raw_git["required_entries"], "required raw-Git entries"))
    signatures = _object(contract["local_signature_verification"], "local signature contract")
    key_path = _safe_repo_path(
        signatures["public_key_repository_path"], "signing public-key repository path"
    )
    if key_path in expected:
        _fail("dynamic signing public-key path collides with a static trusted raw-Git entry")
    expected[key_path] = {
        "role": "maintainer-signing-root",
        "mode": signatures["public_key_mode"],
        "blob_sha": signatures["public_key_blob_sha"],
    }
    return expected


def _validate_publication_authority_contract(value: Any, *, activated: bool) -> dict[str, Any]:
    authority = _object(value, "publication authority contract")
    _exact_keys(
        authority,
        {
            "observation_authority",
            "candidate_supplied",
            "repository_deploy_keys",
            "environment_secret_metadata",
            "private_key_binding",
        },
        "publication authority contract",
    )
    if (
        authority["observation_authority"]
        != "OUT_OF_PROCESS_OWNER_AUTHENTICATED_BOUNDED_FULLY_PAGINATED_GITHUB_API_COLLECTOR"
        or _boolean(authority["candidate_supplied"], "publication candidate authority")
    ):
        _fail("publication authority must come from the trusted owner collector")

    deploy_keys = _object(authority["repository_deploy_keys"], "deploy-key contract")
    _exact_keys(
        deploy_keys,
        {"endpoint", "exact_write_enabled_count", "required_write_key"},
        "deploy-key contract",
    )
    if (
        deploy_keys["endpoint"] != "/repos/EvoRiseKsa/EvoOM-Guard-m/keys"
        or deploy_keys["exact_write_enabled_count"] != 1
    ):
        _fail("deploy-key collection/one-write-key requirement is not exact")
    required_key = _object(deploy_keys["required_write_key"], "required write deploy key")
    _exact_keys(
        required_key,
        {
            "id",
            "title",
            "public_key",
            "fingerprint",
            "algorithm",
            "created_at",
            "verified",
            "read_only",
            "enabled",
        },
        "required write deploy key",
    )
    _positive_id_or_placeholder(required_key["id"], "write deploy-key ID", activated=activated)
    if (
        required_key["title"] != PUBLICATION_KEY_TITLE
        or required_key["algorithm"] != "ssh-ed25519"
        or _boolean(required_key["verified"], "write deploy-key verified") is not True
        or _boolean(required_key["read_only"], "write deploy-key read-only") is not False
        or _boolean(required_key["enabled"], "write deploy-key enabled") is not True
    ):
        _fail("required write deploy-key identity/capability is not exact")
    public_key = _string(required_key["public_key"], "write deploy-key public key")
    fingerprint = _string(required_key["fingerprint"], "write deploy-key fingerprint")
    _timestamp(
        required_key["created_at"],
        "write deploy-key creation",
        allow_placeholder=not activated,
    )
    if activated:
        derived = _openssh_ed25519_fingerprint(public_key, "write deploy-key public key")
        if fingerprint != derived:
            _fail("write deploy-key fingerprint is not derived from its pinned public key")
    elif (
        required_key["id"] != PLACEHOLDER
        or public_key != PLACEHOLDER
        or fingerprint != PLACEHOLDER
        or required_key["created_at"] != PLACEHOLDER
    ):
        _fail("inert deploy-key public identity must remain invalid placeholders")

    secret = _object(
        authority["environment_secret_metadata"], "publication secret metadata contract"
    )
    _exact_keys(
        secret,
        {
            "endpoint",
            "environment",
            "environment_id",
            "exact_secret_inventory",
            "required_secret",
            "secret_value_observable_via_github_api",
        },
        "publication secret metadata contract",
    )
    if (
        secret["endpoint"]
        != ("/repos/EvoRiseKsa/EvoOM-Guard-m/environments/evoguard-release-publication/secrets")
        or secret["environment"] != PUBLICATION_ENVIRONMENT
        or secret["environment_id"] != PUBLICATION_ENVIRONMENT_ID
        or secret["exact_secret_inventory"] != [PUBLICATION_SECRET_NAME]
        or _boolean(secret["secret_value_observable_via_github_api"], "secret API visibility")
    ):
        _fail("publication Environment secret authority/inventory is not exact")
    required_secret = _object(secret["required_secret"], "required publication secret")
    _exact_keys(
        required_secret,
        {"name", "created_at", "updated_at"},
        "required publication secret",
    )
    if required_secret["name"] != PUBLICATION_SECRET_NAME:
        _fail("publication Environment secret name is not exact")
    created_at = _timestamp(
        required_secret["created_at"],
        "publication secret creation",
        allow_placeholder=not activated,
    )
    updated_at = _timestamp(
        required_secret["updated_at"], "publication secret update", allow_placeholder=not activated
    )
    if activated and created_at > updated_at:
        _fail("publication secret metadata timestamps are inconsistent")
    if not activated and (created_at != PLACEHOLDER or updated_at != PLACEHOLDER):
        _fail("inert publication secret metadata must remain invalid placeholders")

    binding = _object(authority["private_key_binding"], "publication key binding contract")
    if binding != {
        "source": "TRUSTED_MAIN_H_ENVIRONMENT_SECRET_PUBLIC_KEY_DERIVATION",
        "candidate_supplied": False,
        "required_before_tag_mutation": True,
        "derived_public_key_must_equal_deploy_key": True,
        "derived_fingerprint_must_equal_deploy_key": True,
    }:
        _fail("publication private/public key binding contract is not exact")
    return authority


def _validate_contract_model(
    contract: dict[str, Any], *, resolved_external_shape: bool
) -> dict[str, Any]:
    """Validate the inert model, optionally with external test-shape pins resolved."""

    _exact_keys(
        contract,
        {
            "format",
            "assurance_state",
            "activation",
            "repository",
            "control_plane_authority",
            "refs",
            "maintenance_base",
            "candidate_scope",
            "review",
            "required_branch_protection",
            "required_repository_rulesets",
            "required_environments",
            "required_publication_authority",
            "trusted_raw_git",
            "local_signature_verification",
            "runs",
            "tag_contract",
            "release_contract",
            "checkpoint_contract",
            "retirement_contract",
            "blockers",
        },
        "maintenance contract",
    )
    if contract["format"] != "EVOGUARD_MAINTENANCE_LANE_PHASE0_V2":
        _fail("maintenance contract format is not exact")
    blockers = _unique_strings(contract["blockers"], "contract blockers")
    if frozenset(blockers) != REQUIRED_BLOCKER_IDS:
        _fail("contract blocker IDs must equal the exact closed required blocker set")
    activation = _object(contract["activation"], "activation contract")
    _exact_keys(
        activation,
        {
            "enabled",
            "one_shot_version",
            "current_release_flags",
            "owner_authorized_post_merge_pins",
        },
        "activation contract",
    )
    enabled = _boolean(activation["enabled"], "activation enabled")
    if activation["one_shot_version"] != "4.5.1":
        _fail("maintenance contract is not literal one-shot v4.5.1")
    if enabled or contract["assurance_state"] != "INERT_PRE_ACTIVATION_MODEL_NOT_LIVE_PROOF":
        _fail("checked-in Phase-0 model can only be inert and cannot activate itself")
    flags = _object(activation["current_release_flags"], "current release flags")
    if flags != {
        "EVOGUARD_RELEASE_SOURCE_V2_ENABLED": "false",
        "EVOGUARD_RELEASE_ARTIFACT_ADMISSION_V1_ENABLED": "false",
        "EVOGUARD_RELEASE_PUBLICATION_ENABLED": "false",
    }:
        _fail("legacy/default release flags must remain exactly false")
    pins = _object(activation["owner_authorized_post_merge_pins"], "post-merge pins")
    _exact_keys(
        pins,
        {
            "trusted_workflow_sha_variable",
            "trusted_workflow_sha",
            "trusted_workflow_tree_variable",
            "trusted_workflow_tree",
            "one_shot_enable_variable",
            "one_shot_enable_value",
        },
        "post-merge pins",
    )
    if (
        pins["trusted_workflow_sha_variable"] != "EVOGUARD_V451_TRUSTED_WORKFLOW_SHA"
        or (pins["trusted_workflow_tree_variable"] != "EVOGUARD_V451_TRUSTED_WORKFLOW_TREE_SHA")
        or pins["one_shot_enable_variable"] != "EVOGUARD_V451_MAINTENANCE_ENABLED"
    ):
        _fail("post-merge owner authorization variable names are not literal")
    for field in ("trusted_workflow_sha", "trusted_workflow_tree"):
        _sha(pins[field], field, allow_placeholder=not resolved_external_shape)
    if resolved_external_shape:
        if pins["one_shot_enable_value"] != pins["trusted_workflow_sha"]:
            _fail("external one-shot shape must bind the exact trusted workflow SHA")
    elif (
        pins["trusted_workflow_sha"] != PLACEHOLDER
        or pins["trusted_workflow_tree"] != PLACEHOLDER
        or pins["one_shot_enable_value"] != PLACEHOLDER
    ):
        _fail("inert post-merge pins must remain invalid external placeholders")

    repository = _object(contract["repository"], "repository contract")
    if repository != {
        "full_name": "EvoRiseKsa/EvoOM-Guard-m",
        "id": 1293651176,
        "owner_login": "EvoRiseKsa",
        "owner_id": 231647061,
        "default_branch": "main",
    }:
        _fail("repository identity is not the literal reviewed repository")
    authority = _object(contract["control_plane_authority"], "control-plane authority")
    if authority != {
        "source": "OWNER_AUTHENTICATED_GITHUB_API",
        "candidate_supplied": False,
        "fully_paginated": True,
        "raw_responses_bounded_before_parsing": True,
    }:
        _fail("control-plane authority is not owner-authenticated and bounded")
    refs = _object(contract["refs"], "literal refs")
    if refs != {
        "trusted_workflow_branch": "main",
        "trusted_workflow_ref": "refs/heads/main",
        "maintenance_base_branch": "maintenance/v4.5",
        "maintenance_base_ref": "refs/heads/maintenance/v4.5",
        "candidate_branch": "release/v4.5.1",
        "candidate_ref": "refs/heads/release/v4.5.1",
        "tag": "v4.5.1",
    }:
        _fail("maintenance refs are not the literal one-shot identities")
    base = _object(contract["maintenance_base"], "maintenance base")
    _exact_keys(base, {"post_v4_5_0_commit", "post_v4_5_0_tree"}, "maintenance base")
    _sha(base["post_v4_5_0_commit"], "post-v4.5.0 commit")
    _sha(base["post_v4_5_0_tree"], "post-v4.5.0 tree")

    scope = _object(contract["candidate_scope"], "candidate scope")
    _exact_keys(
        scope,
        {"required_changed_paths", "allowed_changed_paths", "verification_source"},
        "candidate scope",
    )
    required = set(_unique_strings(scope["required_changed_paths"], "required paths"))
    allowed = set(_unique_strings(scope["allowed_changed_paths"], "allowed paths"))
    if (
        not required
        or not required <= allowed
        or scope["verification_source"] != ("TRUSTED_RAW_GIT_DIFF_WITH_MODES_BLOBS_AND_PATCH_BYTES")
    ):
        _fail("candidate scope is not a non-empty trusted raw-Git contract")
    review = _object(contract["review"], "review contract")
    if review != {
        "required_exact_head_approver": "MANA-awam",
        "required_exact_head_approver_id": 304223352,
        "same_owner_procedural_only": True,
    }:
        _fail("review identity/non-independence statement is not exact")

    protection = _validate_protection(
        contract["required_branch_protection"], "required branch protection"
    )
    rulesets = _array(contract["required_repository_rulesets"], "repository rulesets")
    if len(rulesets) != 1:
        _fail("exactly one repository ruleset is required")
    ruleset = _object(rulesets[0], "release tag ruleset")
    if ruleset != {
        "id": 19713401,
        "name": "EvoGuard release tag authority",
        "target": "tag",
        "source_type": "Repository",
        "source": "EvoRiseKsa/EvoOM-Guard-m",
        "enforcement": "active",
        "include": ["refs/tags/v*"],
        "exclude": [],
        "rules": ["creation", "update", "deletion", "non_fast_forward"],
        "bypass_actors": [{"actor_id": None, "actor_type": "DeployKey", "bypass_mode": "always"}],
        "current_user_can_bypass": "never",
    }:
        _fail("release tag ruleset differs from the literal reviewed baseline")
    environments = _object(contract["required_environments"], "required environments")
    if set(environments) != set(ENVIRONMENT_PINS):
        _fail("environment inventory is not the exact four-environment set")
    for name, raw in environments.items():
        environment = _object(raw, f"environment {name}")
        _exact_keys(
            environment,
            {
                "id",
                "can_admins_bypass",
                "prevent_self_review",
                "reviewer_login",
                "reviewer_id",
                "protected_branches",
                "custom_branch_policies",
                "deployment_branch",
                "deployment_branch_policy_id",
            },
            f"environment {name}",
        )
        if (
            _boolean(environment["can_admins_bypass"], "environment admin bypass")
            or not _boolean(environment["prevent_self_review"], "prevent self review")
            or environment["reviewer_login"] != "MANA-awam"
            or environment["reviewer_id"] != 304223352
            or _boolean(environment["protected_branches"], "protected branches")
            or not _boolean(environment["custom_branch_policies"], "custom policy")
            or environment["deployment_branch"] != "main"
            or (
                environment["id"],
                environment["deployment_branch_policy_id"],
            )
            != ENVIRONMENT_PINS[name]
        ):
            _fail(f"environment {name} is not restricted to trusted main")
        _integer(environment["id"], f"environment {name} id")
        _integer(
            environment["deployment_branch_policy_id"],
            f"environment {name} branch-policy id",
        )
    _validate_publication_authority_contract(
        contract["required_publication_authority"], activated=resolved_external_shape
    )
    raw_git = _validate_raw_entries(contract["trusted_raw_git"], activated=resolved_external_shape)
    if resolved_external_shape and (
        raw_git["trusted_workflow_sha"] != pins["trusted_workflow_sha"]
        or raw_git["trusted_workflow_tree"] != pins["trusted_workflow_tree"]
    ):
        _fail("raw-Git root does not equal owner-authorized post-merge pins")

    signatures = _object(contract["local_signature_verification"], "local signature contract")
    _exact_keys(
        signatures,
        {
            "source",
            "public_key_repository_path",
            "public_key_mode",
            "public_key_blob_sha",
            "public_key_fingerprint",
            "source_object_type",
            "tag_object_type",
            "rest_author_login_is_signer_proof",
            "rest_verification_fields_are_fingerprint_proof",
        },
        "local signature contract",
    )
    if (
        signatures["source"] != "TRUSTED_RAW_GIT_OBJECTS_ONLY"
        or signatures["source_object_type"] != "commit"
        or signatures["tag_object_type"] != "tag"
        or _boolean(signatures["rest_author_login_is_signer_proof"], "REST author proof")
        or _boolean(
            signatures["rest_verification_fields_are_fingerprint_proof"],
            "REST fingerprint proof",
        )
    ):
        _fail("signature authority must be local raw Git, never REST identity fields")
    key_path = _safe_repo_path(
        signatures["public_key_repository_path"], "signing public-key repository path"
    )
    if key_path != SIGNING_KEY_PATH:
        _fail("signing public-key repository path differs from the reviewed trusted path")
    if signatures["public_key_mode"] != SIGNING_KEY_MODE:
        _fail("signing public-key mode must be the literal regular-file mode 100644")
    for field in ("public_key_blob_sha", "public_key_fingerprint"):
        value = _string(signatures[field], f"signature {field}")
        if resolved_external_shape and value == PLACEHOLDER:
            _fail(f"resolved signature {field} cannot be a placeholder")
        if not resolved_external_shape and value != PLACEHOLDER:
            _fail(f"inert signature {field} must remain an invalid placeholder")
    if resolved_external_shape:
        _sha(signatures["public_key_blob_sha"], "signing public-key blob")
        if FINGERPRINT_PATTERN.fullmatch(signatures["public_key_fingerprint"]) is None:
            _fail("signing public-key fingerprint is not canonical")

    runs = _array(contract["runs"], "run topology")
    if [run.get("phase") for run in runs if isinstance(run, dict)] != list(RUN_PHASES):
        _fail("run topology must be A -> B -> CD -> E -> F -> G -> H")
    for phase, raw in zip(RUN_PHASES, runs, strict=True):
        run = _object(raw, f"phase {phase} contract")
        _exact_keys(run, {"phase", "workflow_role", "event", "jobs"}, f"phase {phase}")
        if run["workflow_role"] != f"workflow-{phase}":
            _fail(f"phase {phase} workflow role is not exact")
        expected_event = "workflow_dispatch" if phase in {"A", "E"} else "workflow_run"
        if run["event"] != expected_event:
            _fail(f"phase {phase} event is not exact")
        jobs = _unique_strings(run["jobs"], f"phase {phase} jobs")
        if jobs != RUN_JOBS[phase]:
            _fail(f"phase {phase} job inventory is not literal")
    tag = _object(contract["tag_contract"], "tag contract")
    _exact_keys(
        tag,
        {
            "input_authority",
            "private_signing_key_in_actions",
            "raw_object_variable",
            "maximum_decoded_bytes",
            "required_object_type",
            "required_name",
            "required_target_type",
            "push_object_sha_not_target_commit",
            "phase0_observation_shape_only",
            "canonical_raw_tag_parser_implemented",
            "future_canonical_fields",
        },
        "tag contract",
    )
    if (
        tag["input_authority"] != "OWNER_AUTHORIZED_PUBLIC_RAW_TAG_OBJECT"
        or _boolean(tag["private_signing_key_in_actions"], "private key in Actions")
        or tag["raw_object_variable"] != "EVOGUARD_V451_SIGNED_TAG_OBJECT_B64"
        or _integer(tag["maximum_decoded_bytes"], "maximum decoded tag bytes")
        != TAG_MAX_DECODED_BYTES
        or tag["required_object_type"] != "tag"
        or tag["required_name"] != "v4.5.1"
        or tag["required_target_type"] != "commit"
        or not _boolean(tag["push_object_sha_not_target_commit"], "tag object push")
        or not _boolean(tag["phase0_observation_shape_only"], "tag shape-only state")
        or _boolean(tag["canonical_raw_tag_parser_implemented"], "tag parser state")
        or tag["future_canonical_fields"]
        != ["object", "type", "tag", "tagger", "message", "signature", "encoding"]
    ):
        _fail("annotated signed tag contract is not exact")
    release_contract = _object(contract["release_contract"], "release contract")
    if release_contract != {
        "immutable": True,
        "required_assets": ["evo-guard.pyz", "evo-guard.spdx.json", "SHA256SUMS"],
        "phase0_observation_shape_only": True,
        "digest_authority_implemented": False,
        "required_future_digest_authorities": [
            "RETAINED_F_BYTE_RECEIPT",
            "RETAINED_G_BYTE_RECEIPT",
            "DOWNLOADED_GITHUB_RELEASE_ASSET_BYTES",
        ],
    }:
        _fail("Phase-0 immutable-release shape/digest blocker is not exact")
    checkpoint = _object(contract["checkpoint_contract"], "checkpoint contract")
    if checkpoint != {
        "phase0_shape_only": True,
        "before_publication_completed_runs": ["A", "B", "CD", "E", "F", "G"],
        "after_publication_completed_runs": ["A", "B", "CD", "E", "F", "G", "H"],
        "required_future_temporal_binding": (
            "FRESH_OWNER_CONTROL_PLANE_OBSERVATION_BOUND_TO_EACH_RUN_ATTEMPT_AND_"
            "EACH_ENVIRONMENT_APPROVAL_BEFORE_SECRET_ACCESS"
        ),
        "temporal_binding_implemented": False,
    }:
        _fail("Phase-0 checkpoint/temporal-binding contract is not exact")
    retirement = _object(contract["retirement_contract"], "retirement contract")
    if retirement != {
        "phase0_requirement_only": True,
        "implemented": False,
        "required_actions": [
            "DISABLE_ONE_SHOT_AUTHORIZATION",
            "DELETE_RAW_TAG_OBJECT_VARIABLE",
            "DELETE_PUBLICATION_DEPLOY_KEY",
            "DELETE_PUBLICATION_ENVIRONMENT_SECRET",
        ],
        "required_surviving_state": [
            "IMMUTABLE_V4_5_1_RELEASE",
            "SIGNED_ANNOTATED_V4_5_1_TAG_OBJECT",
        ],
        "future_evidence": (
            "SEPARATE_OWNER_COLLECTED_SIGNED_RETIREMENT_RECEIPT_BOUND_TO_RELEASE_LEDGER"
        ),
    }:
        _fail("Phase-0 retirement requirement is not exact")
    _ = protection
    return contract


def validate_contract(contract: dict[str, Any]) -> dict[str, Any]:
    """Validate only the checked-in inert Phase-0 model."""

    return _validate_contract_model(contract, resolved_external_shape=False)


def _resolved_contract_shape(
    contract: dict[str, Any], external_pins: dict[str, Any]
) -> dict[str, Any]:
    """Resolve test-only observation shapes without creating an activation path."""

    validate_contract(contract)
    _exact_keys(
        external_pins,
        {
            "format",
            "trusted_workflow_sha",
            "trusted_workflow_tree",
            "one_shot_enable_value",
            "maintainer_signing_public_key_blob_sha",
            "maintainer_signing_public_key_fingerprint",
            "publication_deploy_key_id",
            "publication_deploy_key_public_key",
            "publication_deploy_key_fingerprint",
            "publication_deploy_key_created_at",
            "publication_secret_created_at",
            "publication_secret_updated_at",
        },
        "external Phase-0 pin observation shape",
    )
    if external_pins["format"] != "EVOGUARD_PHASE0_EXTERNAL_PIN_OBSERVATION_SHAPE_V1":
        _fail("external Phase-0 pin observation shape format is not exact")
    resolved = copy.deepcopy(contract)
    pins = resolved["activation"]["owner_authorized_post_merge_pins"]
    pins["trusted_workflow_sha"] = external_pins["trusted_workflow_sha"]
    pins["trusted_workflow_tree"] = external_pins["trusted_workflow_tree"]
    pins["one_shot_enable_value"] = external_pins["one_shot_enable_value"]
    raw_git = resolved["trusted_raw_git"]
    raw_git["trusted_workflow_sha"] = external_pins["trusted_workflow_sha"]
    raw_git["trusted_workflow_tree"] = external_pins["trusted_workflow_tree"]
    signatures = resolved["local_signature_verification"]
    signatures["public_key_blob_sha"] = external_pins["maintainer_signing_public_key_blob_sha"]
    signatures["public_key_fingerprint"] = external_pins[
        "maintainer_signing_public_key_fingerprint"
    ]
    publication = resolved["required_publication_authority"]
    deploy_key = publication["repository_deploy_keys"]["required_write_key"]
    deploy_key["id"] = external_pins["publication_deploy_key_id"]
    deploy_key["public_key"] = external_pins["publication_deploy_key_public_key"]
    deploy_key["fingerprint"] = external_pins["publication_deploy_key_fingerprint"]
    deploy_key["created_at"] = external_pins["publication_deploy_key_created_at"]
    secret = publication["environment_secret_metadata"]["required_secret"]
    secret["created_at"] = external_pins["publication_secret_created_at"]
    secret["updated_at"] = external_pins["publication_secret_updated_at"]
    return _validate_contract_model(resolved, resolved_external_shape=True)


def _validate_checks(checks_value: Any, contract: dict[str, Any], target_sha: str) -> None:
    required = {
        (item["context"], item["app_id"])
        for item in contract["required_branch_protection"]["required_checks"]
    }
    observed: dict[tuple[str, int], dict[str, Any]] = {}
    for index, raw in enumerate(_array(checks_value, "PR checks")):
        check = _object(raw, f"PR check {index}")
        _exact_keys(
            check,
            {"context", "app_id", "head_sha", "status", "conclusion"},
            f"PR check {index}",
        )
        key = (
            _string(check["context"], "check context"),
            _integer(check["app_id"], "check App ID"),
        )
        if key in observed:
            _fail("duplicate check/App-ID observation")
        if _sha(check["head_sha"], "check head") != target_sha:
            _fail("required check is bound to a moved head")
        if check["status"] != "completed" or check["conclusion"] != "success":
            _fail("required check is not a completed success")
        observed[key] = check
    if set(observed) != required:
        _fail("observed checks do not equal the literal 11-check/App-ID baseline")


def _validate_publication_authority_observation_shape(value: Any, contract: dict[str, Any]) -> None:
    """Validate normalized collector output shape, not collector authenticity."""

    observation = _object(value, "publication authority observation shape")
    _exact_keys(
        observation,
        {"format", "deploy_keys_collection", "environment_secret_collection"},
        "publication authority observation shape",
    )
    if observation["format"] != "EVOGUARD_PUBLICATION_AUTHORITY_OBSERVATION_SHAPE_V1":
        _fail("publication authority observation shape format is not exact")
    required = contract["required_publication_authority"]

    deploy_collection = _object(
        observation["deploy_keys_collection"], "deploy-key collection shape"
    )
    _exact_keys(
        deploy_collection,
        {
            "endpoint",
            "page_count",
            "pagination_complete",
            "raw_response_sha256",
            "items",
        },
        "deploy-key collection shape",
    )
    if (
        deploy_collection["endpoint"] != required["repository_deploy_keys"]["endpoint"]
        or _boolean(deploy_collection["pagination_complete"], "deploy-key pagination") is not True
    ):
        _fail("deploy-key collection shape is not complete for the literal endpoint")
    _integer(deploy_collection["page_count"], "deploy-key page count")
    _sha256(deploy_collection["raw_response_sha256"], "deploy-key raw response digest")
    deploy_keys: list[dict[str, Any]] = []
    ids: set[int] = set()
    key_texts: set[str] = set()
    for index, raw in enumerate(_array(deploy_collection["items"], "deploy keys")):
        key = _object(raw, f"deploy key {index}")
        _exact_keys(
            key,
            {"id", "title", "key", "created_at", "verified", "read_only", "enabled"},
            f"deploy key {index}",
        )
        key_id = _integer(key["id"], "deploy-key ID")
        key_text = _string(key["key"], "deploy-key public key")
        if key_id in ids or key_text in key_texts:
            _fail("deploy-key collection contains duplicate IDs or public keys")
        ids.add(key_id)
        key_texts.add(key_text)
        _string(key["title"], "deploy-key title")
        _timestamp(key["created_at"], "deploy-key creation")
        _boolean(key["verified"], "deploy-key verified")
        _boolean(key["read_only"], "deploy-key read-only")
        _boolean(key["enabled"], "deploy-key enabled")
        deploy_keys.append(key)
    write_keys = [item for item in deploy_keys if item["read_only"] is False]
    if len(write_keys) != 1:
        _fail("collector items must contain exactly one write-enabled deploy key")
    expected_key = required["repository_deploy_keys"]["required_write_key"]
    write_key = write_keys[0]
    if write_key != {
        "id": expected_key["id"],
        "title": expected_key["title"],
        "key": expected_key["public_key"],
        "created_at": expected_key["created_at"],
        "verified": True,
        "read_only": False,
        "enabled": True,
    }:
        _fail("sole write-enabled deploy key differs from the owner-pinned identity")
    if (
        _openssh_ed25519_fingerprint(write_key["key"], "write deploy-key public key")
        != expected_key["fingerprint"]
    ):
        _fail("write deploy-key public key does not match the owner-pinned fingerprint")

    secret_collection = _object(
        observation["environment_secret_collection"],
        "publication secret collection shape",
    )
    _exact_keys(
        secret_collection,
        {
            "endpoint",
            "environment",
            "environment_id",
            "page_count",
            "pagination_complete",
            "raw_response_sha256",
            "items",
        },
        "publication secret collection shape",
    )
    secret_contract = required["environment_secret_metadata"]
    if (
        secret_collection["endpoint"] != secret_contract["endpoint"]
        or secret_collection["environment"] != PUBLICATION_ENVIRONMENT
        or secret_collection["environment_id"] != PUBLICATION_ENVIRONMENT_ID
        or _boolean(secret_collection["pagination_complete"], "secret pagination") is not True
    ):
        _fail("publication secret collection shape is not the exact Environment endpoint")
    _integer(secret_collection["page_count"], "publication secret page count")
    _sha256(secret_collection["raw_response_sha256"], "publication secret raw response digest")
    secret_items = _array(secret_collection["items"], "publication Environment secrets")
    if secret_items != [secret_contract["required_secret"]]:
        _fail("publication Environment secret metadata/inventory is not exact")


def _validate_runs(
    value: Any,
    *,
    contract: dict[str, Any],
    trusted_workflow_sha: str,
    target_source_sha: str,
    checkpoint: str,
) -> None:
    runs = _array(value, "run observation shapes")
    expected: tuple[str, ...]
    if checkpoint == "before-publication":
        expected = RUN_PHASES[:-1]
    elif checkpoint == "after-publication-before-retirement":
        expected = RUN_PHASES
    else:
        _fail("observation checkpoint is not one of the two Phase-0 shapes")
    if len(runs) != len(expected):
        _fail("run observation inventory is not exact for the named checkpoint")
    prior: dict[str, Any] | None = None
    run_ids: set[int] = set()
    for phase, raw in zip(expected, runs, strict=True):
        run = _object(raw, f"phase {phase} run")
        _exact_keys(
            run,
            {
                "phase",
                "workflow_role",
                "workflow_sha",
                "target_source_sha",
                "run_id",
                "run_attempt",
                "event",
                "conclusion",
                "completed_jobs",
                "upstream_run_id",
                "upstream_run_attempt",
            },
            f"phase {phase} run",
        )
        if run["phase"] != phase or run["workflow_role"] != f"workflow-{phase}":
            _fail("run phase/workflow substitution")
        if _sha(run["workflow_sha"], "run workflow SHA") != trusted_workflow_sha:
            _fail("run did not execute the owner-pinned trusted workflow SHA")
        if _sha(run["target_source_sha"], "run target SHA") != target_source_sha:
            _fail("run target source substitution")
        run_id = _integer(run["run_id"], "run ID")
        if run_id in run_ids:
            _fail("A-through-H run IDs must be globally unique")
        run_ids.add(run_id)
        _integer(run["run_attempt"], "run attempt")
        expected_event = "workflow_dispatch" if phase in {"A", "E"} else "workflow_run"
        if run["event"] != expected_event or run["conclusion"] != "success":
            _fail("run event/conclusion is not exact")
        jobs = _unique_strings(run["completed_jobs"], "completed jobs")
        expected_jobs = tuple(contract["runs"][RUN_PHASES.index(phase)]["jobs"])
        if jobs != expected_jobs:
            _fail(f"phase {phase} completed-job inventory is not exact")
        if prior is None:
            if run["upstream_run_id"] is not None or run["upstream_run_attempt"] is not None:
                _fail("phase A must not claim an upstream attempt")
        elif run["upstream_run_id"] != prior["run_id"] or (
            run["upstream_run_attempt"] != prior["run_attempt"]
        ):
            _fail("run is bound to a stale upstream attempt")
        prior = run


def validate_observation_shape(
    control_plane: dict[str, Any],
    raw_git: dict[str, Any],
    local_verifier_observations: dict[str, Any],
    contract: dict[str, Any],
    external_pins: dict[str, Any],
    *,
    checkpoint: str,
) -> None:
    """Validate only a non-authoritative Phase-0 observation *shape*.

    This function performs no GitHub authentication, raw-object derivation,
    cryptographic signature verification, retained F/G byte verification, or
    temporal checkpoint binding. Its inputs are synthetic/normalized shapes
    used to freeze a future protocol. They are never live admission proof.
    """

    contract = _resolved_contract_shape(contract, external_pins)
    if checkpoint not in {"before-publication", "after-publication-before-retirement"}:
        _fail("observation checkpoint is not one of the two Phase-0 shapes")
    _exact_keys(
        control_plane,
        {
            "format",
            "repository",
            "activation_variables",
            "branches",
            "branch_protections",
            "pull_requests",
            "rulesets",
            "environments",
            "publication_authority",
            "runs",
            "tag",
            "release",
        },
        "control-plane observation shape",
    )
    if control_plane["format"] != "EVOGUARD_OWNER_CONTROL_PLANE_OBSERVATION_SHAPE_V1":
        _fail("control-plane observation shape format is not exact")
    if control_plane["repository"] != contract["repository"]:
        _fail("alternate repository/owner identity")
    pins = contract["activation"]["owner_authorized_post_merge_pins"]
    variables = _object(control_plane["activation_variables"], "activation variables")
    if variables != {
        pins["trusted_workflow_sha_variable"]: pins["trusted_workflow_sha"],
        pins["trusted_workflow_tree_variable"]: pins["trusted_workflow_tree"],
        pins["one_shot_enable_variable"]: pins["one_shot_enable_value"],
        **contract["activation"]["current_release_flags"],
    }:
        _fail("owner-authorized activation variables are not exact")
    branches = _object(control_plane["branches"], "branch observations")
    _exact_keys(branches, {"main", "maintenance/v4.5", "release/v4.5.1"}, "branches")
    workflow_branch = _object(branches["main"], "main branch")
    base_branch = _object(branches["maintenance/v4.5"], "maintenance branch")
    candidate_branch = _object(branches["release/v4.5.1"], "candidate branch")
    for branch in (workflow_branch, base_branch, candidate_branch):
        _exact_keys(branch, {"sha", "tree_sha"}, "branch identity")
        _sha(branch["sha"], "branch SHA")
        _sha(branch["tree_sha"], "branch tree")
    if workflow_branch != {
        "sha": pins["trusted_workflow_sha"],
        "tree_sha": pins["trusted_workflow_tree"],
    }:
        _fail("trusted main moved from the owner-authorized post-merge pin")
    if base_branch != {
        "sha": contract["maintenance_base"]["post_v4_5_0_commit"],
        "tree_sha": contract["maintenance_base"]["post_v4_5_0_tree"],
    }:
        _fail("maintenance base moved from post-v4.5.0 state")
    protections = _object(control_plane["branch_protections"], "branch protections")
    if set(protections) != {"main", "maintenance/v4.5"}:
        _fail("branch-protection observation inventory is not exact")
    for name in protections:
        _validate_protection(protections[name], f"observed {name} protection")
        if protections[name] != contract["required_branch_protection"]:
            _fail(f"observed {name} protection differs from the literal baseline")
    if control_plane["rulesets"] != contract["required_repository_rulesets"]:
        _fail("repository/tag ruleset observation differs from the literal baseline")
    if control_plane["environments"] != contract["required_environments"]:
        _fail("Environment observation differs from the literal trusted-main baseline")
    _validate_publication_authority_observation_shape(
        control_plane["publication_authority"], contract
    )

    pulls = _array(control_plane["pull_requests"], "release pull requests")
    if len(pulls) != 1:
        _fail("exactly one literal open maintenance pull request is required")
    pull = _object(pulls[0], "release pull request")
    _exact_keys(
        pull,
        {
            "number",
            "state",
            "base_ref",
            "base_sha",
            "head_ref",
            "head_repo_full_name",
            "head_repo_id",
            "head_sha",
            "reviews",
            "checks",
        },
        "release pull request",
    )
    _integer(pull["number"], "pull request number")
    refs = contract["refs"]
    if (
        pull["state"] != "open"
        or pull["base_ref"] != refs["maintenance_base_branch"]
        or pull["base_sha"] != base_branch["sha"]
        or pull["head_ref"] != refs["candidate_branch"]
        or pull["head_repo_full_name"] != contract["repository"]["full_name"]
        or pull["head_repo_id"] != contract["repository"]["id"]
        or pull["head_sha"] != candidate_branch["sha"]
    ):
        _fail("pull request base/head/repository is not the literal current identity")
    latest_review: dict[str, Any] | None = None
    for index, raw in enumerate(_array(pull["reviews"], "reviews")):
        review = _object(raw, f"review {index}")
        _exact_keys(review, {"id", "actor", "actor_id", "state", "commit_sha"}, f"review {index}")
        _integer(review["id"], "review ID")
        if (
            review["actor"] == "MANA-awam"
            and review["actor_id"] == 304223352
            and (latest_review is None or review["id"] > latest_review["id"])
        ):
            latest_review = review
    if (
        latest_review is None
        or latest_review["state"] != "APPROVED"
        or (latest_review["commit_sha"] != candidate_branch["sha"])
    ):
        _fail("required same-owner review is not an exact-head approval")
    _validate_checks(pull["checks"], contract, candidate_branch["sha"])

    _exact_keys(
        raw_git,
        {
            "format",
            "trusted_workflow_sha",
            "trusted_workflow_tree",
            "entries",
            "maintenance_base_sha",
            "maintenance_base_tree",
            "target_source_sha",
            "target_source_tree",
            "target_parents",
            "changes",
            "tag_object",
        },
        "raw-Git observation shape",
    )
    if raw_git["format"] != "EVOGUARD_RAW_GIT_OBSERVATION_SHAPE_V1":
        _fail("raw-Git observation shape format is not exact")
    if raw_git["trusted_workflow_sha"] != workflow_branch["sha"] or (
        raw_git["trusted_workflow_tree"] != workflow_branch["tree_sha"]
    ):
        _fail("raw-Git trusted root differs from owner-authorized main")
    if raw_git["entries"] != _expected_observed_raw_entries(contract):
        _fail("raw-Git-derived workflow/control/policy/pack/signing-key entries differ from pins")
    if raw_git["maintenance_base_sha"] != base_branch["sha"] or (
        raw_git["maintenance_base_tree"] != base_branch["tree_sha"]
    ):
        _fail("raw-Git maintenance base differs from control-plane base")
    if raw_git["target_source_sha"] != candidate_branch["sha"] or (
        raw_git["target_source_tree"] != candidate_branch["tree_sha"]
    ):
        _fail("raw-Git target differs from the exact PR head")
    parents = tuple(
        _sha(item, "target parent") for item in _array(raw_git["target_parents"], "parents")
    )
    if parents != (base_branch["sha"],):
        _fail("target must have one exact post-v4.5.0 parent")
    changes: set[str] = set()
    for index, raw in enumerate(_array(raw_git["changes"], "raw-Git changes")):
        change = _object(raw, f"raw-Git change {index}")
        _exact_keys(
            change,
            {"path", "old_mode", "new_mode", "old_blob", "new_blob", "patch_sha256"},
            f"raw-Git change {index}",
        )
        path = _string(change["path"], "changed path")
        if path in changes:
            _fail("raw-Git changed paths are duplicated")
        changes.add(path)
        if change["old_mode"] != "100644" or change["new_mode"] != "100644":
            _fail("maintenance change mode is not literal 100644")
        _sha(change["old_blob"], "old blob")
        _sha(change["new_blob"], "new blob")
        _sha256(change["patch_sha256"], "patch digest")
    required = set(contract["candidate_scope"]["required_changed_paths"])
    allowed = set(contract["candidate_scope"]["allowed_changed_paths"])
    if not required <= changes or not changes <= allowed:
        _fail("raw-Git candidate scope expanded or omitted required paths")

    _exact_keys(
        local_verifier_observations,
        {
            "format",
            "authority_status",
            "public_key",
            "source_commit",
            "tag",
            "publication_secret_binding",
        },
        "local verifier observation shape",
    )
    if (
        local_verifier_observations["format"] != "EVOGUARD_LOCAL_GIT_VERIFIER_OBSERVATION_SHAPE_V1"
        or local_verifier_observations["authority_status"] != "NON_AUTHORITATIVE_PHASE0_SHAPE_ONLY"
    ):
        _fail("local verifier observation is not explicitly shape-only")
    key = _object(local_verifier_observations["public_key"], "public-key shape")
    _exact_keys(key, {"path", "mode", "blob_sha", "fingerprint"}, "public-key shape")
    signature_contract = contract["local_signature_verification"]
    if key != {
        "path": signature_contract["public_key_repository_path"],
        "mode": signature_contract["public_key_mode"],
        "blob_sha": signature_contract["public_key_blob_sha"],
        "fingerprint": signature_contract["public_key_fingerprint"],
    }:
        _fail("local verifier shape does not name the externally pinned public key")
    source_observation = _object(
        local_verifier_observations["source_commit"], "source verifier observation shape"
    )
    _exact_keys(
        source_observation,
        {
            "object_type",
            "object_sha",
            "signer_fingerprint",
            "raw_object_sha256",
            "verifier_receipt_sha256",
        },
        "source verifier observation shape",
    )
    if {
        "object_type": source_observation["object_type"],
        "object_sha": source_observation["object_sha"],
        "signer_fingerprint": source_observation["signer_fingerprint"],
    } != {
        "object_type": "commit",
        "object_sha": candidate_branch["sha"],
        "signer_fingerprint": key["fingerprint"],
    }:
        _fail("source verifier observation shape is not bound to the expected object/key")
    _sha256(source_observation["raw_object_sha256"], "source raw-object digest shape")
    _sha256(source_observation["verifier_receipt_sha256"], "source verifier-receipt digest shape")

    _validate_runs(
        control_plane["runs"],
        contract=contract,
        trusted_workflow_sha=workflow_branch["sha"],
        target_source_sha=candidate_branch["sha"],
        checkpoint=checkpoint,
    )
    if checkpoint == "before-publication":
        if (
            control_plane["tag"] != {"state": "absent"}
            or (control_plane["release"] != {"state": "absent"})
            or raw_git["tag_object"] != {"state": "absent"}
            or (local_verifier_observations["tag"] != {"state": "absent"})
            or local_verifier_observations["publication_secret_binding"]
            != {"state": "not-observed-before-H"}
        ):
            _fail("before-publication shape requires A-through-G and absent H outputs")
        return
    tag_object = _object(raw_git["tag_object"], "raw tag object")
    _exact_keys(
        tag_object,
        {"state", "object_type", "object_sha", "name", "target_type", "target_sha", "size_bytes"},
        "raw tag object",
    )
    if (
        tag_object["state"] != "present"
        or tag_object["object_type"] != "tag"
        or tag_object["name"] != "v4.5.1"
        or tag_object["target_type"] != "commit"
        or tag_object["target_sha"] != candidate_branch["sha"]
        or _integer(tag_object["size_bytes"], "tag object size")
        > contract["tag_contract"]["maximum_decoded_bytes"]
    ):
        _fail("raw tag observation shape is oversized, retargeted, or structurally wrong")
    _sha(tag_object["object_sha"], "annotated tag object SHA")
    tag_observation = _object(local_verifier_observations["tag"], "tag verifier observation shape")
    _exact_keys(
        tag_observation,
        {
            "object_type",
            "object_sha",
            "signer_fingerprint",
            "raw_object_sha256",
            "verifier_receipt_sha256",
        },
        "tag verifier observation shape",
    )
    if {
        "object_type": tag_observation["object_type"],
        "object_sha": tag_observation["object_sha"],
        "signer_fingerprint": tag_observation["signer_fingerprint"],
    } != {
        "object_type": "tag",
        "object_sha": tag_object["object_sha"],
        "signer_fingerprint": key["fingerprint"],
    }:
        _fail("tag verifier observation shape is not bound to the expected object/key")
    _sha256(tag_observation["raw_object_sha256"], "tag raw-object digest shape")
    _sha256(tag_observation["verifier_receipt_sha256"], "tag verifier-receipt digest shape")
    if control_plane["tag"] != {
        "state": "present",
        "name": "v4.5.1",
        "ref_object_type": "tag",
        "ref_object_sha": tag_object["object_sha"],
        "target_sha": candidate_branch["sha"],
    }:
        _fail("GitHub tag-ref observation shape does not point to the named tag object")

    binding = _object(
        local_verifier_observations["publication_secret_binding"],
        "publication secret-binding observation shape",
    )
    _exact_keys(
        binding,
        {
            "state",
            "source",
            "workflow_sha",
            "run_id",
            "run_attempt",
            "environment",
            "environment_id",
            "secret_name",
            "secret_created_at",
            "secret_updated_at",
            "derived_public_key",
            "derived_fingerprint",
            "derivation_receipt_sha256",
        },
        "publication secret-binding observation shape",
    )
    h_run = _array(control_plane["runs"], "run observation shapes")[-1]
    deploy_key = contract["required_publication_authority"]["repository_deploy_keys"][
        "required_write_key"
    ]
    secret = contract["required_publication_authority"]["environment_secret_metadata"][
        "required_secret"
    ]
    if {
        "state": binding["state"],
        "source": binding["source"],
        "workflow_sha": binding["workflow_sha"],
        "run_id": binding["run_id"],
        "run_attempt": binding["run_attempt"],
        "environment": binding["environment"],
        "environment_id": binding["environment_id"],
        "secret_name": binding["secret_name"],
        "secret_created_at": binding["secret_created_at"],
        "secret_updated_at": binding["secret_updated_at"],
        "derived_public_key": binding["derived_public_key"],
        "derived_fingerprint": binding["derived_fingerprint"],
    } != {
        "state": "observed-before-tag-mutation",
        "source": "TRUSTED_MAIN_H_ENVIRONMENT_SECRET_PUBLIC_KEY_DERIVATION",
        "workflow_sha": workflow_branch["sha"],
        "run_id": h_run["run_id"],
        "run_attempt": h_run["run_attempt"],
        "environment": PUBLICATION_ENVIRONMENT,
        "environment_id": PUBLICATION_ENVIRONMENT_ID,
        "secret_name": PUBLICATION_SECRET_NAME,
        "secret_created_at": secret["created_at"],
        "secret_updated_at": secret["updated_at"],
        "derived_public_key": deploy_key["public_key"],
        "derived_fingerprint": deploy_key["fingerprint"],
    }:
        _fail("publication secret-binding shape is not bound to H/key/secret metadata")
    _sha256(binding["derivation_receipt_sha256"], "key-derivation receipt digest shape")
    release = _object(control_plane["release"], "release observation")
    _exact_keys(
        release,
        {"state", "tag", "target_sha", "immutable", "assets"},
        "release observation",
    )
    if (
        release["state"] != "published"
        or release["tag"] != "v4.5.1"
        or release["target_sha"] != candidate_branch["sha"]
        or _boolean(release["immutable"], "immutable release") is not True
    ):
        _fail("published release identity is not exact and immutable")
    assets = _array(release["assets"], "release assets")
    expected_names = tuple(contract["release_contract"]["required_assets"])
    if tuple(asset.get("name") for asset in assets if isinstance(asset, dict)) != expected_names:
        _fail("release asset inventory is not the exact ordered three-asset set")
    for index, raw in enumerate(assets):
        asset = _object(raw, f"release asset {index}")
        _exact_keys(asset, {"name", "sha256"}, f"release asset {index}")
        _sha256(asset["sha256"], "release asset digest shape")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check that the v4.5.1 Phase-0 contract remains inert."
    )
    parser.add_argument(
        "--check-inert",
        action="store_true",
        help="validate only the checked-in, non-operational Phase-0 model",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.check_inert:
        print("maintenance lane rejected: only --check-inert is implemented")
        return 1
    try:
        contract = load_json(CONTRACT_PATH)
        validate_contract(contract)
        if contract["activation"]["enabled"] is not False or not contract["blockers"]:
            _fail("checked-in Phase-0 contract is not inert")
    except MaintenanceControlError as exc:
        print(f"maintenance lane rejected: {exc}")
        return 1
    print("maintenance Phase-0 model valid and inert; no publication authority")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
