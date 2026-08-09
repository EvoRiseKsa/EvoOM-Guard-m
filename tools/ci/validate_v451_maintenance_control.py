#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Validate the inert Phase-0 model for the one-time v4.5.1 lane.

The checked-in contract is intentionally not an operational publication gate.
Live validation requires three independently obtained inputs: owner-authenticated
GitHub control-plane observations, raw-Git derivation, and local signature
verification with a pinned public key.  Candidate JSON cannot supply any of
those authorities.  The CLI checks only that the source contract remains inert.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, NoReturn

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "security" / "v4.5.1-maintenance-lane.json"
MAX_CONTROL_BYTES = 2 * 1024 * 1024
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
FINGERPRINT_PATTERN = re.compile(r"^(?:[0-9A-F]{40}|[0-9A-F]{64}|SHA256:[A-Za-z0-9+/]{43}=?)$")
PLACEHOLDER = "POST_MERGE_REQUIRED"
RUN_PHASES = ("A", "B", "CD", "E", "F", "G", "H")
WORKFLOW_ROLES = tuple(f"workflow-{phase}" for phase in RUN_PHASES)
REQUIRED_CHECKS = (
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
RUN_JOBS = {
    "A": ("metadata", "reverify"),
    "B": ("preflight", "receipt"),
    "CD": ("preflight", "seal", "detached-verify"),
    "E": ("preflight", "build", "attest"),
    "F": ("preflight", "verify-attestations", "seal"),
    "G": ("detached-verify",),
    "H": ("preflight", "draft", "publish"),
}
RAW_ENTRY_PINS = {
    ".github/workflows/evoguard-release-source-reverify.yml": (
        "workflow-A",
        "ce8aa1eeccb7e2ed06b93bfdcee34be62a1cb04e",
    ),
    ".github/workflows/evoguard-produce-release-source-receipt.yml": (
        "workflow-B",
        "ae6c2ecda3e7b29223db69b33b9135949e0ad567",
    ),
    ".github/workflows/evoguard-admit-release-source.yml": (
        "workflow-CD",
        "e92f8ae8cd4281520b346a021d6f9d78d43b6e2d",
    ),
    ".github/workflows/evoguard-build-release-artifact.yml": (
        "workflow-E",
        "ffdbc343f7331551a6f69361c8091a517d7dff7e",
    ),
    ".github/workflows/evoguard-admit-release-artifact.yml": (
        "workflow-F",
        "2845d56f3e0f184246d15b27af1d63937e39dc2a",
    ),
    ".github/workflows/evoguard-verify-release-artifact.yml": (
        "workflow-G",
        "3fd1aa0f274900c5aa877d473f6fdb6f87e8bc4c",
    ),
    ".github/workflows/evoguard-publish-admitted-release.yml": (
        "workflow-H",
        "8d0e695cfda1023b0d3729e3a2e558152bb4564e",
    ),
    ".github/CODEOWNERS": ("control", "db526d147dc07ce36518af4a20aabdf2a16dfe56"),
    ".evoguard.json": ("policy", "7988a6a7d6f1df0ebd14028eba29f2257b2b1d2c"),
    "security/release-pipeline-bootstrap.json": (
        "control",
        "97d5283661874dc68b9535b37b7a74e47bb9421b",
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
ENVIRONMENT_PINS = {
    "evoguard-release-source-v2": (18718844374, 55562429),
    "evoguard-release-artifact-v1": (18718845035, 55562431),
    "evoguard-release-draft": (18718845676, 55562435),
    "evoguard-release-publication": (18718846349, 55562438),
}


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
    value = _string(value, label)
    if allow_placeholder and value == PLACEHOLDER:
        return value
    if SHA_PATTERN.fullmatch(value) is None:
        _fail(f"{label} must be one lowercase 40-hex Git object ID")
    return value


def _sha256(value: Any, label: str) -> str:
    value = _string(value, label)
    if SHA256_PATTERN.fullmatch(value) is None:
        _fail(f"{label} must be one lowercase SHA-256 digest")
    return value


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
        if path.startswith("/") or "\\" in path or ".." in path.split("/"):
            _fail(f"raw-Git path is not a safe literal repository path: {path!r}")
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


def validate_contract(
    contract: dict[str, Any], *, require_activated: bool = False
) -> dict[str, Any]:
    """Validate the source-owned Phase-0 model and its inert/active state."""

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
            "trusted_raw_git",
            "local_signature_verification",
            "runs",
            "tag_contract",
            "release_contract",
            "blockers",
        },
        "maintenance contract",
    )
    if contract["format"] != "EVOGUARD_MAINTENANCE_LANE_PHASE0_V2":
        _fail("maintenance contract format is not exact")
    blockers = _unique_strings(contract["blockers"], "contract blockers")
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
    expected_state = (
        "ACTIVE_ONE_SHOT_V4_5_1" if enabled else "INERT_PRE_ACTIVATION_MODEL_NOT_LIVE_PROOF"
    )
    if contract["assurance_state"] != expected_state:
        _fail("assurance state does not match activation")
    if require_activated and (not enabled or blockers):
        _fail("maintenance lane is intentionally inert while blockers remain")
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
        _sha(pins[field], field, allow_placeholder=not enabled)
    if enabled and pins["one_shot_enable_value"] != pins["trusted_workflow_sha"]:
        _fail("one-shot enable value must bind the exact trusted workflow SHA")
    if not enabled and pins["one_shot_enable_value"] != PLACEHOLDER:
        _fail("inert one-shot enable value must remain an invalid placeholder")

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
    raw_git = _validate_raw_entries(contract["trusted_raw_git"], activated=enabled)
    if enabled and (
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
    for field in ("public_key_repository_path", "public_key_blob_sha", "public_key_fingerprint"):
        value = _string(signatures[field], f"signature {field}")
        if enabled and value == PLACEHOLDER:
            _fail(f"active signature {field} cannot be a placeholder")
    if enabled:
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
        },
        "tag contract",
    )
    if (
        tag["input_authority"] != "OWNER_AUTHORIZED_PUBLIC_RAW_TAG_OBJECT"
        or _boolean(tag["private_signing_key_in_actions"], "private key in Actions")
        or tag["raw_object_variable"] != "EVOGUARD_V451_SIGNED_TAG_OBJECT_B64"
        or tag["maximum_decoded_bytes"] != 131072
        or tag["required_object_type"] != "tag"
        or tag["required_name"] != "v4.5.1"
        or tag["required_target_type"] != "commit"
        or not _boolean(tag["push_object_sha_not_target_commit"], "tag object push")
    ):
        _fail("annotated signed tag contract is not exact")
    release_contract = _object(contract["release_contract"], "release contract")
    if release_contract != {
        "immutable": True,
        "required_assets": ["evo-guard.pyz", "evo-guard.spdx.json", "SHA256SUMS"],
        "digest_authority": "EXACT_RETAINED_F_G_ADMISSION_BYTES",
    }:
        _fail("immutable release asset/digest contract is not exact")
    _ = protection
    return contract


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


def _validate_runs(
    value: Any,
    *,
    contract: dict[str, Any],
    trusted_workflow_sha: str,
    target_source_sha: str,
    complete: bool,
) -> None:
    runs = _array(value, "run observations")
    if not runs and not complete:
        return
    expected = RUN_PHASES if complete else RUN_PHASES[: len(runs)]
    if len(runs) != len(expected):
        _fail("observed runs are not an exact seven-run prefix")
    prior: dict[str, Any] | None = None
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
        _integer(run["run_id"], "run ID")
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


def validate_trusted_observations(
    control_plane: dict[str, Any],
    raw_git: dict[str, Any],
    local_signatures: dict[str, Any],
    contract: dict[str, Any],
    *,
    stage: str = "pre-admission",
) -> None:
    """Validate three trusted inputs; none may originate in candidate JSON.

    ``control_plane`` must come from an owner-authenticated, fully paginated,
    bounded GitHub API collector. ``raw_git`` must be derived from literal Git
    objects under the owner-pinned workflow root. ``local_signatures`` must be
    produced by local commit/tag verification using the pinned public key.
    """

    validate_contract(contract, require_activated=True)
    if stage not in {"pre-admission", "post-publication"}:
        _fail("stage must be pre-admission or post-publication")
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
            "runs",
            "tag",
            "release",
        },
        "trusted control-plane observation",
    )
    if control_plane["format"] != "EVOGUARD_OWNER_CONTROL_PLANE_V1":
        _fail("control-plane observation format is not exact")
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
        "trusted raw-Git observation",
    )
    if raw_git["format"] != "EVOGUARD_TRUSTED_RAW_GIT_V1":
        _fail("trusted raw-Git observation format is not exact")
    if raw_git["trusted_workflow_sha"] != workflow_branch["sha"] or (
        raw_git["trusted_workflow_tree"] != workflow_branch["tree_sha"]
    ):
        _fail("raw-Git trusted root differs from owner-authorized main")
    if raw_git["entries"] != contract["trusted_raw_git"]["required_entries"]:
        _fail("raw-Git-derived workflow/control/policy/pack entries differ from pins")
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
        local_signatures,
        {"format", "public_key", "source_commit", "tag"},
        "local signature proof",
    )
    if local_signatures["format"] != "EVOGUARD_LOCAL_GIT_SIGNATURE_PROOF_V1":
        _fail("local signature proof format is not exact")
    key = _object(local_signatures["public_key"], "verified public key")
    _exact_keys(key, {"path", "blob_sha", "fingerprint"}, "verified public key")
    signature_contract = contract["local_signature_verification"]
    if key != {
        "path": signature_contract["public_key_repository_path"],
        "blob_sha": signature_contract["public_key_blob_sha"],
        "fingerprint": signature_contract["public_key_fingerprint"],
    }:
        _fail("local verifier did not use the pinned public key")
    source_proof = _object(local_signatures["source_commit"], "source signature proof")
    if source_proof != {
        "object_type": "commit",
        "object_sha": candidate_branch["sha"],
        "verified": True,
        "fingerprint": key["fingerprint"],
    }:
        _fail("source commit lacks a local raw-Git signature by the pinned key")

    _validate_runs(
        control_plane["runs"],
        contract=contract,
        trusted_workflow_sha=workflow_branch["sha"],
        target_source_sha=candidate_branch["sha"],
        complete=stage == "post-publication",
    )
    if stage == "pre-admission":
        if (
            control_plane["tag"] != {"state": "absent"}
            or (control_plane["release"] != {"state": "absent"})
            or raw_git["tag_object"] != {"state": "absent"}
            or (local_signatures["tag"] != {"state": "absent"})
        ):
            _fail("pre-admission requires absent tag/release observations")
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
        or _integer(tag_object["size_bytes"], "tag object size") > 131072
    ):
        _fail("raw annotated tag object is noncanonical, oversized, or retargeted")
    _sha(tag_object["object_sha"], "annotated tag object SHA")
    tag_proof = _object(local_signatures["tag"], "tag signature proof")
    if tag_proof != {
        "object_type": "tag",
        "object_sha": tag_object["object_sha"],
        "verified": True,
        "fingerprint": key["fingerprint"],
    }:
        _fail("annotated tag lacks a local signature by the pinned key")
    if control_plane["tag"] != {
        "state": "present",
        "name": "v4.5.1",
        "ref_object_type": "tag",
        "ref_object_sha": tag_object["object_sha"],
        "target_sha": candidate_branch["sha"],
    }:
        _fail("GitHub tag ref does not point to the verified annotated tag object")
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
        _exact_keys(asset, {"name", "sha256", "admitted_sha256"}, f"release asset {index}")
        digest = _sha256(asset["sha256"], "release asset digest")
        if _sha256(asset["admitted_sha256"], "admitted asset digest") != digest:
            _fail("release asset digest differs from retained admission")


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
        validate_contract(contract, require_activated=False)
        if contract["activation"]["enabled"] is not False or not contract["blockers"]:
            _fail("checked-in Phase-0 contract is not inert")
    except MaintenanceControlError as exc:
        print(f"maintenance lane rejected: {exc}")
        return 1
    print("maintenance Phase-0 model valid and inert; no publication authority")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
