# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Regressions for the inert, non-authoritative v4.5.1 Phase-0 model."""

from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
from typing import Any

import pytest

from tools.ci import validate_v451_maintenance_control as validator

ROOT = Path(__file__).parents[1]
MAIN_SHA = "1" * 40
MAIN_TREE = "2" * 40
BASE_SHA = "2a8f012a8b6a5b62b9b0990207db8e0aed589795"
BASE_TREE = "d1ae967f286dd8c70d6e0ba19748773c9e1ecc7b"
TARGET_SHA = "3" * 40
TARGET_TREE = "4" * 40
MAINTAINER_KEY_BLOB = "5" * 40
MAINTAINER_FINGERPRINT = "A" * 40
DEPLOY_KEY_ID = 45101
DEPLOY_PUBLIC_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH"
)
DEPLOY_FINGERPRINT = "SHA256:gNSIRW+2Iyiuvsdp/bgjy38bvWHw6wQm3tuoXrl3WjQ"
READ_ONLY_PUBLIC_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"
)
DEPLOY_CREATED = "2030-01-01T00:00:00Z"
SECRET_CREATED = "2030-01-01T00:01:00Z"
SECRET_UPDATED = "2030-01-01T00:02:00Z"


def _contract() -> dict[str, Any]:
    return validator.load_json(validator.CONTRACT_PATH)


def _external_pins() -> dict[str, Any]:
    return {
        "format": "EVOGUARD_PHASE0_EXTERNAL_PIN_OBSERVATION_SHAPE_V1",
        "trusted_workflow_sha": MAIN_SHA,
        "trusted_workflow_tree": MAIN_TREE,
        "one_shot_enable_value": MAIN_SHA,
        "maintainer_signing_public_key_repository_path": ("security/v4.5.1-maintainer-signing.pub"),
        "maintainer_signing_public_key_blob_sha": MAINTAINER_KEY_BLOB,
        "maintainer_signing_public_key_fingerprint": MAINTAINER_FINGERPRINT,
        "publication_deploy_key_id": DEPLOY_KEY_ID,
        "publication_deploy_key_public_key": DEPLOY_PUBLIC_KEY,
        "publication_deploy_key_fingerprint": DEPLOY_FINGERPRINT,
        "publication_deploy_key_created_at": DEPLOY_CREATED,
        "publication_secret_created_at": SECRET_CREATED,
        "publication_secret_updated_at": SECRET_UPDATED,
    }


def _resolved(contract: dict[str, Any], pins: dict[str, Any]) -> dict[str, Any]:
    return validator._resolved_contract_shape(contract, pins)


def _runs(contract: dict[str, Any], checkpoint: str) -> list[dict[str, Any]]:
    contracts = contract["runs"][:-1] if checkpoint == "before-publication" else contract["runs"]
    result: list[dict[str, Any]] = []
    prior: dict[str, Any] | None = None
    for index, run_contract in enumerate(contracts):
        run = {
            "phase": run_contract["phase"],
            "workflow_role": run_contract["workflow_role"],
            "workflow_sha": MAIN_SHA,
            "target_source_sha": TARGET_SHA,
            "run_id": 1000 + index,
            "run_attempt": 1,
            "event": run_contract["event"],
            "conclusion": "success",
            "completed_jobs": copy.deepcopy(run_contract["jobs"]),
            "upstream_run_id": None if prior is None else prior["run_id"],
            "upstream_run_attempt": None if prior is None else prior["run_attempt"],
        }
        result.append(run)
        prior = run
    return result


def _publication_authority(contract: dict[str, Any]) -> dict[str, Any]:
    required = contract["required_publication_authority"]
    write_key = required["repository_deploy_keys"]["required_write_key"]
    secret = required["environment_secret_metadata"]["required_secret"]
    return {
        "format": "EVOGUARD_PUBLICATION_AUTHORITY_OBSERVATION_SHAPE_V1",
        "deploy_keys_collection": {
            "endpoint": required["repository_deploy_keys"]["endpoint"],
            "page_count": 1,
            "pagination_complete": True,
            "raw_response_sha256": "a" * 64,
            "items": [
                {
                    "id": 45100,
                    "title": "read-only consumer",
                    "key": READ_ONLY_PUBLIC_KEY,
                    "created_at": "2029-12-01T00:00:00Z",
                    "verified": True,
                    "read_only": True,
                    "enabled": True,
                },
                {
                    "id": write_key["id"],
                    "title": write_key["title"],
                    "key": write_key["public_key"],
                    "created_at": write_key["created_at"],
                    "verified": True,
                    "read_only": False,
                    "enabled": True,
                },
            ],
        },
        "environment_secret_collection": {
            "endpoint": required["environment_secret_metadata"]["endpoint"],
            "environment": "evoguard-release-publication",
            "environment_id": 18718846349,
            "page_count": 1,
            "pagination_complete": True,
            "raw_response_sha256": "b" * 64,
            "items": [copy.deepcopy(secret)],
        },
    }


def _control_plane(contract: dict[str, Any], checkpoint: str) -> dict[str, Any]:
    pins = contract["activation"]["owner_authorized_post_merge_pins"]
    checks = [
        {
            "context": item["context"],
            "app_id": item["app_id"],
            "head_sha": TARGET_SHA,
            "status": "completed",
            "conclusion": "success",
        }
        for item in contract["required_branch_protection"]["required_checks"]
    ]
    value = {
        "format": "EVOGUARD_OWNER_CONTROL_PLANE_OBSERVATION_SHAPE_V1",
        "repository": copy.deepcopy(contract["repository"]),
        "activation_variables": {
            pins["trusted_workflow_sha_variable"]: MAIN_SHA,
            pins["trusted_workflow_tree_variable"]: MAIN_TREE,
            pins["one_shot_enable_variable"]: MAIN_SHA,
            **contract["activation"]["current_release_flags"],
        },
        "branches": {
            "main": {"sha": MAIN_SHA, "tree_sha": MAIN_TREE},
            "maintenance/v4.5": {"sha": BASE_SHA, "tree_sha": BASE_TREE},
            "release/v4.5.1": {"sha": TARGET_SHA, "tree_sha": TARGET_TREE},
        },
        "branch_protections": {
            "main": copy.deepcopy(contract["required_branch_protection"]),
            "maintenance/v4.5": copy.deepcopy(contract["required_branch_protection"]),
        },
        "pull_requests": [
            {
                "number": 451,
                "state": "open",
                "base_ref": "maintenance/v4.5",
                "base_sha": BASE_SHA,
                "head_ref": "release/v4.5.1",
                "head_repo_full_name": "EvoRiseKsa/EvoOM-Guard-m",
                "head_repo_id": 1293651176,
                "head_sha": TARGET_SHA,
                "reviews": [
                    {
                        "id": 9001,
                        "actor": "MANA-awam",
                        "actor_id": 304223352,
                        "state": "APPROVED",
                        "commit_sha": TARGET_SHA,
                    }
                ],
                "checks": checks,
            }
        ],
        "rulesets": copy.deepcopy(contract["required_repository_rulesets"]),
        "environments": copy.deepcopy(contract["required_environments"]),
        "publication_authority": _publication_authority(contract),
        "runs": _runs(contract, checkpoint),
        "tag": {"state": "absent"},
        "release": {"state": "absent"},
    }
    if checkpoint == "after-publication-before-retirement":
        value["tag"] = {
            "state": "present",
            "name": "v4.5.1",
            "ref_object_type": "tag",
            "ref_object_sha": "e" * 40,
            "target_sha": TARGET_SHA,
        }
        value["release"] = {
            "state": "published",
            "tag": "v4.5.1",
            "target_sha": TARGET_SHA,
            "immutable": True,
            "assets": [
                {"name": "evo-guard.pyz", "sha256": "a" * 64},
                {"name": "evo-guard.spdx.json", "sha256": "b" * 64},
                {"name": "SHA256SUMS", "sha256": "c" * 64},
            ],
        }
    return value


def _raw_git(contract: dict[str, Any], checkpoint: str) -> dict[str, Any]:
    changes = [
        {
            "path": path,
            "old_mode": "100644",
            "new_mode": "100644",
            "old_blob": f"{index + 7:x}" * 40,
            "new_blob": f"{index + 8:x}" * 40,
            "patch_sha256": f"{index + 1:x}" * 64,
        }
        for index, path in enumerate(contract["candidate_scope"]["required_changed_paths"])
    ]
    value = {
        "format": "EVOGUARD_RAW_GIT_OBSERVATION_SHAPE_V1",
        "trusted_workflow_sha": MAIN_SHA,
        "trusted_workflow_tree": MAIN_TREE,
        "entries": copy.deepcopy(contract["trusted_raw_git"]["required_entries"]),
        "maintenance_base_sha": BASE_SHA,
        "maintenance_base_tree": BASE_TREE,
        "target_source_sha": TARGET_SHA,
        "target_source_tree": TARGET_TREE,
        "target_parents": [BASE_SHA],
        "changes": changes,
        "tag_object": {"state": "absent"},
    }
    if checkpoint == "after-publication-before-retirement":
        value["tag_object"] = {
            "state": "present",
            "object_type": "tag",
            "object_sha": "e" * 40,
            "name": "v4.5.1",
            "target_type": "commit",
            "target_sha": TARGET_SHA,
            "size_bytes": 4096,
        }
    return value


def _local_observations(contract: dict[str, Any], checkpoint: str) -> dict[str, Any]:
    signature = contract["local_signature_verification"]
    value = {
        "format": "EVOGUARD_LOCAL_GIT_VERIFIER_OBSERVATION_SHAPE_V1",
        "authority_status": "NON_AUTHORITATIVE_PHASE0_SHAPE_ONLY",
        "public_key": {
            "path": signature["public_key_repository_path"],
            "blob_sha": signature["public_key_blob_sha"],
            "fingerprint": signature["public_key_fingerprint"],
        },
        "source_commit": {
            "object_type": "commit",
            "object_sha": TARGET_SHA,
            "signer_fingerprint": signature["public_key_fingerprint"],
            "raw_object_sha256": "d" * 64,
            "verifier_receipt_sha256": "e" * 64,
        },
        "tag": {"state": "absent"},
        "publication_secret_binding": {"state": "not-observed-before-H"},
    }
    if checkpoint == "after-publication-before-retirement":
        write_key = contract["required_publication_authority"]["repository_deploy_keys"][
            "required_write_key"
        ]
        secret = contract["required_publication_authority"]["environment_secret_metadata"][
            "required_secret"
        ]
        h_run = _runs(contract, checkpoint)[-1]
        value["tag"] = {
            "object_type": "tag",
            "object_sha": "e" * 40,
            "signer_fingerprint": signature["public_key_fingerprint"],
            "raw_object_sha256": "f" * 64,
            "verifier_receipt_sha256": "1" * 64,
        }
        value["publication_secret_binding"] = {
            "state": "observed-before-tag-mutation",
            "source": "TRUSTED_MAIN_H_ENVIRONMENT_SECRET_PUBLIC_KEY_DERIVATION",
            "workflow_sha": MAIN_SHA,
            "run_id": h_run["run_id"],
            "run_attempt": h_run["run_attempt"],
            "environment": "evoguard-release-publication",
            "environment_id": 18718846349,
            "secret_name": "EVOGUARD_RELEASE_TAG_DEPLOY_KEY",
            "secret_created_at": secret["created_at"],
            "secret_updated_at": secret["updated_at"],
            "derived_public_key": write_key["public_key"],
            "derived_fingerprint": write_key["fingerprint"],
            "derivation_receipt_sha256": "2" * 64,
        }
    return value


def _validate_shape(
    *,
    checkpoint: str,
    contract: dict[str, Any] | None = None,
    pins: dict[str, Any] | None = None,
    control: dict[str, Any] | None = None,
    raw_git: dict[str, Any] | None = None,
    local: dict[str, Any] | None = None,
) -> None:
    contract = contract or _contract()
    pins = pins or _external_pins()
    resolved = _resolved(contract, pins)
    validator.validate_observation_shape(
        control or _control_plane(resolved, checkpoint),
        raw_git or _raw_git(resolved, checkpoint),
        local or _local_observations(resolved, checkpoint),
        contract,
        pins,
        checkpoint=checkpoint,
    )


def test_checked_in_phase0_is_permanently_inert_and_not_self_activating() -> None:
    contract = _contract()
    validator.validate_contract(contract)
    assert contract["assurance_state"] == "INERT_PRE_ACTIVATION_MODEL_NOT_LIVE_PROOF"
    assert contract["activation"]["enabled"] is False
    assert contract["blockers"]
    assert validator.main(["--check-inert"]) == 0
    assert validator.main([]) == 1

    mutated = copy.deepcopy(contract)
    mutated["activation"]["enabled"] = True
    mutated["assurance_state"] = "ACTIVE_ONE_SHOT_V4_5_1"
    with pytest.raises(validator.MaintenanceControlError, match="cannot activate itself"):
        validator.validate_contract(mutated)

    mutated = copy.deepcopy(contract)
    mutated["activation"]["owner_authorized_post_merge_pins"]["trusted_workflow_sha"] = MAIN_SHA
    with pytest.raises(validator.MaintenanceControlError, match="placeholders"):
        validator.validate_contract(mutated)


def test_external_pin_shape_does_not_mutate_or_activate_checked_in_contract() -> None:
    contract = _contract()
    original = copy.deepcopy(contract)
    resolved = _resolved(contract, _external_pins())
    assert contract == original
    assert resolved["activation"]["enabled"] is False
    assert resolved["blockers"]
    assert resolved["trusted_raw_git"]["trusted_workflow_sha"] == MAIN_SHA


def test_topology_has_exact_two_checkpoints_and_one_cd_run() -> None:
    contract = _contract()
    assert [item["phase"] for item in contract["runs"]] == ["A", "B", "CD", "E", "F", "G", "H"]
    assert contract["runs"][2]["jobs"] == ["preflight", "seal", "detached-verify"]
    _validate_shape(checkpoint="before-publication")
    _validate_shape(checkpoint="after-publication-before-retirement")

    resolved = _resolved(contract, _external_pins())
    control = _control_plane(resolved, "before-publication")
    control["runs"] = []
    with pytest.raises(validator.MaintenanceControlError, match="checkpoint"):
        _validate_shape(checkpoint="before-publication", contract=contract, control=control)


def test_phase0_pins_literal_baselines_and_checked_in_git_blobs() -> None:
    contract = _contract()
    protection = contract["required_branch_protection"]
    assert len(protection["required_checks"]) == 11
    assert len({(item["context"], item["app_id"]) for item in protection["required_checks"]}) == 11
    assert contract["required_repository_rulesets"][0]["bypass_actors"] == [
        {"actor_id": None, "actor_type": "DeployKey", "bypass_mode": "always"}
    ]
    assert {item["deployment_branch"] for item in contract["required_environments"].values()} == {
        "main"
    }
    entries = contract["trusted_raw_git"]["required_entries"]
    assert len([item for item in entries.values() if item["role"].startswith("workflow-")]) == 7
    for path, entry in entries.items():
        source_bytes = (ROOT / path).read_bytes()
        source_blob = hashlib.sha1(
            f"blob {len(source_bytes)}\0".encode() + source_bytes,
            usedforsecurity=False,
        ).hexdigest()
        assert entry["mode"] == "100644"
        assert entry["blob_sha"] == source_blob


def test_literal_contract_values_cannot_be_redefined() -> None:
    original = _contract()
    mutations = [
        lambda value: value["required_branch_protection"]["required_checks"][0].__setitem__(
            "app_id", 1
        ),
        lambda value: value["required_environments"]["evoguard-release-source-v2"].__setitem__(
            "id", 1
        ),
        lambda value: value["trusted_raw_git"]["required_entries"][
            ".github/workflows/evoguard-release-source-reverify.yml"
        ].__setitem__("blob_sha", "9" * 40),
        lambda value: value["runs"][0].__setitem__("jobs", ["metadata"]),
        lambda value: value["required_publication_authority"]["repository_deploy_keys"].__setitem__(
            "exact_write_enabled_count", 2
        ),
    ]
    for mutate in mutations:
        contract = copy.deepcopy(original)
        mutate(contract)
        with pytest.raises(validator.MaintenanceControlError):
            validator.validate_contract(contract)


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda value: value["repository"].__setitem__("full_name", "attacker/repo"),
            "alternate repository",
        ),
        (
            lambda value: value["branches"]["main"].__setitem__("sha", "9" * 40),
            "trusted main moved",
        ),
        (
            lambda value: value["branches"]["maintenance/v4.5"].__setitem__("sha", "9" * 40),
            "maintenance base moved",
        ),
        (
            lambda value: value["pull_requests"].append(copy.deepcopy(value["pull_requests"][0])),
            "exactly one",
        ),
        (
            lambda value: value["pull_requests"][0]["reviews"][0].__setitem__(
                "commit_sha", "9" * 40
            ),
            "exact-head approval",
        ),
        (
            lambda value: value["pull_requests"][0]["checks"][0].__setitem__("app_id", 1),
            "11-check/App-ID",
        ),
    ],
)
def test_control_plane_shape_substitutions_fail_closed(mutator: Any, message: str) -> None:
    contract = _contract()
    pins = _external_pins()
    resolved = _resolved(contract, pins)
    control = _control_plane(resolved, "before-publication")
    mutator(control)
    with pytest.raises(validator.MaintenanceControlError, match=message):
        _validate_shape(
            checkpoint="before-publication",
            contract=contract,
            pins=pins,
            control=control,
        )


def test_candidate_cannot_expand_the_closed_observation_shape() -> None:
    contract = _contract()
    pins = _external_pins()
    resolved = _resolved(contract, pins)
    control = _control_plane(resolved, "before-publication")
    control["sole_write_enabled"] = True
    with pytest.raises(validator.MaintenanceControlError, match="keys are not closed"):
        _validate_shape(
            checkpoint="before-publication", contract=contract, pins=pins, control=control
        )


def test_branch_ruleset_and_environment_weakening_fail_closed() -> None:
    contract = _contract()
    pins = _external_pins()
    resolved = _resolved(contract, pins)
    control = _control_plane(resolved, "before-publication")
    for protection in control["branch_protections"].values():
        protection["allow_force_pushes"] = True
    with pytest.raises(validator.MaintenanceControlError, match="must be false"):
        _validate_shape(
            checkpoint="before-publication", contract=contract, pins=pins, control=control
        )

    control = _control_plane(resolved, "before-publication")
    control["rulesets"][0]["bypass_actors"] = []
    with pytest.raises(validator.MaintenanceControlError, match="ruleset"):
        _validate_shape(
            checkpoint="before-publication", contract=contract, pins=pins, control=control
        )

    control = _control_plane(resolved, "before-publication")
    control["environments"]["evoguard-release-publication"]["deployment_branch"] = (
        "maintenance/v4.5"
    )
    with pytest.raises(validator.MaintenanceControlError, match="Environment"):
        _validate_shape(
            checkpoint="before-publication", contract=contract, pins=pins, control=control
        )


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda value: value["deploy_keys_collection"]["items"].append(
                copy.deepcopy(value["deploy_keys_collection"]["items"][1])
            ),
            "duplicate",
        ),
        (
            lambda value: value["deploy_keys_collection"]["items"][0].__setitem__(
                "read_only", False
            ),
            "exactly one",
        ),
        (
            lambda value: value["deploy_keys_collection"]["items"][1].__setitem__("id", 999),
            "owner-pinned",
        ),
        (
            lambda value: value["deploy_keys_collection"]["items"][1].__setitem__("title", "other"),
            "owner-pinned",
        ),
        (
            lambda value: value["deploy_keys_collection"]["items"][1].__setitem__(
                "verified", False
            ),
            "owner-pinned",
        ),
        (
            lambda value: value["deploy_keys_collection"].__setitem__("pagination_complete", False),
            "complete",
        ),
    ],
)
def test_deploy_key_collection_enforces_one_exact_write_authority(
    mutator: Any, message: str
) -> None:
    contract = _contract()
    pins = _external_pins()
    resolved = _resolved(contract, pins)
    control = _control_plane(resolved, "before-publication")
    mutator(control["publication_authority"])
    with pytest.raises(validator.MaintenanceControlError, match=message):
        _validate_shape(
            checkpoint="before-publication", contract=contract, pins=pins, control=control
        )


def test_deploy_key_fingerprint_is_derived_not_a_boolean_claim() -> None:
    pins = _external_pins()
    pins["publication_deploy_key_fingerprint"] = "SHA256:" + ("A" * 43)
    with pytest.raises(validator.MaintenanceControlError, match="derived"):
        _resolved(_contract(), pins)


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda value: value["environment_secret_collection"].__setitem__(
                "environment", "other"
            ),
            "Environment endpoint",
        ),
        (
            lambda value: value["environment_secret_collection"]["items"][0].__setitem__(
                "name", "OTHER"
            ),
            "metadata/inventory",
        ),
        (
            lambda value: value["environment_secret_collection"]["items"].append(
                copy.deepcopy(value["environment_secret_collection"]["items"][0])
            ),
            "metadata/inventory",
        ),
        (
            lambda value: value["environment_secret_collection"].__setitem__(
                "pagination_complete", False
            ),
            "Environment endpoint",
        ),
    ],
)
def test_publication_secret_metadata_is_exact_collector_shape(mutator: Any, message: str) -> None:
    contract = _contract()
    pins = _external_pins()
    resolved = _resolved(contract, pins)
    control = _control_plane(resolved, "before-publication")
    mutator(control["publication_authority"])
    with pytest.raises(validator.MaintenanceControlError, match=message):
        _validate_shape(
            checkpoint="before-publication", contract=contract, pins=pins, control=control
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("derived_fingerprint", "SHA256:" + ("B" * 43)),
        ("derived_public_key", READ_ONLY_PUBLIC_KEY),
        ("run_id", 9999),
        ("environment", "other"),
        ("secret_created_at", "2031-01-01T00:00:00Z"),
    ],
)
def test_private_secret_to_public_deploy_key_binding_shape_is_exact(field: str, value: Any) -> None:
    contract = _contract()
    pins = _external_pins()
    resolved = _resolved(contract, pins)
    local = _local_observations(resolved, "after-publication-before-retirement")
    local["publication_secret_binding"][field] = value
    with pytest.raises(validator.MaintenanceControlError, match="secret-binding"):
        _validate_shape(
            checkpoint="after-publication-before-retirement",
            contract=contract,
            pins=pins,
            local=local,
        )


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda value: value["entries"][
                ".github/workflows/evoguard-release-source-reverify.yml"
            ].__setitem__("blob_sha", "9" * 40),
            "workflow/control/policy/pack",
        ),
        (lambda value: value.__setitem__("target_parents", [BASE_SHA, "9" * 40]), "one exact"),
        (lambda value: value["changes"][0].__setitem__("old_mode", "100755"), "mode"),
        (
            lambda value: value["changes"].append(
                {
                    "path": ".github/workflows/release.yml",
                    "old_mode": "100644",
                    "new_mode": "100644",
                    "old_blob": "8" * 40,
                    "new_blob": "9" * 40,
                    "patch_sha256": "f" * 64,
                }
            ),
            "scope expanded",
        ),
    ],
)
def test_raw_git_observation_shape_substitutions_fail_closed(mutator: Any, message: str) -> None:
    contract = _contract()
    pins = _external_pins()
    resolved = _resolved(contract, pins)
    raw_git = _raw_git(resolved, "before-publication")
    mutator(raw_git)
    with pytest.raises(validator.MaintenanceControlError, match=message):
        _validate_shape(
            checkpoint="before-publication", contract=contract, pins=pins, raw_git=raw_git
        )


def test_local_verifier_input_is_explicitly_shape_only_not_crypto_proof() -> None:
    contract = _contract()
    pins = _external_pins()
    resolved = _resolved(contract, pins)
    local = _local_observations(resolved, "before-publication")
    local["authority_status"] = "VERIFIED"
    with pytest.raises(validator.MaintenanceControlError, match="shape-only"):
        _validate_shape(checkpoint="before-publication", contract=contract, pins=pins, local=local)

    local = _local_observations(resolved, "before-publication")
    local["source_commit"]["verified"] = True
    with pytest.raises(validator.MaintenanceControlError, match="keys are not closed"):
        _validate_shape(checkpoint="before-publication", contract=contract, pins=pins, local=local)


def test_run_chain_rejects_stale_duplicate_and_separate_d_run_shapes() -> None:
    contract = _contract()
    pins = _external_pins()
    resolved = _resolved(contract, pins)
    control = _control_plane(resolved, "after-publication-before-retirement")
    control["runs"][4]["upstream_run_attempt"] = 2
    with pytest.raises(validator.MaintenanceControlError, match="stale upstream"):
        _validate_shape(
            checkpoint="after-publication-before-retirement",
            contract=contract,
            pins=pins,
            control=control,
        )

    control = _control_plane(resolved, "after-publication-before-retirement")
    control["runs"][4]["run_id"] = control["runs"][3]["run_id"]
    control["runs"][5]["upstream_run_id"] = control["runs"][4]["run_id"]
    with pytest.raises(validator.MaintenanceControlError, match="globally unique"):
        _validate_shape(
            checkpoint="after-publication-before-retirement",
            contract=contract,
            pins=pins,
            control=control,
        )

    control = _control_plane(resolved, "after-publication-before-retirement")
    control["runs"].insert(3, copy.deepcopy(control["runs"][2]))
    control["runs"][3]["phase"] = "D"
    with pytest.raises(validator.MaintenanceControlError, match="checkpoint"):
        _validate_shape(
            checkpoint="after-publication-before-retirement",
            contract=contract,
            pins=pins,
            control=control,
        )


@pytest.mark.parametrize(
    ("target", "field", "value", "message"),
    [
        ("raw", "object_type", "commit", "raw tag observation shape"),
        ("raw", "name", "v4.5.2", "raw tag observation shape"),
        ("raw", "target_sha", "9" * 40, "raw tag observation shape"),
        ("raw", "size_bytes", 131073, "raw tag observation shape"),
        ("local", "signer_fingerprint", "B" * 40, "tag verifier observation shape"),
    ],
)
def test_tag_observation_shape_mutations_fail_without_crypto_claim(
    target: str, field: str, value: Any, message: str
) -> None:
    contract = _contract()
    pins = _external_pins()
    resolved = _resolved(contract, pins)
    raw_git = _raw_git(resolved, "after-publication-before-retirement")
    local = _local_observations(resolved, "after-publication-before-retirement")
    (raw_git["tag_object"] if target == "raw" else local["tag"])[field] = value
    with pytest.raises(validator.MaintenanceControlError, match=message):
        _validate_shape(
            checkpoint="after-publication-before-retirement",
            contract=contract,
            pins=pins,
            raw_git=raw_git,
            local=local,
        )


def test_tag_and_release_byte_authority_remain_explicit_blockers() -> None:
    contract = _contract()
    assert contract["tag_contract"]["phase0_observation_shape_only"] is True
    assert contract["tag_contract"]["canonical_raw_tag_parser_implemented"] is False
    assert contract["release_contract"]["phase0_observation_shape_only"] is True
    assert contract["release_contract"]["digest_authority_implemented"] is False
    assert any("retained F/G byte receipts" in item for item in contract["blockers"])
    assert any("canonical raw annotated-tag parser" in item for item in contract["blockers"])


def test_release_observation_shape_rejects_mutability_inventory_and_bad_digest() -> None:
    contract = _contract()
    pins = _external_pins()
    resolved = _resolved(contract, pins)
    control = _control_plane(resolved, "after-publication-before-retirement")
    control["release"]["immutable"] = False
    with pytest.raises(validator.MaintenanceControlError, match="immutable"):
        _validate_shape(
            checkpoint="after-publication-before-retirement",
            contract=contract,
            pins=pins,
            control=control,
        )

    control = _control_plane(resolved, "after-publication-before-retirement")
    control["release"]["assets"].append({"name": "extra", "sha256": "f" * 64})
    with pytest.raises(validator.MaintenanceControlError, match="inventory"):
        _validate_shape(
            checkpoint="after-publication-before-retirement",
            contract=contract,
            pins=pins,
            control=control,
        )

    control = _control_plane(resolved, "after-publication-before-retirement")
    control["release"]["assets"][0]["sha256"] = "bad"
    with pytest.raises(validator.MaintenanceControlError, match="digest shape"):
        _validate_shape(
            checkpoint="after-publication-before-retirement",
            contract=contract,
            pins=pins,
            control=control,
        )


def test_retirement_and_temporal_binding_are_requirements_not_claimed_results() -> None:
    contract = _contract()
    checkpoint = contract["checkpoint_contract"]
    retirement = contract["retirement_contract"]
    assert checkpoint["temporal_binding_implemented"] is False
    assert retirement["implemented"] is False
    assert retirement["required_actions"] == [
        "DISABLE_ONE_SHOT_AUTHORIZATION",
        "DELETE_RAW_TAG_OBJECT_VARIABLE",
        "DELETE_PUBLICATION_DEPLOY_KEY",
        "DELETE_PUBLICATION_ENVIRONMENT_SECRET",
    ]
    assert any("time-bound" in item for item in contract["blockers"])
    assert any("retirement" in item for item in contract["blockers"])


def test_exact_before_and_after_observation_shapes_pass_without_authority_claim() -> None:
    _validate_shape(checkpoint="before-publication")
    _validate_shape(checkpoint="after-publication-before-retirement")


def test_duplicate_nonfinite_and_hardlinked_json_are_rejected(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"format":"a","format":"b"}\n', encoding="utf-8")
    with pytest.raises(validator.MaintenanceControlError, match="duplicate JSON key"):
        validator.load_json(duplicate)

    nonfinite = tmp_path / "nonfinite.json"
    nonfinite.write_text('{"value":NaN}\n', encoding="utf-8")
    with pytest.raises(validator.MaintenanceControlError, match="non-finite"):
        validator.load_json(nonfinite)

    source = tmp_path / "source.json"
    linked = tmp_path / "linked.json"
    source.write_text('{"format":"bounded"}\n', encoding="utf-8")
    os.link(source, linked)
    with pytest.raises(validator.MaintenanceControlError, match="regular non-link"):
        validator.load_json(source)


def test_contract_and_claims_are_code_owned() -> None:
    codeowners = (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8")
    assert "/security/ @MANA-awam @EvoRiseKsa" in codeowners
    assert "/tools/ci/ @MANA-awam @EvoRiseKsa" in codeowners
    assert "/docs/V4.5.1_MAINTENANCE_LANE.md @MANA-awam @EvoRiseKsa" in codeowners
