# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Regression tests for the inert v4.5.1 Phase-0 maintenance model."""

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
KEY_BLOB = "5" * 40
KEY_FINGERPRINT = "A" * 40
VALIDATOR_BLOB = "6" * 40


def _active_contract() -> dict[str, Any]:
    contract = validator.load_json(validator.CONTRACT_PATH)
    contract["assurance_state"] = "ACTIVE_ONE_SHOT_V4_5_1"
    contract["activation"]["enabled"] = True
    pins = contract["activation"]["owner_authorized_post_merge_pins"]
    pins["trusted_workflow_sha"] = MAIN_SHA
    pins["trusted_workflow_tree"] = MAIN_TREE
    pins["one_shot_enable_value"] = MAIN_SHA
    contract["trusted_raw_git"]["trusted_workflow_sha"] = MAIN_SHA
    contract["trusted_raw_git"]["trusted_workflow_tree"] = MAIN_TREE
    contract["trusted_raw_git"]["required_entries"][
        "tools/ci/validate_v451_maintenance_control.py"
    ]["blob_sha"] = VALIDATOR_BLOB
    signatures = contract["local_signature_verification"]
    signatures["public_key_repository_path"] = "security/v4.5.1-maintainer-signing.pub"
    signatures["public_key_blob_sha"] = KEY_BLOB
    signatures["public_key_fingerprint"] = KEY_FINGERPRINT
    contract["blockers"] = []
    validator.validate_contract(contract, require_activated=True)
    return contract


def _control_plane(contract: dict[str, Any]) -> dict[str, Any]:
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
    return {
        "format": "EVOGUARD_OWNER_CONTROL_PLANE_V1",
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
        "runs": [],
        "tag": {"state": "absent"},
        "release": {"state": "absent"},
    }


def _raw_git(contract: dict[str, Any]) -> dict[str, Any]:
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
    return {
        "format": "EVOGUARD_TRUSTED_RAW_GIT_V1",
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


def _local_signatures(contract: dict[str, Any]) -> dict[str, Any]:
    signature_contract = contract["local_signature_verification"]
    return {
        "format": "EVOGUARD_LOCAL_GIT_SIGNATURE_PROOF_V1",
        "public_key": {
            "path": signature_contract["public_key_repository_path"],
            "blob_sha": KEY_BLOB,
            "fingerprint": KEY_FINGERPRINT,
        },
        "source_commit": {
            "object_type": "commit",
            "object_sha": TARGET_SHA,
            "verified": True,
            "fingerprint": KEY_FINGERPRINT,
        },
        "tag": {"state": "absent"},
    }


def _runs(contract: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    prior: dict[str, Any] | None = None
    for index, run_contract in enumerate(contract["runs"]):
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


def _published_inputs(
    contract: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    control = _control_plane(contract)
    raw_git = _raw_git(contract)
    signatures = _local_signatures(contract)
    control["runs"] = _runs(contract)
    tag_sha = "e" * 40
    raw_git["tag_object"] = {
        "state": "present",
        "object_type": "tag",
        "object_sha": tag_sha,
        "name": "v4.5.1",
        "target_type": "commit",
        "target_sha": TARGET_SHA,
        "size_bytes": 4096,
    }
    signatures["tag"] = {
        "object_type": "tag",
        "object_sha": tag_sha,
        "verified": True,
        "fingerprint": KEY_FINGERPRINT,
    }
    control["tag"] = {
        "state": "present",
        "name": "v4.5.1",
        "ref_object_type": "tag",
        "ref_object_sha": tag_sha,
        "target_sha": TARGET_SHA,
    }
    control["release"] = {
        "state": "published",
        "tag": "v4.5.1",
        "target_sha": TARGET_SHA,
        "immutable": True,
        "assets": [
            {"name": "evo-guard.pyz", "sha256": "a" * 64, "admitted_sha256": "a" * 64},
            {
                "name": "evo-guard.spdx.json",
                "sha256": "b" * 64,
                "admitted_sha256": "b" * 64,
            },
            {"name": "SHA256SUMS", "sha256": "c" * 64, "admitted_sha256": "c" * 64},
        ],
    }
    return control, raw_git, signatures


def _validate_pre(
    contract: dict[str, Any],
    control: dict[str, Any] | None = None,
    raw_git: dict[str, Any] | None = None,
    signatures: dict[str, Any] | None = None,
) -> None:
    validator.validate_trusted_observations(
        control or _control_plane(contract),
        raw_git or _raw_git(contract),
        signatures or _local_signatures(contract),
        contract,
    )


def test_checked_in_phase0_contract_is_explicitly_inert() -> None:
    contract = validator.load_json(validator.CONTRACT_PATH)
    validator.validate_contract(contract)
    assert contract["assurance_state"] == "INERT_PRE_ACTIVATION_MODEL_NOT_LIVE_PROOF"
    assert contract["activation"]["enabled"] is False
    assert contract["blockers"]
    assert validator.main(["--check-inert"]) == 0
    assert validator.main([]) == 1
    with pytest.raises(validator.MaintenanceControlError, match="intentionally inert"):
        validator.validate_contract(contract, require_activated=True)


def test_topology_is_seven_runs_and_c_d_share_one_run() -> None:
    contract = validator.load_json(validator.CONTRACT_PATH)
    assert [item["phase"] for item in contract["runs"]] == [
        "A",
        "B",
        "CD",
        "E",
        "F",
        "G",
        "H",
    ]
    cd = contract["runs"][2]
    assert cd["workflow_role"] == "workflow-CD"
    assert cd["jobs"] == ["preflight", "seal", "detached-verify"]
    active = _active_contract()
    assert len(_runs(active)) == 7
    assert len({run["run_id"] for run in _runs(active)}) == 7


def test_phase0_pins_literal_control_plane_and_raw_git_baselines() -> None:
    contract = validator.load_json(validator.CONTRACT_PATH)
    protection = contract["required_branch_protection"]
    assert len(protection["required_checks"]) == 11
    assert len({(item["context"], item["app_id"]) for item in protection["required_checks"]}) == 11
    assert contract["required_repository_rulesets"] == [
        {
            "id": 19713401,
            "name": "EvoGuard release tag authority",
            "target": "tag",
            "source_type": "Repository",
            "source": "EvoRiseKsa/EvoOM-Guard-m",
            "enforcement": "active",
            "include": ["refs/tags/v*"],
            "exclude": [],
            "rules": ["creation", "update", "deletion", "non_fast_forward"],
            "bypass_actors": [
                {"actor_id": None, "actor_type": "DeployKey", "bypass_mode": "always"}
            ],
            "current_user_can_bypass": "never",
        }
    ]
    assert set(contract["required_environments"]) == {
        "evoguard-release-source-v2",
        "evoguard-release-artifact-v1",
        "evoguard-release-draft",
        "evoguard-release-publication",
    }
    assert {
        environment["deployment_branch"]
        for environment in contract["required_environments"].values()
    } == {"main"}
    entries = contract["trusted_raw_git"]["required_entries"]
    workflow_entries = [
        entry for entry in entries.values() if entry["role"].startswith("workflow-")
    ]
    assert len(workflow_entries) == 7
    assert all(entry["mode"] == "100644" for entry in entries.values())
    assert all(
        validator.SHA_PATTERN.fullmatch(entry["blob_sha"]) for path, entry in entries.items()
    )
    for path, entry in entries.items():
        source_bytes = (ROOT / path).read_bytes()
        source_blob = hashlib.sha1(
            f"blob {len(source_bytes)}\0".encode() + source_bytes,
            usedforsecurity=False,
        ).hexdigest()
        assert entry["blob_sha"] == source_blob


def test_phase0_literal_baselines_cannot_be_redefined_inside_the_contract() -> None:
    original = validator.load_json(validator.CONTRACT_PATH)

    contract = copy.deepcopy(original)
    contract["required_branch_protection"]["required_checks"][0]["app_id"] = 1
    with pytest.raises(validator.MaintenanceControlError, match="literal ordered 11"):
        validator.validate_contract(contract)

    contract = copy.deepcopy(original)
    contract["required_environments"]["evoguard-release-source-v2"]["id"] = 1
    with pytest.raises(validator.MaintenanceControlError, match="restricted to trusted main"):
        validator.validate_contract(contract)

    contract = copy.deepcopy(original)
    contract["trusted_raw_git"]["required_entries"][
        ".github/workflows/evoguard-release-source-reverify.yml"
    ]["blob_sha"] = "9" * 40
    with pytest.raises(validator.MaintenanceControlError, match="reviewed baseline"):
        validator.validate_contract(contract)

    contract = copy.deepcopy(original)
    contract["runs"][0]["jobs"] = ["metadata"]
    with pytest.raises(validator.MaintenanceControlError, match="job inventory is not literal"):
        validator.validate_contract(contract)


def test_active_model_keeps_workflow_and_target_identities_distinct() -> None:
    contract = _active_contract()
    assert MAIN_SHA != TARGET_SHA
    _validate_pre(contract)


def test_candidate_cannot_self_report_workflow_blobs_or_signer_identity() -> None:
    contract = _active_contract()
    control = _control_plane(contract)
    control["workflow_blobs"] = copy.deepcopy(contract["trusted_raw_git"]["required_entries"])
    with pytest.raises(validator.MaintenanceControlError, match="keys are not closed"):
        _validate_pre(contract, control=control)

    control = _control_plane(contract)
    control["author_login"] = "EvoRiseKsa"
    with pytest.raises(validator.MaintenanceControlError, match="keys are not closed"):
        _validate_pre(contract, control=control)


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda value: value["repository"].__setitem__("full_name", "attacker/EvoOM-Guard-m"),
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
            lambda value: value["branches"]["release/v4.5.1"].__setitem__("sha", "9" * 40),
            "pull request base/head",
        ),
        (
            lambda value: value["pull_requests"].append(copy.deepcopy(value["pull_requests"][0])),
            "exactly one",
        ),
        (
            lambda value: value["pull_requests"][0].__setitem__(
                "head_repo_full_name", "attacker/EvoOM-Guard-m"
            ),
            "pull request base/head",
        ),
        (
            lambda value: value["pull_requests"][0]["reviews"][0].__setitem__(
                "commit_sha", "9" * 40
            ),
            "exact-head approval",
        ),
        (
            lambda value: value["pull_requests"][0]["checks"][0].__setitem__("app_id", 1),
            "11-check/App-ID baseline",
        ),
    ],
)
def test_control_plane_substitutions_fail_closed(mutator: Any, message: str) -> None:
    contract = _active_contract()
    control = _control_plane(contract)
    mutator(control)
    with pytest.raises(validator.MaintenanceControlError, match=message):
        _validate_pre(contract, control=control)


def test_both_branches_cannot_be_weakened_together() -> None:
    contract = _active_contract()
    control = _control_plane(contract)
    for protection in control["branch_protections"].values():
        protection["allow_force_pushes"] = True
    with pytest.raises(validator.MaintenanceControlError, match="must be false"):
        _validate_pre(contract, control=control)


def test_ruleset_and_environment_weakening_fail_closed() -> None:
    contract = _active_contract()
    control = _control_plane(contract)
    control["rulesets"][0]["bypass_actors"] = []
    with pytest.raises(validator.MaintenanceControlError, match="ruleset"):
        _validate_pre(contract, control=control)

    control = _control_plane(contract)
    control["environments"]["evoguard-release-publication"]["deployment_branch"] = (
        "maintenance/v4.5"
    )
    with pytest.raises(validator.MaintenanceControlError, match="Environment"):
        _validate_pre(contract, control=control)


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda value: value["entries"][
                ".github/workflows/evoguard-release-source-reverify.yml"
            ].__setitem__("blob_sha", "9" * 40),
            "workflow/control/policy/pack",
        ),
        (
            lambda value: value.__setitem__("target_parents", [BASE_SHA, "9" * 40]),
            "one exact",
        ),
        (
            lambda value: value["changes"][0].__setitem__("old_mode", "100755"),
            "mode",
        ),
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
def test_raw_git_substitutions_fail_closed(mutator: Any, message: str) -> None:
    contract = _active_contract()
    raw_git = _raw_git(contract)
    mutator(raw_git)
    with pytest.raises(validator.MaintenanceControlError, match=message):
        _validate_pre(contract, raw_git=raw_git)


def test_source_signature_requires_local_raw_git_and_pinned_key() -> None:
    contract = _active_contract()
    signatures = _local_signatures(contract)
    signatures["source_commit"]["verified"] = False
    with pytest.raises(validator.MaintenanceControlError, match="local raw-Git"):
        _validate_pre(contract, signatures=signatures)

    signatures = _local_signatures(contract)
    signatures["public_key"]["fingerprint"] = "B" * 40
    with pytest.raises(validator.MaintenanceControlError, match="pinned public key"):
        _validate_pre(contract, signatures=signatures)


def test_stale_attempt_and_separate_d_run_are_rejected() -> None:
    contract = _active_contract()
    control, raw_git, signatures = _published_inputs(contract)
    control["runs"][4]["upstream_run_attempt"] = 2
    with pytest.raises(validator.MaintenanceControlError, match="stale upstream"):
        validator.validate_trusted_observations(
            control, raw_git, signatures, contract, stage="post-publication"
        )

    control, raw_git, signatures = _published_inputs(contract)
    control["runs"].insert(3, copy.deepcopy(control["runs"][2]))
    control["runs"][3]["phase"] = "D"
    with pytest.raises(validator.MaintenanceControlError, match="seven-run"):
        validator.validate_trusted_observations(
            control, raw_git, signatures, contract, stage="post-publication"
        )


@pytest.mark.parametrize(
    ("target", "field", "value", "message"),
    [
        ("raw", "object_type", "commit", "raw annotated tag"),
        ("raw", "name", "v4.5.2", "raw annotated tag"),
        ("raw", "target_sha", "9" * 40, "raw annotated tag"),
        ("raw", "size_bytes", 131073, "raw annotated tag"),
        ("signature", "verified", False, "local signature"),
        ("signature", "fingerprint", "B" * 40, "local signature"),
    ],
)
def test_tag_object_and_signature_mutations_fail_closed(
    target: str, field: str, value: Any, message: str
) -> None:
    contract = _active_contract()
    control, raw_git, signatures = _published_inputs(contract)
    if target == "raw":
        raw_git["tag_object"][field] = value
    else:
        signatures["tag"][field] = value
    with pytest.raises(validator.MaintenanceControlError, match=message):
        validator.validate_trusted_observations(
            control, raw_git, signatures, contract, stage="post-publication"
        )


def test_release_asset_and_immutability_mutations_fail_closed() -> None:
    contract = _active_contract()
    control, raw_git, signatures = _published_inputs(contract)
    control["release"]["immutable"] = False
    with pytest.raises(validator.MaintenanceControlError, match="immutable"):
        validator.validate_trusted_observations(
            control, raw_git, signatures, contract, stage="post-publication"
        )

    control, raw_git, signatures = _published_inputs(contract)
    control["release"]["assets"][0]["admitted_sha256"] = "f" * 64
    with pytest.raises(validator.MaintenanceControlError, match="digest differs"):
        validator.validate_trusted_observations(
            control, raw_git, signatures, contract, stage="post-publication"
        )


def test_exact_published_model_passes() -> None:
    contract = _active_contract()
    control, raw_git, signatures = _published_inputs(contract)
    validator.validate_trusted_observations(
        control, raw_git, signatures, contract, stage="post-publication"
    )


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
