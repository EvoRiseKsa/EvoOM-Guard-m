# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Closed-world tests for the inert v4.5.1 maintenance release contract."""

from __future__ import annotations

import copy
import json
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
FINGERPRINT = "A" * 40


def _active_contract() -> dict[str, Any]:
    contract = validator.load_json(validator.CONTRACT_PATH)
    contract["activation"] = "ACTIVE_FOR_ONE_V4_5_1_OPERATION"
    contract["blockers"] = []
    contract["review"]["allowed_signing_key_fingerprints"] = [FINGERPRINT]
    return contract


def _protection() -> dict[str, Any]:
    return {
        "strict_status_checks": True,
        "required_checks": [
            {"context": "test (3.12)", "app_id": 15368},
            {"context": "CodeQL", "app_id": 57789},
        ],
        "dismiss_stale_reviews": True,
        "require_code_owner_reviews": True,
        "require_last_push_approval": True,
        "required_approving_review_count": 1,
        "enforce_admins": True,
        "allow_force_pushes": False,
        "allow_deletions": False,
        "required_conversation_resolution": True,
    }


def _branch(name: str, sha: str, tree: str) -> dict[str, Any]:
    return {
        "name": name,
        "ref": f"refs/heads/{name}",
        "sha": sha,
        "tree_sha": tree,
        "protected": True,
        "protection": _protection(),
    }


def _snapshot() -> dict[str, Any]:
    contract = _active_contract()
    required_paths = list(contract["candidate"]["required_changed_paths"])
    return {
        "format": "EVOGUARD_MAINTENANCE_CONTROL_V1",
        "repository": copy.deepcopy(contract["repository"]),
        "trusted_workflow_branch": _branch("main", MAIN_SHA, MAIN_TREE),
        "maintenance_base_branch": _branch("maintenance/v4.5", BASE_SHA, BASE_TREE),
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
                "changed_paths": required_paths,
                "reviews": [
                    {
                        "id": 9001,
                        "actor": "MANA-awam",
                        "state": "APPROVED",
                        "commit_sha": TARGET_SHA,
                    }
                ],
                "checks": [
                    {
                        "context": "test (3.12)",
                        "app_id": 15368,
                        "head_sha": TARGET_SHA,
                        "status": "completed",
                        "conclusion": "success",
                    },
                    {
                        "context": "CodeQL",
                        "app_id": 57789,
                        "head_sha": TARGET_SHA,
                        "status": "completed",
                        "conclusion": "success",
                    },
                ],
            }
        ],
        "source_commit": {
            "sha": TARGET_SHA,
            "tree_sha": TARGET_TREE,
            "parents": [BASE_SHA],
            "author_login": "EvoRiseKsa",
            "verification": {
                "verified": True,
                "reason": "valid",
                "signing_key_fingerprint": FINGERPRINT,
            },
        },
        "workflow_blobs": {
            path: f"{index + 5:x}" * 40
            for index, path in enumerate(dict.fromkeys(contract["workflows"].values()))
        },
        "attempt_chain": [],
        "tag": {"state": "absent"},
        "release": {"state": "absent"},
    }


def _published_snapshot() -> dict[str, Any]:
    contract = _active_contract()
    snapshot = _snapshot()
    chain: list[dict[str, Any]] = []
    prior: dict[str, Any] | None = None
    for index, phase in enumerate(validator.PHASES):
        run = {
            "phase": phase,
            "workflow_path": contract["workflows"][phase],
            "workflow_blob_sha": snapshot["workflow_blobs"][contract["workflows"][phase]],
            "workflow_sha": MAIN_SHA,
            "target_sha": TARGET_SHA,
            "run_id": 1000 + index,
            "run_attempt": 1,
            "event": "workflow_dispatch" if phase in {"A", "E"} else "workflow_run",
            "conclusion": "success",
            "upstream_run_id": None if prior is None else prior["run_id"],
            "upstream_run_attempt": None if prior is None else prior["run_attempt"],
        }
        chain.append(run)
        prior = run
    snapshot["attempt_chain"] = chain
    snapshot["tag"] = {
        "state": "present",
        "name": "v4.5.1",
        "object_type": "tag",
        "tag_object_sha": "e" * 40,
        "target_commit_sha": TARGET_SHA,
        "verification": {
            "verified": True,
            "reason": "valid",
            "signer_login": "EvoRiseKsa",
            "signing_key_fingerprint": FINGERPRINT,
        },
    }
    snapshot["release"] = {
        "state": "published",
        "tag": "v4.5.1",
        "target_sha": TARGET_SHA,
        "immutable": True,
        "assets": ["evo-guard.pyz", "evo-guard.spdx.json", "SHA256SUMS"],
    }
    return snapshot


def test_checked_in_contract_is_literal_and_inert() -> None:
    contract = validator.load_json(validator.CONTRACT_PATH)
    validator.validate_contract(contract, require_activated=False)
    assert contract["activation"] == ("INERT_UNTIL_ALL_BLOCKERS_ARE_REVIEWED_AND_REMOVED")
    assert contract["blockers"]
    assert contract["repository"]["full_name"] == "EvoRiseKsa/EvoOM-Guard-m"
    assert contract["trusted_workflow_source"] == {
        "branch": "main",
        "ref": "refs/heads/main",
    }
    assert contract["maintenance_base"]["branch"] == "maintenance/v4.5"
    assert contract["candidate"]["branch"] == "release/v4.5.1"
    with pytest.raises(validator.MaintenanceControlError, match="intentionally inert"):
        validator.validate_contract(contract)


def test_maintenance_contract_code_and_claims_are_code_owned() -> None:
    codeowners = (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8")
    assert "/security/ @MANA-awam @EvoRiseKsa" in codeowners
    assert "/tools/ci/ @MANA-awam @EvoRiseKsa" in codeowners
    assert "/docs/V4.5.1_MAINTENANCE_LANE.md @MANA-awam @EvoRiseKsa" in codeowners


def test_trusted_workflow_sha_is_separate_from_target_source_sha() -> None:
    contract = _active_contract()
    snapshot = _snapshot()
    assert MAIN_SHA != TARGET_SHA
    assert validator.validate_snapshot(snapshot, contract) is snapshot


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: value["repository"].__setitem__("full_name", "attacker/EvoOM-Guard-m"),
            "repository identity",
        ),
        (
            lambda value: value["trusted_workflow_branch"].__setitem__("name", "maintenance/v4.5"),
            "trusted workflow branch identity",
        ),
        (
            lambda value: value["maintenance_base_branch"].__setitem__("protected", False),
            "unprotected",
        ),
        (
            lambda value: value["maintenance_base_branch"].__setitem__("sha", "9" * 40),
            "moved away",
        ),
        (
            lambda value: value["pull_requests"][0].__setitem__(
                "head_repo_full_name", "attacker/EvoOM-Guard-m"
            ),
            "alternate-repository",
        ),
        (
            lambda value: value["pull_requests"][0].__setitem__("head_sha", "8" * 40),
            "source commit does not equal",
        ),
        (
            lambda value: value["source_commit"].__setitem__("parents", [BASE_SHA, "8" * 40]),
            "one exact",
        ),
        (
            lambda value: value["source_commit"]["verification"].__setitem__("verified", False),
            "not GitHub-verifiably signed",
        ),
        (
            lambda value: value["pull_requests"][0]["reviews"][0].__setitem__(
                "commit_sha", "8" * 40
            ),
            "exact-head approval",
        ),
        (
            lambda value: value["pull_requests"][0]["checks"][0].__setitem__("head_sha", "8" * 40),
            "moved head",
        ),
        (
            lambda value: value["pull_requests"][0]["changed_paths"].append(
                ".github/workflows/release.yml"
            ),
            "expanded",
        ),
        (
            lambda value: value["maintenance_base_branch"]["protection"].__setitem__(
                "allow_force_pushes", True
            ),
            "must be false",
        ),
    ],
)
def test_pre_admission_mutations_fail_closed(mutation: Any, message: str) -> None:
    snapshot = _snapshot()
    mutation(snapshot)
    with pytest.raises(validator.MaintenanceControlError, match=message):
        validator.validate_snapshot(snapshot, _active_contract())


def test_stale_attempt_is_rejected() -> None:
    snapshot = _published_snapshot()
    snapshot["attempt_chain"][5]["upstream_run_attempt"] = 2
    with pytest.raises(validator.MaintenanceControlError, match="stale upstream"):
        validator.validate_snapshot(snapshot, _active_contract(), stage="post-publication")


def test_workflow_blob_substitution_is_rejected() -> None:
    snapshot = _published_snapshot()
    snapshot["attempt_chain"][4]["workflow_blob_sha"] = "f" * 40
    with pytest.raises(validator.MaintenanceControlError, match="blob substitution"):
        validator.validate_snapshot(snapshot, _active_contract(), stage="post-publication")


def test_unsigned_or_lightweight_tag_is_rejected() -> None:
    unsigned = _published_snapshot()
    unsigned["tag"]["verification"]["verified"] = False
    with pytest.raises(validator.MaintenanceControlError, match="signature"):
        validator.validate_snapshot(unsigned, _active_contract(), stage="post-publication")

    lightweight = _published_snapshot()
    lightweight["tag"]["object_type"] = "commit"
    with pytest.raises(validator.MaintenanceControlError, match="annotated tag"):
        validator.validate_snapshot(lightweight, _active_contract(), stage="post-publication")


def test_exact_published_control_is_accepted_only_with_full_chain() -> None:
    snapshot = _published_snapshot()
    assert (
        validator.validate_snapshot(snapshot, _active_contract(), stage="post-publication")
        is snapshot
    )
    snapshot["attempt_chain"].pop()
    with pytest.raises(validator.MaintenanceControlError, match="A-through-H"):
        validator.validate_snapshot(snapshot, _active_contract(), stage="post-publication")


def test_duplicate_json_keys_and_nonfinite_numbers_are_rejected(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"format":"a","format":"b"}\n', encoding="utf-8")
    with pytest.raises(validator.MaintenanceControlError, match="duplicate JSON key"):
        validator.load_json(duplicate)

    nonfinite = tmp_path / "nonfinite.json"
    nonfinite.write_text('{"value":NaN}\n', encoding="utf-8")
    with pytest.raises(validator.MaintenanceControlError, match="non-finite"):
        validator.load_json(nonfinite)


def test_control_input_rejects_a_hardlinked_file(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    linked = tmp_path / "linked.json"
    source.write_text('{"format":"bounded"}\n', encoding="utf-8")
    os.link(source, linked)
    with pytest.raises(validator.MaintenanceControlError, match="regular non-link"):
        validator.load_json(source)


def test_contract_file_has_no_candidate_selected_repository_or_ref() -> None:
    text = (ROOT / "security/v4.5.1-maintenance-lane.json").read_text(encoding="utf-8")
    assert "workflow_dispatch.inputs" not in text
    assert "github.event.inputs" not in text
    assert "repository_input" not in text
    assert json.loads(text)["candidate"]["ref"] == "refs/heads/release/v4.5.1"


def test_existing_a_through_h_are_mechanically_main_only() -> None:
    contract = validator.load_json(validator.CONTRACT_PATH)
    for path in set(contract["workflows"].values()):
        workflow = (ROOT / path).read_text(encoding="utf-8")
        assert "maintenance/v4.5" not in workflow
        assert "release/v4.5.1" not in workflow

    source_reverify = (ROOT / contract["workflows"]["A"]).read_text(encoding="utf-8")
    publication = (ROOT / contract["workflows"]["H"]).read_text(encoding="utf-8")
    assert 'test "$GITHUB_WORKFLOW_SHA" = "$TARGET_SHA"' in source_reverify
    assert '"$TARGET_SHA:refs/tags/$tag"' in publication
