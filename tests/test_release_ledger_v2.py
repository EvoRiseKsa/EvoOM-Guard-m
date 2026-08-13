# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
"""Fail-closed tests for the protected immutable release-ledger v2 contract."""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.machinery
import json
import os
import shutil
import subprocess
import sys
import time
import types
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from evoom_guard.signing import (
    generate_keypair,
    public_key_id,
    sign_file,
)
from tools.ci import collect_repository_controls_v2 as controls_collector
from tools.ci import validate_release_ledger_v2 as validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = (
    ROOT / "tests" / "baseline" / "schema" / "release-ledger-v2.schema.json"
)


def test_release_ledger_contract_paths_are_code_owned() -> None:
    codeowners = (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    for path in (
        "/tools/ci/",
        "/tests/baseline/",
        "/tests/test_release_ledger_v2.py",
        "/evidence/release-ledgers/",
        "/docs/RELEASE_LEDGER_V2.md",
        "/docs/RELEASE_GATE_CHECKLIST.md",
        "/docs/RELEASE_TRUST_PIPELINE.md",
        "/docs/adr/",
    ):
        assert f"{path} @MANA-awam @EvoRiseKsa" in codeowners


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _git(label: str) -> str:
    return hashlib.sha1(label.encode("utf-8")).hexdigest()  # noqa: S324 - Git object ID


def _file(path: str) -> dict[str, Any]:
    return {
        "path": path,
        "size_bytes": len(path.encode("utf-8")) + 1,
        "sha256": _sha(f"{path}\n"),
    }


def _release_cli_json(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")


def _artifact(name: str, role: str, asset_id: int) -> dict[str, Any]:
    descriptor = _file(f"release-assets/{name}")
    return {
        "name": name,
        "role": role,
        **descriptor,
        "release_asset_id": asset_id,
        "github_digest": f"sha256:{descriptor['sha256']}",
        "download_url": (
            "https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/download/"
            f"v9.9.9/{name}"
        ),
    }


def _retained_file(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": value["path"],
        "size_bytes": value["size_bytes"],
        "sha256": value["sha256"],
    }


def _release_deploy_public_key() -> str:
    algorithm = b"ssh-ed25519"
    raw_key = bytes(range(1, 33))
    blob = (
        len(algorithm).to_bytes(4, "big")
        + algorithm
        + len(raw_key).to_bytes(4, "big")
        + raw_key
    )
    return f"ssh-ed25519 {base64.b64encode(blob).decode('ascii')} release-test"


def _release_deploy_fingerprint() -> str:
    blob = base64.b64decode(_release_deploy_public_key().split()[1], validate=True)
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii")
    return f"SHA256:{digest.rstrip('=')}"


def _repository_control_observation(ledger: dict[str, Any]) -> dict[str, Any]:
    controls = ledger["repository_controls"]
    release = ledger["release"]
    repository = release["repository"]
    base = f"/repos/{repository}"
    by_environment = {item["name"]: item for item in controls["environments"]}

    def runner(
        method: str,
        endpoint: str,
        query: dict[str, int | str],
    ) -> controls_collector.ApiResponse:
        assert method == "GET"
        if endpoint == base:
            body: Any = {
                "full_name": repository,
                "id": int(release["repository_id"]),
                "private": False,
                "visibility": "public",
                "owner": {
                    "id": int(release["repository_owner_id"]),
                    "login": "EvoRiseKsa",
                    "type": "User",
                },
            }
        elif endpoint.endswith("/git/ref/heads/main"):
            body = {
                "ref": "refs/heads/main",
                "object": {
                    "sha": ledger["source"]["candidate_commit_sha"],
                    "type": "commit",
                },
            }
        elif endpoint.endswith("/branches/main/protection"):
            main = controls["main_branch"]
            body = {
                "required_status_checks": {
                    "strict": main["strict_required_checks"],
                    "checks": main["required_checks"],
                },
                "enforce_admins": {"enabled": main["enforce_admins"]},
                "required_pull_request_reviews": {
                    "dismiss_stale_reviews": main["dismiss_stale_reviews"],
                    "require_code_owner_reviews": main["code_owner_reviews"],
                    "required_approving_review_count": main[
                        "required_approving_reviews"
                    ],
                    "require_last_push_approval": main["last_push_approval"],
                },
                "required_linear_history": {"enabled": main["linear_history"]},
                "allow_force_pushes": {"enabled": main["allow_force_pushes"]},
                "allow_deletions": {"enabled": main["allow_deletions"]},
            }
        elif endpoint.endswith("/actions/permissions/workflow"):
            body = {
                "default_workflow_permissions": controls["actions"][
                    "default_workflow_permissions"
                ],
                "can_approve_pull_request_reviews": controls["actions"][
                    "can_approve_pull_requests"
                ],
            }
        elif endpoint.endswith("/actions/permissions"):
            body = {
                "enabled": controls["actions"]["enabled"],
                "allowed_actions": controls["actions"]["allowed_actions"],
                "sha_pinning_required": controls["actions"]["sha_pinning_required"],
            }
        elif endpoint.endswith("/immutable-releases"):
            body = controls["immutable_releases"]
        elif "/rulesets/" in endpoint:
            ruleset = controls["tag_ruleset"]
            body = {
                "id": ruleset["id"],
                "name": ruleset["name"],
                "target": ruleset["target"],
                "enforcement": ruleset["enforcement"],
                "conditions": {
                    "ref_name": {
                        "include": ruleset["include"],
                        "exclude": ruleset["exclude"],
                    }
                },
                "rules": [{"type": item} for item in ruleset["rules"]],
                "bypass_actors": ruleset["bypass_actor_classes"],
            }
        elif endpoint.endswith("/keys"):
            key = controls["release_deploy_key"]
            body = [
                {
                    "id": key["id"],
                    "title": key["title"],
                    "key": _release_deploy_public_key(),
                    "verified": key["verified"],
                    "read_only": key["read_only"],
                    "enabled": True,
                }
            ]
        elif endpoint.endswith("/environments"):
            values = []
            for item in controls["environments"]:
                values.append(
                    {
                        "id": item["id"],
                        "name": item["name"],
                        "can_admins_bypass": item["can_admins_bypass"],
                        "protection_rules": [
                            {
                                "id": item["required_reviewers_rule_id"],
                                "type": "required_reviewers",
                                "prevent_self_review": item["prevent_self_review"],
                                "reviewers": [
                                    {
                                        "type": "User",
                                        "reviewer": {
                                            "id": item["reviewer_id"],
                                            "login": item["reviewer"],
                                        },
                                    }
                                ],
                            },
                            {
                                "id": item["branch_policy_rule_id"],
                                "type": "branch_policy",
                            },
                        ],
                        "deployment_branch_policy": {
                            "protected_branches": False,
                            "custom_branch_policies": True,
                        },
                    }
                )
            body = {"total_count": len(values), "environments": values}
        elif endpoint.endswith("/deployment-branch-policies"):
            environment_name = endpoint.split("/environments/", 1)[1].split("/", 1)[0]
            item = by_environment[environment_name]
            body = {
                "total_count": 1,
                "branch_policies": [
                    {
                        "id": item["deployment_branch_policy_id"],
                        "name": "main",
                        "type": "branch",
                    }
                ],
            }
        elif "/actions/variables/" in endpoint:
            name = endpoint.rsplit("/", 1)[1]
            body = {"name": name, "value": "false"}
        elif endpoint.endswith("/secrets"):
            body = {"total_count": 0, "secrets": []}
        else:
            raise AssertionError(f"unexpected repository-control endpoint: {endpoint}")
        return controls_collector.ApiResponse(
            json.dumps(body, separators=(",", ":")).encode("utf-8")
        )

    times = iter(
        [
            datetime(2030, 1, 1, 0, 23, tzinfo=timezone.utc),
            *[
                datetime(2030, 1, 1, 0, 23, tzinfo=timezone.utc)
                for _ in range(16)
            ],
            datetime(2030, 1, 1, 0, 25, tzinfo=timezone.utc),
            datetime(2030, 1, 1, 0, 26, tzinfo=timezone.utc),
            datetime(2030, 1, 1, 0, 27, tzinfo=timezone.utc),
            datetime(2030, 1, 1, 0, 27, tzinfo=timezone.utc),
        ]
    )
    return controls_collector.collect(
        repository,
        controls["tag_ruleset"]["id"],
        api_runner=runner,
        clock=lambda: next(times),
    )


def _key_retirement_value(
    ledger: dict[str, Any],
    *,
    ledger_bytes: bytes,
    ledger_signature_bytes: bytes,
    key_id: str,
) -> dict[str, Any]:
    controls = ledger["repository_controls"]
    deploy_key = controls["release_deploy_key"]
    environment = next(
        item
        for item in controls["environments"]
        if item["name"] == "evoguard-release-publication"
    )
    common = {
        "http_status": 200,
        "pagination_complete": True,
        "per_page": 100,
        "page_count": 1,
        "total_count": 0,
        "present": False,
    }
    return {
        "format": "EVOGUARD_RELEASE_KEY_RETIREMENT_V1",
        "created_utc": "2030-01-01T00:33:00Z",
        "github_api_version": "2022-11-28",
        "repository": {
            "name": ledger["release"]["repository"],
            "id": ledger["release"]["repository_id"],
            "owner_id": ledger["release"]["repository_owner_id"],
        },
        "release": {
            "tag": ledger["release"]["tag"],
            "commit_sha": ledger["release"]["commit_sha"],
        },
        "ledger": {
            "sha256": hashlib.sha256(ledger_bytes).hexdigest(),
            "signature_sha256": hashlib.sha256(
                ledger_signature_bytes
            ).hexdigest(),
            "key_id": key_id,
            "created_utc": ledger["ledger_scope"]["created_utc"],
        },
        "publication_authority": {
            "deploy_key": {
                "kind": "repository-deploy-key",
                "id": deploy_key["id"],
                "title": deploy_key["title"],
                "fingerprint": deploy_key["fingerprint"],
                "api_action": "list-repository-deploy-keys",
                "request_method": "GET",
                "endpoint": f"/repos/{ledger['release']['repository']}/keys",
                **common,
                "observed_utc": "2030-01-01T00:31:00Z",
            },
            "environment_secret": {
                "kind": "environment-secret-name",
                "environment_id": environment["id"],
                "environment": environment["name"],
                "secret_name": "EVOGUARD_RELEASE_TAG_DEPLOY_KEY",
                "api_action": "list-environment-secrets",
                "request_method": "GET",
                "endpoint": (
                    f"/repos/{ledger['release']['repository']}/environments/"
                    "evoguard-release-publication/secrets"
                ),
                **common,
                "observed_utc": "2030-01-01T00:32:00Z",
            },
        },
        "proof_boundary": "owner-collected-point-in-time-github-api-observation",
    }


def _phase(
    name: str,
    *,
    path: str,
    event: str,
    jobs: list[str],
    run_id: int,
    workflow_id: int,
    candidate: str,
) -> dict[str, Any]:
    times = {
        "A": ("2030-01-01T00:01:00Z", "2030-01-01T00:02:00Z"),
        "B": ("2030-01-01T00:03:00Z", "2030-01-01T00:04:00Z"),
        "C": ("2030-01-01T00:05:00Z", "2030-01-01T00:06:00Z"),
        "D": ("2030-01-01T00:07:00Z", "2030-01-01T00:08:00Z"),
        "E": ("2030-01-01T00:09:00Z", "2030-01-01T00:10:00Z"),
        "F": ("2030-01-01T00:11:00Z", "2030-01-01T00:12:00Z"),
        "G": ("2030-01-01T00:13:00Z", "2030-01-01T00:14:00Z"),
        "H": ("2030-01-01T00:15:00Z", "2030-01-01T00:22:00Z"),
    }
    return {
        "phase": name,
        "workflow_id": workflow_id,
        "workflow_path": path,
        "workflow_blob_sha": _git(f"workflow-{name if name != 'D' else 'C'}"),
        "event": event,
        "source_ref": "refs/heads/main",
        "run_id": run_id,
        "run_attempt": 1,
        "head_sha": candidate,
        "conclusion": "success",
        "run_url": (
            "https://github.com/EvoRiseKsa/EvoOM-Guard-m/actions/runs/"
            f"{run_id}"
        ),
        "started_utc": times[name][0],
        "completed_utc": times[name][1],
        "successful_jobs": jobs,
        "upstream": None,
        "dispatch_inputs": {},
    }


def _control_bundle(
    *,
    domain: str,
    format_name: str,
    phase: str,
    run_id: int,
    artifact_id: int,
    artifact_name: str,
    retention_days: int,
    manifest_path: str,
    materials: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "domain": domain,
        "format": format_name,
        "phase": phase,
        "workflow_run_id": run_id,
        "workflow_run_attempt": 1,
        "observed_utc": "2030-01-01T00:24:00Z",
        "github_artifact": {
            "id": artifact_id,
            "name": artifact_name,
            "digest": f"sha256:{_sha(f'github-artifact-{artifact_id}')}",
            "url": (
                "https://github.com/EvoRiseKsa/EvoOM-Guard-m/actions/"
                f"runs/{run_id}/artifacts/{artifact_id}"
            ),
            "retention_days": retention_days,
        },
        "manifest": _file(manifest_path),
        "materials": materials,
    }


def _valid_ledger() -> dict[str, Any]:
    candidate = _git("candidate")
    candidate_tree = _git("candidate-tree")
    parent = _git("parent")
    parent_tree = _git("parent-tree")

    phases = [
        _phase(
            "A",
            path=".github/workflows/evoguard-release-source-reverify.yml",
            event="workflow_dispatch",
            jobs=["metadata", "reverify"],
            run_id=1001,
            workflow_id=101,
            candidate=candidate,
        ),
        _phase(
            "B",
            path=".github/workflows/evoguard-produce-release-source-receipt.yml",
            event="workflow_run",
            jobs=["preflight", "receipt"],
            run_id=1002,
            workflow_id=102,
            candidate=candidate,
        ),
        _phase(
            "C",
            path=".github/workflows/evoguard-admit-release-source.yml",
            event="workflow_run",
            jobs=["preflight", "seal"],
            run_id=1003,
            workflow_id=103,
            candidate=candidate,
        ),
        _phase(
            "D",
            path=".github/workflows/evoguard-admit-release-source.yml",
            event="workflow_run",
            jobs=["detached-verify"],
            run_id=1003,
            workflow_id=103,
            candidate=candidate,
        ),
        _phase(
            "E",
            path=".github/workflows/evoguard-build-release-artifact.yml",
            event="workflow_dispatch",
            jobs=["preflight", "build", "attest"],
            run_id=1004,
            workflow_id=104,
            candidate=candidate,
        ),
        _phase(
            "F",
            path=".github/workflows/evoguard-admit-release-artifact.yml",
            event="workflow_run",
            jobs=["preflight", "verify-attestations", "seal"],
            run_id=1005,
            workflow_id=105,
            candidate=candidate,
        ),
        _phase(
            "G",
            path=".github/workflows/evoguard-verify-release-artifact.yml",
            event="workflow_run",
            jobs=["detached-verify"],
            run_id=1006,
            workflow_id=106,
            candidate=candidate,
        ),
        _phase(
            "H",
            path=".github/workflows/evoguard-publish-admitted-release.yml",
            event="workflow_run",
            jobs=["preflight", "draft", "publish"],
            run_id=1007,
            workflow_id=107,
            candidate=candidate,
        ),
    ]
    by_phase = {item["phase"]: item for item in phases}
    for phase, upstream in (
        ("B", "A"),
        ("C", "B"),
        ("D", "C"),
        ("F", "E"),
        ("G", "F"),
        ("H", "G"),
    ):
        by_phase[phase]["upstream"] = {
            "phase": upstream,
            "run_id": by_phase[upstream]["run_id"],
            "run_attempt": by_phase[upstream]["run_attempt"],
        }
    by_phase["D"]["workflow_blob_sha"] = by_phase["C"]["workflow_blob_sha"]
    by_phase["D"]["run_url"] = by_phase["C"]["run_url"]
    by_phase["E"]["dispatch_inputs"] = {
        "source_admission_run_id": by_phase["C"]["run_id"],
        "source_admission_run_attempt": by_phase["C"]["run_attempt"],
        "expected_version": "9.9.9",
    }

    artifacts = [
        _artifact("evo-guard.pyz", "runtime", 2001),
        _artifact("evo-guard.spdx.json", "spdx-sbom", 2002),
        _artifact("SHA256SUMS", "checksum-manifest", 2003),
    ]
    by_asset = {item["name"]: item for item in artifacts}

    root_ids = {
        domain: f"sha256:{_sha(f'root-{domain}')}"
        for domain in validator.ROOT_DOMAINS
    }
    source_rsae = {
        **_file("admission/source/source-allow.rsae"),
        "algorithm": "Ed25519",
        "key_id": root_ids["release-source-admission-v2"],
    }
    artifact_subjects = []
    for name in ("evo-guard.pyz", "evo-guard.spdx.json"):
        artifact_subjects.append(
            {
                "name": name,
                "artifact_sha256": by_asset[name]["sha256"],
                "artifact_size_bytes": by_asset[name]["size_bytes"],
                "raae": {
                    **_file(f"admission/artifact/{name}.raae"),
                    "algorithm": "Ed25519",
                    "key_id": root_ids["release-artifact-admission-v1"],
                },
                "protected_seal_result": _file(
                    f"admission/artifact/{name}.seal-result.json"
                ),
                "detached_verification_result": _file(
                    f"admission/artifact/{name}.detached-verification.json"
                ),
                "live_provider_reverification": {
                    "protected_seal": True,
                    "detached_verification": False,
                },
            }
        )

    source_materials = [
        _file("controls/source/producer-receipt.json"),
        _file("controls/source/source.json"),
        _file("controls/source/context.json"),
        _file("controls/source/verdict.json"),
        _file("controls/source/handoff.json"),
        _file("controls/source/producer.json"),
        _file("controls/source/signing-requirements.lock"),
        _file("controls/source/admitter.json"),
        _file("controls/source/github-policy.json"),
    ]
    artifact_materials = [
        _retained_file(source_rsae),
        _retained_file(by_asset["evo-guard.pyz"]),
        _retained_file(by_asset["evo-guard.spdx.json"]),
        _retained_file(by_asset["SHA256SUMS"]),
        _file("controls/artifact/builder-controls.json"),
        _file("controls/artifact/source.json"),
        _file("controls/artifact/context.json"),
        _file("controls/artifact/producer.json"),
        _file("controls/artifact/source-admitter.json"),
        _file("controls/artifact/source-github-policy.json"),
        _file("controls/artifact/signing-requirements.lock"),
        _file("controls/artifact/builder.json"),
        _file("controls/artifact/admitter.json"),
        _file("controls/artifact/verify_spdx_attestation.py"),
        _file("controls/artifact/build-provenance-verification.json"),
        _file("controls/artifact/build-provenance-verification-output.json"),
        _file("controls/artifact/spdx-provenance-verification.json"),
        _file("controls/artifact/spdx-provenance-verification-output.json"),
        _file("controls/artifact/sbom-attestation-output.json"),
        _file("controls/artifact/sbom-attestation-receipt.json"),
    ]
    publication_materials = [
        _file("controls/publication/evo-guard.pyz.detached-verification.json"),
        _file(
            "controls/publication/evo-guard.spdx.json.detached-verification.json"
        ),
        _file("controls/publication/raae-negative-results.txt"),
    ]
    publication_ready_materials = [
        _file(by_asset[name]["path"])
        for name in ("evo-guard.pyz", "evo-guard.spdx.json", "SHA256SUMS")
    ]

    return {
        "schema_version": "evoguard-release-ledger-v2",
        "ledger_scope": {
            "kind": "post-publication-immutable-release-evidence",
            "created_utc": "2030-01-01T00:30:00Z",
            "complete": True,
            "evidence_boundary": "recorded-observations-and-retained-bytes",
            "readme": _file("README.md"),
        },
        "project": {
            "name": "EvoOM Guard",
            "version": "9.9.9",
        },
        "release": {
            "repository": "EvoRiseKsa/EvoOM-Guard-m",
            "repository_id": str(validator.EXPECTED_REPOSITORY_ID),
            "repository_owner_id": str(validator.EXPECTED_REPOSITORY_OWNER_ID),
            "source_repository_visibility_at_signing": "public",
            "tag": "v9.9.9",
            "commit_sha": candidate,
            "tree_sha": candidate_tree,
            "release_id": 3001,
            "state": "published",
            "prerelease": False,
            "immutable": True,
            "created_utc": "2030-01-01T00:00:30Z",
            "published_utc": "2030-01-01T00:20:00Z",
            "release_url": (
                "https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v9.9.9"
            ),
        },
        "source": {
            "protected_ref": "refs/heads/main",
            "candidate_commit_sha": candidate,
            "candidate_tree_sha": candidate_tree,
            "parent_commit_sha": parent,
            "parent_tree_sha": parent_tree,
            "parent_count": 1,
        },
        "schema_contracts": {
            "release_ledger": {
                "id": "urn:evoguard:release-ledger:2",
                "path": "tests/baseline/schema/release-ledger-v2.schema.json",
                "sha256": hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest(),
                "git_blob_sha": validator._git_blob_sha(SCHEMA_PATH.read_bytes()),
                "trusted_parent_commit_sha": parent,
                "trusted_parent_tree_sha": parent_tree,
            },
            "validator": {
                "path": "tools/ci/validate_release_ledger_v2.py",
                "sha256": hashlib.sha256(
                    Path(validator.__file__).read_bytes()
                ).hexdigest(),
                "git_blob_sha": validator._git_blob_sha(
                    Path(validator.__file__).read_bytes()
                ),
                "trusted_parent_commit_sha": parent,
                "trusted_parent_tree_sha": parent_tree,
            },
            "repository_controls_collector": {
                "path": validator.REPOSITORY_CONTROLS_COLLECTOR_REPOSITORY_PATH,
                "sha256": hashlib.sha256(
                    (
                        ROOT
                        / validator.REPOSITORY_CONTROLS_COLLECTOR_REPOSITORY_PATH
                    ).read_bytes()
                ).hexdigest(),
                "git_blob_sha": validator._git_blob_sha(
                    (
                        ROOT
                        / validator.REPOSITORY_CONTROLS_COLLECTOR_REPOSITORY_PATH
                    ).read_bytes()
                ),
                "trusted_parent_commit_sha": parent,
                "trusted_parent_tree_sha": parent_tree,
            },
            "verdict_record": "1.11",
            "sarif": "2.1.0",
            "verifier_pack": "EVOGUARD_PACK_V2",
            "release_source_admission": "EVOGUARD_RELEASE_SOURCE_ADMISSION_V2",
            "release_artifact_admission": (
                "EVOGUARD_RELEASE_ARTIFACT_ADMISSION_V1"
            ),
            "publication_controls": "EVOGUARD_RELEASE_PUBLICATION_CONTROLS_V1",
            "junit_digest_formats": [
                "JUNIT_XML_SHA256",
                "EVOGUARD_JUNIT_REPORT_SET_V1",
                "EVOGUARD_JUNIT_COMPOSITE_V1",
                "EVOGUARD_JUNIT_COMPOSITE_V2",
            ],
        },
        "artifacts": artifacts,
        "checksum_manifest": {
            "path": by_asset["SHA256SUMS"]["path"],
            "format": "sha256sum-two-space",
            "manifest_sha256": by_asset["SHA256SUMS"]["sha256"],
            "entries": [
                {
                    "target": name,
                    "sha256": by_asset[name]["sha256"],
                }
                for name in ("evo-guard.pyz", "evo-guard.spdx.json")
            ],
        },
        "workflow_chain": phases,
        "control_evidence": {
            "source_external_controls": _control_bundle(
                domain="source-external-controls",
                format_name="EVOGUARD_RELEASE_SOURCE_V2_EXTERNAL_CONTROLS_V1",
                phase="C",
                run_id=by_phase["C"]["run_id"],
                artifact_id=4001,
                artifact_name="evoguard-release-source-v2-controls-1",
                retention_days=30,
                manifest_path="controls/source/control-manifest.json",
                materials=source_materials,
            ),
            "artifact_external_controls": _control_bundle(
                domain="artifact-external-controls",
                format_name="EVOGUARD_RELEASE_ASSET_F_CONTROLS_V1",
                phase="F",
                run_id=by_phase["F"]["run_id"],
                artifact_id=4002,
                artifact_name=(
                    "evoguard-release-artifact-v1-complete-controls-1"
                ),
                retention_days=30,
                manifest_path="controls/artifact/f-control-manifest.json",
                materials=artifact_materials,
            ),
            "publication_controls": _control_bundle(
                domain="publication-controls",
                format_name="EVOGUARD_RELEASE_PUBLICATION_CONTROLS_V1",
                phase="G",
                run_id=by_phase["G"]["run_id"],
                artifact_id=4003,
                artifact_name="evoguard-release-artifact-admission-v1-verified-1",
                retention_days=30,
                manifest_path="controls/publication/publication-controls.json",
                materials=publication_materials,
            ),
            "publication_ready": _control_bundle(
                domain="publication-ready",
                format_name="EVOGUARD_RELEASE_PUBLICATION_READY_V1",
                phase="H",
                run_id=by_phase["H"]["run_id"],
                artifact_id=4004,
                artifact_name="evoguard-release-publication-ready-1006-1",
                retention_days=1,
                manifest_path="controls/publication-ready/publication-ready.json",
                materials=publication_ready_materials,
            ),
        },
        "source_admission": {
            "format": "EVOGUARD_RELEASE_SOURCE_ADMISSION_V2",
            "decision": "ALLOW",
            "target_commit_sha": candidate,
            "target_tree_sha": candidate_tree,
            "rsae": source_rsae,
            "protected_seal_result": _file(
                "admission/source/protected-seal-result.json"
            ),
            "detached_verification_result": _file(
                "admission/source/detached-verification-result.json"
            ),
            "negative_results": _file(
                "admission/source/detached-negative-results.json"
            ),
            "negative_case_count": 11,
        },
        "artifact_admission": {
            "format": "EVOGUARD_RELEASE_ARTIFACT_ADMISSION_V1",
            "decision": "ALLOW",
            "source_rsae_sha256": source_rsae["sha256"],
            "subjects": artifact_subjects,
            "negative_results": _file(
                "admission/artifact/raae-negative-results.txt"
            ),
            "negative_case_count": 7,
        },
        "attestations": {
            "source_producer": {
                "role": "source-producer-receipt",
                "phase": "B",
                "predicate_type": "https://slsa.dev/provenance/v1",
                "subject_name": "producer-receipt.json",
                "subject_sha256": source_materials[0]["sha256"],
                "signer_workflow": by_phase["B"]["workflow_path"],
                "signer_workflow_blob_sha": by_phase["B"]["workflow_blob_sha"],
                "source_ref": "refs/heads/main",
                "source_digest": candidate,
                "run_id": by_phase["B"]["run_id"],
                "run_attempt": 1,
                "verified_utc": "2030-01-01T00:05:30Z",
                "verification_receipt": _file(
                    "attestations/source-producer-verification.json"
                ),
                "verification_output": _file(
                    "attestations/source-producer-verification-output.json"
                ),
            },
            "build_provenance": {
                "role": "build-provenance",
                "phase": "E",
                "predicate_type": "https://slsa.dev/provenance/v1",
                "subject_name": "evo-guard.pyz",
                "subject_sha256": by_asset["evo-guard.pyz"]["sha256"],
                "signer_workflow": by_phase["E"]["workflow_path"],
                "signer_workflow_blob_sha": by_phase["E"]["workflow_blob_sha"],
                "source_ref": "refs/heads/main",
                "source_digest": candidate,
                "run_id": by_phase["E"]["run_id"],
                "run_attempt": 1,
                "verified_utc": "2030-01-01T00:11:15Z",
                "verification_receipt": _file(
                    "controls/artifact/build-provenance-verification.json"
                ),
                "verification_output": _file(
                    "controls/artifact/build-provenance-verification-output.json"
                ),
            },
            "spdx_provenance": {
                "role": "spdx-file-provenance",
                "phase": "E",
                "predicate_type": "https://slsa.dev/provenance/v1",
                "subject_name": "evo-guard.spdx.json",
                "subject_sha256": by_asset["evo-guard.spdx.json"]["sha256"],
                "signer_workflow": by_phase["E"]["workflow_path"],
                "signer_workflow_blob_sha": by_phase["E"]["workflow_blob_sha"],
                "source_ref": "refs/heads/main",
                "source_digest": candidate,
                "run_id": by_phase["E"]["run_id"],
                "run_attempt": 1,
                "verified_utc": "2030-01-01T00:11:30Z",
                "verification_receipt": _file(
                    "controls/artifact/spdx-provenance-verification.json"
                ),
                "verification_output": _file(
                    "controls/artifact/spdx-provenance-verification-output.json"
                ),
            },
            "sbom_provenance": {
                "role": "sbom-provenance",
                "phase": "E",
                "predicate_type": "https://spdx.dev/Document/v2.3",
                "subject_name": "evo-guard.pyz",
                "subject_sha256": by_asset["evo-guard.pyz"]["sha256"],
                "signer_workflow": by_phase["E"]["workflow_path"],
                "signer_workflow_blob_sha": by_phase["E"]["workflow_blob_sha"],
                "source_ref": "refs/heads/main",
                "source_digest": candidate,
                "run_id": by_phase["E"]["run_id"],
                "run_attempt": 1,
                "verified_utc": "2030-01-01T00:11:45Z",
                "verification_receipt": _file(
                    "controls/artifact/sbom-attestation-receipt.json"
                ),
                "verification_output": _file(
                    "controls/artifact/sbom-attestation-output.json"
                ),
            },
            "release": {
                "predicate_type": "https://in-toto.io/attestation/release/v0.2",
                "verified_utc": "2030-01-01T00:21:00Z",
                "identity": "https://dotcom.releases.github.com",
                "purl": "pkg:github/EvoRiseKsa/EvoOM-Guard-m@v9.9.9",
                "tag": "v9.9.9",
                "commit_sha": candidate,
                "asset_subjects": [
                    {
                        "name": item["name"],
                        "sha256": item["sha256"],
                    }
                    for item in artifacts
                ],
                "verification_scope": "recorded-external-attestation",
            },
        },
        "trust_roots": [
            {
                "domain": domain,
                "key_id": root_ids[domain],
                "public_key": _file(f"trust/{domain}.pub.pem"),
            }
            for domain in validator.ROOT_DOMAINS
        ],
        "toolchain": {
            "bootstrap_guard": {
                "url": (
                    "https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/"
                    "download/v9.8.0/evo-guard.pyz"
                ),
                "version": "9.8.0",
                "sha256": _sha("bootstrap-runtime"),
            },
            "runner_image": {
                "reference": (
                    "python:3.12-slim@sha256:"
                    f"{_sha('runner-image')}"
                ),
                "sha256": _sha("runner-image"),
                "network": "none",
            },
            "git": {
                "name": "git",
                "platform": "ubuntu-24.04",
                "sha256": _sha("git-executable"),
            },
            "github_cli": {
                "name": "gh",
                "platform": "ubuntu-24.04",
                "sha256": _sha("gh-executable"),
            },
            "provider_identities": {
                "source_admission": {
                    "platform": "posix",
                    "uid": 60001,
                    "gid": 60001,
                },
                "artifact_admission": {
                    "platform": "posix",
                    "uid": 60002,
                    "gid": 60002,
                },
            },
            "trusted_build_inputs": {
                "source_parent_sha": parent,
                "source_parent_tree_sha": parent_tree,
                "build_pyz_blob_sha": _git("build-pyz-blob"),
                "spdx_generator_blob_sha": _git("spdx-generator-blob"),
                "spdx_attestation_verifier_blob_sha": _git(
                    "spdx-attestation-verifier-blob"
                ),
            },
        },
        "repository_controls": {
            "observed_utc": "2030-01-01T00:27:00Z",
            "main_branch": {
                "ref": "refs/heads/main",
                "head_sha": candidate,
                "protected": True,
                "strict_required_checks": True,
                "enforce_admins": True,
                "required_checks": [
                    {"context": context, "app_id": app_id}
                    for context, app_id in sorted(validator.REQUIRED_MAIN_CHECKS)
                ],
                "required_approving_reviews": 1,
                "code_owner_reviews": True,
                "dismiss_stale_reviews": True,
                "last_push_approval": True,
                "linear_history": True,
                "allow_force_pushes": False,
                "allow_deletions": False,
            },
            "tag_ruleset": {
                "id": 5001,
                "name": "EvoGuard release tag authority",
                "target": "tag",
                "enforcement": "active",
                "include": ["refs/tags/v*"],
                "exclude": [],
                "rules": [
                    "creation",
                    "update",
                    "deletion",
                    "non_fast_forward",
                ],
                "bypass_actor_classes": [
                    {
                        "actor_type": "DeployKey",
                        "actor_id": None,
                        "bypass_mode": "always",
                    }
                ],
            },
            "release_deploy_key": {
                "id": 5002,
                "title": "release tag authority",
                "fingerprint": _release_deploy_fingerprint(),
                "algorithm": "ssh-ed25519",
                "verified": True,
                "read_only": False,
                "sole_write_enabled": True,
            },
            "immutable_releases": {
                "enabled": True,
                "enforced_by_owner": False,
            },
            "actions": {
                "enabled": True,
                "allowed_actions": "all",
                "sha_pinning_required": True,
                "default_workflow_permissions": "read",
                "can_approve_pull_requests": False,
            },
            "environments": [
                {
                    "id": 18718844374,
                    "name": "evoguard-release-source-v2",
                    "reviewer": "MANA-awam",
                    "reviewer_id": 304223352,
                    "required_reviewers_rule_id": 60851006,
                    "branch_policy_rule_id": 60851007,
                    "prevent_self_review": True,
                    "can_admins_bypass": False,
                    "deployment_branch": "main",
                    "deployment_branch_policy_id": 55562429,
                },
                {
                    "id": 18718845035,
                    "name": "evoguard-release-artifact-v1",
                    "reviewer": "MANA-awam",
                    "reviewer_id": 304223352,
                    "required_reviewers_rule_id": 60851009,
                    "branch_policy_rule_id": 60851010,
                    "prevent_self_review": True,
                    "can_admins_bypass": False,
                    "deployment_branch": "main",
                    "deployment_branch_policy_id": 55562431,
                },
                {
                    "id": 18718845676,
                    "name": "evoguard-release-draft",
                    "reviewer": "MANA-awam",
                    "reviewer_id": 304223352,
                    "required_reviewers_rule_id": 60851011,
                    "branch_policy_rule_id": 60851012,
                    "prevent_self_review": True,
                    "can_admins_bypass": False,
                    "deployment_branch": "main",
                    "deployment_branch_policy_id": 55562435,
                },
                {
                    "id": 18718846349,
                    "name": "evoguard-release-publication",
                    "reviewer": "MANA-awam",
                    "reviewer_id": 304223352,
                    "required_reviewers_rule_id": 60851015,
                    "branch_policy_rule_id": 60851016,
                    "prevent_self_review": True,
                    "can_admins_bypass": False,
                    "deployment_branch": "main",
                    "deployment_branch_policy_id": 55562438,
                },
            ],
            "observation_evidence": _file(
                "controls/repository/repository-controls-observation.json"
            ),
            "repository_admission_secret_absence_after_publication": [
                {
                    "secret_name": (
                        "EVOGUARD_RELEASE_SOURCE_ADMISSION_V2_PRIVATE_KEY_B64"
                    ),
                    "present": False,
                    "observed_utc": "2030-01-01T00:25:00Z",
                    "observation_scope": "github-repository-secret-name-list",
                },
                {
                    "secret_name": (
                        "EVOGUARD_RELEASE_ARTIFACT_ADMISSION_V1_PRIVATE_KEY_B64"
                    ),
                    "present": False,
                    "observed_utc": "2030-01-01T00:25:00Z",
                    "observation_scope": "github-repository-secret-name-list",
                },
            ],
            "admission_secret_absence_after_publication": [
                {
                    "environment": "evoguard-release-source-v2",
                    "secret_name": (
                        "EVOGUARD_RELEASE_SOURCE_ADMISSION_V2_PRIVATE_KEY_B64"
                    ),
                    "present": False,
                    "observed_utc": "2030-01-01T00:26:00Z",
                    "observation_scope": "github-environment-secret-name-list",
                },
                {
                    "environment": "evoguard-release-artifact-v1",
                    "secret_name": (
                        "EVOGUARD_RELEASE_ARTIFACT_ADMISSION_V1_PRIVATE_KEY_B64"
                    ),
                    "present": False,
                    "observed_utc": "2030-01-01T00:27:00Z",
                    "observation_scope": "github-environment-secret-name-list",
                },
            ],
            "publication_authority_retirement": {
                "status": "pending-post-ledger",
                "deploy_key_id": 5002,
                "environment": "evoguard-release-publication",
                "secret_name": "EVOGUARD_RELEASE_TAG_DEPLOY_KEY",
                "proof_boundary": "not-claimed-by-release-ledger",
            },
            "activation_flags_after_publication": {
                "source_admission": False,
                "artifact_admission": False,
                "publication": False,
            },
            "publication_window": {
                "main_frozen": True,
                "other_contents_write_actors_frozen": True,
                "manual_release_operations_frozen": True,
                "observation_scope": "operator-reviewed-control-plane",
            },
        },
        "tag_ci": {
            "path": ".github/workflows/ci.yml",
            "event": "push",
            "tag_ref": "refs/tags/v9.9.9",
            "run_id": 7001,
            "attempt": 1,
            "head_sha": candidate,
            "conclusion": "success",
            "run_url": (
                "https://github.com/EvoRiseKsa/EvoOM-Guard-m/actions/runs/7001"
            ),
            "completed_utc": "2030-01-01T00:21:00Z",
            "observed_utc": "2030-01-01T00:24:00Z",
            "successful_jobs": list(validator.EXPECTED_TAG_JOBS),
        },
        "marketplace": {
            "action": "EvoOM Guard",
            "version": "v9.9.9",
            "url": "https://github.com/marketplace/actions/evoom-guard",
            "observed_utc": "2030-01-01T00:25:00Z",
        },
        "ledger_signature": {
            "algorithm": "Ed25519",
            "purpose": "evoguard-release-ledger-v2",
            "key_id": f"sha256:{_sha('ledger-signing-key')}",
            "signed_path": "RELEASE_LEDGER.json",
            "signature_path": "RELEASE_LEDGER.json.sig",
            "signature_encoding": "base64",
            "public_key": _file("trust/release-ledger-v2.pub.pem"),
            "trusted_parent_anchor": {
                "path": "security/release-ledger-roots/v9.9.9.pub.pem",
                "sha256": _sha("ledger-parent-anchor"),
                "git_blob_sha": _git("ledger-parent-anchor"),
                "trusted_parent_commit_sha": parent,
                "trusted_parent_tree_sha": parent_tree,
            },
        },
    }


def _schema() -> dict[str, Any]:
    return validator._load_json_file(SCHEMA_PATH, label="test schema")


def test_v2_schema_is_valid_and_synthetic_contract_passes() -> None:
    schema = _schema()
    Draft202012Validator.check_schema(schema)
    validator.validate_structure(_valid_ledger())


def test_project_status_is_a_schema_required_main_check_and_tag_job() -> None:
    ledger = _valid_ledger()
    ledger["repository_controls"]["main_branch"]["required_checks"] = [
        item
        for item in ledger["repository_controls"]["main_branch"]["required_checks"]
        if item["context"] != "project-status"
    ]
    with pytest.raises(
        validator.LedgerValidationError,
        match="schema validation failed",
    ):
        validator.validate_structure(ledger)

    ledger = _valid_ledger()
    ledger["tag_ci"]["successful_jobs"].remove("project-status")
    with pytest.raises(
        validator.LedgerValidationError,
        match="schema validation failed",
    ):
        validator.validate_structure(ledger)


def test_official_schema_is_not_caller_replaceable() -> None:
    ledger = _valid_ledger()
    ledger["unexpected"] = True
    with pytest.raises(validator.LedgerValidationError, match="schema validation failed"):
        validator.validate_structure(ledger)
    with pytest.raises(SystemExit):
        validator._parser().parse_args(
            ["--schema", str(SCHEMA_PATH), "validate", "."]
        )
    with pytest.raises(SystemExit):
        validator._parser().parse_args(["validate", "."])


def test_signed_schema_descriptor_binds_exact_repository_bytes() -> None:
    ledger = _valid_ledger()
    ledger["schema_contracts"]["release_ledger"]["sha256"] = _sha(
        "permissive-schema"
    )
    with pytest.raises(validator.LedgerValidationError, match="exact official"):
        validator.validate_structure(ledger)


def test_signed_validator_descriptor_binds_trusted_parent_and_exact_bytes() -> None:
    ledger = _valid_ledger()
    ledger["schema_contracts"]["validator"]["sha256"] = _sha(
        "candidate-mutated-validator"
    )
    with pytest.raises(validator.LedgerValidationError, match="trusted-parent validator"):
        validator.validate_structure(ledger)

    ledger = _valid_ledger()
    ledger["schema_contracts"]["validator"]["trusted_parent_commit_sha"] = _git(
        "wrong-parent"
    )
    with pytest.raises(validator.LedgerValidationError, match="trusted-parent validator"):
        validator.validate_structure(ledger)


def test_external_trusted_parent_rejects_candidate_contract_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "trusted-parent"
    repository.mkdir()

    def git(*arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    git("init", "-q")
    git("config", "user.name", "Ledger Test")
    git("config", "user.email", "ledger@example.invalid")
    schema_target = repository / validator.OFFICIAL_SCHEMA_REPOSITORY_PATH
    validator_target = repository / validator.VALIDATOR_REPOSITORY_PATH
    collector_target = (
        repository / validator.REPOSITORY_CONTROLS_COLLECTOR_REPOSITORY_PATH
    )
    private = tmp_path / "ledger-anchor.private.pem"
    public = repository / "security/release-ledger-roots/v9.9.9.pub.pem"
    public.parent.mkdir(parents=True)
    generate_keypair(str(private), str(public))
    schema_target.parent.mkdir(parents=True)
    validator_target.parent.mkdir(parents=True)
    schema_target.write_bytes(SCHEMA_PATH.read_bytes())
    validator_target.write_bytes(Path(validator.__file__).read_bytes())
    collector_target.write_bytes(
        (
            ROOT / validator.REPOSITORY_CONTROLS_COLLECTOR_REPOSITORY_PATH
        ).read_bytes()
    )
    for _field, relative in validator.TRUSTED_BUILD_INPUT_PATHS.items():
        source = ROOT.joinpath(*PurePosixPath(relative).parts)
        target = repository.joinpath(*PurePosixPath(relative).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    git("add", ".")
    git("commit", "-q", "-m", "trusted parent")
    parent = git("rev-parse", "HEAD")
    parent_tree = git("rev-parse", "HEAD^{tree}")
    ledger = _valid_ledger()
    ledger["ledger_signature"]["key_id"] = public_key_id(str(public))
    ledger["ledger_signature"]["trusted_parent_anchor"].update(
        {
            "sha256": hashlib.sha256(public.read_bytes()).hexdigest(),
            "git_blob_sha": validator._git_blob_sha(public.read_bytes()),
        }
    )
    ledger["source"]["parent_commit_sha"] = parent
    ledger["source"]["parent_tree_sha"] = parent_tree
    ledger["toolchain"]["trusted_build_inputs"].update(
        {
            field: git("rev-parse", f"HEAD:{relative}")
            for field, relative in validator.TRUSTED_BUILD_INPUT_PATHS.items()
        }
    )
    for contract in (
        ledger["schema_contracts"]["release_ledger"],
        ledger["schema_contracts"]["validator"],
        ledger["schema_contracts"]["repository_controls_collector"],
        ledger["ledger_signature"]["trusted_parent_anchor"],
    ):
        contract["trusted_parent_commit_sha"] = parent
        contract["trusted_parent_tree_sha"] = parent_tree
    ledger_root = tmp_path / "ledger"
    ledger_root.mkdir()
    trusted = validator._load_trusted_ledger_key(ledger_root, public)
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "malicious.git"))
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", str(tmp_path / "malicious-objects"))
    validator._validate_trusted_parent_contracts(
        ledger_root,
        ledger,
        repository,
        trusted,
    )
    monkeypatch.delenv("GIT_DIR")
    monkeypatch.delenv("GIT_OBJECT_DIRECTORY")

    validator_target.write_bytes(Path(validator.__file__).read_bytes() + b"\n# mutation\n")
    git("add", ".")
    git("commit", "-q", "-m", "candidate mutation")
    candidate = git("rev-parse", "HEAD")
    candidate_tree = git("rev-parse", "HEAD^{tree}")
    ledger["source"]["parent_commit_sha"] = candidate
    ledger["source"]["parent_tree_sha"] = candidate_tree
    for contract in (
        ledger["schema_contracts"]["release_ledger"],
        ledger["schema_contracts"]["validator"],
        ledger["schema_contracts"]["repository_controls_collector"],
        ledger["ledger_signature"]["trusted_parent_anchor"],
    ):
        contract["trusted_parent_commit_sha"] = candidate
        contract["trusted_parent_tree_sha"] = candidate_tree
    with pytest.raises(
        validator.LedgerValidationError,
        match="validator tree entry is not exact",
    ):
        validator._validate_trusted_parent_contracts(
            ledger_root,
            ledger,
            repository,
            trusted,
        )

    validator_target.write_bytes(Path(validator.__file__).read_bytes())
    missing_tool = repository / "ops" / "build_pyz.py"
    missing_tool.unlink()
    git("add", ".")
    git("commit", "-q", "-m", "parent missing trusted build input")
    missing_parent = git("rev-parse", "HEAD")
    missing_tree = git("rev-parse", "HEAD^{tree}")
    ledger["source"]["parent_commit_sha"] = missing_parent
    ledger["source"]["parent_tree_sha"] = missing_tree
    for contract in (
        ledger["schema_contracts"]["release_ledger"],
        ledger["schema_contracts"]["validator"],
        ledger["schema_contracts"]["repository_controls_collector"],
        ledger["ledger_signature"]["trusted_parent_anchor"],
    ):
        contract["trusted_parent_commit_sha"] = missing_parent
        contract["trusted_parent_tree_sha"] = missing_tree
    with pytest.raises(
        validator.LedgerValidationError,
        match=r"build input ops/build_pyz\.py tree entry is not exact",
    ):
        validator._validate_trusted_parent_contracts(
            ledger_root,
            ledger,
            repository,
            trusted,
        )


def _first_party_parent_repository(
    tmp_path: Path,
) -> tuple[Path, str, str]:
    repository = tmp_path / "first-party-parent"
    repository.mkdir()

    def git(*arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    git("init", "-q")
    git("config", "user.name", "First Party Parent Test")
    git("config", "user.email", "first-party@example.invalid")
    shutil.copytree(
        ROOT / "evoom_guard",
        repository / "evoom_guard",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    git("add", ".")
    git("commit", "-q", "-m", "literal trusted parent")
    return (
        repository,
        git("rev-parse", "HEAD"),
        git("rev-parse", "HEAD^{tree}"),
    )


def test_first_party_verification_code_is_loaded_from_literal_parent_and_restored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, parent, parent_tree = _first_party_parent_repository(tmp_path)
    signing_target = repository / "evoom_guard" / "signing.py"
    signing_target.write_bytes(
        signing_target.read_bytes()
        + b"\n\ndef public_key_id(_path: str) -> str:\n"
        + b"    return 'sha256:' + ('0' * 64)\n"
    )
    subprocess.run(
        ["git", "-C", str(repository), "add", "evoom_guard/signing.py"],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "commit",
            "-q",
            "-m",
            "untrusted candidate mutation",
        ],
        check=True,
    )

    private = tmp_path / "signing.private.pem"
    public = tmp_path / "signing.public.pem"
    generate_keypair(str(private), str(public))
    ambient_signing = sys.modules["evoom_guard.signing"]
    expected_key_id = public_key_id(str(public))
    attacker_key_id = f"sha256:{'f' * 64}"
    monkeypatch.setattr(
        ambient_signing,
        "public_key_id",
        lambda _path: attacker_key_id,
    )

    contracts = validator._trusted_parent_contract_reference(
        repository,
        parent,
        parent_tree,
    )
    parent_signing_bytes = subprocess.check_output(
        [
            "git",
            "-C",
            str(repository),
            "show",
            f"{parent}:evoom_guard/signing.py",
        ]
    )
    with validator._trusted_parent_first_party(contracts):
        trusted_signing = sys.modules["evoom_guard.signing"]
        trusted_file = trusted_signing.__file__
        assert isinstance(trusted_file, str)
        trusted_origin = Path(trusted_file)
        assert trusted_signing is not ambient_signing
        assert trusted_origin.read_bytes() == parent_signing_bytes
        assert not validator._path_is_within(trusted_origin, repository)
        assert trusted_signing.public_key_id(str(public)) == expected_key_id

    assert sys.modules["evoom_guard.signing"] is ambient_signing
    assert ambient_signing.public_key_id(str(public)) == attacker_key_id


def test_first_party_snapshot_is_rechecked_when_validation_body_raises(
    tmp_path: Path,
) -> None:
    repository, parent, parent_tree = _first_party_parent_repository(tmp_path)
    contracts = validator._trusted_parent_contract_reference(
        repository,
        parent,
        parent_tree,
    )

    with pytest.raises(
        validator.LedgerValidationError,
        match="loaded trusted first-party module",
    ) as caught:
        with validator._trusted_parent_first_party(contracts):
            signing_file = sys.modules["evoom_guard.signing"].__file__
            assert isinstance(signing_file, str)
            signing_path = Path(signing_file)
            signing_path.write_bytes(signing_path.read_bytes() + b"\n# tampered\n")
            raise RuntimeError("primary validation failure")
    assert isinstance(caught.value.__cause__, RuntimeError)


def test_safe_python_roots_exclude_nested_runtime_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "candidate"
    nested_runtime = candidate / ".venv"
    nested_site = nested_runtime / "Lib" / "site-packages"
    external_runtime = tmp_path / "trusted-runtime"
    external_lib = external_runtime / "Lib"
    nested_site.mkdir(parents=True)
    external_lib.mkdir(parents=True)
    monkeypatch.setattr(validator.sys, "prefix", str(nested_runtime))
    monkeypatch.setattr(validator.sys, "base_prefix", str(external_runtime))
    monkeypatch.setattr(
        validator.sys,
        "path",
        [str(nested_site), str(external_lib)],
    )

    roots = validator._safe_python_roots(candidate)

    assert external_runtime in roots
    assert nested_runtime not in roots
    assert nested_site not in roots
    assert all(
        not validator._path_is_within(root, candidate)
        and not validator._path_is_within(candidate, root)
        for root in roots
    )


def test_trusted_imports_fail_closed_when_active_runtime_overlaps_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "candidate"
    nested_runtime = candidate / ".venv"
    nested_site = nested_runtime / "Lib" / "site-packages"
    fake_package = nested_site / "cryptography"
    fake_package.mkdir(parents=True)
    marker = tmp_path / "fake-cryptography-executed"
    (fake_package / "__init__.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(validator.sys, "prefix", str(nested_runtime))
    monkeypatch.setattr(validator.sys, "path", [str(nested_site)])
    expected_path = list(validator.sys.path)

    with pytest.raises(
        validator.LedgerValidationError,
        match="trusted Python runtime overlaps a blocked root",
    ):
        with validator._trusted_python_imports(
            import_root=None,
            blocked_roots=(candidate,),
        ):
            pytest.fail("overlapping runtime entered the trusted import context")

    assert validator.sys.path == expected_path
    assert not marker.exists()


def test_trusted_import_context_ignores_and_restores_fake_cryptography(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, parent, parent_tree = _first_party_parent_repository(tmp_path)
    contracts = validator._trusted_parent_contract_reference(
        repository,
        parent,
        parent_tree,
    )
    attacker = tmp_path / "attacker"
    package = attacker / "cryptography"
    package.mkdir(parents=True)
    marker = tmp_path / "fake-cryptography-executed"
    fake_file = package / "__init__.py"
    fake_file.write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    fake = types.ModuleType("cryptography")
    fake.__file__ = str(fake_file)
    fake.__spec__ = importlib.machinery.ModuleSpec(
        "cryptography",
        loader=None,
        origin=str(fake_file),
        is_package=True,
    )
    monkeypatch.setitem(sys.modules, "cryptography", fake)
    monkeypatch.syspath_prepend(str(attacker))

    with validator._trusted_parent_first_party(contracts):
        loaded = sys.modules["cryptography"]
        assert loaded is not fake
        loaded_file = Path(str(loaded.__file__))
        assert any(
            validator._path_is_within(loaded_file, Path(prefix))
            for prefix in {sys.prefix, sys.base_prefix}
        )
        assert not marker.exists()

    assert sys.modules["cryptography"] is fake
    assert not marker.exists()


def test_trusted_import_context_rejects_new_originless_modules(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ambient = types.ModuleType("candidate.synthetic")
    monkeypatch.setitem(sys.modules, "candidate.synthetic", ambient)
    with pytest.raises(
        validator.LedgerValidationError,
        match="module escaped trusted import roots",
    ):
        with validator._trusted_python_imports(
            import_root=None,
            blocked_roots=(tmp_path,),
        ):
            assert "candidate.synthetic" not in sys.modules
            sys.modules["late.synthetic"] = types.ModuleType("late.synthetic")
    assert sys.modules["candidate.synthetic"] is ambient
    assert "late.synthetic" not in sys.modules


def test_trusted_import_context_accepts_only_original_pyexpat_aliases(
    tmp_path: Path,
) -> None:
    with validator._trusted_python_imports(
        import_root=None,
        blocked_roots=(tmp_path,),
    ):
        pyexpat = importlib.import_module("pyexpat")
        assert sys.modules["pyexpat.errors"] is pyexpat.errors
        assert sys.modules["pyexpat.model"] is pyexpat.model

    with pytest.raises(
        validator.LedgerValidationError,
        match="module escaped trusted import roots",
    ):
        with validator._trusted_python_imports(
            import_root=None,
            blocked_roots=(tmp_path,),
        ):
            sys.modules["pyexpat.errors"] = types.ModuleType(
                "pyexpat.errors"
            )


def test_trusted_import_context_rebuilds_original_typing_aliases(
    tmp_path: Path,
) -> None:
    with validator._trusted_python_imports(
        import_root=None,
        blocked_roots=(tmp_path,),
    ):
        typing = importlib.import_module("typing")
        assert sys.modules["typing.io"] is typing.io
        assert sys.modules["typing.re"] is typing.re


def test_nested_trusted_import_context_retains_safe_rust_extension(
    tmp_path: Path,
) -> None:
    with validator._trusted_python_imports(
        import_root=None,
        blocked_roots=(tmp_path,),
    ):
        rust = importlib.import_module("cryptography.hazmat.bindings._rust")
        with validator._trusted_python_imports(
            import_root=None,
            blocked_roots=(tmp_path,),
        ):
            assert sys.modules["cryptography.hazmat.bindings._rust"] is rust


def test_retained_keys_are_bound_to_ids_and_external_anchor(
    tmp_path: Path,
) -> None:
    repository, parent, parent_tree = _first_party_parent_repository(tmp_path)
    contracts = validator._trusted_parent_contract_reference(
        repository,
        parent,
        parent_tree,
    )
    root = tmp_path / "retained"
    root.mkdir()
    ledger = _valid_ledger()
    public_bytes: list[bytes] = []
    for index, item in enumerate(ledger["trust_roots"]):
        private = tmp_path / f"root-{index}.pem"
        public = tmp_path / f"root-{index}.pub.pem"
        generate_keypair(str(private), str(public))
        target = root.joinpath(*PurePosixPath(item["public_key"]["path"]).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        data = public.read_bytes()
        target.write_bytes(data)
        item["key_id"] = public_key_id(str(public))
        public_bytes.append(data)

    ledger_private = tmp_path / "ledger.pem"
    external_public = tmp_path / "ledger.pub.pem"
    generate_keypair(str(ledger_private), str(external_public))
    retained_public = root.joinpath(
        *PurePosixPath(ledger["ledger_signature"]["public_key"]["path"]).parts
    )
    retained_public.parent.mkdir(parents=True, exist_ok=True)
    retained_public.write_bytes(external_public.read_bytes())
    trusted = validator._load_trusted_ledger_key(root, external_public)
    ledger["ledger_signature"]["key_id"] = trusted.key_id

    with validator._trusted_parent_first_party(contracts):
        validator._validate_keys_and_anchor(root, ledger, trusted)
        first = root.joinpath(
            *PurePosixPath(ledger["trust_roots"][0]["public_key"]["path"]).parts
        )
        first.write_bytes(public_bytes[1])
        with pytest.raises(
            validator.LedgerValidationError,
            match="root key ID",
        ):
            validator._validate_keys_and_anchor(root, ledger, trusted)
        first.write_bytes(public_bytes[0])
        retained_public.write_bytes(public_bytes[0])
        with pytest.raises(
            validator.LedgerValidationError,
            match="differs from external trusted key",
        ):
            validator._validate_keys_and_anchor(root, ledger, trusted)


def test_first_party_parent_tree_rejects_non_regular_git_entries(
    tmp_path: Path,
) -> None:
    repository, _parent, _parent_tree = _first_party_parent_repository(tmp_path)
    object_id = subprocess.run(
        ["git", "-C", str(repository), "hash-object", "-w", "--stdin"],
        input="signing.py",
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "update-index",
            "--add",
            "--cacheinfo",
            f"120000,{object_id},evoom_guard/linked.py",
        ],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "commit",
            "-q",
            "-m",
            "non-regular first-party entry",
        ],
        check=True,
    )
    parent = subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    tree = subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "HEAD^{tree}"],
        text=True,
    ).strip()
    contracts = validator._trusted_parent_contract_reference(
        repository,
        parent,
        tree,
    )
    with pytest.raises(
        validator.LedgerValidationError,
        match="non-regular blob",
    ):
        validator._read_trusted_first_party_tree(contracts)


def test_trusted_git_output_is_bounded_before_aggregation() -> None:
    with pytest.raises(
        validator.LedgerValidationError,
        match="bounded combined output limit",
    ):
        validator._run_bounded_subprocess(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'x' * 1048576)",
            ],
            environment=dict(os.environ),
            output_limit=128,
            timeout=5,
            label="adversarial Git output",
        )


def test_bounded_subprocess_rejects_descendant_inherited_output_pipes() -> None:
    started = time.monotonic()
    with pytest.raises(
        validator.LedgerValidationError,
        match="left bounded output pipes open",
    ):
        validator._run_bounded_subprocess(
            [
                sys.executable,
                "-c",
                (
                    "import subprocess,sys;"
                    "subprocess.Popen([sys.executable,'-c',"
                    "'import time;time.sleep(5)'])"
                ),
            ],
            environment=dict(os.environ),
            output_limit=128,
            timeout=1,
            label="adversarial inherited output",
        )
    assert time.monotonic() - started < 3


def test_git_blob_identity_uses_bounded_git_protocol(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (
        validator._git_blob_sha(b"")
        == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
    )
    monkeypatch.setattr(validator, "MAX_JSON_BYTES", 0)
    with pytest.raises(
        validator.LedgerValidationError,
        match="bounded size limit",
    ):
        validator._git_blob_sha(b"x")


def test_git_blob_identity_uses_the_frozen_bounded_git_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted = validator._resolve_trusted_git(ROOT)
    calls: list[tuple[Path, tuple[str, ...], str, int, bytes | None, Any]] = []

    def bounded_git(
        repository: Path,
        *arguments: str,
        label: str,
        output_limit: int,
        input_data: bytes | None = None,
        executable: Any = None,
    ) -> bytes:
        calls.append(
            (
                repository,
                arguments,
                label,
                output_limit,
                input_data,
                executable,
            )
        )
        return b"f2ba8f84ab5c1bce84a7b441cb1959cfc7093b7f\n"

    monkeypatch.setattr(validator, "_trusted_git", bounded_git)
    assert (
        validator._git_blob_sha(
            b"abc",
            repository=ROOT,
            executable=trusted,
        )
        == "f2ba8f84ab5c1bce84a7b441cb1959cfc7093b7f"
    )
    assert calls == [
        (
            trusted.path.parent,
            ("hash-object", "--stdin"),
            "blob identity",
            65,
            b"abc",
            trusted,
        )
    ]


@pytest.mark.parametrize(
    "output",
    (
        b"f2ba8f84ab5c1bce84a7b441cb1959cfc7093b7f",
        b"F2BA8F84AB5C1BCE84A7B441CB1959CFC7093B7F\n",
        b"f2ba8f84ab5c1bce84a7b441cb1959cfc7093b7f\nextra",
        b"0" * 64 + b"\n",
    ),
)
def test_git_blob_identity_rejects_noncanonical_trusted_git_output(
    output: bytes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        validator,
        "_trusted_git",
        lambda *_args, **_kwargs: output,
    )
    with pytest.raises(
        validator.LedgerValidationError,
        match="non-canonical SHA-1 blob identity",
    ):
        validator._git_blob_sha(
            b"abc",
            executable=validator._resolve_trusted_git(ROOT),
        )


def test_trusted_git_ignores_relative_path_and_freezes_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = validator._resolve_trusted_git()
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    fake = candidate / ("git.exe" if os.name == "nt" else "git")
    fake.write_bytes(b"candidate-controlled executable")
    if os.name != "nt":
        fake.chmod(0o755)
    monkeypatch.chdir(candidate)
    monkeypatch.setenv("PATH", f".{os.pathsep}{host.path.parent}")
    resolved = validator._resolve_trusted_git(candidate)
    assert resolved.path == host.path

    copied = tmp_path / ("trusted-git.exe" if os.name == "nt" else "trusted-git")
    shutil.copyfile(host.path, copied)
    if os.name != "nt":
        copied.chmod(0o755)
    data, identity = validator._read_trusted_executable(copied)
    frozen = validator._TrustedExecutable(
        path=copied,
        data=data,
        identity=identity,
        search_path=str(copied.parent),
        parent_chain=validator._directory_chain(
            copied.parent,
            label="test Git parent",
        ),
    )
    copied.write_bytes(bytes([data[0] ^ 1]) + data[1:])
    with pytest.raises(
        validator.LedgerValidationError,
        match="trusted Git executable changed",
    ):
        validator._require_trusted_executable_unchanged(frozen)


def test_trusted_git_rejects_path_directory_ancestor_of_repository(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = validator._resolve_trusted_git()
    ancestor = tmp_path / "path-ancestor"
    ancestor.mkdir()
    fake = ancestor / ("git.exe" if os.name == "nt" else "git")
    shutil.copyfile(host.path, fake)
    if os.name != "nt":
        fake.chmod(0o755)
    repository = ancestor / "repository"
    repository.mkdir()
    cwd = tmp_path / "disjoint-cwd"
    cwd.mkdir()
    synthetic_temp = tmp_path / "disjoint-temp"
    synthetic_temp.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(
        validator.tempfile,
        "gettempdir",
        lambda: str(synthetic_temp),
    )
    monkeypatch.setenv(
        "PATH",
        f"{ancestor}{os.pathsep}{host.path.parent}",
    )
    resolved = validator._resolve_trusted_git(repository)
    assert resolved.path == host.path


def test_trusted_executable_reader_accepts_hardlinked_system_git(
    tmp_path: Path,
) -> None:
    host = validator._resolve_trusted_git()
    copied = tmp_path / ("host-copy.exe" if os.name == "nt" else "host-copy")
    shutil.copyfile(host.path, copied)
    linked = tmp_path / ("git.exe" if os.name == "nt" else "git")
    try:
        os.link(copied, linked)
    except OSError:
        pytest.skip("hard links are unavailable for the host Git executable")
    data, identity = validator._read_trusted_executable(linked)
    assert data == host.data
    assert identity[2] == len(data)


def test_direct_validator_does_not_import_candidate_crypto_or_jsonschema(
    tmp_path: Path,
) -> None:
    isolated = tmp_path / "isolated"
    validator_path = isolated / "tools/ci/validate_release_ledger_v2.py"
    schema_path = (
        isolated
        / "tests/baseline/schema/release-ledger-v2.schema.json"
    )
    validator_path.parent.mkdir(parents=True)
    schema_path.parent.mkdir(parents=True)
    shutil.copyfile(Path(validator.__file__), validator_path)
    shutil.copyfile(SCHEMA_PATH, schema_path)
    crypto_marker = tmp_path / "crypto-marker"
    schema_marker = tmp_path / "jsonschema-marker"
    fake_crypto = validator_path.parent / "cryptography"
    fake_crypto.mkdir()
    (fake_crypto / "__init__.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(crypto_marker)!r}).write_text('bad', encoding='utf-8')\n",
        encoding="utf-8",
    )
    (validator_path.parent / "jsonschema.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(schema_marker)!r}).write_text('bad', encoding='utf-8')\n",
        encoding="utf-8",
    )
    draft = isolated / "draft.json"
    output = isolated / "canonical.json"
    draft.write_text("{}\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(validator_path),
            "canonicalize",
            str(draft),
            str(output),
        ],
        cwd=isolated,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 1
    assert not crypto_marker.exists()
    assert not schema_marker.exists()
    assert not output.exists()


def test_release_ledger_commands_require_isolated_python_bootstrap() -> None:
    validator_doc = (ROOT / "docs/RELEASE_LEDGER_V2.md").read_text(
        encoding="utf-8"
    )
    assembler_doc = (ROOT / "docs/RELEASE_LEDGER_V2_ASSEMBLY.md").read_text(
        encoding="utf-8"
    )
    checklist = (ROOT / "docs/RELEASE_GATE_CHECKLIST.md").read_text(
        encoding="utf-8"
    )
    assert "python tools/ci/validate_release_ledger_v2.py" not in (
        validator_doc + checklist
    )
    assert "python -I tools/ci/validate_release_ledger_v2.py" in validator_doc
    assert "python -I tools/ci/validate_release_ledger_v2.py" in checklist
    assert "python tools/ci/assemble_release_ledger_v2.py" not in assembler_doc
    assert "python -I tools/ci/assemble_release_ledger_v2.py" in assembler_doc


def test_schema_format_checkers_are_fail_closed() -> None:
    malformed_time = _valid_ledger()
    malformed_time["ledger_scope"]["created_utc"] = "2030-02-31T00:30:00Z"
    assert any(
        "is not a 'date-time'" in error
        for error in validator._schema_errors(malformed_time, _schema())
    )

    relative_uri = _valid_ledger()
    relative_uri["release"]["release_url"] = "/releases/v9.9.9"
    assert any(
        "is not a 'uri'" in error
        for error in validator._schema_errors(relative_uri, _schema())
    )


@pytest.mark.parametrize(
    "url",
    (
        "https://",
        "https:// bad",
        "https://example.invalid/evo-guard.pyz",
    ),
)
def test_bootstrap_guard_url_is_exact(url: str) -> None:
    ledger = _valid_ledger()
    ledger["toolchain"]["bootstrap_guard"]["url"] = url
    with pytest.raises(validator.LedgerValidationError):
        validator.validate_structure(ledger)


def test_attestation_predicate_uri_is_exact() -> None:
    ledger = _valid_ledger()
    ledger["attestations"]["source_producer"][
        "predicate_type"
    ] = "https://example.invalid/provenance"
    with pytest.raises(
        validator.LedgerValidationError,
        match="source_producer is not bound",
    ):
        validator._validate_attestations(ledger)


_TIMESTAMP_PATHS: tuple[tuple[str | int, ...], ...] = (
    ("ledger_scope", "created_utc"),
    ("release", "created_utc"),
    ("release", "published_utc"),
    ("repository_controls", "observed_utc"),
    ("tag_ci", "completed_utc"),
    ("tag_ci", "observed_utc"),
    ("marketplace", "observed_utc"),
    *(
        ("workflow_chain", index, field)
        for index in range(len(validator.PHASES))
        for field in ("started_utc", "completed_utc")
    ),
    *(
        ("control_evidence", name, "observed_utc")
        for name in (
            "source_external_controls",
            "artifact_external_controls",
            "publication_controls",
            "publication_ready",
        )
    ),
    *(
        ("attestations", name, "verified_utc")
        for name in (
            "source_producer",
            "build_provenance",
            "spdx_provenance",
            "sbom_provenance",
            "release",
        )
    ),
    *(
        (
            "repository_controls",
            "admission_secret_absence_after_publication",
            index,
            "observed_utc",
        )
        for index in range(2)
    ),
)


@pytest.mark.parametrize("path", _TIMESTAMP_PATHS)
def test_every_utc_timestamp_rejects_impossible_calendar_date(
    path: tuple[str | int, ...],
) -> None:
    ledger = _valid_ledger()
    target: Any = ledger
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = "2030-02-31T00:00:00Z"
    with pytest.raises(
        validator.LedgerValidationError,
        match="not an ISO date-time",
    ):
        validator._validate_timeline(ledger)


def test_inventory_rejects_unexpected_entry_during_bounded_scan(
    tmp_path: Path,
) -> None:
    (tmp_path / "unexpected").write_text("x", encoding="utf-8")
    with pytest.raises(
        validator.LedgerValidationError,
        match="unexpected file",
    ):
        validator._actual_inventory(
            tmp_path,
            expected_files=set(),
            expected_directories={"."},
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: value["workflow_chain"][1].update(
                {"started_utc": "2030-01-01T00:01:30Z"}
            ),
            "preceding phase",
        ),
        (
            lambda value: value["attestations"]["build_provenance"].update(
                {"verified_utc": "2030-01-01T00:09:30Z"}
            ),
            "outside E/F",
        ),
        (
            lambda value: value["repository_controls"].update(
                {"observed_utc": "2030-01-01T00:19:00Z"}
            ),
            "outside publication",
        ),
        (
            lambda value: value["tag_ci"].update(
                {
                    "completed_utc": "2030-01-01T00:26:00Z",
                    "observed_utc": "2030-01-01T00:24:00Z",
                }
            ),
            "observed before",
        ),
    ],
)
def test_timeline_mutations_fail_closed(mutation: Any, message: str) -> None:
    ledger = _valid_ledger()
    mutation(ledger)
    with pytest.raises(validator.LedgerValidationError, match=message):
        validator.validate_structure(ledger)


@pytest.mark.parametrize(
    "target_commit_utc",
    (
        "2029-12-31T23:59:00Z",
        "2030-01-02T00:00:00Z",
    ),
)
def test_release_created_utc_is_not_a_lifecycle_clock(
    target_commit_utc: str,
) -> None:
    ledger = _valid_ledger()
    ledger["release"]["created_utc"] = target_commit_utc

    validator.validate_structure(ledger)


@pytest.mark.parametrize(
    "published_utc",
    (
        "2030-01-01T00:14:59Z",
        "2030-01-01T00:22:01Z",
    ),
)
def test_release_publication_must_remain_inside_phase_h(
    published_utc: str,
) -> None:
    ledger = _valid_ledger()
    ledger["release"]["created_utc"] = "2029-12-31T23:59:00Z"
    ledger["release"]["published_utc"] = published_utc

    with pytest.raises(
        validator.LedgerValidationError,
        match="release publication must occur inside phase H",
    ):
        validator.validate_structure(ledger)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: value["artifacts"].pop(),
            "schema validation failed",
        ),
        (
            lambda value: value["release"].update({"unexpected": True}),
            "schema validation failed",
        ),
        (
            lambda value: value["workflow_chain"][0].update(
                {"workflow_path": ".github/workflows/release.yml"}
            ),
            "schema validation failed",
        ),
        (
            lambda value: value["source_admission"].update(
                {"negative_case_count": 10}
            ),
            "schema validation failed",
        ),
        (
            lambda value: value["repository_controls"][
                "activation_flags_after_publication"
            ].update({"publication": True}),
            "schema validation failed",
        ),
        (
            lambda value: value["attestations"].pop("spdx_provenance"),
            "schema validation failed",
        ),
    ],
)
def test_schema_mutations_fail_closed(
    mutation: Any,
    message: str,
) -> None:
    ledger = _valid_ledger()
    mutation(ledger)
    with pytest.raises(validator.LedgerValidationError, match=message):
        validator.validate_structure(ledger)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: value["release"].update({"commit_sha": _git("wrong")}),
            "immutable release does not bind",
        ),
        (
            lambda value: value["workflow_chain"][4]["dispatch_inputs"].update(
                {"source_admission_run_id": 9999}
            ),
            "phase E inputs",
        ),
        (
            lambda value: value["workflow_chain"][3].update({"workflow_id": 9999}),
            "phase D does not share",
        ),
        (
            lambda value: value["checksum_manifest"]["entries"][0].update(
                {"sha256": _sha("wrong")}
            ),
            "checksum entries",
        ),
        (
            lambda value: value["trust_roots"][1].update(
                {"key_id": value["trust_roots"][0]["key_id"]}
            ),
            "distinct key IDs",
        ),
        (
            lambda value: value["artifact_admission"].update(
                {"source_rsae_sha256": _sha("wrong")}
            ),
            "does not bind the retained RSAE",
        ),
        (
            lambda value: value["repository_controls"]["main_branch"].update(
                {"required_checks": ["test (3.12)"]}
            ),
            "schema validation failed",
        ),
        (
            lambda value: value["tag_ci"].update({"head_sha": _git("wrong")}),
            "tag CI does not bind",
        ),
        (
            lambda value: value["attestations"]["spdx_provenance"].update(
                {"subject_sha256": value["artifacts"][0]["sha256"]}
            ),
            "spdx_provenance does not bind",
        ),
        (
            lambda value: value["control_evidence"]["artifact_external_controls"][
                "materials"
            ][1].update({"sha256": _sha("wrong-f-asset")}),
            "artifact controls do not retain",
        ),
        (
            lambda value: value["control_evidence"]["publication_ready"]["materials"][
                0
            ].update({"sha256": _sha("wrong-h-asset")}),
            "publication-ready materials do not equal",
        ),
    ],
)
def test_cross_field_mutations_fail_closed(
    mutation: Any,
    message: str,
) -> None:
    ledger = _valid_ledger()
    mutation(ledger)
    with pytest.raises(validator.LedgerValidationError, match=message):
        validator.validate_structure(ledger)


def test_strict_json_rejects_duplicate_keys_and_nonfinite_numbers() -> None:
    with pytest.raises(
        validator.LedgerValidationError,
        match="duplicate JSON key: tag",
    ):
        validator._load_json_bytes(
            b'{"tag":"v9.9.9","tag":"v0.0.0"}',
            label="duplicate",
        )
    with pytest.raises(
        validator.LedgerValidationError,
        match="non-finite JSON number",
    ):
        validator._load_json_bytes(b'{"value":NaN}', label="nonfinite")


def test_actual_source_and_artifact_result_contracts_are_closed_world(
    tmp_path: Path,
) -> None:
    source_manifest = {
        "authentication": {"key_id": "sha256:" + "1" * 64},
        "record": {"sha256": "2" * 64},
        "producer_receipt": {"sha256": "3" * 64},
    }
    source_seal = {
        "format": "EVOGUARD_RELEASE_SOURCE_ADMISSION_V2",
        "ok": True,
        "sealed": True,
        "verified": True,
        "status": "SEALED",
        "bundle": "/runner/source-allow.rsae",
        "key_id": source_manifest["authentication"]["key_id"],
        "record_sha256": source_manifest["record"]["sha256"],
        "producer_receipt_sha256": source_manifest["producer_receipt"]["sha256"],
        "decision": "ALLOW",
        "admission": True,
        "provider_verified": True,
    }
    source_path = tmp_path / "source-seal.json"
    source_path.write_bytes(_release_cli_json(source_seal))
    validator._validate_source_result(
        tmp_path,
        {"path": source_path.name},
        manifest=source_manifest,
        sealed=True,
        bundle_name="source-allow.rsae",
        label="source seal",
    )
    source_seal["live_provider_reverification"] = True
    source_path.write_bytes(_release_cli_json(source_seal))
    with pytest.raises(validator.LedgerValidationError, match="keys are not exact"):
        validator._validate_source_result(
            tmp_path,
            {"path": source_path.name},
            manifest=source_manifest,
            sealed=True,
            bundle_name="source-allow.rsae",
            label="source seal",
        )

    artifact_manifest = {
        "artifact": {"kind": "file", "sha256": "4" * 64, "size": 9},
        "release_source": {"target_commit_sha": "5" * 40},
        "builder": {"workflow": "E"},
        "admitter": {"workflow": "F"},
        "authentication": {"key_id": "sha256:" + "6" * 64},
    }
    artifact_verify = {
        "format": "EVOGUARD_RELEASE_ARTIFACT_ADMISSION_V1",
        "ok": True,
        "verified": True,
        "status": "VERIFIED",
        "decision": "ALLOW",
        "admission": True,
        "artifact": artifact_manifest["artifact"],
        "release_source": artifact_manifest["release_source"],
        "builder": artifact_manifest["builder"],
        "admitter": artifact_manifest["admitter"],
        "key_id": artifact_manifest["authentication"]["key_id"],
        "verification_scope": "detached-offline-retained-provider-evidence",
        "live_provider_reverification": False,
    }
    artifact_path = tmp_path / "artifact-verify.json"
    artifact_path.write_bytes(_release_cli_json(artifact_verify))
    validator._validate_artifact_result(
        tmp_path,
        {"path": artifact_path.name},
        manifest=artifact_manifest,
        sealed=False,
        bundle_name="unused.raae",
        label="artifact verify",
    )
    artifact_verify["live_provider_reverification"] = True
    artifact_path.write_bytes(_release_cli_json(artifact_verify))
    with pytest.raises(validator.LedgerValidationError, match="actual F/G"):
        validator._validate_artifact_result(
            tmp_path,
            {"path": artifact_path.name},
            manifest=artifact_manifest,
            sealed=False,
            bundle_name="unused.raae",
            label="artifact verify",
        )


def test_release_result_loader_rejects_ambiguous_json(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "source-result.json"
    source_path.write_bytes(b'{"status":"SEALED","status":"VERIFIED"}\n')
    with pytest.raises(
        validator.LedgerValidationError,
        match="duplicate JSON key: status",
    ):
        validator._load_strict_json_descriptor(
            tmp_path,
            {"path": source_path.name},
            label="source result",
        )

    source_path.write_bytes(b'{"value":NaN}\n')
    with pytest.raises(
        validator.LedgerValidationError,
        match="non-finite JSON number",
    ):
        validator._load_strict_json_descriptor(
            tmp_path,
            {"path": source_path.name},
            label="source result",
        )


def test_actual_negative_records_require_exact_bytes_and_order(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source-negative.json"
    source.write_bytes(validator.canonical_json_bytes(validator.SOURCE_NEGATIVE_RESULT))
    validator._validate_source_negative_file(
        tmp_path,
        {"path": source.name},
        label="source negatives",
    )
    source.write_bytes(
        validator.canonical_json_bytes(
            {**validator.SOURCE_NEGATIVE_RESULT, "extra": "REJECTED"}
        )
    )
    with pytest.raises(validator.LedgerValidationError, match="eleven-case"):
        validator._validate_source_negative_file(
            tmp_path,
            {"path": source.name},
            label="source negatives",
        )

    artifact = tmp_path / "artifact-negative.txt"
    artifact.write_bytes(
        ("\n".join(validator.ARTIFACT_NEGATIVE_LINES) + "\n").encode("ascii")
    )
    validator._validate_artifact_negative_file(
        tmp_path,
        {"path": artifact.name},
        label="artifact negatives",
    )
    artifact.write_bytes(
        ("\n".join(reversed(validator.ARTIFACT_NEGATIVE_LINES)) + "\n").encode(
            "ascii"
        )
    )
    with pytest.raises(validator.LedgerValidationError, match="ordered seven-case"):
        validator._validate_artifact_negative_file(
            tmp_path,
            {"path": artifact.name},
            label="artifact negatives",
        )


def test_envelope_attestation_evidence_requires_exact_embedded_bytes(
    tmp_path: Path,
) -> None:
    ledger = _valid_ledger()
    attestation = ledger["attestations"]["build_provenance"]
    receipt = b'{"receipt":"exact"}\n'
    output = b'[{"output":"exact"}]\n'
    for descriptor, data in (
        (attestation["verification_receipt"], receipt),
        (attestation["verification_output"], output),
    ):
        path = tmp_path / Path(*PurePosixPath(descriptor["path"]).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    validator._require_embedded_attestation_evidence(
        tmp_path,
        ledger,
        attestation_name="build_provenance",
        embedded_receipt=receipt,
        embedded_output=output,
        envelope_label="pyz RAAE",
    )
    with pytest.raises(
        validator.LedgerValidationError,
        match="exact provider evidence embedded in pyz RAAE",
    ):
        validator._require_embedded_attestation_evidence(
            tmp_path,
            ledger,
            attestation_name="build_provenance",
            embedded_receipt=receipt + b" ",
            embedded_output=output,
            envelope_label="pyz RAAE",
        )


def _raw_attestation(
    ledger: dict[str, Any],
    name: str,
    *,
    subject_sha256: str,
    predicate: dict[str, Any] | None = None,
) -> bytes:
    attestation = ledger["attestations"][name]
    repository = ledger["release"]["repository"]
    source = ledger["source"]["candidate_commit_sha"]
    workflow_path = attestation["signer_workflow"]
    expected_event = (
        "workflow_run" if name == "source_producer" else "workflow_dispatch"
    )
    repository_id = ledger["release"]["repository_id"]
    signer_uri = (
        f"https://github.com/{repository}/{workflow_path}@refs/heads/main"
    )
    run_uri = (
        f"https://github.com/{repository}/actions/runs/{attestation['run_id']}/"
        f"attempts/{attestation['run_attempt']}"
    )
    if predicate is None:
        predicate = {
            "buildDefinition": {
                "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                "externalParameters": {
                    "workflow": {
                        "repository": f"https://github.com/{repository}",
                        "ref": "refs/heads/main",
                        "path": workflow_path,
                    }
                },
                "internalParameters": {
                    "github": {
                        "event_name": expected_event,
                        "repository_id": repository_id,
                        "repository_owner_id": ledger["release"][
                            "repository_owner_id"
                        ],
                        "runner_environment": "github-hosted",
                    }
                },
                "resolvedDependencies": [
                    {
                        "uri": (
                            f"git+https://github.com/{repository}@refs/heads/main"
                        ),
                        "digest": {"gitCommit": source},
                    }
                ],
            },
            "runDetails": {
                "builder": {"id": signer_uri},
                "metadata": {"invocationId": run_uri},
            },
        }
    value = [
        {
            "attestation": {"opaque": "provider-verified"},
            "verificationResult": {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "signature": {
                    "certificate": {
                        "certificateIssuer": (
                            "CN=sigstore-intermediate,O=sigstore.dev"
                        ),
                        "subjectAlternativeName": signer_uri,
                        "issuer": "https://token.actions.githubusercontent.com",
                        "githubWorkflowTrigger": expected_event,
                        "githubWorkflowRepository": repository,
                        "githubWorkflowSHA": source,
                        "githubWorkflowName": "EvoGuard release artifact builder",
                        "githubWorkflowRef": "refs/heads/main",
                        "buildSignerURI": signer_uri,
                        "buildSignerDigest": source,
                        "runnerEnvironment": "github-hosted",
                        "sourceRepositoryURI": f"https://github.com/{repository}",
                        "sourceRepositoryDigest": source,
                        "sourceRepositoryRef": "refs/heads/main",
                        "sourceRepositoryIdentifier": repository_id,
                        "sourceRepositoryOwnerURI": (
                            "https://github.com/EvoRiseKsa"
                        ),
                        "sourceRepositoryOwnerIdentifier": ledger["release"][
                            "repository_owner_id"
                        ],
                        "buildConfigURI": signer_uri,
                        "buildConfigDigest": source,
                        "buildTrigger": expected_event,
                        "runInvocationURI": run_uri,
                        "sourceRepositoryVisibilityAtSigning": "public",
                    }
                },
                "verifiedTimestamps": [
                    {
                        "type": "Tlog",
                        "uri": "https://rekor.sigstore.dev",
                        "timestamp": "2030-01-01T00:12:00Z",
                    }
                ],
                "verifiedIdentity": {
                    "subjectAlternativeName": {
                        "subjectAlternativeName": "",
                        "regexp": (
                            f"^https://github.com/{repository}/{workflow_path}"
                        ),
                    },
                    "issuer": {
                        "issuer": "",
                        "regexp": ".*",
                    },
                    "runnerEnvironment": "github-hosted",
                },
                "statement": {
                    "_type": "https://in-toto.io/Statement/v1",
                    "subject": [
                        {
                            "name": attestation["subject_name"],
                            "digest": {"sha256": subject_sha256},
                        }
                    ],
                    "predicateType": attestation["predicate_type"],
                    "predicate": predicate,
                },
            },
        }
    ]
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _update_matching_descriptor(
    value: object,
    *,
    path: str,
    data: bytes,
) -> None:
    if isinstance(value, dict):
        if (
            value.get("path") == path
            and "size_bytes" in value
            and "sha256" in value
        ):
            value["size_bytes"] = len(data)
            value["sha256"] = hashlib.sha256(data).hexdigest()
            if "github_digest" in value:
                value["github_digest"] = f"sha256:{value['sha256']}"
        for child in value.values():
            _update_matching_descriptor(child, path=path, data=data)
    elif isinstance(value, list):
        for child in value:
            _update_matching_descriptor(child, path=path, data=data)


def test_attestation_receipts_bind_subject_policy_and_output(
    tmp_path: Path,
) -> None:
    ledger = _valid_ledger()
    descriptors = validator._collect_descriptors(ledger)
    producer = next(
        descriptor
        for path, descriptor in descriptors.items()
        if path.endswith("/producer-receipt.json")
    )
    pyz = ledger["artifacts"][0]
    spdx = ledger["artifacts"][1]
    subjects = {
        "source_producer": {"sha256": producer[1], "size": producer[0]},
        "build_provenance": {
            "sha256": pyz["sha256"],
            "size": pyz["size_bytes"],
        },
        "spdx_provenance": {
            "sha256": spdx["sha256"],
            "size": spdx["size_bytes"],
        },
        "sbom_provenance": {
            "sha256": pyz["sha256"],
            "size": pyz["size_bytes"],
        },
    }
    spdx_document = {"SPDXID": "SPDXRef-DOCUMENT", "spdxVersion": "SPDX-2.3"}
    spdx_bytes = validator.canonical_json_bytes(spdx_document)
    spdx_path = tmp_path / Path(*PurePosixPath(spdx["path"]).parts)
    spdx_path.parent.mkdir(parents=True, exist_ok=True)
    spdx_path.write_bytes(spdx_bytes)
    _update_matching_descriptor(
        ledger,
        path=spdx["path"],
        data=spdx_bytes,
    )
    ledger["attestations"]["spdx_provenance"]["subject_sha256"] = spdx["sha256"]
    subjects["spdx_provenance"] = {
        "sha256": spdx["sha256"],
        "size": spdx["size_bytes"],
    }
    for name, subject in subjects.items():
        attestation = ledger["attestations"][name]
        output_path = tmp_path / Path(
            *PurePosixPath(attestation["verification_output"]["path"]).parts
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_bytes = _raw_attestation(
            ledger,
            name,
            subject_sha256=subject["sha256"],
            predicate=spdx_document if name == "sbom_provenance" else None,
        )
        output_path.write_bytes(output_bytes)
        _update_matching_descriptor(
            ledger,
            path=attestation["verification_output"]["path"],
            data=output_bytes,
        )
        policy = {
            "repository": "EvoRiseKsa/EvoOM-Guard-m",
            "signer_workflow": (
                "EvoRiseKsa/EvoOM-Guard-m/"
                f"{attestation['signer_workflow']}"
            ),
            "signer_digest": ledger["source"]["candidate_commit_sha"],
            "source_ref": "refs/heads/main",
            "source_digest": ledger["source"]["candidate_commit_sha"],
            "cert_oidc_issuer": "https://token.actions.githubusercontent.com",
            "predicate_type": attestation["predicate_type"],
            "deny_self_hosted_runners": True,
            "attestation_limit": 1,
        }
        output_descriptor = {
            "sha256": attestation["verification_output"]["sha256"],
            "size": attestation["verification_output"]["size_bytes"],
            "verified_attestation_count": 1,
        }
        receipt: dict[str, Any] = {
            "format": "EVOGUARD_GITHUB_ATTESTATION_RECEIPT_V1",
            "artifact": subject,
            "verification_policy": policy,
            "verification_output": output_descriptor,
        }
        if name == "sbom_provenance":
            receipt = {
                "format": "EVOGUARD_GITHUB_SPDX_ATTESTATION_RECEIPT_V1",
                "artifact": {
                    "name": attestation["subject_name"],
                    **subject,
                },
                "predicate": {
                    "name": spdx["name"],
                    "sha256": spdx["sha256"],
                    "size": spdx["size_bytes"],
                    "type": "https://spdx.dev/Document/v2.3",
                },
                "verification_policy": {
                    **policy,
                    "repository_id": ledger["release"]["repository_id"],
                    "repository_owner_id": ledger["release"]["repository_owner_id"],
                },
                "workflow_run": {
                    "id": attestation["run_id"],
                    "attempt": attestation["run_attempt"],
                    "event": "workflow_dispatch",
                },
                "verification_output": output_descriptor,
            }
        receipt_bytes = validator.canonical_json_bytes(receipt)
        receipt_path = tmp_path / Path(
            *PurePosixPath(attestation["verification_receipt"]["path"]).parts
        )
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_bytes(receipt_bytes)
        _update_matching_descriptor(
            ledger,
            path=attestation["verification_receipt"]["path"],
            data=receipt_bytes,
        )

    validator._validate_attestation_bytes(tmp_path, ledger)
    receipt_path = tmp_path / Path(
        *PurePosixPath(
            ledger["attestations"]["build_provenance"]["verification_receipt"][
                "path"
            ]
        ).parts
    )
    forged = json.loads(receipt_path.read_text(encoding="utf-8"))
    forged["artifact"]["sha256"] = _sha("wrong-subject")
    receipt_path.write_bytes(validator.canonical_json_bytes(forged))
    with pytest.raises(validator.LedgerValidationError, match="does not bind"):
        validator._validate_attestation_bytes(tmp_path, ledger)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: value[0].update({"unexpected": True}),
            "entry keys are not exact",
        ),
        (
            lambda value: value[0]["verificationResult"]["statement"].update(
                {
                    "subject": [
                        value[0]["verificationResult"]["statement"]["subject"][0],
                        value[0]["verificationResult"]["statement"]["subject"][0],
                    ]
                }
            ),
            "exactly one subject",
        ),
        (
            lambda value: value[0]["verificationResult"]["statement"][
                "predicate"
            ]["buildDefinition"]["resolvedDependencies"].append(
                value[0]["verificationResult"]["statement"]["predicate"][
                    "buildDefinition"
                ]["resolvedDependencies"][0]
            ),
            "resolved dependency set is not exact",
        ),
        (
            lambda value: value[0]["verificationResult"]["signature"][
                "certificate"
            ].update(
                {
                    "runInvocationURI": (
                        "https://github.com/EvoRiseKsa/EvoOM-Guard-m/"
                        "actions/runs/999999/attempts/1"
                    )
                }
            ),
            "run ID/attempt",
        ),
        (
            lambda value: value[0]["verificationResult"]["statement"].update(
                {"predicateType": "https://example.invalid/predicate"}
            ),
            "predicateType",
        ),
        (
            lambda value: value[0]["verificationResult"]["statement"][
                "predicate"
            ]["buildDefinition"]["externalParameters"]["workflow"].update(
                {"path": "/.github/workflows/evoguard-build-release-artifact.yml"}
            ),
            "workflow parameters are not exact",
        ),
        (
            lambda value: value[0]["verificationResult"]["statement"][
                "predicate"
            ]["buildDefinition"].update(
                {"buildType": "https://example.invalid/build-type"}
            ),
            "build type",
        ),
        (
            lambda value: value[0]["verificationResult"]["statement"][
                "predicate"
            ]["buildDefinition"]["internalParameters"]["github"].update(
                {"event_name": "workflow_run"}
            ),
            "GitHub identity is not exact",
        ),
        (
            lambda value: value[0]["verificationResult"]["statement"][
                "predicate"
            ]["buildDefinition"]["internalParameters"]["github"].update(
                {"repository_id": "1001"}
            ),
            "GitHub identity is not exact",
        ),
        (
            lambda value: value[0]["verificationResult"]["signature"][
                "certificate"
            ].update({"sourceRepositoryIdentifier": "1001"}),
            "certificate does not bind",
        ),
        (
            lambda value: value[0]["verificationResult"]["signature"][
                "certificate"
            ].update({"sourceRepositoryOwnerIdentifier": "1003"}),
            "certificate repository owner ID is not exact",
        ),
        (
            lambda value: value[0]["verificationResult"]["verifiedIdentity"][
                "subjectAlternativeName"
            ].update({"regexp": r"^https://attacker\.invalid/.*$"}),
            "verified identity is not GitHub-hosted",
        ),
        (
            lambda value: value[0]["verificationResult"]["verifiedIdentity"][
                "issuer"
            ].update({"regexp": r"^https://attacker\.invalid$"}),
            "verified identity is not GitHub-hosted",
        ),
    ],
)
def test_strict_slsa_raw_attestation_rejects_ambiguity(
    mutation: Any,
    message: str,
) -> None:
    ledger = _valid_ledger()
    attestation = ledger["attestations"]["build_provenance"]
    artifact = ledger["artifacts"][0]
    value = json.loads(
        _raw_attestation(
            ledger,
            "build_provenance",
            subject_sha256=artifact["sha256"],
        )
    )
    mutation(value)
    data = (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    with pytest.raises(validator.LedgerValidationError, match=message):
        validator._validate_slsa_raw_output(
            data,
            repository=ledger["release"]["repository"],
            repository_id=ledger["release"]["repository_id"],
            repository_owner_id=ledger["release"]["repository_owner_id"],
            workflow_path=attestation["signer_workflow"],
            source_digest=ledger["source"]["candidate_commit_sha"],
            run_id=attestation["run_id"],
            run_attempt=attestation["run_attempt"],
            expected_event="workflow_dispatch",
            subject_name=attestation["subject_name"],
            subject_sha256=artifact["sha256"],
            subject_size=artifact["size_bytes"],
            label="test SLSA output",
        )


def test_gh_2_90_provider_metadata_shape_is_accepted() -> None:
    ledger = _valid_ledger()
    attestation = ledger["attestations"]["build_provenance"]
    artifact = ledger["artifacts"][0]
    data = _raw_attestation(
        ledger,
        "build_provenance",
        subject_sha256=artifact["sha256"],
    )
    decoded = json.loads(data)
    result = decoded[0]["verificationResult"]
    assert set(result) == {
        "mediaType",
        "signature",
        "verifiedTimestamps",
        "verifiedIdentity",
        "statement",
    }
    assert result["statement"]["predicate"]["buildDefinition"]["externalParameters"][
        "workflow"
    ]["path"] == attestation["signer_workflow"]

    validator._validate_slsa_raw_output(
        data,
        repository=ledger["release"]["repository"],
        repository_id=ledger["release"]["repository_id"],
        repository_owner_id=ledger["release"]["repository_owner_id"],
        workflow_path=attestation["signer_workflow"],
        source_digest=ledger["source"]["candidate_commit_sha"],
        run_id=attestation["run_id"],
        run_attempt=attestation["run_attempt"],
        expected_event="workflow_dispatch",
        subject_name=attestation["subject_name"],
        subject_sha256=artifact["sha256"],
        subject_size=artifact["size_bytes"],
        label="gh 2.90 representative output",
    )


@pytest.mark.parametrize("attestation_name", ["build_provenance", "sbom_provenance"])
def test_gh_2_97_go_quoted_identity_prefix_is_accepted(
    attestation_name: str,
) -> None:
    ledger = _valid_ledger()
    attestation = ledger["attestations"][attestation_name]
    artifact = ledger["artifacts"][0]
    data = _raw_attestation(
        ledger,
        attestation_name,
        subject_sha256=artifact["sha256"],
    )
    decoded = json.loads(data)
    workflow = (
        f"{ledger['release']['repository']}/{attestation['signer_workflow']}"
    )
    patterns = validator._github_identity_regexp_candidates(
        f"https://github.com/{workflow}"
    )
    decoded[0]["verificationResult"]["verifiedIdentity"][
        "subjectAlternativeName"
    ]["regexp"] = patterns[1]
    quoted = (
        json.dumps(decoded, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    common = {
        "repository": ledger["release"]["repository"],
        "repository_id": ledger["release"]["repository_id"],
        "repository_owner_id": ledger["release"]["repository_owner_id"],
        "workflow_path": attestation["signer_workflow"],
        "source_digest": ledger["source"]["candidate_commit_sha"],
        "run_id": attestation["run_id"],
        "run_attempt": attestation["run_attempt"],
        "expected_event": "workflow_dispatch",
        "subject_name": attestation["subject_name"],
        "subject_sha256": artifact["sha256"],
    }
    if attestation_name == "build_provenance":
        validator._validate_slsa_raw_output(
            quoted,
            **common,
            subject_size=artifact["size_bytes"],
            label="gh 2.97 representative SLSA output",
        )
    else:
        validator._validate_spdx_raw_output(
            quoted,
            **common,
            spdx_predicate=decoded[0]["verificationResult"]["statement"][
                "predicate"
            ],
            label="gh 2.97 representative SPDX output",
        )


def test_strict_spdx_attestation_binds_exact_predicate_bytes() -> None:
    ledger = _valid_ledger()
    attestation = ledger["attestations"]["sbom_provenance"]
    artifact = ledger["artifacts"][0]
    predicate = {"SPDXID": "SPDXRef-DOCUMENT", "spdxVersion": "SPDX-2.3"}
    data = _raw_attestation(
        ledger,
        "sbom_provenance",
        subject_sha256=artifact["sha256"],
        predicate=predicate,
    )
    validator._validate_spdx_raw_output(
        data,
        repository=ledger["release"]["repository"],
        repository_id=ledger["release"]["repository_id"],
        repository_owner_id=ledger["release"]["repository_owner_id"],
        workflow_path=attestation["signer_workflow"],
        source_digest=ledger["source"]["candidate_commit_sha"],
        run_id=attestation["run_id"],
        run_attempt=attestation["run_attempt"],
        expected_event="workflow_dispatch",
        subject_name=attestation["subject_name"],
        subject_sha256=artifact["sha256"],
        spdx_predicate=predicate,
        label="test SPDX output",
    )
    with pytest.raises(validator.LedgerValidationError, match="does not equal"):
        validator._validate_spdx_raw_output(
            data,
            repository=ledger["release"]["repository"],
            repository_id=ledger["release"]["repository_id"],
            repository_owner_id=ledger["release"]["repository_owner_id"],
            workflow_path=attestation["signer_workflow"],
            source_digest=ledger["source"]["candidate_commit_sha"],
            run_id=attestation["run_id"],
            run_attempt=attestation["run_attempt"],
            expected_event="workflow_dispatch",
            subject_name=attestation["subject_name"],
            subject_sha256=artifact["sha256"],
            spdx_predicate={"SPDXID": "SPDXRef-OTHER"},
            label="test SPDX output",
        )
    forged = json.loads(data)
    forged[0]["verificationResult"]["verifiedIdentity"]["subjectAlternativeName"][
        "regexp"
    ] = r"^https://attacker\.invalid/.*$"
    forged_data = (
        json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    with pytest.raises(
        validator.LedgerValidationError,
        match="verified identity is not GitHub-hosted",
    ):
        validator._validate_spdx_raw_output(
            forged_data,
            repository=ledger["release"]["repository"],
            repository_id=ledger["release"]["repository_id"],
            repository_owner_id=ledger["release"]["repository_owner_id"],
            workflow_path=attestation["signer_workflow"],
            source_digest=ledger["source"]["candidate_commit_sha"],
            run_id=attestation["run_id"],
            run_attempt=attestation["run_attempt"],
            expected_event="workflow_dispatch",
            subject_name=attestation["subject_name"],
            subject_sha256=artifact["sha256"],
            spdx_predicate=predicate,
            label="test SPDX output",
        )


def test_publication_control_bytes_bind_assets_admissions_and_target(
    tmp_path: Path,
) -> None:
    ledger = _valid_ledger()
    bundle = ledger["control_evidence"]["publication_controls"]
    artifact_controls = ledger["control_evidence"]["artifact_external_controls"]
    phases = validator._phase_map(ledger)
    roots = {item["domain"]: item["key_id"] for item in ledger["trust_roots"]}
    toolchain = ledger["toolchain"]

    def artifact_material(filename: str) -> dict[str, Any]:
        return next(
            item
            for item in artifact_controls["materials"]
            if PurePosixPath(item["path"]).name == filename
        )

    verifier_descriptor = artifact_material("verify_spdx_attestation.py")
    verifier_bytes = b"# synthetic trusted SPDX verifier\n"
    verifier_path = tmp_path / Path(
        *PurePosixPath(verifier_descriptor["path"]).parts
    )
    verifier_path.parent.mkdir(parents=True, exist_ok=True)
    verifier_path.write_bytes(verifier_bytes)
    verifier_descriptor.update(
        {
            "size_bytes": len(verifier_bytes),
            "sha256": hashlib.sha256(verifier_bytes).hexdigest(),
        }
    )
    toolchain["trusted_build_inputs"]["spdx_attestation_verifier_blob_sha"] = (
        validator._git_blob_sha(verifier_bytes)
    )

    def retained_descriptor(filename: str) -> dict[str, Any]:
        descriptor = artifact_material(filename)
        return {
            "sha256": descriptor["sha256"],
            "size": descriptor["size_bytes"],
        }

    f_manifest = {
        "format": artifact_controls["format"],
        "artifacts": {
            filename: retained_descriptor(filename)
            for filename in ("evo-guard.pyz", "evo-guard.spdx.json")
        },
        "checksums": retained_descriptor("SHA256SUMS"),
        "release_source_admission": retained_descriptor("source-allow.rsae"),
        "release_version": ledger["project"]["version"],
        "repository": ledger["release"]["repository"],
        "repository_id": ledger["release"]["repository_id"],
        "target_sha": ledger["source"]["candidate_commit_sha"],
        "attestation_evidence": {
            filename: retained_descriptor(filename)
            for filename in (
                "build-provenance-verification.json",
                "build-provenance-verification-output.json",
                "spdx-provenance-verification.json",
                "spdx-provenance-verification-output.json",
                "sbom-attestation-receipt.json",
                "sbom-attestation-output.json",
            )
        },
        "external_settings": {
            "runtime": {
                "url": toolchain["bootstrap_guard"]["url"],
                "version": toolchain["bootstrap_guard"]["version"],
                "sha256": toolchain["bootstrap_guard"]["sha256"],
            },
            "toolchain": {
                "git_sha256": toolchain["git"]["sha256"],
                "gh_sha256": toolchain["github_cli"]["sha256"],
                "provider_uid": toolchain["provider_identities"][
                    "artifact_admission"
                ]["uid"],
                "provider_gid": toolchain["provider_identities"][
                    "artifact_admission"
                ]["gid"],
            },
            "source_admission": {
                "bootstrap_sha256": toolchain["bootstrap_guard"]["sha256"],
                "git_sha256": toolchain["git"]["sha256"],
                "gh_sha256": toolchain["github_cli"]["sha256"],
                "provider_uid": toolchain["provider_identities"]["source_admission"][
                    "uid"
                ],
                "provider_gid": toolchain["provider_identities"]["source_admission"][
                    "gid"
                ],
            },
            "publication": {
                "tag_deploy_key_fingerprint": ledger["repository_controls"][
                    "release_deploy_key"
                ]["fingerprint"],
            },
            "public_key_ids": {
                "release_artifact_admission_v1": roots[
                    "release-artifact-admission-v1"
                ],
                "release_source_admission_v2": roots[
                    "release-source-admission-v2"
                ],
                "trusted_finalizer": roots["trusted-finalizer"],
                "artifact_admission_v1": roots["artifact-admission-v1"],
                "artifact_digest_admission_v2": roots[
                    "artifact-digest-admission-v2"
                ],
                "release_source_finalizer_v1": roots[
                    "release-source-finalizer-v1"
                ],
            },
        },
        "trusted_tools": {
            "tools/ci/verify_spdx_attestation.py": toolchain[
                "trusted_build_inputs"
            ]["spdx_attestation_verifier_blob_sha"]
        },
        "workflows": {
            phase: {
                "workflow_repository": ledger["release"]["repository"],
                "workflow_repository_id": ledger["release"]["repository_id"],
                "workflow_id": str(phases[phase]["workflow_id"]),
                "workflow_path": phases[phase]["workflow_path"],
                "workflow_blob_sha": phases[phase]["workflow_blob_sha"],
                "workflow_run_id": str(phases[phase]["run_id"]),
                "workflow_run_attempt": phases[phase]["run_attempt"],
                "workflow_event": phases[phase]["event"],
                "workflow_ref": "refs/heads/main",
                "workflow_commit_sha": ledger["source"]["candidate_commit_sha"],
                "runner_class": "github-hosted",
            }
            for phase in ("E", "F")
        },
    }
    f_manifest_path = tmp_path / Path(
        *PurePosixPath(artifact_controls["manifest"]["path"]).parts
    )
    f_manifest_path.parent.mkdir(parents=True, exist_ok=True)
    f_manifest_bytes = validator.canonical_json_bytes(f_manifest)
    f_manifest_path.write_bytes(f_manifest_bytes)
    artifact_controls["manifest"]["size_bytes"] = len(f_manifest_bytes)
    artifact_controls["manifest"]["sha256"] = hashlib.sha256(
        f_manifest_bytes
    ).hexdigest()

    builder_descriptor = artifact_material("builder-controls.json")
    builder_controls = {
        "format": "EVOGUARD_RELEASE_ASSET_BUILDER_CONTROLS_V1",
        "artifacts": f_manifest["artifacts"],
        "checksums": f_manifest["checksums"],
        "release_source_admission": f_manifest["release_source_admission"],
        "release_version": ledger["project"]["version"],
        "repository": ledger["release"]["repository"],
        "source_created": "2030-01-01T00:13:00Z",
        "source_admission_run_attempt": phases["C"]["run_attempt"],
        "source_admission_run_id": str(phases["C"]["run_id"]),
        "target_sha": ledger["source"]["candidate_commit_sha"],
        "trusted_build_parent_sha": ledger["source"]["parent_commit_sha"],
        "trusted_build_parent_tree_sha": ledger["source"]["parent_tree_sha"],
        "trusted_build_tool_blobs": {
            "ops/build_pyz.py": toolchain["trusted_build_inputs"][
                "build_pyz_blob_sha"
            ],
            "ops/generate_spdx_sbom.py": toolchain["trusted_build_inputs"][
                "spdx_generator_blob_sha"
            ],
        },
        "build_container": {
            "reference": toolchain["runner_image"]["reference"],
            "sha256": toolchain["runner_image"]["sha256"],
            "network": toolchain["runner_image"]["network"],
        },
    }
    builder_bytes = validator.canonical_json_bytes(builder_controls)
    builder_path = tmp_path / Path(*PurePosixPath(builder_descriptor["path"]).parts)
    builder_path.write_bytes(builder_bytes)
    builder_descriptor.update(
        {
            "size_bytes": len(builder_bytes),
            "sha256": hashlib.sha256(builder_bytes).hexdigest(),
        }
    )

    manifest = {
        "format": bundle["format"],
        "repository": ledger["release"]["repository"],
        "target_sha": ledger["source"]["candidate_commit_sha"],
        "release_version": ledger["project"]["version"],
        "f": {
            "workflow_id": str(phases["F"]["workflow_id"]),
            "workflow_blob_sha": phases["F"]["workflow_blob_sha"],
            "workflow_run_id": str(phases["F"]["run_id"]),
            "workflow_run_attempt": phases["F"]["run_attempt"],
        },
        "g": {
            "workflow_id": str(phases["G"]["workflow_id"]),
            "workflow_blob_sha": phases["G"]["workflow_blob_sha"],
            "workflow_run_id": str(phases["G"]["run_id"]),
            "workflow_run_attempt": phases["G"]["run_attempt"],
        },
        "f_control_manifest": {
            "sha256": artifact_controls["manifest"]["sha256"],
            "size": artifact_controls["manifest"]["size_bytes"],
        },
        "f_external_settings": f_manifest["external_settings"],
        "f_trusted_tools": f_manifest["trusted_tools"],
        "f_workflows": f_manifest["workflows"],
        "release_assets": {
            item["name"]: {
                "sha256": item["sha256"],
                "size": item["size_bytes"],
            }
            for item in ledger["artifacts"]
        },
        "admissions": {
            PurePosixPath(subject["raae"]["path"]).name: {
                "sha256": subject["raae"]["sha256"],
                "size": subject["raae"]["size_bytes"],
            }
            for subject in ledger["artifact_admission"]["subjects"]
        },
        "attestation_evidence": {
            PurePosixPath(item["path"]).name: {
                "sha256": item["sha256"],
                "size": item["size_bytes"],
            }
            for item in artifact_controls["materials"]
            if PurePosixPath(item["path"]).name
            in {
                "build-provenance-verification.json",
                "build-provenance-verification-output.json",
                "spdx-provenance-verification.json",
                "spdx-provenance-verification-output.json",
                "sbom-attestation-receipt.json",
                "sbom-attestation-output.json",
            }
        },
    }
    manifest_path = tmp_path / Path(
        *PurePosixPath(bundle["manifest"]["path"]).parts
    )
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_bytes(validator.canonical_json_bytes(manifest))

    publication_ready = ledger["control_evidence"]["publication_ready"]
    ready_manifest = {
        "format": publication_ready["format"],
        "repository": ledger["release"]["repository"],
        "target_sha": ledger["source"]["candidate_commit_sha"],
        "tag": ledger["release"]["tag"],
        "g_run_id": str(phases["G"]["run_id"]),
        "g_run_attempt": phases["G"]["run_attempt"],
        "tag_deploy_key_fingerprint": ledger["repository_controls"][
            "release_deploy_key"
        ]["fingerprint"],
        "host_tools": {
            "git": {
                "path": "/usr/bin/git",
                "sha256": toolchain["git"]["sha256"],
                "size": 1024,
            },
            "gh": {
                "path": "/usr/bin/gh",
                "sha256": toolchain["github_cli"]["sha256"],
                "size": 2048,
            },
            "ssh": {
                "path": "/usr/bin/ssh",
                "sha256": _sha("ssh"),
                "size": 3072,
            },
            "ssh_keygen": {
                "path": "/usr/bin/ssh-keygen",
                "sha256": _sha("ssh-keygen"),
                "size": 4096,
            },
        },
        "assets": {
            item["name"]: {
                "sha256": item["sha256"],
                "size": item["size_bytes"],
            }
            for item in ledger["artifacts"]
        },
    }
    ready_path = tmp_path / Path(
        *PurePosixPath(publication_ready["manifest"]["path"]).parts
    )
    ready_path.parent.mkdir(parents=True, exist_ok=True)
    ready_bytes = validator.canonical_json_bytes(ready_manifest)
    ready_path.write_bytes(ready_bytes)
    publication_ready["manifest"].update(
        {
            "size_bytes": len(ready_bytes),
            "sha256": hashlib.sha256(ready_bytes).hexdigest(),
        }
    )
    ledger["control_evidence"] = {
        "artifact_external_controls": artifact_controls,
        "publication_controls": bundle,
        "publication_ready": publication_ready,
    }

    validator._validate_control_bytes(tmp_path, ledger)

    artifact_mutations = (
        (
            lambda value: value["external_settings"]["runtime"].__setitem__(
                "version", "0.0.0"
            ),
            "artifact controls differ",
        ),
        (
            lambda value: value["trusted_tools"].__setitem__(
                "tools/ci/verify_spdx_attestation.py", "0" * 40
            ),
            "artifact controls differ",
        ),
        (
            lambda value: value["workflows"]["E"].__setitem__(
                "workflow_blob_sha", "0" * 40
            ),
            "exact phase E",
        ),
    )
    for mutate, message in artifact_mutations:
        forged = copy.deepcopy(f_manifest)
        mutate(forged)
        f_manifest_path.write_bytes(validator.canonical_json_bytes(forged))
        with pytest.raises(validator.LedgerValidationError, match=message):
            validator._validate_control_bytes(tmp_path, ledger)
    f_manifest_path.write_bytes(f_manifest_bytes)
    forged_builder = copy.deepcopy(builder_controls)
    forged_builder["trusted_build_tool_blobs"]["ops/build_pyz.py"] = "0" * 40
    builder_path.write_bytes(validator.canonical_json_bytes(forged_builder))
    with pytest.raises(validator.LedgerValidationError, match="E builder controls"):
        validator._validate_control_bytes(tmp_path, ledger)
    builder_path.write_bytes(builder_bytes)

    for tool_name in ("git", "gh", "ssh", "ssh_keygen"):
        for field, invalid in (
            ("path", "relative/tool"),
            ("sha256", "0" * 63),
            ("size", 0),
        ):
            forged = copy.deepcopy(ready_manifest)
            forged["host_tools"][tool_name][field] = invalid
            ready_path.write_bytes(validator.canonical_json_bytes(forged))
            with pytest.raises(
                validator.LedgerValidationError,
                match="publication-ready host tool",
            ):
                validator._validate_control_bytes(tmp_path, ledger)
    ready_mutations = (
        lambda value: value.__setitem__(
            "tag_deploy_key_fingerprint", "SHA256:" + ("B" * 43)
        ),
        lambda value: value["assets"]["evo-guard.pyz"].__setitem__(
            "sha256", _sha("wrong-ready-asset")
        ),
        lambda value: value["host_tools"].pop("ssh"),
    )
    for mutate in ready_mutations:
        forged = copy.deepcopy(ready_manifest)
        mutate(forged)
        ready_path.write_bytes(validator.canonical_json_bytes(forged))
        with pytest.raises(validator.LedgerValidationError, match="publication-ready"):
            validator._validate_control_bytes(tmp_path, ledger)
    ready_path.write_bytes(ready_bytes)

    mutations = (
        lambda value: value.__setitem__("release_version", "0.0.0"),
        lambda value: value["f_control_manifest"].__setitem__(
            "sha256", _sha("wrong-F-manifest")
        ),
        lambda value: value["f_external_settings"]["runtime"].__setitem__(
            "sha256", _sha("wrong-runtime")
        ),
        lambda value: value["f_external_settings"]["runtime"].__setitem__(
            "version", "0.0.0"
        ),
        lambda value: value["f_trusted_tools"].__setitem__(
            "tools/ci/verify_spdx_attestation.py", "0" * 40
        ),
        lambda value: value["f_workflows"]["E"].__setitem__(
            "workflow_blob_sha", "0" * 40
        ),
    )
    for mutate in mutations:
        forged = copy.deepcopy(manifest)
        mutate(forged)
        manifest_path.write_bytes(validator.canonical_json_bytes(forged))
        with pytest.raises(
            validator.LedgerValidationError,
            match="publication controls do not bind",
        ):
            validator._validate_control_bytes(tmp_path, ledger)
    manifest_path.write_bytes(validator.canonical_json_bytes(manifest))

    manifest["admissions"]["evo-guard.pyz.raae"]["sha256"] = _sha(
        "wrong-admission"
    )
    manifest_path.write_bytes(validator.canonical_json_bytes(manifest))
    with pytest.raises(
        validator.LedgerValidationError,
        match="do not bind the release assets",
    ):
        validator._validate_control_bytes(tmp_path, ledger)

    manifest["admissions"]["evo-guard.pyz.raae"]["sha256"] = ledger[
        "artifact_admission"
    ]["subjects"][0]["raae"]["sha256"]
    manifest.pop("target_sha")
    manifest_path.write_bytes(validator.canonical_json_bytes(manifest))
    with pytest.raises(
        validator.LedgerValidationError,
        match="manifest keys are not exact",
    ):
        validator._validate_control_bytes(tmp_path, ledger)


def test_canonicalize_refuses_overwrite_and_collects_no_evidence(
    tmp_path: Path,
) -> None:
    ledger = _valid_ledger()
    source = tmp_path / "draft.json"
    output = tmp_path / "canonical.json"
    source.write_text(json.dumps(ledger, indent=2), encoding="utf-8")

    validator._canonicalize(source, output)
    assert output.read_bytes() == validator.canonical_json_bytes(ledger)
    assert {item.name for item in tmp_path.iterdir()} == {
        "draft.json",
        "canonical.json",
    }
    with pytest.raises(validator.LedgerValidationError, match="refusing to overwrite"):
        validator._canonicalize(source, output)


def test_canonicalize_refuses_missing_output_parent(tmp_path: Path) -> None:
    source = tmp_path / "draft.json"
    source.write_text(json.dumps(_valid_ledger()), encoding="utf-8")
    with pytest.raises(
        validator.LedgerValidationError,
        match="cannot inspect canonical output parent component",
    ):
        validator._canonicalize(
            source,
            tmp_path / "missing" / "RELEASE_LEDGER.json",
        )


def test_repository_control_observation_is_closed_and_cross_bound(
    tmp_path: Path,
) -> None:
    ledger = _valid_ledger()
    value = _repository_control_observation(ledger)
    path = tmp_path / Path(
        *PurePosixPath(
            ledger["repository_controls"]["observation_evidence"]["path"]
        ).parts
    )
    path.parent.mkdir(parents=True)
    path.write_bytes(validator.canonical_json_bytes(value))
    validator._validate_repository_control_observation_bytes(tmp_path, ledger)

    value["observations"][0]["pages"][0]["http_status"] = 403
    path.write_bytes(validator.canonical_json_bytes(value))
    with pytest.raises(
        validator.LedgerValidationError,
        match="response metadata is not exact",
    ):
        validator._validate_repository_control_observation_bytes(tmp_path, ledger)

    value = _repository_control_observation(ledger)
    value["observations"][8]["pagination"]["observed_item_count"] = 101
    path.write_bytes(validator.canonical_json_bytes(value))
    with pytest.raises(
        validator.LedgerValidationError,
        match="pagination count",
    ):
        validator._validate_repository_control_observation_bytes(tmp_path, ledger)


@pytest.mark.parametrize(
    "case",
    [
        "window-before-h",
        "window-after-ledger",
        "observation-order",
        "repository-id",
        "consistent-repository-identity-substitution",
        "repository-id-string",
        "repository-owner-id-bool",
        "repository-owner-id-float",
        "repository-owner-login",
        "repository-owner-type",
        "repository-private",
        "repository-visibility",
        "repository-visibility-missing",
        "required-check-app",
        "actions-allowed",
        "immutable-disabled",
        "tag-exclude",
        "tag-rule-non-object",
        "deploy-key-algorithm",
        "deploy-key-unverified",
        "deploy-key-read-only-int",
        "deploy-key-enabled-int",
        "deploy-key-disabled",
        "second-deploy-key-read-only-int",
        "deploy-key-title-empty",
        "environment-reviewer-id",
        "environment-id",
        "environment-reviewer-rule-id",
        "environment-branch-rule-id",
        "environment-reviewer-type",
        "environment-policy-id",
        "activation-enabled",
        "page-status-float",
        "page-number-bool",
        "observation-query-float",
        "page-query-float",
        "pagination-page-count-float",
        "pagination-linked-last-bool",
        "repository-secret-present-first-page",
        "repository-secret-present-later-page",
        "secret-present-first-page",
        "secret-present-later-page",
        "secret-invalid-link-later-page",
    ],
)
def test_repository_control_v2_mutations_fail_closed(
    tmp_path: Path,
    case: str,
) -> None:
    ledger = _valid_ledger()
    value = _repository_control_observation(ledger)
    if case == "window-before-h":
        value["observed_window"]["started_utc"] = "2030-01-01T00:21:59Z"
    elif case == "window-after-ledger":
        value["observed_window"]["completed_utc"] = "2030-01-01T00:31:00Z"
    elif case == "observation-order":
        value["observations"][0], value["observations"][1] = (
            value["observations"][1],
            value["observations"][0],
        )
    elif case == "repository-id":
        value["observations"][0]["pages"][0]["body"]["id"] += 1
    elif case == "consistent-repository-identity-substitution":
        replacement_repository_id = validator.EXPECTED_REPOSITORY_ID + 1
        replacement_owner_id = validator.EXPECTED_REPOSITORY_OWNER_ID + 1
        ledger["release"]["repository_id"] = str(replacement_repository_id)
        ledger["release"]["repository_owner_id"] = str(replacement_owner_id)
        value["repository_id"] = replacement_repository_id
        value["repository_owner_id"] = replacement_owner_id
        value["observations"][0]["pages"][0]["body"]["id"] = (
            replacement_repository_id
        )
        value["observations"][0]["pages"][0]["body"]["owner"]["id"] = (
            replacement_owner_id
        )
    elif case == "repository-id-string":
        value["observations"][0]["pages"][0]["body"]["id"] = str(
            value["observations"][0]["pages"][0]["body"]["id"]
        )
    elif case == "repository-owner-id-bool":
        value["observations"][0]["pages"][0]["body"]["owner"]["id"] = True
    elif case == "repository-owner-id-float":
        value["observations"][0]["pages"][0]["body"]["owner"]["id"] = float(
            value["observations"][0]["pages"][0]["body"]["owner"]["id"]
        )
    elif case == "repository-owner-login":
        value["observations"][0]["pages"][0]["body"]["owner"]["login"] = "another"
    elif case == "repository-owner-type":
        value["observations"][0]["pages"][0]["body"]["owner"]["type"] = "Organization"
    elif case == "repository-private":
        value["observations"][0]["pages"][0]["body"]["private"] = True
    elif case == "repository-visibility":
        value["observations"][0]["pages"][0]["body"]["visibility"] = "internal"
    elif case == "repository-visibility-missing":
        del value["observations"][0]["pages"][0]["body"]["visibility"]
    elif case == "required-check-app":
        value["observations"][2]["pages"][0]["body"][
            "required_status_checks"
        ]["checks"][0]["app_id"] += 1
    elif case == "actions-allowed":
        value["observations"][3]["pages"][0]["body"]["allowed_actions"] = "selected"
    elif case == "immutable-disabled":
        value["observations"][5]["pages"][0]["body"]["enabled"] = False
    elif case == "tag-exclude":
        value["observations"][6]["pages"][0]["body"]["conditions"]["ref_name"][
            "exclude"
        ] = ["refs/tags/v0.*"]
    elif case == "tag-rule-non-object":
        value["observations"][6]["pages"][0]["body"]["rules"][0] = "creation"
    elif case == "deploy-key-algorithm":
        value["observations"][7]["pages"][0]["body"][0]["key"] = (
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7"
        )
    elif case == "deploy-key-unverified":
        value["observations"][7]["pages"][0]["body"][0]["verified"] = False
    elif case == "deploy-key-read-only-int":
        value["observations"][7]["pages"][0]["body"][0]["read_only"] = 0
    elif case == "deploy-key-enabled-int":
        value["observations"][7]["pages"][0]["body"][0]["enabled"] = 1
    elif case == "deploy-key-disabled":
        value["observations"][7]["pages"][0]["body"][0]["enabled"] = False
    elif case == "second-deploy-key-read-only-int":
        deploy_observation = value["observations"][7]
        second = copy.deepcopy(deploy_observation["pages"][0]["body"][0])
        second.update({"id": 5003, "title": "second key", "read_only": 0})
        deploy_observation["pages"][0]["body"].append(second)
        deploy_observation["pagination"]["observed_item_count"] = 2
    elif case == "deploy-key-title-empty":
        value["observations"][7]["pages"][0]["body"][0]["title"] = ""
    elif case == "environment-reviewer-id":
        value["observations"][8]["pages"][0]["body"]["environments"][0][
            "protection_rules"
        ][0]["reviewers"][0]["reviewer"]["id"] += 1
    elif case == "environment-id":
        value["observations"][8]["pages"][0]["body"]["environments"][0]["id"] += 1
    elif case == "environment-reviewer-rule-id":
        value["observations"][8]["pages"][0]["body"]["environments"][0][
            "protection_rules"
        ][0]["id"] += 1
    elif case == "environment-branch-rule-id":
        value["observations"][8]["pages"][0]["body"]["environments"][0][
            "protection_rules"
        ][1]["id"] += 1
    elif case == "environment-reviewer-type":
        value["observations"][8]["pages"][0]["body"]["environments"][0][
            "protection_rules"
        ][0]["reviewers"][0]["type"] = "Team"
    elif case == "environment-policy-id":
        value["observations"][9]["pages"][0]["body"]["branch_policies"][0]["id"] += 1
    elif case == "activation-enabled":
        value["observations"][13]["pages"][0]["body"]["value"] = "true"
    elif case == "page-status-float":
        value["observations"][0]["pages"][0]["http_status"] = 200.0
    elif case == "page-number-bool":
        value["observations"][0]["pages"][0]["number"] = True
    elif case == "observation-query-float":
        value["observations"][7]["query"]["per_page"] = 100.0
    elif case == "page-query-float":
        value["observations"][7]["pages"][0]["query"]["page"] = 1.0
    elif case == "pagination-page-count-float":
        value["observations"][7]["pagination"]["page_count"] = 1.0
    elif case == "pagination-linked-last-bool":
        value["observations"][7]["pagination"]["linked_last_page"] = True
    elif case == "repository-secret-present-first-page":
        observation = value["observations"][16]
        observation["pages"][0]["body"] = {
            "total_count": 1,
            "secrets": [
                {
                    "name": (
                        "EVOGUARD_RELEASE_SOURCE_ADMISSION_V2_PRIVATE_KEY_B64"
                    )
                }
            ],
        }
        observation["pagination"]["observed_item_count"] = 1
        observation["pagination"]["reported_total_count"] = 1
    elif case == "repository-secret-present-later-page":
        observation = value["observations"][16]
        secret_name = "EVOGUARD_RELEASE_SOURCE_ADMISSION_V2_PRIVATE_KEY_B64"
        endpoint = observation["endpoint"]
        observation["pages"][0]["body"] = {
            "total_count": 101,
            "secrets": [{"name": f"OTHER_{index:03d}"} for index in range(100)],
        }
        observation["pages"][0]["link_header"] = (
            f'<https://api.github.com{endpoint}?page=2&per_page=100>; rel="next", '
            f'<https://api.github.com{endpoint}?page=2&per_page=100>; rel="last"'
        )
        observation["pages"].append(
            {
                "body": {
                    "total_count": 101,
                    "secrets": [{"name": secret_name}],
                },
                "http_status": 200,
                "link_header": (
                    f'<https://api.github.com{endpoint}?page=1&per_page=100>; '
                    'rel="prev", '
                    f'<https://api.github.com{endpoint}?page=1&per_page=100>; '
                    'rel="first"'
                ),
                "number": 2,
                "query": {"page": 2, "per_page": 100},
            }
        )
        observation["pagination"].update(
            {
                "linked_last_page": 2,
                "observed_item_count": 101,
                "page_count": 2,
                "reported_total_count": 101,
            }
        )
    elif case == "secret-present-first-page":
        observation = value["observations"][17]
        observation["pages"][0]["body"] = {
            "total_count": 1,
            "secrets": [
                {
                    "name": (
                        "EVOGUARD_RELEASE_SOURCE_ADMISSION_V2_PRIVATE_KEY_B64"
                    )
                }
            ],
        }
        observation["pagination"]["observed_item_count"] = 1
        observation["pagination"]["reported_total_count"] = 1
    elif case == "secret-present-later-page":
        observation = value["observations"][17]
        secret_name = "EVOGUARD_RELEASE_SOURCE_ADMISSION_V2_PRIVATE_KEY_B64"
        first_secrets = [{"name": f"OTHER_{index:03d}"} for index in range(100)]
        observation["pages"][0]["body"] = {
            "total_count": 101,
            "secrets": first_secrets,
        }
        endpoint = observation["endpoint"]
        observation["pages"][0]["link_header"] = (
            f'<https://api.github.com{endpoint}?page=2&per_page=100>; rel="next", '
            f'<https://api.github.com{endpoint}?page=2&per_page=100>; rel="last"'
        )
        observation["pages"].append(
            {
                "body": {
                    "total_count": 101,
                    "secrets": [{"name": secret_name}],
                },
                "http_status": 200,
                "link_header": (
                    f'<https://api.github.com{endpoint}?page=1&per_page=100>; '
                    'rel="prev", '
                    f'<https://api.github.com{endpoint}?page=1&per_page=100>; '
                    'rel="first"'
                ),
                "number": 2,
                "query": {"page": 2, "per_page": 100},
            }
        )
        observation["pagination"].update(
            {
                "linked_last_page": 2,
                "observed_item_count": 101,
                "page_count": 2,
                "reported_total_count": 101,
            }
        )
    elif case == "secret-invalid-link-later-page":
        observation = value["observations"][17]
        first_secrets = [{"name": f"OTHER_{index:03d}"} for index in range(100)]
        observation["pages"][0]["body"] = {
            "total_count": 101,
            "secrets": first_secrets,
        }
        observation["pages"][0]["link_header"] = 'garbage; rel="next"'
        observation["pages"].append(
            {
                "body": {
                    "total_count": 101,
                    "secrets": [{"name": "OTHER_100"}],
                },
                "http_status": 200,
                "link_header": None,
                "number": 2,
                "query": {"page": 2, "per_page": 100},
            }
        )
        observation["pagination"].update(
            {
                "linked_last_page": 2,
                "observed_item_count": 101,
                "page_count": 2,
                "reported_total_count": 101,
            }
        )
    else:  # pragma: no cover - parametrization is closed above
        raise AssertionError(case)

    path = tmp_path / Path(
        *PurePosixPath(
            ledger["repository_controls"]["observation_evidence"]["path"]
        ).parts
    )
    path.parent.mkdir(parents=True)
    path.write_bytes(validator.canonical_json_bytes(value))
    with pytest.raises(validator.LedgerValidationError):
        validator._validate_repository_control_observation_bytes(tmp_path, ledger)


def test_repository_control_v2_accepts_exact_two_page_secret_traversal(
    tmp_path: Path,
) -> None:
    ledger = _valid_ledger()
    value = _repository_control_observation(ledger)
    observation = value["observations"][17]
    endpoint = observation["endpoint"]
    observation["pages"][0]["body"] = {
        "total_count": 101,
        "secrets": [{"name": f"OTHER_{index:03d}"} for index in range(100)],
    }
    observation["pages"][0]["link_header"] = (
        f'<https://api.github.com{endpoint}?page=2&per_page=100>; rel="next", '
        f'<https://api.github.com{endpoint}?page=2&per_page=100>; rel="last"'
    )
    observation["pages"].append(
        {
            "body": {
                "total_count": 101,
                "secrets": [{"name": "OTHER_100"}],
            },
            "http_status": 200,
            "link_header": (
                f'<https://api.github.com{endpoint}?page=1&per_page=100>; '
                'rel="prev", '
                f'<https://api.github.com{endpoint}?page=1&per_page=100>; '
                'rel="first"'
            ),
            "number": 2,
            "query": {"page": 2, "per_page": 100},
        }
    )
    observation["pagination"].update(
        {
            "linked_last_page": 2,
            "observed_item_count": 101,
            "page_count": 2,
            "reported_total_count": 101,
        }
    )
    path = tmp_path / Path(
        *PurePosixPath(
            ledger["repository_controls"]["observation_evidence"]["path"]
        ).parts
    )
    path.parent.mkdir(parents=True)
    path.write_bytes(validator.canonical_json_bytes(value))

    validator._validate_repository_control_observation_bytes(tmp_path, ledger)


@pytest.mark.parametrize(
    "url",
    [
        (
            "HTTPS://api.github.com/repos/EvoRiseKsa/EvoOM-Guard-m/"
            "actions/secrets?page=2&per_page=100"
        ),
        (
            "https://evil.example/repos/EvoRiseKsa/EvoOM-Guard-m/"
            "actions/secrets?page=2&per_page=100"
        ),
        (
            "https://api.github.com/repos/EvoRiseKsa/EvoOM-Guard-m/"
            "keys?page=2&per_page=100"
        ),
        (
            "https://api.github.com/repos/EvoRiseKsa/EvoOM-Guard-m/"
            "actions/secrets?per_page=100&page=2"
        ),
        (
            "https://api.github.com/repos/EvoRiseKsa/EvoOM-Guard-m/"
            "actions/secrets?page=02&per_page=100"
        ),
        (
            "https://api.github.com/repos/EvoRiseKsa/EvoOM-Guard-m/"
            "actions/secrets?page=2&per_page=100&token=secret"
        ),
    ],
)
def test_repository_control_v2_independently_rejects_nonliteral_links(
    url: str,
) -> None:
    endpoint = "/repos/EvoRiseKsa/EvoOM-Guard-m/actions/secrets"
    with pytest.raises(validator.LedgerValidationError):
        validator._control_link_relations(
            (
                f'<{url}>; rel="next", '
                f'<https://api.github.com{endpoint}?page=2&per_page=100>; '
                'rel="last"'
            ),
            endpoint=endpoint,
            page_number=1,
            repository_id=123456789,
            expected_last_page=None,
        )


def test_repository_control_v2_accepts_repository_id_link_alias() -> None:
    endpoint = "/repos/EvoRiseKsa/EvoOM-Guard-m/actions/secrets"
    relations, last = validator._control_link_relations(
        (
            "<https://api.github.com/repositories/123456789/actions/secrets"
            '?page=2&per_page=100>; rel="next", '
            "<https://api.github.com/repositories/123456789/actions/secrets"
            '?page=2&per_page=100>; rel="last"'
        ),
        endpoint=endpoint,
        page_number=1,
        repository_id=123456789,
        expected_last_page=None,
    )
    assert relations == {"next", "last"}
    assert last == 2


def test_key_retirement_is_post_ledger_cross_bound_and_signed(
    tmp_path: Path,
) -> None:
    ledger_root = tmp_path / "ledger"
    ledger_root.mkdir()
    private = tmp_path / "retirement.pem"
    public = tmp_path / "retirement.pub.pem"
    generate_keypair(str(private), str(public))
    trusted = validator._load_trusted_ledger_key(ledger_root, public)
    ledger = _valid_ledger()
    ledger["ledger_signature"]["key_id"] = trusted.key_id
    ledger_bytes = validator.canonical_json_bytes(ledger)
    ledger_signature_bytes = base64.b64encode(b"\0" * 64) + b"\n"
    value = _key_retirement_value(
        ledger,
        ledger_bytes=ledger_bytes,
        ledger_signature_bytes=ledger_signature_bytes,
        key_id=trusted.key_id,
    )
    validator._validate_key_retirement_value(
        value,
        ledger=ledger,
        ledger_bytes=ledger_bytes,
        ledger_signature_bytes=ledger_signature_bytes,
        trusted_key=trusted,
    )
    receipt = tmp_path / "KEY_RETIREMENT.json"
    receipt.write_bytes(validator.canonical_json_bytes(value))
    sign_file(str(receipt), str(private))
    signature = Path(f"{receipt}.sig").read_bytes()
    validator._verify_external_ledger_signature(
        receipt.read_bytes(),
        signature,
        trusted,
    )

    value["publication_authority"]["deploy_key"]["http_status"] = 404
    with pytest.raises(
        validator.LedgerValidationError,
        match="successful complete absence",
    ):
        validator._validate_key_retirement_value(
            value,
            ledger=ledger,
            ledger_bytes=ledger_bytes,
            ledger_signature_bytes=ledger_signature_bytes,
            trusted_key=trusted,
        )

    value = _key_retirement_value(
        ledger,
        ledger_bytes=ledger_bytes,
        ledger_signature_bytes=ledger_signature_bytes,
        key_id=trusted.key_id,
    )
    value["created_utc"] = ledger["ledger_scope"]["created_utc"]
    with pytest.raises(
        validator.LedgerValidationError,
        match="post-ledger window",
    ):
        validator._validate_key_retirement_value(
            value,
            ledger=ledger,
            ledger_bytes=ledger_bytes,
            ledger_signature_bytes=ledger_signature_bytes,
            trusted_key=trusted,
        )


def test_key_retirement_rejects_between_stage_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger_root = tmp_path / "ledger"
    ledger_root.mkdir()
    private = tmp_path / "retirement.pem"
    public = tmp_path / "retirement.pub.pem"
    generate_keypair(str(private), str(public))
    trusted = validator._load_trusted_ledger_key(ledger_root, public)
    ledger = _valid_ledger()
    ledger["ledger_signature"]["key_id"] = trusted.key_id
    ledger_path = ledger_root / "RELEASE_LEDGER.json"
    ledger_path.write_bytes(validator.canonical_json_bytes(ledger))
    sign_file(str(ledger_path), str(private))
    ledger_signature_path = Path(f"{ledger_path}.sig")
    receipt = tmp_path / "KEY_RETIREMENT.json"
    receipt.write_bytes(
        validator.canonical_json_bytes(
            _key_retirement_value(
                ledger,
                ledger_bytes=ledger_path.read_bytes(),
                ledger_signature_bytes=ledger_signature_path.read_bytes(),
                key_id=trusted.key_id,
            )
        )
    )
    sign_file(str(receipt), str(private))
    signature = Path(f"{receipt}.sig")
    monkeypatch.setattr(
        validator,
        "validate_directory",
        lambda *_: ledger,
    )
    original = validator._validate_key_retirement_value

    def mutate_after_semantics(*args: Any, **kwargs: Any) -> None:
        original(*args, **kwargs)
        receipt.write_bytes(receipt.read_bytes() + b" ")

    monkeypatch.setattr(
        validator,
        "_validate_key_retirement_value",
        mutate_after_semantics,
    )
    with pytest.raises(
        validator.LedgerValidationError,
        match="inputs changed",
    ):
        validator.validate_key_retirement(
            ledger_root,
            receipt,
            signature,
            public,
            tmp_path / "unused-parent",
        )


def _replace_file_descriptors(value: object, contents: dict[str, bytes]) -> None:
    if isinstance(value, dict):
        path = value.get("path")
        if (
            isinstance(path, str)
            and "size_bytes" in value
            and "sha256" in value
        ):
            data = contents[path]
            value["size_bytes"] = len(data)
            value["sha256"] = hashlib.sha256(data).hexdigest()
            if "github_digest" in value:
                value["github_digest"] = f"sha256:{value['sha256']}"
        for item in value.values():
            _replace_file_descriptors(item, contents)
    elif isinstance(value, list):
        for item in value:
            _replace_file_descriptors(item, contents)


def _signed_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path]:
    ledger_root = tmp_path / "ledger"
    ledger_root.mkdir()
    ledger = _valid_ledger()
    inventory = validator._collect_descriptors(ledger)
    contents = {path: f"{path}\n".encode() for path in inventory}
    contents["README.md"] = b"Synthetic ledger fixture.\n"
    asset_paths = {
        item["name"]: item["path"]
        for item in ledger["artifacts"]
    }
    contents[asset_paths["SHA256SUMS"]] = "".join(
        f"{hashlib.sha256(contents[asset_paths[name]]).hexdigest()}  {name}\n"
        for name in ("evo-guard.pyz", "evo-guard.spdx.json")
    ).encode("ascii")
    observation_path = ledger["repository_controls"]["observation_evidence"]["path"]
    contents[observation_path] = validator.canonical_json_bytes(
        _repository_control_observation(ledger)
    )

    key_directory = tmp_path / "_keys"
    key_directory.mkdir()
    for index, root in enumerate(ledger["trust_roots"]):
        private = key_directory / f"root-{index}.pem"
        public = key_directory / f"root-{index}.pub.pem"
        generate_keypair(str(private), str(public))
        root["key_id"] = public_key_id(str(public))
        contents[root["public_key"]["path"]] = public.read_bytes()

    signing_private = key_directory / "ledger.pem"
    signing_public = tmp_path / "trusted-release-ledger-v2.pub.pem"
    generate_keypair(str(signing_private), str(signing_public))
    ledger["ledger_signature"]["key_id"] = public_key_id(str(signing_public))
    contents[ledger["ledger_signature"]["public_key"]["path"]] = (
        signing_public.read_bytes()
    )
    ledger["ledger_signature"]["trusted_parent_anchor"].update(
        {
            "sha256": hashlib.sha256(signing_public.read_bytes()).hexdigest(),
            "git_blob_sha": validator._git_blob_sha(signing_public.read_bytes()),
        }
    )

    # Preserve the semantic key bindings after the synthetic roots receive real
    # key IDs. Envelope internals are independently tested by their owner
    # modules; this integration fixture exercises the ledger's byte inventory,
    # root identity, canonicalization, and detached signature.
    roots = {item["domain"]: item["key_id"] for item in ledger["trust_roots"]}
    ledger["source_admission"]["rsae"]["key_id"] = roots[
        "release-source-admission-v2"
    ]
    for subject in ledger["artifact_admission"]["subjects"]:
        subject["raae"]["key_id"] = roots["release-artifact-admission-v1"]

    _replace_file_descriptors(ledger, contents)
    by_asset = {item["name"]: item for item in ledger["artifacts"]}
    ledger["checksum_manifest"]["manifest_sha256"] = by_asset["SHA256SUMS"][
        "sha256"
    ]
    for entry in ledger["checksum_manifest"]["entries"]:
        entry["sha256"] = by_asset[entry["target"]]["sha256"]
    ledger["artifact_admission"]["source_rsae_sha256"] = ledger[
        "source_admission"
    ]["rsae"]["sha256"]
    for subject in ledger["artifact_admission"]["subjects"]:
        artifact = by_asset[subject["name"]]
        subject["artifact_sha256"] = artifact["sha256"]
        subject["artifact_size_bytes"] = artifact["size_bytes"]
    for name in ("build_provenance", "sbom_provenance"):
        ledger["attestations"][name]["subject_sha256"] = by_asset[
            "evo-guard.pyz"
        ]["sha256"]
    ledger["attestations"]["spdx_provenance"]["subject_sha256"] = by_asset[
        "evo-guard.spdx.json"
    ]["sha256"]
    ledger["attestations"]["source_producer"]["subject_sha256"] = hashlib.sha256(
        contents["controls/source/producer-receipt.json"]
    ).hexdigest()
    ledger["attestations"]["release"]["asset_subjects"] = [
        {"name": item["name"], "sha256": item["sha256"]}
        for item in ledger["artifacts"]
    ]

    # The full validator still executes every generic ledger check. These four
    # owners are replaced because their cryptographic/control bindings have
    # focused suites and this fixture does not construct complete live inputs.
    monkeypatch.setattr(validator, "_validate_control_bytes", lambda *_: None)
    monkeypatch.setattr(validator, "_validate_attestation_bytes", lambda *_: None)
    monkeypatch.setattr(validator, "_validate_envelopes", lambda *_: None)
    monkeypatch.setattr(validator, "_validate_keys_and_anchor", lambda *_: None)
    monkeypatch.setattr(
        validator,
        "_validate_trusted_parent_contracts",
        lambda *_: None,
    )

    inventory = validator._collect_descriptors(ledger)
    for relative in inventory:
        target = ledger_root / Path(*PurePosixPath(relative).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(contents[relative])
    ledger_path = ledger_root / "RELEASE_LEDGER.json"
    ledger_path.write_bytes(validator.canonical_json_bytes(ledger))
    sign_file(str(ledger_path), str(signing_private))
    for child in key_directory.iterdir():
        child.unlink()
    key_directory.rmdir()
    return ledger_root, signing_public
def test_complete_directory_signature_and_closed_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, trusted_key = _signed_directory(tmp_path, monkeypatch)
    validator.validate_directory(root, trusted_key)

    (root / "unexpected.txt").write_text("not inventoried\n", encoding="utf-8")
    with pytest.raises(validator.LedgerValidationError, match="file set is not exact"):
        validator.validate_directory(root, trusted_key)


def test_complete_directory_rejects_unsigned_readme_and_extra_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, trusted_key = _signed_directory(tmp_path, monkeypatch)
    readme = root / "README.md"
    readme.write_bytes(readme.read_bytes() + b"unsigned mutation\n")
    with pytest.raises(validator.LedgerValidationError, match="retained evidence README"):
        validator.validate_directory(root, trusted_key)

    second = tmp_path / "second"
    second.mkdir()
    root, trusted_key = _signed_directory(second, monkeypatch)
    (root / "empty-extra").mkdir()
    with pytest.raises(validator.LedgerValidationError, match="directory set is not exact"):
        validator.validate_directory(root, trusted_key)


def test_complete_directory_rejects_hardlinks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, trusted_key = _signed_directory(tmp_path, monkeypatch)
    try:
        os.link(root / "README.md", root / "hardlink.txt")
    except OSError:
        pytest.skip("hard links are unavailable on this filesystem")
    with pytest.raises(validator.LedgerValidationError, match="hard-linked"):
        validator.validate_directory(root, trusted_key)


def test_complete_directory_detects_post_read_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, trusted_key = _signed_directory(tmp_path, monkeypatch)

    def mutate_after_generic_reads(*_args: object) -> None:
        readme = root / "README.md"
        readme.write_bytes(readme.read_bytes() + b"late mutation\n")

    monkeypatch.setattr(validator, "_validate_envelopes", mutate_after_generic_reads)
    with pytest.raises(
        validator.LedgerValidationError,
        match="retained evidence changed during validation",
    ):
        validator.validate_directory(root, trusted_key)


def test_complete_directory_rejects_link_like_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    root, trusted_key = _signed_directory(real, monkeypatch)
    link = tmp_path / "linked"
    try:
        link.symlink_to(root, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this platform")
    with pytest.raises(validator.LedgerValidationError, match="link-like component"):
        validator.validate_directory(link, trusted_key)


def test_invalid_ledger_signature_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, trusted_key = _signed_directory(tmp_path, monkeypatch)
    signature = root / "RELEASE_LEDGER.json.sig"
    encoded = bytearray(signature.read_bytes())
    encoded[0] = ord("A") if encoded[0] != ord("A") else ord("B")
    signature.write_bytes(bytes(encoded))
    with pytest.raises(validator.LedgerValidationError, match="signature"):
        validator.validate_directory(root, trusted_key)


def test_self_signed_seven_key_bundle_needs_external_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _attacker_ledger_key = _signed_directory(tmp_path, monkeypatch)
    authority_private = tmp_path / "authority.pem"
    authority_public = tmp_path / "authority.pub.pem"
    generate_keypair(str(authority_private), str(authority_public))

    with pytest.raises(
        validator.LedgerValidationError,
        match="external trusted key",
    ):
        validator.validate_directory(root, authority_public)


def test_trusted_ledger_key_must_be_independent_and_plain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, trusted_key = _signed_directory(tmp_path, monkeypatch)
    retained = root / "trust" / "release-ledger-v2.pub.pem"
    with pytest.raises(validator.LedgerValidationError, match="outside the ledger root"):
        validator.validate_directory(root, retained)

    hardlink = tmp_path / "trusted-hardlink.pub.pem"
    try:
        os.link(trusted_key, hardlink)
    except OSError:
        pytest.skip("hard links are unavailable on this filesystem")
    with pytest.raises(validator.LedgerValidationError, match="hard-linked"):
        validator.validate_directory(root, hardlink)


def test_trusted_ledger_key_rejects_link_like_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, trusted_key = _signed_directory(tmp_path, monkeypatch)
    link = tmp_path / "trusted-link.pub.pem"
    try:
        link.symlink_to(trusted_key)
    except OSError:
        pytest.skip("file symlinks are unavailable on this filesystem")
    with pytest.raises(validator.LedgerValidationError, match="regular non-link"):
        validator.validate_directory(root, link)


def test_invalid_signature_fails_before_inventory_traversal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, trusted_key = _signed_directory(tmp_path, monkeypatch)
    signature = root / "RELEASE_LEDGER.json.sig"
    encoded = bytearray(signature.read_bytes())
    encoded[0] = ord("A") if encoded[0] != ord("A") else ord("B")
    signature.write_bytes(bytes(encoded))

    def forbidden_inventory(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("inventory traversal ran before authentication")

    monkeypatch.setattr(validator, "_actual_inventory", forbidden_inventory)
    with pytest.raises(validator.LedgerValidationError, match="signature"):
        validator.validate_directory(root, trusted_key)


@pytest.mark.parametrize(
    "replacement",
    [
        b"A" * (validator.CANONICAL_SIGNATURE_BYTES + 1),
        b"A" * (validator.CANONICAL_SIGNATURE_BYTES - 1) + b" ",
    ],
)
def test_signature_sidecar_is_bounded_and_canonical(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement: bytes,
) -> None:
    root, trusted_key = _signed_directory(tmp_path, monkeypatch)
    (root / "RELEASE_LEDGER.json.sig").write_bytes(replacement)
    with pytest.raises(validator.LedgerValidationError, match="signature"):
        validator.validate_directory(root, trusted_key)


def test_external_anchor_change_during_validation_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, trusted_key = _signed_directory(tmp_path, monkeypatch)

    def mutate_anchor(*_args: object) -> None:
        original = trusted_key.read_bytes()
        trusted_key.write_bytes(b"X" * len(original))

    monkeypatch.setattr(validator, "_validate_control_bytes", mutate_anchor)
    with pytest.raises(
        validator.LedgerValidationError,
        match="external trusted ledger public key changed",
    ):
        validator.validate_directory(root, trusted_key)


def test_same_size_mtime_restored_evidence_mutation_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, trusted_key = _signed_directory(tmp_path, monkeypatch)
    readme = root / "README.md"
    original = readme.read_bytes()
    metadata = readme.stat()

    def mutate_original_after_snapshot(*_args: object) -> None:
        mutated = bytes([original[0] ^ 1]) + original[1:]
        readme.write_bytes(mutated)
        os.utime(readme, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))

    monkeypatch.setattr(
        validator,
        "_validate_envelopes",
        mutate_original_after_snapshot,
    )
    with pytest.raises(
        validator.LedgerValidationError,
        match="retained evidence changed during validation",
    ):
        validator.validate_directory(root, trusted_key)


def test_retained_budget_rejects_file_count_file_size_and_total() -> None:
    digest = "0" * 64
    with pytest.raises(validator.LedgerValidationError, match="file count"):
        validator._require_retained_budget(
            {
                f"evidence/{index}.json": (1, digest)
                for index in range(validator.MAX_RETAINED_FILES + 1)
            }
        )
    with pytest.raises(validator.LedgerValidationError, match="file exceeds"):
        validator._require_retained_budget(
            {
                "evidence/oversized.bin": (
                    validator.MAX_RETAINED_FILE_BYTES + 1,
                    digest,
                )
            }
        )
    with pytest.raises(validator.LedgerValidationError, match="total exceeds"):
        validator._require_retained_budget(
            {
                f"evidence/{index}.bin": (
                    validator.MAX_RETAINED_FILE_BYTES,
                    digest,
                )
                for index in range(
                    validator.MAX_RETAINED_TOTAL_BYTES
                    // validator.MAX_RETAINED_FILE_BYTES
                    + 1
                )
            }
        )
