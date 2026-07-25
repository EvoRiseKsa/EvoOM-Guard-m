# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
"""Fail-closed tests for the protected immutable release-ledger v2 contract."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from evoom_guard.signing import (
    generate_keypair,
    public_key_id,
    sign_file,
)
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


def _repository_control_observation(ledger: dict[str, Any]) -> dict[str, Any]:
    controls = ledger["repository_controls"]
    environments = {
        item["name"]: item["id"] for item in controls["environments"]
    }
    return {
        "format": "EVOGUARD_REPOSITORY_CONTROL_OBSERVATION_V1",
        "repository": ledger["release"]["repository"],
        "repository_id": ledger["release"]["repository_id"],
        "repository_owner_id": ledger["release"]["repository_owner_id"],
        "collector": {
            "name": "evoguard-release-ledger",
            "version": "2",
        },
        "github_api_version": "2022-11-28",
        "observations": [
            {
                "environment_id": environments[item["environment"]],
                "environment": item["environment"],
                "api_action": "list-environment-secrets",
                "request_method": "GET",
                "endpoint": (
                    f"/repos/{ledger['release']['repository']}/environments/"
                    f"{item['environment']}/secrets"
                ),
                "http_status": 200,
                "pagination_complete": True,
                "per_page": 100,
                "page_count": 1,
                "total_count": 0,
                "queried_secret_name": item["secret_name"],
                "present": False,
                "observed_utc": item["observed_utc"],
            }
            for item in controls["admission_secret_absence_after_publication"]
        ],
        "evidence_boundary": "owner-collected-point-in-time-github-api-observation",
    }


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
            jobs=["preflight", "seal"],
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
            "repository_id": "999999",
            "repository_owner_id": "1002",
            "source_repository_visibility_at_signing": "public",
            "tag": "v9.9.9",
            "commit_sha": candidate,
            "tree_sha": candidate_tree,
            "release_id": 3001,
            "state": "published",
            "prerelease": False,
            "immutable": True,
            "created_utc": "2030-01-01T00:18:00Z",
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
                artifact_name="evoguard-release-artifact-v1-controls-1",
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
                artifact_name="evoguard-release-publication-ready-1",
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
                    "attestations/build-provenance-verification.json"
                ),
                "verification_output": _file(
                    "attestations/build-provenance-verification-output.json"
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
                    "attestations/spdx-provenance-verification.json"
                ),
                "verification_output": _file(
                    "attestations/spdx-provenance-verification-output.json"
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
                    "attestations/sbom-provenance-verification.json"
                ),
                "verification_output": _file(
                    "attestations/sbom-provenance-verification-output.json"
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
            },
        },
        "repository_controls": {
            "observed_utc": "2030-01-01T00:23:00Z",
            "main_branch": {
                "ref": "refs/heads/main",
                "head_sha": candidate,
                "protected": True,
                "strict_required_checks": True,
                "enforce_admins": True,
                "required_checks": sorted(validator.REQUIRED_MAIN_CHECKS),
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
                "fingerprint": f"SHA256:{'A' * 43}",
                "read_only": False,
                "sole_write_enabled": True,
            },
            "immutable_releases": True,
            "actions": {
                "enabled": True,
                "sha_pinning_required": True,
                "default_workflow_permissions": "read",
                "can_approve_pull_requests": False,
            },
            "environments": [
                {
                    "id": 6001,
                    "name": "evoguard-release-source-v2",
                    "reviewer": "MANA-awam",
                    "prevent_self_review": True,
                    "can_admins_bypass": False,
                    "deployment_branch": "main",
                    "secret_required": True,
                },
                {
                    "id": 6002,
                    "name": "evoguard-release-artifact-v1",
                    "reviewer": "MANA-awam",
                    "prevent_self_review": True,
                    "can_admins_bypass": False,
                    "deployment_branch": "main",
                    "secret_required": True,
                },
                {
                    "id": 6003,
                    "name": "evoguard-release-draft",
                    "reviewer": "MANA-awam",
                    "prevent_self_review": True,
                    "can_admins_bypass": False,
                    "deployment_branch": "main",
                    "secret_required": False,
                },
                {
                    "id": 6004,
                    "name": "evoguard-release-publication",
                    "reviewer": "MANA-awam",
                    "prevent_self_review": True,
                    "can_admins_bypass": False,
                    "deployment_branch": "main",
                    "secret_required": True,
                },
            ],
            "observation_evidence": _file(
                "controls/repository/repository-controls-observation.json"
            ),
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
        },
    }


def _schema() -> dict[str, Any]:
    return validator._load_json_file(SCHEMA_PATH, label="test schema")


def test_v2_schema_is_valid_and_synthetic_contract_passes() -> None:
    schema = _schema()
    Draft202012Validator.check_schema(schema)
    validator.validate_structure(_valid_ledger())


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
    schema_target.parent.mkdir(parents=True)
    validator_target.parent.mkdir(parents=True)
    schema_target.write_bytes(SCHEMA_PATH.read_bytes())
    validator_target.write_bytes(Path(validator.__file__).read_bytes())
    git("add", ".")
    git("commit", "-q", "-m", "trusted parent")
    parent = git("rev-parse", "HEAD")
    parent_tree = git("rev-parse", "HEAD^{tree}")
    ledger = _valid_ledger()
    ledger["source"]["parent_commit_sha"] = parent
    ledger["source"]["parent_tree_sha"] = parent_tree
    for contract in (
        ledger["schema_contracts"]["release_ledger"],
        ledger["schema_contracts"]["validator"],
    ):
        contract["trusted_parent_commit_sha"] = parent
        contract["trusted_parent_tree_sha"] = parent_tree
    ledger_root = tmp_path / "ledger"
    ledger_root.mkdir()
    validator._validate_trusted_parent_contracts(
        ledger_root,
        ledger,
        repository,
    )

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
            "missing required checks",
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
    source_path.write_bytes(validator.canonical_json_bytes(source_seal))
    validator._validate_source_result(
        tmp_path,
        {"path": source_path.name},
        manifest=source_manifest,
        sealed=True,
        bundle_name="source-allow.rsae",
        label="source seal",
    )
    source_seal["live_provider_reverification"] = True
    source_path.write_bytes(validator.canonical_json_bytes(source_seal))
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
    artifact_path.write_bytes(validator.canonical_json_bytes(artifact_verify))
    validator._validate_artifact_result(
        tmp_path,
        {"path": artifact_path.name},
        manifest=artifact_manifest,
        sealed=False,
        bundle_name="unused.raae",
        label="artifact verify",
    )
    artifact_verify["live_provider_reverification"] = True
    artifact_path.write_bytes(validator.canonical_json_bytes(artifact_verify))
    with pytest.raises(validator.LedgerValidationError, match="actual F/G"):
        validator._validate_artifact_result(
            tmp_path,
            {"path": artifact_path.name},
            manifest=artifact_manifest,
            sealed=False,
            bundle_name="unused.raae",
            label="artifact verify",
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
    signer_uri = f"https://github.com/{repository}/{workflow_path}@{source}"
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
                        "repository_owner_id": "1002",
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
                        "sourceRepositoryOwnerIdentifier": "1002",
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
                        "regexp": f"^{signer_uri}$",
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
        attestation["verification_output"].update(
            {
                "size_bytes": len(output_bytes),
                "sha256": hashlib.sha256(output_bytes).hexdigest(),
            }
        )
        receipt = {
            "format": "EVOGUARD_GITHUB_ATTESTATION_RECEIPT_V1",
            "artifact": subject,
            "verification_policy": {
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
            },
            "verification_output": {
                "sha256": attestation["verification_output"]["sha256"],
                "size": attestation["verification_output"]["size_bytes"],
                "verified_attestation_count": 1,
            },
        }
        receipt_bytes = validator.canonical_json_bytes(receipt)
        receipt_path = tmp_path / Path(
            *PurePosixPath(attestation["verification_receipt"]["path"]).parts
        )
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_bytes(receipt_bytes)
        attestation["verification_receipt"].update(
            {
                "size_bytes": len(receipt_bytes),
                "sha256": hashlib.sha256(receipt_bytes).hexdigest(),
            }
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


def test_publication_control_bytes_bind_assets_admissions_and_target(
    tmp_path: Path,
) -> None:
    ledger = _valid_ledger()
    bundle = ledger["control_evidence"]["publication_controls"]
    ledger["control_evidence"] = {"publication_controls": bundle}
    phases = validator._phase_map(ledger)
    manifest = {
        "format": bundle["format"],
        "repository": ledger["release"]["repository"],
        "target_sha": ledger["source"]["candidate_commit_sha"],
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
    }
    manifest_path = tmp_path / Path(
        *PurePosixPath(bundle["manifest"]["path"]).parts
    )
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_bytes(validator.canonical_json_bytes(manifest))

    validator._validate_control_bytes(tmp_path, ledger)

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

    value["observations"][0]["http_status"] = 403
    path.write_bytes(validator.canonical_json_bytes(value))
    with pytest.raises(
        validator.LedgerValidationError,
        match="observation 0 is not exact",
    ):
        validator._validate_repository_control_observation_bytes(tmp_path, ledger)

    value = _repository_control_observation(ledger)
    value["observations"][0]["total_count"] = 101
    path.write_bytes(validator.canonical_json_bytes(value))
    with pytest.raises(
        validator.LedgerValidationError,
        match="observation 0 is not exact",
    ):
        validator._validate_repository_control_observation_bytes(tmp_path, ledger)


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

    # The full validator still executes every generic ledger check. These two
    # owners are replaced only because constructing valid RSAE/RAAE and live
    # GitHub control manifests belongs to their existing focused suites.
    monkeypatch.setattr(validator, "_validate_control_bytes", lambda *_: None)
    monkeypatch.setattr(validator, "_validate_attestation_bytes", lambda *_: None)
    monkeypatch.setattr(validator, "_validate_envelopes", lambda *_: None)
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
