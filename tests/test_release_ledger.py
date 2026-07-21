# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available - see LICENSE for permitted use.
"""Offline truth checks for the published immutable v4.0.2 release ledger."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
LEDGER_ROOT = ROOT / "tests" / "baseline" / "v4.0.2"
LEDGER_PATH = LEDGER_ROOT / "RELEASE_LEDGER.json"
SCHEMA_PATH = ROOT / "tests" / "baseline" / "schema" / "release-ledger-v1.schema.json"
METADATA_FILES = {"README.md", "RELEASE_LEDGER.json"}

RELEASE_COMMIT = "3374164c65ad692049929fdc903eafb47c843a8e"
RELEASE_TREE = "e89fd44b78519f9eedf026f516dc6c8766140e3a"
PYZ_SHA256 = "7813db5c99f27f780ec31bbaa124b5526405783d1f53caecc32f70aabfbc13c3"
CHECKSUM_SHA256 = "2e17327e727dc2c3e57065419619dc14e56ce917227d3c6cedc9a95a7122226c"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _strict_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    assert isinstance(value, dict)
    return value


def _ledger() -> dict[str, Any]:
    return _strict_json(LEDGER_PATH)


def _safe_artifact_path(relative: str) -> Path:
    assert "\\" not in relative, f"backslash is forbidden in artifact path: {relative}"
    pure = PurePosixPath(relative)
    assert not pure.is_absolute(), f"absolute artifact path: {relative}"
    assert ".." not in pure.parts, f"parent traversal in artifact path: {relative}"
    assert pure.parts and all(part not in {"", "."} for part in pure.parts)
    target = LEDGER_ROOT.joinpath(*pure.parts)
    assert target.resolve().is_relative_to(LEDGER_ROOT.resolve())
    current = target
    while current != LEDGER_ROOT:
        assert not current.is_symlink(), f"symlink in release artifact path: {relative}"
        current = current.parent
    return target


def test_release_ledger_schema_duplicate_keys_and_fixed_identity() -> None:
    ledger = _ledger()
    schema = _strict_json(SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(ledger)

    assert ledger["schema_version"] == "evoguard-release-ledger-v1"
    assert ledger["project"] == {"name": "EvoOM Guard", "version": "4.0.2"}
    assert ledger["release"] == {
        "repository": "EvoRiseKsa/EvoOM-Guard-m",
        "tag": "v4.0.2",
        "commit_sha": RELEASE_COMMIT,
        "tree_sha": RELEASE_TREE,
        "release_id": 357596743,
        "state": "published",
        "prerelease": False,
        "immutable": True,
        "created_utc": "2026-07-21T18:52:06Z",
        "published_utc": "2026-07-21T19:58:00Z",
        "release_url": (
            "https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.0.2"
        ),
    }

    with pytest.raises(ValueError, match="duplicate JSON key: tag"):
        json.loads('{"tag":"v4.0.2","tag":"v0.0.0"}', object_pairs_hook=_unique_object)


def test_release_artifact_inventory_is_complete_safe_and_byte_exact() -> None:
    ledger = _ledger()
    entries = ledger["artifacts"]
    assert entries == sorted(entries, key=lambda entry: entry["name"].casefold())
    assert len({entry["name"] for entry in entries}) == len(entries)
    assert len({entry["path"] for entry in entries}) == len(entries)

    expected_paths = {entry["path"] for entry in entries}
    actual_paths = {
        path.relative_to(LEDGER_ROOT).as_posix()
        for path in LEDGER_ROOT.rglob("*")
        if path.is_file() and path.name not in METADATA_FILES
    }
    assert actual_paths == expected_paths

    for entry in entries:
        target = _safe_artifact_path(entry["path"])
        assert target.is_file(), f"missing release artifact: {entry['path']}"
        assert target.stat().st_size == entry["size_bytes"]
        assert _sha256(target) == entry["sha256"]
        assert entry["github_digest"] == f"sha256:{entry['sha256']}"


def test_checksum_manifest_is_exact_and_zipapp_runs_offline() -> None:
    ledger = _ledger()
    artifacts = {entry["name"]: entry for entry in ledger["artifacts"]}
    pyz = _safe_artifact_path(artifacts["evo-guard.pyz"]["path"])
    checksums = _safe_artifact_path(artifacts["SHA256SUMS"]["path"])

    assert checksums.read_bytes() == f"{PYZ_SHA256}  evo-guard.pyz\n".encode("ascii")
    assert _sha256(pyz) == PYZ_SHA256
    assert _sha256(checksums) == CHECKSUM_SHA256
    assert ledger["checksum_manifest"] == {
        "path": "SHA256SUMS",
        "format": "sha256sum-two-space",
        "target": "evo-guard.pyz",
        "target_sha256": PYZ_SHA256,
        "manifest_sha256": CHECKSUM_SHA256,
    }

    completed = subprocess.run(
        [sys.executable, "-I", str(pyz), "version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.stdout.strip() == "evo-guard 4.0.2"
    assert completed.stderr == ""


def test_workflows_attestations_and_artifacts_bind_to_one_release() -> None:
    ledger = _ledger()
    release = ledger["release"]
    workflow = ledger["release_workflow"]
    tag_ci = ledger["tag_ci"]
    provenance = ledger["build_provenance"]
    release_attestation = ledger["release_attestation"]
    artifacts = {entry["name"]: entry for entry in ledger["artifacts"]}

    assert workflow["head_sha"] == release["commit_sha"] == RELEASE_COMMIT
    assert workflow["run_id"] == 29862754126
    assert workflow["run_url"].endswith(f"/runs/{workflow['run_id']}")
    assert workflow["pytest"] == {
        "passed": 1594,
        "skipped": 11,
        "subtests_passed": 59,
    }
    assert workflow["linux_e2e_passed"] == [10, 8]
    assert workflow["windows_e2e_passed"] == 10

    assert tag_ci["head_sha"] == RELEASE_COMMIT
    assert tag_ci["tag_ref"] == f"refs/tags/{release['tag']}"
    assert tag_ci["run_id"] == 29863741885
    assert tag_ci["run_url"].endswith(f"/runs/{tag_ci['run_id']}")
    assert set(tag_ci["successful_jobs"]) == {
        "blackbox-docker-e2e",
        "release-tag-guard",
        "e2e-runners",
        "test (3.10)",
        "test (3.11)",
        "test (3.12)",
        "publish-pyz",
    }

    assert provenance["source_digest"] == RELEASE_COMMIT
    assert provenance["subject_name"] == "evo-guard.pyz"
    assert provenance["subject_sha256"] == artifacts["evo-guard.pyz"]["sha256"]
    assert provenance["invocation_url"].endswith(
        f"/runs/{workflow['run_id']}/attempts/{workflow['attempt']}"
    )

    assert release_attestation["tag"] == release["tag"]
    assert release_attestation["commit_sha"] == RELEASE_COMMIT
    assert release_attestation["purl"] == (
        "pkg:github/EvoRiseKsa/EvoOM-Guard-m@v4.0.2"
    )
    attested_assets = {
        entry["name"]: entry["sha256"] for entry in release_attestation["asset_subjects"]
    }
    assert attested_assets == {
        name: entry["sha256"] for name, entry in artifacts.items()
    }


def test_release_ledger_records_only_shipped_public_contracts() -> None:
    contracts = _ledger()["schema_contracts"]
    assert contracts == {
        "verdict_record": "1.11",
        "sarif": "2.1.0",
        "verifier_pack": "EVOGUARD_PACK_V2",
        "junit_digest_formats": [
            "JUNIT_XML_SHA256",
            "EVOGUARD_JUNIT_REPORT_SET_V1",
            "EVOGUARD_JUNIT_COMPOSITE_V1",
            "EVOGUARD_JUNIT_COMPOSITE_V2",
        ],
    }
    assert not any(
        (LEDGER_ROOT / name).exists()
        for name in ("action", "artifacts", "benchmarks", "commands", "evidence", "packs")
    )
