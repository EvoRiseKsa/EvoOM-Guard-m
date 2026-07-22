# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available - see LICENSE for permitted use.
"""Offline truth checks for the published immutable release ledgers."""

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
SCHEMA_PATH = ROOT / "tests" / "baseline" / "schema" / "release-ledger-v1.schema.json"
METADATA_FILES = {"README.md", "RELEASE_LEDGER.json"}
SUCCESSFUL_TAG_JOBS = {
    "blackbox-docker-e2e",
    "release-tag-guard",
    "e2e-runners",
    "test (3.10)",
    "test (3.11)",
    "test (3.12)",
    "publish-pyz",
}

RELEASE_CASES: tuple[dict[str, Any], ...] = (
    {
        "version": "4.0.2",
        "tag": "v4.0.2",
        "commit": "3374164c65ad692049929fdc903eafb47c843a8e",
        "tree": "e89fd44b78519f9eedf026f516dc6c8766140e3a",
        "release_id": 357596743,
        "created_utc": "2026-07-21T18:52:06Z",
        "published_utc": "2026-07-21T19:58:00Z",
        "marketplace_observed_utc": "2026-07-21T20:07:32Z",
        "pyz_sha256": "7813db5c99f27f780ec31bbaa124b5526405783d1f53caecc32f70aabfbc13c3",
        "checksum_sha256": (
            "2e17327e727dc2c3e57065419619dc14e56ce917227d3c6cedc9a95a7122226c"
        ),
        "release_run_id": 29862754126,
        "tag_ci_run_id": 29863741885,
        "pytest": {"passed": 1594, "skipped": 11, "subtests_passed": 59},
        "build_timestamp_utc": "2026-07-21T19:46:59Z",
        "release_attestation_timestamp_utc": "2026-07-21T19:58:01Z",
    },
    {
        "version": "4.1.0",
        "tag": "v4.1.0",
        "commit": "16029f3e34237ed07b97649c5c9be35d0a356bf7",
        "tree": "7c749ed298050840fdd52577e6364a6e63cd36a6",
        "release_id": 357774573,
        "created_utc": "2026-07-22T04:11:11Z",
        "published_utc": "2026-07-22T04:25:44Z",
        "marketplace_observed_utc": "2026-07-22T04:38:00Z",
        "pyz_sha256": "d5ce7dbefa870307d6fe49ddec1e9847cad89d15f6afe2b74f4e7b8953fc62b2",
        "checksum_sha256": (
            "2e9839e838d9384a2f7200f9caddb336ffe043cd971f8151c9d3efb090fa4c3b"
        ),
        "release_run_id": 29890414339,
        "tag_ci_run_id": 29891032932,
        "pytest": {"passed": 1696, "skipped": 11, "subtests_passed": 59},
        "build_timestamp_utc": "2026-07-22T04:16:08Z",
        "release_attestation_timestamp_utc": "2026-07-22T04:25:45Z",
    },
    {
        "version": "4.2.0",
        "tag": "v4.2.0",
        "commit": "db2d433aa8662ee4fca0957f9b917d8733f80596",
        "tree": "7dbb0df6cd1013c24373de302bab95738495117e",
        "release_id": 357976954,
        "created_utc": "2026-07-22T11:30:52Z",
        "published_utc": "2026-07-22T19:36:43Z",
        "marketplace_observed_utc": "2026-07-22T19:42:46Z",
        "pyz_sha256": "789428de56c42808fadeed654fc3d9377d2456e15dadf53b8eb24e4287028c88",
        "checksum_sha256": (
            "04f270bbe64ab9e8a5c719ba2c5e4a88a1dea74cdbc0d52b8f1bb6f1e6794be0"
        ),
        "release_run_id": 29916717885,
        "tag_ci_run_id": 29951698966,
        "pytest": {"passed": 1722, "skipped": 11, "subtests_passed": 59},
        "build_timestamp_utc": "2026-07-22T11:47:16Z",
        "release_attestation_timestamp_utc": "2026-07-22T19:36:44Z",
    },
)


@pytest.fixture(params=RELEASE_CASES, ids=lambda case: str(case["tag"]))
def release_case(request: pytest.FixtureRequest) -> dict[str, Any]:
    case = request.param
    assert isinstance(case, dict)
    return case


def _ledger_root(case: dict[str, Any]) -> Path:
    return ROOT / "tests" / "baseline" / str(case["tag"])


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


def _ledger(case: dict[str, Any]) -> dict[str, Any]:
    return _strict_json(_ledger_root(case) / "RELEASE_LEDGER.json")


def _safe_artifact_path(case: dict[str, Any], relative: str) -> Path:
    ledger_root = _ledger_root(case)
    assert "\\" not in relative, f"backslash is forbidden in artifact path: {relative}"
    pure = PurePosixPath(relative)
    assert not pure.is_absolute(), f"absolute artifact path: {relative}"
    assert ".." not in pure.parts, f"parent traversal in artifact path: {relative}"
    assert pure.parts and all(part not in {"", "."} for part in pure.parts)
    target = ledger_root.joinpath(*pure.parts)
    assert target.resolve().is_relative_to(ledger_root.resolve())
    current = target
    while current != ledger_root:
        assert not current.is_symlink(), f"symlink in release artifact path: {relative}"
        current = current.parent
    return target


def test_release_ledger_schema_duplicate_keys_and_fixed_identity(
    release_case: dict[str, Any],
) -> None:
    ledger = _ledger(release_case)
    schema = _strict_json(SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(ledger)

    tag = str(release_case["tag"])
    commit = str(release_case["commit"])
    assert ledger["schema_version"] == "evoguard-release-ledger-v1"
    assert ledger["project"] == {
        "name": "EvoOM Guard",
        "version": release_case["version"],
    }
    assert ledger["release"] == {
        "repository": "EvoRiseKsa/EvoOM-Guard-m",
        "tag": tag,
        "commit_sha": commit,
        "tree_sha": release_case["tree"],
        "release_id": release_case["release_id"],
        "state": "published",
        "prerelease": False,
        "immutable": True,
        "created_utc": release_case["created_utc"],
        "published_utc": release_case["published_utc"],
        "release_url": (
            f"https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/{tag}"
        ),
    }
    assert ledger["marketplace"] == {
        "action": "EvoOM Guard",
        "version": tag,
        "url": "https://github.com/marketplace/actions/evoom-guard",
        "observed_utc": release_case["marketplace_observed_utc"],
    }

    with pytest.raises(ValueError, match="duplicate JSON key: tag"):
        json.loads(f'{{"tag":"{tag}","tag":"v0.0.0"}}', object_pairs_hook=_unique_object)


def test_release_artifact_inventory_is_complete_safe_and_byte_exact(
    release_case: dict[str, Any],
) -> None:
    ledger = _ledger(release_case)
    entries = ledger["artifacts"]
    assert entries == sorted(entries, key=lambda entry: entry["name"].casefold())
    assert len({entry["name"] for entry in entries}) == len(entries)
    assert len({entry["path"] for entry in entries}) == len(entries)

    ledger_root = _ledger_root(release_case)
    expected_paths = {entry["path"] for entry in entries}
    actual_paths = {
        path.relative_to(ledger_root).as_posix()
        for path in ledger_root.rglob("*")
        if path.is_file() and path.name not in METADATA_FILES
    }
    assert actual_paths == expected_paths

    for entry in entries:
        target = _safe_artifact_path(release_case, entry["path"])
        assert target.is_file(), f"missing release artifact: {entry['path']}"
        assert target.stat().st_size == entry["size_bytes"]
        assert _sha256(target) == entry["sha256"]
        assert entry["github_digest"] == f"sha256:{entry['sha256']}"
        assert entry["download_url"] == (
            "https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/download/"
            f"{release_case['tag']}/{entry['name']}"
        )


def test_checksum_manifest_is_exact_and_zipapp_runs_offline(
    release_case: dict[str, Any],
) -> None:
    ledger = _ledger(release_case)
    artifacts = {entry["name"]: entry for entry in ledger["artifacts"]}
    pyz = _safe_artifact_path(release_case, artifacts["evo-guard.pyz"]["path"])
    checksums = _safe_artifact_path(release_case, artifacts["SHA256SUMS"]["path"])
    pyz_sha256 = str(release_case["pyz_sha256"])
    checksum_sha256 = str(release_case["checksum_sha256"])

    assert checksums.read_bytes() == f"{pyz_sha256}  evo-guard.pyz\n".encode("ascii")
    assert _sha256(pyz) == pyz_sha256
    assert _sha256(checksums) == checksum_sha256
    assert ledger["checksum_manifest"] == {
        "path": "SHA256SUMS",
        "format": "sha256sum-two-space",
        "target": "evo-guard.pyz",
        "target_sha256": pyz_sha256,
        "manifest_sha256": checksum_sha256,
    }

    completed = subprocess.run(
        [sys.executable, "-I", str(pyz), "version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.stdout.strip() == f"evo-guard {release_case['version']}"
    assert completed.stderr == ""


def test_workflows_attestations_and_artifacts_bind_to_one_release(
    release_case: dict[str, Any],
) -> None:
    ledger = _ledger(release_case)
    release = ledger["release"]
    workflow = ledger["release_workflow"]
    tag_ci = ledger["tag_ci"]
    provenance = ledger["build_provenance"]
    release_attestation = ledger["release_attestation"]
    artifacts = {entry["name"]: entry for entry in ledger["artifacts"]}
    commit = str(release_case["commit"])
    tag = str(release_case["tag"])

    assert workflow["head_sha"] == release["commit_sha"] == commit
    assert workflow["run_id"] == release_case["release_run_id"]
    assert workflow["run_url"].endswith(f"/runs/{workflow['run_id']}")
    assert workflow["pytest"] == release_case["pytest"]
    assert workflow["linux_e2e_passed"] == [10, 8]
    assert workflow["windows_e2e_passed"] == 10

    assert tag_ci["head_sha"] == commit
    assert tag_ci["tag_ref"] == f"refs/tags/{tag}"
    assert tag_ci["run_id"] == release_case["tag_ci_run_id"]
    assert tag_ci["run_url"].endswith(f"/runs/{tag_ci['run_id']}")
    assert set(tag_ci["successful_jobs"]) == SUCCESSFUL_TAG_JOBS

    assert provenance["source_digest"] == commit
    assert provenance["subject_name"] == "evo-guard.pyz"
    assert provenance["subject_sha256"] == artifacts["evo-guard.pyz"]["sha256"]
    assert provenance["transparency_log_timestamp_utc"] == (
        release_case["build_timestamp_utc"]
    )
    assert provenance["invocation_url"].endswith(
        f"/runs/{workflow['run_id']}/attempts/{workflow['attempt']}"
    )

    assert release_attestation["tag"] == tag
    assert release_attestation["commit_sha"] == commit
    assert release_attestation["verified_timestamp_utc"] == (
        release_case["release_attestation_timestamp_utc"]
    )
    assert release_attestation["purl"] == (
        f"pkg:github/EvoRiseKsa/EvoOM-Guard-m@{tag}"
    )
    attested_assets = {
        entry["name"]: entry["sha256"]
        for entry in release_attestation["asset_subjects"]
    }
    assert attested_assets == {
        name: entry["sha256"] for name, entry in artifacts.items()
    }


def test_release_ledger_records_stable_public_contracts_only(
    release_case: dict[str, Any],
) -> None:
    contracts = _ledger(release_case)["schema_contracts"]
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
    ledger_root = _ledger_root(release_case)
    assert not any(
        (ledger_root / name).exists()
        for name in ("action", "artifacts", "benchmarks", "commands", "evidence", "packs")
    )
