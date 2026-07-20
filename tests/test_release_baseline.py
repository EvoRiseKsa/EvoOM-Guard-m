from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator

from evoom_guard.pack_manifest import pack_digest
from evoom_guard.signing import verify_file

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "tests" / "baseline" / "v4.0.1"
MANIFEST = BASELINE / "BASELINE_MANIFEST.json"
SCHEMA = ROOT / "tests" / "baseline" / "schema" / "baseline-v2.schema.json"
METADATA_FILES = {"BASELINE_MANIFEST.json", "README.md", "ERRATA.md"}
RELEASE_COMMIT = "5ed7e84017619496521b813f859a6a8bf0a2b1df"
RELEASE_TREE = "434d09817bd166be4e123836b941ee1b808d17bf"
CAPTURE_COMMIT = "00427917c03266f99a9cf99a21e82ed57c46f226"
PYZ_SHA256 = "81a5139e1e0f3c5ce1f9180db85c699eec305474f9588f7d2831099defdce2f7"


def sha256(path: Path) -> str:
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


def _manifest() -> dict[str, Any]:
    return _strict_json(MANIFEST)


def _inventory(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    entries = manifest["artifact_inventory"]
    by_id = {entry["id"]: entry for entry in entries}
    assert len(by_id) == len(entries), "artifact IDs must be unique"
    assert len({entry["path"] for entry in entries}) == len(entries), (
        "artifact paths must be unique"
    )
    return by_id


def _safe_artifact_path(relative: str) -> Path:
    assert "\\" not in relative, f"backslash is forbidden in artifact path: {relative}"
    pure = PurePosixPath(relative)
    assert not pure.is_absolute(), f"absolute artifact path: {relative}"
    assert ".." not in pure.parts, f"parent traversal in artifact path: {relative}"
    assert pure.parts and all(part not in {"", "."} for part in pure.parts)
    target = BASELINE.joinpath(*pure.parts)
    assert target.resolve().is_relative_to(BASELINE.resolve())
    current = target
    while current != BASELINE:
        assert not current.is_symlink(), f"symlink in baseline artifact path: {relative}"
        current = current.parent
    return target


def _parse_action_contract(path: Path) -> tuple[dict[str, dict[str, object]], dict[str, str]]:
    inputs: dict[str, dict[str, object]] = {}
    outputs: dict[str, str] = {}
    section: str | None = None
    current: str | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw == "inputs:":
            section, current = "inputs", None
            continue
        if raw == "outputs:":
            section, current = "outputs", None
            continue
        if raw and not raw.startswith(" "):
            section, current = None, None
            continue
        key_match = re.fullmatch(r"  ([a-z0-9-]+):", raw)
        if section and key_match:
            current = key_match.group(1)
            if section == "inputs":
                inputs[current] = {}
            continue
        if section == "inputs" and current:
            required = re.fullmatch(r"    required: (true|false)", raw)
            default = re.fullmatch(r"    default: (.*)", raw)
            if required:
                inputs[current]["required"] = required.group(1) == "true"
            elif default:
                scalar = default.group(1)
                inputs[current]["default"] = (
                    json.loads(scalar) if scalar.startswith('"') else scalar
                )
        elif section == "outputs" and current:
            value = re.fullmatch(r"    value: (.*)", raw)
            if value:
                outputs[current] = value.group(1)
    return inputs, outputs


def test_baseline_v2_schema_and_release_truth() -> None:
    manifest = _manifest()
    schema = _strict_json(SCHEMA)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(manifest)

    assert manifest["schema_version"] == "baseline-v2"
    assert manifest["project"] == {"name": "EvoOM Guard", "version": "4.0.1"}
    assert manifest["capture_source"]["commit_sha"] == CAPTURE_COMMIT
    assert manifest["capture_source"]["relationship"] == "identical-tree"
    assert manifest["release"]["tag"] == "v4.0.1"
    assert manifest["release"]["commit_sha"] == RELEASE_COMMIT
    assert manifest["release"]["tree_sha"] == RELEASE_TREE
    assert manifest["release"]["asset_build_commit_sha"] == RELEASE_COMMIT
    assert manifest["release"]["state"] == "published"
    assert manifest["release"]["immutable"] is True
    assert manifest["release_workflow"]["head_sha"] == RELEASE_COMMIT
    assert manifest["release_workflow"]["pytest"] == {
        "passed": 1157,
        "skipped": 11,
        "subtests_passed": 52,
    }


def test_inventory_is_complete_safe_and_byte_exact() -> None:
    manifest = _manifest()
    entries = manifest["artifact_inventory"]
    assert entries == sorted(entries, key=lambda entry: entry["path"].casefold())
    inventory = _inventory(manifest)

    expected_paths = {entry["path"] for entry in inventory.values()}
    actual_paths = {
        path.relative_to(BASELINE).as_posix()
        for path in BASELINE.rglob("*")
        if path.is_file() and path.name not in METADATA_FILES
    }
    assert actual_paths == expected_paths

    for entry in inventory.values():
        target = _safe_artifact_path(entry["path"])
        assert target.is_file(), f"missing baseline artifact: {entry['path']}"
        assert target.stat().st_size == entry["size_bytes"]
        assert sha256(target) == entry["sha256"]


def test_all_vector_references_resolve_to_inventory() -> None:
    manifest = _manifest()
    inventory = _inventory(manifest)
    vectors = manifest["vectors"]
    references = set(vectors["commands"] + vectors["reports"] + vectors["sarif"])
    references.update(vectors["records"].values())
    references.update(vectors["signed_record"].values())
    references.update(vectors["verifier_pack"]["files"])
    references.add(vectors["verifier_pack"]["doctor_report"])
    references.update(
        {
            manifest["release"]["manifest_artifact_id"],
            manifest["release"]["pyz_artifact_id"],
            manifest["release"]["checksum_artifact_id"],
            manifest["action_contract"]["snapshot_artifact_id"],
            manifest["benchmark"]["artifact_id"],
        }
    )
    assert references <= set(inventory)


def test_release_manifest_binds_asset_provenance_and_workflow() -> None:
    manifest = _manifest()
    inventory = _inventory(manifest)
    release_path = _safe_artifact_path(
        inventory[manifest["release"]["manifest_artifact_id"]]["path"]
    )
    release = _strict_json(release_path)
    assert release["schema_version"] == "evoguard-release-manifest-v1"
    assert release["tag"] == "v4.0.1"
    assert release["commit_sha"] == RELEASE_COMMIT
    assert release["tree_sha"] == RELEASE_TREE
    assert release["state"] == "published"
    assert release["immutable"] is True
    assert release["release_workflow"]["head_sha"] == RELEASE_COMMIT
    assert release["release_workflow"]["run_id"] == 29766032321
    assert release["build_provenance"]["source_digest"] == RELEASE_COMMIT
    assert release["build_provenance"]["subject_sha256"] == PYZ_SHA256
    assert release["build_provenance"]["runner_environment"] == "github-hosted"
    assert release["marketplace"]["version"] == "v4.0.1"


def test_release_checksum_is_exact_and_zipapp_runs_offline() -> None:
    manifest = _manifest()
    inventory = _inventory(manifest)
    pyz = _safe_artifact_path(inventory[manifest["release"]["pyz_artifact_id"]]["path"])
    checks = _safe_artifact_path(
        inventory[manifest["release"]["checksum_artifact_id"]]["path"]
    )
    raw = checks.read_bytes()
    assert raw == f"{PYZ_SHA256}  evo-guard.pyz\n".encode("ascii")
    assert sha256(pyz) == PYZ_SHA256
    completed = subprocess.run(
        [sys.executable, "-I", str(pyz), "version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.stdout.strip() == "evo-guard 4.0.1"
    assert completed.stderr == ""


def test_detached_signature_authenticates_exact_committed_bytes() -> None:
    manifest = _manifest()
    inventory = _inventory(manifest)
    signed = manifest["vectors"]["signed_record"]
    record = _safe_artifact_path(inventory[signed["record"]]["path"])
    signature = _safe_artifact_path(inventory[signed["signature"]]["path"])
    public_key = _safe_artifact_path(inventory[signed["public_key"]]["path"])
    data = record.read_bytes()
    assert b"\r\n" in data
    assert b"\n" not in data.replace(b"\r\n", b"")
    assert verify_file(str(record), str(signature), str(public_key)) is True
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    assert (
        "tests/baseline/v4.0.1/artifacts/record-pass-repo-signed.json -text"
        in attributes
    )


def test_record_report_and_sarif_vectors_are_versioned() -> None:
    manifest = _manifest()
    inventory = _inventory(manifest)
    for expected_verdict, artifact_id in manifest["vectors"]["records"].items():
        record = _strict_json(_safe_artifact_path(inventory[artifact_id]["path"]))
        assert record["schema_version"] == "1.11"
        assert record["tool"] == "evoguard"
        assert record["tool_version"] == "4.0.1"
        assert record["verdict"] == expected_verdict
        assert isinstance(record["reason_code"], str) and record["reason_code"]

    for artifact_id in manifest["vectors"]["sarif"]:
        sarif = _strict_json(_safe_artifact_path(inventory[artifact_id]["path"]))
        assert sarif["version"] == "2.1.0"


def test_verifier_pack_snapshot_recomputes_recorded_identity() -> None:
    manifest = _manifest()
    inventory = _inventory(manifest)
    vector = manifest["vectors"]["verifier_pack"]
    pack_root = BASELINE / "packs" / "blackbox-cli"
    assert pack_digest(str(pack_root)) == vector["sha256"]
    report = _strict_json(_safe_artifact_path(inventory[vector["doctor_report"]]["path"]))
    assert report["ok"] is True
    assert report["pack_digest_format"] == vector["digest_format"]
    assert report["pack_sha256"] == vector["sha256"]


def test_action_snapshot_matches_frozen_input_output_contract() -> None:
    manifest = _manifest()
    inventory = _inventory(manifest)
    snapshot_id = manifest["action_contract"]["snapshot_artifact_id"]
    action = _safe_artifact_path(inventory[snapshot_id]["path"])
    inputs, outputs = _parse_action_contract(action)
    assert len(inputs) == 25
    assert len(outputs) == 5
    assert inputs == manifest["action_contract"]["inputs"]
    assert outputs == manifest["action_contract"]["outputs"]


def test_benchmark_snapshot_is_complete_without_timing_claims() -> None:
    manifest = _manifest()
    inventory = _inventory(manifest)
    benchmark = manifest["benchmark"]
    path = _safe_artifact_path(inventory[benchmark["artifact_id"]]["path"])
    rows = [
        json.loads(line, object_pairs_hook=_unique_object)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(rows) == benchmark["rows"] == 16
    assert len({row["id"] for row in rows}) == len(rows)
    assert all(row["engine_version"] == "4.0.1" for row in rows)
    assert all(row["as_expected"] is True for row in rows)
    assert all(isinstance(row["elapsed_s"], (int, float)) for row in rows)
    assert benchmark["timing_semantics"] == "observational-not-byte-reproducible"
