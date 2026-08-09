# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
"""Fail-closed checks for durable, bounded public runtime observations."""

from __future__ import annotations

import hashlib
import json
import shutil
from copy import deepcopy
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import ValidationError  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[1]
OBSERVATIONS_ROOT = ROOT / "evidence" / "runtime-observations"
SCHEMA_PATH = OBSERVATIONS_ROOT / "runtime-observation-v1.schema.json"
RECORD_DIR = OBSERVATIONS_ROOT / "v4.5.0-gvisor-31298956172"
RECORD_PATH = RECORD_DIR / "PUBLIC_RECORD.json"
RELEASE_LEDGER_PATH = (
    ROOT / "evidence" / "release-ledgers" / "v4.5.0" / "RELEASE_LEDGER.json"
)

EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
IMAGE_ID = "sha256:54a0b2beae90fe14c2131f1e880e1388c9df77390bc260d7317e589765e064e8"
IMAGE_REFERENCE = (
    "python:3.12-slim@"
    "sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36"
)
EXPECTED_RAW_PATHS = (
    "raw/evidence-boundary.txt",
    "raw/guard-broken-add-fail.json",
    "raw/guard-honest-pass.json",
    "raw/gvisor-archive.sha512",
    "raw/gvisor-archive.size",
    "raw/gvisor-source-ref.txt",
    "raw/isolation-conformance.json",
    "raw/observation.json",
    "raw/residual-containers-final.txt",
    "raw/residual-containers.txt",
    "raw/runsc-version.txt",
)
EXPECTED_PROBE_IDS = {
    "candidate_mount_read_only",
    "forbidden_path_read",
    "network_none",
    "normal_cleanup",
    "root_filesystem_read_only",
    "runtime_selection",
    "security_profile",
    "timeout_cleanup",
    "user_identity",
}
EXPECTED_CLAIMS = (
    "This record binds one same-owner GitHub-hosted run to the exact v4.5.0 "
    "release artifact and signed release ledger named here.",
    "On that run, Docker selected runsc for the recorded checksum-pinned gVisor "
    "release, network mode was none, and the resolved container image ID matched "
    "this record.",
    "The release-shipped isolation conformance kit reported one passing gvisor "
    "profile and nine passing required probes.",
    "The external black-box verifier pack reported 2/2 for the honest case and "
    "0/2 with reason_code tests_failed for the deliberately broken add case.",
)
EXPECTED_NONCLAIMS = (
    "not an independent review or independently operated trust domain",
    "not a production deployment or field-efficacy result",
    "not a dedicated-host or hostile-host proof",
    "not an HSM, KMS, production key-custody, or signer proof",
    "not a multi-host, non-forking-ledger, rollback-resistance, or external-witness proof",
    "not a Firecracker, microVM, or dedicated guest-kernel proof",
    "not an independent proof that every installed sidecar reports or enforces the runsc "
    "release identity",
    "not an independent review of the private workflow; its Git blob is bound but its "
    "bytes are not retained here",
    "not proof that gVisor, Docker, the hosted runner, or the workflow is invulnerable",
    "not an audited exact count of candidate calls from the nonzero launcher receipts",
    "not a substitute for the signed v4.5.0 release ledger",
)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _strict_json_bytes(data: bytes) -> dict[str, Any]:
    value = json.loads(
        data.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    assert isinstance(value, dict)
    return value


def _strict_json(path: Path) -> dict[str, Any]:
    return _strict_json_bytes(path.read_bytes())


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _strict_utc_timestamp(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("runtime-observation timestamp must be a string")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError("runtime-observation timestamp must be a valid UTC second") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ValueError("runtime-observation timestamp must be canonical UTC")
    return value


def _safe_record_path(record_dir: Path, relative: str) -> Path:
    assert "\\" not in relative, f"backslash in record path: {relative}"
    pure = PurePosixPath(relative)
    assert not pure.is_absolute(), f"absolute record path: {relative}"
    assert pure.parts and all(part not in {"", ".", ".."} for part in pure.parts)
    target = record_dir.joinpath(*pure.parts)
    assert target.resolve().is_relative_to(record_dir.resolve())
    current = target
    while current != record_dir:
        assert not current.is_symlink(), f"symlink in record path: {relative}"
        current = current.parent
    return target


def _case_map(record: dict[str, Any]) -> dict[str, dict[str, Any]]:
    cases = record["verdict_cases"]
    assert isinstance(cases, list)
    mapped = {str(case["id"]): case for case in cases}
    assert len(mapped) == len(cases)
    return mapped


def _assert_release_binding(record: dict[str, Any]) -> None:
    binding = record["release_binding"]
    ledger_descriptor = binding["ledger"]
    assert ledger_descriptor == {
        "path": "evidence/release-ledgers/v4.5.0/RELEASE_LEDGER.json",
        "sha256": _sha256(RELEASE_LEDGER_PATH),
        "size_bytes": RELEASE_LEDGER_PATH.stat().st_size,
    }
    ledger = _strict_json(RELEASE_LEDGER_PATH)
    release = ledger["release"]
    assert binding["repository"] == release["repository"]
    assert binding["tag"] == release["tag"] == "v4.5.0"
    assert binding["commit"] == release["commit_sha"]
    assert binding["tree"] == release["tree_sha"]
    assert release["immutable"] is True
    artifacts = {artifact["name"]: artifact for artifact in ledger["artifacts"]}
    pyz = artifacts["evo-guard.pyz"]
    assert binding["artifact"] == {
        "name": pyz["name"],
        "sha256": pyz["sha256"],
        "size_bytes": pyz["size_bytes"],
    }


def _assert_source_and_runtime_bindings(
    record: dict[str, Any], record_dir: Path
) -> dict[str, Any]:
    observation = _strict_json(record_dir / "raw" / "observation.json")
    source = record["source_run"]
    github = observation["environment"]["github"]
    assert github["ref"] == "refs/pull/10/merge"
    assert source == {
        "repository": github["repository"],
        "pull_request": 10,
        "run_id": int(github["run_id"]),
        "run_attempt": int(github["run_attempt"]),
        "event_name": github["event_name"],
        "base_sha": github["acceptance_base_sha"],
        "head_sha": github["acceptance_head_sha"],
        # The retained legacy field is GITHUB_SHA for refs/pull/10/merge,
        # not the identity of the workflow file itself.
        "event_merge_sha": github["workflow_sha"],
        "workflow_path": ".github/workflows/release-bound-gvisor-v45.yml",
        "workflow_blob_sha": "e72ed5befeeff24c3ef6c05aa56f73f69a376949",
        "merge_commit_sha": "564545f98bc5c74d9d66bbf99fa5785f404d9928",
    }

    public_core = observation["bindings"]["public_core"]
    assert record["release_binding"]["repository"] == public_core["repository"]
    assert record["release_binding"]["tag"] == public_core["release"]
    assert record["release_binding"]["commit"] == public_core["commit"]
    assert record["release_binding"]["tree"] == public_core["tree"]
    assert record["release_binding"]["artifact"] == {
        "name": "evo-guard.pyz",
        "sha256": public_core["pyz"]["sha256"],
        "size_bytes": public_core["pyz"]["size"],
    }

    runtime = record["runtime_binding"]
    gvisor = observation["bindings"]["gvisor"]
    image = observation["bindings"]["container_image"]
    assert runtime == {
        "provider": "gvisor",
        "runtime": gvisor["runtime_name"],
        "tag": gvisor["tag"],
        "tag_object": gvisor["tag_object"],
        "peeled_commit": gvisor["peeled_commit"],
        "version_lines": observation["environment"]["runsc_version"],
        "archive": {
            "url": gvisor["archive_url"],
            "sha512": gvisor["archive_sha512"],
            "size_bytes": gvisor["archive_size"],
        },
        "requested_image": image["requested"],
        "resolved_image_id": image["resolved_image_id"],
        "network": "none",
        "runner_os": github["runner_os"],
        "runner_arch": github["runner_arch"],
    }
    assert runtime["requested_image"] == IMAGE_REFERENCE
    assert runtime["resolved_image_id"] == IMAGE_ID

    assert (record_dir / "raw" / "gvisor-source-ref.txt").read_text(
        encoding="ascii"
    ).splitlines() == [
        f"{runtime['tag_object']}\trefs/tags/{runtime['tag']}",
        f"{runtime['peeled_commit']}\trefs/tags/{runtime['tag']}^{{}}",
    ]
    assert (record_dir / "raw" / "runsc-version.txt").read_text(
        encoding="ascii"
    ).splitlines() == runtime["version_lines"]
    checksum_line = (record_dir / "raw" / "gvisor-archive.sha512").read_text(
        encoding="ascii"
    )
    assert checksum_line.startswith(f"{runtime['archive']['sha512']}  ")
    assert int(
        (record_dir / "raw" / "gvisor-archive.size").read_text(encoding="ascii")
    ) == runtime["archive"]["size_bytes"]
    return observation


def _assert_conformance(record: dict[str, Any], record_dir: Path) -> None:
    binding = record["conformance"]
    conformance = _strict_json(_safe_record_path(record_dir, binding["raw_path"]))
    profiles = conformance["profiles"]
    assert isinstance(profiles, list) and len(profiles) == 1
    profile = profiles[0]
    probes = profile["probes"]
    assert binding == {
        "raw_path": "raw/isolation-conformance.json",
        "suite_id": conformance["suite_id"],
        "profile_id": profile["id"],
        "status": conformance["status"],
        "profiles_total": sum(conformance["summary"]["profiles"].values()),
        "profiles_passed": conformance["summary"]["profiles"]["pass"],
        "probes_total": sum(conformance["summary"]["probes"].values()),
        "probes_passed": conformance["summary"]["probes"]["pass"],
    }
    assert binding["profiles_total"] == binding["profiles_passed"] == 1
    assert binding["probes_total"] == binding["probes_passed"] == 9
    assert profile["status"] == "pass"
    assert profile["requested_runtime"] == "runsc"
    assert profile["runtime"] == {
        "available": True,
        "available_runtimes": ["io.containerd.runc.v2", "runc", "runsc"],
        "observed": "runsc",
        "requested": "runsc",
    }
    inspect = profile["container"]["inspect"]
    assert inspect["runtime"] == "runsc"
    assert inspect["network_mode"] == "none"
    assert inspect["image"] == IMAGE_ID
    assert len(probes) == len(EXPECTED_PROBE_IDS)
    assert {probe["id"] for probe in probes} == EXPECTED_PROBE_IDS
    assert all(probe["required"] is True and probe["status"] == "pass" for probe in probes)


def _assert_verdicts(record: dict[str, Any], record_dir: Path) -> None:
    cases = _case_map(record)
    assert set(cases) == {"honest-pass", "broken-add-fail"}
    expected_semantics = {
        "honest-pass": {
            "verdict": "PASS",
            "passed": True,
            "exit_code": 0,
            "reason_code": "tests_passed",
            "tests_passed": 2,
            "tests_total": 2,
        },
        "broken-add-fail": {
            "verdict": "FAIL",
            "passed": False,
            "exit_code": 1,
            "reason_code": "tests_failed",
            "tests_passed": 0,
            "tests_total": 2,
        },
    }
    for case_id, case in cases.items():
        verdict = _strict_json(_safe_record_path(record_dir, case["raw_path"]))
        for field, value in expected_semantics[case_id].items():
            assert case[field] == verdict[field] == value
        for field in (
            "files_changed",
            "protected_violations",
            "execution_state",
            "execution_phase",
            "verdict_source",
            "isolation",
        ):
            assert case[field] == verdict[field]
        assert case["files_changed"] == ["calc/ops.py"]
        assert case["protected_violations"] == []
        evidence = verdict["attestation"]["isolation_evidence"]
        assert evidence == verdict["attestation"]["blackbox_pack_isolation_evidence"]
        assert case["runtime"] == evidence["runtime"] == "runsc"
        assert case["network"] == evidence["network"] == "none"
        assert case["resolved_image_id"] == evidence["image_digest"] == IMAGE_ID
        assert evidence["requested"] == evidence["delivered"] == "gvisor"
        assert evidence["image"] == IMAGE_REFERENCE
        assert evidence["candidate_launcher_invocation_observed"] is True
        assert evidence["candidate_launcher_events"] > 0
        assert evidence["candidate_container_ids_observed"] > 0
        assert evidence["candidate_invocations"] > 0
        assert (
            case["launcher_receipt_assertion"]
            == "nonzero-not-an-audited-exact-call-count"
        )


def _assert_cleanup(record: dict[str, Any], record_dir: Path) -> None:
    assert record["cleanup"] == {
        "post_cases": {
            "path": "raw/residual-containers.txt",
            "sha256": EMPTY_SHA256,
            "size_bytes": 0,
        },
        "final": {
            "path": "raw/residual-containers-final.txt",
            "sha256": EMPTY_SHA256,
            "size_bytes": 0,
        },
    }
    for descriptor in record["cleanup"].values():
        assert _safe_record_path(record_dir, descriptor["path"]).read_bytes() == b""
    conformance = _strict_json(record_dir / "raw" / "isolation-conformance.json")
    profiles = conformance["profiles"]
    assert isinstance(profiles, list) and len(profiles) == 1
    probes = {probe["id"]: probe for probe in profiles[0]["probes"]}
    assert probes["normal_cleanup"]["observed"]["proven_absent"] is True
    assert probes["timeout_cleanup"]["observed"]["cleanup"]["proven_absent"] is True


def _assert_record(record: dict[str, Any], record_dir: Path = RECORD_DIR) -> None:
    schema = _strict_json(SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(record)
    _strict_utc_timestamp(record["transfer"]["expires_at"])

    inventory = record["raw_inventory"]
    paths = tuple(item["path"] for item in inventory)
    assert paths == tuple(sorted(paths)) == EXPECTED_RAW_PATHS
    assert len(paths) == len(set(paths))
    actual = {
        path.relative_to(record_dir).as_posix()
        for path in (record_dir / "raw").rglob("*")
        if path.is_file()
    }
    assert actual == set(paths)
    for item in inventory:
        path = _safe_record_path(record_dir, item["path"])
        assert path.is_file()
        assert path.stat().st_size == item["size_bytes"]
        assert _sha256(path) == item["sha256"]

    observation = _assert_source_and_runtime_bindings(record, record_dir)
    observation_evidence = observation["evidence"]
    inventory_by_path = {item["path"]: item for item in inventory}
    selected_observation_descriptors = (
        observation_evidence["conformance"],
        observation_evidence["guard_cases"]["honest-pass"]["verdict"],
        observation_evidence["guard_cases"]["broken-add-fail"]["verdict"],
        observation_evidence["installation"]["evidence_boundary"],
        observation_evidence["installation"]["gvisor_archive_sha512"],
        observation_evidence["installation"]["gvisor_archive_size"],
        observation_evidence["installation"]["gvisor_source_ref"],
        observation_evidence["installation"]["runsc_version"],
        observation_evidence["cleanup"],
    )
    for descriptor in selected_observation_descriptors:
        retained = inventory_by_path[f"raw/{descriptor['path']}"]
        assert retained["sha256"] == descriptor["sha256"]
        assert retained["size_bytes"] == descriptor["size"]

    _assert_release_binding(record)
    _assert_conformance(record, record_dir)
    _assert_verdicts(record, record_dir)
    _assert_cleanup(record, record_dir)
    assert tuple(record["claims"]) == EXPECTED_CLAIMS
    assert tuple(record["nonclaims"]) == EXPECTED_NONCLAIMS
    assert record["transfer"] == {
        "carrier": "github-actions-artifact",
        "source_run_id": record["source_run"]["run_id"],
        "artifact_id": 9033891750,
        "artifact_name": "evoom-guard-v4.5.0-gvisor-31298956172-1",
        "artifact_digest": (
            "sha256:3adeffcc910988b0f98f9e9970dcc5cfd16d5ab7902d349aa5c6c12a379b321b"
        ),
        "expires_at": "2026-08-23T06:29:32Z",
        "role": "transient-locator-not-source-of-truth",
        "transient": True,
        "durable_subset": "this-directory",
    }
    assert (record_dir / "raw" / "evidence-boundary.txt").read_text(
        encoding="ascii"
    ) == "same-owner GitHub-hosted observation; not production or independent\n"


def test_public_runtime_observation_is_closed_bound_and_byte_exact() -> None:
    _assert_record(_strict_json(RECORD_PATH))


def test_all_retained_json_rejects_duplicate_keys_and_nonfinite_numbers() -> None:
    for path in (SCHEMA_PATH, RECORD_PATH, RELEASE_LEDGER_PATH):
        _strict_json(path)
    for path in (RECORD_DIR / "raw").glob("*.json"):
        _strict_json(path)
    with pytest.raises(ValueError, match="duplicate JSON key: status"):
        _strict_json_bytes(b'{"status":"pass","status":"fail"}')
    with pytest.raises(ValueError, match="non-finite JSON number: NaN"):
        _strict_json_bytes(b'{"value":NaN}')


def test_schema_rejects_malformed_transfer_expiry() -> None:
    schema = _strict_json(SCHEMA_PATH)
    record = deepcopy(_strict_json(RECORD_PATH))
    record["transfer"]["expires_at"] = "not-a-date"

    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(record)


def test_verifier_rejects_invalid_calendar_transfer_expiry() -> None:
    record = deepcopy(_strict_json(RECORD_PATH))
    record["transfer"]["expires_at"] = "2026-02-31T06:29:32Z"

    with pytest.raises(ValueError, match="valid UTC second"):
        _assert_record(record)


@pytest.mark.parametrize(
    "mutation",
    (
        "unknown-top-level-field",
        "production-overclaim",
        "drop-inventory-entry",
        "replace-inventory-hash",
        "release-commit-drift",
        "gvisor-peeled-commit-drift",
        "network-drift",
        "probe-count-drift",
        "honest-verdict-flip",
        "negative-reason-flip",
        "drop-nonclaim",
        "add-claim",
        "launcher-count-overclaim",
    ),
)
def test_public_runtime_observation_mutations_fail_closed(mutation: str) -> None:
    record = deepcopy(_strict_json(RECORD_PATH))
    cases = _case_map(record)
    if mutation == "unknown-top-level-field":
        record["unexpected"] = True
    elif mutation == "production-overclaim":
        record["scope"]["production"] = True
    elif mutation == "drop-inventory-entry":
        record["raw_inventory"].pop()
    elif mutation == "replace-inventory-hash":
        record["raw_inventory"][0]["sha256"] = "0" * 64
    elif mutation == "release-commit-drift":
        record["release_binding"]["commit"] = "0" * 40
    elif mutation == "gvisor-peeled-commit-drift":
        record["runtime_binding"]["peeled_commit"] = "0" * 40
    elif mutation == "network-drift":
        record["runtime_binding"]["network"] = "bridge"
    elif mutation == "probe-count-drift":
        record["conformance"]["probes_passed"] = 8
    elif mutation == "honest-verdict-flip":
        cases["honest-pass"]["verdict"] = "FAIL"
    elif mutation == "negative-reason-flip":
        cases["broken-add-fail"]["reason_code"] = "tests_passed"
    elif mutation == "drop-nonclaim":
        record["nonclaims"].pop()
    elif mutation == "add-claim":
        record["claims"].append("production proven")
    elif mutation == "launcher-count-overclaim":
        cases["honest-pass"]["launcher_receipt_assertion"] = "exactly-three-calls"
    else:  # pragma: no cover - the parametrization above is closed.
        raise AssertionError(f"unknown mutation: {mutation}")
    with pytest.raises((AssertionError, ValidationError)):
        _assert_record(record)


def test_retained_raw_byte_mutation_fails_closed(tmp_path: Path) -> None:
    mutated = tmp_path / RECORD_DIR.name
    shutil.copytree(RECORD_DIR, mutated)
    target = mutated / "raw" / "runsc-version.txt"
    target.write_bytes(target.read_bytes() + b"tampered\n")
    with pytest.raises(AssertionError):
        _assert_record(_strict_json(mutated / "PUBLIC_RECORD.json"), mutated)
