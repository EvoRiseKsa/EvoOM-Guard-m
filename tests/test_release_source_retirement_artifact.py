from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools/ci/validate_release_source_retirement_artifact.py"
SPEC = importlib.util.spec_from_file_location("release_source_retirement_artifact", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

REPOSITORY = "EvoRiseKsa/EvoOM-Guard-m"
REPOSITORY_ID = 123456
BASE_SHA = "a" * 40
MAIN_SHA = "b" * 40
RUN_ID = 987654321
RUN_ATTEMPT = 2
PR_NUMBER = 444
RULESET_ID = 7654321
DEPLOY_KEY_ID = 24680
DEPLOY_KEY_FINGERPRINT = "SHA256:gNSIRW+2Iyiuvsdp/bgjy38bvWHw6wQm3tuoXrl3WjQ"
ACTIVE_SNAPSHOT_RAW = b'{"fixture":"active-source-authority"}\n'
RETIRED_SNAPSHOT_RAW = b'{"fixture":"retired-source-authority"}\n'


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _descriptor(raw: bytes) -> dict[str, object]:
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}


def _receipt(
    authority_state: str,
    *,
    snapshot_raw: bytes,
    main_sha: str,
) -> dict[str, object]:
    active = authority_state == "source-active"
    return {
        "format": MODULE.RECEIPT_FORMAT,
        "verdict": "PASS",
        "api_version": MODULE.API_VERSION,
        "started_at": "2026-08-15T11:59:45Z",
        "observed_at": "2026-08-15T12:00:00Z",
        "capture_duration_seconds": 15,
        "snapshot_age_seconds": 30,
        "snapshot_sha256": hashlib.sha256(snapshot_raw).hexdigest(),
        "repository": {"full_name": REPOSITORY, "id": REPOSITORY_ID},
        "main_authority": {
            "authority_state": authority_state,
            "main_sha": main_sha,
            "classic_branch_protection_absent": True,
            "ruleset_id": RULESET_ID,
            "ruleset_target": "branch",
            "ruleset_enforcement": "active",
            "sole_bypass_actor": "DeployKey" if active else None,
            "deploy_key_id": DEPLOY_KEY_ID if active else None,
            "deploy_key_fingerprint": DEPLOY_KEY_FINGERPRINT if active else None,
            "retired_deploy_key_id": None if active else DEPLOY_KEY_ID,
            "retired_deploy_key_fingerprint": (None if active else DEPLOY_KEY_FINGERPRINT),
            "enabled_write_deploy_key_count": 1 if active else 0,
        },
        "required_status_checks": [
            {"context": context, "integration_id": integration}
            for context, integration in sorted(MODULE.EXPECTED_STATUS_CHECKS)
        ],
    }


def _closure(
    active_receipt_raw: bytes,
    retired_receipt_raw: bytes,
    active_snapshot_raw: bytes = ACTIVE_SNAPSHOT_RAW,
    retired_snapshot_raw: bytes = RETIRED_SNAPSHOT_RAW,
    *,
    promotion_completed: bool = True,
    terminal_main_sha: str = MAIN_SHA,
) -> dict[str, object]:
    return {
        "format": MODULE.CLOSURE_FORMAT,
        "run_id": str(RUN_ID),
        "run_attempt": RUN_ATTEMPT,
        "promotion_completed": promotion_completed,
        "base_sha": BASE_SHA,
        "candidate_sha": MAIN_SHA,
        "pull_request_number": PR_NUMBER,
        "main_sha_after_attempt": terminal_main_sha,
        "main_ruleset_id": RULESET_ID,
        "source_deploy_key_id": DEPLOY_KEY_ID,
        "source_deploy_key_fingerprint": DEPLOY_KEY_FINGERPRINT,
        "source_deploy_key_absent": True,
        "main_deploy_key_bypass_absent": True,
        "retired_source_deploy_key_id": DEPLOY_KEY_ID,
        "retired_source_deploy_key_fingerprint": DEPLOY_KEY_FINGERPRINT,
        "active_snapshot": _descriptor(active_snapshot_raw),
        "active_verification": _descriptor(active_receipt_raw),
        "retired_snapshot": _descriptor(retired_snapshot_raw),
        "retired_verification": _descriptor(retired_receipt_raw),
        "boundary": {
            "github_control_plane_point_in_time": True,
            "private_key_erasure_claimed": False,
            "future_non_readdition_claimed": False,
        },
    }


def _artifact(
    tmp_path: Path,
    *,
    promotion_completed: bool = True,
    terminal_main_sha: str = MAIN_SHA,
) -> Path:
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    active_receipt_raw = _canonical(
        _receipt(
            "source-active",
            snapshot_raw=ACTIVE_SNAPSHOT_RAW,
            main_sha=BASE_SHA,
        )
    )
    retired_receipt_raw = _canonical(
        _receipt(
            "source-retired",
            snapshot_raw=RETIRED_SNAPSHOT_RAW,
            main_sha=terminal_main_sha,
        )
    )
    (artifact / "source-authority-active.json").write_bytes(ACTIVE_SNAPSHOT_RAW)
    (artifact / "source-authority-active-receipt.json").write_bytes(active_receipt_raw)
    (artifact / "source-authority-retired.json").write_bytes(RETIRED_SNAPSHOT_RAW)
    (artifact / "source-authority-retired-receipt.json").write_bytes(retired_receipt_raw)
    (artifact / "source-authority-closure.json").write_bytes(
        _canonical(
            _closure(
                active_receipt_raw,
                retired_receipt_raw,
                promotion_completed=promotion_completed,
                terminal_main_sha=terminal_main_sha,
            )
        )
    )
    return artifact


def _rewrite(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value))


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _validate(artifact: Path, **overrides: object) -> dict[str, Any]:
    arguments: dict[str, object] = {
        "expected_repository": REPOSITORY,
        "expected_repository_id": REPOSITORY_ID,
        "expected_base_sha": BASE_SHA,
        "expected_candidate_sha": MAIN_SHA,
        "expected_promotion_run_id": RUN_ID,
        "expected_promotion_run_attempt": RUN_ATTEMPT,
    }
    arguments.update(overrides)
    return MODULE.validate(artifact, **arguments)


def test_valid_closed_artifact_produces_complete_binding(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    binding = _validate(artifact)
    assert binding["format"] == MODULE.FORMAT
    assert binding["repository"] == {"full_name": REPOSITORY, "id": REPOSITORY_ID}
    assert binding["target"] == {
        "base_sha": BASE_SHA,
        "candidate_sha": MAIN_SHA,
        "main_sha": MAIN_SHA,
        "promotion_completed": True,
        "pull_request_number": PR_NUMBER,
    }
    assert binding["promotion_run"] == {
        "run_id": str(RUN_ID),
        "run_attempt": RUN_ATTEMPT,
    }
    assert binding["main_ruleset_id"] == RULESET_ID
    assert binding["active_source_authority"]["authority_state"] == "source-active"
    assert binding["active_source_authority"]["main_sha"] == BASE_SHA
    assert binding["retired_source_authority"]["authority_state"] == "source-retired"
    assert binding["retired_source_authority"]["main_sha"] == MAIN_SHA
    for state in ("active_source_authority", "retired_source_authority"):
        assert binding[state]["ruleset_id"] == RULESET_ID
        assert binding[state]["deploy_key_id"] == DEPLOY_KEY_ID
        assert binding[state]["deploy_key_fingerprint"] == DEPLOY_KEY_FINGERPRINT
        assert set(binding[state]) == {
            "authority_state",
            "main_sha",
            "started_at",
            "observed_at",
            "ruleset_id",
            "deploy_key_id",
            "deploy_key_fingerprint",
            "snapshot",
            "verification",
        }
    assert binding["retired_source_deploy_key"] == {
        "id": DEPLOY_KEY_ID,
        "fingerprint": DEPLOY_KEY_FINGERPRINT,
    }
    assert set(binding["descriptors"]) == MODULE.EXPECTED_FILES
    for name in MODULE.EXPECTED_FILES:
        assert binding["descriptors"][name] == _descriptor((artifact / name).read_bytes())


def test_cli_writes_canonical_create_only_binding(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    output = tmp_path / "binding.json"
    arguments = [
        "--artifact",
        str(artifact),
        "--expected-repository",
        REPOSITORY,
        "--expected-repository-id",
        str(REPOSITORY_ID),
        "--expected-base-sha",
        BASE_SHA,
        "--expected-candidate-sha",
        MAIN_SHA,
        "--expected-promotion-run-id",
        str(RUN_ID),
        "--expected-promotion-run-attempt",
        str(RUN_ATTEMPT),
        "--binding-out",
        str(output),
    ]
    assert MODULE.main(arguments) == 0
    value = json.loads(output.read_bytes())
    assert output.read_bytes() == _canonical(value)
    assert MODULE.main(arguments) == 1


@pytest.mark.parametrize(
    ("filename", "raw"),
    [
        (
            "source-authority-active-receipt.json",
            b'{"format":"first","format":"second"}\n',
        ),
        (
            "source-authority-retired-receipt.json",
            b'{"format":"first","format":"second"}\n',
        ),
        (
            "source-authority-closure.json",
            b'{"format":"first","format":"second"}\n',
        ),
    ],
)
def test_duplicate_json_members_are_rejected(tmp_path: Path, filename: str, raw: bytes) -> None:
    artifact = _artifact(tmp_path)
    (artifact / filename).write_bytes(raw)
    with pytest.raises(MODULE.RetirementArtifactError, match="repeats member"):
        _validate(artifact)


@pytest.mark.parametrize(
    "filename",
    [
        "source-authority-active-receipt.json",
        "source-authority-retired-receipt.json",
        "source-authority-closure.json",
    ],
)
def test_nonfinite_json_is_rejected(tmp_path: Path, filename: str) -> None:
    artifact = _artifact(tmp_path)
    (artifact / filename).write_bytes(b'{"forbidden":NaN}\n')
    with pytest.raises(MODULE.RetirementArtifactError, match="forbidden constant"):
        _validate(artifact)


@pytest.mark.parametrize(
    "receipt_name",
    [
        "source-authority-active-receipt.json",
        "source-authority-retired-receipt.json",
    ],
)
@pytest.mark.parametrize("mutation", ["extra", "missing"])
def test_receipt_inventory_is_exact(tmp_path: Path, receipt_name: str, mutation: str) -> None:
    artifact = _artifact(tmp_path)
    path = artifact / receipt_name
    receipt = _load(path)
    if mutation == "extra":
        receipt["extra"] = True
    else:
        receipt.pop("verdict")
    _rewrite(path, receipt)
    with pytest.raises(MODULE.RetirementArtifactError, match="inventory"):
        _validate(artifact)


@pytest.mark.parametrize("mutation", ["extra", "missing"])
def test_closure_inventory_is_exact(tmp_path: Path, mutation: str) -> None:
    artifact = _artifact(tmp_path)
    path = artifact / "source-authority-closure.json"
    closure = _load(path)
    if mutation == "extra":
        closure["extra"] = True
    else:
        closure.pop("boundary")
    _rewrite(path, closure)
    with pytest.raises(MODULE.RetirementArtifactError, match="inventory"):
        _validate(artifact)


def test_artifact_inventory_rejects_extra_and_missing_files(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    (artifact / "unexpected.txt").write_text("no", encoding="utf-8")
    with pytest.raises(MODULE.RetirementArtifactError, match="file inventory"):
        _validate(artifact)
    (artifact / "unexpected.txt").unlink()
    (artifact / "source-authority-closure.json").unlink()
    with pytest.raises(MODULE.RetirementArtifactError, match="file inventory"):
        _validate(artifact)


@pytest.mark.parametrize(
    ("filename", "raw"),
    [
        ("source-authority-active.json", ACTIVE_SNAPSHOT_RAW),
        ("source-authority-retired.json", RETIRED_SNAPSHOT_RAW),
    ],
)
def test_snapshot_tamper_is_rejected(tmp_path: Path, filename: str, raw: bytes) -> None:
    artifact = _artifact(tmp_path)
    (artifact / filename).write_bytes(raw + b" ")
    with pytest.raises(MODULE.RetirementArtifactError, match="snapshot SHA-256"):
        _validate(artifact)


@pytest.mark.parametrize(
    "descriptor_name",
    [
        "active_snapshot",
        "active_verification",
        "retired_snapshot",
        "retired_verification",
    ],
)
def test_closure_descriptor_mismatch_is_rejected(tmp_path: Path, descriptor_name: str) -> None:
    artifact = _artifact(tmp_path)
    path = artifact / "source-authority-closure.json"
    closure = _load(path)
    closure[descriptor_name]["sha256"] = "0" * 64
    _rewrite(path, closure)
    with pytest.raises(MODULE.RetirementArtifactError, match="does not bind"):
        _validate(artifact)


@pytest.mark.parametrize(
    ("field", "value"),
    [("run_id", "123"), ("run_attempt", 3), ("run_attempt", True), ("run_attempt", 2.0)],
)
def test_wrong_or_noninteger_promotion_run_binding_is_rejected(
    tmp_path: Path, field: str, value: object
) -> None:
    artifact = _artifact(tmp_path)
    path = artifact / "source-authority-closure.json"
    closure = _load(path)
    closure[field] = value
    _rewrite(path, closure)
    with pytest.raises(MODULE.RetirementArtifactError, match="promotion run"):
        _validate(artifact)


@pytest.mark.parametrize("value", [1, 1.0, None])
def test_closure_requires_an_exact_json_boolean_for_completed_promotion(
    tmp_path: Path, value: object
) -> None:
    artifact = _artifact(tmp_path)
    path = artifact / "source-authority-closure.json"
    closure = _load(path)
    closure["promotion_completed"] = value
    _rewrite(path, closure)
    with pytest.raises(MODULE.RetirementArtifactError, match="JSON boolean"):
        _validate(artifact)


def test_unpromoted_terminal_closure_is_p_only_and_binds_the_base(tmp_path: Path) -> None:
    artifact = _artifact(
        tmp_path,
        promotion_completed=False,
        terminal_main_sha=BASE_SHA,
    )
    with pytest.raises(MODULE.RetirementArtifactError, match="promotion completed"):
        _validate(artifact)

    binding = _validate(artifact, allow_unpromoted_terminal_closure=True)
    assert binding["target"] == {
        "base_sha": BASE_SHA,
        "candidate_sha": MAIN_SHA,
        "main_sha": BASE_SHA,
        "promotion_completed": False,
        "pull_request_number": PR_NUMBER,
    }
    assert binding["active_source_authority"]["main_sha"] == BASE_SHA
    assert binding["retired_source_authority"]["main_sha"] == BASE_SHA


@pytest.mark.parametrize(
    ("promotion_completed", "terminal_main_sha", "message"),
    [
        (True, BASE_SHA, "candidate terminal state"),
        (False, MAIN_SHA, "base terminal state"),
        (False, "c" * 40, "base terminal state"),
    ],
)
def test_terminal_state_must_match_the_exact_boolean_state(
    tmp_path: Path,
    promotion_completed: bool,
    terminal_main_sha: str,
    message: str,
) -> None:
    artifact = _artifact(
        tmp_path,
        promotion_completed=promotion_completed,
        terminal_main_sha=terminal_main_sha,
    )
    with pytest.raises(MODULE.RetirementArtifactError, match=message):
        _validate(artifact, allow_unpromoted_terminal_closure=True)


def test_terminal_receipt_and_closure_main_must_match(tmp_path: Path) -> None:
    artifact = _artifact(
        tmp_path,
        promotion_completed=False,
        terminal_main_sha=BASE_SHA,
    )
    closure_path = artifact / "source-authority-closure.json"
    closure = _load(closure_path)
    closure["promotion_completed"] = True
    closure["main_sha_after_attempt"] = MAIN_SHA
    _rewrite(closure_path, closure)
    with pytest.raises(MODULE.RetirementArtifactError, match="main SHA"):
        _validate(artifact, allow_unpromoted_terminal_closure=True)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("main_ruleset_id", RULESET_ID + 1),
        ("source_deploy_key_id", DEPLOY_KEY_ID + 1),
        (
            "source_deploy_key_fingerprint",
            "SHA256:GJ8X8ywwW/rSXwQ8sBu/2RYiz0+a2xNJMmsUwslS+RA",
        ),
        ("retired_source_deploy_key_id", DEPLOY_KEY_ID + 1),
        (
            "retired_source_deploy_key_fingerprint",
            "SHA256:GJ8X8ywwW/rSXwQ8sBu/2RYiz0+a2xNJMmsUwslS+RA",
        ),
    ],
)
def test_closure_retired_key_must_match_receipt(tmp_path: Path, field: str, value: object) -> None:
    artifact = _artifact(tmp_path)
    path = artifact / "source-authority-closure.json"
    closure = _load(path)
    closure[field] = value
    _rewrite(path, closure)
    with pytest.raises(MODULE.RetirementArtifactError, match="does not match"):
        _validate(artifact)


@pytest.mark.parametrize(
    ("receipt_name", "field", "value", "message"),
    [
        (
            "source-authority-active-receipt.json",
            "ruleset_id",
            RULESET_ID + 1,
            "ruleset",
        ),
        (
            "source-authority-active-receipt.json",
            "deploy_key_id",
            DEPLOY_KEY_ID + 1,
            "deploy-key ID",
        ),
        (
            "source-authority-retired-receipt.json",
            "retired_deploy_key_fingerprint",
            "SHA256:GJ8X8ywwW/rSXwQ8sBu/2RYiz0+a2xNJMmsUwslS+RA",
            "fingerprint",
        ),
    ],
)
def test_active_and_retired_authority_identity_must_match(
    tmp_path: Path,
    receipt_name: str,
    field: str,
    value: object,
    message: str,
) -> None:
    artifact = _artifact(tmp_path)
    receipt_path = artifact / receipt_name
    receipt = _load(receipt_path)
    receipt["main_authority"][field] = value
    _rewrite(receipt_path, receipt)
    closure_path = artifact / "source-authority-closure.json"
    closure = _load(closure_path)
    descriptor_name = (
        "active_verification"
        if receipt_name == "source-authority-active-receipt.json"
        else "retired_verification"
    )
    closure[descriptor_name] = _descriptor(receipt_path.read_bytes())
    _rewrite(closure_path, closure)
    with pytest.raises(MODULE.RetirementArtifactError, match=message):
        _validate(artifact)


def test_active_base_must_advance_to_retired_candidate(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    receipt_path = artifact / "source-authority-active-receipt.json"
    receipt = _load(receipt_path)
    receipt["main_authority"]["main_sha"] = "c" * 40
    _rewrite(receipt_path, receipt)
    closure_path = artifact / "source-authority-closure.json"
    closure = _load(closure_path)
    closure["active_verification"] = _descriptor(receipt_path.read_bytes())
    _rewrite(closure_path, closure)
    with pytest.raises(MODULE.RetirementArtifactError, match="expected promoted target"):
        _validate(artifact)


def test_retired_observation_must_not_predate_active_observation(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    receipt_path = artifact / "source-authority-active-receipt.json"
    receipt = _load(receipt_path)
    receipt["started_at"] = "2026-08-15T12:00:45Z"
    receipt["observed_at"] = "2026-08-15T12:01:00Z"
    _rewrite(receipt_path, receipt)
    closure_path = artifact / "source-authority-closure.json"
    closure = _load(closure_path)
    closure["active_verification"] = _descriptor(receipt_path.read_bytes())
    _rewrite(closure_path, closure)
    with pytest.raises(MODULE.RetirementArtifactError, match="predates"):
        _validate(artifact)


@pytest.mark.parametrize(
    ("path", "field", "value"),
    [
        ("repository", "id", float(REPOSITORY_ID)),
        ("main_authority", "enabled_write_deploy_key_count", False),
        ("main_authority", "ruleset_id", True),
        ("root", "snapshot_age_seconds", 30.0),
    ],
)
def test_receipt_integer_fields_reject_bool_and_float_equivalents(
    tmp_path: Path, path: str, field: str, value: object
) -> None:
    artifact = _artifact(tmp_path)
    receipt_path = artifact / "source-authority-retired-receipt.json"
    receipt = _load(receipt_path)
    target = receipt if path == "root" else receipt[path]
    target[field] = value
    _rewrite(receipt_path, receipt)
    with pytest.raises(MODULE.RetirementArtifactError):
        _validate(artifact)


def test_noncanonical_receipt_or_closure_is_rejected(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    receipt_path = artifact / "source-authority-retired-receipt.json"
    receipt_path.write_text(json.dumps(_load(receipt_path), indent=2) + "\n", encoding="utf-8")
    with pytest.raises(MODULE.RetirementArtifactError, match="canonical JSON"):
        _validate(artifact)


def test_symlinked_member_is_rejected(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    member = artifact / "source-authority-retired.json"
    outside = tmp_path / "outside.json"
    outside.write_bytes(member.read_bytes())
    member.unlink()
    try:
        member.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks are unavailable: {exc}")
    with pytest.raises(MODULE.RetirementArtifactError, match="non-symlink"):
        _validate(artifact)


def test_hardlinked_member_is_rejected(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    member = artifact / "source-authority-retired.json"
    outside = tmp_path / "hardlink.json"
    try:
        os.link(member, outside)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")
    with pytest.raises(MODULE.RetirementArtifactError, match="filesystem link"):
        _validate(artifact)


def test_empty_or_oversized_member_is_rejected(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    member = artifact / "source-authority-closure.json"
    member.write_bytes(b"")
    with pytest.raises(MODULE.RetirementArtifactError, match="outside bounds"):
        _validate(artifact)


def test_expected_argument_types_are_strict(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    with pytest.raises(MODULE.RetirementArtifactError, match="positive JSON integer"):
        _validate(artifact, expected_promotion_run_attempt=True)
    with pytest.raises(MODULE.RetirementArtifactError, match="positive JSON integer"):
        _validate(artifact, expected_repository_id=float(REPOSITORY_ID))


def test_binding_cannot_be_written_inside_closed_artifact(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    binding = _validate(artifact)
    with pytest.raises(MODULE.RetirementArtifactError, match="outside"):
        MODULE._write_binding(artifact / "binding.json", binding, artifact)
