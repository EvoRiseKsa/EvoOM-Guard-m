#!/usr/bin/env python3
"""Bind a downloaded signed-source retirement artifact fail closed.

After the source-promotion workflow has emitted its closed active-authority
artifact, it emits one terminal artifact once the temporary write authority has
been retired.  The terminal state is either the exact candidate (promotion
completed) or the exact base (promotion did not complete).  This verifier is
intended to run from a separately trusted workflow.  It accepts only the exact
five-file active/retired artifact, independently checks both receipts and closure
contracts, and writes a create-only canonical binding for downstream release
gates.  Unpromoted terminal closure is rejected by default and is available only
through an explicit source-promotion-internal opt-in.

The point-in-time GitHub observations remain control-plane evidence.  This
binding does not turn them into an independence, key-erasure, or future-state
claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

FORMAT = "EVOGUARD_RELEASE_SOURCE_RETIREMENT_BINDING_V1"
RECEIPT_FORMAT = "EVOGUARD_RELEASE_SOURCE_PROTECTION_VERIFICATION_V1"
CLOSURE_FORMAT = "EVOGUARD_SIGNED_SOURCE_AUTHORITY_CLOSURE_V1"
API_VERSION = "2026-03-10"
FROZEN_REPOSITORY = "EvoRiseKsa/EvoOM-Guard-m"
EXPECTED_FILES = frozenset(
    {
        "source-authority-active.json",
        "source-authority-active-receipt.json",
        "source-authority-retired.json",
        "source-authority-retired-receipt.json",
        "source-authority-closure.json",
    }
)
FILE_LIMITS = {
    "source-authority-active.json": 2 * 1024 * 1024,
    "source-authority-active-receipt.json": 256 * 1024,
    "source-authority-retired.json": 2 * 1024 * 1024,
    "source-authority-retired-receipt.json": 256 * 1024,
    "source-authority-closure.json": 128 * 1024,
}
EXPECTED_STATUS_CHECKS = frozenset(
    {
        ("test (3.10)", 15368),
        ("test (3.11)", 15368),
        ("test (3.12)", 15368),
        ("e2e-runners", 15368),
        ("blackbox-docker-e2e", 15368),
        ("smoke", 15368),
        ("analyze", 15368),
        ("CodeQL", 57789),
        ("project-status", 15368),
        ("fuzz (address)", 15368),
        ("fuzz (undefined)", 15368),
    }
)
_POSITIVE_INTEGER = re.compile(r"[1-9][0-9]*\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


class RetirementArtifactError(ValueError):
    """The source-authority retirement artifact is not admissible."""


def _fail(message: str) -> NoReturn:
    raise RetirementArtifactError(message)


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"JSON document repeats member {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    _fail(f"JSON document contains forbidden constant {value!r}")


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    return value


def _exact_mapping(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    result = _mapping(value, label)
    if set(result) != keys:
        _fail(f"{label} member inventory is not exact")
    return result


def _json_equal(value: Any, expected: Any) -> bool:
    """Compare JSON values without Python bool/int/float equivalence."""

    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(value) == set(expected) and all(
            _json_equal(value[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        return len(value) == len(expected) and all(
            _json_equal(item, expected_item)
            for item, expected_item in zip(value, expected, strict=True)
        )
    return bool(value == expected)


def _positive(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        _fail(f"{label} must be a positive JSON integer")
    return value


def _nonnegative(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _fail(f"{label} must be a non-negative JSON integer")
    return value


def _parse_positive(value: str, label: str) -> int:
    if _POSITIVE_INTEGER.fullmatch(value) is None:
        _fail(f"{label} must be a canonical positive integer")
    return int(value)


def _parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        _fail(f"{label} must be canonical whole-second UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise RetirementArtifactError(f"{label} is not a real UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        _fail(f"{label} is not canonical UTC")
    return parsed


def _identity(item: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
        item.st_nlink,
    )


def _read_file(path: Path, *, maximum: int) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise RetirementArtifactError(f"{path.name} cannot be inspected: {exc}") from exc
    if path.is_symlink() or not stat.S_ISREG(before.st_mode):
        _fail(f"{path.name} must be one regular non-symlink file")
    if before.st_nlink != 1:
        _fail(f"{path.name} must have exactly one filesystem link")
    if before.st_size < 2 or before.st_size > maximum:
        _fail(f"{path.name} size is outside bounds")
    raw = path.read_bytes()
    after = path.lstat()
    if _identity(before) != _identity(after) or len(raw) != before.st_size:
        _fail(f"{path.name} changed during its bounded read")
    return raw


def _read_artifact(path: Path) -> dict[str, bytes]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise RetirementArtifactError(f"artifact cannot be inspected: {exc}") from exc
    if path.is_symlink() or not stat.S_ISDIR(before.st_mode):
        _fail("artifact must be one non-symlink directory")
    try:
        names = {entry.name for entry in path.iterdir()}
    except OSError as exc:
        raise RetirementArtifactError(f"artifact cannot be enumerated: {exc}") from exc
    if names != EXPECTED_FILES:
        _fail("artifact file inventory is not exact")
    result = {
        name: _read_file(path / name, maximum=FILE_LIMITS[name]) for name in sorted(EXPECTED_FILES)
    }
    after = path.lstat()
    try:
        after_names = {entry.name for entry in path.iterdir()}
    except OSError as exc:
        raise RetirementArtifactError(f"artifact cannot be re-enumerated: {exc}") from exc
    if _identity(before) != _identity(after) or after_names != names:
        _fail("artifact changed during its bounded read")
    return result


def _canonical_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RetirementArtifactError(f"{label} is not valid UTF-8 JSON") from exc
    result = _mapping(value, label)
    canonical = (
        json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("utf-8")
    if raw != canonical:
        _fail(f"{label} is not canonical JSON")
    return result


def _descriptor(value: Any, label: str) -> dict[str, Any]:
    result = _exact_mapping(value, {"sha256", "size"}, label)
    if not isinstance(result["sha256"], str) or _SHA256.fullmatch(result["sha256"]) is None:
        _fail(f"{label}.sha256 is not one canonical SHA-256 digest")
    _positive(result["size"], f"{label}.size")
    return result


def _actual_descriptor(raw: bytes) -> dict[str, Any]:
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}


def _require_descriptor(value: Any, raw: bytes, label: str) -> None:
    descriptor = _descriptor(value, label)
    if not _json_equal(descriptor, _actual_descriptor(raw)):
        _fail(f"{label} does not bind the artifact bytes")


def _validate_receipt(
    value: dict[str, Any],
    *,
    snapshot_raw: bytes,
    expected_repository: str,
    expected_repository_id: int,
    expected_main_sha: str,
    expected_authority_state: str,
) -> dict[str, Any]:
    label = f"{expected_authority_state} verification receipt"
    receipt = _exact_mapping(
        value,
        {
            "format",
            "verdict",
            "api_version",
            "started_at",
            "observed_at",
            "capture_duration_seconds",
            "snapshot_age_seconds",
            "snapshot_sha256",
            "repository",
            "main_authority",
            "required_status_checks",
        },
        label,
    )
    if not _json_equal(receipt["format"], RECEIPT_FORMAT):
        _fail(f"{label} format is not exact")
    if not _json_equal(receipt["verdict"], "PASS"):
        _fail(f"{label} did not PASS")
    if not _json_equal(receipt["api_version"], API_VERSION):
        _fail(f"{label} API version is not exact")

    started = _parse_timestamp(receipt["started_at"], "receipt.started_at")
    observed = _parse_timestamp(receipt["observed_at"], "receipt.observed_at")
    duration = _nonnegative(receipt["capture_duration_seconds"], "receipt.capture_duration_seconds")
    if observed < started or int((observed - started).total_seconds()) != duration:
        _fail("receipt capture timestamps and duration are not self-consistent")
    if duration > 120:
        _fail("receipt capture duration exceeds 120 seconds")
    age = _nonnegative(receipt["snapshot_age_seconds"], "receipt.snapshot_age_seconds")
    if age > 120:
        _fail("receipt records a stale source-authority snapshot")

    snapshot_sha256 = receipt["snapshot_sha256"]
    if not isinstance(snapshot_sha256, str) or _SHA256.fullmatch(snapshot_sha256) is None:
        _fail("receipt snapshot SHA-256 is not canonical")
    if snapshot_sha256 != hashlib.sha256(snapshot_raw).hexdigest():
        _fail(f"{label} snapshot SHA-256 does not bind its snapshot bytes")

    repository = _exact_mapping(receipt["repository"], {"full_name", "id"}, "receipt repository")
    if not _json_equal(
        repository,
        {"full_name": expected_repository, "id": expected_repository_id},
    ):
        _fail("receipt repository identity is not exact")

    authority = _exact_mapping(
        receipt["main_authority"],
        {
            "authority_state",
            "main_sha",
            "classic_branch_protection_absent",
            "ruleset_id",
            "ruleset_target",
            "ruleset_enforcement",
            "sole_bypass_actor",
            "deploy_key_id",
            "deploy_key_fingerprint",
            "retired_deploy_key_id",
            "retired_deploy_key_fingerprint",
            "enabled_write_deploy_key_count",
        },
        "receipt main authority",
    )
    if not _json_equal(authority["authority_state"], expected_authority_state):
        _fail(f"receipt is not for {expected_authority_state} authority")
    if not _json_equal(authority["main_sha"], expected_main_sha):
        _fail("receipt main SHA is not the expected promoted target")
    for field in ("classic_branch_protection_absent",):
        if authority[field] is not True:
            _fail(f"receipt {field} is not true")
    if not _json_equal(authority["ruleset_target"], "branch"):
        _fail("receipt ruleset target is not branch")
    if not _json_equal(authority["ruleset_enforcement"], "active"):
        _fail("receipt ruleset enforcement is not active")
    ruleset_id = _positive(authority["ruleset_id"], "receipt ruleset ID")
    if expected_authority_state == "source-active":
        if not _json_equal(authority["sole_bypass_actor"], "DeployKey"):
            _fail("active receipt does not expose the sole DeployKey bypass")
        deploy_key_id = _positive(authority["deploy_key_id"], "active source deploy-key ID")
        deploy_key_fingerprint = authority["deploy_key_fingerprint"]
        if (
            authority["retired_deploy_key_id"] is not None
            or authority["retired_deploy_key_fingerprint"] is not None
        ):
            _fail("active receipt incorrectly exposes a retired source deploy key")
        if not _json_equal(authority["enabled_write_deploy_key_count"], 1):
            _fail("active receipt does not prove exactly one enabled write deploy key")
    elif expected_authority_state == "source-retired":
        if authority["sole_bypass_actor"] is not None:
            _fail("retired receipt still exposes a main ruleset bypass actor")
        if (
            authority["deploy_key_id"] is not None
            or authority["deploy_key_fingerprint"] is not None
        ):
            _fail("retired receipt still exposes an active source deploy key")
        deploy_key_id = _positive(
            authority["retired_deploy_key_id"], "retired source deploy-key ID"
        )
        deploy_key_fingerprint = authority["retired_deploy_key_fingerprint"]
        if not _json_equal(authority["enabled_write_deploy_key_count"], 0):
            _fail("retired receipt does not prove zero enabled write deploy keys")
    else:
        _fail("receipt authority state is unsupported")
    if (
        not isinstance(deploy_key_fingerprint, str)
        or _FINGERPRINT.fullmatch(deploy_key_fingerprint) is None
    ):
        _fail("source deploy-key fingerprint is not canonical")

    checks = receipt["required_status_checks"]
    if not isinstance(checks, list):
        _fail("receipt required status checks must be an array")
    normalized: list[tuple[str, int]] = []
    for index, raw in enumerate(checks):
        check = _exact_mapping(
            raw,
            {"context", "integration_id"},
            f"receipt.required_status_checks[{index}]",
        )
        context = check["context"]
        integration = check["integration_id"]
        if not isinstance(context, str) or not context:
            _fail("receipt required status-check context is malformed")
        normalized.append((context, _positive(integration, "status-check integration ID")))
    if (
        normalized != sorted(EXPECTED_STATUS_CHECKS)
        or frozenset(normalized) != EXPECTED_STATUS_CHECKS
    ):
        _fail("receipt required status-check inventory/order is not exact")
    return {
        "authority_state": expected_authority_state,
        "main_sha": expected_main_sha,
        "started_at": receipt["started_at"],
        "observed_at": receipt["observed_at"],
        "ruleset_id": ruleset_id,
        "deploy_key_id": deploy_key_id,
        "deploy_key_fingerprint": deploy_key_fingerprint,
    }


def _validate_closure(
    value: dict[str, Any],
    *,
    active_snapshot_raw: bytes,
    active_receipt_raw: bytes,
    retired_snapshot_raw: bytes,
    retired_receipt_raw: bytes,
    expected_base_sha: str,
    expected_candidate_sha: str,
    expected_promotion_run_id: int,
    expected_promotion_run_attempt: int,
    active_identity: dict[str, Any],
    retired_identity: dict[str, Any],
    allow_unpromoted_terminal_closure: bool,
) -> tuple[bool, str, int]:
    closure = _exact_mapping(
        value,
        {
            "format",
            "run_id",
            "run_attempt",
            "promotion_completed",
            "base_sha",
            "candidate_sha",
            "pull_request_number",
            "main_sha_after_attempt",
            "main_ruleset_id",
            "source_deploy_key_id",
            "source_deploy_key_fingerprint",
            "source_deploy_key_absent",
            "main_deploy_key_bypass_absent",
            "retired_source_deploy_key_id",
            "retired_source_deploy_key_fingerprint",
            "active_snapshot",
            "active_verification",
            "retired_snapshot",
            "retired_verification",
            "boundary",
        },
        "source-authority closure",
    )
    if not _json_equal(closure["format"], CLOSURE_FORMAT):
        _fail("source-authority closure format is not exact")
    if not _json_equal(closure["run_id"], str(expected_promotion_run_id)):
        _fail("source-authority closure promotion run ID is not exact")
    if not _json_equal(closure["run_attempt"], expected_promotion_run_attempt):
        _fail("source-authority closure promotion run attempt is not exact")
    promotion_completed, terminal_main_sha = _terminal_state(
        closure,
        expected_base_sha=expected_base_sha,
        expected_candidate_sha=expected_candidate_sha,
        allow_unpromoted_terminal_closure=allow_unpromoted_terminal_closure,
    )
    if not _json_equal(closure["base_sha"], expected_base_sha):
        _fail("source-authority closure base SHA is not exact")
    if not _json_equal(closure["candidate_sha"], expected_candidate_sha):
        _fail("source-authority closure candidate SHA is not exact")
    if not _json_equal(active_identity["main_sha"], expected_base_sha):
        _fail("active source authority is not bound to the promotion base")
    if not _json_equal(retired_identity["main_sha"], terminal_main_sha):
        _fail("retired source authority is not bound to the terminal main SHA")
    if not _json_equal(active_identity["ruleset_id"], retired_identity["ruleset_id"]):
        _fail("active and retired source authority use different main rulesets")
    if not _json_equal(closure["main_ruleset_id"], active_identity["ruleset_id"]):
        _fail("source-authority closure main ruleset does not match both receipts")
    if not _json_equal(active_identity["deploy_key_id"], retired_identity["deploy_key_id"]):
        _fail("active and retired source authority use different deploy-key IDs")
    if not _json_equal(
        active_identity["deploy_key_fingerprint"],
        retired_identity["deploy_key_fingerprint"],
    ):
        _fail("active and retired source authority use different deploy-key fingerprints")
    if not _json_equal(closure["source_deploy_key_id"], active_identity["deploy_key_id"]):
        _fail("source-authority closure source deploy-key ID does not match both receipts")
    if not _json_equal(
        closure["source_deploy_key_fingerprint"],
        active_identity["deploy_key_fingerprint"],
    ):
        _fail("source-authority closure source deploy-key fingerprint does not match both receipts")
    pull_request_number = _positive(
        closure["pull_request_number"], "source-authority closure pull-request number"
    )
    if closure["source_deploy_key_absent"] is not True:
        _fail("source-authority closure does not prove source deploy-key absence")
    if closure["main_deploy_key_bypass_absent"] is not True:
        _fail("source-authority closure does not prove main bypass absence")
    if not _json_equal(closure["retired_source_deploy_key_id"], retired_identity["deploy_key_id"]):
        _fail("source-authority closure retired deploy-key ID does not match the receipt")
    if not _json_equal(
        closure["retired_source_deploy_key_fingerprint"],
        retired_identity["deploy_key_fingerprint"],
    ):
        _fail("source-authority closure retired deploy-key fingerprint does not match the receipt")

    _require_descriptor(
        closure["active_snapshot"],
        active_snapshot_raw,
        "closure.active_snapshot",
    )
    _require_descriptor(
        closure["active_verification"],
        active_receipt_raw,
        "closure.active_verification",
    )
    _require_descriptor(
        closure["retired_snapshot"],
        retired_snapshot_raw,
        "closure.retired_snapshot",
    )
    _require_descriptor(
        closure["retired_verification"],
        retired_receipt_raw,
        "closure.retired_verification",
    )
    boundary = _exact_mapping(
        closure["boundary"],
        {
            "github_control_plane_point_in_time",
            "private_key_erasure_claimed",
            "future_non_readdition_claimed",
        },
        "source-authority closure boundary",
    )
    if not _json_equal(
        boundary,
        {
            "github_control_plane_point_in_time": True,
            "private_key_erasure_claimed": False,
            "future_non_readdition_claimed": False,
        },
    ):
        _fail("source-authority closure boundary is not exact")
    return promotion_completed, terminal_main_sha, pull_request_number


def _terminal_state(
    closure: dict[str, Any],
    *,
    expected_base_sha: str,
    expected_candidate_sha: str,
    allow_unpromoted_terminal_closure: bool,
) -> tuple[bool, str]:
    promotion_completed = closure.get("promotion_completed")
    if type(promotion_completed) is not bool:
        _fail("source-authority closure promotion_completed must be a JSON boolean")
    terminal_main_sha = closure.get("main_sha_after_attempt")
    if not isinstance(terminal_main_sha, str) or _SHA.fullmatch(terminal_main_sha) is None:
        _fail("source-authority closure terminal main SHA is not canonical")
    expected_terminal_sha = (
        expected_candidate_sha if promotion_completed else expected_base_sha
    )
    if terminal_main_sha != expected_terminal_sha:
        state = "candidate" if promotion_completed else "base"
        _fail(f"source-authority closure {state} terminal state is not exact")
    if not promotion_completed and not allow_unpromoted_terminal_closure:
        _fail("source-authority closure does not prove promotion completed")
    return promotion_completed, terminal_main_sha


def validate(
    artifact: Path,
    *,
    expected_repository: str,
    expected_repository_id: int,
    expected_base_sha: str,
    expected_candidate_sha: str,
    expected_promotion_run_id: int,
    expected_promotion_run_attempt: int,
    allow_unpromoted_terminal_closure: bool = False,
) -> dict[str, Any]:
    if expected_repository != FROZEN_REPOSITORY:
        _fail("expected repository is not the frozen release repository")
    _positive(expected_repository_id, "expected repository ID")
    _positive(expected_promotion_run_id, "expected promotion run ID")
    _positive(expected_promotion_run_attempt, "expected promotion run attempt")
    if not isinstance(expected_base_sha, str) or _SHA.fullmatch(expected_base_sha) is None:
        _fail("expected base SHA is not one full lowercase Git ID")
    if (
        not isinstance(expected_candidate_sha, str)
        or _SHA.fullmatch(expected_candidate_sha) is None
    ):
        _fail("expected candidate SHA is not one full lowercase Git ID")
    if expected_base_sha == expected_candidate_sha:
        _fail("expected base and candidate SHAs must differ")
    if type(allow_unpromoted_terminal_closure) is not bool:
        _fail("unpromoted terminal-closure opt-in must be boolean")

    files = _read_artifact(artifact)
    active_snapshot_raw = files["source-authority-active.json"]
    active_receipt_raw = files["source-authority-active-receipt.json"]
    retired_snapshot_raw = files["source-authority-retired.json"]
    retired_receipt_raw = files["source-authority-retired-receipt.json"]
    closure_raw = files["source-authority-closure.json"]
    active_receipt = _canonical_json(active_receipt_raw, "active verification receipt")
    retired_receipt = _canonical_json(retired_receipt_raw, "retired verification receipt")
    closure = _canonical_json(closure_raw, "source-authority closure")
    _, terminal_main_sha = _terminal_state(
        closure,
        expected_base_sha=expected_base_sha,
        expected_candidate_sha=expected_candidate_sha,
        allow_unpromoted_terminal_closure=allow_unpromoted_terminal_closure,
    )
    active_identity = _validate_receipt(
        active_receipt,
        snapshot_raw=active_snapshot_raw,
        expected_repository=expected_repository,
        expected_repository_id=expected_repository_id,
        expected_main_sha=expected_base_sha,
        expected_authority_state="source-active",
    )
    retired_identity = _validate_receipt(
        retired_receipt,
        snapshot_raw=retired_snapshot_raw,
        expected_repository=expected_repository,
        expected_repository_id=expected_repository_id,
        expected_main_sha=terminal_main_sha,
        expected_authority_state="source-retired",
    )
    if _parse_timestamp(
        active_identity["observed_at"], "active receipt observed_at"
    ) > _parse_timestamp(retired_identity["observed_at"], "retired receipt observed_at"):
        _fail("retired source authority observation predates active authority")
    promotion_completed, terminal_main_sha, pull_request_number = _validate_closure(
        closure,
        active_snapshot_raw=active_snapshot_raw,
        active_receipt_raw=active_receipt_raw,
        retired_snapshot_raw=retired_snapshot_raw,
        retired_receipt_raw=retired_receipt_raw,
        expected_base_sha=expected_base_sha,
        expected_candidate_sha=expected_candidate_sha,
        expected_promotion_run_id=expected_promotion_run_id,
        expected_promotion_run_attempt=expected_promotion_run_attempt,
        active_identity=active_identity,
        retired_identity=retired_identity,
        allow_unpromoted_terminal_closure=allow_unpromoted_terminal_closure,
    )
    return {
        "format": FORMAT,
        "repository": {"full_name": expected_repository, "id": expected_repository_id},
        "target": {
            "base_sha": expected_base_sha,
            "candidate_sha": expected_candidate_sha,
            "main_sha": terminal_main_sha,
            "promotion_completed": promotion_completed,
            "pull_request_number": pull_request_number,
        },
        "promotion_run": {
            "run_id": str(expected_promotion_run_id),
            "run_attempt": expected_promotion_run_attempt,
        },
        "main_ruleset_id": active_identity["ruleset_id"],
        "active_source_authority": {
            **active_identity,
            "snapshot": _actual_descriptor(active_snapshot_raw),
            "verification": _actual_descriptor(active_receipt_raw),
        },
        "retired_source_authority": {
            **retired_identity,
            "snapshot": _actual_descriptor(retired_snapshot_raw),
            "verification": _actual_descriptor(retired_receipt_raw),
        },
        "retired_source_deploy_key": {
            "id": retired_identity["deploy_key_id"],
            "fingerprint": retired_identity["deploy_key_fingerprint"],
        },
        "descriptors": {name: _actual_descriptor(files[name]) for name in sorted(EXPECTED_FILES)},
    }


def _write_binding(path: Path, value: dict[str, Any], artifact: Path) -> None:
    if path.exists() or path.is_symlink():
        _fail("binding target must not already exist")
    if path.parent.is_symlink() or not path.parent.is_dir():
        _fail("binding parent must be an existing non-symlink directory")
    try:
        if path.parent.resolve() == artifact.resolve():
            _fail("binding target must be outside the closed artifact directory")
    except OSError as exc:
        raise RetirementArtifactError(f"binding path cannot be resolved: {exc}") from exc
    encoded = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("utf-8")
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise RetirementArtifactError("binding target must not already exist") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--expected-repository", required=True)
    parser.add_argument("--expected-repository-id", required=True)
    parser.add_argument("--expected-base-sha", required=True)
    parser.add_argument("--expected-candidate-sha", required=True)
    parser.add_argument("--expected-promotion-run-id", required=True)
    parser.add_argument("--expected-promotion-run-attempt", required=True)
    parser.add_argument("--binding-out", required=True, type=Path)
    parser.add_argument(
        "--allow-unpromoted-terminal-closure",
        action="store_true",
        help="P-only: admit a retired terminal artifact whose main remains at the base",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        repository_id = _parse_positive(arguments.expected_repository_id, "expected repository ID")
        run_id = _parse_positive(arguments.expected_promotion_run_id, "expected promotion run ID")
        run_attempt = _parse_positive(
            arguments.expected_promotion_run_attempt,
            "expected promotion run attempt",
        )
        binding = validate(
            arguments.artifact,
            expected_repository=arguments.expected_repository,
            expected_repository_id=repository_id,
            expected_base_sha=arguments.expected_base_sha,
            expected_candidate_sha=arguments.expected_candidate_sha,
            expected_promotion_run_id=run_id,
            expected_promotion_run_attempt=run_attempt,
            allow_unpromoted_terminal_closure=arguments.allow_unpromoted_terminal_closure,
        )
        _write_binding(arguments.binding_out, binding, arguments.artifact)
    except (OSError, RetirementArtifactError) as exc:
        print(f"release source retirement artifact rejected: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(binding, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
