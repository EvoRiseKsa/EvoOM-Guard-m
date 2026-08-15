#!/usr/bin/env python3
"""Validate the live GitHub authority used for signed source promotion.

The trusted promotion workflow captures a bounded, authenticated REST snapshot
immediately before its transport-only deploy key is used.  This verifier makes
the snapshot fail closed unless ``main`` is governed only by one exact active
repository ruleset, classic branch protection is absent, and the generic
``DeployKey`` bypass can resolve to only one enabled write key with the pinned
public fingerprint.  The same verifier also proves the bounded post-promotion
retired state and the later tag-publication state where the branch bypass is
absent.

The snapshot is control-plane evidence, not a durable independent attestation.
It never contains either private key or the observer token.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn

SNAPSHOT_FORMAT = "EVOGUARD_RELEASE_SOURCE_PROTECTION_SNAPSHOT_V1"
RECEIPT_FORMAT = "EVOGUARD_RELEASE_SOURCE_PROTECTION_VERIFICATION_V1"
API_VERSION = "2026-03-10"
EXPECTED_OWNER = {"login": "EvoRiseKsa", "id": 231647061, "type": "User"}
EXPECTED_ACTOR = {"login": "EvoRiseKsa", "id": 231647061, "type": "User"}
MAINTAINER_SIGNING_KEY_FINGERPRINT = (
    "SHA256:iCn7wa6HgKdu7luf/16rrKZzSk5FygJoA8EKNl3LJ24"
)
EXPECTED_RULE_TYPES = frozenset(
    {
        "creation",
        "deletion",
        "non_fast_forward",
        "required_linear_history",
        "pull_request",
        "required_status_checks",
    }
)
EXPECTED_CHECKS = frozenset(
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
MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024
MAX_ITEMS = 1000
MAX_SNAPSHOT_AGE_SECONDS = 120
MAX_FUTURE_SKEW_SECONDS = 5
_POSITIVE_INTEGER = re.compile(r"[1-9][0-9]*\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
AUTHORITY_STATES = frozenset({"source-active", "source-retired", "tag-active"})


class ProtectionError(ValueError):
    """The source-promotion protection snapshot is invalid."""


def _fail(message: str) -> NoReturn:
    raise ProtectionError(message)


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"snapshot repeats JSON member {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    _fail(f"snapshot contains forbidden JSON constant {value!r}")


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    return value


def _exact_mapping(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    item = _mapping(value, label)
    if set(item) != keys:
        _fail(f"{label} member inventory is not exact")
    return item


def _json_equal(value: Any, expected: Any) -> bool:
    """Compare JSON values without Python's bool/int/float equivalence."""

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


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        _fail(f"{label} must be a bounded array")
    return value


def _positive(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        _fail(f"{label} must be a positive integer")
    return value


def _parse_expected_integer(value: str, label: str) -> int:
    if _POSITIVE_INTEGER.fullmatch(value) is None:
        _fail(f"{label} must be a canonical positive integer")
    return int(value)


def _read_snapshot(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ProtectionError(f"snapshot cannot be inspected: {exc}") from exc
    if path.is_symlink() or not stat.S_ISREG(before.st_mode):
        _fail("snapshot must be one regular non-symlink file")
    if before.st_size < 2 or before.st_size > MAX_SNAPSHOT_BYTES:
        _fail("snapshot size is outside bounds")
    raw = path.read_bytes()
    after = path.lstat()
    def identity(item: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            item.st_dev,
            item.st_ino,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
    if identity(before) != identity(after):
        _fail("snapshot changed during its bounded read")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtectionError("snapshot is not valid UTF-8 JSON") from exc
    return _exact_mapping(
        value,
        {
            "format",
            "api_version",
            "started_at",
            "observed_at",
            "authenticated_actor",
            "repository",
            "main_branch",
            "classic_main_branch_protection",
            "branch_and_push_rulesets",
            "main_ruleset",
            "applicable_main_rules",
            "deploy_keys",
        },
        "snapshot",
    ), raw


def _parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        _fail(f"{label} must be canonical whole-second UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ProtectionError(f"{label} is not a real UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        _fail(f"{label} is not canonical UTC")
    return parsed


def _validate_time(
    started_value: Any, observed_value: Any, now: datetime
) -> tuple[str, str, int, int]:
    started = _parse_timestamp(started_value, "started_at")
    observed = _parse_timestamp(observed_value, "observed_at")
    duration = int((observed - started).total_seconds())
    if duration < 0:
        _fail("started_at must not follow observed_at")
    if duration > MAX_SNAPSHOT_AGE_SECONDS:
        _fail("control-plane capture duration exceeds 120 seconds")
    now = now.astimezone(timezone.utc).replace(microsecond=0)
    if observed > now + timedelta(seconds=MAX_FUTURE_SKEW_SECONDS):
        _fail("observed_at is unacceptably far in the future")
    age = max(0, int((now - observed).total_seconds()))
    if age > MAX_SNAPSHOT_AGE_SECONDS:
        _fail("control-plane snapshot is stale")
    return started_value, observed_value, duration, age


def _validate_complete_collection(value: Any, label: str) -> list[Any]:
    collection = _exact_mapping(value, {"complete", "pages", "items"}, label)
    if collection["complete"] is not True:
        _fail(f"{label} is not marked complete")
    _positive(collection["pages"], f"{label}.pages")
    return _list(collection["items"], f"{label}.items")


def _rules_by_type(value: Any, label: str) -> dict[str, dict[str, Any]]:
    rules = _list(value, label)
    result: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(rules):
        rule = _mapping(raw, f"{label}[{index}]")
        rule_type = rule.get("type")
        if not isinstance(rule_type, str) or rule_type in result:
            _fail(f"{label} contains an invalid or duplicate rule type")
        result[rule_type] = rule
    if frozenset(result) != EXPECTED_RULE_TYPES:
        _fail(f"{label} rule-type inventory is not exact")
    return result


def _required_checks(rule: dict[str, Any], label: str) -> frozenset[tuple[str, int]]:
    parameters = _exact_mapping(
        rule.get("parameters"),
        {
            "strict_required_status_checks_policy",
            "do_not_enforce_on_create",
            "required_status_checks",
        },
        f"{label}.parameters",
    )
    if parameters.get("strict_required_status_checks_policy") is not True:
        _fail(f"{label} does not require strict status checks")
    if parameters.get("do_not_enforce_on_create") is not False:
        _fail(f"{label} permits an unenforced creation")
    checks: set[tuple[str, int]] = set()
    for index, raw in enumerate(
        _list(parameters.get("required_status_checks"), f"{label}.required_status_checks")
    ):
        check = _exact_mapping(
            raw,
            {"context", "integration_id"},
            f"{label}.required_status_checks[{index}]",
        )
        context = check.get("context")
        integration = check.get("integration_id")
        if (
            not isinstance(context, str)
            or not context
            or isinstance(integration, bool)
            or not isinstance(integration, int)
            or integration < 1
            or (context, integration) in checks
        ):
            _fail(f"{label} contains a malformed or duplicate status check")
        checks.add((context, integration))
    if frozenset(checks) != EXPECTED_CHECKS:
        _fail(f"{label} required check/App-ID inventory is not exact")
    return frozenset(checks)


def _validate_rule_contract(rules: dict[str, dict[str, Any]], label: str) -> None:
    for rule_type in (
        "creation",
        "deletion",
        "non_fast_forward",
        "required_linear_history",
    ):
        if set(rules[rule_type]) not in (
            {"type"},
            {"type", "ruleset_id", "ruleset_source_type", "ruleset_source"},
        ):
            _fail(f"{label}.{rule_type} must be one parameter-free rule")
    pull = _exact_mapping(
        rules["pull_request"].get("parameters"),
        {
            "allowed_merge_methods",
            "dismissal_restriction",
            "dismiss_stale_reviews_on_push",
            "require_code_owner_review",
            "require_last_push_approval",
            "required_approving_review_count",
            "required_reviewers",
            "required_review_thread_resolution",
        },
        f"{label}.pull_request",
    )
    if not _json_equal(
        pull,
        {
            "allowed_merge_methods": ["rebase"],
            "dismissal_restriction": None,
            "dismiss_stale_reviews_on_push": True,
            "require_code_owner_review": True,
            "require_last_push_approval": True,
            "required_approving_review_count": 1,
            "required_reviewers": [],
            "required_review_thread_resolution": True,
        },
    ):
        _fail(f"{label} pull-request protections are not exact")
    _required_checks(rules["required_status_checks"], f"{label}.required_status_checks")


def _ssh_ed25519_fingerprint(value: Any) -> str:
    if not isinstance(value, str) or "\r" in value or "\n" in value:
        _fail("deploy-key public key is not one canonical line")
    fields = value.split(" ")
    if len(fields) not in (2, 3) or any(not field for field in fields):
        _fail("deploy-key public key fields are not canonical")
    if fields[0] != "ssh-ed25519":
        _fail("source-promotion deploy key must be ssh-ed25519")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ProtectionError("deploy-key public key Base64 is invalid") from exc
    if base64.b64encode(blob).decode("ascii") != fields[1]:
        _fail("deploy-key public key Base64 is not canonical")

    def field(offset: int) -> tuple[bytes, int]:
        if offset + 4 > len(blob):
            _fail("deploy-key SSH wire blob is truncated")
        size = int.from_bytes(blob[offset : offset + 4], "big")
        start = offset + 4
        end = start + size
        if end > len(blob):
            _fail("deploy-key SSH wire field is truncated")
        return blob[start:end], end

    kind, offset = field(0)
    key, offset = field(offset)
    if kind != b"ssh-ed25519" or len(key) != 32 or offset != len(blob):
        _fail("deploy-key SSH wire inventory is not exact Ed25519")
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def validate(
    snapshot_path: Path,
    *,
    expected_repository: str,
    expected_repository_id: int,
    expected_main_sha: str,
    expected_ruleset_id: int,
    expected_deploy_key_id: int,
    expected_deploy_key_fingerprint: str,
    authority_state: str = "source-active",
    now: datetime,
) -> dict[str, Any]:
    _positive(expected_repository_id, "expected repository ID")
    _positive(expected_ruleset_id, "expected ruleset ID")
    _positive(expected_deploy_key_id, "expected deploy-key ID")
    if expected_deploy_key_fingerprint == MAINTAINER_SIGNING_KEY_FINGERPRINT:
        _fail("source transport key must be distinct from the maintainer signing key")
    snapshot, raw = _read_snapshot(snapshot_path)
    if snapshot["format"] != SNAPSHOT_FORMAT or snapshot["api_version"] != API_VERSION:
        _fail("snapshot format/API version is not exact")
    started_at, observed_at, capture_duration, snapshot_age = _validate_time(
        snapshot["started_at"], snapshot["observed_at"], now
    )
    if not _json_equal(snapshot["authenticated_actor"], EXPECTED_ACTOR):
        _fail("control-plane observer is not the frozen maintainer account")
    repository = _exact_mapping(
        snapshot["repository"],
        {"full_name", "id", "default_branch", "fork", "owner"},
        "repository",
    )
    if not _json_equal(
        repository,
        {
            "full_name": expected_repository,
            "id": expected_repository_id,
            "default_branch": "main",
            "fork": False,
            "owner": EXPECTED_OWNER,
        },
    ):
        _fail("repository identity/default branch is not exact")
    main_branch = _exact_mapping(
        snapshot["main_branch"], {"name", "sha", "protected"}, "main branch"
    )
    if not _json_equal(
        main_branch,
        {"name": "main", "sha": expected_main_sha, "protected": True},
    ):
        _fail("live main branch identity/protection/SHA is not exact")
    classic = _exact_mapping(
        snapshot["classic_main_branch_protection"], {"status"}, "classic protection"
    )
    if not _json_equal(classic["status"], 404):
        _fail("classic main branch protection must be absent before ruleset bypass")

    details = _validate_complete_collection(
        snapshot["branch_and_push_rulesets"], "branch/push rulesets"
    )
    if len(details) != 1:
        _fail("there must be exactly one repository/inherited branch-or-push ruleset")
    active = [_mapping(details[0], "ruleset")]
    if (
        not _json_equal(active[0].get("id"), expected_ruleset_id)
        or active[0].get("enforcement") != "active"
        or active[0].get("target") != "branch"
    ):
        _fail("the sole branch/push ruleset identity or enforcement is not exact")

    ruleset = _mapping(snapshot["main_ruleset"], "main ruleset")
    if not _json_equal(ruleset, active[0]):
        _fail("main ruleset does not equal the complete-list object")
    if (
        not _json_equal(ruleset.get("id"), expected_ruleset_id)
        or ruleset.get("name") != "EvoOM Guard main signed-source authority"
        or ruleset.get("target") != "branch"
        or ruleset.get("source_type") != "Repository"
        or ruleset.get("source") != expected_repository
        or ruleset.get("enforcement") != "active"
    ):
        _fail("main ruleset identity/source/enforcement is not exact")
    if authority_state not in AUTHORITY_STATES:
        _fail("authority state is not supported")
    bypass = _list(ruleset.get("bypass_actors"), "main ruleset bypass actors")
    expected_bypass = (
        [{"actor_id": None, "actor_type": "DeployKey", "bypass_mode": "always"}]
        if authority_state == "source-active"
        else []
    )
    if not _json_equal(bypass, expected_bypass):
        if authority_state == "source-active":
            _fail("main ruleset bypass must be the generic DeployKey actor only")
        _fail("main ruleset must expose no bypass actor after source promotion")
    conditions = _exact_mapping(ruleset.get("conditions"), {"ref_name"}, "ruleset conditions")
    ref_name = _exact_mapping(
        conditions["ref_name"], {"include", "exclude"}, "ruleset ref condition"
    )
    if not _json_equal(ref_name, {"include": ["refs/heads/main"], "exclude": []}):
        _fail("main ruleset ref condition is not exact")
    rule_contract = _rules_by_type(ruleset.get("rules"), "main ruleset rules")
    _validate_rule_contract(rule_contract, "main ruleset")

    applicable = _validate_complete_collection(
        snapshot["applicable_main_rules"], "applicable main rules"
    )
    applicable_contract = _rules_by_type(applicable, "applicable main rules")
    for rule_type, rule in applicable_contract.items():
        if (
            not _json_equal(rule.get("ruleset_id"), expected_ruleset_id)
            or rule.get("ruleset_source_type") != "Repository"
            or rule.get("ruleset_source") != expected_repository
        ):
            _fail(f"applicable main rule {rule_type} comes from an unexpected ruleset")
    _validate_rule_contract(applicable_contract, "applicable main rules")

    deploy_keys = _validate_complete_collection(snapshot["deploy_keys"], "deploy keys")
    writers: list[dict[str, Any]] = []
    key_ids: set[int] = set()
    for index, raw_key in enumerate(deploy_keys):
        key = _exact_mapping(
            raw_key,
            {"id", "key", "title", "verified", "read_only", "enabled"},
            f"deploy_keys[{index}]",
        )
        key_id = _positive(key["id"], f"deploy_keys[{index}].id")
        if key_id in key_ids:
            _fail("deploy-key inventory contains a duplicate ID")
        key_ids.add(key_id)
        if (
            not isinstance(key["key"], str)
            or not key["key"]
            or not isinstance(key["title"], str)
            or not key["title"]
            or not isinstance(key["verified"], bool)
            or not isinstance(key["read_only"], bool)
            or not isinstance(key["enabled"], bool)
        ):
            _fail(f"deploy_keys[{index}] has a malformed normalized shape")
        if key.get("enabled") is True and key.get("read_only") is False:
            writers.append(key)
    actual_fingerprint: str | None = None
    if authority_state == "source-retired":
        if writers:
            _fail("source-retired authority must expose no enabled write deploy key")
        if expected_deploy_key_id in key_ids:
            _fail("retired source-promotion deploy key is still present")
    else:
        if len(writers) != 1:
            _fail("repository must expose exactly one enabled write deploy key")
        writer = writers[0]
        if (
            not _json_equal(writer.get("id"), expected_deploy_key_id)
            or writer.get("verified") is not True
        ):
            _fail("sole enabled write deploy key identity/verification is not exact")
        actual_fingerprint = _ssh_ed25519_fingerprint(writer.get("key"))
        if actual_fingerprint != expected_deploy_key_fingerprint:
            _fail("sole enabled write deploy key fingerprint is not the owner pin")

    return {
        "format": RECEIPT_FORMAT,
        "verdict": "PASS",
        "api_version": API_VERSION,
        "started_at": started_at,
        "observed_at": observed_at,
        "capture_duration_seconds": capture_duration,
        "snapshot_age_seconds": snapshot_age,
        "snapshot_sha256": hashlib.sha256(raw).hexdigest(),
        "repository": {"full_name": expected_repository, "id": expected_repository_id},
        "main_authority": {
            "authority_state": authority_state,
            "main_sha": expected_main_sha,
            "classic_branch_protection_absent": True,
            "ruleset_id": expected_ruleset_id,
            "ruleset_target": "branch",
            "ruleset_enforcement": "active",
            "sole_bypass_actor": "DeployKey" if authority_state == "source-active" else None,
            "deploy_key_id": (
                None if authority_state == "source-retired" else expected_deploy_key_id
            ),
            "deploy_key_fingerprint": actual_fingerprint,
            "retired_deploy_key_id": (
                expected_deploy_key_id if authority_state == "source-retired" else None
            ),
            "retired_deploy_key_fingerprint": (
                expected_deploy_key_fingerprint
                if authority_state == "source-retired"
                else None
            ),
            "enabled_write_deploy_key_count": len(writers),
        },
        "required_status_checks": [
            {"context": context, "integration_id": integration}
            for context, integration in sorted(EXPECTED_CHECKS)
        ],
    }


def _write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        _fail("receipt target must not already exist")
    if path.parent.is_symlink() or not path.parent.is_dir():
        _fail("receipt parent must be an existing non-symlink directory")
    encoded = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--expected-repository", required=True)
    parser.add_argument("--expected-repository-id", required=True)
    parser.add_argument("--expected-main-sha", required=True)
    parser.add_argument("--expected-ruleset-id", required=True)
    parser.add_argument("--expected-deploy-key-id", required=True)
    parser.add_argument("--expected-deploy-key-fingerprint", required=True)
    parser.add_argument(
        "--authority-state",
        choices=sorted(AUTHORITY_STATES),
        default="source-active",
    )
    parser.add_argument("--now")
    parser.add_argument("--receipt", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        repository_id = _parse_expected_integer(
            arguments.expected_repository_id, "expected repository ID"
        )
        ruleset_id = _parse_expected_integer(arguments.expected_ruleset_id, "expected ruleset ID")
        deploy_key_id = _parse_expected_integer(
            arguments.expected_deploy_key_id, "expected deploy-key ID"
        )
        if arguments.expected_repository != "EvoRiseKsa/EvoOM-Guard-m":
            _fail("expected repository is not the frozen release repository")
        if _SHA.fullmatch(arguments.expected_main_sha) is None:
            _fail("expected main SHA is not one full lowercase Git ID")
        if _FINGERPRINT.fullmatch(arguments.expected_deploy_key_fingerprint) is None:
            _fail("expected deploy-key fingerprint is not canonical SHA256")
        if arguments.now is None:
            now = datetime.now(timezone.utc)
        else:
            if _TIMESTAMP.fullmatch(arguments.now) is None:
                _fail("now must be canonical whole-second UTC")
            try:
                now = datetime.strptime(arguments.now, "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=timezone.utc
                )
            except ValueError as exc:
                raise ProtectionError("now is not a real UTC timestamp") from exc
        receipt = validate(
            arguments.snapshot,
            expected_repository=arguments.expected_repository,
            expected_repository_id=repository_id,
            expected_main_sha=arguments.expected_main_sha,
            expected_ruleset_id=ruleset_id,
            expected_deploy_key_id=deploy_key_id,
            expected_deploy_key_fingerprint=arguments.expected_deploy_key_fingerprint,
            authority_state=arguments.authority_state,
            now=now,
        )
        _write_receipt(arguments.receipt, receipt)
    except (OSError, ProtectionError) as exc:
        print(f"release source protection rejected: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
