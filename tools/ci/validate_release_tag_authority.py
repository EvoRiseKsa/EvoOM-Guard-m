#!/usr/bin/env python3
"""Validate the single-use GitHub authority for publishing a release tag.

The H workflow is expected to capture this snapshot with an
Administration:read observer token immediately before using the transport-only
tag deploy key.  This verifier proves that the source-promotion authority is
retired, the exact tag ruleset is the sole tag ruleset, and only the pinned
Ed25519 tag key can write.  It does not execute Git or trust the capture process
to make policy decisions.
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
from pathlib import Path, PurePosixPath
from typing import Any, NamedTuple, NoReturn

SNAPSHOT_FORMAT = "EVOGUARD_RELEASE_TAG_AUTHORITY_SNAPSHOT_V1"
RECEIPT_FORMAT = "EVOGUARD_RELEASE_TAG_AUTHORITY_VERIFICATION_V1"
API_VERSION = "2026-03-10"
EXPECTED_REPOSITORY = "EvoRiseKsa/EvoOM-Guard-m"
EXPECTED_OWNER = {"login": "EvoRiseKsa", "id": 231647061, "type": "User"}
EXPECTED_ACTOR = {"login": "EvoRiseKsa", "id": 231647061, "type": "User"}
EXPECTED_MAIN_RULESET_NAME = "EvoOM Guard main signed-source authority"
EXPECTED_TAG_RULESET_NAME = "EvoOM Guard release tag authority"
EXPECTED_MAIN_RULE_TYPES = frozenset(
    {
        "creation",
        "deletion",
        "non_fast_forward",
        "pull_request",
        "required_linear_history",
        "required_status_checks",
    }
)
EXPECTED_TAG_RULE_TYPES = frozenset(
    {"creation", "deletion", "non_fast_forward", "update"}
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
MAX_SIGNING_ROOT_BYTES = 16 * 1024
MAX_PUBLIC_KEY_BYTES = 16 * 1024
MAX_PAGES = 10
MAX_RULESETS = 100
MAX_DEPLOY_KEYS = 1000
MAX_SNAPSHOT_AGE_SECONDS = 120
MAX_FUTURE_SKEW_SECONDS = 5
_POSITIVE_INTEGER = re.compile(r"[1-9][0-9]*\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
)


class TagAuthorityError(ValueError):
    """The observed tag-publication authority is not the frozen contract."""


class MaintainerSigningRoot(NamedTuple):
    """Exact public evidence extracted from the frozen maintainer root."""

    root_path: Path
    root_sha256: str
    version: str
    public_key_path: str
    public_key_sha256: str
    public_key_fingerprint: str


def _fail(message: str) -> NoReturn:
    raise TagAuthorityError(message)


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


def _array(value: Any, label: str, *, maximum: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        _fail(f"{label} must be a bounded array")
    return value


def _positive(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        _fail(f"{label} must be a positive integer")
    return value


def _identity(value: Any, expected: dict[str, Any], label: str) -> dict[str, Any]:
    identity = _exact_mapping(value, {"login", "id", "type"}, label)
    identifier = _positive(identity["id"], f"{label}.id")
    if (
        not isinstance(identity["login"], str)
        or not isinstance(identity["type"], str)
        or identity["login"] != expected["login"]
        or identifier != expected["id"]
        or identity["type"] != expected["type"]
    ):
        _fail(f"{label} is not exact")
    return identity


def _parse_expected_integer(value: str, label: str) -> int:
    if _POSITIVE_INTEGER.fullmatch(value) is None:
        _fail(f"{label} must be a canonical positive integer")
    return int(value)


def _read_snapshot(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise TagAuthorityError(f"snapshot cannot be inspected: {exc}") from exc
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
        raise TagAuthorityError("snapshot is not valid UTF-8 JSON") from exc
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
            "tag_rulesets",
            "deploy_keys",
        },
        "snapshot",
    ), raw


def _parse_timestamp(value: Any, label: str) -> tuple[str, datetime]:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        _fail(f"{label} must be canonical whole-second UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise TagAuthorityError(f"{label} is not a real UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        _fail(f"{label} is not canonical UTC")
    return value, parsed


def _validate_time_window(
    started_value: Any,
    observed_value: Any,
    now: datetime,
) -> tuple[str, str, int, int]:
    started_at, started = _parse_timestamp(started_value, "started_at")
    observed_at, observed = _parse_timestamp(observed_value, "observed_at")
    if now.tzinfo is None:
        _fail("verification time must be timezone-aware")
    now = now.astimezone(timezone.utc).replace(microsecond=0)
    if observed > now + timedelta(seconds=MAX_FUTURE_SKEW_SECONDS):
        _fail("observed_at is unacceptably far in the future")
    duration = int((observed - started).total_seconds())
    if duration < 0 or duration > MAX_SNAPSHOT_AGE_SECONDS:
        _fail("capture duration must be between 0 and 120 seconds")
    age = max(0, int((now - observed).total_seconds()))
    if age > MAX_SNAPSHOT_AGE_SECONDS:
        _fail("tag-authority snapshot is stale")
    return started_at, observed_at, duration, age


def _complete_collection(
    value: Any,
    label: str,
    *,
    maximum_items: int,
) -> list[Any]:
    collection = _exact_mapping(value, {"complete", "pages", "items"}, label)
    if collection["complete"] is not True:
        _fail(f"{label} is not marked complete")
    pages = _positive(collection["pages"], f"{label}.pages")
    if pages > MAX_PAGES:
        _fail(f"{label}.pages exceeds the capture bound")
    items = _array(collection["items"], f"{label}.items", maximum=maximum_items)
    if len(items) > pages * 100 or len(items) < (pages - 1) * 100:
        _fail(f"{label} pagination cardinality is inconsistent")
    return items


def _sorted_unique_strings(value: Any, expected: list[str], label: str) -> None:
    items = _array(value, label, maximum=MAX_RULESETS)
    if items != expected or any(not isinstance(item, str) for item in items):
        _fail(f"{label} is not exact")


def _rule_map(
    value: Any,
    label: str,
    *,
    expected_types: frozenset[str],
) -> dict[str, dict[str, Any]]:
    rules = _array(value, label, maximum=32)
    result: dict[str, dict[str, Any]] = {}
    observed_order: list[str] = []
    for index, raw in enumerate(rules):
        rule = _mapping(raw, f"{label}[{index}]")
        rule_type = rule.get("type")
        if not isinstance(rule_type, str) or rule_type in result:
            _fail(f"{label} contains an invalid or duplicate rule type")
        result[rule_type] = rule
        observed_order.append(rule_type)
    if frozenset(result) != expected_types or observed_order != sorted(expected_types):
        _fail(f"{label} rule-type inventory/order is not exact")
    return result


def _validate_required_checks(rule: dict[str, Any], label: str) -> None:
    if set(rule) != {"type", "parameters"}:
        _fail(f"{label} rule shape is not exact")
    parameters = _exact_mapping(
        rule["parameters"],
        {
            "do_not_enforce_on_create",
            "strict_required_status_checks_policy",
            "required_status_checks",
        },
        f"{label}.parameters",
    )
    if parameters["do_not_enforce_on_create"] is not False:
        _fail(f"{label} permits an unenforced creation")
    if parameters["strict_required_status_checks_policy"] is not True:
        _fail(f"{label} does not require strict status checks")
    checks: list[tuple[str, int]] = []
    for index, raw in enumerate(
        _array(
            parameters["required_status_checks"],
            f"{label}.required_status_checks",
            maximum=100,
        )
    ):
        check = _exact_mapping(
            raw,
            {"context", "integration_id"},
            f"{label}.required_status_checks[{index}]",
        )
        context = check["context"]
        integration = check["integration_id"]
        if (
            not isinstance(context, str)
            or not context
            or isinstance(integration, bool)
            or not isinstance(integration, int)
            or integration < 1
        ):
            _fail(f"{label} contains a malformed status check")
        checks.append((context, integration))
    if checks != sorted(EXPECTED_CHECKS):
        _fail(f"{label} required check/App-ID inventory/order is not exact")


def _validate_main_rules(value: Any) -> None:
    rules = _rule_map(
        value,
        "main ruleset rules",
        expected_types=EXPECTED_MAIN_RULE_TYPES,
    )
    for rule_type in (
        "creation",
        "deletion",
        "non_fast_forward",
        "required_linear_history",
    ):
        if rules[rule_type] != {"type": rule_type}:
            _fail(f"main ruleset {rule_type} rule is not parameter-free")
    pull = _exact_mapping(
        rules["pull_request"],
        {"type", "parameters"},
        "main pull-request rule",
    )
    parameters = _exact_mapping(
        pull["parameters"],
        {
            "allowed_merge_methods",
            "dismissal_restriction",
            "dismiss_stale_reviews_on_push",
            "require_code_owner_review",
            "require_last_push_approval",
            "required_approving_review_count",
            "required_review_thread_resolution",
            "required_reviewers",
        },
        "main pull-request parameters",
    )
    boolean_fields = (
        "dismiss_stale_reviews_on_push",
        "require_code_owner_review",
        "require_last_push_approval",
        "required_review_thread_resolution",
    )
    count = parameters["required_approving_review_count"]
    if (
        parameters["allowed_merge_methods"] != ["rebase"]
        or parameters["dismissal_restriction"] is not None
        or parameters["required_reviewers"] != []
        or any(parameters[field] is not True for field in boolean_fields)
        or isinstance(count, bool)
        or not isinstance(count, int)
        or count != 1
    ):
        _fail("main pull-request protection is not exact")
    _validate_required_checks(
        rules["required_status_checks"],
        "main required-status-check rule",
    )


def _validate_tag_rules(value: Any) -> None:
    rules = _rule_map(
        value,
        "tag ruleset rules",
        expected_types=EXPECTED_TAG_RULE_TYPES,
    )
    for rule_type, rule in rules.items():
        if rule != {"type": rule_type}:
            _fail(f"tag ruleset {rule_type} rule is not parameter-free")


def _validate_ruleset_shape(value: Any, label: str) -> dict[str, Any]:
    return _exact_mapping(
        value,
        {
            "id",
            "name",
            "target",
            "source_type",
            "source",
            "enforcement",
            "bypass_actors",
            "conditions",
            "rules",
        },
        label,
    )


def _validate_ref_condition(
    value: Any,
    *,
    include: list[str],
    label: str,
) -> None:
    conditions = _exact_mapping(value, {"ref_name"}, f"{label} conditions")
    ref_name = _exact_mapping(
        conditions["ref_name"],
        {"include", "exclude"},
        f"{label} ref-name condition",
    )
    _sorted_unique_strings(ref_name["include"], include, f"{label} includes")
    _sorted_unique_strings(ref_name["exclude"], [], f"{label} excludes")


def _ssh_ed25519_fingerprint(value: Any, *, label: str = "tag deploy key") -> str:
    if not isinstance(value, str) or "\r" in value or "\n" in value:
        _fail(f"{label} public key is not one canonical line")
    fields = value.split(" ")
    if len(fields) < 2 or any(not field for field in fields):
        _fail(f"{label} public key fields are not canonical")
    if fields[0] != "ssh-ed25519":
        _fail(f"{label} must be ssh-ed25519")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TagAuthorityError(f"{label} public key Base64 is invalid") from exc
    if base64.b64encode(blob).decode("ascii") != fields[1]:
        _fail(f"{label} public key Base64 is not canonical")

    def field(offset: int) -> tuple[bytes, int]:
        if offset + 4 > len(blob):
            _fail(f"{label} SSH wire blob is truncated")
        size = int.from_bytes(blob[offset : offset + 4], "big")
        start = offset + 4
        end = start + size
        if end > len(blob):
            _fail(f"{label} SSH wire field is truncated")
        return blob[start:end], end

    kind, offset = field(0)
    key, offset = field(offset)
    if kind != b"ssh-ed25519" or len(key) != 32 or offset != len(blob):
        _fail(f"{label} SSH wire inventory is not exact Ed25519")
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def _read_regular_bytes(path: Path, *, maximum: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise TagAuthorityError(f"{label} cannot be inspected: {exc}") from exc
    if path.is_symlink() or not stat.S_ISREG(before.st_mode):
        _fail(f"{label} must be one regular non-symlink file")
    if before.st_size < 2 or before.st_size > maximum:
        _fail(f"{label} size is outside bounds")
    raw = path.read_bytes()
    after = path.lstat()
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_identity != after_identity:
        _fail(f"{label} changed during its bounded read")
    return raw


def _load_maintainer_signing_root(path: Path) -> MaintainerSigningRoot:
    raw = _read_regular_bytes(
        path,
        maximum=MAX_SIGNING_ROOT_BYTES,
        label="maintainer signing root",
    )
    if b"\x00" in raw or b"\r" in raw or not raw.endswith(b"\n"):
        _fail("maintainer signing root must be NUL-free LF-terminated UTF-8 JSON")

    def unique_root(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail(f"maintainer signing root repeats JSON member {key!r}")
            result[key] = value
        return result

    def reject_root_constant(value: str) -> NoReturn:
        _fail(f"maintainer signing root contains forbidden JSON constant {value!r}")

    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_root,
            parse_constant=reject_root_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TagAuthorityError("maintainer signing root is not strict UTF-8 JSON") from exc
    root = _exact_mapping(
        document,
        {
            "format",
            "version",
            "github_login",
            "github_user_id",
            "key_type",
            "public_key_path",
            "public_key_sha256",
            "provided_source_file_sha256_crlf",
            "public_key_fingerprint",
            "signature_namespace",
            "private_key_location",
            "github_verification_required",
        },
        "maintainer signing root",
    )
    version = root["version"]
    if not isinstance(version, str) or _VERSION.fullmatch(version) is None:
        _fail("maintainer signing root version is not one stable semantic version")
    if path.name != f"v{version}.json":
        _fail("maintainer signing root filename is not version-bound")
    user_id = _positive(root["github_user_id"], "maintainer signing root GitHub user ID")
    if (
        root["format"] != "EVOGUARD_RELEASE_MAINTAINER_SIGNING_ROOT_V1"
        or root["github_login"] != EXPECTED_ACTOR["login"]
        or user_id != EXPECTED_ACTOR["id"]
        or root["key_type"] != "ssh-ed25519"
        or root["signature_namespace"] != "git"
        or root["private_key_location"] != "OUTSIDE_REPOSITORY_AND_GITHUB_ACTIONS"
        or root["github_verification_required"] is not True
    ):
        _fail("maintainer signing root identity/policy is not exact")

    public_key_path = root["public_key_path"]
    if not isinstance(public_key_path, str) or "\\" in public_key_path:
        _fail("maintainer public-key path is not canonical")
    normalized_path = PurePosixPath(public_key_path)
    expected_path = f"security/release-maintainer-roots/v{version}.pub"
    if (
        normalized_path.is_absolute()
        or normalized_path.as_posix() != public_key_path
        or any(part in {"", ".", ".."} for part in normalized_path.parts)
        or public_key_path != expected_path
    ):
        _fail("maintainer public-key path is not version-bound and exact")

    public_key_sha256 = root["public_key_sha256"]
    crlf_sha256 = root["provided_source_file_sha256_crlf"]
    pinned_fingerprint = root["public_key_fingerprint"]
    if not isinstance(public_key_sha256, str) or _HEX_SHA256.fullmatch(public_key_sha256) is None:
        _fail("maintainer public-key SHA-256 is not canonical")
    if not isinstance(crlf_sha256, str) or _HEX_SHA256.fullmatch(crlf_sha256) is None:
        _fail("maintainer CRLF source SHA-256 is not canonical")
    if not isinstance(pinned_fingerprint, str) or _FINGERPRINT.fullmatch(
        pinned_fingerprint
    ) is None:
        _fail("maintainer public-key fingerprint is not canonical")

    public_path = path.parent / normalized_path.name
    if public_path.parent.resolve() != path.parent.resolve():
        _fail("maintainer public key escaped the signing-root directory")
    public_raw = _read_regular_bytes(
        public_path,
        maximum=MAX_PUBLIC_KEY_BYTES,
        label="maintainer public key",
    )
    if b"\x00" in public_raw or b"\r" in public_raw or public_raw.count(b"\n") != 1:
        _fail("maintainer public key must be one NUL-free LF-terminated line")
    if not public_raw.endswith(b"\n"):
        _fail("maintainer public key must be LF-terminated")
    try:
        public_line = public_raw[:-1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise TagAuthorityError("maintainer public key must be ASCII") from exc
    actual_public_sha256 = hashlib.sha256(public_raw).hexdigest()
    if actual_public_sha256 != public_key_sha256:
        _fail("maintainer public-key bytes do not match the pinned SHA-256")
    actual_fingerprint = _ssh_ed25519_fingerprint(
        public_line,
        label="maintainer signing root",
    )
    if actual_fingerprint != pinned_fingerprint:
        _fail("maintainer public-key fingerprint does not match the pinned value")
    return MaintainerSigningRoot(
        root_path=path.resolve(),
        root_sha256=hashlib.sha256(raw).hexdigest(),
        version=version,
        public_key_path=public_key_path,
        public_key_sha256=public_key_sha256,
        public_key_fingerprint=actual_fingerprint,
    )


def validate(
    snapshot_path: Path,
    *,
    expected_repository: str,
    expected_repository_id: int,
    expected_main_sha: str,
    expected_main_ruleset_id: int,
    expected_tag_ruleset_id: int,
    expected_tag_deploy_key_id: int,
    expected_tag_deploy_key_fingerprint: str,
    retired_source_deploy_key_id: int,
    retired_source_deploy_key_fingerprint: str,
    maintainer_signing_root: Path,
    now: datetime,
) -> dict[str, Any]:
    if expected_repository != EXPECTED_REPOSITORY:
        _fail("expected repository is not the frozen release repository")
    _positive(expected_repository_id, "expected repository ID")
    _positive(expected_main_ruleset_id, "expected main ruleset ID")
    _positive(expected_tag_ruleset_id, "expected tag ruleset ID")
    _positive(expected_tag_deploy_key_id, "expected tag deploy-key ID")
    _positive(retired_source_deploy_key_id, "retired source deploy-key ID")
    if not isinstance(expected_main_sha, str) or _SHA.fullmatch(expected_main_sha) is None:
        _fail("expected main SHA is not one full lowercase Git ID")
    if not isinstance(expected_tag_deploy_key_fingerprint, str) or _FINGERPRINT.fullmatch(
        expected_tag_deploy_key_fingerprint
    ) is None:
        _fail("expected tag deploy-key fingerprint is not canonical SHA256")
    if not isinstance(retired_source_deploy_key_fingerprint, str) or _FINGERPRINT.fullmatch(
        retired_source_deploy_key_fingerprint
    ) is None:
        _fail("retired source deploy-key fingerprint is not canonical SHA256")
    if expected_main_ruleset_id == expected_tag_ruleset_id:
        _fail("main and tag ruleset IDs must be distinct")
    if retired_source_deploy_key_id == expected_tag_deploy_key_id:
        _fail("retired source and active tag deploy-key IDs must be distinct")
    signing_root = _load_maintainer_signing_root(maintainer_signing_root)
    if expected_tag_deploy_key_fingerprint == retired_source_deploy_key_fingerprint:
        _fail("tag and retired source deploy-key fingerprints must be distinct")
    if expected_tag_deploy_key_fingerprint == signing_root.public_key_fingerprint:
        _fail("tag deploy-key and maintainer signing-root fingerprints must be distinct")
    if retired_source_deploy_key_fingerprint == signing_root.public_key_fingerprint:
        _fail("retired source deploy-key and maintainer signing-root fingerprints must be distinct")

    snapshot, raw = _read_snapshot(snapshot_path)
    if snapshot["format"] != SNAPSHOT_FORMAT or snapshot["api_version"] != API_VERSION:
        _fail("snapshot format/API version is not exact")
    started_at, observed_at, capture_duration, snapshot_age = _validate_time_window(
        snapshot["started_at"],
        snapshot["observed_at"],
        now,
    )
    _identity(
        snapshot["authenticated_actor"],
        EXPECTED_ACTOR,
        "authenticated actor",
    )
    repository = _exact_mapping(
        snapshot["repository"],
        {"full_name", "id", "default_branch", "fork", "owner"},
        "repository",
    )
    _identity(
        repository["owner"],
        EXPECTED_OWNER,
        "repository owner",
    )
    if (
        not isinstance(repository["full_name"], str)
        or repository["full_name"] != expected_repository
        or _positive(repository["id"], "repository.id") != expected_repository_id
        or not isinstance(repository["default_branch"], str)
        or repository["default_branch"] != "main"
        or repository["fork"] is not False
    ):
        _fail("repository identity/default branch is not exact")
    main = _exact_mapping(
        snapshot["main_branch"],
        {"name", "sha", "protected"},
        "main branch",
    )
    if (
        not isinstance(main["name"], str)
        or main["name"] != "main"
        or not isinstance(main["sha"], str)
        or main["sha"] != expected_main_sha
        or main["protected"] is not True
    ):
        _fail("live main branch identity/protection/SHA is not exact")
    classic = _exact_mapping(
        snapshot["classic_main_branch_protection"],
        {"status"},
        "classic main branch protection",
    )
    status = classic["status"]
    if isinstance(status, bool) or not isinstance(status, int) or status != 404:
        _fail("classic main branch protection must return HTTP 404")

    branch_rulesets = _complete_collection(
        snapshot["branch_and_push_rulesets"],
        "branch/push rulesets",
        maximum_items=MAX_RULESETS,
    )
    if len(branch_rulesets) != 1:
        _fail("there must be exactly one repository/inherited branch-or-push ruleset")
    main_ruleset = _validate_ruleset_shape(branch_rulesets[0], "main ruleset")
    if (
        _positive(main_ruleset["id"], "main ruleset.id") != expected_main_ruleset_id
        or main_ruleset["name"] != EXPECTED_MAIN_RULESET_NAME
        or main_ruleset["target"] != "branch"
        or main_ruleset["source_type"] != "Repository"
        or main_ruleset["source"] != expected_repository
        or main_ruleset["enforcement"] != "active"
    ):
        _fail("main ruleset identity/source/enforcement is not exact")
    if main_ruleset["bypass_actors"] != []:
        _fail("main ruleset must expose no bypass actor during tag authority")
    _validate_ref_condition(
        main_ruleset["conditions"],
        include=["refs/heads/main"],
        label="main ruleset",
    )
    _validate_main_rules(main_ruleset["rules"])

    tag_rulesets = _complete_collection(
        snapshot["tag_rulesets"],
        "tag rulesets",
        maximum_items=MAX_RULESETS,
    )
    if len(tag_rulesets) != 1:
        _fail("there must be exactly one repository/inherited tag ruleset")
    tag_ruleset = _validate_ruleset_shape(tag_rulesets[0], "tag ruleset")
    if (
        _positive(tag_ruleset["id"], "tag ruleset.id") != expected_tag_ruleset_id
        or tag_ruleset["name"] != EXPECTED_TAG_RULESET_NAME
        or tag_ruleset["target"] != "tag"
        or tag_ruleset["source_type"] != "Repository"
        or tag_ruleset["source"] != expected_repository
        or tag_ruleset["enforcement"] != "active"
    ):
        _fail("tag ruleset identity/source/enforcement is not exact")
    expected_bypass = [
        {"actor_id": None, "actor_type": "DeployKey", "bypass_mode": "always"}
    ]
    if tag_ruleset["bypass_actors"] != expected_bypass:
        _fail("tag ruleset bypass must be the generic DeployKey actor only")
    _validate_ref_condition(
        tag_ruleset["conditions"],
        include=["refs/tags/v*"],
        label="tag ruleset",
    )
    _validate_tag_rules(tag_ruleset["rules"])

    deploy_keys = _complete_collection(
        snapshot["deploy_keys"],
        "deploy keys",
        maximum_items=MAX_DEPLOY_KEYS,
    )
    identifiers: set[int] = set()
    public_keys: set[str] = set()
    writers: list[dict[str, Any]] = []
    observed_order: list[int] = []
    for index, raw_key in enumerate(deploy_keys):
        key = _exact_mapping(
            raw_key,
            {"id", "key", "title", "verified", "read_only", "enabled"},
            f"deploy_keys[{index}]",
        )
        identifier = _positive(key["id"], f"deploy_keys[{index}].id")
        public_key = key["key"]
        title = key["title"]
        if identifier in identifiers:
            _fail("deploy-key inventory contains a duplicate ID")
        if not isinstance(public_key, str) or not public_key or public_key in public_keys:
            _fail("deploy-key inventory contains malformed or duplicate key material")
        if (
            not isinstance(title, str)
            or not title
            or "\r" in title
            or "\n" in title
            or not isinstance(key["verified"], bool)
            or not isinstance(key["read_only"], bool)
            or not isinstance(key["enabled"], bool)
        ):
            _fail(f"deploy_keys[{index}] has a malformed normalized shape")
        identifiers.add(identifier)
        public_keys.add(public_key)
        observed_order.append(identifier)
        if public_key.startswith("ssh-ed25519 "):
            observed_fingerprint = _ssh_ed25519_fingerprint(
                public_key,
                label=f"deploy_keys[{index}]",
            )
            if observed_fingerprint == retired_source_deploy_key_fingerprint:
                _fail("retired source-promotion deploy-key fingerprint is still installed")
        if key["enabled"] is True and key["read_only"] is False:
            writers.append(key)
    if observed_order != sorted(observed_order):
        _fail("deploy-key inventory is not normalized by ID")
    if retired_source_deploy_key_id in identifiers:
        _fail("retired source-promotion deploy key is still installed")
    if len(writers) != 1:
        _fail("repository must expose exactly one enabled write deploy key")
    writer = writers[0]
    if writer["id"] != expected_tag_deploy_key_id or writer["verified"] is not True:
        _fail("sole enabled write deploy key identity/verification is not exact")
    actual_fingerprint = _ssh_ed25519_fingerprint(writer["key"])
    if actual_fingerprint != expected_tag_deploy_key_fingerprint:
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
        "authenticated_actor": EXPECTED_ACTOR,
        "repository": {"full_name": expected_repository, "id": expected_repository_id},
        "main_authority": {
            "main_sha": expected_main_sha,
            "ruleset_id": expected_main_ruleset_id,
            "ruleset_name": EXPECTED_MAIN_RULESET_NAME,
            "bypass_actors": [],
            "classic_branch_protection_absent": True,
            "retired_source_deploy_key_id": retired_source_deploy_key_id,
            "retired_source_deploy_key_fingerprint": (
                retired_source_deploy_key_fingerprint
            ),
            "retired_source_deploy_key_absent": True,
        },
        "tag_authority": {
            "ruleset_id": expected_tag_ruleset_id,
            "ruleset_name": EXPECTED_TAG_RULESET_NAME,
            "ref_include": "refs/tags/v*",
            "sole_bypass_actor": "DeployKey",
            "deploy_key_id": expected_tag_deploy_key_id,
            "deploy_key_fingerprint": actual_fingerprint,
            "enabled_write_deploy_key_count": 1,
        },
        "maintainer_signing_root": {
            "sha256": signing_root.root_sha256,
            "version": signing_root.version,
            "public_key_path": signing_root.public_key_path,
            "public_key_sha256": signing_root.public_key_sha256,
            "public_key_fingerprint": signing_root.public_key_fingerprint,
        },
        "key_separation": {
            "tag_vs_retired_source_distinct": True,
            "tag_vs_maintainer_signing_root_distinct": True,
            "retired_source_vs_maintainer_signing_root_distinct": True,
            "tag_deploy_key_fingerprint": actual_fingerprint,
            "retired_source_deploy_key_fingerprint": (
                retired_source_deploy_key_fingerprint
            ),
            "maintainer_signing_root_fingerprint": (
                signing_root.public_key_fingerprint
            ),
        },
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
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise TagAuthorityError("receipt target must not already exist") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--expected-repository", required=True)
    parser.add_argument("--expected-repository-id", required=True)
    parser.add_argument("--expected-main-sha", required=True)
    parser.add_argument("--expected-main-ruleset-id", required=True)
    parser.add_argument("--expected-tag-ruleset-id", required=True)
    parser.add_argument("--expected-tag-deploy-key-id", required=True)
    parser.add_argument("--expected-tag-deploy-key-fingerprint", required=True)
    parser.add_argument("--retired-source-deploy-key-id", required=True)
    parser.add_argument("--retired-source-deploy-key-fingerprint", required=True)
    parser.add_argument("--maintainer-signing-root", required=True, type=Path)
    parser.add_argument("--now")
    parser.add_argument("--receipt", required=True, type=Path)
    return parser


def _parse_now(value: str | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if _TIMESTAMP.fullmatch(value) is None:
        _fail("now must be canonical whole-second UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise TagAuthorityError("now is not a real UTC timestamp") from exc


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        repository_id = _parse_expected_integer(
            arguments.expected_repository_id,
            "expected repository ID",
        )
        main_ruleset_id = _parse_expected_integer(
            arguments.expected_main_ruleset_id,
            "expected main ruleset ID",
        )
        tag_ruleset_id = _parse_expected_integer(
            arguments.expected_tag_ruleset_id,
            "expected tag ruleset ID",
        )
        tag_key_id = _parse_expected_integer(
            arguments.expected_tag_deploy_key_id,
            "expected tag deploy-key ID",
        )
        source_key_id = _parse_expected_integer(
            arguments.retired_source_deploy_key_id,
            "retired source deploy-key ID",
        )
        if arguments.expected_repository != EXPECTED_REPOSITORY:
            _fail("expected repository is not the frozen release repository")
        if _SHA.fullmatch(arguments.expected_main_sha) is None:
            _fail("expected main SHA is not one full lowercase Git ID")
        if _FINGERPRINT.fullmatch(arguments.expected_tag_deploy_key_fingerprint) is None:
            _fail("expected tag deploy-key fingerprint is not canonical SHA256")
        if _FINGERPRINT.fullmatch(arguments.retired_source_deploy_key_fingerprint) is None:
            _fail("retired source deploy-key fingerprint is not canonical SHA256")
        if main_ruleset_id == tag_ruleset_id:
            _fail("main and tag ruleset IDs must be distinct")
        if source_key_id == tag_key_id:
            _fail("retired source and active tag deploy-key IDs must be distinct")
        receipt = validate(
            arguments.snapshot,
            expected_repository=arguments.expected_repository,
            expected_repository_id=repository_id,
            expected_main_sha=arguments.expected_main_sha,
            expected_main_ruleset_id=main_ruleset_id,
            expected_tag_ruleset_id=tag_ruleset_id,
            expected_tag_deploy_key_id=tag_key_id,
            expected_tag_deploy_key_fingerprint=(
                arguments.expected_tag_deploy_key_fingerprint
            ),
            retired_source_deploy_key_id=source_key_id,
            retired_source_deploy_key_fingerprint=(
                arguments.retired_source_deploy_key_fingerprint
            ),
            maintainer_signing_root=arguments.maintainer_signing_root,
            now=_parse_now(arguments.now),
        )
        _write_receipt(arguments.receipt, receipt)
    except (OSError, TagAuthorityError) as exc:
        print(f"release tag authority rejected: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
