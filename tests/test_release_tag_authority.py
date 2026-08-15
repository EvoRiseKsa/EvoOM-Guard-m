from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools/ci/validate_release_tag_authority.py"
CAPTURE_PATH = ROOT / "tools/ci/capture_release_tag_authority.js"
SPEC = importlib.util.spec_from_file_location("release_tag_authority", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

REPOSITORY = "EvoRiseKsa/EvoOM-Guard-m"
REPOSITORY_ID = 123456
MAIN_SHA = "a" * 40
MAIN_RULESET_ID = 501
TAG_RULESET_ID = 701
TAG_KEY_ID = 3001
SOURCE_KEY_ID = 2001
OTHER_KEY_ID = 1001
TAG_PUBLIC_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM8t1VabRi9EDmkG+rDMW2hLkl7hgy848AZK"
    "athhYx1a fixture-tag"
)
TAG_FINGERPRINT = "SHA256:UdFxj+QkmmSKC8Vs2YGLH+IGmynCRozOKh9j/06SBhA"
SOURCE_PUBLIC_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA8dScgUHnQrr6Pu32HU6Qjo4DjBYSMiG+xG"
    "4j4eFgKS fixture-source"
)
SOURCE_FINGERPRINT = "SHA256:64Nn1L7O5FZ4wLHJmFe8HwfrFZ4zPRPTD70kCpn0t9k"
MAINTAINER_PUBLIC_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG8TUiovSWLDqx1RG+z7HvmAXp5qgake19fC"
    "qlxHitou fixture maintainer signing root"
)
MAINTAINER_FINGERPRINT = "SHA256:c0fj96h4Nv7UaLOiR+iCv3qhV2cYObEsURfdYcIkeAI"
NOW = datetime(2026, 8, 15, 12, 0, 30, tzinfo=timezone.utc)


def _main_rules() -> list[dict[str, object]]:
    pull = {
        "allowed_merge_methods": ["rebase"],
        "dismissal_restriction": None,
        "dismiss_stale_reviews_on_push": True,
        "require_code_owner_review": True,
        "require_last_push_approval": True,
        "required_approving_review_count": 1,
        "required_review_thread_resolution": True,
        "required_reviewers": [],
    }
    checks = {
        "do_not_enforce_on_create": False,
        "strict_required_status_checks_policy": True,
        "required_status_checks": [
            {"context": context, "integration_id": integration}
            for context, integration in sorted(MODULE.EXPECTED_CHECKS)
        ],
    }
    result: list[dict[str, object]] = []
    for rule_type in sorted(MODULE.EXPECTED_MAIN_RULE_TYPES):
        rule: dict[str, object] = {"type": rule_type}
        if rule_type == "pull_request":
            rule["parameters"] = pull
        elif rule_type == "required_status_checks":
            rule["parameters"] = checks
        result.append(rule)
    return result


def _tag_rules() -> list[dict[str, str]]:
    return [{"type": rule_type} for rule_type in sorted(MODULE.EXPECTED_TAG_RULE_TYPES)]


def _pull_parameters(snapshot: dict[str, object]) -> dict[str, object]:
    rules = snapshot["branch_and_push_rulesets"]["items"][0]["rules"]
    return next(rule["parameters"] for rule in rules if rule["type"] == "pull_request")


def _ruleset(
    *,
    identifier: int,
    name: str,
    target: str,
    include: list[str],
    bypass_actors: list[dict[str, object]],
    rules: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "id": identifier,
        "name": name,
        "target": target,
        "source_type": "Repository",
        "source": REPOSITORY,
        "enforcement": "active",
        "bypass_actors": bypass_actors,
        "conditions": {"ref_name": {"include": include, "exclude": []}},
        "rules": rules,
    }


def _snapshot() -> dict[str, object]:
    main_ruleset = _ruleset(
        identifier=MAIN_RULESET_ID,
        name=MODULE.EXPECTED_MAIN_RULESET_NAME,
        target="branch",
        include=["refs/heads/main"],
        bypass_actors=[],
        rules=_main_rules(),
    )
    tag_ruleset = _ruleset(
        identifier=TAG_RULESET_ID,
        name=MODULE.EXPECTED_TAG_RULESET_NAME,
        target="tag",
        include=["refs/tags/v*"],
        bypass_actors=[
            {"actor_id": None, "actor_type": "DeployKey", "bypass_mode": "always"}
        ],
        rules=_tag_rules(),
    )
    return {
        "format": MODULE.SNAPSHOT_FORMAT,
        "api_version": MODULE.API_VERSION,
        "started_at": "2026-08-15T11:59:55Z",
        "observed_at": "2026-08-15T12:00:00Z",
        "authenticated_actor": copy.deepcopy(MODULE.EXPECTED_ACTOR),
        "repository": {
            "full_name": REPOSITORY,
            "id": REPOSITORY_ID,
            "default_branch": "main",
            "fork": False,
            "owner": copy.deepcopy(MODULE.EXPECTED_OWNER),
        },
        "main_branch": {"name": "main", "sha": MAIN_SHA, "protected": True},
        "classic_main_branch_protection": {"status": 404},
        "branch_and_push_rulesets": {
            "complete": True,
            "pages": 1,
            "items": [main_ruleset],
        },
        "tag_rulesets": {"complete": True, "pages": 1, "items": [tag_ruleset]},
        "deploy_keys": {
            "complete": True,
            "pages": 1,
            "items": [
                {
                    "id": OTHER_KEY_ID,
                    "key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCfixture reader",
                    "title": "unrelated read-only key",
                    "verified": True,
                    "read_only": True,
                    "enabled": True,
                },
                {
                    "id": TAG_KEY_ID,
                    "key": TAG_PUBLIC_KEY,
                    "title": "v4.7.0 temporary tag authority",
                    "verified": True,
                    "read_only": False,
                    "enabled": True,
                },
            ],
        },
    }


def _write(tmp_path: Path, value: object, *, raw: str | None = None) -> Path:
    path = tmp_path / "tag-authority-snapshot.json"
    encoded = raw if raw is not None else json.dumps(value, sort_keys=True, separators=(",", ":"))
    path.write_text(encoded + ("" if encoded.endswith("\n") else "\n"), encoding="utf-8")
    return path


def _write_maintainer_root(
    tmp_path: Path,
    *,
    public_key: str = MAINTAINER_PUBLIC_KEY,
    fingerprint: str = MAINTAINER_FINGERPRINT,
) -> Path:
    directory = tmp_path / "security" / "release-maintainer-roots"
    directory.mkdir(parents=True, exist_ok=True)
    public_path = directory / "v4.7.0.pub"
    public_bytes = f"{public_key}\n".encode("ascii")
    public_path.write_bytes(public_bytes)
    document = {
        "format": "EVOGUARD_RELEASE_MAINTAINER_SIGNING_ROOT_V1",
        "version": "4.7.0",
        "github_login": "EvoRiseKsa",
        "github_user_id": 231647061,
        "key_type": "ssh-ed25519",
        "public_key_path": "security/release-maintainer-roots/v4.7.0.pub",
        "public_key_sha256": hashlib.sha256(public_bytes).hexdigest(),
        "provided_source_file_sha256_crlf": hashlib.sha256(
            public_bytes.replace(b"\n", b"\r\n")
        ).hexdigest(),
        "public_key_fingerprint": fingerprint,
        "signature_namespace": "git",
        "private_key_location": "OUTSIDE_REPOSITORY_AND_GITHUB_ACTIONS",
        "github_verification_required": True,
    }
    root = directory / "v4.7.0.json"
    root.write_bytes((json.dumps(document, indent=2) + "\n").encode("utf-8"))
    return root


def _validate(
    tmp_path: Path,
    value: object,
    *,
    raw: str | None = None,
    tag_fingerprint: str = TAG_FINGERPRINT,
    source_fingerprint: str = SOURCE_FINGERPRINT,
    maintainer_root: Path | None = None,
) -> dict[str, object]:
    if maintainer_root is None:
        maintainer_root = _write_maintainer_root(tmp_path)
    return MODULE.validate(
        _write(tmp_path, value, raw=raw),
        expected_repository=REPOSITORY,
        expected_repository_id=REPOSITORY_ID,
        expected_main_sha=MAIN_SHA,
        expected_main_ruleset_id=MAIN_RULESET_ID,
        expected_tag_ruleset_id=TAG_RULESET_ID,
        expected_tag_deploy_key_id=TAG_KEY_ID,
        expected_tag_deploy_key_fingerprint=tag_fingerprint,
        retired_source_deploy_key_id=SOURCE_KEY_ID,
        retired_source_deploy_key_fingerprint=source_fingerprint,
        maintainer_signing_root=maintainer_root,
        now=NOW,
    )


def test_valid_single_use_tag_authority_passes(tmp_path: Path) -> None:
    receipt = _validate(tmp_path, _snapshot())
    assert receipt["verdict"] == "PASS"
    assert receipt["snapshot_age_seconds"] == 30
    assert receipt["capture_duration_seconds"] == 5
    assert receipt["main_authority"] == {
        "main_sha": MAIN_SHA,
        "ruleset_id": MAIN_RULESET_ID,
        "ruleset_name": MODULE.EXPECTED_MAIN_RULESET_NAME,
        "bypass_actors": [],
        "classic_branch_protection_absent": True,
        "retired_source_deploy_key_id": SOURCE_KEY_ID,
        "retired_source_deploy_key_fingerprint": SOURCE_FINGERPRINT,
        "retired_source_deploy_key_absent": True,
    }
    assert receipt["tag_authority"]["deploy_key_fingerprint"] == TAG_FINGERPRINT
    assert receipt["tag_authority"]["enabled_write_deploy_key_count"] == 1
    assert receipt["key_separation"] == {
        "tag_vs_retired_source_distinct": True,
        "tag_vs_maintainer_signing_root_distinct": True,
        "retired_source_vs_maintainer_signing_root_distinct": True,
        "tag_deploy_key_fingerprint": TAG_FINGERPRINT,
        "retired_source_deploy_key_fingerprint": SOURCE_FINGERPRINT,
        "maintainer_signing_root_fingerprint": MAINTAINER_FINGERPRINT,
    }


def test_branch_deploy_key_bypass_is_rejected(tmp_path: Path) -> None:
    snapshot = _snapshot()
    snapshot["branch_and_push_rulesets"]["items"][0]["bypass_actors"] = [
        {"actor_id": None, "actor_type": "DeployKey", "bypass_mode": "always"}
    ]
    with pytest.raises(MODULE.TagAuthorityError, match="no bypass"):
        _validate(tmp_path, snapshot)


def test_retired_source_key_is_rejected_even_when_read_only(tmp_path: Path) -> None:
    snapshot = _snapshot()
    snapshot["deploy_keys"]["items"].insert(
        1,
        {
            "id": SOURCE_KEY_ID,
            "key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCfixture source",
            "title": "retired source key",
            "verified": True,
            "read_only": True,
            "enabled": False,
        },
    )
    with pytest.raises(MODULE.TagAuthorityError, match="source-promotion deploy key"):
        _validate(tmp_path, snapshot)


def test_retired_source_key_fingerprint_is_rejected_under_a_new_id(tmp_path: Path) -> None:
    snapshot = _snapshot()
    snapshot["deploy_keys"]["items"].insert(
        1,
        {
            "id": SOURCE_KEY_ID + 1,
            "key": SOURCE_PUBLIC_KEY,
            "title": "reinstalled source key under a new ID",
            "verified": True,
            "read_only": True,
            "enabled": False,
        },
    )
    with pytest.raises(MODULE.TagAuthorityError, match="fingerprint is still installed"):
        _validate(tmp_path, snapshot)


def test_second_enabled_writer_is_rejected(tmp_path: Path) -> None:
    snapshot = _snapshot()
    snapshot["deploy_keys"]["items"][0]["read_only"] = False
    with pytest.raises(MODULE.TagAuthorityError, match="exactly one enabled write"):
        _validate(tmp_path, snapshot)


def test_three_public_key_fixtures_are_distinct_valid_ed25519() -> None:
    observed = {
        MODULE._ssh_ed25519_fingerprint(TAG_PUBLIC_KEY),
        MODULE._ssh_ed25519_fingerprint(SOURCE_PUBLIC_KEY),
        MODULE._ssh_ed25519_fingerprint(
            MAINTAINER_PUBLIC_KEY,
            label="maintainer fixture",
        ),
    }
    assert observed == {TAG_FINGERPRINT, SOURCE_FINGERPRINT, MAINTAINER_FINGERPRINT}


def test_tag_and_retired_source_fingerprints_must_differ(tmp_path: Path) -> None:
    with pytest.raises(MODULE.TagAuthorityError, match="tag and retired source"):
        _validate(
            tmp_path,
            _snapshot(),
            source_fingerprint=TAG_FINGERPRINT,
        )


def test_tag_and_maintainer_root_fingerprints_must_differ(tmp_path: Path) -> None:
    with pytest.raises(MODULE.TagAuthorityError, match="maintainer signing-root"):
        _validate(
            tmp_path,
            _snapshot(),
            tag_fingerprint=MAINTAINER_FINGERPRINT,
        )


def test_retired_source_and_maintainer_root_fingerprints_must_differ(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        MODULE.TagAuthorityError,
        match="retired source deploy-key and maintainer signing-root",
    ):
        _validate(
            tmp_path,
            _snapshot(),
            source_fingerprint=MAINTAINER_FINGERPRINT,
        )


def test_maintainer_root_binds_exact_referenced_public_bytes(tmp_path: Path) -> None:
    root = _write_maintainer_root(tmp_path)
    root.with_suffix(".pub").write_bytes(f"{TAG_PUBLIC_KEY}\n".encode("ascii"))
    with pytest.raises(MODULE.TagAuthorityError, match="pinned SHA-256"):
        _validate(tmp_path, _snapshot(), maintainer_root=root)


def test_maintainer_root_rejects_unknown_members(tmp_path: Path) -> None:
    root = _write_maintainer_root(tmp_path)
    document = json.loads(root.read_text(encoding="utf-8"))
    document["unexpected"] = True
    root.write_bytes((json.dumps(document) + "\n").encode("utf-8"))
    with pytest.raises(MODULE.TagAuthorityError, match="member inventory"):
        _validate(tmp_path, _snapshot(), maintainer_root=root)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda item: item.update({"id": TAG_RULESET_ID + 1}), "identity"),
        (lambda item: item.update({"target": "branch"}), "identity"),
        (lambda item: item.update({"enforcement": "evaluate"}), "identity"),
        (
            lambda item: item["conditions"]["ref_name"]["include"].append("~ALL"),
            "includes",
        ),
        (lambda item: item["rules"].pop(), "rule-type"),
        (
            lambda item: item["rules"][0].update({"parameters": {}}),
            "parameter-free",
        ),
        (lambda item: item["bypass_actors"].clear(), "bypass"),
    ],
)
def test_tag_ruleset_drift_is_rejected(tmp_path: Path, mutation, message: str) -> None:
    snapshot = _snapshot()
    mutation(snapshot["tag_rulesets"]["items"][0])
    with pytest.raises(MODULE.TagAuthorityError, match=message):
        _validate(tmp_path, snapshot)


def test_second_tag_or_branch_ruleset_is_rejected(tmp_path: Path) -> None:
    for collection_name in ("branch_and_push_rulesets", "tag_rulesets"):
        snapshot = _snapshot()
        extra = copy.deepcopy(snapshot[collection_name]["items"][0])
        extra["id"] += 100
        snapshot[collection_name]["items"].append(extra)
        with pytest.raises(MODULE.TagAuthorityError, match="exactly one"):
            _validate(tmp_path, snapshot)


@pytest.mark.parametrize(
    "observed_at",
    ["2026-08-15T11:58:29Z", "2026-08-15T12:00:36Z"],
)
def test_stale_or_future_snapshot_is_rejected(tmp_path: Path, observed_at: str) -> None:
    snapshot = _snapshot()
    snapshot["observed_at"] = observed_at
    snapshot["started_at"] = (
        "2026-08-15T11:58:20Z"
        if observed_at < "2026-08-15T12:00:00Z"
        else "2026-08-15T12:00:30Z"
    )
    with pytest.raises(MODULE.TagAuthorityError):
        _validate(tmp_path, snapshot)


@pytest.mark.parametrize(
    ("started_at", "observed_at"),
    [
        ("2026-08-15T12:00:01Z", "2026-08-15T12:00:00Z"),
        ("2026-08-15T11:57:59Z", "2026-08-15T12:00:00Z"),
    ],
)
def test_negative_or_overlong_capture_window_is_rejected(
    tmp_path: Path,
    started_at: str,
    observed_at: str,
) -> None:
    snapshot = _snapshot()
    snapshot["started_at"] = started_at
    snapshot["observed_at"] = observed_at
    with pytest.raises(MODULE.TagAuthorityError, match="capture duration"):
        _validate(tmp_path, snapshot)


@pytest.mark.parametrize("status", [200, True, 404.0])
def test_classic_main_protection_must_be_exact_404(
    tmp_path: Path,
    status: object,
) -> None:
    snapshot = _snapshot()
    snapshot["classic_main_branch_protection"]["status"] = status
    with pytest.raises(MODULE.TagAuthorityError, match="HTTP 404"):
        _validate(tmp_path, snapshot)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("id", TAG_KEY_ID + 1, "identity"),
        ("verified", False, "verification"),
        ("key", "ssh-ed25519 not-base64", "Base64"),
    ],
)
def test_tag_writer_binding_is_exact(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    snapshot = _snapshot()
    snapshot["deploy_keys"]["items"][1][field] = value
    with pytest.raises(MODULE.TagAuthorityError, match=message):
        _validate(tmp_path, snapshot)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"unexpected": True}),
        lambda value: value["repository"].pop("owner"),
        lambda value: value["tag_rulesets"]["items"][0].update({"extra": None}),
        lambda value: value["deploy_keys"].update({"complete": False}),
        lambda value: value["branch_and_push_rulesets"].update({"pages": 0}),
    ],
)
def test_schema_mutations_fail_closed(tmp_path: Path, mutation) -> None:
    snapshot = _snapshot()
    mutation(snapshot)
    with pytest.raises(MODULE.TagAuthorityError):
        _validate(tmp_path, snapshot)


def test_duplicate_and_nonfinite_json_are_rejected(tmp_path: Path) -> None:
    raw = json.dumps(_snapshot(), sort_keys=True, separators=(",", ":"))
    duplicate = raw.replace('{"api_version":', '{"api_version":"duplicate","api_version":', 1)
    with pytest.raises(MODULE.TagAuthorityError, match="repeats JSON"):
        _validate(tmp_path, {}, raw=duplicate)

    nonfinite = raw.replace('"id":123456', '"id":NaN')
    with pytest.raises(MODULE.TagAuthorityError, match="forbidden JSON constant"):
        _validate(tmp_path, {}, raw=nonfinite)


@pytest.mark.parametrize(
    ("location", "field", "value"),
    [
        ("actor", "login", "MANA-awam"),
        ("actor", "id", 231647061.0),
        ("repository", "id", REPOSITORY_ID + 1),
        ("repository", "id", float(REPOSITORY_ID)),
        ("main", "sha", "b" * 40),
    ],
)
def test_actor_repository_and_main_are_exact(
    tmp_path: Path,
    location: str,
    field: str,
    value: object,
) -> None:
    snapshot = _snapshot()
    target = {
        "actor": snapshot["authenticated_actor"],
        "repository": snapshot["repository"],
        "main": snapshot["main_branch"],
    }[location]
    target[field] = value
    with pytest.raises(MODULE.TagAuthorityError):
        _validate(tmp_path, snapshot)


@pytest.mark.parametrize("substitution", [1, 1.0])
def test_main_protected_rejects_integer_and_float_substitutions(
    tmp_path: Path,
    substitution: object,
) -> None:
    snapshot = _snapshot()
    snapshot["main_branch"]["protected"] = substitution
    with pytest.raises(MODULE.TagAuthorityError, match="live main"):
        _validate(tmp_path, snapshot)


@pytest.mark.parametrize("substitution", [1, 1.0])
@pytest.mark.parametrize(
    "field",
    [
        "dismiss_stale_reviews_on_push",
        "require_code_owner_review",
        "require_last_push_approval",
        "required_review_thread_resolution",
    ],
)
def test_pull_request_booleans_reject_integer_and_float_substitutions(
    tmp_path: Path,
    field: str,
    substitution: object,
) -> None:
    snapshot = _snapshot()
    _pull_parameters(snapshot)[field] = substitution
    with pytest.raises(MODULE.TagAuthorityError, match="pull-request protection"):
        _validate(tmp_path, snapshot)


@pytest.mark.parametrize("substitution", [True, 1.0])
def test_pull_request_count_rejects_boolean_and_float_substitutions(
    tmp_path: Path,
    substitution: object,
) -> None:
    snapshot = _snapshot()
    _pull_parameters(snapshot)["required_approving_review_count"] = substitution
    with pytest.raises(MODULE.TagAuthorityError, match="pull-request protection"):
        _validate(tmp_path, snapshot)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("dismissal_restriction", {}),
        ("required_reviewers", [{}]),
    ],
)
def test_pull_request_optional_authority_fields_are_explicitly_empty(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    snapshot = _snapshot()
    _pull_parameters(snapshot)[field] = value
    with pytest.raises(MODULE.TagAuthorityError, match="pull-request protection"):
        _validate(tmp_path, snapshot)


def test_receipt_is_canonical_and_write_new(tmp_path: Path) -> None:
    receipt = _validate(tmp_path, _snapshot())
    output = tmp_path / "receipt.json"
    MODULE._write_receipt(output, receipt)
    expected = json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
    assert output.read_text(encoding="utf-8") == expected
    with pytest.raises(MODULE.TagAuthorityError, match="must not already exist"):
        MODULE._write_receipt(output, receipt)


def test_capture_is_bounded_get_only_and_writes_new() -> None:
    source = CAPTURE_PATH.read_text(encoding="utf-8")
    methods = re.findall(r"['\"]([A-Z]+) /(?:user|repos/)", source)
    assert methods
    assert set(methods) == {"GET"}
    assert "const MAX_PAGES = 10" in source
    assert "const MAX_RULESETS = 100" in source
    assert "flag: 'wx'" in source
    assert "canonicalize(" in source
    assert "const startedAt = new Date()" in source
    assert "classic_main_branch_protection" in source
    assert "dismissal_restriction" in source
    assert "required_reviewers" in source
