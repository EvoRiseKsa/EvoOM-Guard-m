from __future__ import annotations

import copy
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools/ci/validate_release_source_protection.py"
SPEC = importlib.util.spec_from_file_location("release_source_protection", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

REPOSITORY = "EvoRiseKsa/EvoOM-Guard-m"
REPOSITORY_ID = 123456
MAIN_SHA = "a" * 40
RULESET_ID = 7654321
DEPLOY_KEY_ID = 24680
PUBLIC_KEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH "
    "fixture"
)
FINGERPRINT = "SHA256:gNSIRW+2Iyiuvsdp/bgjy38bvWHw6wQm3tuoXrl3WjQ"
NOW = datetime(2026, 8, 15, 12, 0, 30, tzinfo=timezone.utc)


def _parameters() -> tuple[dict[str, object], dict[str, object]]:
    pull = {
        "allowed_merge_methods": ["rebase"],
        "dismissal_restriction": None,
        "dismiss_stale_reviews_on_push": True,
        "require_code_owner_review": True,
        "require_last_push_approval": True,
        "required_approving_review_count": 1,
        "required_reviewers": [],
        "required_review_thread_resolution": True,
    }
    checks = {
        "do_not_enforce_on_create": False,
        "strict_required_status_checks_policy": True,
        "required_status_checks": [
            {"context": context, "integration_id": integration}
            for context, integration in sorted(MODULE.EXPECTED_CHECKS)
        ],
    }
    return pull, checks


def _rules(*, applicable: bool) -> list[dict[str, object]]:
    pull, checks = _parameters()
    result: list[dict[str, object]] = []
    for rule_type in sorted(MODULE.EXPECTED_RULE_TYPES):
        rule: dict[str, object] = {"type": rule_type}
        if rule_type == "pull_request":
            rule["parameters"] = pull
        if rule_type == "required_status_checks":
            rule["parameters"] = checks
        if applicable:
            rule.update(
                {
                    "ruleset_id": RULESET_ID,
                    "ruleset_source_type": "Repository",
                    "ruleset_source": REPOSITORY,
                }
            )
        result.append(rule)
    return result


def _snapshot() -> dict[str, object]:
    ruleset = {
        "id": RULESET_ID,
        "name": "EvoOM Guard main signed-source authority",
        "target": "branch",
        "source_type": "Repository",
        "source": REPOSITORY,
        "enforcement": "active",
        "bypass_actors": [
            {"actor_id": None, "actor_type": "DeployKey", "bypass_mode": "always"}
        ],
        "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
        "rules": _rules(applicable=False),
    }
    return {
        "format": MODULE.SNAPSHOT_FORMAT,
        "api_version": MODULE.API_VERSION,
        "started_at": "2026-08-15T11:59:45Z",
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
        "branch_and_push_rulesets": {"complete": True, "pages": 1, "items": [ruleset]},
        "main_ruleset": copy.deepcopy(ruleset),
        "applicable_main_rules": {
            "complete": True,
            "pages": 1,
            "items": _rules(applicable=True),
        },
        "deploy_keys": {
            "complete": True,
            "pages": 1,
            "items": [
                {
                    "id": DEPLOY_KEY_ID,
                    "key": PUBLIC_KEY,
                    "title": "release-source-promotion-v4.7.0",
                    "verified": True,
                    "read_only": False,
                    "enabled": True,
                },
                {
                    "id": 9876,
                    "key": PUBLIC_KEY,
                    "title": "read-only-observer",
                    "verified": True,
                    "read_only": True,
                    "enabled": True,
                },
            ],
        },
    }


def _write(tmp_path: Path, value: object, *, raw: str | None = None) -> Path:
    path = tmp_path / "snapshot.json"
    path.write_text(raw if raw is not None else json.dumps(value), encoding="utf-8")
    return path


def _validate(
    tmp_path: Path,
    value: object,
    *,
    authority_state: str = "source-active",
    expected_deploy_key_fingerprint: str = FINGERPRINT,
) -> dict[str, object]:
    return MODULE.validate(
        _write(tmp_path, value),
        expected_repository=REPOSITORY,
        expected_repository_id=REPOSITORY_ID,
        expected_main_sha=MAIN_SHA,
        expected_ruleset_id=RULESET_ID,
        expected_deploy_key_id=DEPLOY_KEY_ID,
        expected_deploy_key_fingerprint=expected_deploy_key_fingerprint,
        authority_state=authority_state,
        now=NOW,
    )


def test_valid_ruleset_only_authority_passes(tmp_path: Path) -> None:
    receipt = _validate(tmp_path, _snapshot())
    assert receipt["verdict"] == "PASS"
    assert receipt["snapshot_age_seconds"] == 30
    assert receipt["capture_duration_seconds"] == 15
    assert receipt["main_authority"] == {
        "authority_state": "source-active",
        "main_sha": MAIN_SHA,
        "classic_branch_protection_absent": True,
        "ruleset_id": RULESET_ID,
        "ruleset_target": "branch",
        "ruleset_enforcement": "active",
        "sole_bypass_actor": "DeployKey",
        "deploy_key_id": DEPLOY_KEY_ID,
        "deploy_key_fingerprint": FINGERPRINT,
        "retired_deploy_key_id": None,
        "retired_deploy_key_fingerprint": None,
        "enabled_write_deploy_key_count": 1,
    }


def test_source_retired_authority_requires_no_bypass_or_writer(tmp_path: Path) -> None:
    snapshot = _snapshot()
    for ruleset in (
        snapshot["branch_and_push_rulesets"]["items"],
        [snapshot["main_ruleset"]],
    ):
        ruleset[0]["bypass_actors"] = []
    snapshot["deploy_keys"]["items"] = [snapshot["deploy_keys"]["items"][1]]
    receipt = _validate(tmp_path, snapshot, authority_state="source-retired")
    assert receipt["main_authority"]["authority_state"] == "source-retired"
    assert receipt["main_authority"]["sole_bypass_actor"] is None
    assert receipt["main_authority"]["enabled_write_deploy_key_count"] == 0
    assert receipt["main_authority"]["retired_deploy_key_id"] == DEPLOY_KEY_ID


def test_tag_active_authority_requires_no_branch_bypass_and_one_writer(tmp_path: Path) -> None:
    snapshot = _snapshot()
    snapshot["branch_and_push_rulesets"]["items"][0]["bypass_actors"] = []
    snapshot["main_ruleset"]["bypass_actors"] = []
    receipt = _validate(tmp_path, snapshot, authority_state="tag-active")
    assert receipt["main_authority"]["authority_state"] == "tag-active"
    assert receipt["main_authority"]["sole_bypass_actor"] is None


def test_retired_authority_rejects_the_source_key_or_any_writer(tmp_path: Path) -> None:
    snapshot = _snapshot()
    snapshot["branch_and_push_rulesets"]["items"][0]["bypass_actors"] = []
    snapshot["main_ruleset"]["bypass_actors"] = []
    with pytest.raises(MODULE.ProtectionError, match="no enabled write"):
        _validate(tmp_path, snapshot, authority_state="source-retired")


@pytest.mark.parametrize("status", [200, 401, 403, 404.0, False])
def test_classic_branch_protection_is_rejected(tmp_path: Path, status: object) -> None:
    value = _snapshot()
    value["classic_main_branch_protection"]["status"] = status
    with pytest.raises(MODULE.ProtectionError, match="classic main"):
        _validate(tmp_path, value)


def test_repository_id_requires_a_json_integer(tmp_path: Path) -> None:
    snapshot = _snapshot()
    snapshot["repository"]["id"] = float(REPOSITORY_ID)
    with pytest.raises(MODULE.ProtectionError, match="repository identity"):
        _validate(tmp_path, snapshot)


@pytest.mark.parametrize(
    ("field", "value"),
    [("sha", "b" * 40), ("protected", False), ("name", "release")],
)
def test_main_binding_is_exact(tmp_path: Path, field: str, value: object) -> None:
    snapshot = _snapshot()
    snapshot["main_branch"][field] = value
    with pytest.raises(MODULE.ProtectionError, match="live main"):
        _validate(tmp_path, snapshot)


def test_extra_disabled_or_evaluate_ruleset_is_rejected(tmp_path: Path) -> None:
    snapshot = _snapshot()
    extra = copy.deepcopy(snapshot["main_ruleset"])
    extra.update({"id": RULESET_ID + 1, "enforcement": "disabled"})
    snapshot["branch_and_push_rulesets"]["items"].append(extra)
    with pytest.raises(MODULE.ProtectionError, match="exactly one"):
        _validate(tmp_path, snapshot)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda item: item.update({"source": "other/repository"}), "identity/source"),
        (lambda item: item.update({"enforcement": "evaluate"}), "identity or enforcement"),
        (lambda item: item["conditions"]["ref_name"]["include"].append("~ALL"), "condition"),
        (lambda item: item["bypass_actors"].append({"actor_id": 1, "actor_type": "User", "bypass_mode": "always"}), "bypass"),
        (lambda item: item["rules"].pop(), "rule-type"),
    ],
)
def test_ruleset_mutations_fail_closed(tmp_path: Path, mutation, message: str) -> None:
    snapshot = _snapshot()
    mutation(snapshot["branch_and_push_rulesets"]["items"][0])
    snapshot["main_ruleset"] = copy.deepcopy(
        snapshot["branch_and_push_rulesets"]["items"][0]
    )
    with pytest.raises(MODULE.ProtectionError, match=message):
        _validate(tmp_path, snapshot)


def test_required_check_app_id_mutation_is_rejected(tmp_path: Path) -> None:
    snapshot = _snapshot()
    for collection in (
        snapshot["branch_and_push_rulesets"]["items"][0]["rules"],
        snapshot["main_ruleset"]["rules"],
        snapshot["applicable_main_rules"]["items"],
    ):
        rule = next(item for item in collection if item["type"] == "required_status_checks")
        rule["parameters"]["required_status_checks"][0]["integration_id"] = 1
    with pytest.raises(MODULE.ProtectionError, match="check/App-ID"):
        _validate(tmp_path, snapshot)


def test_foreign_effective_rule_is_rejected(tmp_path: Path) -> None:
    snapshot = _snapshot()
    snapshot["applicable_main_rules"]["items"][0]["ruleset_id"] += 1
    with pytest.raises(MODULE.ProtectionError, match="unexpected ruleset"):
        _validate(tmp_path, snapshot)


@pytest.mark.parametrize("field", ["complete", "pages"])
def test_incomplete_collection_is_rejected(tmp_path: Path, field: str) -> None:
    snapshot = _snapshot()
    snapshot["deploy_keys"][field] = False if field == "complete" else 0
    with pytest.raises(MODULE.ProtectionError):
        _validate(tmp_path, snapshot)


def test_two_enabled_write_deploy_keys_are_rejected(tmp_path: Path) -> None:
    snapshot = _snapshot()
    snapshot["deploy_keys"]["items"][1]["read_only"] = False
    with pytest.raises(MODULE.ProtectionError, match="exactly one"):
        _validate(tmp_path, snapshot)


@pytest.mark.parametrize("missing", ["enabled", "read_only", "verified", "title"])
def test_deploy_key_shape_is_exact(tmp_path: Path, missing: str) -> None:
    snapshot = _snapshot()
    snapshot["deploy_keys"]["items"][1].pop(missing)
    with pytest.raises(MODULE.ProtectionError, match="member inventory"):
        _validate(tmp_path, snapshot)


@pytest.mark.parametrize("rule_type", ["pull_request", "required_status_checks"])
def test_rule_parameter_shape_rejects_unknown_members(tmp_path: Path, rule_type: str) -> None:
    snapshot = _snapshot()
    for collection in (
        snapshot["branch_and_push_rulesets"]["items"][0]["rules"],
        snapshot["main_ruleset"]["rules"],
        snapshot["applicable_main_rules"]["items"],
    ):
        rule = next(item for item in collection if item["type"] == rule_type)
        rule["parameters"]["unknown"] = True
    with pytest.raises(MODULE.ProtectionError, match="member inventory"):
        _validate(tmp_path, snapshot)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("dismissal_restriction", {"enabled": True, "allowed_actors": []}),
        (
            "required_reviewers",
            [
                {
                    "file_patterns": ["security/**"],
                    "minimum_approvals": 1,
                    "reviewer": {"id": 1, "type": "Team"},
                }
            ],
        ),
    ],
)
def test_additional_pull_request_authorities_fail_closed(
    tmp_path: Path, field: str, value: object
) -> None:
    snapshot = _snapshot()
    for collection in (
        snapshot["branch_and_push_rulesets"]["items"][0]["rules"],
        snapshot["main_ruleset"]["rules"],
        snapshot["applicable_main_rules"]["items"],
    ):
        rule = next(item for item in collection if item["type"] == "pull_request")
        rule["parameters"][field] = copy.deepcopy(value)
    with pytest.raises(MODULE.ProtectionError, match="pull-request protections"):
        _validate(tmp_path, snapshot)


@pytest.mark.parametrize("value", [True, 1.0])
def test_pull_review_count_requires_a_json_integer(tmp_path: Path, value: object) -> None:
    snapshot = _snapshot()
    for collection in (
        snapshot["branch_and_push_rulesets"]["items"][0]["rules"],
        snapshot["main_ruleset"]["rules"],
        snapshot["applicable_main_rules"]["items"],
    ):
        rule = next(item for item in collection if item["type"] == "pull_request")
        rule["parameters"]["required_approving_review_count"] = value
    with pytest.raises(MODULE.ProtectionError, match="pull-request protections"):
        _validate(tmp_path, snapshot)


@pytest.mark.parametrize("value", [1, 1.0])
def test_main_protected_requires_a_json_boolean(tmp_path: Path, value: object) -> None:
    snapshot = _snapshot()
    snapshot["main_branch"]["protected"] = value
    with pytest.raises(MODULE.ProtectionError, match="live main"):
        _validate(tmp_path, snapshot)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("id", DEPLOY_KEY_ID + 1, "identity"),
        ("verified", False, "verification"),
        ("key", "ssh-ed25519 not-base64", "Base64"),
    ],
)
def test_write_deploy_key_binding_is_exact(
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    snapshot = _snapshot()
    snapshot["deploy_keys"]["items"][0][field] = value
    with pytest.raises(MODULE.ProtectionError, match=message):
        _validate(tmp_path, snapshot)


def test_source_transport_key_must_not_reuse_maintainer_signing_key(
    tmp_path: Path,
) -> None:
    with pytest.raises(MODULE.ProtectionError, match="distinct from the maintainer"):
        _validate(
            tmp_path,
            _snapshot(),
            expected_deploy_key_fingerprint=(
                MODULE.MAINTAINER_SIGNING_KEY_FINGERPRINT
            ),
        )


def test_pinned_maintainer_root_and_source_transport_fixture_are_distinct() -> None:
    root = json.loads(
        (ROOT / "security/release-maintainer-roots/v4.7.0.json").read_text(
            encoding="utf-8"
        )
    )
    assert (
        root["public_key_fingerprint"]
        == MODULE.MAINTAINER_SIGNING_KEY_FINGERPRINT
    )
    assert FINGERPRINT != MODULE.MAINTAINER_SIGNING_KEY_FINGERPRINT


@pytest.mark.parametrize(
    "observed_at",
    ["2026-08-15T11:58:29Z", "2026-08-15T12:00:36Z"],
)
def test_stale_or_future_snapshot_is_rejected(tmp_path: Path, observed_at: str) -> None:
    snapshot = _snapshot()
    snapshot["observed_at"] = observed_at
    with pytest.raises(MODULE.ProtectionError):
        _validate(tmp_path, snapshot)


@pytest.mark.parametrize(
    ("started_at", "message"),
    [
        ("2026-08-15T11:57:59Z", "duration"),
        ("2026-08-15T12:00:01Z", "must not follow"),
    ],
)
def test_capture_window_is_bounded(
    tmp_path: Path, started_at: str, message: str
) -> None:
    snapshot = _snapshot()
    snapshot["started_at"] = started_at
    with pytest.raises(MODULE.ProtectionError, match=message):
        _validate(tmp_path, snapshot)


def test_duplicate_json_members_are_rejected(tmp_path: Path) -> None:
    raw = json.dumps(_snapshot())
    raw = raw.replace('{"format":', '{"format":"duplicate","format":', 1)
    with pytest.raises(MODULE.ProtectionError, match="repeats JSON"):
        MODULE.validate(
            _write(tmp_path, {}, raw=raw),
            expected_repository=REPOSITORY,
            expected_repository_id=REPOSITORY_ID,
            expected_main_sha=MAIN_SHA,
            expected_ruleset_id=RULESET_ID,
            expected_deploy_key_id=DEPLOY_KEY_ID,
            expected_deploy_key_fingerprint=FINGERPRINT,
            now=NOW,
        )
