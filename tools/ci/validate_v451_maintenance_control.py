#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Validate the closed, inert v4.5.1 maintenance-release control plane.

This module deliberately does not publish a release.  It validates a snapshot
collected without candidate execution and keeps the trusted default-branch
workflow identity separate from the maintenance candidate identity.  The
checked-in contract remains inert until every literal blocker is resolved in a
reviewed default-branch commit.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, NoReturn

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "security" / "v4.5.1-maintenance-lane.json"
MAX_CONTROL_BYTES = 2 * 1024 * 1024
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
PHASES = tuple("ABCDEFGH")
_PLACEHOLDER = "POST_MERGE_REQUIRED"
FINGERPRINT_PATTERN = re.compile(r"^(?:[0-9A-F]{40}|[0-9A-F]{64}|SHA256:[A-Za-z0-9+/]{43}=?)$")


class MaintenanceControlError(ValueError):
    """The observed release lane is outside the reviewed closed contract."""


def _fail(message: str) -> NoReturn:
    raise MaintenanceControlError(message)


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(f"{label} must be an array")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be a non-empty string")
    return value


def _integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        _fail(f"{label} must be a positive integer")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        _fail(f"{label} must be a boolean")
    return value


def _sha(value: Any, label: str) -> str:
    value = _string(value, label)
    if SHA_PATTERN.fullmatch(value) is None:
        _fail(f"{label} must be one lowercase 40-hex Git object ID")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        _fail(
            f"{label} keys are not closed: missing={sorted(expected - actual)!r}, "
            f"unexpected={sorted(actual - expected)!r}"
        )


def _unique_strings(value: Any, label: str) -> tuple[str, ...]:
    items = tuple(_string(item, f"{label} item") for item in _array(value, label))
    if len(items) != len(set(items)):
        _fail(f"{label} entries must be unique")
    return items


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MaintenanceControlError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    raise MaintenanceControlError(f"non-finite JSON number is forbidden: {value}")


def _metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(stat.S_IFMT(metadata.st_mode)),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(flag and attributes & flag)


def load_json(path: Path) -> dict[str, Any]:
    """Read one bounded, duplicate-free JSON object."""

    try:
        before = os.lstat(path)
    except OSError as exc:
        raise MaintenanceControlError(f"cannot inspect JSON input: {path}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or _is_reparse_point(before)
        or not stat.S_ISREG(before.st_mode)
        or int(before.st_nlink) != 1
    ):
        _fail("JSON input must be one regular non-link file")
    if before.st_size < 2 or before.st_size > MAX_CONTROL_BYTES:
        _fail(f"JSON input is outside the 2-{MAX_CONTROL_BYTES} byte bound")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise MaintenanceControlError(f"cannot open JSON input safely: {path}") from exc
    chunks: list[bytes] = []
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse_point(opened)
            or int(opened.st_nlink) != 1
            or _metadata_identity(opened) != _metadata_identity(before)
        ):
            _fail("JSON input changed while it was opened")
        total = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_CONTROL_BYTES:
                _fail("JSON input exceeded its byte bound while being read")
            chunks.append(chunk)
        after_read = os.fstat(descriptor)
        if _metadata_identity(after_read) != _metadata_identity(opened):
            _fail("JSON input changed while it was read")
    finally:
        os.close(descriptor)
    try:
        after_close = os.lstat(path)
    except OSError as exc:
        raise MaintenanceControlError("cannot re-inspect JSON input") from exc
    if _metadata_identity(after_close) != _metadata_identity(before):
        _fail("JSON input path changed during validation")
    raw = b"".join(chunks)
    if len(raw) != before.st_size:
        _fail("JSON input size changed while it was read")
    try:
        decoded = raw.decode("utf-8")
        value = json.loads(
            decoded,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MaintenanceControlError("JSON input is not canonical UTF-8 JSON") from exc
    return _object(value, "JSON input")


def validate_contract(
    contract: dict[str, Any], *, require_activated: bool = True
) -> dict[str, Any]:
    """Validate the literal checked-in lane contract."""

    _exact_keys(
        contract,
        {
            "format",
            "activation",
            "repository",
            "trusted_workflow_source",
            "maintenance_base",
            "candidate",
            "review",
            "workflows",
            "blockers",
        },
        "maintenance contract",
    )
    if contract["format"] != "EVOGUARD_MAINTENANCE_LANE_V1":
        _fail("maintenance contract format is not exact")
    activation = _string(contract["activation"], "contract activation")
    blockers = _unique_strings(contract["blockers"], "contract blockers")
    if require_activated and (activation != "ACTIVE_FOR_ONE_V4_5_1_OPERATION" or blockers):
        _fail("maintenance lane is intentionally inert while blockers remain")

    repository = _object(contract["repository"], "contract repository")
    _exact_keys(
        repository,
        {"full_name", "id", "owner_login", "owner_id", "default_branch"},
        "contract repository",
    )
    if _string(repository["full_name"], "repository full name") != ("EvoRiseKsa/EvoOM-Guard-m"):
        _fail("contract repository is not literal EvoRiseKsa/EvoOM-Guard-m")
    _integer(repository["id"], "repository id")
    _integer(repository["owner_id"], "repository owner id")
    if repository["owner_login"] != "EvoRiseKsa":
        _fail("contract repository owner is not literal EvoRiseKsa")
    if repository["default_branch"] != "main":
        _fail("contract default branch is not literal main")

    workflow_source = _object(contract["trusted_workflow_source"], "trusted workflow source")
    _exact_keys(workflow_source, {"branch", "ref"}, "trusted workflow source")
    if workflow_source != {"branch": "main", "ref": "refs/heads/main"}:
        _fail("trusted workflow source must be literal protected main")

    base = _object(contract["maintenance_base"], "maintenance base")
    _exact_keys(
        base,
        {"branch", "ref", "post_v4_5_0_commit", "post_v4_5_0_tree"},
        "maintenance base",
    )
    if base["branch"] != "maintenance/v4.5" or base["ref"] != ("refs/heads/maintenance/v4.5"):
        _fail("maintenance base branch is not literal maintenance/v4.5")
    _sha(base["post_v4_5_0_commit"], "post-v4.5.0 commit")
    _sha(base["post_v4_5_0_tree"], "post-v4.5.0 tree")

    candidate = _object(contract["candidate"], "candidate contract")
    _exact_keys(
        candidate,
        {
            "branch",
            "ref",
            "version",
            "tag",
            "required_changed_paths",
            "allowed_changed_paths",
        },
        "candidate contract",
    )
    if candidate["branch"] != "release/v4.5.1" or candidate["ref"] != ("refs/heads/release/v4.5.1"):
        _fail("candidate branch is not literal release/v4.5.1")
    if candidate["version"] != "4.5.1" or candidate["tag"] != "v4.5.1":
        _fail("candidate version/tag is not literal v4.5.1")
    required_paths = set(
        _unique_strings(candidate["required_changed_paths"], "required changed paths")
    )
    allowed_paths = set(
        _unique_strings(candidate["allowed_changed_paths"], "allowed changed paths")
    )
    if not required_paths or not required_paths <= allowed_paths:
        _fail("required candidate paths must be a non-empty allowed subset")
    for path in allowed_paths:
        if path.startswith("/") or "\\" in path or ".." in path.split("/"):
            _fail(f"candidate path is not one literal repository path: {path!r}")

    review = _object(contract["review"], "review contract")
    _exact_keys(
        review,
        {
            "required_exact_head_approver",
            "allowed_commit_signers",
            "allowed_signing_key_fingerprints",
        },
        "review contract",
    )
    if review["required_exact_head_approver"] != "MANA-awam":
        _fail("exact-head approver is not literal MANA-awam")
    signers = _unique_strings(review["allowed_commit_signers"], "commit signers")
    if not signers or not set(signers) <= {"EvoRiseKsa", "MANA-awam"}:
        _fail("commit signers are outside the two reviewed owner accounts")
    fingerprints = _unique_strings(
        review["allowed_signing_key_fingerprints"], "signing fingerprints"
    )
    for fingerprint in fingerprints:
        if fingerprint != _PLACEHOLDER and FINGERPRINT_PATTERN.fullmatch(fingerprint) is None:
            _fail("maintainer signing fingerprint is not canonical")
    if require_activated and (not fingerprints or _PLACEHOLDER in fingerprints):
        _fail("a literal reviewed maintainer signing fingerprint is required")

    workflows = _object(contract["workflows"], "workflow map")
    _exact_keys(workflows, set(PHASES), "workflow map")
    for phase in PHASES:
        path = _string(workflows[phase], f"phase {phase} workflow")
        if not path.startswith(".github/workflows/") or not path.endswith(".yml"):
            _fail(f"phase {phase} workflow path is not literal")
    return contract


def _validate_protection(value: Any, label: str) -> dict[str, Any]:
    protection = _object(value, label)
    _exact_keys(
        protection,
        {
            "strict_status_checks",
            "required_checks",
            "dismiss_stale_reviews",
            "require_code_owner_reviews",
            "require_last_push_approval",
            "required_approving_review_count",
            "enforce_admins",
            "allow_force_pushes",
            "allow_deletions",
            "required_conversation_resolution",
        },
        label,
    )
    for field in (
        "strict_status_checks",
        "dismiss_stale_reviews",
        "require_code_owner_reviews",
        "require_last_push_approval",
        "enforce_admins",
        "required_conversation_resolution",
    ):
        if _boolean(protection[field], f"{label} {field}") is not True:
            _fail(f"{label} {field} must be true")
    for field in ("allow_force_pushes", "allow_deletions"):
        if _boolean(protection[field], f"{label} {field}") is not False:
            _fail(f"{label} {field} must be false")
    if (
        _integer(
            protection["required_approving_review_count"],
            f"{label} required approving review count",
        )
        < 1
    ):
        _fail(f"{label} must require an approval")
    checks = _array(protection["required_checks"], f"{label} required checks")
    normalized: list[tuple[str, int]] = []
    for index, raw in enumerate(checks):
        check = _object(raw, f"{label} required check {index}")
        _exact_keys(check, {"context", "app_id"}, f"{label} required check {index}")
        normalized.append(
            (
                _string(check["context"], f"{label} check context"),
                _integer(check["app_id"], f"{label} check app id"),
            )
        )
    if not normalized or len(normalized) != len(set(normalized)):
        _fail(f"{label} required checks must be non-empty and unique")
    return protection


def _validate_branch(
    value: Any,
    *,
    label: str,
    expected_name: str,
    expected_ref: str,
) -> dict[str, Any]:
    branch = _object(value, label)
    _exact_keys(
        branch,
        {"name", "ref", "sha", "tree_sha", "protected", "protection"},
        label,
    )
    if branch["name"] != expected_name or branch["ref"] != expected_ref:
        _fail(f"{label} identity is not literal {expected_name}")
    _sha(branch["sha"], f"{label} commit")
    _sha(branch["tree_sha"], f"{label} tree")
    if _boolean(branch["protected"], f"{label} protected") is not True:
        _fail(f"{label} is unprotected")
    _validate_protection(branch["protection"], f"{label} protection")
    return branch


def _validate_checks(
    checks_value: Any,
    protection: dict[str, Any],
    *,
    target_sha: str,
) -> None:
    observed: dict[tuple[str, int], dict[str, Any]] = {}
    for index, raw in enumerate(_array(checks_value, "pull request checks")):
        check = _object(raw, f"pull request check {index}")
        _exact_keys(
            check,
            {"context", "app_id", "head_sha", "status", "conclusion"},
            f"pull request check {index}",
        )
        key = (
            _string(check["context"], "check context"),
            _integer(check["app_id"], "check app id"),
        )
        if key in observed:
            _fail(f"duplicate required-check observation: {key!r}")
        if _sha(check["head_sha"], "check head SHA") != target_sha:
            _fail("required check is bound to a moved head")
        observed[key] = check
    required = {
        (_string(item["context"], "required check context"), item["app_id"])
        for item in protection["required_checks"]
    }
    if set(observed) != required:
        _fail("observed required checks do not exactly equal branch protection")
    for check in observed.values():
        if check["status"] != "completed" or check["conclusion"] != "success":
            _fail("every exact required check must have completed successfully")


def _validate_attempt_chain(
    value: Any,
    *,
    contract: dict[str, Any],
    workflow_sha: str,
    target_sha: str,
    workflow_blobs: dict[str, str],
    complete: bool,
) -> None:
    chain = _array(value, "attempt chain")
    if not chain and not complete:
        return
    expected_phases = PHASES if complete else PHASES[: len(chain)]
    if len(chain) != len(expected_phases):
        _fail("attempt chain is not an exact A-through-H prefix")
    prior: dict[str, Any] | None = None
    for phase, raw in zip(expected_phases, chain, strict=True):
        run = _object(raw, f"phase {phase} attempt")
        _exact_keys(
            run,
            {
                "phase",
                "workflow_path",
                "workflow_blob_sha",
                "workflow_sha",
                "target_sha",
                "run_id",
                "run_attempt",
                "event",
                "conclusion",
                "upstream_run_id",
                "upstream_run_attempt",
            },
            f"phase {phase} attempt",
        )
        if run["phase"] != phase:
            _fail("attempt chain phase order changed")
        workflow_path = contract["workflows"][phase]
        if run["workflow_path"] != workflow_path:
            _fail(f"phase {phase} workflow path substitution")
        if (
            _sha(run["workflow_blob_sha"], f"phase {phase} workflow blob")
            != (workflow_blobs[workflow_path])
        ):
            _fail(f"phase {phase} workflow blob substitution")
        if _sha(run["workflow_sha"], f"phase {phase} workflow SHA") != workflow_sha:
            _fail(f"phase {phase} did not execute the frozen default-branch workflow")
        if _sha(run["target_sha"], f"phase {phase} target SHA") != target_sha:
            _fail(f"phase {phase} target substitution")
        _integer(run["run_id"], f"phase {phase} run id")
        _integer(run["run_attempt"], f"phase {phase} run attempt")
        expected_event = "workflow_dispatch" if phase in {"A", "E"} else "workflow_run"
        if run["event"] != expected_event or run["conclusion"] != "success":
            _fail(f"phase {phase} event/conclusion is not exact")
        if prior is None:
            if run["upstream_run_id"] is not None or run["upstream_run_attempt"] is not None:
                _fail("phase A must not claim an upstream attempt")
        else:
            if run["upstream_run_id"] != prior["run_id"] or (
                run["upstream_run_attempt"] != prior["run_attempt"]
            ):
                _fail(f"phase {phase} is bound to a stale upstream attempt")
        prior = run


def validate_snapshot(
    snapshot: dict[str, Any],
    contract: dict[str, Any],
    *,
    stage: str = "pre-admission",
) -> dict[str, Any]:
    """Validate one API-derived control snapshot against the closed contract."""

    validate_contract(contract, require_activated=True)
    if stage not in {"pre-admission", "post-publication"}:
        _fail("validation stage must be pre-admission or post-publication")
    _exact_keys(
        snapshot,
        {
            "format",
            "repository",
            "trusted_workflow_branch",
            "maintenance_base_branch",
            "pull_requests",
            "source_commit",
            "workflow_blobs",
            "attempt_chain",
            "tag",
            "release",
        },
        "maintenance snapshot",
    )
    if snapshot["format"] != "EVOGUARD_MAINTENANCE_CONTROL_V1":
        _fail("maintenance snapshot format is not exact")

    repository = _object(snapshot["repository"], "observed repository")
    _exact_keys(
        repository,
        {"full_name", "id", "owner_login", "owner_id", "default_branch"},
        "observed repository",
    )
    if repository != contract["repository"]:
        _fail("observed repository identity differs from the literal contract")

    workflow_contract = contract["trusted_workflow_source"]
    workflow_branch = _validate_branch(
        snapshot["trusted_workflow_branch"],
        label="trusted workflow branch",
        expected_name=workflow_contract["branch"],
        expected_ref=workflow_contract["ref"],
    )
    base_contract = contract["maintenance_base"]
    base_branch = _validate_branch(
        snapshot["maintenance_base_branch"],
        label="maintenance base branch",
        expected_name=base_contract["branch"],
        expected_ref=base_contract["ref"],
    )
    if base_branch["sha"] != base_contract["post_v4_5_0_commit"] or (
        base_branch["tree_sha"] != base_contract["post_v4_5_0_tree"]
    ):
        _fail("maintenance base moved away from the frozen post-v4.5.0 state")
    if base_branch["protection"] != workflow_branch["protection"]:
        _fail("maintenance protection is not exactly equivalent to main")

    pull_requests = _array(snapshot["pull_requests"], "matching pull requests")
    if len(pull_requests) != 1:
        _fail("exactly one open pull request must use the literal release head")
    pull = _object(pull_requests[0], "release pull request")
    _exact_keys(
        pull,
        {
            "number",
            "state",
            "base_ref",
            "base_sha",
            "head_ref",
            "head_repo_full_name",
            "head_repo_id",
            "head_sha",
            "changed_paths",
            "reviews",
            "checks",
        },
        "release pull request",
    )
    _integer(pull["number"], "pull request number")
    candidate_contract = contract["candidate"]
    if (
        pull["state"] != "open"
        or pull["base_ref"] != base_contract["branch"]
        or (pull["head_ref"] != candidate_contract["branch"])
    ):
        _fail("pull request base/head/state is not the one-time literal contract")
    if pull["head_repo_full_name"] != contract["repository"]["full_name"] or (
        pull["head_repo_id"] != contract["repository"]["id"]
    ):
        _fail("alternate-repository candidate is forbidden")
    if _sha(pull["base_sha"], "pull request base SHA") != base_branch["sha"]:
        _fail("pull request base moved after maintenance control collection")
    target_sha = _sha(pull["head_sha"], "pull request head SHA")

    changed_paths = set(_unique_strings(pull["changed_paths"], "changed paths"))
    required_paths = set(candidate_contract["required_changed_paths"])
    allowed_paths = set(candidate_contract["allowed_changed_paths"])
    if not required_paths <= changed_paths or not changed_paths <= allowed_paths:
        _fail("release candidate expanded or omitted the literal maintenance scope")

    source = _object(snapshot["source_commit"], "source commit")
    _exact_keys(
        source,
        {"sha", "tree_sha", "parents", "author_login", "verification"},
        "source commit",
    )
    if _sha(source["sha"], "source commit SHA") != target_sha:
        _fail("source commit does not equal the exact pull request head")
    _sha(source["tree_sha"], "source commit tree")
    parents = tuple(
        _sha(parent, "source parent") for parent in _array(source["parents"], "parents")
    )
    if parents != (base_branch["sha"],):
        _fail("source commit must have one exact post-v4.5.0 maintenance parent")
    if source["author_login"] not in contract["review"]["allowed_commit_signers"]:
        _fail("source commit author is not an allowed maintainer signer")
    verification = _object(source["verification"], "source verification")
    _exact_keys(
        verification,
        {"verified", "reason", "signing_key_fingerprint"},
        "source verification",
    )
    if _boolean(verification["verified"], "source verified") is not True or (
        verification["reason"] != "valid"
    ):
        _fail("source release commit is not GitHub-verifiably signed")
    if (
        verification["signing_key_fingerprint"]
        not in contract["review"]["allowed_signing_key_fingerprints"]
    ):
        _fail("source release commit is not signed by the pinned maintainer key")

    latest_review_by_actor: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(_array(pull["reviews"], "pull request reviews")):
        review = _object(raw, f"review {index}")
        _exact_keys(review, {"id", "actor", "state", "commit_sha"}, f"review {index}")
        _integer(review["id"], "review id")
        actor = _string(review["actor"], "review actor")
        prior = latest_review_by_actor.get(actor)
        if prior is None or review["id"] > prior["id"]:
            latest_review_by_actor[actor] = review
    approver = contract["review"]["required_exact_head_approver"]
    exact_review = latest_review_by_actor.get(approver)
    if (
        exact_review is None
        or exact_review["state"] != "APPROVED"
        or exact_review["commit_sha"] != target_sha
    ):
        _fail("required same-owner review is not an exact-head approval")
    _validate_checks(pull["checks"], base_branch["protection"], target_sha=target_sha)

    raw_blobs = _object(snapshot["workflow_blobs"], "workflow blobs")
    expected_paths = set(contract["workflows"].values())
    if set(raw_blobs) != expected_paths:
        _fail("workflow blob inventory is not the exact A-through-H set")
    workflow_blobs = {
        path: _sha(value, f"workflow blob {path}") for path, value in raw_blobs.items()
    }
    _validate_attempt_chain(
        snapshot["attempt_chain"],
        contract=contract,
        workflow_sha=workflow_branch["sha"],
        target_sha=target_sha,
        workflow_blobs=workflow_blobs,
        complete=stage == "post-publication",
    )

    tag = _object(snapshot["tag"], "tag observation")
    release = _object(snapshot["release"], "release observation")
    if stage == "pre-admission":
        if tag != {"state": "absent"} or release != {"state": "absent"}:
            _fail("pre-admission requires both tag and release to be absent")
    else:
        _exact_keys(
            tag,
            {
                "state",
                "name",
                "object_type",
                "tag_object_sha",
                "target_commit_sha",
                "verification",
            },
            "tag observation",
        )
        if (
            tag["state"] != "present"
            or tag["name"] != candidate_contract["tag"]
            or tag["object_type"] != "tag"
            or _sha(tag["target_commit_sha"], "tag target") != target_sha
        ):
            _fail("release tag is not one exact annotated tag for the source commit")
        _sha(tag["tag_object_sha"], "annotated tag object")
        tag_verification = _object(tag["verification"], "tag verification")
        _exact_keys(
            tag_verification,
            {"verified", "reason", "signer_login", "signing_key_fingerprint"},
            "tag verification",
        )
        if (
            _boolean(tag_verification["verified"], "tag verified") is not True
            or tag_verification["reason"] != "valid"
            or tag_verification["signer_login"] not in contract["review"]["allowed_commit_signers"]
            or tag_verification["signing_key_fingerprint"]
            not in contract["review"]["allowed_signing_key_fingerprints"]
        ):
            _fail("annotated tag lacks the pinned maintainer-controlled signature")
        _exact_keys(
            release,
            {"state", "tag", "target_sha", "immutable", "assets"},
            "release observation",
        )
        if (
            release["state"] != "published"
            or release["tag"] != candidate_contract["tag"]
            or _sha(release["target_sha"], "release target") != target_sha
            or _boolean(release["immutable"], "immutable release") is not True
            or release["assets"] != ["evo-guard.pyz", "evo-guard.spdx.json", "SHA256SUMS"]
        ):
            _fail("published release is outside the exact immutable asset contract")
    return snapshot


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate the inert, one-time v4.5.1 maintenance control snapshot."
    )
    parser.add_argument("snapshot", type=Path)
    parser.add_argument(
        "--stage",
        choices=("pre-admission", "post-publication"),
        default="pre-admission",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        contract = load_json(CONTRACT_PATH)
        snapshot = load_json(args.snapshot)
        validate_snapshot(snapshot, contract, stage=args.stage)
    except MaintenanceControlError as exc:
        print(f"maintenance lane rejected: {exc}")
        return 1
    print(f"maintenance lane valid: stage={args.stage}, version=v4.5.1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
