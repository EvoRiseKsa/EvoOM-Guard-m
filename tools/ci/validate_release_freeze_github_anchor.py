#!/usr/bin/env python3
"""Validate GitHub server-time evidence for the v4.7.0 freeze declaration."""

from __future__ import annotations

import argparse
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

SNAPSHOT_FORMAT = "EVOGUARD_MINOR_RELEASE_FREEZE_GITHUB_ANCHOR_SNAPSHOT_V1"
RECEIPT_FORMAT = "EVOGUARD_MINOR_RELEASE_FREEZE_GITHUB_ANCHOR_VERIFICATION_V1"
API_VERSION = "2026-03-10"
REPOSITORY = "EvoRiseKsa/EvoOM-Guard-m"
FREEZE_PATH = "security/release-freezes/v4.7.0.json"
MAX_BYTES = 2 * 1024 * 1024
MAX_RUNS = 1000
MAX_SNAPSHOT_AGE_SECONDS = 120
MAX_FUTURE_SKEW_SECONDS = 5
STABILIZATION_SECONDS = 14 * 24 * 60 * 60
MAX_DECLARED_START_DELAY_SECONDS = 60 * 60
EXPECTED_WORKFLOW_PATHS = {
    "windows": ("Windows compatibility", ".github/workflows/windows.yml"),
    "codeql": ("CodeQL", ".github/workflows/codeql.yml"),
    "ci": ("CI", ".github/workflows/ci.yml"),
    "cflite": ("ClusterFuzzLite PR fuzzing", ".github/workflows/cflite_pr.yml"),
}
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_POSITIVE = re.compile(r"[1-9][0-9]*\Z")
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


class AnchorError(ValueError):
    """The GitHub server-time freeze anchor is invalid."""


def _fail(message: str) -> NoReturn:
    raise AnchorError(message)


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"JSON repeats member {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    _fail(f"JSON contains forbidden constant {value!r}")


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    return value


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    result = _mapping(value, label)
    if set(result) != keys:
        _fail(f"{label} member inventory is not exact")
    return result


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


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or _UTC.fullmatch(value) is None:
        _fail(f"{label} is not canonical whole-second UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise AnchorError(f"{label} is not a real UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        _fail(f"{label} is not canonical UTC")
    return parsed


def _read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise AnchorError(f"{label} cannot be inspected: {exc}") from exc
    if path.is_symlink() or not stat.S_ISREG(before.st_mode):
        _fail(f"{label} must be a regular non-symlink file")
    if before.st_size < 2 or before.st_size > MAX_BYTES:
        _fail(f"{label} size is outside bounds")
    raw = path.read_bytes()
    after = path.lstat()
    identity = (
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
    if identity != after_identity:
        _fail(f"{label} changed during its bounded read")
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AnchorError(f"{label} is not valid UTF-8 JSON") from exc
    return _mapping(value, label), raw


def _freeze(root: Path) -> tuple[dict[str, Any], datetime, datetime]:
    record, _ = _read_json(root.joinpath(*FREEZE_PATH.split("/")), "freeze declaration")
    record = _exact(
        record,
        {"format", "state", "version", "source_version", "declaration", "scope", "compatibility"},
        "freeze declaration",
    )
    if (
        record["format"] != "EVOGUARD_MINOR_RELEASE_FREEZE_V1"
        or record["state"] != "FROZEN"
        or record["version"] != "4.7.0"
        or record["source_version"] != "4.7.0.dev0"
    ):
        _fail("freeze declaration is not the active v4.7.0 record")
    declaration = _exact(
        record["declaration"],
        {
            "frozen_parent_commit_sha",
            "frozen_parent_tree_sha",
            "started_at",
            "not_before",
            "stabilization_seconds",
        },
        "freeze timing",
    )
    started = _timestamp(declaration["started_at"], "started_at")
    not_before = _timestamp(declaration["not_before"], "not_before")
    if (
        not _json_equal(declaration["stabilization_seconds"], STABILIZATION_SECONDS)
        or not_before != started + timedelta(seconds=STABILIZATION_SECONDS)
    ):
        _fail("freeze declaration does not encode exactly fourteen days")
    return declaration, started, not_before


def validate(
    *,
    root: Path,
    snapshot_path: Path,
    expected_declaration_commit: str,
    expected_declaration_tree: str,
    expected_repository_id: str,
    expected_workflow_ids: dict[str, str],
    now: datetime,
) -> dict[str, Any]:
    if _SHA.fullmatch(expected_declaration_commit) is None or _SHA.fullmatch(
        expected_declaration_tree
    ) is None:
        _fail("expected declaration commit/tree is not a full lowercase Git ID")
    if _POSITIVE.fullmatch(expected_repository_id) is None:
        _fail("expected repository ID is not a canonical positive integer")
    declaration, started, not_before = _freeze(root.resolve(strict=True))
    snapshot, raw = _read_json(snapshot_path, "GitHub freeze-anchor snapshot")
    snapshot = _exact(
        snapshot,
        {
            "format",
            "api_version",
            "observed_at",
            "repository",
            "repository_id",
            "declaration_commit_sha",
            "declaration_tree_sha",
            "query",
            "workflow_runs",
        },
        "GitHub freeze-anchor snapshot",
    )
    if (
        snapshot["format"] != SNAPSHOT_FORMAT
        or snapshot["api_version"] != API_VERSION
        or snapshot["repository"] != REPOSITORY
        or snapshot["repository_id"] != expected_repository_id
        or snapshot["declaration_commit_sha"] != expected_declaration_commit
        or snapshot["declaration_tree_sha"] != expected_declaration_tree
    ):
        _fail("GitHub freeze-anchor identity is not exact")
    query = _exact(
        snapshot["query"],
        {"branch", "event", "head_sha", "exclude_pull_requests", "per_page"},
        "workflow-run query",
    )
    if not _json_equal(
        query,
        {
            "branch": "main",
            "event": "push",
            "head_sha": expected_declaration_commit,
            "exclude_pull_requests": True,
            "per_page": 100,
        },
    ):
        _fail("workflow-run query is not the exact freeze-declaration search")
    observed = _timestamp(snapshot["observed_at"], "observed_at")
    now = now.astimezone(timezone.utc).replace(microsecond=0)
    if observed > now + timedelta(seconds=MAX_FUTURE_SKEW_SECONDS):
        _fail("freeze-anchor snapshot is unacceptably far in the future")
    age = max(0, int((now - observed).total_seconds()))
    if age > MAX_SNAPSHOT_AGE_SECONDS:
        _fail("freeze-anchor snapshot is stale")
    if now < not_before:
        _fail("fourteen days have not elapsed from the declared start")

    collection = _exact(
        snapshot["workflow_runs"],
        {"complete", "pages", "total_count", "items"},
        "workflow-run collection",
    )
    items = collection["items"]
    if (
        collection["complete"] is not True
        or isinstance(collection["pages"], bool)
        or not isinstance(collection["pages"], int)
        or not 1 <= collection["pages"] <= 10
        or isinstance(collection["total_count"], bool)
        or not isinstance(collection["total_count"], int)
        or not isinstance(items, list)
        or not 1 <= len(items) <= MAX_RUNS
        or collection["total_count"] != len(items)
    ):
        _fail("workflow-run collection is incomplete or outside bounds")
    run_ids: set[str] = set()
    workflow_ids: set[str] = set()
    observed_workflows: set[tuple[str, str, str]] = set()
    created_times: list[datetime] = []
    for index, raw_run in enumerate(items):
        run = _exact(
            raw_run,
            {
                "id",
                "run_attempt",
                "workflow_id",
                "name",
                "path",
                "event",
                "head_branch",
                "head_sha",
                "status",
                "conclusion",
                "created_at",
                "updated_at",
                "repository_id",
                "head_repository_id",
            },
            f"workflow run {index}",
        )
        run_id = run["id"]
        workflow_id = run["workflow_id"]
        if (
            not isinstance(run_id, str)
            or _POSITIVE.fullmatch(run_id) is None
            or run_id in run_ids
            or not isinstance(workflow_id, str)
            or _POSITIVE.fullmatch(workflow_id) is None
            or workflow_id in workflow_ids
        ):
            _fail("workflow-run IDs are malformed or duplicated")
        run_ids.add(run_id)
        workflow_ids.add(workflow_id)
        if (
            not _json_equal(run["run_attempt"], 1)
            or not isinstance(run["name"], str)
            or not run["name"]
            or not isinstance(run["path"], str)
            or run["event"] != "push"
            or run["head_branch"] != "main"
            or run["head_sha"] != expected_declaration_commit
            or run["status"] != "completed"
            or run["conclusion"] != "success"
            or run["repository_id"] != expected_repository_id
            or run["head_repository_id"] != expected_repository_id
        ):
            _fail("workflow run is not an exact successful attempt-1 main push anchor")
        observed_workflows.add((run["name"], run["path"], workflow_id))
        created = _timestamp(run["created_at"], f"workflow run {run_id} created_at")
        updated = _timestamp(run["updated_at"], f"workflow run {run_id} updated_at")
        if updated < created or updated > observed:
            _fail("workflow-run server timestamps are inconsistent")
        created_times.append(created)
    expected_workflows = {
        (*EXPECTED_WORKFLOW_PATHS[key], expected_workflow_ids[key])
        for key in EXPECTED_WORKFLOW_PATHS
    }
    if observed_workflows != expected_workflows or len(items) != len(expected_workflows):
        _fail("exact freeze push workflow name/path/ID inventory is not pinned")
    earliest = min(created_times)
    latest = max(created_times)
    if not latest <= started <= earliest + timedelta(
        seconds=MAX_DECLARED_START_DELAY_SECONDS
    ):
        _fail("declared start is not anchored to the GitHub push window")
    if declaration["frozen_parent_commit_sha"] == expected_declaration_commit:
        _fail("freeze record confuses its parent with its declaration commit")
    return {
        "format": RECEIPT_FORMAT,
        "verdict": "PASS",
        "api_version": API_VERSION,
        "repository": REPOSITORY,
        "repository_id": expected_repository_id,
        "declaration_commit_sha": expected_declaration_commit,
        "declaration_tree_sha": expected_declaration_tree,
        "snapshot_sha256": hashlib.sha256(raw).hexdigest(),
        "snapshot_age_seconds": age,
        "observed_at": observed.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "earliest_push_run_created_at": earliest.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "latest_push_run_created_at": latest.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "declared_started_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "declared_not_before": not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "workflow_run_ids": sorted(run_ids, key=int),
        "workflow_ids": sorted(workflow_ids, key=int),
        "all_runs_attempt_1_terminal_success": True,
        "git_commit_timestamp_used_as_trusted_time": False,
    }


def _write(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        _fail("receipt target must not already exist")
    if path.parent.is_symlink() or not path.parent.is_dir():
        _fail("receipt parent is unavailable")
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--expected-declaration-commit", required=True)
    parser.add_argument("--expected-declaration-tree", required=True)
    parser.add_argument("--expected-repository-id", required=True)
    parser.add_argument("--expected-windows-workflow-id", required=True)
    parser.add_argument("--expected-codeql-workflow-id", required=True)
    parser.add_argument("--expected-ci-workflow-id", required=True)
    parser.add_argument("--expected-cflite-workflow-id", required=True)
    parser.add_argument("--now")
    parser.add_argument("--receipt", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        now = _timestamp(args.now, "now") if args.now else datetime.now(timezone.utc)
        expected_workflow_ids = {
            "windows": args.expected_windows_workflow_id,
            "codeql": args.expected_codeql_workflow_id,
            "ci": args.expected_ci_workflow_id,
            "cflite": args.expected_cflite_workflow_id,
        }
        if any(_POSITIVE.fullmatch(item) is None for item in expected_workflow_ids.values()):
            _fail("expected freeze push workflow IDs must be canonical positive integers")
        if len(set(expected_workflow_ids.values())) != len(expected_workflow_ids):
            _fail("expected freeze push workflow IDs must be mutually distinct")
        receipt = validate(
            root=args.root,
            snapshot_path=args.snapshot,
            expected_declaration_commit=args.expected_declaration_commit,
            expected_declaration_tree=args.expected_declaration_tree,
            expected_repository_id=args.expected_repository_id,
            expected_workflow_ids=expected_workflow_ids,
            now=now,
        )
        _write(args.receipt, receipt)
    except (AnchorError, OSError) as exc:
        print(f"release freeze GitHub anchor rejected: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
