#!/usr/bin/env python3
"""Validate the v4.7.0 minor-release freeze and its 14-day clock.

The checked-in template is inert.  A later release-record-only declaration
commit replaces its four placeholders.  That declaration commit must have one
parent (the reviewed parent-contract commit), change only this record, and land
no later than the declared ``started_at``.  Choosing ``started_at`` slightly in
the future makes ``not_before`` at least fourteen full days after the commit
without requiring a self-referential future commit SHA.  Git commit ``%ct`` is
only a structural sanity check because it is owner-controlled; P and Gate A
must additionally validate GitHub-hosted exact-push run timestamps with
``validate_release_freeze_github_anchor.py`` before claiming the window.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import NoReturn

FORMAT = "EVOGUARD_MINOR_RELEASE_FREEZE_V1"
VERSION = "4.7.0"
SOURCE_VERSION = "4.7.0.dev0"
FREEZE_PATH = "security/release-freezes/v4.7.0.json"
PLACEHOLDER = "POST_MERGE_REQUIRED"
STABILIZATION_SECONDS = 14 * 24 * 60 * 60
MAX_START_DELAY_SECONDS = 60 * 60
SCOPE_SHA256 = "85682b273bc72ddaed4070d25d45ac7da9c3ef4dd21e8b60e2be1fb91ee98e75"
ALLOWED_CHANGED_PATHS = (
    "CHANGELOG.md",
    "PROJECT_STATUS.json",
    "README.md",
    "ROADMAP.md",
    "SECURITY.md",
    "docs/GITHUB_ARTIFACT_ATTESTATIONS.md",
    "docs/PROJECT_STATUS.md",
    "docs/RELEASE_STATUS.md",
    "docs/SBOM.md",
    "docs/architecture/REFACTOR_PROGRAM.md",
    "evoom_guard/__init__.py",
)
REQUIRED_DOCUMENTS = ("CHANGELOG.md", "README.md", "docs/RELEASE_STATUS.md")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_MAX_RECORD_BYTES = 64 * 1024


class FreezeError(ValueError):
    """The freeze record or its raw-Git binding is invalid."""


def _fail(message: str) -> NoReturn:
    raise FreezeError(message)


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            _fail(f"duplicate freeze-record key: {key}")
        value[key] = item
    return value


def _exact(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail(f"{label} keys are not exact")
    return value


def _parse_date(value: object, label: str) -> datetime:
    if not isinstance(value, str) or _DATE.fullmatch(value) is None:
        _fail(f"{label} is not canonical whole-second UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise FreezeError(f"{label} is not a real UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        _fail(f"{label} is not canonical UTC")
    return parsed


def _read_record(root: Path) -> tuple[dict[str, object], bytes]:
    root = root.resolve(strict=True)
    path = root.joinpath(*FREEZE_PATH.split("/"))
    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        _fail("freeze declaration must be one regular non-link file")
    if before.st_size < 1 or before.st_size > _MAX_RECORD_BYTES:
        _fail("freeze declaration size is outside bounds")
    data = path.read_bytes()
    after = os.lstat(path)
    def identity(item: os.stat_result) -> tuple[int, int, int, int, int, int]:
        return (
            item.st_dev,
            item.st_ino,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
            item.st_nlink,
        )
    if identity(before) != identity(after):
        _fail("freeze declaration changed while read")
    try:
        record = json.loads(data, object_pairs_hook=_unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FreezeError("freeze declaration is not canonical JSON data") from exc
    return _exact(
        record,
        {
            "format",
            "state",
            "version",
            "source_version",
            "declaration",
            "scope",
            "compatibility",
        },
        "freeze declaration",
    ), data


def _validate_static(record: dict[str, object]) -> dict[str, object]:
    if (
        record["format"] != FORMAT
        or record["version"] != VERSION
        or record["source_version"] != SOURCE_VERSION
    ):
        _fail("freeze declaration identity is not v4.7.0 V1")
    declaration = _exact(
        record["declaration"],
        {
            "frozen_parent_commit_sha",
            "frozen_parent_tree_sha",
            "started_at",
            "not_before",
            "stabilization_seconds",
        },
        "freeze declaration timing",
    )
    if declaration["stabilization_seconds"] != STABILIZATION_SECONDS:
        _fail("freeze duration is not exactly fourteen days")
    scope = _exact(
        record["scope"],
        {
            "candidate_promotion_policy",
            "candidate_promotion_paths",
            "stabilization_window_allowed_changes",
            "scope_sha256",
        },
        "freeze scope",
    )
    digest_input = {
        "candidate_promotion_paths": list(ALLOWED_CHANGED_PATHS),
        "candidate_promotion_policy": "exact-stable-promotion-scope-only",
        "stabilization_window_allowed_changes": [
            "release-record-corrections-only"
        ],
        "version": VERSION,
    }
    digest = hashlib.sha256(
        (
            json.dumps(digest_input, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
    ).hexdigest()
    if (
        scope["candidate_promotion_policy"]
        != "exact-stable-promotion-scope-only"
        or scope["candidate_promotion_paths"] != list(ALLOWED_CHANGED_PATHS)
        or scope["stabilization_window_allowed_changes"]
        != ["release-record-corrections-only"]
        or scope["scope_sha256"] != SCOPE_SHA256
        or digest != SCOPE_SHA256
    ):
        _fail("freeze stabilization and stable-promotion scopes are not exact")
    compatibility = _exact(
        record["compatibility"],
        {"classification", "required_documents"},
        "freeze compatibility",
    )
    if (
        compatibility["classification"] != "compatible-minor"
        or compatibility["required_documents"] != list(REQUIRED_DOCUMENTS)
    ):
        _fail("minor-release compatibility declaration is not exact")
    return declaration


def _git(repository: Path, *arguments: str, binary: bool = False) -> bytes | str:
    command = ["git", "-C", str(repository), *arguments]
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        _fail(f"trusted raw-Git query failed: {' '.join(arguments)}")
    if binary:
        return completed.stdout
    try:
        return completed.stdout.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise FreezeError("trusted raw-Git output is not ASCII") from exc


def validate_template(root: Path) -> None:
    record, _ = _read_record(root)
    declaration = _validate_static(record)
    if record["state"] != "POST_MERGE_DECLARATION_REQUIRED" or any(
        declaration[key] != PLACEHOLDER
        for key in (
            "frozen_parent_commit_sha",
            "frozen_parent_tree_sha",
            "started_at",
            "not_before",
        )
    ):
        _fail("freeze template is partially activated")


def validate_active(
    root: Path,
    repository: Path,
    declaration_commit: str,
    expected_tree: str,
    now: datetime,
) -> dict[str, object]:
    if _SHA.fullmatch(declaration_commit) is None or _SHA.fullmatch(expected_tree) is None:
        _fail("declaration commit/tree pins are not full lowercase Git IDs")
    if not repository.is_dir():
        _fail("raw-Git repository is unavailable")
    record, record_bytes = _read_record(root)
    declaration = _validate_static(record)
    if record["state"] != "FROZEN":
        _fail("minor-release freeze is not active")
    for key in ("frozen_parent_commit_sha", "frozen_parent_tree_sha"):
        identifier = declaration[key]
        if not isinstance(identifier, str) or _SHA.fullmatch(identifier) is None:
            _fail(f"{key} is not a full lowercase Git ID")
    started_at = _parse_date(declaration["started_at"], "started_at")
    not_before = _parse_date(declaration["not_before"], "not_before")
    if not_before != started_at + timedelta(seconds=STABILIZATION_SECONDS):
        _fail("not_before is not exactly fourteen days after started_at")
    commit_type = _git(repository, "cat-file", "-t", declaration_commit)
    if commit_type != "commit":
        _fail("freeze declaration pin is not a commit")
    parents = str(_git(repository, "rev-list", "--parents", "-n", "1", declaration_commit)).split()
    if len(parents) != 2 or parents[0] != declaration_commit:
        _fail("freeze declaration commit must have exactly one parent")
    parent = parents[1]
    if parent != declaration["frozen_parent_commit_sha"]:
        _fail("freeze declaration parent does not match the record")
    tree = str(_git(repository, "rev-parse", f"{declaration_commit}^{{tree}}"))
    parent_tree = str(_git(repository, "rev-parse", f"{parent}^{{tree}}"))
    if tree != expected_tree or parent_tree != declaration["frozen_parent_tree_sha"]:
        _fail("freeze declaration tree binding is not exact")
    changed_raw = _git(
        repository,
        "diff-tree",
        "--no-commit-id",
        "--name-only",
        "-r",
        "-z",
        parent,
        declaration_commit,
        binary=True,
    )
    assert isinstance(changed_raw, bytes)
    changed = tuple(
        item.decode("utf-8", "strict") for item in changed_raw.split(b"\0") if item
    )
    if changed != (FREEZE_PATH,):
        _fail("freeze declaration commit is not release-record-only")
    for revision in (parent, declaration_commit):
        entry = str(_git(repository, "ls-tree", revision, "--", FREEZE_PATH)).split()
        if len(entry) < 3 or entry[0] != "100644" or entry[1] != "blob":
            _fail("freeze declaration mode/type changed")
    committed_bytes = _git(
        repository,
        "show",
        f"{declaration_commit}:{FREEZE_PATH}",
        binary=True,
    )
    assert isinstance(committed_bytes, bytes)
    if committed_bytes != record_bytes:
        _fail("working freeze declaration differs from the raw committed blob")
    commit_epoch_text = str(_git(repository, "show", "-s", "--format=%ct", declaration_commit))
    if not commit_epoch_text.isdigit():
        _fail("freeze declaration commit time is invalid")
    commit_time = datetime.fromtimestamp(int(commit_epoch_text), tz=timezone.utc)
    if not commit_time <= started_at <= commit_time + timedelta(
        seconds=MAX_START_DELAY_SECONDS
    ):
        _fail("started_at must be within one hour after the declaration commit")
    if now.tzinfo is None:
        _fail("validation time must be timezone-aware")
    now = now.astimezone(timezone.utc).replace(microsecond=0)
    if now < not_before:
        _fail("the fourteen-day stabilization window has not elapsed")
    return {
        "format": "EVOGUARD_MINOR_RELEASE_FREEZE_VERIFICATION_V1",
        "status": "PASS",
        "version": VERSION,
        "declaration_commit_sha": declaration_commit,
        "declaration_tree_sha": tree,
        "frozen_parent_commit_sha": parent,
        "frozen_parent_tree_sha": parent_tree,
        "started_at": started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "not_before": not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verified_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope_sha256": SCOPE_SHA256,
        "git_commit_timestamp_used_as_trusted_time": False,
        "required_external_time_anchor": (
            "EVOGUARD_MINOR_RELEASE_FREEZE_GITHUB_ANCHOR_VERIFICATION_V1"
        ),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--repository", type=Path)
    parser.add_argument("--declaration-commit")
    parser.add_argument("--expected-tree")
    parser.add_argument("--now")
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--allow-template", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.allow_template:
            if any(
                value is not None
                for value in (
                    args.repository,
                    args.declaration_commit,
                    args.expected_tree,
                    args.now,
                    args.receipt,
                )
            ):
                _fail("template validation cannot accept active-run inputs")
            validate_template(args.root)
            print("minor-release freeze template valid and inert")
            return 0
        if None in (args.repository, args.declaration_commit, args.expected_tree):
            _fail("active validation requires repository, declaration commit, and tree")
        now = (
            _parse_date(args.now, "now")
            if args.now is not None
            else datetime.now(timezone.utc).replace(microsecond=0)
        )
        receipt = validate_active(
            args.root,
            args.repository,
            args.declaration_commit,
            args.expected_tree,
            now,
        )
        if args.receipt is not None:
            data = (
                json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("utf-8")
            descriptor = os.open(
                args.receipt,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(descriptor, "wb") as output:
                output.write(data)
        print("minor-release freeze valid: fourteen-day window elapsed")
        return 0
    except (FreezeError, OSError, subprocess.SubprocessError) as exc:
        print(f"minor-release freeze rejected: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
