from __future__ import annotations

import copy
import json
import os
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from tools.ci import validate_minor_release_freeze as freeze

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / freeze.FREEZE_PATH
SCHEMA = ROOT / "tests/baseline/schema/minor-release-freeze-v1.schema.json"
DECLARATION_TIME = datetime(2026, 8, 15, 0, 0, tzinfo=timezone.utc)


@dataclass(frozen=True)
class ActiveFreeze:
    root: Path
    parent: str
    parent_tree: str
    declaration_commit: str
    declaration_tree: str
    started_at: datetime
    not_before: datetime


def _run_git(root: Path, *arguments: str, environment: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0:
        pytest.fail(
            f"git command failed: {arguments!r}\n"
            f"stdout={completed.stdout}\nstderr={completed.stderr}"
        )
    return completed.stdout.strip()


def _write_record(root: Path, record: dict[str, object]) -> None:
    path = root / freeze.FREEZE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(record, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _commit(root: Path, message: str, timestamp: datetime) -> str:
    canonical = timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_DATE": canonical,
            "GIT_COMMITTER_DATE": canonical,
        }
    )
    _run_git(root, "add", "-A", environment=environment)
    _run_git(root, "commit", "-qm", message, environment=environment)
    return _run_git(root, "rev-parse", "HEAD")


def _active_repository(
    root: Path,
    *,
    mutate_record: Callable[[dict[str, object]], None] | None = None,
    extra_changed_path: str | None = None,
    commit_time: datetime = DECLARATION_TIME,
) -> ActiveFreeze:
    root.mkdir()
    _run_git(root, "init", "-q", "--initial-branch=main")
    _run_git(root, "config", "user.name", "Freeze Test")
    _run_git(root, "config", "user.email", "freeze@example.invalid")
    _run_git(root, "config", "core.autocrlf", "false")

    template = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    _write_record(root, template)
    parent = _commit(root, "parent contract", commit_time - timedelta(seconds=1))
    parent_tree = _run_git(root, "rev-parse", f"{parent}^{{tree}}")

    started_at = commit_time
    not_before = started_at + timedelta(seconds=freeze.STABILIZATION_SECONDS)
    record = copy.deepcopy(template)
    record["state"] = "FROZEN"
    declaration = record["declaration"]
    assert isinstance(declaration, dict)
    declaration.update(
        {
            "frozen_parent_commit_sha": parent,
            "frozen_parent_tree_sha": parent_tree,
            "started_at": started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "not_before": not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )
    if mutate_record is not None:
        mutate_record(record)
    _write_record(root, record)
    if extra_changed_path is not None:
        (root / extra_changed_path).write_text("out of scope\n", encoding="utf-8")
    declaration_commit = _commit(root, "activate release freeze", commit_time)
    declaration_tree = _run_git(root, "rev-parse", f"{declaration_commit}^{{tree}}")
    return ActiveFreeze(
        root=root,
        parent=parent,
        parent_tree=parent_tree,
        declaration_commit=declaration_commit,
        declaration_tree=declaration_tree,
        started_at=started_at,
        not_before=not_before,
    )


def _validate(active: ActiveFreeze, *, now: datetime | None = None) -> dict[str, object]:
    return freeze.validate_active(
        active.root,
        active.root,
        active.declaration_commit,
        active.declaration_tree,
        active.not_before if now is None else now,
    )


def _assert_frozen_declaration_invariants(record: dict[str, object]) -> None:
    """Static invariants every activated (``FROZEN``) declaration must satisfy.

    The raw-Git bindings and the server-time anchor are enforced separately by
    ``validate_active`` and the anchor validators at promotion time.
    """

    declaration = record["declaration"]
    assert isinstance(declaration, dict)
    assert freeze.PLACEHOLDER not in set(declaration.values())
    sha = re.compile(r"[0-9a-f]{40}\Z")
    assert sha.fullmatch(declaration["frozen_parent_commit_sha"])
    assert sha.fullmatch(declaration["frozen_parent_tree_sha"])
    started_at = datetime.strptime(
        declaration["started_at"], "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=timezone.utc)
    not_before = datetime.strptime(
        declaration["not_before"], "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=timezone.utc)
    assert not_before == started_at + timedelta(seconds=freeze.STABILIZATION_SECONDS)
    assert declaration["stabilization_seconds"] == freeze.STABILIZATION_SECONDS


def test_checked_in_template_is_schema_valid_and_semantically_inert() -> None:
    """The checked-in record is valid for its exact lifecycle state.

    Before activation the record must be the inert template. Once the
    release-record-only declaration commit sets ``state`` to ``FROZEN``, the
    checked-in record is legitimately active, so this gate then enforces the
    full static declaration invariants instead (the raw-Git bindings and the
    server-time anchor are enforced separately by ``validate_active`` and the
    anchor validators at promotion time).
    """

    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    record = json.loads(TEMPLATE.read_text(encoding="utf-8"))

    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(record)

    if record["state"] == "FROZEN":
        _assert_frozen_declaration_invariants(record)
        return

    freeze.validate_template(ROOT)

    assert record["state"] == "POST_MERGE_DECLARATION_REQUIRED"
    assert set(record["declaration"].values()) == {
        freeze.PLACEHOLDER,
        freeze.STABILIZATION_SECONDS,
    }


def test_next_declaration_activation_dry_run_passes_the_frozen_gate() -> None:
    """Activating the checked-in template exactly as the declaration dance
    does must satisfy the schema and the FROZEN-state gate above.

    This is the standing pre-flight for the next real declaration commit: if
    the schema, the validator constants, or the FROZEN-state invariants ever
    drift apart, this fails here first instead of on a live activation
    attempt (the ordering gap observed on the first v4.7.0 attempt).
    """

    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    record = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    if record["state"] == "FROZEN":
        pytest.skip("the checked-in record is already an active declaration")

    record["state"] = "FROZEN"
    declaration = record["declaration"]
    assert isinstance(declaration, dict)
    started_at = DECLARATION_TIME
    not_before = started_at + timedelta(seconds=freeze.STABILIZATION_SECONDS)
    declaration.update(
        {
            "frozen_parent_commit_sha": "0" * 40,
            "frozen_parent_tree_sha": "0" * 40,
            "started_at": started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "not_before": not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )

    Draft202012Validator(schema).validate(record)
    _assert_frozen_declaration_invariants(record)


def test_active_one_parent_record_only_freeze_passes_at_exact_fourteen_day_boundary(
    tmp_path: Path,
) -> None:
    active = _active_repository(tmp_path / "repository")

    receipt = _validate(active)

    assert _run_git(active.root, "rev-list", "--parents", "-n", "1", "HEAD").split() == [
        active.declaration_commit,
        active.parent,
    ]
    assert receipt == {
        "format": "EVOGUARD_MINOR_RELEASE_FREEZE_VERIFICATION_V1",
        "status": "PASS",
        "version": freeze.VERSION,
        "declaration_commit_sha": active.declaration_commit,
        "declaration_tree_sha": active.declaration_tree,
        "frozen_parent_commit_sha": active.parent,
        "frozen_parent_tree_sha": active.parent_tree,
        "started_at": "2026-08-15T00:00:00Z",
        "not_before": "2026-08-29T00:00:00Z",
        "verified_at": "2026-08-29T00:00:00Z",
        "scope_sha256": freeze.SCOPE_SHA256,
        "git_commit_timestamp_used_as_trusted_time": False,
        "required_external_time_anchor": (
            "EVOGUARD_MINOR_RELEASE_FREEZE_GITHUB_ANCHOR_VERIFICATION_V1"
        ),
    }


def test_active_freeze_rejects_one_second_before_boundary(tmp_path: Path) -> None:
    active = _active_repository(tmp_path / "repository")

    with pytest.raises(freeze.FreezeError, match="window has not elapsed"):
        _validate(active, now=active.not_before - timedelta(seconds=1))


def test_active_freeze_rejects_wrong_recorded_parent(tmp_path: Path) -> None:
    def mutate(record: dict[str, object]) -> None:
        declaration = record["declaration"]
        assert isinstance(declaration, dict)
        declaration["frozen_parent_commit_sha"] = "0" * 40

    active = _active_repository(tmp_path / "repository", mutate_record=mutate)

    with pytest.raises(freeze.FreezeError, match="parent does not match"):
        _validate(active)


@pytest.mark.parametrize("binding", ["expected-tree", "recorded-parent-tree"])
def test_active_freeze_rejects_wrong_tree_binding(tmp_path: Path, binding: str) -> None:
    def mutate(record: dict[str, object]) -> None:
        if binding == "recorded-parent-tree":
            declaration = record["declaration"]
            assert isinstance(declaration, dict)
            declaration["frozen_parent_tree_sha"] = "0" * 40

    active = _active_repository(tmp_path / "repository", mutate_record=mutate)
    expected_tree = "0" * 40 if binding == "expected-tree" else active.declaration_tree

    with pytest.raises(freeze.FreezeError, match="tree binding is not exact"):
        freeze.validate_active(
            active.root,
            active.root,
            active.declaration_commit,
            expected_tree,
            active.not_before,
        )


def test_active_freeze_rejects_non_record_only_commit(tmp_path: Path) -> None:
    active = _active_repository(
        tmp_path / "repository",
        extra_changed_path="unexpected.txt",
    )

    with pytest.raises(freeze.FreezeError, match="not release-record-only"):
        _validate(active)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("started_at", "2026-08-15T01:00:01Z", "within one hour"),
        ("not_before", "2026-08-28T23:59:59Z", "exactly fourteen days"),
        ("started_at", "2026-08-15T00:00:00+00:00", "canonical whole-second UTC"),
    ],
)
def test_active_freeze_rejects_invalid_timestamp_bindings(
    tmp_path: Path,
    field: str,
    value: str,
    message: str,
) -> None:
    def mutate(record: dict[str, object]) -> None:
        declaration = record["declaration"]
        assert isinstance(declaration, dict)
        declaration[field] = value
        if field == "started_at" and message == "within one hour":
            declaration["not_before"] = "2026-08-29T01:00:01Z"

    active = _active_repository(tmp_path / "repository", mutate_record=mutate)

    with pytest.raises(freeze.FreezeError, match=message):
        _validate(active)


@pytest.mark.parametrize(
    "field",
    [
        "frozen_parent_commit_sha",
        "frozen_parent_tree_sha",
        "started_at",
        "not_before",
    ],
)
def test_active_freeze_rejects_every_placeholder(tmp_path: Path, field: str) -> None:
    def mutate(record: dict[str, object]) -> None:
        declaration = record["declaration"]
        assert isinstance(declaration, dict)
        declaration[field] = freeze.PLACEHOLDER

    active = _active_repository(tmp_path / "repository", mutate_record=mutate)

    with pytest.raises(freeze.FreezeError):
        _validate(active)


def test_template_rejects_partial_activation(tmp_path: Path) -> None:
    record = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    declaration = record["declaration"]
    assert isinstance(declaration, dict)
    declaration["started_at"] = "2026-08-15T00:00:00Z"
    _write_record(tmp_path, record)

    with pytest.raises(freeze.FreezeError, match="partially activated"):
        freeze.validate_template(tmp_path)


def _inert_template_raw() -> str:
    """Reconstruct the inert template text from the checked-in record.

    The duplicate-key fixtures splice exact placeholder lines, so they must
    start from the inert form even after the checked-in record has been
    activated to ``FROZEN`` by the release-record declaration commit.
    """

    record = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    record["state"] = "POST_MERGE_DECLARATION_REQUIRED"
    declaration = record["declaration"]
    assert isinstance(declaration, dict)
    for key in (
        "frozen_parent_commit_sha",
        "frozen_parent_tree_sha",
        "started_at",
        "not_before",
    ):
        declaration[key] = freeze.PLACEHOLDER
    return json.dumps(record, indent=2) + "\n"


@pytest.mark.parametrize("nested", [False, True])
def test_freeze_record_rejects_duplicate_keys(tmp_path: Path, nested: bool) -> None:
    raw = _inert_template_raw()
    if nested:
        raw = raw.replace(
            '    "started_at": "POST_MERGE_REQUIRED",',
            '    "started_at": "POST_MERGE_REQUIRED",\n'
            '    "started_at": "POST_MERGE_REQUIRED",',
            1,
        )
        duplicate_key = "started_at"
    else:
        raw = raw.replace(
            '  "format": "EVOGUARD_MINOR_RELEASE_FREEZE_V1",',
            '  "format": "EVOGUARD_MINOR_RELEASE_FREEZE_V1",\n'
            '  "format": "EVOGUARD_MINOR_RELEASE_FREEZE_V1",',
            1,
        )
        duplicate_key = "format"
    path = tmp_path / freeze.FREEZE_PATH
    path.parent.mkdir(parents=True)
    path.write_text(raw, encoding="utf-8", newline="\n")

    with pytest.raises(
        freeze.FreezeError,
        match=rf"duplicate freeze-record key: {duplicate_key}",
    ):
        freeze.validate_template(tmp_path)
