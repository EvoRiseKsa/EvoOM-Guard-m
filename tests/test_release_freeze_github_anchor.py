from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools/ci/validate_release_freeze_github_anchor.py"
SPEC = importlib.util.spec_from_file_location("release_freeze_anchor", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
ANCHOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANCHOR)

DECLARATION_SHA = "a" * 40
DECLARATION_TREE = "b" * 40
PARENT_SHA = "c" * 40
PARENT_TREE = "d" * 40
REPOSITORY_ID = "123456"
NOW = datetime(2026, 8, 29, 0, 0, 30, tzinfo=UTC)
WORKFLOW_IDS = {
    "windows": "2001",
    "codeql": "2002",
    "ci": "2003",
    "cflite": "2004",
}


def _root(
    tmp_path: Path,
    *,
    stabilization_seconds: object = ANCHOR.STABILIZATION_SECONDS,
) -> Path:
    root = tmp_path / "root"
    target = root / "security/release-freezes/v4.7.0.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    record = json.loads(
        (ROOT / "security/release-freezes/v4.7.0.json").read_text(encoding="utf-8")
    )
    record["state"] = "FROZEN"
    record["declaration"].update(
        {
            "frozen_parent_commit_sha": PARENT_SHA,
            "frozen_parent_tree_sha": PARENT_TREE,
            "started_at": "2026-08-15T00:00:00Z",
            "not_before": "2026-08-29T00:00:00Z",
            "stabilization_seconds": stabilization_seconds,
        }
    )
    target.write_text(json.dumps(record), encoding="utf-8")
    return root


def _run(run_id: int, key: str, created: str) -> dict[str, object]:
    name, path = ANCHOR.EXPECTED_WORKFLOW_PATHS[key]
    return {
        "id": str(run_id),
        "run_attempt": 1,
        "workflow_id": WORKFLOW_IDS[key],
        "name": name,
        "path": path,
        "event": "push",
        "head_branch": "main",
        "head_sha": DECLARATION_SHA,
        "status": "completed",
        "conclusion": "success",
        "created_at": created,
        "updated_at": "2026-08-15T00:10:00Z",
        "repository_id": REPOSITORY_ID,
        "head_repository_id": REPOSITORY_ID,
    }


def _snapshot() -> dict[str, object]:
    runs = [
        _run(1001, "windows", "2026-08-14T23:59:58Z"),
        _run(1002, "codeql", "2026-08-14T23:59:59Z"),
        _run(1003, "ci", "2026-08-14T23:59:58Z"),
        _run(1004, "cflite", "2026-08-14T23:59:59Z"),
    ]
    return {
        "format": ANCHOR.SNAPSHOT_FORMAT,
        "api_version": ANCHOR.API_VERSION,
        "observed_at": "2026-08-29T00:00:00Z",
        "repository": ANCHOR.REPOSITORY,
        "repository_id": REPOSITORY_ID,
        "declaration_commit_sha": DECLARATION_SHA,
        "declaration_tree_sha": DECLARATION_TREE,
        "query": {
            "branch": "main",
            "event": "push",
            "head_sha": DECLARATION_SHA,
            "exclude_pull_requests": True,
            "per_page": 100,
        },
        "workflow_runs": {
            "complete": True,
            "pages": 1,
            "total_count": len(runs),
            "items": runs,
        },
    }


def _validate(
    tmp_path: Path,
    value: object,
    *,
    now: datetime = NOW,
    stabilization_seconds: object = ANCHOR.STABILIZATION_SECONDS,
) -> dict[str, object]:
    snapshot = tmp_path / "anchor.json"
    snapshot.write_text(json.dumps(value), encoding="utf-8")
    return ANCHOR.validate(
        root=_root(tmp_path, stabilization_seconds=stabilization_seconds),
        snapshot_path=snapshot,
        expected_declaration_commit=DECLARATION_SHA,
        expected_declaration_tree=DECLARATION_TREE,
        expected_repository_id=REPOSITORY_ID,
        expected_workflow_ids=WORKFLOW_IDS,
        now=now,
    )


def test_server_time_anchor_passes_and_disclaims_git_commit_time(tmp_path: Path) -> None:
    receipt = _validate(tmp_path, _snapshot())
    assert receipt["verdict"] == "PASS"
    assert receipt["workflow_run_ids"] == ["1001", "1002", "1003", "1004"]
    assert receipt["all_runs_attempt_1_terminal_success"] is True
    assert receipt["git_commit_timestamp_used_as_trusted_time"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event", "workflow_dispatch"),
        ("head_branch", "release"),
        ("head_sha", "e" * 40),
        ("status", "queued"),
        ("conclusion", "failure"),
        ("run_attempt", 2),
        ("repository_id", "999"),
        ("head_repository_id", "999"),
    ],
)
def test_non_exact_push_run_is_rejected(tmp_path: Path, field: str, value: object) -> None:
    snapshot = _snapshot()
    snapshot["workflow_runs"]["items"][0][field] = value
    with pytest.raises(ANCHOR.AnchorError, match="successful attempt-1"):
        _validate(tmp_path, snapshot)


@pytest.mark.parametrize("value", [True, 1.0])
def test_run_attempt_requires_a_json_integer(tmp_path: Path, value: object) -> None:
    snapshot = _snapshot()
    snapshot["workflow_runs"]["items"][0]["run_attempt"] = value
    with pytest.raises(ANCHOR.AnchorError, match="successful attempt-1"):
        _validate(tmp_path, snapshot)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("exclude_pull_requests", 1),
        ("exclude_pull_requests", 1.0),
        ("per_page", True),
        ("per_page", 100.0),
    ],
)
def test_query_requires_exact_json_types(
    tmp_path: Path, field: str, value: object
) -> None:
    snapshot = _snapshot()
    snapshot["query"][field] = value
    with pytest.raises(ANCHOR.AnchorError, match="exact freeze-declaration search"):
        _validate(tmp_path, snapshot)


@pytest.mark.parametrize("value", [True, float(ANCHOR.STABILIZATION_SECONDS)])
def test_stabilization_seconds_requires_a_json_integer(
    tmp_path: Path, value: object
) -> None:
    with pytest.raises(ANCHOR.AnchorError, match="exactly fourteen days"):
        _validate(tmp_path, _snapshot(), stabilization_seconds=value)


def test_owner_predated_started_at_is_rejected(tmp_path: Path) -> None:
    snapshot = _snapshot()
    for run in snapshot["workflow_runs"]["items"]:
        run["created_at"] = "2026-08-15T00:00:01Z"
        run["updated_at"] = "2026-08-15T00:10:00Z"
    with pytest.raises(ANCHOR.AnchorError, match="not anchored"):
        _validate(tmp_path, snapshot)


def test_declared_start_more_than_one_hour_after_push_is_rejected(tmp_path: Path) -> None:
    snapshot = _snapshot()
    for run in snapshot["workflow_runs"]["items"]:
        run["created_at"] = "2026-08-14T22:00:00Z"
    with pytest.raises(ANCHOR.AnchorError, match="not anchored"):
        _validate(tmp_path, snapshot)


def test_incomplete_or_empty_inventory_is_rejected(tmp_path: Path) -> None:
    snapshot = _snapshot()
    snapshot["workflow_runs"].update({"complete": False, "total_count": 0, "items": []})
    with pytest.raises(ANCHOR.AnchorError, match="incomplete"):
        _validate(tmp_path, snapshot)


def test_duplicate_run_or_workflow_id_is_rejected(tmp_path: Path) -> None:
    for field in ("id", "workflow_id"):
        snapshot = _snapshot()
        snapshot["workflow_runs"]["items"][1][field] = snapshot["workflow_runs"]["items"][0][field]
        with pytest.raises(ANCHOR.AnchorError, match="duplicated"):
            _validate(tmp_path, snapshot)


def test_snapshot_freshness_is_bounded(tmp_path: Path) -> None:
    snapshot = _snapshot()
    snapshot["observed_at"] = "2026-08-28T23:57:59Z"
    with pytest.raises(ANCHOR.AnchorError, match="stale"):
        _validate(tmp_path, snapshot)


def test_fourteen_day_boundary_is_enforced(tmp_path: Path) -> None:
    with pytest.raises(ANCHOR.AnchorError, match="Fourteen|fourteen"):
        _validate(
            tmp_path,
            _snapshot(),
            now=datetime(2026, 8, 28, 23, 59, 59, tzinfo=UTC),
        )


def test_duplicate_json_member_is_rejected(tmp_path: Path) -> None:
    snapshot = tmp_path / "anchor.json"
    raw = json.dumps(_snapshot()).replace(
        '{"format":', '{"format":"duplicate","format":', 1
    )
    snapshot.write_text(raw, encoding="utf-8")
    with pytest.raises(ANCHOR.AnchorError, match="repeats member"):
        ANCHOR.validate(
            root=_root(tmp_path),
            snapshot_path=snapshot,
            expected_declaration_commit=DECLARATION_SHA,
            expected_declaration_tree=DECLARATION_TREE,
            expected_repository_id=REPOSITORY_ID,
            expected_workflow_ids=WORKFLOW_IDS,
            now=NOW,
        )
