"""Frozen equivalence gates for the repository verifier-pack intake seam."""

from __future__ import annotations

import difflib
import json
import os
import tempfile
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest
from repo_pack_intake_characterization_harness import (
    CASE_NAMES,
    SCHEMA_VERSION,
    canonical_json,
    capture_case,
)

from evoom_guard.verifiers import repo_pack_intake, repo_verifier

VECTOR = (
    Path(__file__).parent
    / "fixtures"
    / "refactor-safety"
    / "repo-pack-intake-v1.json"
)


def _frozen() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_repo_pack_intake_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_repo_pack_intake_behavior(case_name: str, tmp_path: Path) -> None:
    expected = _frozen()["cases"][case_name]
    actual = capture_case(case_name, tmp_path)
    if actual != expected:
        diff = "".join(
            difflib.unified_diff(
                canonical_json(expected).splitlines(keepends=True),
                canonical_json(actual).splitlines(keepends=True),
                fromfile=f"frozen/{case_name}",
                tofile=f"current/{case_name}",
            )
        )
        pytest.fail("repo verifier-pack intake behavior drifted:\n" + diff)


def test_repo_pack_intake_owner_exposes_immutable_typed_contracts() -> None:
    request = repo_pack_intake.RepoPackIntakeRequest(
        candidate_copy="copy",
        files_changed=("app.py",),
        pack_dir="",
        expected_pack_sha256="",
    )
    result = repo_pack_intake.intake_repo_pack(
        request,
        services=repo_pack_intake.RepoPackIntakeServices(
            lexists=lambda _path: False,
            create_workspace=lambda _prefix: pytest.fail(
                "no-pack admission allocated a workspace"
            ),
            snapshot_pack=lambda _source, _destination: pytest.fail(
                "no-pack admission attempted a snapshot"
            ),
        ),
    )

    assert repo_pack_intake.intake_repo_pack.__module__ == (
        "evoom_guard.verifiers.repo_pack_intake"
    )
    assert result == repo_pack_intake.RepoPackIntakeResult()
    with pytest.raises(FrozenInstanceError):
        request.pack_dir = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        result.pack_sha256 = "changed"  # type: ignore[misc]


def test_repo_verifier_resolves_pack_operation_seams_at_each_use(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Earlier pack operations may replace every later historical seam."""

    source = tmp_path / "source"
    pack = tmp_path / "pack"
    source.mkdir()
    pack.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (pack / "test_contract.py").write_text(
        "def test_contract():\n    assert True\n",
        encoding="utf-8",
    )
    events: list[str] = []
    original_lexists = os.path.lexists
    original_mkdtemp = tempfile.mkdtemp
    manifest: dict[str, Any] = {"id": "live-pack", "version": "1"}

    def late_snapshot(_source: str, _destination: str):
        events.append("late-snapshot")
        return "a" * 64, manifest

    def unexpected_snapshot(_source: str, _destination: str):
        pytest.fail("a snapshotted pack operation seam was used")

    def late_mkdtemp(*, prefix: str) -> str:
        events.append("late-mkdtemp")
        monkeypatch.setattr(repo_verifier, "snapshot_pack", late_snapshot)
        return original_mkdtemp(prefix=prefix)

    def live_lexists(path: str) -> bool:
        exists = original_lexists(path)
        if os.path.basename(path) == "evoguard_verifier_pack":
            events.append("live-lexists")
            monkeypatch.setattr(repo_verifier.tempfile, "mkdtemp", late_mkdtemp)
        return exists

    monkeypatch.setattr(repo_verifier.os.path, "lexists", live_lexists)
    monkeypatch.setattr(repo_verifier, "snapshot_pack", unexpected_snapshot)

    result = repo_verifier.RepoVerifier(
        isolation="docker",
        mem_limit_mb=0,
        test_command=["unused"],
    ).verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        {
            "repo_path": str(source),
            "verifier_pack": str(pack),
            "expect_verifier_pack_sha256": "a" * 64,
        },
    )

    assert result.artifact["verifier_pack_sha256"] == "a" * 64
    assert result.artifact["verifier_pack_manifest"] == manifest
    assert events == ["live-lexists", "late-mkdtemp", "late-snapshot"]


def test_unexpected_snapshot_failure_preserves_workspace_for_final_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The adapter records the workspace before invoking the live snapshot seam."""

    source = tmp_path / "source"
    pack = tmp_path / "pack"
    source.mkdir()
    pack.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (pack / "test_contract.py").write_text(
        "def test_contract():\n    assert True\n",
        encoding="utf-8",
    )
    cleanup_observations: list[tuple[tuple[tuple[str, str | None], ...], object]] = []
    original_cleanup = repo_verifier._cleanup_repo_workspaces

    def interrupting_snapshot(_source: str, _destination: str):
        raise KeyboardInterrupt("controlled snapshot interruption")

    def recording_cleanup(workspaces, *, primary):
        cleanup_observations.append((tuple(workspaces), primary))
        return original_cleanup(workspaces, primary=primary)

    monkeypatch.setattr(repo_verifier, "snapshot_pack", interrupting_snapshot)
    monkeypatch.setattr(
        repo_verifier, "_cleanup_repo_workspaces", recording_cleanup
    )

    with pytest.raises(KeyboardInterrupt, match="controlled snapshot interruption"):
        repo_verifier.RepoVerifier(
            isolation="docker",
            mem_limit_mb=0,
            test_command=["unused"],
        ).verify(
            "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
            {"repo_path": str(source), "verifier_pack": str(pack)},
        )

    assert len(cleanup_observations) == 1
    workspaces, primary = cleanup_observations[0]
    assert isinstance(primary, KeyboardInterrupt)
    assert workspaces[0][0] == "candidate workspace"
    assert workspaces[0][1]
    assert workspaces[1][0] == "verifier-pack snapshot"
    assert workspaces[1][1]
