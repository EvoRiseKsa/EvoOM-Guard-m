"""Deterministic characterization of RepoVerifier's verifier-pack intake seam."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

from evoom_guard.contracts import VerdictResult
from evoom_guard.pack_manifest import PackManifestError
from evoom_guard.verifiers import repo_verifier

SCHEMA_VERSION = "repo-pack-intake-characterization-v1"
CASE_NAMES = (
    "digest_mismatch",
    "expected_pin_without_pack",
    "invalid_pack_snapshot",
    "reserved_mount_collision",
    "valid_identity_sticky_evidence",
)

_APP_EDIT = "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n"
_EXPECTED_DIGEST = "a" * 64
_OBSERVED_DIGEST = "b" * 64
_MANIFEST = {
    "description": "characterization",
    "id": "frozen-pack",
    "target_type": "repository",
    "version": "1",
}


def canonical_json(value: Any) -> str:
    """Return stable, human-reviewable JSON."""

    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _normalized_result(result: VerdictResult) -> dict[str, Any]:
    artifact = copy.deepcopy(result.artifact)
    artifact.pop("elapsed", None)
    return {
        "artifact": artifact,
        "diagnostics": result.diagnostics,
        "passed": result.passed,
        "score": result.score,
    }


def capture_case(case_name: str, workspace: Path) -> dict[str, Any]:
    """Capture one pre-extraction result and dependency-call ordering."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown repo-pack intake case: {case_name}")

    source = workspace / f"source-{case_name}"
    source.mkdir(parents=True)
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    if case_name == "reserved_mount_collision":
        (source / "evoguard_verifier_pack").mkdir()

    pack = workspace / f"pack-{case_name}"
    pack.mkdir()
    (pack / "test_contract.py").write_text(
        "def test_contract():\n    assert True\n",
        encoding="utf-8",
    )

    events: list[dict[str, str]] = []
    candidate_workspace_root: str | None = None
    repo_copy_root: str | None = None
    pack_workspace_root: str | None = None

    original_lexists = repo_verifier.os.path.lexists
    original_mkdtemp = repo_verifier.tempfile.mkdtemp
    original_snapshot_pack = repo_verifier.snapshot_pack
    original_cleanup = repo_verifier._cleanup_repo_workspaces

    def token(path: str) -> str:
        normalized = os.path.normpath(path)
        if normalized == os.path.normpath(str(pack)):
            return "<PACK_SOURCE>"
        if pack_workspace_root is not None:
            pack_root = os.path.normpath(pack_workspace_root)
            if normalized == pack_root:
                return "<PACK_WORKSPACE>"
            if normalized.startswith(pack_root + os.sep):
                return "<PACK_WORKSPACE>/" + os.path.relpath(
                    normalized, pack_root
                ).replace(os.sep, "/")
        if repo_copy_root is not None:
            copy_root = os.path.normpath(repo_copy_root)
            if normalized == copy_root:
                return "<REPO_COPY>"
            if normalized.startswith(copy_root + os.sep):
                return "<REPO_COPY>/" + os.path.relpath(
                    normalized, copy_root
                ).replace(os.sep, "/")
        if candidate_workspace_root is not None:
            candidate_root = os.path.normpath(candidate_workspace_root)
            if normalized == candidate_root:
                return "<CANDIDATE_WORKSPACE>"
            if normalized.startswith(candidate_root + os.sep):
                return "<CANDIDATE_WORKSPACE>/" + os.path.relpath(
                    normalized, candidate_root
                ).replace(os.sep, "/")
        return path

    def recording_lexists(path: str) -> bool:
        exists = original_lexists(path)
        normalized = os.path.normpath(path)
        if (
            normalized == os.path.normpath(str(pack))
            or normalized.endswith(os.path.normpath("evoguard_verifier_pack"))
        ):
            events.append(
                {
                    "exists": str(exists).lower(),
                    "op": "lexists",
                    "path": token(path),
                }
            )
        return exists

    def recording_mkdtemp(*, prefix: str) -> str:
        nonlocal candidate_workspace_root, pack_workspace_root, repo_copy_root
        path = original_mkdtemp(prefix=prefix)
        if prefix == "evo_repo_":
            candidate_workspace_root = path
            repo_copy_root = os.path.join(path, "repo")
        elif prefix == "evo_pack_snapshot_":
            pack_workspace_root = path
        events.append({"op": "mkdtemp", "prefix": prefix})
        return path

    def controlled_snapshot(source_path: str, destination: str):
        events.append(
            {
                "destination": token(destination),
                "op": "snapshot-pack",
                "source": token(source_path),
            }
        )
        if case_name == "invalid_pack_snapshot":
            raise PackManifestError("controlled invalid verifier pack")
        digest = (
            _EXPECTED_DIGEST
            if case_name == "valid_identity_sticky_evidence"
            else _OBSERVED_DIGEST
        )
        return digest, copy.deepcopy(_MANIFEST)

    def recording_cleanup(workspaces, *, primary):
        events.append(
            {
                "op": "cleanup",
                "primary": "none" if primary is None else type(primary).__name__,
                "workspaces": ",".join(
                    f"{label}={token(path) if path is not None else '<NONE>'}"
                    for label, path in workspaces
                ),
            }
        )
        return original_cleanup(workspaces, primary=primary)

    repo_verifier.os.path.lexists = recording_lexists
    repo_verifier.tempfile.mkdtemp = recording_mkdtemp
    repo_verifier.snapshot_pack = controlled_snapshot
    repo_verifier._cleanup_repo_workspaces = recording_cleanup
    try:
        problem: dict[str, Any] = {"repo_path": str(source)}
        if case_name != "expected_pin_without_pack":
            problem["verifier_pack"] = str(pack)
        if case_name in {
            "digest_mismatch",
            "expected_pin_without_pack",
            "valid_identity_sticky_evidence",
        }:
            problem["expect_verifier_pack_sha256"] = _EXPECTED_DIGEST.upper()
        result = repo_verifier.RepoVerifier(
            isolation="docker",
            mem_limit_mb=0,
            test_command=["unused"],
        ).verify(_APP_EDIT, problem)
    finally:
        repo_verifier.os.path.lexists = original_lexists
        repo_verifier.tempfile.mkdtemp = original_mkdtemp
        repo_verifier.snapshot_pack = original_snapshot_pack
        repo_verifier._cleanup_repo_workspaces = original_cleanup

    return {"events": events, "result": _normalized_result(result)}


def capture_all(workspace: Path) -> dict[str, Any]:
    """Capture all reviewed cases in one versioned envelope."""

    return {
        "cases": {name: capture_case(name, workspace) for name in CASE_NAMES},
        "schema_version": SCHEMA_VERSION,
    }
