"""Deterministic pre-extraction contract for repository candidate handling."""

from __future__ import annotations

import copy
import json
import os
from contextlib import ExitStack
from pathlib import Path
from typing import Any
from unittest.mock import patch

from evoom_guard.contracts import VerdictResult
from evoom_guard.verifiers import repo_verifier

SCHEMA_VERSION = "repo-candidate-phase-v1"
CASE_NAMES = (
    "copy_failure",
    "deletion_failure",
    "deletion_success_after_pack_intake",
    "empty_candidate",
    "lenient_candidate",
    "materialization_failure",
    "protected_deletion",
    "protected_edit",
    "structured_candidate",
    "textual_file_and_patch",
)


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
    """Capture one candidate-admission/materialization/deletion branch."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown repo-candidate case: {case_name}")

    source = workspace / f"source-{case_name}"
    source.mkdir(parents=True)
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (source / "old.py").write_text("OLD = True\n", encoding="utf-8")
    tests = source / "tests"
    tests.mkdir()
    (tests / "test_app.py").write_text(
        "def test_app():\n    assert True\n",
        encoding="utf-8",
    )

    events: list[dict[str, Any]] = []
    candidate_workspace: str | None = None
    candidate_copy: str | None = None

    original_isdir = repo_verifier.os.path.isdir
    original_mkdtemp = repo_verifier.tempfile.mkdtemp
    original_copy = repo_verifier.copy_repo_tree
    original_apply = repo_verifier.apply_blocks_to_copy
    original_intake = repo_verifier.intake_repo_pack
    original_delete = repo_verifier.delete_path_within_root
    original_cleanup = repo_verifier._cleanup_repo_workspaces

    def token(path: str | None) -> str:
        if path is None:
            return "<NONE>"
        normalized = os.path.normpath(path)
        source_root = os.path.normpath(str(source))
        if normalized == source_root:
            return "<SOURCE>"
        if candidate_copy is not None:
            copy_root = os.path.normpath(candidate_copy)
            if normalized == copy_root:
                return "<REPO_COPY>"
            if normalized.startswith(copy_root + os.sep):
                return "<REPO_COPY>/" + os.path.relpath(
                    normalized, copy_root
                ).replace(os.sep, "/")
        if candidate_workspace is not None:
            work_root = os.path.normpath(candidate_workspace)
            if normalized == work_root:
                return "<CANDIDATE_WORKSPACE>"
            if normalized.startswith(work_root + os.sep):
                return "<CANDIDATE_WORKSPACE>/" + os.path.relpath(
                    normalized, work_root
                ).replace(os.sep, "/")
        return path

    def recording_isdir(path: str) -> bool:
        outcome = original_isdir(path)
        if os.path.normpath(path) == os.path.normpath(str(source)):
            events.append(
                {"op": "isdir", "path": token(path), "result": outcome}
            )
        return outcome

    def recording_mkdtemp(*, prefix: str) -> str:
        nonlocal candidate_workspace, candidate_copy
        path = original_mkdtemp(prefix=prefix)
        if prefix == "evo_repo_":
            candidate_workspace = path
            candidate_copy = os.path.join(path, "repo")
        events.append({"op": "mkdtemp", "prefix": prefix})
        return path

    def recording_copy(src: str, dst: str) -> None:
        events.append({"dst": token(dst), "op": "copy", "src": token(src)})
        if case_name == "copy_failure":
            raise RuntimeError("controlled copy failure")
        original_copy(src, dst)

    def recording_apply(
        root: str,
        file_blocks: dict[str, str],
        patch_blocks: list[repo_verifier.PatchBlock],
    ) -> str | None:
        events.append(
            {
                "files": dict(file_blocks),
                "op": "materialize",
                "patches": [
                    {
                        "path": block.path,
                        "replace": block.replace,
                        "search": block.search,
                    }
                    for block in patch_blocks
                ],
                "root": token(root),
            }
        )
        if case_name in {
            "lenient_candidate",
            "materialization_failure",
            "structured_candidate",
            "textual_file_and_patch",
        }:
            return "controlled materialization failure"
        return original_apply(root, file_blocks, patch_blocks)

    def recording_intake(request, *, services):
        events.append(
            {
                "files_changed": list(request.files_changed),
                "op": "pack-intake",
            }
        )
        return original_intake(request, services=services)

    def recording_delete(root: str, relative: str) -> bool:
        events.append(
            {"op": "delete", "path": relative, "root": token(root)}
        )
        if case_name == "deletion_failure":
            raise repo_verifier.UnsafeWorkspacePath(
                "controlled unsafe deletion"
            )
        return original_delete(root, relative)

    def recording_cleanup(workspaces, *, primary):
        events.append(
            {
                "op": "cleanup",
                "primary": "none" if primary is None else type(primary).__name__,
                "workspaces": [
                    [label, token(path)] for label, path in workspaces
                ],
            }
        )
        return original_cleanup(workspaces, primary=primary)

    hypothesis = "plain prose"
    problem: dict[str, Any] = {"repo_path": str(source)}
    if case_name == "empty_candidate":
        pass
    elif case_name == "structured_candidate":
        problem["file_blocks"] = {
            "app.py": "literal <<<END FILE>>> remains content\n"
        }
        hypothesis = (
            "<<<FILE: ignored.py>>>\nWRONG = True\n<<<END FILE>>>\n"
        )
    elif case_name == "textual_file_and_patch":
        hypothesis = (
            "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n"
            "<<<PATCH: old.py>>>\n<<<SEARCH>>>\nTrue\n"
            "<<<REPLACE>>>\nFalse\n<<<END PATCH>>>\n"
        )
    elif case_name == "lenient_candidate":
        problem["target_files"] = ["app.py"]
        hypothesis = "<<FILE: app.py>>\nVALUE = 3\n<<END FILE>>\n"
    elif case_name == "protected_edit":
        hypothesis = (
            "<<<FILE: tests/test_app.py>>>\n"
            "def test_app():\n    assert False\n"
            "<<<END FILE>>>\n"
        )
    elif case_name == "protected_deletion":
        problem["deleted"] = ["tests/test_app.py"]
        hypothesis = "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n"
    elif case_name in {
        "deletion_failure",
        "deletion_success_after_pack_intake",
    }:
        problem["deleted"] = ["old.py"]
        hypothesis = "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n"
    else:
        hypothesis = "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n"

    result: VerdictResult | None = None
    error: dict[str, str] | None = None
    with ExitStack() as stack:
        stack.enter_context(patch.object(repo_verifier.os.path, "isdir", recording_isdir))
        stack.enter_context(
            patch.object(repo_verifier.tempfile, "mkdtemp", recording_mkdtemp)
        )
        stack.enter_context(patch.object(repo_verifier, "copy_repo_tree", recording_copy))
        stack.enter_context(
            patch.object(repo_verifier, "apply_blocks_to_copy", recording_apply)
        )
        stack.enter_context(patch.object(repo_verifier, "intake_repo_pack", recording_intake))
        stack.enter_context(
            patch.object(repo_verifier, "delete_path_within_root", recording_delete)
        )
        stack.enter_context(
            patch.object(repo_verifier, "_cleanup_repo_workspaces", recording_cleanup)
        )
        try:
            result = repo_verifier.RepoVerifier(
                isolation="docker",
                mem_limit_mb=0,
                test_command=["unused"],
            ).verify(hypothesis, problem)
        except BaseException as exc:
            error = {"message": str(exc), "type": type(exc).__name__}

    return {
        "error": error,
        "events": events,
        "result": None if result is None else _normalized_result(result),
    }


def capture_all(workspace: Path) -> dict[str, Any]:
    """Capture all reviewed cases in one versioned envelope."""

    return {
        "cases": {name: capture_case(name, workspace) for name in CASE_NAMES},
        "schema_version": SCHEMA_VERSION,
    }
