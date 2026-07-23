"""Deterministic characterization of the candidate materialization transaction."""

from __future__ import annotations

import json
from typing import Any

from evoom_guard.candidate import PatchBlock, PatchError
from evoom_guard.candidate import apply_patch as canonical_apply_patch
from evoom_guard.verifiers import repo_verifier
from evoom_guard.workspace import UnsafeWorkspacePath

SCHEMA_VERSION = "repo-materialization-characterization-v1"
CASE_NAMES = (
    "file_then_patch_and_restore",
    "manifest_disappears",
    "missing_patch_target",
    "patch_failure",
    "unsafe_manifest_read",
    "write_failure",
)


def canonical_json(value: Any) -> str:
    """Return the repository's stable human-reviewable vector encoding."""

    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def capture_case(case_name: str) -> dict[str, Any]:
    """Capture one legacy facade result and its exact dependency call order."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown materialization characterization case: {case_name}")

    files: dict[str, str] = {}
    file_blocks: dict[str, str] = {}
    patch_blocks: list[PatchBlock] = []
    if case_name == "file_then_patch_and_restore":
        files = {
            "package.json": "original-package",
            "src/module.py": "before",
        }
        file_blocks = {
            "package.json": "candidate-package",
            "src/new.py": "new",
        }
        patch_blocks = [
            PatchBlock("src/module.py", "before", "after"),
            PatchBlock("package.json", "candidate", "patched"),
        ]
    elif case_name == "manifest_disappears":
        files = {"package.json": "original-package"}
        file_blocks = {"package.json": "candidate-package"}
    elif case_name == "missing_patch_target":
        patch_blocks = [PatchBlock("src/missing.py", "before", "after")]
    elif case_name == "patch_failure":
        files = {"src/module.py": "before"}
        patch_blocks = [PatchBlock("src/module.py", "before", "after")]
    elif case_name == "unsafe_manifest_read":
        files = {"package.json": "original-package"}
        file_blocks = {"package.json": "candidate-package"}
    elif case_name == "write_failure":
        file_blocks = {"src/fail.py": "candidate"}

    events: list[dict[str, str]] = []
    read_counts: dict[str, int] = {}

    def read_text(root: str, relative_path: str) -> str:
        events.append({"op": "read", "path": relative_path, "root": root})
        read_counts[relative_path] = read_counts.get(relative_path, 0) + 1
        if case_name == "unsafe_manifest_read" and relative_path == "package.json":
            raise UnsafeWorkspacePath("controlled unsafe read")
        if (
            case_name == "manifest_disappears"
            and relative_path == "package.json"
            and read_counts[relative_path] > 1
        ):
            raise FileNotFoundError(relative_path)
        try:
            return files[relative_path]
        except KeyError:
            raise FileNotFoundError(relative_path) from None

    def write_text(root: str, relative_path: str, content: str) -> None:
        events.append(
            {
                "content": content,
                "op": "write",
                "path": relative_path,
                "root": root,
            }
        )
        if case_name == "write_failure":
            raise OSError("controlled write failure")
        files[relative_path] = content

    def patcher(source: str, search: str, replace: str) -> str:
        events.append(
            {
                "op": "patch",
                "replace": replace,
                "search": search,
                "source": source,
            }
        )
        if case_name == "patch_failure":
            raise PatchError("controlled patch failure")
        return canonical_apply_patch(source, search, replace)

    def restore_package_json(original: str | None, candidate: str) -> str:
        events.append(
            {
                "candidate": candidate,
                "op": "restore-package",
                "original": "<absent>" if original is None else original,
            }
        )
        return f"{candidate}|judge({original})"

    original_dependencies = (
        repo_verifier.read_text_within_root,
        repo_verifier.write_text_within_root,
        repo_verifier.apply_patch,
        repo_verifier.restore_judge_package_json,
    )
    repo_verifier.read_text_within_root = read_text
    repo_verifier.write_text_within_root = write_text
    repo_verifier.apply_patch = patcher
    repo_verifier.restore_judge_package_json = restore_package_json
    try:
        error = repo_verifier.apply_blocks_to_copy(
            "repo-copy", file_blocks, patch_blocks
        )
    finally:
        (
            repo_verifier.read_text_within_root,
            repo_verifier.write_text_within_root,
            repo_verifier.apply_patch,
            repo_verifier.restore_judge_package_json,
        ) = original_dependencies

    return {
        "error": error,
        "events": events,
        "files": {path: files[path] for path in sorted(files)},
    }


def capture_all() -> dict[str, Any]:
    """Capture every reviewed case under one versioned envelope."""

    return {
        "cases": {name: capture_case(name) for name in CASE_NAMES},
        "schema_version": SCHEMA_VERSION,
    }
