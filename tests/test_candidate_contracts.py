# ------------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# ------------------------------------------------------------------------------
"""Compatibility and dependency contracts for the candidate domain."""

from __future__ import annotations

import base64
import pickle
import subprocess
import sys
from pathlib import Path

import evoom_guard.blackbox as blackbox
import evoom_guard.candidate as candidate
import evoom_guard.candidate.edits as edits
import evoom_guard.candidate.patch as patch
import evoom_guard.evidence as evidence
import evoom_guard.guard as guard_module
import evoom_guard.patch_applier as legacy_patch
import evoom_guard.verifiers.candidate_edits as legacy_edits
import evoom_guard.verifiers.repo_verifier as repo_verifier

ROOT = Path(__file__).resolve().parents[1]

CANDIDATE_EXPORTS = (
    "AmbiguousMatchError",
    "NoMatchError",
    "PatchBlock",
    "PatchError",
    "apply_patch",
    "parse_blocks_lenient",
    "parse_file_blocks",
    "parse_patch_blocks",
)


def test_candidate_surface_is_explicit() -> None:
    assert tuple(candidate.__all__) == CANDIDATE_EXPORTS


def test_candidate_contracts_keep_exact_legacy_and_consumer_aliases() -> None:
    edit_consumers = (legacy_edits, repo_verifier)
    for name in (
        "PatchBlock",
        "parse_blocks_lenient",
        "parse_file_blocks",
        "parse_patch_blocks",
    ):
        canonical = getattr(candidate, name)
        assert canonical is getattr(edits, name)
        for consumer in edit_consumers:
            assert canonical is getattr(consumer, name)

    for consumer in (legacy_patch, repo_verifier, evidence):
        assert candidate.PatchError is consumer.PatchError
        assert candidate.apply_patch is consumer.apply_patch

    for name in (
        "AmbiguousMatchError",
        "NoMatchError",
        "PatchError",
        "apply_patch",
    ):
        assert getattr(candidate, name) is getattr(patch, name)

    assert candidate.AmbiguousMatchError is legacy_patch.AmbiguousMatchError
    assert candidate.NoMatchError is legacy_patch.NoMatchError
    assert candidate.parse_file_blocks is guard_module.parse_file_blocks
    assert candidate.parse_patch_blocks is guard_module.parse_patch_blocks
    assert candidate.parse_file_blocks is blackbox.parse_file_blocks
    assert candidate.parse_patch_blocks is blackbox.parse_patch_blocks
    assert candidate.parse_file_blocks is evidence.parse_file_blocks
    assert candidate.parse_patch_blocks is evidence.parse_patch_blocks


def test_private_parser_objects_keep_exact_compatibility_aliases() -> None:
    for name in (
        "_BLOCK_RE",
        "_LENIENT_FILE_RE",
        "_LENIENT_PATCH_RE",
        "_PATCH_BLOCK_RE",
    ):
        canonical = getattr(edits, name)
        assert canonical is getattr(legacy_edits, name)
        assert canonical is getattr(repo_verifier, name)


def test_legacy_module_surfaces_remain_frozen() -> None:
    legacy_edit_public = {
        name for name in dir(legacy_edits) if not name.startswith("_")
    }
    assert legacy_edit_public == {
        "NamedTuple",
        "PatchBlock",
        "annotations",
        "parse_blocks_lenient",
        "parse_file_blocks",
        "parse_patch_blocks",
        "re",
    }

    legacy_patch_public = {
        name for name in dir(legacy_patch) if not name.startswith("_")
    }
    assert legacy_patch_public == {
        "AmbiguousMatchError",
        "NoMatchError",
        "PatchError",
        "apply_patch",
    }


def test_historical_pickles_resolve_through_legacy_facades() -> None:
    patch_block_bytes = base64.b64decode(
        "Y2NvcHlfcmVnCl9yZWNvbnN0cnVjdG9yCnAwCihjZXZvb21fZ3VhcmQudmVyaWZp"
        "ZXJzLmNhbmRpZGF0ZV9lZGl0cwpQYXRjaEJsb2NrCnAxCmNfX2J1aWx0aW5fXwp0"
        "dXBsZQpwMgooVmEucHkKcDMKVm9sZApwNApWbmV3CnA1CnRwNgp0cDcKUnA4Ci4="
    )
    patch_error_bytes = base64.b64decode(
        "Y2V2b29tX2d1YXJkLnBhdGNoX2FwcGxpZXIKUGF0Y2hFcnJvcgpwMAooVmhpc3Rv"
        "cmljYWwKcDEKdHAyClJwMwou"
    )

    assert pickle.loads(patch_block_bytes) == candidate.PatchBlock(
        "a.py", "old", "new"
    )
    restored_error = pickle.loads(patch_error_bytes)
    assert type(restored_error) is candidate.PatchError
    assert restored_error.args == ("historical",)


def test_candidate_import_does_not_initialize_higher_layers() -> None:
    code = """
import sys
sys.path.insert(0, sys.argv[1])
import evoom_guard.candidate

forbidden = (
    "evoom_guard.guard",
    "evoom_guard.verifiers",
    "evoom_guard.evidence",
    "evoom_guard.execution",
    "evoom_guard.isolation",
)
loaded = sorted(
    name
    for name in sys.modules
    if any(name == root or name.startswith(root + ".") for root in forbidden)
)
assert loaded == [], loaded
"""
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code, str(ROOT)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr


def test_materialization_retains_dynamic_patch_seam(
    monkeypatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "module.py"
    target.write_text("before\n", encoding="utf-8")
    seen: list[tuple[str, str, str]] = []

    def fake_apply(source: str, search: str, replace: str) -> str:
        seen.append((source, search, replace))
        return "after\n"

    monkeypatch.setattr(repo_verifier, "apply_patch", fake_apply)
    error = repo_verifier.apply_blocks_to_copy(
        str(tmp_path),
        {},
        [candidate.PatchBlock("module.py", "before", "after")],
    )

    assert error is None
    assert seen == [("before\n", "before", "after")]
    assert target.read_text(encoding="utf-8") == "after\n"
