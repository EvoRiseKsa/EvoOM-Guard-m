"""Frozen repository result/sticky evidence projection contract."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from repo_result_characterization_harness import (
    CASE_NAMES,
    SCHEMA_VERSION,
    canonical_json,
    capture_case,
)

VECTOR = (
    Path(__file__).parent
    / "fixtures"
    / "refactor-safety"
    / "repo-result-projection-v1.json"
)


def _frozen() -> dict[str, object]:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_repo_result_projection_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == CASE_NAMES  # type: ignore[arg-type]


def test_pack_snapshot_identity_is_normalized_only_after_facade_capture(
    tmp_path: Path,
) -> None:
    captured = capture_case("pack_completed", tmp_path)

    assert captured["artifact"]["verifier_pack_sha256"] == "<PACK_SHA256>"
    assert (
        captured["artifact"]["runtime_tree_sha256"]
        == "<RUNTIME_TREE_SHA256>"
    )
    assert captured["artifact"]["repo_suite_junit_sha256"] != "<PACK_SHA256>"
    assert captured["artifact"]["verifier_pack_junit_sha256"] != "<PACK_SHA256>"


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_repo_result_projection(
    case_name: str,
    tmp_path: Path,
) -> None:
    frozen = _frozen()
    expected = frozen["cases"][case_name]["sha256"]  # type: ignore[index]
    observed = hashlib.sha256(
        canonical_json(capture_case(case_name, tmp_path)).encode("utf-8")
    ).hexdigest()
    assert observed == expected
