"""Frozen black-box pack execution, interpretation, and adapter semantics."""

from __future__ import annotations

import difflib
import json
from pathlib import Path

import pytest
from blackbox_pack_characterization_harness import (
    CASE_NAMES,
    NORMALIZED_FIELDS,
    SCHEMA_VERSION,
    canonical_json,
    capture_all,
    capture_case,
    capture_live_lookup,
)

FIXTURE = Path(__file__).parent / "fixtures" / "refactor-safety" / "blackbox-pack-phase-v1.json"


def _frozen() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _assert_exact(expected: object, actual: object, label: str) -> None:
    if actual == expected:
        return
    diff = "".join(
        difflib.unified_diff(
            canonical_json({"value": expected}).splitlines(keepends=True),
            canonical_json({"value": actual}).splitlines(keepends=True),
            fromfile=f"frozen/{label}",
            tofile=f"current/{label}",
        )
    )
    pytest.fail(f"black-box pack characterization drifted for {label}:\n{diff}")


def test_blackbox_pack_characterization_manifest_is_frozen() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert frozen["normalization"] == list(NORMALIZED_FIELDS)
    assert tuple(frozen["cases"]) == tuple(CASE_NAMES)


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_blackbox_pack_branch_order_identity_and_errors_are_frozen(
    case_name: str,
    tmp_path: Path,
) -> None:
    _assert_exact(
        _frozen()["cases"][case_name],
        capture_case(case_name, tmp_path / case_name),
        case_name,
    )


def test_blackbox_pack_facade_providers_are_resolved_live(
    tmp_path: Path,
) -> None:
    _assert_exact(
        _frozen()["live_lookup"],
        capture_live_lookup(tmp_path / "live-lookup"),
        "live_lookup",
    )


def test_blackbox_pack_full_capture_is_reproducible(tmp_path: Path) -> None:
    _assert_exact(_frozen(), capture_all(tmp_path / "all"), "all")
