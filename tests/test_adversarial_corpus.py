# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Machine-check the executable Phase 2A adversarial-corpus registry."""

from __future__ import annotations

import ast
import json
from pathlib import Path

ROOT = Path(__file__).parents[1]
CORPUS = ROOT / "adversarial" / "corpus.jsonl"
REQUIRED_FIELDS = {
    "id",
    "boundary",
    "status",
    "observed_on",
    "platform",
    "safe_fixture",
    "current_observation",
    "target_phase",
    "test_nodeid",
}
STATUSES = {"known_gap", "enforced", "documented_exception"}


def _rows() -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in CORPUS.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_adversarial_corpus_has_a_unique_complete_schema() -> None:
    rows = _rows()

    assert len(rows) >= 14
    assert all(set(row) == REQUIRED_FIELDS for row in rows)
    assert len({row["id"] for row in rows}) == len(rows)
    assert len({row["test_nodeid"] for row in rows}) == len(rows)
    assert {row["status"] for row in rows} <= STATUSES
    assert all(row["observed_on"] == "3.4.2" for row in rows)
    assert all(row["safe_fixture"] is True for row in rows)
    assert all(row["current_observation"] for row in rows)


def test_every_registered_nodeid_resolves_to_a_real_test_function() -> None:
    for row in _rows():
        nodeid = str(row["test_nodeid"])
        relative_path, *qualname = nodeid.split("::")
        assert qualname, f"missing test name in {nodeid}"
        path = ROOT / relative_path
        assert path.is_file(), f"missing test file for {nodeid}"
        functions = {
            node.name
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        assert qualname[-1] in functions, f"missing test function for {nodeid}"


def test_phase2_corpus_has_no_unowned_known_gap() -> None:
    rows = _rows()
    known_gaps = [row for row in rows if row["status"] == "known_gap"]

    assert known_gaps == []
