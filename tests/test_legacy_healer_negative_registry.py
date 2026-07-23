# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available - see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Validate the public, sanitized legacy-healer negative-case registry."""

from __future__ import annotations

import ast
import json
from pathlib import Path

ROOT = Path(__file__).parents[1]
REGISTRY = ROOT / "adversarial" / "legacy-healer-negative-v1.jsonl"
SCHEMA_VERSION = "legacy-healer-negative-v1"
ORIGIN = "sanitized-legacy-healer-audit"
REQUIRED_FIELDS = {
    "schema_version",
    "id",
    "origin",
    "failure_class",
    "status",
    "public_summary",
    "expected_control",
    "test_nodeid",
}
STATUSES = {"enforced", "pending"}
REQUIRED_ENFORCED_CLASSES = {
    "test_tampering",
    "judge_configuration_tampering",
    "source_workspace_mutation",
}
REQUIRED_AGENT_ADMISSION_CLASSES = {
    "proposal_scope_violation",
    "decision_side_effect",
    "claim_evidence_mismatch",
}


def _rows() -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in REGISTRY.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _nodeid_exists(nodeid: str) -> bool:
    relative_path, *qualname = nodeid.split("::")
    if not qualname:
        return False

    path = ROOT / relative_path
    if not path.is_file() or path.suffix != ".py":
        return False

    body: list[ast.stmt] = ast.parse(path.read_text(encoding="utf-8")).body
    for name in qualname:
        match = next(
            (
                node
                for node in body
                if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == name
            ),
            None,
        )
        if match is None:
            return False
        body = match.body
    return True


def test_legacy_healer_negative_registry_has_a_unique_public_schema() -> None:
    rows = _rows()

    assert len(rows) >= 10
    assert all(set(row) == REQUIRED_FIELDS for row in rows)
    assert all(row["schema_version"] == SCHEMA_VERSION for row in rows)
    assert all(row["origin"] == ORIGIN for row in rows)
    assert {row["status"] for row in rows} <= STATUSES
    assert len({row["id"] for row in rows}) == len(rows)
    assert all(str(row["id"]).startswith("legacy-") for row in rows)
    assert all(row["public_summary"] for row in rows)
    assert all(row["expected_control"] for row in rows)

    # The public registry contains generalized failure classes only. Provenance,
    # payloads, repositories, private paths, and commit identifiers belong in the
    # private corpus and are deliberately excluded from this exact schema.
    forbidden_fields = {
        "commit",
        "commit_sha",
        "repository",
        "source_path",
        "patch",
        "payload",
        "credential",
    }
    assert all(forbidden_fields.isdisjoint(row) for row in rows)


def test_every_enforced_case_resolves_to_a_real_unique_test_nodeid() -> None:
    enforced = [row for row in _rows() if row["status"] == "enforced"]
    nodeids = [row["test_nodeid"] for row in enforced]

    assert REQUIRED_ENFORCED_CLASSES <= {row["failure_class"] for row in enforced}
    assert all(isinstance(nodeid, str) and nodeid for nodeid in nodeids)
    assert len(set(nodeids)) == len(nodeids)
    assert all(_nodeid_exists(str(nodeid)) for nodeid in nodeids)


def test_agent_admission_cases_are_executable_and_no_gap_remains() -> None:
    rows = _rows()
    agent_cases = [
        row
        for row in rows
        if row["failure_class"] in REQUIRED_AGENT_ADMISSION_CLASSES
    ]

    assert {row["failure_class"] for row in agent_cases} == REQUIRED_AGENT_ADMISSION_CLASSES
    assert all(row["status"] == "enforced" for row in agent_cases)
    assert all(_nodeid_exists(str(row["test_nodeid"])) for row in agent_cases)
    assert not [row for row in rows if row["status"] == "pending"]
