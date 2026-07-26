# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Machine-check the executable Phase 2A adversarial-corpus registry."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

import tools.evaluation.run_adversarial_corpus as corpus_runner

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
    assert all(
        isinstance(row["observed_on"], str) and row["observed_on"]
        for row in rows
    )
    assert all(row["safe_fixture"] is True for row in rows)
    assert all(row["current_observation"] for row in rows)


def test_every_registered_nodeid_resolves_to_a_real_test_function() -> None:
    for row in _rows():
        nodeid = str(row["test_nodeid"])
        relative_path, *qualname = nodeid.split("::")
        assert qualname, f"missing test name in {nodeid}"
        path = ROOT / relative_path
        assert path.is_file(), f"missing test file for {nodeid}"
        body = ast.parse(path.read_text(encoding="utf-8")).body
        resolved: ast.AST | None = None
        for part in qualname:
            matches = [
                node
                for node in body
                if isinstance(
                    node,
                    (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
                )
                and node.name == part
            ]
            assert len(matches) == 1, f"invalid exact test nodeid {nodeid}"
            resolved = matches[0]
            body = resolved.body if isinstance(resolved, ast.ClassDef) else []
        assert isinstance(
            resolved, (ast.FunctionDef, ast.AsyncFunctionDef)
        ), f"nodeid does not end at a test function: {nodeid}"


def test_every_known_gap_has_an_owned_target_phase() -> None:
    rows = _rows()
    known_gaps = [row for row in rows if row["status"] == "known_gap"]

    assert known_gaps, "a zero-gap registry would contradict the documented default boundary"
    assert all(
        isinstance(row["target_phase"], str) and row["target_phase"]
        for row in known_gaps
    )


def test_dynamic_runner_selects_every_registry_nodeid_including_known_gaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = tuple(str(row["test_nodeid"]) for row in _rows())
    observed: dict[str, object] = {}

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        observed["kwargs"] = kwargs
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(corpus_runner.subprocess, "run", fake_run)

    assert corpus_runner.run_registered_corpus() == 0
    command = observed["command"]
    kwargs = observed["kwargs"]
    assert isinstance(command, list)
    assert isinstance(kwargs, dict)
    assert command[:9] == [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "--color=no",
        "-p",
        "no:cacheprovider",
        "-o",
        "addopts=",
    ]
    assert tuple(command[9:]) == expected
    known_gap_nodeids = {
        str(row["test_nodeid"])
        for row in _rows()
        if row["status"] == "known_gap"
    }
    assert known_gap_nodeids
    assert known_gap_nodeids <= set(command[9:])
    environment = kwargs["env"]
    assert isinstance(environment, dict)
    assert environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert "PYTEST_ADDOPTS" not in environment


def test_dynamic_runner_rejects_ambiguous_registry_json(tmp_path: Path) -> None:
    registry = tmp_path / "corpus.jsonl"
    registry.write_text(
        '{"test_nodeid":"tests/test_x.py::test_x",'
        '"test_nodeid":"tests/test_y.py::test_y"}\n',
        encoding="utf-8",
    )

    with pytest.raises(corpus_runner.CorpusRegistryError, match="duplicate JSON key"):
        corpus_runner.registered_nodeids(registry)
