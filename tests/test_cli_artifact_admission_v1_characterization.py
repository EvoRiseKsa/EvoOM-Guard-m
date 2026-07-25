"""Frozen equivalence gate for the pending Artifact Admission V1 CLI owner."""

from __future__ import annotations

import difflib
import inspect
import json
from pathlib import Path

import pytest

from evoom_guard import cli
from tests.cli_artifact_admission_v1_characterization_harness import (
    BASELINE_COMMIT,
    CASE_NAMES,
    SCHEMA_VERSION,
    canonical_json,
    capture_case,
)

VECTOR = (
    Path(__file__).parent
    / "fixtures"
    / "refactor-safety"
    / "cli-artifact-admission-v1.json"
)


def _frozen() -> dict[str, object]:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_cli_artifact_admission_v1_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["baseline_commit"] == BASELINE_COMMIT
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_cli_artifact_admission_v1_behavior(case_name: str) -> None:
    expected = _frozen()["cases"][case_name]
    actual = capture_case(case_name)
    if actual != expected:
        diff = "".join(
            difflib.unified_diff(
                canonical_json(expected).splitlines(keepends=True),
                canonical_json(actual).splitlines(keepends=True),
                fromfile=f"frozen/{case_name}",
                tofile=f"current/{case_name}",
            )
        )
        pytest.fail("Artifact Admission V1 CLI behavior drifted:\n" + diff)


@pytest.mark.parametrize(
    ("command_name", "docstring"),
    (
        (
            "cmd_seal_artifact_admission",
            "Seal one file only after an external Trusted Finalizer ALLOW.",
        ),
        (
            "cmd_verify_artifact_admission",
            "Verify a file binding with external artifact/finalizer trust inputs.",
        ),
    ),
)
def test_public_artifact_admission_v1_facades_are_frozen(
    command_name: str,
    docstring: str,
) -> None:
    command = getattr(cli, command_name)
    assert str(inspect.signature(command)) == (
        "(args: 'argparse.Namespace', *, "
        "out: 'Callable[[str], None]' = <built-in function print>) -> 'int'"
    )
    assert command.__doc__ == docstring
