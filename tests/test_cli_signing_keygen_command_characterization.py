"""Frozen equivalence gates for the bounded signing-command extraction."""

from __future__ import annotations

import difflib
import inspect
import json
from pathlib import Path

import pytest

from evoom_guard import cli
from tests.cli_signing_keygen_command_characterization_harness import (
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
    / "cli-signing-keygen-command-v1.json"
)


def _frozen() -> dict[str, object]:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_cli_signing_keygen_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["baseline_commit"] == BASELINE_COMMIT
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_cli_signing_keygen_behavior(case_name: str) -> None:
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
        pytest.fail("CLI keygen command behavior drifted:\n" + diff)


def test_public_keygen_signature_is_frozen() -> None:
    assert str(inspect.signature(cli.cmd_keygen)) == (
        "(args: 'argparse.Namespace', *, "
        "out: 'Callable[[str], None]' = <built-in function print>) -> 'int'"
    )


def test_public_keygen_docstring_is_frozen() -> None:
    assert cli.cmd_keygen.__doc__ == (
        "Execute ``evo-guard keygen`` — generate an Ed25519 signing keypair."
    )
