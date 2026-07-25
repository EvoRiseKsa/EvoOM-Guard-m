"""Frozen equivalence gate for the pending Release Source Finalizer owner."""

from __future__ import annotations

import difflib
import inspect
import json
from pathlib import Path

import pytest

from evoom_guard import cli
from tests.cli_release_source_finalizer_characterization_harness import (
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
    / "cli-release-source-finalizer.json"
)


def _frozen() -> dict[str, object]:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_cli_release_source_finalizer_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["baseline_commit"] == BASELINE_COMMIT
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_cli_release_source_finalizer_behavior(case_name: str) -> None:
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
        pytest.fail("Release Source Finalizer CLI behavior drifted:\n" + diff)


@pytest.mark.parametrize(
    ("command_name", "docstring"),
    (
        (
            "cmd_release_source_handoff",
            "Write an unsigned handoff for the separate protected-main contract.",
        ),
        (
            "cmd_seal_release_source_finalizer",
            "Seal a protected-main handoff only after external source matching.",
        ),
        (
            "cmd_verify_release_source_finalized",
            "Verify a separate release-source envelope and external bindings.",
        ),
        (
            "cmd_derive_release_source_controls",
            "Re-derive source/context from raw Git without making an admission claim.",
        ),
    ),
)
def test_public_release_source_finalizer_facades_are_frozen(
    command_name: str,
    docstring: str,
) -> None:
    command = getattr(cli, command_name)
    assert str(inspect.signature(command)) == (
        "(args: 'argparse.Namespace', *, "
        "out: 'Callable[[str], None]' = <built-in function print>) -> 'int'"
    )
    assert command.__doc__ == docstring


def test_release_source_finalizer_success_cases_have_no_provider_or_network_seam() -> None:
    command_sources = "\n".join(
        inspect.getsource(getattr(cli, command_name))
        for command_name in (
            "cmd_release_source_handoff",
            "cmd_seal_release_source_finalizer",
            "cmd_verify_release_source_finalized",
            "cmd_derive_release_source_controls",
        )
    ).lower()
    assert "github" not in command_sources
    assert "subprocess" not in command_sources
    assert "socket" not in command_sources
    for case_name in (
        "handoff_success_boundary",
        "seal_success_allow_boundary",
        "verify_success_allow_boundary",
        "derive_success_boundary",
    ):
        frozen = _frozen()["cases"][case_name]
        assert frozen["exception"] is None
        assert frozen["exit_code"] == 0
