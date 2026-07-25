"""Frozen equivalence gate for the pending Artifact Digest Admission V2 owner."""

from __future__ import annotations

import difflib
import inspect
import json
from pathlib import Path

import pytest

from evoom_guard import cli
from tests.cli_artifact_digest_v2_characterization_harness import (
    BASELINE_COMMIT,
    CASE_NAMES,
    SCHEMA_VERSION,
    _verify_args,
    canonical_json,
    capture_case,
)

VECTOR = (
    Path(__file__).parent
    / "fixtures"
    / "refactor-safety"
    / "cli-artifact-digest-v2.json"
)


def _frozen() -> dict[str, object]:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_cli_artifact_digest_v2_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["baseline_commit"] == BASELINE_COMMIT
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))


@pytest.mark.parametrize("probe", ("unknown-attribute", "vars"))
def test_offline_namespace_is_a_closed_world(probe: str) -> None:
    events: list[str] = []
    args = _verify_args(events)
    args._strict_allowed = frozenset({"binding"})

    with pytest.raises(AssertionError, match="unexpected argument attribute"):
        if probe == "unknown-attribute":
            getattr(args, "telemetry_endpoint", None)
        else:
            vars(args)
    assert events == [
        (
            "offline-boundary-violated:telemetry_endpoint"
            if probe == "unknown-attribute"
            else "offline-boundary-violated:__dict__"
        )
    ]


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_cli_artifact_digest_v2_behavior(case_name: str) -> None:
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
        pytest.fail("Artifact Digest Admission V2 CLI behavior drifted:\n" + diff)


@pytest.mark.parametrize(
    ("command_name", "docstring"),
    (
        (
            "cmd_seal_artifact_digest_admission",
            "Seal one immutable digest after an external Trusted Finalizer ALLOW.",
        ),
        (
            "cmd_verify_artifact_digest_admission",
            "Verify V2 with external subject, provenance, and finalizer inputs.",
        ),
    ),
)
def test_public_artifact_digest_v2_facades_are_frozen(
    command_name: str,
    docstring: str,
) -> None:
    command = getattr(cli, command_name)
    assert str(inspect.signature(command)) == (
        "(args: 'argparse.Namespace', *, "
        "out: 'Callable[[str], None]' = <built-in function print>) -> 'int'"
    )
    assert command.__doc__ == docstring
