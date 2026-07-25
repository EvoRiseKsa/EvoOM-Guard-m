"""Frozen equivalence gate for the pending GitHub receipt command owner."""

from __future__ import annotations

import difflib
import inspect
import json
from pathlib import Path

import pytest

from evoom_guard import cli
from tests.cli_github_attestation_receipt_characterization_harness import (
    _OFFLINE_ALLOWED,
    BASELINE_COMMIT,
    CASE_NAMES,
    SCHEMA_VERSION,
    _args,
    _ForbiddenEnvironment,
    canonical_json,
    capture_case,
)

VECTOR = (
    Path(__file__).parent
    / "fixtures"
    / "refactor-safety"
    / "cli-github-attestation-receipt.json"
)


def _frozen() -> dict[str, object]:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_cli_github_attestation_receipt_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["baseline_commit"] == BASELINE_COMMIT
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))


@pytest.mark.parametrize("probe", ("unknown-attribute", "vars"))
def test_offline_receipt_namespace_is_a_closed_world(probe: str) -> None:
    events: list[str] = []
    args = _args("verify", events)
    args._strict_allowed = _OFFLINE_ALLOWED

    with pytest.raises(AssertionError, match="unexpected argument attribute"):
        if probe == "unknown-attribute":
            getattr(args, "telemetry_endpoint", None)
        else:
            vars(args)
    assert events == [
        (
            "boundary-violated:telemetry_endpoint"
            if probe == "unknown-attribute"
            else "boundary-violated:__dict__"
        )
    ]


@pytest.mark.parametrize("probe", ("get", "getitem", "contains", "iter", "copy"))
def test_environment_guard_is_fail_closed(probe: str) -> None:
    events: list[str] = []
    environment = _ForbiddenEnvironment(events)

    with pytest.raises(AssertionError, match="read ambient environment"):
        if probe == "get":
            environment.get("GH_TOKEN")
        elif probe == "getitem":
            environment["GH_TOKEN"]
        elif probe == "contains":
            environment.__contains__("GH_TOKEN")
        elif probe == "iter":
            iter(environment)
        else:
            environment.copy()
    assert events and events[0].startswith("environment-boundary-violated:")


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_cli_github_attestation_receipt_behavior(
    case_name: str,
) -> None:
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
        pytest.fail("GitHub attestation receipt CLI behavior drifted:\n" + diff)


@pytest.mark.parametrize(
    ("command_name", "docstring"),
    (
        (
            "cmd_github_attestation_receipt",
            "Run the narrow provider verifier and retain its exact bounded evidence.",
        ),
        (
            "cmd_verify_github_attestation_receipt",
            "Check retained evidence continuity without making a live provider call.",
        ),
        (
            "cmd_reverify_github_attestation_receipt",
            "Make a fresh constrained GitHub CLI verification for a retained receipt.",
        ),
    ),
)
def test_public_github_attestation_receipt_facades_are_frozen(
    command_name: str,
    docstring: str,
) -> None:
    command = getattr(cli, command_name)
    assert str(inspect.signature(command)) == (
        "(args: 'argparse.Namespace', *, "
        "out: 'Callable[[str], None]' = <built-in function print>) -> 'int'"
    )
    assert command.__doc__ == docstring
