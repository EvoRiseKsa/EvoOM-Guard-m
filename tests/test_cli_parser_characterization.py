"""Frozen parser characterization for the bounded parser-owner extraction."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from evoom_guard import cli
from tests.cli_parser_characterization_harness import snapshot

FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "cli_parser_characterization_v1.json"
)


def test_cli_parser_matches_frozen_characterization() -> None:
    expected = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert snapshot() == expected


def test_cli_parser_resolves_dependencies_at_their_original_call_sites(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An early parser helper may replace every dependency used later."""

    nested_calls: list[str] = []
    release_calls: list[str] = []
    policy_calls: list[str] = []
    verifier_calls: list[str] = []
    ref_calls: list[str] = []
    original_nested = cli._add_nested_release_source_expectation_arguments
    original_release = cli._add_release_artifact_key_registry_arguments
    original_policy = cli._add_github_attestation_policy_arguments
    original_verifier = cli._add_github_attestation_verifier_arguments
    original_ref = cli._immutable_release_ref

    def late_nested(parser: argparse.ArgumentParser) -> None:
        nested_calls.append("late")
        original_nested(parser)

    def late_release(parser: argparse.ArgumentParser) -> None:
        release_calls.append("late")
        original_release(parser)

    def late_policy(parser: argparse.ArgumentParser) -> None:
        policy_calls.append("late")
        original_policy(parser)

    def late_verifier(parser: argparse.ArgumentParser) -> None:
        verifier_calls.append("late")
        original_verifier(parser)

    def late_ref(value: object) -> str:
        ref_calls.append(str(value))
        return original_ref(value)

    def early_nested(parser: argparse.ArgumentParser) -> None:
        nested_calls.append("early")
        monkeypatch.setattr(
            cli, "_add_nested_release_source_expectation_arguments", late_nested
        )
        monkeypatch.setattr(
            cli, "_add_release_artifact_key_registry_arguments", late_release
        )
        monkeypatch.setattr(
            cli, "_add_github_attestation_policy_arguments", late_policy
        )
        monkeypatch.setattr(
            cli, "_add_github_attestation_verifier_arguments", late_verifier
        )
        monkeypatch.setattr(cli, "_immutable_release_ref", late_ref)
        original_nested(parser)

    monkeypatch.setattr(
        cli, "_add_nested_release_source_expectation_arguments", early_nested
    )
    parser = cli.build_parser()

    # The original parser captured this converter while constructing the
    # ``init --ref`` action; a later global reset must not change that action.
    monkeypatch.setattr(cli, "_immutable_release_ref", original_ref)
    parsed = parser.parse_args(["init", "--ref", "v4.3.0"])

    assert nested_calls == ["early", "late"]
    assert release_calls == ["late", "late"]
    assert policy_calls == ["late"] * 5
    assert verifier_calls == ["late"] * 3
    assert ref_calls == ["v4.3.0"]
    assert parsed.ref == "v4.3.0"
