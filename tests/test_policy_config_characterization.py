# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Characterization and reviewed mutation contracts for trusted policy intake."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evoom_guard.policy import config as policy_config


def _write_policy(root: Path, payload: object) -> Path:
    path = root / ".evoguard.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("payload", "first_error"),
    [
        (
            {
                "test_command": 7,
                "protected": "not-a-list",
                "harness_inputs": ["ci/run.py"],
            },
            "invalid 'test_command'",
        ),
        (
            {
                "protected": "not-a-list",
                "harness_inputs": "also-not-a-list",
            },
            "invalid 'protected'",
        ),
    ],
)
def test_command_and_path_error_precedence_is_frozen(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object],
    first_error: str,
) -> None:
    def unexpected_normalization(_values: object) -> tuple[str, ...]:
        raise AssertionError("later harness validation ran before the first error")

    monkeypatch.setattr(
        policy_config,
        "normalize_harness_inputs",
        unexpected_normalization,
    )
    path = _write_policy(tmp_path, payload)

    with pytest.raises(policy_config.ConfigError, match=first_error):
        policy_config.load_config(str(path), required=True)


def test_harness_normalization_failure_precedes_conflict_detection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cause = ValueError("controlled harness normalization failure")

    def fail_normalization(_values: object) -> tuple[str, ...]:
        raise cause

    def unexpected_conflict_check(
        _harness: object,
        _globs: object,
    ) -> tuple[str, ...]:
        raise AssertionError("conflict detection ran after normalization failed")

    monkeypatch.setattr(
        policy_config,
        "normalize_harness_inputs",
        fail_normalization,
    )
    monkeypatch.setattr(
        policy_config,
        "setup_output_harness_conflicts",
        unexpected_conflict_check,
    )
    path = _write_policy(
        tmp_path,
        {
            "setup_output_globs": ["ci/**"],
            "harness_inputs": ["ci/run.py"],
        },
    )

    with pytest.raises(
        policy_config.ConfigError,
        match="controlled harness normalization failure",
    ) as raised:
        policy_config.load_config(str(path), required=True)

    assert raised.value.__cause__ is cause


def test_harness_conflict_remains_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def controlled_conflict(
        harness: list[str],
        globs: list[str],
    ) -> tuple[str, ...]:
        assert harness == ["ci/run.py"]
        assert globs == ["ci/**"]
        return ("ci/run.py",)

    monkeypatch.setattr(
        policy_config,
        "setup_output_harness_conflicts",
        controlled_conflict,
    )
    path = _write_policy(
        tmp_path,
        {
            "setup_output_globs": ["ci/**"],
            "harness_inputs": ["ci/run.py"],
        },
    )

    with pytest.raises(
        policy_config.ConfigError,
        match="cannot exclude harness_inputs: ci/run.py",
    ):
        policy_config.load_config(str(path), required=True)


def test_single_path_policy_skips_cross_policy_conflict_detection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_conflict_check(
        _harness: object,
        _globs: object,
    ) -> tuple[str, ...]:
        raise AssertionError("cross-policy check ran without both policy lists")

    monkeypatch.setattr(
        policy_config,
        "setup_output_harness_conflicts",
        unexpected_conflict_check,
    )
    path = _write_policy(tmp_path, {"protected": ["security/**"]})

    assert policy_config.load_config(str(path), required=True) == {
        "protected": ["security/**"]
    }
