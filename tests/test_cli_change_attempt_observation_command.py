# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""CLI contract tests for advisory change-attempt observation projection."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from evoom_guard import cli
from evoom_guard.cli import (
    change_attempt_observation_commands as command_owner,
)
from tests.test_change_attempt_observation import CASES, _signed_attempt_fixture

_DIGEST = "a" * 64
_KEY_ID = "sha256:" + ("b" * 64)


class _InvalidObservation(ValueError):
    pass


class _OperationalFailure(RuntimeError):
    pass


def _args() -> argparse.Namespace:
    return argparse.Namespace(
        finalizer_bundle="finalized.evb",
        trusted_pub="finalizer.pub",
        expected_source="expected-source.json",
        expected_context="expected-context.json",
        out="attempt-observation.json",
        force=False,
    )


def _verified(decision: str, verdict: str) -> SimpleNamespace:
    return SimpleNamespace(
        observation_sha256="c" * 64,
        inspection=SimpleNamespace(
            payload={
                "authority": {
                    "mode": "ADVISORY_ONLY",
                    "external_action": False,
                },
                "outcome": {
                    "decision": decision,
                    "verdict": verdict,
                },
                "signed_evidence": {
                    "bundle_sha256": _DIGEST,
                    "finalizer_key_id": _KEY_ID,
                },
            }
        ),
    )


def _services(
    projector,
    *,
    reader=lambda _path, *, label: {"label": label},
) -> command_owner.ProjectObservationServices:
    return command_owner.ProjectObservationServices(
        read_external_object=reader,
        project_observation=projector,
        invalid_errors=(_InvalidObservation,),
        operational_errors=(_OperationalFailure,),
        machine_report=lambda out, value: out(json.dumps(value, sort_keys=True)),
        absolute_path=lambda path: f"/absolute/{path}",
    )


@pytest.mark.parametrize(
    ("decision", "verdict"),
    (("ALLOW", "PASS"), ("DENY", "REJECTED")),
)
def test_projection_success_is_not_an_admission_gate(
    decision: str,
    verdict: str,
) -> None:
    calls: list[dict[str, Any]] = []

    def projector(bundle: str, output: str, **kwargs):
        calls.append({"bundle": bundle, "output": output, **kwargs})
        return _verified(decision, verdict)

    output: list[str] = []
    exit_code = command_owner.execute_project_change_attempt_observation(
        _args(),
        services=_services(projector),
        out=output.append,
    )

    report = json.loads(output[0])
    assert exit_code == 0
    assert report == {
        "authority": "ADVISORY_ONLY",
        "bundle_sha256": _DIGEST,
        "decision": decision,
        "external_action": False,
        "finalizer_key_id": _KEY_ID,
        "format": "EVOGUARD_CHANGE_ATTEMPT_OBSERVATION_PROJECTION_V1",
        "observation": "/absolute/attempt-observation.json",
        "observation_sha256": "c" * 64,
        "ok": True,
        "status": "PROJECTED",
        "verdict": verdict,
        "verified": True,
    }
    assert calls == [
        {
            "bundle": "finalized.evb",
            "output": "attempt-observation.json",
            "trusted_finalizer_public_key_path": "finalizer.pub",
            "expected_source": {"label": "expected source"},
            "expected_context": {"label": "expected context"},
            "force": False,
        }
    ]
    assert "risk" not in output[0].lower()
    assert "source" not in report
    assert "context" not in report


def test_invalid_authenticated_input_exits_one() -> None:
    def projector(*_args, **_kwargs):
        raise _InvalidObservation("bundle verification failed")

    output: list[str] = []
    exit_code = command_owner.execute_project_change_attempt_observation(
        _args(),
        services=_services(projector),
        out=output.append,
    )

    report = json.loads(output[0])
    assert exit_code == 1
    assert report["status"] == "INVALID"
    assert report["verified"] is False


def test_missing_trusted_json_exits_two_before_projection() -> None:
    def reader(_path: str, *, label: str):
        raise OSError(f"{label} unavailable")

    output: list[str] = []
    exit_code = command_owner.execute_project_change_attempt_observation(
        _args(),
        services=_services(lambda *_args, **_kwargs: None, reader=reader),
        out=output.append,
    )

    report = json.loads(output[0])
    assert exit_code == 2
    assert report["status"] == "ERROR"
    assert report["verified"] is False


def test_signing_runtime_failure_exits_two() -> None:
    def projector(*_args, **_kwargs):
        raise _OperationalFailure("signing runtime unavailable")

    output: list[str] = []
    exit_code = command_owner.execute_project_change_attempt_observation(
        _args(),
        services=_services(projector),
        out=output.append,
    )

    report = json.loads(output[0])
    assert exit_code == 2
    assert report["status"] == "ERROR"
    assert report["verified"] is False


def test_public_parser_exposes_only_projection_authority_inputs() -> None:
    parsed = cli.build_parser().parse_args(
        [
            "project-change-attempt-observation",
            "finalized.evb",
            "--trusted-pub",
            "finalizer.pub",
            "--expected-source",
            "source.json",
            "--expected-context",
            "context.json",
            "--out",
            "observation.json",
        ]
    )

    assert parsed.command == "project-change-attempt-observation"
    assert parsed.finalizer_bundle == "finalized.evb"
    assert parsed.trusted_pub == "finalizer.pub"
    assert parsed.expected_source == "source.json"
    assert parsed.expected_context == "context.json"
    assert parsed.out == "observation.json"
    assert parsed.force is False
    assert not hasattr(parsed, "require_pass")
    assert not hasattr(parsed, "decision")
    assert not hasattr(parsed, "authority")


@pytest.mark.parametrize("case_index", (0, 1))
def test_public_facade_projects_real_signed_allow_and_deny(
    case_index: int,
    tmp_path: Path,
) -> None:
    case = CASES[case_index]
    fixture = _signed_attempt_fixture(
        tmp_path,
        case,
        prefix=f"cli-{case['decision'].lower()}",
    )
    source_path = tmp_path / "source.json"
    context_path = tmp_path / "context.json"
    output_path = tmp_path / "observation.json"
    source_path.write_text(json.dumps(fixture.source), encoding="utf-8")
    context_path.write_text(json.dumps(fixture.context), encoding="utf-8")
    parsed = cli.build_parser().parse_args(
        [
            "project-change-attempt-observation",
            str(fixture.bundle),
            "--trusted-pub",
            str(fixture.public_key),
            "--expected-source",
            str(source_path),
            "--expected-context",
            str(context_path),
            "--out",
            str(output_path),
        ]
    )

    output: list[str] = []
    exit_code = cli.cmd_project_change_attempt_observation(parsed, out=output.append)

    report = json.loads(output[0])
    observation = json.loads(output_path.read_text(encoding="ascii"))
    assert exit_code == 0
    assert report["decision"] == case["decision"]
    assert report["verdict"] == case["verdict"]
    assert report["authority"] == "ADVISORY_ONLY"
    assert report["external_action"] is False
    assert observation["authority"]["mode"] == "ADVISORY_ONLY"
    assert observation["authority"]["external_action"] is False
