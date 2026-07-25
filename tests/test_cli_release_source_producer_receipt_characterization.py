"""Frozen equivalence gate for the pending producer-receipt command owner."""

from __future__ import annotations

import difflib
import inspect
import json
from pathlib import Path

import pytest

from evoom_guard import cli
from tests.cli_release_source_producer_receipt_characterization_harness import (
    _CREATE_ALLOWED,
    _FORBIDDEN_CAPABILITY_ARGS,
    _REVERIFY_ALLOWED,
    _VERIFY_ALLOWED,
    BASELINE_COMMIT,
    CASE_NAMES,
    SCHEMA_VERSION,
    canonical_json,
    capture_case,
    capture_trace,
)

VECTOR = (
    Path(__file__).parent
    / "fixtures"
    / "refactor-safety"
    / "cli-release-source-producer-receipt.json"
)


def _frozen() -> dict[str, object]:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_cli_release_source_producer_receipt_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["baseline_commit"] == BASELINE_COMMIT
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_cli_release_source_producer_receipt_behavior(
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
        pytest.fail("Producer-receipt CLI behavior drifted:\n" + diff)


@pytest.mark.parametrize(
    ("command_name", "docstring"),
    (
        (
            "cmd_create_release_source_producer_receipt",
            "Create an unsigned canonical claim; it is never an admission decision.",
        ),
        (
            "cmd_verify_release_source_producer_receipt",
            "Verify local/raw-Git producer binding without treating it as provider proof.",
        ),
        (
            "cmd_reverify_attested_release_source_producer_receipt",
            "Make a fresh GitHub provider check after local/raw-Git verification.",
        ),
    ),
)
def test_public_producer_receipt_facades_are_frozen(
    command_name: str,
    docstring: str,
) -> None:
    command = getattr(cli, command_name)
    assert str(inspect.signature(command)) == (
        "(args: 'argparse.Namespace', *, "
        "out: 'Callable[[str], None]' = <built-in function print>) -> 'int'"
    )
    assert command.__doc__ == docstring


@pytest.mark.parametrize(
    ("case_name", "expected_events"),
    (
        (
            "create_eager_stdin_first_reads_handoff",
            [
                'arg:verdict="-"',
                'arg:handoff="/inputs/handoff.json"',
                "raise:argument",
            ],
        ),
        (
            "verify_eager_stdin_first_reads_all",
            [
                'arg:receipt="-"',
                'arg:handoff="/inputs/handoff.json"',
                'arg:verdict="/inputs/verdict.json"',
                "raise:argument",
            ],
        ),
        (
            "reverify_eager_stdin_first_reads_all",
            [
                'arg:receipt="-"',
                'arg:handoff="/inputs/handoff.json"',
                'arg:verdict="/inputs/verdict.json"',
                "raise:argument",
            ],
        ),
    ),
)
def test_stdin_guards_eagerly_read_the_complete_tuple(
    case_name: str,
    expected_events: list[str],
) -> None:
    trace = capture_trace(case_name)
    assert trace["events"] == expected_events
    assert trace["exception"] == {
        "type": "_ExpectedFatal",
        "message": f"expected:{case_name}",
        "same_identity": True,
    }
    assert trace["reports"] == []


def test_local_verification_is_successfully_verified_but_nonadmitting() -> None:
    default = capture_trace("verify_success_default_nonadmitting")
    opted_in = capture_trace("verify_success_opt_in_nonadmitting")
    expected_payload = {
        "format": "EVOGUARD_RELEASE_SOURCE_PRODUCER_RECEIPT_V1",
        "ok": False,
        "verified": True,
        "status": "NONADMITTING_LOCAL_AND_RAW_GIT_VERIFIED",
        "record_sha256": "3" * 64,
        "decision": "NONE",
        "admission": False,
        "provider_verified": False,
        "requires": "explicit-allow-nonadmitting-evidence-for-archive-only-success",
    }
    assert default["reports"] == [
        {"reporter": "initial", "payload": expected_payload}
    ]
    assert opted_in["reports"] == default["reports"]
    assert default["exit_code"] == 1
    assert opted_in["exit_code"] == 0


def test_fresh_provider_reverification_remains_nonadmitting() -> None:
    default = capture_trace("reverify_success_default_nonadmitting")
    opted_in = capture_trace("reverify_success_opt_in_nonadmitting")
    report = default["reports"][0]
    assert report["payload"] == {
        "format": "EVOGUARD_RELEASE_SOURCE_PRODUCER_RECEIPT_V1",
        "ok": False,
        "verified": True,
        "status": "NONADMITTING_FRESH_PROVIDER_VERIFIED",
        "record_sha256": "3" * 64,
        "github_receipt": "/outputs/github-receipt.json",
        "github_raw_output": "/outputs/github-raw.txt",
        "decision": "NONE",
        "admission": False,
        "requires": "explicit-allow-nonadmitting-evidence-for-archive-only-success",
    }
    assert default["exit_code"] == 1
    assert opted_in["exit_code"] == 0
    assert opted_in["reports"] == default["reports"]
    assert [call["name"] for call in default["calls"]].count("reverify") == 1


def test_provider_output_residue_is_frozen_without_cleanup_claims() -> None:
    create = capture_trace("create_provider_oserror_preserves_receipt")
    reverify = capture_trace(
        "reverify_provider_oserror_preserves_provider_outputs"
    )
    assert tuple(create["files"]) == ("/outputs/producer-receipt.json",)
    assert tuple(reverify["files"]) == (
        "/outputs/github-raw.txt",
        "/outputs/github-receipt.json",
    )
    assert create["exit_code"] == 1
    assert reverify["exit_code"] == 1
    assert create["reports"][0]["payload"]["status"] == "REJECTED"
    assert reverify["reports"][0]["payload"]["status"] == "REJECTED"


def test_command_authority_surfaces_exclude_admission_isolation_and_pins() -> None:
    assert not (_CREATE_ALLOWED & _FORBIDDEN_CAPABILITY_ARGS)
    assert not (_VERIFY_ALLOWED & _FORBIDDEN_CAPABILITY_ARGS)
    assert not (_REVERIFY_ALLOWED & _FORBIDDEN_CAPABILITY_ARGS)

    command_sources = "\n".join(
        inspect.getsource(getattr(cli, command_name))
        for command_name in (
            "cmd_create_release_source_producer_receipt",
            "cmd_verify_release_source_producer_receipt",
            "cmd_reverify_attested_release_source_producer_receipt",
        )
    )
    assert '"admission": True' not in command_sources
    assert "provider_isolation" not in command_sources
    assert "gh_executable_sha256" not in command_sources
    assert "git_executable_sha256" not in command_sources
    assert "sign_key" not in command_sources
    assert "sign_pub" not in command_sources

    reverify = capture_trace("reverify_success_default_nonadmitting")
    provider_call = [
        call for call in reverify["calls"] if call["name"] == "reverify"
    ][0]
    assert set(provider_call["kwargs"]) == {
        "expected_source",
        "expected_context",
        "expected_producer",
        "expected_bootstrap_guard_sha256",
        "expected_github_policy",
        "git_repository",
        "git_repository_is_bare",
        "github_receipt_path",
        "github_raw_output_path",
        "gh_executable",
        "timeout_seconds",
    }
