"""Frozen equivalence gate for the pending Release Source Admission owner."""

from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

import pytest

from evoom_guard import cli
from evoom_guard.cli import (
    release_source_admission_commands as release_source_admission_owner,
)
from tests.cli_release_source_admission_characterization_harness import (
    BASELINE_COMMIT,
    CASE_NAMES,
    SCHEMA_VERSION,
    SEAL_ALLOWED,
    SEAL_STDIN_CASES,
    VERIFY_ALLOWED,
    _args,
    capture_case,
)

VECTOR = (
    Path(__file__).parent
    / "fixtures"
    / "refactor-safety"
    / "cli-release-source-admission.json"
)


def _frozen() -> dict[str, object]:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def test_cli_release_source_admission_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    cases = frozen["cases"]
    assert isinstance(cases, dict)
    assert frozen["baseline_commit"] == BASELINE_COMMIT
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(cases) == tuple(sorted(CASE_NAMES))
    assert len(cases) == 56
    assert sum(name.startswith("seal_") for name in cases) == 40
    assert sum(name.startswith("verify_") for name in cases) == 16
    assert set(SEAL_STDIN_CASES.values()) == {"receipt", "handoff", "verdict"}


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_cli_release_source_admission_behavior(case_name: str) -> None:
    cases = _frozen()["cases"]
    assert isinstance(cases, dict)
    assert _digest(capture_case(case_name)) == cases[case_name]


@pytest.mark.parametrize(
    ("allowed", "probe"),
    (
        (SEAL_ALLOWED, "env"),
        (SEAL_ALLOWED, "github_token"),
        (SEAL_ALLOWED, "network"),
        (SEAL_ALLOWED, "allow_nonadmitting_evidence"),
        (VERIFY_ALLOWED, "receipt"),
        (VERIFY_ALLOWED, "sign_key"),
        (VERIFY_ALLOWED, "gh_executable"),
        (VERIFY_ALLOWED, "git_repository"),
        (VERIFY_ALLOWED, "force"),
        (VERIFY_ALLOWED, "env"),
        (VERIFY_ALLOWED, "github_token"),
        (VERIFY_ALLOWED, "network"),
    ),
)
def test_release_source_admission_namespaces_are_closed_worlds(
    allowed: frozenset[str],
    probe: str,
) -> None:
    events: list[str] = []
    args = _args(events)
    args._strict_allowed = allowed

    with pytest.raises(AssertionError, match="unexpected argument attribute"):
        getattr(args, probe)
    assert events == [f"boundary-violated:{probe}"]


def test_seal_trusted_reads_and_providers_have_one_frozen_order() -> None:
    captured = capture_case("seal_success")
    events = captured["events"]
    assert isinstance(events, list)
    reads = [event for event in events if event.startswith("reader:")]
    assert reads == [
        "reader:original:expected release source:/trust/source.json",
        "reader:original:expected release-source context:/trust/context.json",
        "reader:original:expected producer identity:/trust/producer.json",
        "reader:original:expected release-source admitter:/trust/admitter.json",
        (
            "reader:original:GitHub producer-attestation policy:"
            "/trust/github-policy.json"
        ),
        (
            "reader:original:GitHub Actions workflow_run event payload:"
            "/trust/event.json"
        ),
    ]
    calls = captured["calls"]
    assert isinstance(calls, list)
    assert [call["provider"] for call in calls] == [
        "git-pin",
        "provider-isolation",
        "workflow-verify",
        "runtime-validate",
        "producer-receipt-reverify",
        "seal",
    ]
    assert events.index("helper:preflight:original") < events.index(
        "provider:git-pin:original"
    )
    assert events.index("environment:get:GITHUB_EVENT_PATH") < events.index(
        "provider:runtime-validate:original"
    )


def test_seal_success_projection_order_is_explicitly_frozen() -> None:
    events = capture_case("seal_success_projection_order")["events"]
    assert isinstance(events, list)
    projections = [event for event in events if event.startswith("projection:")]
    assert projections == [
        "projection:sealed.bundle_path",
        "projection:sealed.manifest",
        "projection:sealed.manifest[authentication]",
        "projection:sealed.manifest.authentication[key_id]",
        "projection:sealed.manifest",
        "projection:sealed.manifest[record]",
        "projection:sealed.manifest.record[sha256]",
        "projection:sealed.manifest",
        "projection:sealed.manifest[producer_receipt]",
        "projection:sealed.manifest.producer_receipt[sha256]",
        "projection:sealed.decision",
    ]


def test_verify_success_is_offline_and_has_one_projection_order() -> None:
    captured = capture_case("verify_success_offline_boundary")
    events = captured["events"]
    calls = captured["calls"]
    assert isinstance(events, list)
    assert isinstance(calls, list)
    assert [call["provider"] for call in calls] == ["verify"]
    assert not any(event.startswith("environment:") for event in events)
    assert not any(
        event.startswith(
            (
                "provider:git-pin:",
                "provider:provider-isolation:",
                "provider:workflow-verify:",
                "provider:runtime-validate:",
                "provider:producer-receipt-reverify:",
                "provider:seal:",
            )
        )
        for event in events
    )
    projections = [event for event in events if event.startswith("projection:")]
    assert projections == [
        "projection:verified.bundle",
        "projection:verified.bundle.manifest",
        "projection:verified.bundle.manifest[authentication]",
        "projection:verified.bundle.manifest.authentication[key_id]",
        "projection:verified.bundle",
        "projection:verified.bundle.manifest",
        "projection:verified.bundle.manifest[record]",
        "projection:verified.bundle.manifest.record[sha256]",
        "projection:verified.bundle",
        "projection:verified.bundle.manifest",
        "projection:verified.bundle.manifest[producer_receipt]",
        "projection:verified.bundle.manifest.producer_receipt[sha256]",
        "projection:verified.decision",
    ]


def test_verify_service_contract_has_no_connected_authority_seam() -> None:
    assert set(
        release_source_admission_owner.VerifyReleaseSourceAdmissionServices.__dataclass_fields__
    ) == {
        "admission_format",
        "key_separation_provider",
        "machine_report_provider",
        "read_external_object_provider",
        "release_source_error",
        "signing_unavailable_error",
        "verify_release_source_admission",
    }


def test_provider_partial_evidence_is_not_hidden_or_rolled_back() -> None:
    captured = capture_case("seal_partial_provider_output_preserved")
    assert captured["exit_code"] == 1
    assert captured["files"] == {
        "/outputs/github-raw.json": "partial-provider-raw-output",
        "/outputs/github-receipt.json": "partial-provider-receipt",
    }
    calls = captured["calls"]
    assert isinstance(calls, list)
    assert [call["provider"] for call in calls][-1] == "producer-receipt-reverify"


def test_preflight_rejection_precedes_executable_and_provider_io() -> None:
    captured = capture_case("seal_preflight_rejects_before_executables")
    assert captured["exit_code"] == 1
    assert captured["calls"] == []
    outputs = captured["outputs"]
    assert isinstance(outputs, list)
    assert outputs[0]["status"] == "REJECTED"


@pytest.mark.parametrize(
    ("case_name", "exception_type"),
    (
        ("seal_receipt_property_failure_identity", "RuntimeError"),
        ("seal_provider_baseexception_identity", "KeyboardInterrupt"),
        ("seal_projection_failure_identity", "RuntimeError"),
        ("seal_output_failure_identity", "RuntimeError"),
        ("verify_provider_baseexception_identity", "KeyboardInterrupt"),
        ("verify_projection_failure_identity", "RuntimeError"),
        ("verify_output_failure_identity", "RuntimeError"),
    ),
)
def test_uncaught_exception_identity_is_preserved(
    case_name: str,
    exception_type: str,
) -> None:
    exception = capture_case(case_name)["exception"]
    assert exception == {
        "type": exception_type,
        "message": {
            "KeyboardInterrupt": "provider interrupted",
            "RuntimeError": (
                "argument property failed"
                if "property" in case_name
                else "projection failed"
                if "projection" in case_name
                else "output failed"
            ),
        }[exception_type],
        "same_identity": True,
    }


@pytest.mark.parametrize(
    ("command_name", "docstring"),
    (
        (
            "cmd_seal_release_source_admission",
            "Freshly verify the protected producer relation, then sign one V2 ALLOW.",
        ),
        (
            "cmd_verify_release_source_admission",
            "Verify a V2 source authorization using only external trust roots.",
        ),
    ),
)
def test_public_release_source_admission_facades_are_frozen(
    command_name: str,
    docstring: str,
) -> None:
    command = getattr(cli, command_name)
    assert str(inspect.signature(command)) == (
        "(args: 'argparse.Namespace', *, "
        "out: 'Callable[[str], None]' = <built-in function print>) -> 'int'"
    )
    assert command.__doc__ == docstring
