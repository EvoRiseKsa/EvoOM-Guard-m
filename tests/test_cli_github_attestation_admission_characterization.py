"""Frozen equivalence gate for GitHub attestation admission facade extraction."""

from __future__ import annotations

import difflib
import inspect
import json
from pathlib import Path

import pytest

from evoom_guard import cli
from tests.cli_github_attestation_admission_characterization_harness import (
    BASELINE_COMMIT,
    CASE_NAMES,
    SCHEMA_VERSION,
    SEAL_ALLOWED,
    SEAL_REGULAR_PATH_CASES,
    VERIFY_ALLOWED,
    VERIFY_REGULAR_PATH_CASES,
    _args,
    _ForbiddenEnvironment,
    canonical_json,
    capture_case,
)

VECTOR = (
    Path(__file__).parent
    / "fixtures"
    / "refactor-safety"
    / "cli-github-attestation-admission.json"
)


def _frozen() -> dict[str, object]:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_cli_github_attestation_admission_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    cases = frozen["cases"]
    assert isinstance(cases, dict)
    assert frozen["baseline_commit"] == BASELINE_COMMIT
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(cases) == tuple(sorted(CASE_NAMES))
    assert sum(name.startswith("seal_") for name in cases) >= 31
    assert sum(name.startswith("verify_") for name in cases) >= 25
    assert set(SEAL_REGULAR_PATH_CASES.values()) == {
        "artifact",
        "finalizer_bundle",
        "receipt_out",
        "raw_output_out",
        "out",
        "finalizer_pub",
        "sign_key",
    }
    assert set(VERIFY_REGULAR_PATH_CASES.values()) == {
        "binding",
        "artifact",
        "receipt",
        "raw_output",
        "finalizer_bundle",
        "trusted_pub",
        "finalizer_pub",
    }


@pytest.mark.parametrize(
    ("command_kind", "allowed", "probe"),
    (
        ("seal", SEAL_ALLOWED, "force"),
        ("seal", SEAL_ALLOWED, "vars"),
        ("verify", VERIFY_ALLOWED, "force"),
        ("verify", VERIFY_ALLOWED, "gh_executable"),
        ("verify", VERIFY_ALLOWED, "timeout_seconds"),
        ("verify", VERIFY_ALLOWED, "provider_isolation_uid"),
        ("verify", VERIFY_ALLOWED, "sign_key"),
        ("verify", VERIFY_ALLOWED, "out"),
        ("verify", VERIFY_ALLOWED, "vars"),
    ),
)
def test_admission_namespaces_are_closed_worlds(
    command_kind: str,
    allowed: frozenset[str],
    probe: str,
) -> None:
    events: list[str] = []
    args = _args(events)
    args._strict_allowed = allowed

    with pytest.raises(AssertionError, match="unexpected argument attribute"):
        if probe == "vars":
            vars(args)
        else:
            getattr(args, probe)
    assert events == [
        f"boundary-violated:{'__dict__' if probe == 'vars' else probe}"
    ]
    assert command_kind in {"seal", "verify"}


@pytest.mark.parametrize("probe", ("get", "getitem", "contains", "iter", "copy"))
def test_admission_environment_guard_is_fail_closed(probe: str) -> None:
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
def test_frozen_cli_github_attestation_admission_behavior(
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
        pytest.fail("GitHub attestation admission CLI behavior drifted:\n" + diff)


def test_seal_success_projection_order_is_explicitly_frozen() -> None:
    events = capture_case("seal_repeated_projection_order")["events"]
    projections = [event for event in events if event.startswith("projection:")]
    assert projections == [
        "projection:seal.receipt",
        "projection:seal.receipt.receipt_path",
        "projection:seal.receipt",
        "projection:seal.receipt.raw_output_path",
        "projection:seal.admission",
        "projection:seal.admission.binding_path",
        "projection:seal.receipt",
        "projection:seal.receipt.artifact",
        "projection:seal.receipt.artifact.as_dict",
        "projection:seal.receipt",
        "projection:seal.receipt.policy",
        "projection:seal.receipt.policy.as_dict",
        "projection:seal.admission",
        "projection:seal.admission.subject",
        "projection:seal.admission.subject.as_dict",
        "projection:seal.admission",
        "projection:seal.admission.provenance_reference",
        "projection:seal.admission.provenance_reference.as_dict",
        "projection:seal.admission",
        "projection:seal.admission.payload",
        "projection:seal.admission",
        "projection:seal.admission.payload",
    ]


def test_verify_success_projection_order_is_explicitly_frozen() -> None:
    events = capture_case("verify_repeated_projection_order")["events"]
    projections = [event for event in events if event.startswith("projection:")]
    assert projections == [
        "projection:verify.receipt",
        "projection:verify.receipt.artifact",
        "projection:verify.receipt.artifact.as_dict",
        "projection:verify.receipt",
        "projection:verify.receipt.policy",
        "projection:verify.receipt.policy.as_dict",
        "projection:verify.admission",
        "projection:verify.admission.subject",
        "projection:verify.admission.subject.as_dict",
        "projection:verify.admission",
        "projection:verify.admission.provenance_reference",
        "projection:verify.admission.provenance_reference.as_dict",
        "projection:verify.admission",
        "projection:verify.admission.inspection",
        "projection:verify.admission.inspection.finalizer",
        "projection:verify.admission",
        "projection:verify.admission.inspection",
        "projection:verify.admission.inspection.payload",
    ]


def test_seal_parser_has_no_overwrite_escape_hatch() -> None:
    argv = [
        "seal-github-attestation-admission",
        "artifact.bin",
        "finalizer.evb",
        "--receipt-out",
        "receipt.json",
        "--raw-output-out",
        "raw.json",
        "--out",
        "binding.json",
        "--finalizer-pub",
        "finalizer.pub",
        "--expected-source",
        "source.json",
        "--expected-context",
        "context.json",
        "--sign-key",
        "admission.key",
        "--repo",
        "owner/repository",
        "--signer-workflow",
        "owner/repository/.github/workflows/build.yml",
        "--signer-digest",
        "1" * 40,
        "--source-ref",
        "refs/heads/main",
        "--source-digest",
        "2" * 40,
        "--cert-oidc-issuer",
        "https://token.actions.githubusercontent.com",
        "--force",
    ]
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(argv)


@pytest.mark.parametrize(
    ("command_name", "docstring"),
    (
        (
            "cmd_seal_github_attestation_admission",
            (
                "Freshly verify provider evidence, then bind it to a finalizer ALLOW.\n\n"
                "    This command intentionally owns no shortcut around the provider policy,\n"
                "    external finalizer source/context, or separate V2 admission key.  In\n"
                "    particular it exposes no overwrite switch: a protected job must choose\n"
                "    fresh, reviewable evidence paths for every run.\n"
                "    "
            ),
        ),
        (
            "cmd_verify_github_attestation_admission",
            "Verify retained provider bytes and their V2 finalizer-bound relation.",
        ),
    ),
)
def test_public_github_attestation_admission_facades_are_frozen(
    command_name: str,
    docstring: str,
) -> None:
    command = getattr(cli, command_name)
    assert str(inspect.signature(command)) == (
        "(args: 'argparse.Namespace', *, "
        "out: 'Callable[[str], None]' = <built-in function print>) -> 'int'"
    )
    assert command.__doc__ == docstring
