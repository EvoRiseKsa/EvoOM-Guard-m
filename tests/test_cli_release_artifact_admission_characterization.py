"""Frozen equivalence gate for the pending Release Artifact Admission owner."""

from __future__ import annotations

import ast
import difflib
import inspect
import json
from pathlib import Path

import pytest

from evoom_guard import cli
from tests.cli_release_artifact_admission_characterization_harness import (
    _SEAL_ARGS,
    _VERIFY_ARGS,
    BASELINE_COMMIT,
    CASE_NAMES,
    FORBIDDEN_VERIFY_CAPABILITIES,
    SCHEMA_VERSION,
    _args,
    canonical_json,
    capture_case,
)

VECTOR = (
    Path(__file__).parent / "fixtures" / "refactor-safety" / "cli-release-artifact-admission.json"
)


def _frozen() -> dict[str, object]:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_cli_release_artifact_admission_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["baseline_commit"] == BASELINE_COMMIT
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))
    assert sum(name.startswith("seal_") for name in CASE_NAMES) >= 25
    assert sum(name.startswith("verify_") for name in CASE_NAMES) >= 16


def test_frozen_vector_has_no_checkout_specific_paths() -> None:
    frozen_text = VECTOR.read_text(encoding="utf-8")
    assert str(Path(__file__).resolve()) not in frozen_text
    assert "\\Users\\" not in frozen_text
    assert "/home/runner/work/" not in frozen_text
    existing_output = frozen_text.count(
        'arg:out=\\"/outputs/existing-release-artifact.raae\\"'
    )
    # The frozen preflight reads the output once while building its complete
    # path set and once again for the existence check.
    assert existing_output == 2


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_cli_release_artifact_admission_behavior(
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
        pytest.fail("Release Artifact Admission CLI behavior drifted:\n" + diff)


@pytest.mark.parametrize(
    ("command_name", "docstring"),
    (
        (
            "cmd_seal_github_release_artifact_admission",
            "Bind the live F job to E, freshly verify GitHub, then seal one RAAE.",
        ),
        (
            "cmd_verify_github_release_artifact_admission",
            "Verify one RAAE, its artifact, nested RSAE, and all six roots offline.",
        ),
    ),
)
def test_public_release_artifact_admission_facades_are_frozen(
    command_name: str,
    docstring: str,
) -> None:
    command = getattr(cli, command_name)
    assert str(inspect.signature(command)) == (
        "(args: 'argparse.Namespace', *, "
        "out: 'Callable[[str], None]' = <built-in function print>) -> 'int'"
    )
    assert command.__doc__ == docstring


def test_seal_success_requires_live_provider_authority_and_exact_pins() -> None:
    trace = capture_case("seal_success_online_boundary")
    assert trace["exception"] is None
    assert trace["exit_code"] == 0
    assert trace["reports"][0]["status"] == "SEALED"
    assert trace["reports"][0]["provider_verified"] is True
    assert trace["reports"][0]["live_provider_reverification"] is True

    names = [call["name"] for call in trace["calls"]]
    assert names == ["bind-runtime", "git-pin", "provider-isolation", "seal"]
    bind_call = trace["calls"][0]
    assert bind_call["kwargs"]["environment"] == "<same-controlled-environment>"
    seal_call = trace["calls"][-1]
    assert set(seal_call["kwargs"]) == {
        "admitter",
        "trusted_release_source_public_key_path",
        "expected_release_source",
        "expected_release_source_context",
        "expected_release_source_producer",
        "expected_release_source_admitter",
        "expected_release_source_bootstrap_guard_sha256",
        "expected_release_source_github_policy",
        "expected_release_source_git_executable_sha256",
        "expected_release_source_github_cli_executable_sha256",
        "expected_release_source_provider_isolation_uid",
        "expected_release_source_provider_isolation_gid",
        "key_separation",
        "git_repository",
        "git_repository_is_bare",
        "git_executable",
        "provider_isolation",
        "private_key_path",
        "signing_public_key_path",
        "expected_signing_key_id",
        "gh_executable",
        "timeout_seconds",
    }


def test_verify_success_is_offline_and_has_no_live_provider_authority() -> None:
    trace = capture_case("verify_success_offline_closed_world")
    assert trace["exception"] is None
    assert trace["exit_code"] == 0
    assert trace["reports"][0]["status"] == "VERIFIED"
    assert trace["reports"][0]["verification_scope"] == (
        "detached-offline-retained-provider-evidence"
    )
    assert trace["reports"][0]["live_provider_reverification"] is False
    assert [call["name"] for call in trace["calls"]] == ["verify"]
    assert not any(event.startswith("environment:") for event in trace["events"])

    verify_call = trace["calls"][0]
    assert set(verify_call["kwargs"]) == {
        "trusted_public_key_path",
        "trusted_release_source_public_key_path",
        "expected_release_source",
        "expected_release_source_context",
        "expected_release_source_producer",
        "expected_release_source_admitter",
        "expected_release_source_bootstrap_guard_sha256",
        "expected_release_source_github_policy",
        "expected_release_source_git_executable_sha256",
        "expected_release_source_github_cli_executable_sha256",
        "expected_release_source_provider_isolation_uid",
        "expected_release_source_provider_isolation_gid",
        "expected_builder",
        "expected_admitter",
        "expected_key_separation",
        "expected_git_executable_sha256",
        "expected_github_cli_executable_sha256",
        "expected_provider_isolation_uid",
        "expected_provider_isolation_gid",
    }
    assert not (set(verify_call["kwargs"]) & FORBIDDEN_VERIFY_CAPABILITIES)


def test_preflight_reads_all_paths_before_rejecting_output_stdin() -> None:
    trace = capture_case("seal_preflight_reads_complete_path_set_before_rejecting_stdin")
    assert trace["exit_code"] == 1
    assert trace["reports"][0]["status"] == "REJECTED"
    events = trace["events"]
    assert events.index('arg:out="-"') < events.index(
        'arg:release_source_admission="/inputs/release-source.rsae"'
    )
    assert events.index('arg:sign_key="/keys/release-artifact-admission-v1.key"') < (
        events.index("reporter:original:REJECTED")
    )
    assert not any(event.startswith("reader:") for event in events)


def test_verify_stdin_guard_preserves_boolean_short_circuit_order() -> None:
    bundle = capture_case("verify_bundle_stdin_short_circuits_artifact")
    artifact = capture_case("verify_artifact_stdin_after_bundle_read")
    assert bundle["events"][:2] == [
        'arg:bundle="-"',
        "reporter:original:REJECTED",
    ]
    assert artifact["events"][:3] == [
        'arg:bundle="/inputs/release-artifact.raae"',
        'arg:artifact="-"',
        "reporter:original:REJECTED",
    ]


def test_signer_collision_fails_before_executable_or_provider_construction() -> None:
    trace = capture_case("seal_signer_domain_collision_precedes_execution_pins")
    assert trace["exit_code"] == 1
    assert trace["reports"][0]["status"] == "REJECTED"
    assert "earlier configured trust domain" in trace["reports"][0]["error"]
    assert [call["name"] for call in trace["calls"]] == ["bind-runtime"]


def test_provider_partial_output_has_no_unclaimed_cleanup_semantics() -> None:
    trace = capture_case("seal_provider_oserror_preserves_partial_bundle")
    assert trace["exit_code"] == 1
    assert trace["reports"][0]["status"] == "REJECTED"
    assert trace["files"] == {
        "/outputs/release-artifact.raae": "partial-release-artifact-admission"
    }


def test_success_projection_orders_are_explicitly_frozen() -> None:
    seal = capture_case("seal_success_online_boundary")
    verify = capture_case("verify_success_offline_closed_world")
    assert [event for event in seal["events"] if event.startswith("projection:")] == [
        "projection:sealed.bundle_path",
        "projection:sealed.artifact",
        "projection:sealed.artifact.as_dict",
        "projection:sealed.manifest",
        "projection:sealed.manifest[release_source]",
        "projection:sealed.manifest",
        "projection:sealed.manifest[builder]",
        "projection:sealed.manifest",
        "projection:sealed.manifest[admitter]",
        "projection:sealed.manifest",
        "projection:sealed.manifest[authentication]",
        "projection:sealed.manifest.authentication[key_id]",
        "projection:sealed.decision",
    ]
    assert [event for event in verify["events"] if event.startswith("projection:")] == [
        "projection:verified.bundle",
        "projection:verified.bundle.manifest",
        "projection:verified.decision",
        "projection:verified.artifact",
        "projection:verified.artifact.as_dict",
        "projection:verified.bundle.manifest[release_source]",
        "projection:verified.bundle.manifest[builder]",
        "projection:verified.bundle.manifest[admitter]",
        "projection:verified.bundle.manifest[authentication]",
        "projection:verified.bundle.manifest.authentication[key_id]",
    ]


def test_each_live_facade_seam_is_frozen_during_command_execution() -> None:
    expectations = {
        "seal_preflight_helper_is_live_after_environment_read": (
            "preflight:late:/inputs/github-event.json"
        ),
        "seal_key_helper_is_live_after_metadata_reads": "key-helper:late",
        "verify_nested_helper_is_live_after_stdin_guard": "nested-helper:late",
        "verify_reader_is_live_during_nested_reads": (
            "reader:late:expected release-source producer:/inputs/release-source-producer.json"
        ),
    }
    for case_name, expected_event in expectations.items():
        trace = capture_case(case_name)
        assert trace["exit_code"] == 0
        assert trace["exception"] is None
        assert expected_event in trace["events"]


@pytest.mark.parametrize(
    ("kind", "allowed", "probe"),
    (
        ("seal", _SEAL_ARGS, "force"),
        ("seal", _SEAL_ARGS, "allow_overwrite"),
        ("seal", _SEAL_ARGS, "network"),
        ("seal", _SEAL_ARGS, "__dict__"),
        ("verify", _VERIFY_ARGS, "gh_executable"),
        ("verify", _VERIFY_ARGS, "git_repository"),
        ("verify", _VERIFY_ARGS, "sign_key"),
        ("verify", _VERIFY_ARGS, "timeout_seconds"),
        ("verify", _VERIFY_ARGS, "force"),
        ("verify", _VERIFY_ARGS, "__dict__"),
    ),
)
def test_release_artifact_namespaces_are_closed_worlds(
    kind: str,
    allowed: frozenset[str],
    probe: str,
) -> None:
    events: list[str] = []
    args = _args(events)
    args._strict_allowed = allowed
    with pytest.raises(AssertionError, match="unexpected argument attribute"):
        getattr(args, probe)
    assert events == [f"boundary-violated:{probe}"]
    assert kind in {"seal", "verify"}


def test_verify_facade_does_not_import_online_provider_or_git_capabilities() -> None:
    sources = [inspect.getsource(cli.cmd_verify_github_release_artifact_admission)]
    owner_path = Path(cli.__file__).with_name("release_artifact_admission_commands.py")
    if owner_path.exists():
        owner_source = owner_path.read_text(encoding="utf-8")
        owner_tree = ast.parse(owner_source)
        import_roots = {
            alias.name.partition(".")[0]
            for node in ast.walk(owner_tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            (node.module or "").partition(".")[0]
            for node in ast.walk(owner_tree)
            if isinstance(node, ast.ImportFrom)
        }
        assert import_roots <= {
            "__future__",
            "argparse",
            "collections",
            "dataclasses",
            "os",
            "typing",
        }
        verify_functions = [
            node
            for node in owner_tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "execute_verify_github_release_artifact_admission"
        ]
        assert len(verify_functions) == 1
        verify_source = ast.get_source_segment(
            owner_source,
            verify_functions[0],
        )
        assert verify_source is not None
        sources.append(verify_source)

        verify_names = {
            node.id for node in ast.walk(verify_functions[0]) if isinstance(node, ast.Name)
        } | {node.attr for node in ast.walk(verify_functions[0]) if isinstance(node, ast.Attribute)}
        assert not (
            verify_names
            & {
                "environment",
                "environment_provider",
                "environ",
                "gh_executable",
                "git_executable",
                "git_executable_pin",
                "git_repository",
                "github_attestation_provider_isolation",
                "private_key_path",
                "provider_isolation",
                "sign_key",
                "socket",
                "subprocess",
            }
        )

    source = "\n".join(sources)
    assert "github_attestation_provider_isolation" not in source
    assert "git_executable_pin" not in source
    assert "GITHUB_EVENT_PATH" not in source
    assert "args.gh_executable" not in source
    assert "args.git_executable" not in source
    assert "args.git_repository" not in source
    assert "private_key_path" not in source


def test_seal_parser_has_no_overwrite_escape_hatch() -> None:
    parser = cli.build_parser()
    seal = parser.parse_args(
        [
            "seal-github-release-artifact-admission",
            "source.rsae",
            "artifact.pyz",
            "--out",
            "artifact.raae",
            "--builder",
            "builder.json",
            "--admitter",
            "admitter.json",
            "--expected-release-source",
            "source.json",
            "--expected-release-source-context",
            "context.json",
            "--expected-release-source-producer",
            "producer.json",
            "--expected-release-source-admitter",
            "source-admitter.json",
            "--expected-release-source-bootstrap-guard-sha",
            "1" * 64,
            "--expected-release-source-github-policy",
            "policy.json",
            "--expected-release-source-git-executable-sha256",
            "2" * 64,
            "--expected-release-source-gh-executable-sha256",
            "3" * 64,
            "--expected-release-source-provider-isolation-uid",
            "2001",
            "--expected-release-source-provider-isolation-gid",
            "2002",
            "--git-repository",
            ".",
            "--git-executable",
            "/usr/bin/git",
            "--git-executable-sha256",
            "4" * 64,
            "--gh-executable",
            "/usr/bin/gh",
            "--gh-executable-sha256",
            "5" * 64,
            "--provider-isolation-uid",
            "3001",
            "--provider-isolation-gid",
            "3002",
            "--sign-key",
            "sign.key",
            "--sign-pub",
            "sign.pub",
            "--trusted-finalizer-pub",
            "finalizer.pub",
            "--artifact-admission-v1-pub",
            "artifact-v1.pub",
            "--artifact-digest-admission-v2-pub",
            "artifact-v2.pub",
            "--release-source-finalizer-v1-pub",
            "source-finalizer.pub",
            "--release-source-admission-v2-pub",
            "source-admission.pub",
        ]
    )
    assert not hasattr(seal, "force")
    assert not hasattr(seal, "allow_overwrite")
