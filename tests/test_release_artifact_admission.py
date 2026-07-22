from __future__ import annotations

import copy
import json
import os
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from test_github_attestation import _verified_gh_output
from test_release_source_admission import _AdmissionInputs
from test_release_source_admission import _inputs as _release_source_inputs
from test_release_source_admission import _seal as _seal_release_source

from evoom_guard import cli, finalizer_derivation, github_attestation
from evoom_guard.admission import release_artifact as release_artifact_admission
from evoom_guard.evidence_bundle import (
    canonical_archive_bytes,
    canonical_json_bytes,
    sha256_bytes,
)
from evoom_guard.finalizer_derivation import GitExecutablePin
from evoom_guard.signing import generate_keypair, public_key_id


@dataclass
class _Inputs:
    release_source: _AdmissionInputs
    artifact: Path
    output: Path
    private: Path
    public: Path
    builder: dict[str, Any]
    admitter: dict[str, Any]
    runtime_admitter: (
        release_artifact_admission.RuntimeBoundReleaseArtifactAdmitter
    )
    key_separation: dict[str, str]
    git_executable: GitExecutablePin
    provider_isolation: github_attestation.GitHubAttestationProviderIsolation
    provider_directories: list[Path]
    provider_calls: list[dict[str, object]]


def _keys(tmp_path: Path, name: str) -> tuple[Path, Path]:
    private = tmp_path / f"{name}.private.pem"
    public = tmp_path / f"{name}.public.pem"
    generate_keypair(str(private), str(public))
    return private, public


def _unopened_git_pin(tmp_path: Path, digest: str) -> GitExecutablePin:
    pin = object.__new__(GitExecutablePin)
    object.__setattr__(pin, "executable_path", str((tmp_path / "outer-git").resolve()))
    object.__setattr__(pin, "executable_sha256", digest)
    return pin


def _runtime_inputs(
    builder: dict[str, Any], admitter: dict[str, Any]
) -> tuple[dict[str, str], dict[str, Any]]:
    environment = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": admitter["workflow_repository"],
        "GITHUB_REPOSITORY_ID": admitter["workflow_repository_id"],
        "GITHUB_RUN_ID": admitter["workflow_run_id"],
        "GITHUB_RUN_ATTEMPT": str(admitter["workflow_run_attempt"]),
        "GITHUB_EVENT_NAME": admitter["workflow_event"],
        "GITHUB_REF": admitter["workflow_ref"],
        "GITHUB_SHA": admitter["workflow_commit_sha"],
        "GITHUB_WORKFLOW_REF": (
            f"{admitter['workflow_repository']}/{admitter['workflow_path']}"
            f"@{admitter['workflow_ref']}"
        ),
        "GITHUB_WORKFLOW_SHA": admitter["workflow_commit_sha"],
        "RUNNER_ENVIRONMENT": "github-hosted",
    }
    event = {
        "repository": {
            "full_name": builder["workflow_repository"],
            "id": int(builder["workflow_repository_id"]),
        },
        "workflow_run": {
            "id": int(builder["workflow_run_id"]),
            "run_attempt": builder["workflow_run_attempt"],
            "workflow_id": int(builder["workflow_id"]),
            "path": builder["workflow_path"],
            "head_sha": builder["workflow_commit_sha"],
            "head_branch": "main",
            "head_repository": {
                "full_name": builder["workflow_repository"],
                "id": int(builder["workflow_repository_id"]),
            },
            "event": builder["workflow_event"],
            "status": "completed",
            "conclusion": "success",
        },
    }
    return environment, event


def _provider_factory(
    directories: list[Path], calls: list[dict[str, object]]
):
    def _provider(
        artifact_path: str,
        receipt_path: str,
        raw_output_path: str,
        **kwargs: object,
    ) -> github_attestation.CreatedGitHubAttestationReceipt:
        calls.append(dict(kwargs))
        directories.append(Path(receipt_path).resolve().parent)
        artifact_bytes = Path(artifact_path).read_bytes()
        policy = github_attestation.github_attestation_policy(
            str(kwargs["repository"]),
            str(kwargs["signer_workflow"]),
            str(kwargs["source_digest"]),
            signer_digest=str(kwargs["signer_digest"]),
            source_ref=str(kwargs["source_ref"]),
            cert_oidc_issuer=str(kwargs["cert_oidc_issuer"]),
        )
        artifact = github_attestation.GitHubAttestationArtifact(
            sha256=sha256_bytes(artifact_bytes), size=len(artifact_bytes)
        )
        raw = _verified_gh_output(
            artifact_sha256=artifact.sha256,
            repository=policy.repository,
            signer_workflow=policy.signer_workflow,
            signer_digest=policy.signer_digest,
            source_ref=policy.source_ref,
            source_digest=policy.source_digest,
            issuer=policy.cert_oidc_issuer,
            run_id=str(kwargs["expected_workflow_run_id"]),
            run_attempt=int(kwargs["expected_workflow_run_attempt"]),
        )
        receipt = {
            "format": github_attestation.GITHUB_ATTESTATION_RECEIPT_FORMAT,
            "artifact": artifact.as_dict(),
            "verification_policy": policy.as_dict(),
            "verification_output": {
                "sha256": sha256_bytes(raw),
                "size": len(raw),
                "verified_attestation_count": 1,
            },
        }
        receipt_absolute = Path(receipt_path).resolve()
        output_absolute = Path(raw_output_path).resolve()
        receipt_absolute.write_bytes(canonical_json_bytes(receipt))
        output_absolute.write_bytes(raw)
        return github_attestation.CreatedGitHubAttestationReceipt(
            receipt_path=str(receipt_absolute),
            raw_output_path=str(output_absolute),
            artifact=artifact,
            policy=policy,
            verified_attestation_count=1,
        )

    return _provider


def _inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _Inputs:
    release_source = _release_source_inputs(tmp_path, monkeypatch)
    _seal_release_source(release_source)
    target = release_source.source["target_commit_sha"]
    builder = {
        "workflow_repository": release_source.source["repository"],
        "workflow_repository_id": release_source.source["repository_id"],
        "workflow_id": "77771",
        "workflow_path": ".github/workflows/build-release-artifact.yml",
        "workflow_blob_sha": "b" * 40,
        "workflow_run_id": "987654330",
        "workflow_run_attempt": 2,
        "workflow_event": "workflow_dispatch",
        "workflow_ref": "refs/heads/main",
        "workflow_commit_sha": target,
        "runner_class": "github-hosted",
    }
    admitter = {
        "workflow_repository": release_source.source["repository"],
        "workflow_repository_id": release_source.source["repository_id"],
        "workflow_id": "77772",
        "workflow_path": ".github/workflows/admit-release-artifact.yml",
        "workflow_blob_sha": "c" * 40,
        "workflow_run_id": "987654331",
        "workflow_run_attempt": 1,
        "workflow_event": "workflow_run",
        "workflow_ref": "refs/heads/main",
        "workflow_commit_sha": target,
        "runner_class": "github-hosted",
    }
    environment, event = _runtime_inputs(builder, admitter)
    runtime_admitter = (
        release_artifact_admission.bind_release_artifact_admitter_runtime(
            builder,
            admitter,
            source=release_source.source,
            environment=environment,
            event_payload=event,
        )
    )
    private, public = _keys(tmp_path, "release-artifact-admission-v1")
    key_separation = {
        **release_source.key_separation,
        "release_source_admission_v2": public_key_id(str(release_source.public)),
    }
    artifact = tmp_path / "release-product.bin"
    artifact.write_bytes(b"exact protected-main release artifact\n")
    git_executable = _unopened_git_pin(tmp_path, "7" * 64)
    provider_isolation = github_attestation.GitHubAttestationProviderIsolation(
        executable_path=str((tmp_path / "outer-gh").resolve()),
        executable_sha256="8" * 64,
        uid=60001,
        gid=60002,
    )
    provider_directories: list[Path] = []
    provider_calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        release_artifact_admission,
        "validate_provider_isolated_signing_key_path",
        lambda path, _isolation: path,
    )
    monkeypatch.setattr(
        release_artifact_admission,
        "_verify_workflow_blob",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        release_artifact_admission,
        "create_github_attestation_receipt",
        _provider_factory(provider_directories, provider_calls),
    )
    return _Inputs(
        release_source=release_source,
        artifact=artifact,
        output=tmp_path / "release-artifact-admission.raae",
        private=private,
        public=public,
        builder=builder,
        admitter=admitter,
        runtime_admitter=runtime_admitter,
        key_separation=key_separation,
        git_executable=git_executable,
        provider_isolation=provider_isolation,
        provider_directories=provider_directories,
        provider_calls=provider_calls,
    )


def _seal(inputs: _Inputs, **overrides: object):
    arguments: dict[str, object] = {
        "admitter": inputs.runtime_admitter,
        "trusted_release_source_public_key_path": str(inputs.release_source.public),
        "expected_release_source": inputs.release_source.source,
        "expected_release_source_context": inputs.release_source.context,
        "expected_release_source_producer": inputs.release_source.producer,
        "expected_release_source_admitter": inputs.release_source.admitter,
        "expected_release_source_bootstrap_guard_sha256": "a" * 64,
        "expected_release_source_github_policy": inputs.release_source.policy,
        "expected_release_source_git_executable_sha256": (
            inputs.release_source.git_executable.executable_sha256
        ),
        "expected_release_source_github_cli_executable_sha256": (
            inputs.release_source.provider_isolation.executable_sha256
        ),
        "expected_release_source_provider_isolation_uid": (
            inputs.release_source.provider_isolation.uid
        ),
        "expected_release_source_provider_isolation_gid": (
            inputs.release_source.provider_isolation.gid
        ),
        "key_separation": inputs.key_separation,
        "git_repository": str(inputs.release_source.repo),
        "git_executable": inputs.git_executable,
        "provider_isolation": inputs.provider_isolation,
        "private_key_path": str(inputs.private),
        "signing_public_key_path": str(inputs.public),
        "expected_signing_key_id": public_key_id(str(inputs.public)),
    }
    arguments.update(overrides)
    return release_artifact_admission.seal_release_artifact_admission(
        str(inputs.release_source.output),
        str(inputs.artifact),
        str(inputs.output),
        **arguments,  # type: ignore[arg-type]
    )


def _verify(inputs: _Inputs, **overrides: object):
    arguments: dict[str, object] = {
        "trusted_public_key_path": str(inputs.public),
        "trusted_release_source_public_key_path": str(inputs.release_source.public),
        "expected_release_source": inputs.release_source.source,
        "expected_release_source_context": inputs.release_source.context,
        "expected_release_source_producer": inputs.release_source.producer,
        "expected_release_source_admitter": inputs.release_source.admitter,
        "expected_release_source_bootstrap_guard_sha256": "a" * 64,
        "expected_release_source_github_policy": inputs.release_source.policy,
        "expected_release_source_git_executable_sha256": (
            inputs.release_source.git_executable.executable_sha256
        ),
        "expected_release_source_github_cli_executable_sha256": (
            inputs.release_source.provider_isolation.executable_sha256
        ),
        "expected_release_source_provider_isolation_uid": (
            inputs.release_source.provider_isolation.uid
        ),
        "expected_release_source_provider_isolation_gid": (
            inputs.release_source.provider_isolation.gid
        ),
        "expected_builder": inputs.builder,
        "expected_admitter": inputs.admitter,
        "expected_key_separation": inputs.key_separation,
        "expected_git_executable_sha256": inputs.git_executable.executable_sha256,
        "expected_github_cli_executable_sha256": (
            inputs.provider_isolation.executable_sha256
        ),
        "expected_provider_isolation_uid": inputs.provider_isolation.uid,
        "expected_provider_isolation_gid": inputs.provider_isolation.gid,
    }
    arguments.update(overrides)
    return release_artifact_admission.verify_release_artifact_admission(
        str(inputs.output),
        str(inputs.artifact),
        **arguments,  # type: ignore[arg-type]
    )


def test_round_trip_binds_source_artifact_builder_admitter_and_rotated_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    sealed = _seal(inputs)
    verified = _verify(inputs)

    assert sealed.decision == verified.decision == "ALLOW"
    assert sealed.manifest["format"] == (
        release_artifact_admission.RELEASE_ARTIFACT_ADMISSION_FORMAT
    )
    assert sealed.manifest["builder"] == inputs.builder
    assert sealed.manifest["admitter"] == inputs.admitter
    assert sealed.manifest["release_source"]["target_commit_sha"] == (
        inputs.release_source.source["target_commit_sha"]
    )
    assert sealed.manifest["toolchain"] == {
        "git": {"sha256": "7" * 64},
        "github_cli": {"sha256": "8" * 64},
        "provider_isolation": {"platform": "posix", "uid": 60001, "gid": 60002},
    }
    assert inputs.release_source.git_executable.executable_sha256 == "2" * 64
    assert inputs.release_source.provider_isolation.executable_sha256 == "1" * 64
    assert verified.artifact.sha256 == sha256_bytes(inputs.artifact.read_bytes())
    assert len(inputs.provider_calls) == 1


def test_cli_round_trip_keeps_nested_and_outer_trust_inputs_distinct(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    environment, event = _runtime_inputs(inputs.builder, inputs.admitter)
    event_path = tmp_path / "workflow-run-event.json"
    event_path.write_bytes(canonical_json_bytes(event))
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))

    objects = {
        "builder": inputs.builder,
        "admitter": inputs.admitter,
        "source": inputs.release_source.source,
        "context": inputs.release_source.context,
        "producer": inputs.release_source.producer,
        "source-admitter": inputs.release_source.admitter,
        "source-policy": inputs.release_source.policy,
    }
    object_paths: dict[str, Path] = {}
    for name, value in objects.items():
        path = tmp_path / f"{name}.json"
        path.write_bytes(canonical_json_bytes(value))
        object_paths[name] = path

    def pinned_git(path: str, digest: str) -> GitExecutablePin:
        assert path == inputs.git_executable.executable_path
        assert digest == inputs.git_executable.executable_sha256
        return inputs.git_executable

    def isolated_provider(
        path: str,
        digest: str,
        *,
        uid: int,
        gid: int,
    ) -> github_attestation.GitHubAttestationProviderIsolation:
        assert path == inputs.provider_isolation.executable_path
        assert digest == inputs.provider_isolation.executable_sha256
        assert uid == inputs.provider_isolation.uid
        assert gid == inputs.provider_isolation.gid
        return inputs.provider_isolation

    monkeypatch.setattr(finalizer_derivation, "git_executable_pin", pinned_git)
    monkeypatch.setattr(
        github_attestation,
        "github_attestation_provider_isolation",
        isolated_provider,
    )

    earlier_keys = inputs.release_source.separation_public_keys
    registry_args = [
        "--trusted-finalizer-pub",
        str(earlier_keys["trusted_finalizer"]),
        "--artifact-admission-v1-pub",
        str(earlier_keys["artifact_admission_v1"]),
        "--artifact-digest-admission-v2-pub",
        str(earlier_keys["artifact_digest_admission_v2"]),
        "--release-source-finalizer-v1-pub",
        str(earlier_keys["release_source_finalizer_v1"]),
        "--release-source-admission-v2-pub",
        str(inputs.release_source.public),
    ]
    nested_args = [
        "--expected-release-source",
        str(object_paths["source"]),
        "--expected-release-source-context",
        str(object_paths["context"]),
        "--expected-release-source-producer",
        str(object_paths["producer"]),
        "--expected-release-source-admitter",
        str(object_paths["source-admitter"]),
        "--expected-release-source-bootstrap-guard-sha",
        "a" * 64,
        "--expected-release-source-github-policy",
        str(object_paths["source-policy"]),
        "--expected-release-source-git-executable-sha256",
        inputs.release_source.git_executable.executable_sha256,
        "--expected-release-source-gh-executable-sha256",
        inputs.release_source.provider_isolation.executable_sha256,
        "--expected-release-source-provider-isolation-uid",
        str(inputs.release_source.provider_isolation.uid),
        "--expected-release-source-provider-isolation-gid",
        str(inputs.release_source.provider_isolation.gid),
    ]
    parser = cli.build_parser()
    seal_args = parser.parse_args(
        [
            "seal-github-release-artifact-admission",
            str(inputs.release_source.output),
            str(inputs.artifact),
            "--out",
            str(inputs.output),
            "--builder",
            str(object_paths["builder"]),
            "--admitter",
            str(object_paths["admitter"]),
            *nested_args,
            "--git-repository",
            str(inputs.release_source.repo),
            "--git-executable",
            inputs.git_executable.executable_path,
            "--git-executable-sha256",
            inputs.git_executable.executable_sha256,
            "--gh-executable",
            inputs.provider_isolation.executable_path,
            "--gh-executable-sha256",
            inputs.provider_isolation.executable_sha256,
            "--provider-isolation-uid",
            str(inputs.provider_isolation.uid),
            "--provider-isolation-gid",
            str(inputs.provider_isolation.gid),
            "--sign-key",
            str(inputs.private),
            "--sign-pub",
            str(inputs.public),
            *registry_args,
        ]
    )
    reports: list[str] = []
    assert (
        cli.cmd_seal_github_release_artifact_admission(seal_args, out=reports.append)
        == 0
    )
    sealed_report = json.loads(reports[-1])
    assert sealed_report["status"] == "SEALED"
    assert sealed_report["provider_verified"] is True
    assert len(inputs.provider_calls) == 1

    def provider_must_not_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("detached CLI verification called the live provider")

    monkeypatch.setattr(
        release_artifact_admission,
        "create_github_attestation_receipt",
        provider_must_not_run,
    )
    verify_args = parser.parse_args(
        [
            "verify-github-release-artifact-admission",
            str(inputs.output),
            str(inputs.artifact),
            "--trusted-pub",
            str(inputs.public),
            "--expected-builder",
            str(object_paths["builder"]),
            "--expected-admitter",
            str(object_paths["admitter"]),
            *nested_args,
            "--expected-git-executable-sha256",
            inputs.git_executable.executable_sha256,
            "--expected-gh-executable-sha256",
            inputs.provider_isolation.executable_sha256,
            "--expected-provider-isolation-uid",
            str(inputs.provider_isolation.uid),
            "--expected-provider-isolation-gid",
            str(inputs.provider_isolation.gid),
            *registry_args,
        ]
    )
    reports.clear()
    assert (
        cli.cmd_verify_github_release_artifact_admission(
            verify_args,
            out=reports.append,
        )
        == 0
    )
    verified_report = json.loads(reports[-1])
    assert verified_report["status"] == "VERIFIED"
    assert verified_report["live_provider_reverification"] is False
    assert len(inputs.provider_calls) == 1


def test_runtime_binding_rejects_a_different_head_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    environment, event = _runtime_inputs(inputs.builder, inputs.admitter)
    event["workflow_run"]["head_repository"]["full_name"] = "fork/project"

    with pytest.raises(
        release_artifact_admission.ReleaseArtifactAdmissionError,
        match="head_repository|head repository|full_name",
    ):
        release_artifact_admission.bind_release_artifact_admitter_runtime(
            inputs.builder,
            inputs.admitter,
            source=inputs.release_source.source,
            environment=environment,
            event_payload=event,
        )


def test_rsae_failure_happens_before_provider_or_private_key_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    opened = False

    def fail_source(*_args: object, **_kwargs: object) -> None:
        raise release_artifact_admission.ReleaseArtifactAdmissionError("bad RSAE")

    def private_opened(_path: str) -> None:
        nonlocal opened
        opened = True
        raise AssertionError("private key was opened")

    monkeypatch.setattr(
        release_artifact_admission, "_verify_release_source_snapshot", fail_source
    )
    monkeypatch.setattr(
        "evoom_guard.signing.load_signing_key_snapshot", private_opened
    )

    with pytest.raises(
        release_artifact_admission.ReleaseArtifactAdmissionError, match="bad RSAE"
    ):
        _seal(inputs)
    assert not opened
    assert inputs.provider_calls == []


def test_raw_git_failure_happens_before_provider_or_private_key_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    opened = False

    def fail_blob(**_kwargs: object) -> None:
        raise release_artifact_admission.ReleaseArtifactAdmissionError("bad blob")

    def private_opened(_path: str) -> None:
        nonlocal opened
        opened = True
        raise AssertionError("private key was opened")

    monkeypatch.setattr(release_artifact_admission, "_verify_workflow_blob", fail_blob)
    monkeypatch.setattr(
        "evoom_guard.signing.load_signing_key_snapshot", private_opened
    )

    with pytest.raises(
        release_artifact_admission.ReleaseArtifactAdmissionError, match="bad blob"
    ):
        _seal(inputs)
    assert not opened
    assert inputs.provider_calls == []


def test_provider_workspace_is_removed_before_private_key_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    from evoom_guard import signing

    real_load = signing.load_signing_key_snapshot

    def guarded_load(path: str):
        assert inputs.provider_directories
        assert all(not directory.exists() for directory in inputs.provider_directories)
        return real_load(path)

    monkeypatch.setattr(signing, "load_signing_key_snapshot", guarded_load)
    _seal(inputs)


def test_detached_verify_does_not_contact_the_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    _seal(inputs)

    def provider_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("offline verification contacted GitHub")

    monkeypatch.setattr(
        release_artifact_admission,
        "create_github_attestation_receipt",
        provider_called,
    )
    assert _verify(inputs).decision == "ALLOW"


def test_detached_verify_rejects_changed_artifact_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    _seal(inputs)
    inputs.artifact.write_bytes(b"different artifact\n")

    with pytest.raises(
        release_artifact_admission.ReleaseArtifactAdmissionError,
        match="external artifact|artifact/builder",
    ):
        _verify(inputs)


def test_tampered_retained_provider_output_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    _seal(inputs)
    with zipfile.ZipFile(inputs.output, "r") as archive:
        members = [(name, archive.read(name)) for name in archive.namelist()]
    replaced = [
        (name, data + b" " if name.endswith("attestation-output.json") else data)
        for name, data in members
    ]
    inputs.output.write_bytes(canonical_archive_bytes(replaced))

    with pytest.raises(
        release_artifact_admission.ReleaseArtifactAdmissionError,
        match="raw output bytes|descriptor",
    ):
        release_artifact_admission.inspect_release_artifact_admission(
            str(inputs.output)
        )


def test_existing_output_fails_before_a_second_provider_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    _seal(inputs)
    original = inputs.output.read_bytes()

    with pytest.raises(
        release_artifact_admission.ReleaseArtifactAdmissionError,
        match="refusing to overwrite",
    ):
        _seal(inputs)
    assert inputs.output.read_bytes() == original
    assert len(inputs.provider_calls) == 1


def test_sixth_key_cannot_reuse_the_rsae_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    with pytest.raises(
        release_artifact_admission.ReleaseArtifactAdmissionError,
        match="earlier trust domain",
    ):
        _seal(
            inputs,
            expected_signing_key_id=inputs.key_separation[
                "release_source_admission_v2"
            ],
        )
    assert inputs.provider_calls == []


def test_forged_runtime_dataclass_is_not_an_admission_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    forged = release_artifact_admission.RuntimeBoundReleaseArtifactAdmitter(
        builder=copy.deepcopy(inputs.builder),
        admitter=copy.deepcopy(inputs.admitter),
    )
    with pytest.raises(
        release_artifact_admission.ReleaseArtifactAdmissionError,
        match="not bound",
    ):
        _seal(inputs, admitter=forged)
    assert inputs.provider_calls == []


def test_builder_and_admitter_are_closed_world_objects() -> None:
    builder = {
        "workflow_repository": "owner/project",
        "workflow_repository_id": "1",
        "workflow_id": "2",
        "workflow_path": ".github/workflows/build.yml",
        "workflow_blob_sha": "a" * 40,
        "workflow_run_id": "3",
        "workflow_run_attempt": 1,
        "workflow_event": "workflow_dispatch",
        "workflow_ref": "refs/heads/main",
        "workflow_commit_sha": "b" * 40,
        "runner_class": "github-hosted",
        "unknown": True,
    }
    with pytest.raises(
        release_artifact_admission.ReleaseArtifactAdmissionError,
        match="unknown",
    ):
        release_artifact_admission.validate_release_artifact_builder(builder)


def test_manifest_json_is_strictly_canonical(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    sealed = _seal(inputs)
    inspected = release_artifact_admission.inspect_release_artifact_admission(
        sealed.bundle_path
    )
    decoded = json.loads(inspected.manifest_bytes)
    assert canonical_json_bytes(decoded) == inspected.manifest_bytes
    assert os.path.getsize(sealed.bundle_path) <= (
        release_artifact_admission.MAX_RELEASE_ARTIFACT_ADMISSION_ARCHIVE_BYTES
    )


def test_manifest_matches_the_published_closed_world_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    sealed = _seal(inputs)
    schema_path = (
        Path(__file__).parents[1]
        / "evoom_guard"
        / "schemas"
        / "release-artifact-admission-1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    Draft202012Validator.check_schema(schema)
    assert list(Draft202012Validator(schema).iter_errors(sealed.manifest)) == []
