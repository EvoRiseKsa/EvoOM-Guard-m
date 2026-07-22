from __future__ import annotations

import copy
import json
import os
import zipfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from test_github_attestation import _verified_gh_output
from test_release_source_finalizer import _git
from test_release_source_producer_receipt import _receipt_inputs

from evoom_guard import (
    finalizer_derivation,
    github_attestation,
    release_source_producer_receipt,
)
from evoom_guard.admission import release_source as release_source_admission
from evoom_guard.cli import main as cli_main
from evoom_guard.evidence_bundle import _archive_bytes, _canonical_json, _sha256
from evoom_guard.finalizer_derivation import GitExecutablePin
from evoom_guard.release_source_finalizer import (
    RELEASE_SOURCE_EVIDENCE_DOMAIN,
    release_source_decision,
)
from evoom_guard.signing import (
    generate_keypair,
    public_key_id,
    sign_bytes,
)


@dataclass
class _AdmissionInputs:
    attested: release_source_producer_receipt.AttestedReleaseSourceProducerReceipt
    source: dict[str, Any]
    context: dict[str, Any]
    producer: dict[str, Any]
    admitter: dict[str, Any]
    runtime_admitter: release_source_producer_receipt.RuntimeBoundReleaseSourceAdmitter
    policy: dict[str, Any]
    git_executable: GitExecutablePin
    provider_isolation: github_attestation.GitHubAttestationProviderIsolation
    repo: Path
    verdict: Path
    handoff: Path
    producer_receipt: Path
    private: Path
    public: Path
    key_separation: dict[str, str]
    separation_public_keys: dict[str, Path]
    output: Path


def _keys(tmp_path: Path, name: str) -> tuple[Path, Path]:
    private = tmp_path / f"{name}.private.pem"
    public = tmp_path / f"{name}.public.pem"
    generate_keypair(str(private), str(public))
    return private, public


def _provider_files(
    artifact_path: str,
    receipt_path: str,
    raw_output_path: str,
    **kwargs: object,
) -> github_attestation.CreatedGitHubAttestationReceipt:
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
        sha256=_sha256(artifact_bytes), size=len(artifact_bytes)
    )
    raw = _verified_gh_output(
        artifact_sha256=artifact.sha256,
        repository=policy.repository,
        signer_workflow=policy.signer_workflow,
        signer_digest=policy.signer_digest,
        source_ref=policy.source_ref,
        source_digest=policy.source_digest,
        issuer=policy.cert_oidc_issuer,
        run_id="987654322",
        run_attempt=1,
    )
    receipt = {
        "format": github_attestation.GITHUB_ATTESTATION_RECEIPT_FORMAT,
        "artifact": artifact.as_dict(),
        "verification_policy": policy.as_dict(),
        "verification_output": {
            "sha256": _sha256(raw),
            "size": len(raw),
            "verified_attestation_count": 1,
        },
    }
    raw_path = Path(raw_output_path).resolve()
    provider_receipt_path = Path(receipt_path).resolve()
    raw_path.write_bytes(raw)
    provider_receipt_path.write_bytes(_canonical_json(receipt))
    return github_attestation.CreatedGitHubAttestationReceipt(
        receipt_path=str(provider_receipt_path),
        raw_output_path=str(raw_path),
        artifact=artifact,
        policy=policy,
        verified_attestation_count=1,
    )


def _admitter_runtime_inputs(
    admitter: dict[str, Any],
    producer: dict[str, Any],
) -> tuple[dict[str, str], dict[str, Any]]:
    environment = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": admitter["workflow_repository"],
        "GITHUB_REPOSITORY_ID": admitter["workflow_repository_id"],
        "GITHUB_RUN_ID": admitter["workflow_run_id"],
        "GITHUB_RUN_ATTEMPT": str(admitter["workflow_run_attempt"]),
        "GITHUB_EVENT_NAME": "workflow_run",
        "GITHUB_REF": admitter["workflow_ref"],
        "GITHUB_SHA": admitter["workflow_commit_sha"],
        "GITHUB_WORKFLOW_REF": (
            f"{admitter['workflow_repository']}/{admitter['workflow_path']}"
            f"@{admitter['workflow_ref']}"
        ),
        "GITHUB_WORKFLOW_SHA": admitter["workflow_commit_sha"],
        "RUNNER_ENVIRONMENT": "github-hosted",
    }
    event_payload = {
        "repository": {
            "full_name": admitter["workflow_repository"],
            "id": int(admitter["workflow_repository_id"]),
        },
        "workflow_run": {
            "id": int(producer["workflow_run_id"]),
            "run_attempt": producer["workflow_run_attempt"],
            "workflow_id": int(producer["workflow_id"]),
            "path": producer["workflow_path"],
            "head_sha": producer["workflow_commit_sha"],
            "head_branch": "main",
            "event": producer["workflow_event"],
            "status": "completed",
            "conclusion": "success",
        },
    }
    return environment, event_payload


def _inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _AdmissionInputs:
    repo, verdict, handoff, source, context, producer, target = _receipt_inputs(
        tmp_path,
        include_admitter=True,
    )
    producer_receipt = tmp_path / "producer-receipt.json"
    release_source_producer_receipt.create_release_source_producer_receipt(
        str(verdict),
        str(handoff),
        str(producer_receipt),
        source=source,
        context=context,
        bootstrap_guard_sha256="a" * 64,
        producer=producer,
        git_repository=str(repo),
    )
    policy = {
        "repository": "owner/project",
        "signer_workflow": (
            "owner/project/.github/workflows/evoguard-produce-release-source-receipt.yml"
        ),
        "signer_digest": target,
        "source_ref": "refs/heads/main",
        "source_digest": target,
        "cert_oidc_issuer": github_attestation.GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
    }
    private, public = _keys(tmp_path, "release-source-admission-v2")
    provider_isolation = github_attestation.GitHubAttestationProviderIsolation(
        executable_path=str((tmp_path / "trusted-gh").resolve()),
        executable_sha256="1" * 64,
        uid=65534,
        gid=65534,
    )
    git_executable = object.__new__(GitExecutablePin)
    object.__setattr__(
        git_executable,
        "executable_path",
        str((tmp_path / "trusted-git").resolve()),
    )
    object.__setattr__(git_executable, "executable_sha256", "2" * 64)
    real_reader = finalizer_derivation._GitReader

    class _UnpinnedFixtureReader(real_reader):
        def __init__(
            self,
            repository: str,
            *,
            bare: bool,
            git_executable: GitExecutablePin | None = None,
        ) -> None:
            super().__init__(repository, bare=bare)

    monkeypatch.setattr(finalizer_derivation, "_GitReader", _UnpinnedFixtureReader)
    real_derive_release_source_bindings = (
        release_source_producer_receipt.derive_release_source_bindings
    )

    def _derive_without_test_pin(**kwargs: Any):
        kwargs.pop("git_executable", None)
        return real_derive_release_source_bindings(**kwargs)

    monkeypatch.setattr(
        release_source_producer_receipt,
        "derive_release_source_bindings",
        _derive_without_test_pin,
    )
    monkeypatch.setattr(
        release_source_producer_receipt,
        "create_github_attestation_receipt",
        _provider_files,
    )
    monkeypatch.setattr(
        release_source_producer_receipt,
        "validate_provider_isolated_signing_key_path",
        lambda path, _isolation: path,
    )
    attested = release_source_producer_receipt.reverify_attested_release_source_producer_receipt(
        str(producer_receipt),
        str(handoff),
        str(verdict),
        expected_source=source,
        expected_context=context,
        expected_producer=producer,
        expected_bootstrap_guard_sha256="a" * 64,
        expected_github_policy=policy,
        git_repository=str(repo),
        github_receipt_path=str(tmp_path / "github-receipt.json"),
        github_raw_output_path=str(tmp_path / "github-output.json"),
        gh_executable=provider_isolation.executable_path,
        provider_isolation=provider_isolation,
        protected_signing_key_path=str(private),
        git_executable=git_executable,
    )
    admitter = {
        "workflow_repository": "owner/project",
        "workflow_repository_id": "12345",
        "workflow_id": "66666",
        "workflow_path": ".github/workflows/evoguard-admit-release-source.yml",
        "workflow_blob_sha": _git(
            repo,
            "rev-parse",
            f"{target}:.github/workflows/evoguard-admit-release-source.yml",
        ),
        "workflow_run_id": "987654323",
        "workflow_run_attempt": 1,
        "workflow_event": "workflow_run",
        "workflow_ref": "refs/heads/main",
        "workflow_commit_sha": target,
        "trigger_workflow_id": producer["workflow_id"],
        "trigger_workflow_path": producer["workflow_path"],
        "trigger_workflow_blob_sha": producer["workflow_blob_sha"],
        "trigger_workflow_run_id": producer["workflow_run_id"],
        "trigger_workflow_run_attempt": producer["workflow_run_attempt"],
        "runner_class": "github-hosted",
    }
    runtime_environment, event_payload = _admitter_runtime_inputs(admitter, producer)
    runtime_admitter = (
        release_source_producer_receipt.validate_release_source_admitter_runtime_environment(
            admitter,
            producer,
            environment=runtime_environment,
            event_payload=event_payload,
        )
    )
    separation_public_keys: dict[str, Path] = {}
    key_separation: dict[str, str] = {}
    for domain in sorted(release_source_admission.RELEASE_SOURCE_ADMISSION_DISTINCT_KEY_DOMAINS):
        _other_private, other_public = _keys(tmp_path, domain)
        separation_public_keys[domain] = other_public
        key_separation[domain] = public_key_id(str(other_public))
    return _AdmissionInputs(
        attested=attested,
        source=source,
        context=context,
        producer=producer,
        admitter=admitter,
        runtime_admitter=runtime_admitter,
        policy=policy,
        git_executable=git_executable,
        provider_isolation=provider_isolation,
        repo=repo,
        verdict=verdict,
        handoff=handoff,
        producer_receipt=producer_receipt,
        private=private,
        public=public,
        key_separation=key_separation,
        separation_public_keys=separation_public_keys,
        output=tmp_path / "release-source-admission.rsae",
    )


def _seal(inputs: _AdmissionInputs) -> release_source_admission.SealedReleaseSourceAdmission:
    return release_source_admission.seal_release_source_admission(
        inputs.attested,
        str(inputs.output),
        admitter=inputs.runtime_admitter,
        key_separation=inputs.key_separation,
        git_repository=str(inputs.repo),
        git_executable=inputs.git_executable,
        provider_isolation=inputs.provider_isolation,
        private_key_path=str(inputs.private),
        signing_public_key_path=str(inputs.public),
        expected_signing_key_id=public_key_id(str(inputs.public)),
    )


def _verify(
    inputs: _AdmissionInputs,
    **overrides: object,
) -> release_source_admission.VerifiedReleaseSourceAdmission:
    arguments: dict[str, object] = {
        "trusted_public_key_path": str(inputs.public),
        "expected_source": inputs.source,
        "expected_context": inputs.context,
        "expected_producer": inputs.producer,
        "expected_admitter": inputs.admitter,
        "expected_bootstrap_guard_sha256": "a" * 64,
        "expected_github_policy": inputs.policy,
        "expected_key_separation": inputs.key_separation,
        "expected_git_executable_sha256": inputs.git_executable.executable_sha256,
        "expected_github_cli_executable_sha256": (
            inputs.provider_isolation.executable_sha256
        ),
        "expected_provider_isolation_uid": inputs.provider_isolation.uid,
        "expected_provider_isolation_gid": inputs.provider_isolation.gid,
    }
    arguments.update(overrides)
    return release_source_admission.verify_release_source_admission(
        str(inputs.output), **arguments  # type: ignore[arg-type]
    )


def _archive_members(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path, "r") as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def _replace_archive(path: Path, replacements: dict[str, bytes]) -> None:
    members = _archive_members(path)
    members.update(replacements)
    path.write_bytes(
        _archive_bytes(
            (name, members[name])
            for name in release_source_admission._ARCHIVE_PATHS
        )
    )


def test_v2_round_trip_binds_all_bytes_and_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    sealed = _seal(inputs)
    verified = _verify(inputs)

    assert sealed.decision == verified.decision == "ALLOW"
    manifest = verified.bundle.manifest
    assert manifest["format"] == release_source_admission.RELEASE_SOURCE_ADMISSION_FORMAT
    assert manifest["authentication"] == {
        "algorithm": "Ed25519",
        "key_id": public_key_id(str(inputs.public)),
        "purpose": "evoguard-release-source-admission-v2",
        "key_domain": "release-source-admission-v2",
        "signature_path": "admission.sig",
    }
    assert manifest["replay"] == {
        "evaluation": {"run_id": "987654321", "run_attempt": 1},
        "producer": {"run_id": "987654322", "run_attempt": 1},
        "trigger": {"run_id": "987654321", "run_attempt": 1},
        "admitter": {"run_id": "987654323", "run_attempt": 1},
    }
    assert manifest["admitter"] == inputs.admitter
    assert manifest["toolchain"] == {
        "git": {"sha256": inputs.git_executable.executable_sha256},
        "github_cli": {"sha256": inputs.provider_isolation.executable_sha256},
        "provider_isolation": {
            "platform": "posix",
            "uid": inputs.provider_isolation.uid,
            "gid": inputs.provider_isolation.gid,
        },
    }
    assert manifest["key_separation"] == inputs.key_separation
    schema_path = (
        Path(release_source_admission.__file__).parents[1]
        / "schemas"
        / "release-source-admission-2.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(manifest)
    assert release_source_decision(verified.bundle.manifest) == "DENY"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("expected_git_executable_sha256", "3" * 64),
        ("expected_github_cli_executable_sha256", "4" * 64),
        ("expected_provider_isolation_uid", 65533),
        ("expected_provider_isolation_gid", 65532),
    ],
)
def test_v2_verifier_requires_external_toolchain_pins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    value: object,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    _seal(inputs)
    with pytest.raises(
        release_source_admission.ReleaseSourceAdmissionError,
        match="does not match external",
    ):
        _verify(inputs, **{name: value})


def test_v2_cli_round_trip_uses_external_trust_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    monkeypatch.setattr(
        finalizer_derivation,
        "git_executable_pin",
        lambda _path, _digest: inputs.git_executable,
    )
    event_path = tmp_path / "github-event.json"
    event_path.write_bytes(
        _canonical_json(
            {
                "repository": {
                    "full_name": inputs.admitter["workflow_repository"],
                    "id": int(inputs.admitter["workflow_repository_id"]),
                },
                "workflow_run": {
                    "id": int(inputs.producer["workflow_run_id"]),
                    "run_attempt": inputs.producer["workflow_run_attempt"],
                    "workflow_id": int(inputs.producer["workflow_id"]),
                    "path": inputs.producer["workflow_path"],
                    "head_sha": inputs.producer["workflow_commit_sha"],
                    "head_branch": "main",
                    "event": inputs.producer["workflow_event"],
                    "status": "completed",
                    "conclusion": "success",
                },
            }
        )
    )
    runtime_environment = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": inputs.admitter["workflow_repository"],
        "GITHUB_REPOSITORY_ID": inputs.admitter["workflow_repository_id"],
        "GITHUB_RUN_ID": inputs.admitter["workflow_run_id"],
        "GITHUB_RUN_ATTEMPT": str(inputs.admitter["workflow_run_attempt"]),
        "GITHUB_EVENT_NAME": "workflow_run",
        "GITHUB_REF": inputs.admitter["workflow_ref"],
        "GITHUB_SHA": inputs.admitter["workflow_commit_sha"],
        "GITHUB_WORKFLOW_REF": (
            f"{inputs.admitter['workflow_repository']}/"
            f"{inputs.admitter['workflow_path']}@{inputs.admitter['workflow_ref']}"
        ),
        "GITHUB_WORKFLOW_SHA": inputs.admitter["workflow_commit_sha"],
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_EVENT_PATH": str(event_path),
    }
    for name, value in runtime_environment.items():
        monkeypatch.setenv(name, str(value))
    external_files = {
        "source": (tmp_path / "expected-source.json", inputs.source),
        "context": (tmp_path / "expected-context.json", inputs.context),
        "producer": (tmp_path / "expected-producer.json", inputs.producer),
        "admitter": (tmp_path / "expected-admitter.json", inputs.admitter),
        "policy": (tmp_path / "expected-policy.json", inputs.policy),
    }
    for path, value in external_files.values():
        path.write_bytes(_canonical_json(value))
    output = tmp_path / "cli-source-admission.rsae"

    assert (
        cli_main(
            [
                "seal-release-source-admission",
                str(inputs.producer_receipt),
                str(inputs.handoff),
                str(inputs.verdict),
                "--out",
                str(output),
                "--source",
                str(external_files["source"][0]),
                "--context",
                str(external_files["context"][0]),
                "--producer",
                str(external_files["producer"][0]),
                "--admitter",
                str(external_files["admitter"][0]),
                "--bootstrap-guard-sha",
                "a" * 64,
                "--github-policy",
                str(external_files["policy"][0]),
                "--git-repository",
                str(inputs.repo),
                "--git-executable",
                inputs.git_executable.executable_path,
                "--git-executable-sha256",
                inputs.git_executable.executable_sha256,
                "--github-receipt-out",
                str(tmp_path / "cli-github-receipt.json"),
                "--github-raw-output-out",
                str(tmp_path / "cli-github-output.json"),
                "--gh-executable",
                str(tmp_path / "trusted-gh"),
                "--gh-executable-sha256",
                "1" * 64,
                "--provider-isolation-uid",
                "65534",
                "--provider-isolation-gid",
                "65534",
                "--sign-key",
                str(inputs.private),
                "--sign-pub",
                str(inputs.public),
                "--trusted-finalizer-pub",
                str(inputs.separation_public_keys["trusted_finalizer"]),
                "--artifact-admission-v1-pub",
                str(inputs.separation_public_keys["artifact_admission_v1"]),
                "--artifact-digest-admission-v2-pub",
                str(inputs.separation_public_keys["artifact_digest_admission_v2"]),
                "--release-source-finalizer-v1-pub",
                str(inputs.separation_public_keys["release_source_finalizer_v1"]),
            ]
        )
        == 0
    )
    sealed_report = json.loads(capsys.readouterr().out)
    assert sealed_report["status"] == "SEALED"
    assert sealed_report["decision"] == "ALLOW"

    assert (
        cli_main(
            [
                "verify-release-source-admission",
                str(output),
                "--trusted-pub",
                str(inputs.public),
                "--expected-source",
                str(external_files["source"][0]),
                "--expected-context",
                str(external_files["context"][0]),
                "--expected-producer",
                str(external_files["producer"][0]),
                "--expected-admitter",
                str(external_files["admitter"][0]),
                "--expected-bootstrap-guard-sha",
                "a" * 64,
                "--expected-github-policy",
                str(external_files["policy"][0]),
                "--expected-git-executable-sha256",
                inputs.git_executable.executable_sha256,
                "--expected-gh-executable-sha256",
                inputs.provider_isolation.executable_sha256,
                "--expected-provider-isolation-uid",
                str(inputs.provider_isolation.uid),
                "--expected-provider-isolation-gid",
                str(inputs.provider_isolation.gid),
                "--trusted-finalizer-pub",
                str(inputs.separation_public_keys["trusted_finalizer"]),
                "--artifact-admission-v1-pub",
                str(inputs.separation_public_keys["artifact_admission_v1"]),
                "--artifact-digest-admission-v2-pub",
                str(inputs.separation_public_keys["artifact_digest_admission_v2"]),
                "--release-source-finalizer-v1-pub",
                str(inputs.separation_public_keys["release_source_finalizer_v1"]),
            ]
        )
        == 0
    )
    verified_report = json.loads(capsys.readouterr().out)
    assert verified_report["status"] == "VERIFIED"
    assert verified_report["decision"] == "ALLOW"


def test_admitter_runtime_rejects_replayed_run_attempt_and_trigger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    environment = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": inputs.admitter["workflow_repository"],
        "GITHUB_REPOSITORY_ID": inputs.admitter["workflow_repository_id"],
        "GITHUB_RUN_ID": inputs.admitter["workflow_run_id"],
        "GITHUB_RUN_ATTEMPT": str(inputs.admitter["workflow_run_attempt"]),
        "GITHUB_EVENT_NAME": "workflow_run",
        "GITHUB_REF": inputs.admitter["workflow_ref"],
        "GITHUB_SHA": inputs.admitter["workflow_commit_sha"],
        "GITHUB_WORKFLOW_REF": (
            f"{inputs.admitter['workflow_repository']}/"
            f"{inputs.admitter['workflow_path']}@{inputs.admitter['workflow_ref']}"
        ),
        "GITHUB_WORKFLOW_SHA": inputs.admitter["workflow_commit_sha"],
        "RUNNER_ENVIRONMENT": "github-hosted",
    }
    event_payload = {
        "repository": {
            "full_name": inputs.admitter["workflow_repository"],
            "id": int(inputs.admitter["workflow_repository_id"]),
        },
        "workflow_run": {
            "id": int(inputs.producer["workflow_run_id"]),
            "run_attempt": inputs.producer["workflow_run_attempt"],
            "workflow_id": int(inputs.producer["workflow_id"]),
            "path": inputs.producer["workflow_path"],
            "head_sha": inputs.producer["workflow_commit_sha"],
            "head_branch": "main",
            "event": inputs.producer["workflow_event"],
            "status": "completed",
            "conclusion": "success",
        },
    }

    changed_environment = dict(environment)
    changed_environment["GITHUB_RUN_ATTEMPT"] = "2"
    with pytest.raises(
        release_source_producer_receipt.ReleaseSourceProducerReceiptError,
        match="GITHUB_RUN_ATTEMPT",
    ):
        release_source_producer_receipt.validate_release_source_admitter_runtime_environment(
            inputs.admitter,
            inputs.producer,
            environment=changed_environment,
            event_payload=event_payload,
        )

    changed_event = copy.deepcopy(event_payload)
    changed_event["workflow_run"]["run_attempt"] = 2
    with pytest.raises(
        release_source_producer_receipt.ReleaseSourceProducerReceiptError,
        match="event run_attempt",
    ):
        release_source_producer_receipt.validate_release_source_admitter_runtime_environment(
            inputs.admitter,
            inputs.producer,
            environment=environment,
            event_payload=changed_event,
        )


def test_v1_decision_remains_deny_only_after_v2_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    record = inputs.attested.verified.handoff.verdict
    assert record["verdict"] == "PASS"
    assert release_source_decision(record) == "DENY"


def test_manually_constructed_attested_object_cannot_reach_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    forged = release_source_producer_receipt.AttestedReleaseSourceProducerReceipt(
        verified=inputs.attested.verified,
        github_receipt=inputs.attested.github_receipt,
    )

    import evoom_guard.signing as signing

    monkeypatch.setattr(
        signing,
        "_load_private_key_snapshot",
        lambda *_args, **_kwargs: pytest.fail("key opened before capability validation"),
    )
    with pytest.raises(release_source_admission.ReleaseSourceAdmissionError, match="freshly verified"):
        release_source_admission.seal_release_source_admission(
            forged,
            str(inputs.output),
            admitter=inputs.runtime_admitter,
            key_separation=inputs.key_separation,
            git_repository=str(inputs.repo),
            git_executable=inputs.git_executable,
            provider_isolation=inputs.provider_isolation,
            private_key_path=str(inputs.private),
            signing_public_key_path=str(inputs.public),
            expected_signing_key_id=public_key_id(str(inputs.public)),
        )
    assert not inputs.output.exists()


def test_plain_admitter_dict_cannot_reach_private_key_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    import evoom_guard.signing as signing

    monkeypatch.setattr(
        signing,
        "_load_private_key_snapshot",
        lambda *_args, **_kwargs: pytest.fail(
            "plain C selector reached the admission key"
        ),
    )
    with pytest.raises(
        release_source_admission.ReleaseSourceAdmissionError,
        match="runtime-bound admitter capability",
    ):
        release_source_admission.seal_release_source_admission(  # type: ignore[arg-type]
            inputs.attested,
            str(inputs.output),
            admitter=inputs.admitter,
            key_separation=inputs.key_separation,
            git_repository=str(inputs.repo),
            git_executable=inputs.git_executable,
            provider_isolation=inputs.provider_isolation,
            private_key_path=str(inputs.private),
            signing_public_key_path=str(inputs.public),
            expected_signing_key_id=public_key_id(str(inputs.public)),
        )
    assert not inputs.output.exists()


def test_unisolated_provider_result_cannot_reach_admission_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    unisolated = release_source_producer_receipt.reverify_attested_release_source_producer_receipt(
        str(inputs.producer_receipt),
        str(inputs.handoff),
        str(inputs.verdict),
        expected_source=inputs.source,
        expected_context=inputs.context,
        expected_producer=inputs.producer,
        expected_bootstrap_guard_sha256="a" * 64,
        expected_github_policy=inputs.policy,
        git_repository=str(inputs.repo),
        github_receipt_path=str(tmp_path / "unisolated-github-receipt.json"),
        github_raw_output_path=str(tmp_path / "unisolated-github-output.json"),
    )
    import evoom_guard.signing as signing

    monkeypatch.setattr(
        signing,
        "_load_private_key_snapshot",
        lambda *_args, **_kwargs: pytest.fail("unisolated provider result reached key open"),
    )
    output = tmp_path / "unisolated.rsae"
    with pytest.raises(
        release_source_admission.ReleaseSourceAdmissionError,
        match="isolated provider verification",
    ):
        release_source_admission.seal_release_source_admission(
            unisolated,
            str(output),
            admitter=inputs.runtime_admitter,
            key_separation=inputs.key_separation,
            git_repository=str(inputs.repo),
            git_executable=inputs.git_executable,
            provider_isolation=inputs.provider_isolation,
            private_key_path=str(inputs.private),
            signing_public_key_path=str(inputs.public),
            expected_signing_key_id=public_key_id(str(inputs.public)),
        )
    assert not output.exists()


def test_admission_capability_requires_pinned_git_before_provider_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    isolation = github_attestation.GitHubAttestationProviderIsolation(
        executable_path=str((tmp_path / "trusted-gh-second").resolve()),
        executable_sha256="3" * 64,
        uid=65533,
        gid=65533,
    )
    monkeypatch.setattr(
        release_source_producer_receipt,
        "create_github_attestation_receipt",
        lambda *_args, **_kwargs: pytest.fail("provider launched without pinned Git"),
    )
    with pytest.raises(
        release_source_producer_receipt.ReleaseSourceProducerReceiptError,
        match="requires a pinned Git executable",
    ):
        release_source_producer_receipt.reverify_attested_release_source_producer_receipt(
            str(inputs.producer_receipt),
            str(inputs.handoff),
            str(inputs.verdict),
            expected_source=inputs.source,
            expected_context=inputs.context,
            expected_producer=inputs.producer,
            expected_bootstrap_guard_sha256="a" * 64,
            expected_github_policy=inputs.policy,
            git_repository=str(inputs.repo),
            github_receipt_path=str(tmp_path / "no-pin-receipt.json"),
            github_raw_output_path=str(tmp_path / "no-pin-output.json"),
            gh_executable=isolation.executable_path,
            provider_isolation=isolation,
            protected_signing_key_path=str(inputs.private),
        )


def test_isolated_provider_capability_is_bound_to_exact_signing_key_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    other_private, other_public = _keys(tmp_path, "other-release-source-admission-v2")
    import evoom_guard.signing as signing

    monkeypatch.setattr(
        signing,
        "_load_private_key_snapshot",
        lambda *_args, **_kwargs: pytest.fail("mismatched key path reached key open"),
    )
    output = tmp_path / "wrong-key.rsae"
    with pytest.raises(
        release_source_admission.ReleaseSourceAdmissionError,
        match="exact protected signing-key path",
    ):
        release_source_admission.seal_release_source_admission(
            inputs.attested,
            str(output),
            admitter=inputs.runtime_admitter,
            key_separation=inputs.key_separation,
            git_repository=str(inputs.repo),
            git_executable=inputs.git_executable,
            provider_isolation=inputs.provider_isolation,
            private_key_path=str(other_private),
            signing_public_key_path=str(other_public),
            expected_signing_key_id=public_key_id(str(other_public)),
        )
    assert not output.exists()


def test_admission_capability_is_bound_to_exact_provider_isolation_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    changed_isolation = replace(inputs.provider_isolation, uid=65533)
    import evoom_guard.signing as signing

    monkeypatch.setattr(
        signing,
        "_load_private_key_snapshot",
        lambda *_args, **_kwargs: pytest.fail(
            "mismatched provider contract reached key open"
        ),
    )
    with pytest.raises(
        release_source_admission.ReleaseSourceAdmissionError,
        match="isolated provider verification",
    ):
        release_source_admission.seal_release_source_admission(
            inputs.attested,
            str(inputs.output),
            admitter=inputs.runtime_admitter,
            key_separation=inputs.key_separation,
            git_repository=str(inputs.repo),
            git_executable=inputs.git_executable,
            provider_isolation=changed_isolation,
            private_key_path=str(inputs.private),
            signing_public_key_path=str(inputs.public),
            expected_signing_key_id=public_key_id(str(inputs.public)),
        )
    assert not inputs.output.exists()


def _mutate_attested_receipt(
    attested: release_source_producer_receipt.AttestedReleaseSourceProducerReceipt,
    mutator,
) -> release_source_producer_receipt.AttestedReleaseSourceProducerReceipt:
    payload = copy.deepcopy(attested.verified.receipt.payload)
    mutator(payload)
    inspected = replace(attested.verified.receipt, payload=payload)
    return replace(attested, verified=replace(attested.verified, receipt=inspected))


@pytest.mark.parametrize(
    "case",
    [
        "producer-receipt-bytes",
        "provider-receipt-bytes",
        "provider-raw-bytes",
        "provider-policy",
        "evaluation-attempt",
        "workflow-blob",
        "bootstrap-runtime",
        "replay",
    ],
)
def test_every_pre_key_tamper_fails_before_private_key_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    attested = inputs.attested
    if case == "producer-receipt-bytes":
        bad_receipt = replace(
            attested.verified.receipt,
            receipt_bytes=attested.verified.receipt.receipt_bytes + b"\n",
        )
        attested = replace(attested, verified=replace(attested.verified, receipt=bad_receipt))
    elif case == "provider-receipt-bytes":
        Path(attested.github_receipt.receipt_path).write_bytes(
            Path(attested.github_receipt.receipt_path).read_bytes() + b"\n"
        )
    elif case == "provider-raw-bytes":
        Path(attested.github_receipt.raw_output_path).write_bytes(b"{}")
    elif case == "provider-policy":
        wrong = github_attestation.github_attestation_policy(
            "owner/project",
            inputs.policy["signer_workflow"],
            inputs.policy["source_digest"],
            signer_digest="f" * 40,
            source_ref="refs/heads/main",
            cert_oidc_issuer=github_attestation.GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
        )
        attested = replace(
            attested,
            github_receipt=replace(attested.github_receipt, policy=wrong),
        )
    elif case == "evaluation-attempt":
        attested = _mutate_attested_receipt(
            attested,
            lambda payload: payload["source"].__setitem__("workflow_run_attempt", 2),
        )
    elif case == "workflow-blob":
        attested = _mutate_attested_receipt(
            attested,
            lambda payload: payload["producer"].__setitem__("workflow_blob_sha", "f" * 40),
        )
    elif case == "bootstrap-runtime":
        attested = _mutate_attested_receipt(
            attested,
            lambda payload: payload["bootstrap"].__setitem__(
                "runtime_identity_format", "UNSUPPORTED"
            ),
        )
    elif case == "replay":
        real_replay = release_source_admission._replay_binding

        def wrong_replay(
            source: dict[str, Any],
            producer: dict[str, Any],
            admitter: dict[str, Any],
        ) -> dict[str, Any]:
            replay = real_replay(source, producer, admitter)
            replay["producer"]["run_attempt"] += 1
            return replay

        monkeypatch.setattr(release_source_admission, "_replay_binding", wrong_replay)

    import evoom_guard.signing as signing

    monkeypatch.setattr(
        signing,
        "_load_private_key_snapshot",
        lambda *_args, **_kwargs: pytest.fail(f"key opened for pre-key failure: {case}"),
    )
    with pytest.raises(release_source_admission.ReleaseSourceAdmissionError):
        release_source_admission.seal_release_source_admission(
            attested,
            str(inputs.output),
            admitter=inputs.runtime_admitter,
            key_separation=inputs.key_separation,
            git_repository=str(inputs.repo),
            git_executable=inputs.git_executable,
            provider_isolation=inputs.provider_isolation,
            private_key_path=str(inputs.private),
            signing_public_key_path=str(inputs.public),
            expected_signing_key_id=public_key_id(str(inputs.public)),
        )
    assert not inputs.output.exists()


def test_provider_inputs_must_be_distinct_regular_files_before_key_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    receipt_path = Path(inputs.attested.github_receipt.receipt_path)
    receipt_path.unlink()
    receipt_path.mkdir()

    import evoom_guard.signing as signing

    monkeypatch.setattr(
        signing,
        "_load_private_key_snapshot",
        lambda *_args, **_kwargs: pytest.fail("key opened for non-regular provider receipt"),
    )
    with pytest.raises(release_source_admission.ReleaseSourceAdmissionError, match="regular"):
        _seal(inputs)


def test_provider_symlink_is_rejected_before_key_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    receipt_path = Path(inputs.attested.github_receipt.receipt_path)
    target = tmp_path / "provider-target.json"
    target.write_bytes(receipt_path.read_bytes())
    receipt_path.unlink()
    try:
        os.symlink(target, receipt_path)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    import evoom_guard.signing as signing

    monkeypatch.setattr(
        signing,
        "_load_private_key_snapshot",
        lambda *_args, **_kwargs: pytest.fail("key opened for symlink provider receipt"),
    )
    with pytest.raises(release_source_admission.ReleaseSourceAdmissionError, match="symlink"):
        _seal(inputs)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("workflow_blob_sha", "f" * 40),
        ("trigger_workflow_run_id", "987654399"),
    ],
)
def test_admitter_selector_and_raw_git_blob_fail_before_private_key_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    admitter = dict(inputs.admitter)
    admitter[field] = value
    environment, event_payload = _admitter_runtime_inputs(admitter, inputs.producer)
    runtime_admitter = (
        release_source_producer_receipt.validate_release_source_admitter_runtime_environment(
            admitter,
            inputs.producer,
            environment=environment,
            event_payload=event_payload,
        )
    )

    import evoom_guard.signing as signing

    monkeypatch.setattr(
        signing,
        "_load_private_key_snapshot",
        lambda *_args, **_kwargs: pytest.fail("key opened for invalid C selector"),
    )
    with pytest.raises(release_source_admission.ReleaseSourceAdmissionError):
        release_source_admission.seal_release_source_admission(
            inputs.attested,
            str(inputs.output),
            admitter=runtime_admitter,
            key_separation=inputs.key_separation,
            git_repository=str(inputs.repo),
            git_executable=inputs.git_executable,
            provider_isolation=inputs.provider_isolation,
            private_key_path=str(inputs.private),
            signing_public_key_path=str(inputs.public),
            expected_signing_key_id=public_key_id(str(inputs.public)),
        )
    assert not inputs.output.exists()


def test_sealing_and_verification_require_the_exact_named_key_separation_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)

    import evoom_guard.signing as signing

    real_load = signing._load_private_key_snapshot
    monkeypatch.setattr(
        signing,
        "_load_private_key_snapshot",
        lambda *_args, **_kwargs: pytest.fail("key opened before exclusions were validated"),
    )
    with pytest.raises(release_source_admission.ReleaseSourceAdmissionError, match="key separation"):
        release_source_admission.seal_release_source_admission(
            inputs.attested,
            str(inputs.output),
            admitter=inputs.runtime_admitter,
            key_separation={},
            git_repository=str(inputs.repo),
            git_executable=inputs.git_executable,
            provider_isolation=inputs.provider_isolation,
            private_key_path=str(inputs.private),
            signing_public_key_path=str(inputs.public),
            expected_signing_key_id=public_key_id(str(inputs.public)),
        )
    monkeypatch.setattr(signing, "_load_private_key_snapshot", real_load)
    _seal(inputs)
    with pytest.raises(release_source_admission.ReleaseSourceAdmissionError, match="key separation"):
        _verify(inputs, expected_key_separation={})


def test_admission_key_cannot_reuse_a_named_domain_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    separation = dict(inputs.key_separation)
    separation["trusted_finalizer"] = public_key_id(str(inputs.public))
    with pytest.raises(release_source_admission.ReleaseSourceAdmissionError, match="trust domain"):
        release_source_admission.seal_release_source_admission(
            inputs.attested,
            str(inputs.output),
            admitter=inputs.runtime_admitter,
            key_separation=separation,
            git_repository=str(inputs.repo),
            git_executable=inputs.git_executable,
            provider_isolation=inputs.provider_isolation,
            private_key_path=str(inputs.private),
            signing_public_key_path=str(inputs.public),
            expected_signing_key_id=public_key_id(str(inputs.public)),
        )


def test_named_key_domains_must_be_complete_and_mutually_distinct(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    _seal(inputs)
    duplicate = dict(inputs.key_separation)
    duplicate["artifact_admission_v1"] = duplicate["trusted_finalizer"]
    with pytest.raises(release_source_admission.ReleaseSourceAdmissionError, match="distinct"):
        _verify(inputs, expected_key_separation=duplicate)


@pytest.mark.parametrize(
    "expectation",
    ["attempt", "workflow-blob", "admitter-attempt", "bootstrap", "policy", "key-separation"],
)
def test_external_replay_and_policy_expectations_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    expectation: str,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    _seal(inputs)
    overrides: dict[str, object] = {}
    if expectation == "attempt":
        source = dict(inputs.source, workflow_run_attempt=2)
        context = dict(inputs.context, run_attempt=2)
        producer = dict(inputs.producer, trigger_workflow_run_attempt=2)
        overrides.update(
            expected_source=source,
            expected_context=context,
            expected_producer=producer,
        )
    elif expectation == "workflow-blob":
        overrides["expected_producer"] = dict(inputs.producer, workflow_blob_sha="f" * 40)
    elif expectation == "admitter-attempt":
        overrides["expected_admitter"] = dict(inputs.admitter, workflow_run_attempt=2)
    elif expectation == "bootstrap":
        overrides["expected_bootstrap_guard_sha256"] = "b" * 64
    elif expectation == "policy":
        overrides["expected_github_policy"] = dict(inputs.policy, signer_digest="f" * 40)
    else:
        changed = dict(inputs.key_separation)
        _private, replacement = _keys(tmp_path, "replacement-domain")
        changed["trusted_finalizer"] = public_key_id(str(replacement))
        overrides["expected_key_separation"] = changed
    with pytest.raises(release_source_admission.ReleaseSourceAdmissionError):
        _verify(inputs, **overrides)


def test_wrong_public_key_and_cross_domain_signature_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    _seal(inputs)
    _wrong_private, wrong_public = _keys(tmp_path, "wrong-admission")
    with pytest.raises(release_source_admission.ReleaseSourceAdmissionError, match="key_id"):
        _verify(inputs, trusted_public_key_path=str(wrong_public))

    inspected = release_source_admission.inspect_release_source_admission(str(inputs.output))
    cross_domain_signature = sign_bytes(
        RELEASE_SOURCE_EVIDENCE_DOMAIN + inspected.manifest_bytes,
        str(inputs.private),
    )
    import base64

    _replace_archive(
        inputs.output,
        {
            release_source_admission.RELEASE_SOURCE_ADMISSION_SIGNATURE_PATH: base64.b64encode(
                cross_domain_signature
            )
        },
    )
    with pytest.raises(release_source_admission.ReleaseSourceAdmissionError, match="signature"):
        _verify(inputs)


def test_wrong_key_domain_tamper_and_noncanonical_archive_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    _seal(inputs)
    members = _archive_members(inputs.output)
    manifest = json.loads(
        members[release_source_admission.RELEASE_SOURCE_ADMISSION_MANIFEST_PATH]
    )
    manifest["authentication"]["key_domain"] = "release-source-finalizer-v1"
    _replace_archive(
        inputs.output,
        {
            release_source_admission.RELEASE_SOURCE_ADMISSION_MANIFEST_PATH: _canonical_json(
                manifest
            )
        },
    )
    with pytest.raises(release_source_admission.ReleaseSourceAdmissionError, match="authentication"):
        release_source_admission.inspect_release_source_admission(str(inputs.output))

    inputs.output.unlink()
    _seal(inputs)
    inputs.output.write_bytes(inputs.output.read_bytes() + b"suffix")
    with pytest.raises(release_source_admission.ReleaseSourceAdmissionError):
        release_source_admission.inspect_release_source_admission(str(inputs.output))


def test_each_evidence_member_is_cryptographically_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    _seal(inputs)
    original = inputs.output.read_bytes()
    tamperable = [
        release_source_admission.RELEASE_SOURCE_ADMISSION_VERDICT_PATH,
        release_source_admission.RELEASE_SOURCE_ADMISSION_HANDOFF_PATH,
        release_source_admission.RELEASE_SOURCE_ADMISSION_PRODUCER_RECEIPT_PATH,
        release_source_admission.RELEASE_SOURCE_ADMISSION_GITHUB_RECEIPT_PATH,
        release_source_admission.RELEASE_SOURCE_ADMISSION_GITHUB_RAW_OUTPUT_PATH,
    ]
    for name in tamperable:
        inputs.output.write_bytes(original)
        members = _archive_members(inputs.output)
        _replace_archive(inputs.output, {name: members[name] + b" "})
        with pytest.raises(release_source_admission.ReleaseSourceAdmissionError):
            release_source_admission.inspect_release_source_admission(str(inputs.output))


def test_output_no_clobber_and_retained_bundle_survives_provider_file_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    _seal(inputs)
    original = inputs.output.read_bytes()
    import evoom_guard.signing as signing

    monkeypatch.setattr(
        signing,
        "_load_private_key_snapshot",
        lambda *_args, **_kwargs: pytest.fail("key opened for an existing output"),
    )
    with pytest.raises(release_source_admission.ReleaseSourceAdmissionError):
        _seal(inputs)
    assert inputs.output.read_bytes() == original

    Path(inputs.attested.github_receipt.receipt_path).unlink()
    Path(inputs.attested.github_receipt.raw_output_path).unlink()
    assert _verify(inputs).decision == "ALLOW"


def test_failed_staging_verification_preserves_existing_forced_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    previous = b"previous-output-must-survive"
    inputs.output.write_bytes(previous)
    import evoom_guard.signing as signing

    monkeypatch.setattr(
        signing,
        "verify_bytes_with_key_id",
        lambda *_args, **_kwargs: (False, public_key_id(str(inputs.public))),
    )
    with pytest.raises(
        release_source_admission.ReleaseSourceAdmissionError,
        match="staged.*failed cryptographic verification",
    ):
        release_source_admission.seal_release_source_admission(
            inputs.attested,
            str(inputs.output),
            admitter=inputs.runtime_admitter,
            key_separation=inputs.key_separation,
            git_repository=str(inputs.repo),
            git_executable=inputs.git_executable,
            provider_isolation=inputs.provider_isolation,
            private_key_path=str(inputs.private),
            signing_public_key_path=str(inputs.public),
            expected_signing_key_id=public_key_id(str(inputs.public)),
            force=True,
        )
    assert inputs.output.read_bytes() == previous


@pytest.mark.parametrize("collision", ["private-key", "provider-receipt", "provider-output"])
def test_output_path_collisions_fail_before_key_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    collision: str,
) -> None:
    inputs = _inputs(tmp_path, monkeypatch)
    if collision == "private-key":
        output = inputs.private
    elif collision == "provider-receipt":
        output = Path(inputs.attested.github_receipt.receipt_path)
    else:
        output = Path(inputs.attested.github_receipt.raw_output_path)

    import evoom_guard.signing as signing

    monkeypatch.setattr(
        signing,
        "_load_private_key_snapshot",
        lambda *_args, **_kwargs: pytest.fail(f"key opened for output collision: {collision}"),
    )
    with pytest.raises(release_source_admission.ReleaseSourceAdmissionError):
        release_source_admission.seal_release_source_admission(
            inputs.attested,
            str(output),
            admitter=inputs.runtime_admitter,
            key_separation=inputs.key_separation,
            git_repository=str(inputs.repo),
            git_executable=inputs.git_executable,
            provider_isolation=inputs.provider_isolation,
            private_key_path=str(inputs.private),
            signing_public_key_path=str(inputs.public),
            expected_signing_key_id=public_key_id(str(inputs.public)),
            force=True,
        )
