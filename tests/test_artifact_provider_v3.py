from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from evoom_guard import github_attestation
from evoom_guard.admission import artifact_provider_v3
from evoom_guard.guard import guard
from evoom_guard.signing import generate_keypair
from evoom_guard.trusted_finalizer import create_finalizer_handoff, seal_finalizer_bundle


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _keys(tmp_path: Path, name: str) -> tuple[Path, Path]:
    private = tmp_path / f"{name}.private.pem"
    public = tmp_path / f"{name}.public.pem"
    generate_keypair(str(private), str(public))
    return private, public


def _finalized_allow(tmp_path: Path):
    repo = tmp_path / "repo"
    tests = repo / "tests"
    tests.mkdir(parents=True)
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tests / "test_app.py").write_text(
        "from app import VALUE\n\n\ndef test_value():\n    assert VALUE == 2\n",
        encoding="utf-8",
    )
    record = guard(
        str(repo),
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        base_sha="a" * 40,
        head_sha="b" * 40,
        base_tree_sha="c" * 40,
        head_tree_sha="d" * 40,
    ).to_dict()
    attestation = record["attestation"]
    source = {
        "pull_request_number": 42,
        "workflow_run_id": "123456",
        "workflow_run_attempt": 1,
        "base_sha": attestation["base_sha"],
        "head_sha": attestation["head_sha"],
    }
    context = {
        "repository": "owner/project",
        "repository_id": "12345",
        "run_id": "123456",
        "run_attempt": 1,
        "base_sha": attestation["base_sha"],
        "head_sha": attestation["head_sha"],
        "base_tree_sha": attestation["base_tree_sha"],
        "head_tree_sha": attestation["head_tree_sha"],
        "candidate_sha256": attestation["candidate_sha256"],
        "policy_sha256": attestation["policy_sha256"],
        "verifier_pack_sha256": attestation["verifier_pack_sha256"],
        "guard_artifact_sha256": "e" * 64,
    }
    verdict = tmp_path / "verdict.json"
    _write_json(verdict, record)
    handoff = tmp_path / "handoff.json"
    create_finalizer_handoff(str(verdict), str(handoff), source=source, context=context)
    finalizer_private, finalizer_public = _keys(tmp_path, "finalizer")
    bundle = tmp_path / "finalized.evb"
    sealed = seal_finalizer_bundle(
        str(handoff),
        str(verdict),
        str(bundle),
        expected_source=source,
        expected_context=context,
        private_key_path=str(finalizer_private),
    )
    assert sealed.decision == "ALLOW"
    return bundle, finalizer_public, source, context


def _policy_kwargs() -> dict[str, object]:
    return {
        "repository": "owner/project",
        "signer_workflow": "owner/project/.github/workflows/build.yml",
        "signer_digest": "b" * 40,
        "source_ref": "refs/heads/main",
        "source_digest": "b" * 40,
        "cert_oidc_issuer": github_attestation.GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
        "workflow_run_id": "987654321",
        "workflow_run_attempt": 2,
    }


def _provider_output(
    *,
    subject_name: str = "ghcr.io/owner/product",
    subject_digest: str = "f" * 64,
    repository: str = "owner/project",
    source_digest: str = "b" * 40,
    signer_digest: str = "b" * 40,
    run_id: str = "987654321",
    run_attempt: int = 2,
) -> bytes:
    source_ref = "refs/heads/main"
    workflow = f"{repository}/.github/workflows/build.yml"
    repository_url = f"https://github.com/{repository}"
    signer_uri = f"https://github.com/{workflow}@{signer_digest}"
    run_uri = f"{repository_url}/actions/runs/{run_id}/attempts/{run_attempt}"
    value = [
        {
            "verificationResult": {
                "signature": {
                    "certificate": {
                        "subjectAlternativeName": signer_uri,
                        "issuer": github_attestation.GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
                        "githubWorkflowRepository": repository,
                        "githubWorkflowSHA": source_digest,
                        "githubWorkflowRef": source_ref,
                        "buildSignerURI": signer_uri,
                        "buildSignerDigest": signer_digest,
                        "runnerEnvironment": "github-hosted",
                        "sourceRepositoryURI": repository_url,
                        "sourceRepositoryDigest": source_digest,
                        "sourceRepositoryRef": source_ref,
                        "runInvocationURI": run_uri,
                    }
                },
                "verifiedIdentity": {"runnerEnvironment": "github-hosted"},
                "statement": {
                    "_type": "https://in-toto.io/Statement/v1",
                    "subject": [
                        {
                            "name": subject_name,
                            "digest": {"sha256": subject_digest},
                        }
                    ],
                    "predicateType": github_attestation.GITHUB_ATTESTATION_PREDICATE_TYPE,
                    "predicate": {
                        "buildDefinition": {
                            "externalParameters": {
                                "workflow": {
                                    "repository": repository_url,
                                    "ref": source_ref,
                                }
                            },
                            "internalParameters": {
                                "github": {"runner_environment": "github-hosted"}
                            },
                            "resolvedDependencies": [
                                {
                                    "uri": f"git+{repository_url}@{source_ref}",
                                    "digest": {"gitCommit": source_digest},
                                }
                            ],
                        },
                        "runDetails": {
                            "builder": {"id": signer_uri},
                            "metadata": {"invocationId": run_uri},
                        },
                    },
                },
            }
        }
    ]
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _isolation() -> github_attestation.GitHubAttestationProviderIsolation:
    return github_attestation.GitHubAttestationProviderIsolation(
        executable_path="/trusted/gh",
        executable_sha256="1" * 64,
        uid=65534,
        gid=65534,
    )


def _create_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    context: dict[str, object],
):
    output = _provider_output()
    calls: list[tuple[str, object]] = []

    def fake_provider(uri: str, policy: object, **kwargs: object) -> bytes:
        calls.append((uri, policy))
        assert kwargs["provider_isolation"] == _isolation()
        return output

    monkeypatch.setattr(
        artifact_provider_v3,
        "run_github_oci_attestation_verify",
        fake_provider,
    )
    receipt = tmp_path / "provider-v3.json"
    raw = tmp_path / "provider-v3.raw.json"
    created = artifact_provider_v3.create_artifact_provider_v3_receipt(
        "ghcr.io/owner/product",
        "sha256:" + "f" * 64,
        str(receipt),
        str(raw),
        **_policy_kwargs(),
        expected_finalizer_context=context,
        provider_isolation=_isolation(),
    )
    assert calls[0][0] == "oci://ghcr.io/owner/product@sha256:" + "f" * 64
    return created, receipt, raw, output


def test_oci_provider_runner_uses_only_digest_qualified_ghcr_and_registry_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []
    output = _provider_output()

    def fake_execute(command: list[str], **_kwargs: object) -> bytes:
        commands.append(command)
        return output

    monkeypatch.setattr(github_attestation, "_execute_gh_attestation_command", fake_execute)
    policy = github_attestation.github_attestation_policy(
        "owner/project",
        "owner/project/.github/workflows/build.yml",
        "b" * 40,
        signer_digest="b" * 40,
        source_ref="refs/heads/main",
        cert_oidc_issuer=github_attestation.GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
    )
    github_attestation.run_github_oci_attestation_verify(
        "oci://ghcr.io/owner/product@sha256:" + "f" * 64,
        policy,
        gh_executable="trusted-gh",
    )
    assert commands[0][0:4] == [
        "trusted-gh",
        "attestation",
        "verify",
        "oci://ghcr.io/owner/product@sha256:" + "f" * 64,
    ]
    assert "--bundle-from-oci" in commands[0]
    assert "--deny-self-hosted-runners" in commands[0]
    assert commands[0][commands[0].index("--limit") + 1] == "1"


@pytest.mark.parametrize(
    "uri",
    [
        "oci://ghcr.io/owner/product:latest",
        "oci://ghcr.io/owner/product",
        "oci://docker.io/owner/product@sha256:" + "f" * 64,
        "oci://ghcr.io/Owner/product@sha256:" + "f" * 64,
        "oci://ghcr.io/owner/product@sha512:" + "f" * 64,
        "oci://ghcr.io/owner/product@sha256:" + "F" * 64,
    ],
)
def test_oci_provider_runner_rejects_mutable_or_noncanonical_subjects(uri: str) -> None:
    policy = github_attestation.github_attestation_policy(
        "owner/project",
        "owner/project/.github/workflows/build.yml",
        "b" * 40,
        signer_digest="b" * 40,
        source_ref="refs/heads/main",
        cert_oidc_issuer=github_attestation.GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
    )
    with pytest.raises(github_attestation.GitHubAttestationError, match="canonical public GHCR"):
        github_attestation.run_github_oci_attestation_verify(uri, policy)


def test_provider_semantics_bind_subject_name_digest_and_build_invocation() -> None:
    policy = github_attestation.github_attestation_policy(
        "owner/project",
        "owner/project/.github/workflows/build.yml",
        "b" * 40,
        signer_digest="b" * 40,
        source_ref="refs/heads/main",
        cert_oidc_issuer=github_attestation.GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
    )
    verified = github_attestation.validate_github_oci_attestation_verifier_output(
        _provider_output(),
        subject_name="ghcr.io/owner/product",
        subject_digest="sha256:" + "f" * 64,
        policy=policy,
        expected_workflow_run_id="987654321",
        expected_workflow_run_attempt=2,
    )
    assert verified.workflow_run_id == "987654321"
    assert verified.workflow_run_attempt == 2

    for output, message in (
        (_provider_output(subject_name="ghcr.io/owner/other"), "subject name"),
        (_provider_output(subject_digest="e" * 64), "subject SHA-256"),
        (_provider_output(run_id="987654322"), "run ID/attempt"),
    ):
        with pytest.raises(github_attestation.GitHubAttestationError, match=message):
            github_attestation.validate_github_oci_attestation_verifier_output(
                output,
                subject_name="ghcr.io/owner/product",
                subject_digest="sha256:" + "f" * 64,
                policy=policy,
                expected_workflow_run_id="987654321",
                expected_workflow_run_attempt=2,
            )


def test_v3_receipt_is_canonical_schema_valid_and_rechecks_retained_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _bundle, _finalizer_public, _source, context = _finalized_allow(tmp_path)
    created, receipt, raw, output = _create_receipt(tmp_path, monkeypatch, context)

    assert receipt.read_bytes() == artifact_provider_v3.canonical_json_bytes(
        json.loads(receipt.read_text(encoding="utf-8"))
    )
    schema = json.loads(
        (
            Path(artifact_provider_v3.__file__).parent.parent
            / "schemas"
            / "artifact-provider-receipt-3.schema.json"
        ).read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(json.loads(receipt.read_text(encoding="utf-8")))
    verified = artifact_provider_v3.verify_artifact_provider_v3_receipt(
        str(receipt),
        str(raw),
        created.subject.registry_repository,
        created.subject.digest,
        **_policy_kwargs(),
        expected_finalizer_context=context,
    )
    assert verified.subject == created.subject
    assert raw.read_bytes() == output

    raw.write_bytes(output + b" ")
    with pytest.raises(artifact_provider_v3.ArtifactProviderV3Error):
        artifact_provider_v3.verify_artifact_provider_v3_receipt(
            str(receipt),
            str(raw),
            created.subject.registry_repository,
            created.subject.digest,
            **_policy_kwargs(),
            expected_finalizer_context=context,
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"registry_repository": "ghcr.io/other/product"}, "namespace"),
        ({"repository": "owner/other"}, "repository"),
        ({"source_digest": "c" * 40, "signer_digest": "c" * 40}, "source digest"),
        ({"signer_digest": "c" * 40}, "same-revision"),
        ({"source_ref": "refs/tags/v1"}, "branch ref"),
        ({"workflow_run_id": "123456", "workflow_run_attempt": 1}, "must differ"),
    ],
)
def test_v3_external_relation_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, object],
    message: str,
) -> None:
    _bundle, _finalizer_public, _source, context = _finalized_allow(tmp_path)
    inputs: dict[str, object] = {
        "registry_repository": "ghcr.io/owner/product",
        "digest": "sha256:" + "f" * 64,
        **_policy_kwargs(),
    }
    inputs.update(overrides)
    monkeypatch.setattr(
        artifact_provider_v3,
        "run_github_oci_attestation_verify",
        lambda *_args, **_kwargs: _provider_output(),
    )
    with pytest.raises(artifact_provider_v3.ArtifactProviderV3Error, match=message):
        artifact_provider_v3.create_artifact_provider_v3_receipt(
            inputs.pop("registry_repository"),  # type: ignore[arg-type]
            inputs.pop("digest"),  # type: ignore[arg-type]
            str(tmp_path / "receipt.json"),
            str(tmp_path / "raw.json"),
            **inputs,  # type: ignore[arg-type]
            expected_finalizer_context=context,
            provider_isolation=_isolation(),
        )


def test_v3_repository_mismatch_stops_before_provider_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _bundle, _finalizer_public, _source, context = _finalized_allow(tmp_path)
    called = False

    def fake_provider(*_args: object, **_kwargs: object) -> bytes:
        nonlocal called
        called = True
        return _provider_output(repository="owner/other")

    monkeypatch.setattr(
        artifact_provider_v3,
        "run_github_oci_attestation_verify",
        fake_provider,
    )
    with pytest.raises(
        artifact_provider_v3.ArtifactProviderV3Error,
        match="must match expected finalizer context.repository",
    ):
        artifact_provider_v3.create_artifact_provider_v3_receipt(
            "ghcr.io/owner/product",
            "sha256:" + "f" * 64,
            str(tmp_path / "receipt.json"),
            str(tmp_path / "raw.json"),
            repository="owner/other",
            signer_workflow="owner/other/.github/workflows/build.yml",
            signer_digest="b" * 40,
            source_ref="refs/heads/main",
            source_digest="b" * 40,
            cert_oidc_issuer=github_attestation.GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
            workflow_run_id="987654321",
            workflow_run_attempt=2,
            expected_finalizer_context=context,
            provider_isolation=_isolation(),
        )
    assert called is False


def test_v3_seal_and_verify_bind_provider_subject_receipt_and_finalizer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, finalizer_public, source, context = _finalized_allow(tmp_path)
    admission_private, admission_public = _keys(tmp_path, "artifact-provider")
    receipt = tmp_path / "provider-v3.json"
    raw = tmp_path / "provider-v3.raw.json"
    binding = tmp_path / "provider-v3.eab"
    monkeypatch.setattr(
        artifact_provider_v3,
        "validate_provider_isolated_signing_key_path",
        lambda *_args, **_kwargs: str(admission_private),
    )
    monkeypatch.setattr(
        artifact_provider_v3,
        "run_github_oci_attestation_verify",
        lambda *_args, **_kwargs: _provider_output(),
    )

    sealed = artifact_provider_v3.seal_artifact_provider_v3_admission(
        "ghcr.io/owner/product",
        "sha256:" + "f" * 64,
        str(receipt),
        str(raw),
        str(bundle),
        str(binding),
        **_policy_kwargs(),
        trusted_finalizer_public_key_path=str(finalizer_public),
        expected_finalizer_source=source,
        expected_finalizer_context=context,
        private_key_path=str(admission_private),
        provider_isolation=_isolation(),
    )
    assert sealed.admission.payload["format"] == "EVOGUARD_ARTIFACT_BINDING_V2"
    assert sealed.admission.subject.as_dict() == {
        "kind": "oci-manifest-or-index",
        "digest": "sha256:" + "f" * 64,
    }
    assert sealed.admission.provenance_reference.identity.startswith(
        "artifact-provider-v3:sha256:"
    )
    verified = artifact_provider_v3.verify_artifact_provider_v3_admission(
        str(binding),
        "ghcr.io/owner/product",
        "sha256:" + "f" * 64,
        str(receipt),
        str(raw),
        str(bundle),
        **_policy_kwargs(),
        trusted_public_key_path=str(admission_public),
        trusted_finalizer_public_key_path=str(finalizer_public),
        expected_finalizer_source=source,
        expected_finalizer_context=context,
    )
    assert verified.admission.finalizer.decision == "ALLOW"

    with pytest.raises(artifact_provider_v3.ArtifactProviderV3Error):
        artifact_provider_v3.verify_artifact_provider_v3_admission(
            str(binding),
            "ghcr.io/owner/product",
            "sha256:" + "e" * 64,
            str(receipt),
            str(raw),
            str(bundle),
            **_policy_kwargs(),
            trusted_public_key_path=str(admission_public),
            trusted_finalizer_public_key_path=str(finalizer_public),
            expected_finalizer_source=source,
            expected_finalizer_context=context,
        )


def test_v3_identity_has_a_frozen_canonical_vector() -> None:
    subject = artifact_provider_v3.artifact_provider_v3_subject(
        "ghcr.io/owner/product", "sha256:" + "f" * 64
    )
    policy = github_attestation.github_attestation_policy(
        "owner/project",
        "owner/project/.github/workflows/build.yml",
        "b" * 40,
        signer_digest="b" * 40,
        source_ref="refs/heads/main",
        cert_oidc_issuer=github_attestation.GITHUB_ATTESTATION_CERT_OIDC_ISSUER,
    )
    assert artifact_provider_v3.artifact_provider_v3_provenance_identity(
        subject, policy, "987654321", 2
    ) == (
        "artifact-provider-v3:sha256:"
        "330fdbd4a40a7876e0f76293f1ebe3ac8b456a93ad54125baddbe1e8b851e524"
    )


@pytest.mark.parametrize(
    ("repository", "digest"),
    [
        (object(), "sha256:" + "f" * 64),
        ("docker.io/owner/product", "sha256:" + "f" * 64),
        ("ghcr.io/owner/product:latest", "sha256:" + "f" * 64),
        ("ghcr.io/owner/product", object()),
        ("ghcr.io/owner/product", "sha512:" + "f" * 64),
        ("ghcr.io/owner/product", "sha256:" + "F" * 64),
    ],
)
def test_v3_subject_accepts_only_canonical_immutable_ghcr(
    repository: object,
    digest: object,
) -> None:
    with pytest.raises(artifact_provider_v3.ArtifactProviderV3Error):
        artifact_provider_v3.artifact_provider_v3_subject(  # type: ignore[arg-type]
            repository,
            digest,
        )


def test_v3_receipt_validation_is_closed_world_and_type_exact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _bundle, _finalizer_public, _source, context = _finalized_allow(tmp_path)
    _created, receipt, _raw, _output = _create_receipt(tmp_path, monkeypatch, context)
    base = json.loads(receipt.read_text(encoding="utf-8"))
    variants: list[dict[str, object]] = []

    extra = copy.deepcopy(base)
    extra["unknown"] = True
    variants.append(extra)
    for path, value in (
        (("format",), "EVOGUARD_ARTIFACT_PROVIDER_RECEIPT_V2"),
        (("provider", "name"), "other-provider"),
        (("provider", "bundle_source"), "local-file"),
        (("subject", "kind"), "file"),
        (("build", "workflow_run_id"), "01"),
        (("build", "workflow_run_attempt"), True),
        (("verification_policy", "predicate_type"), "other"),
        (("verification_policy", "deny_self_hosted_runners"), 1),
        (("verification_policy", "attestation_limit"), True),
        (("verification_output", "sha256"), "F" * 64),
        (("verification_output", "size"), True),
        (("verification_output", "verified_attestation_count"), True),
    ):
        variant = copy.deepcopy(base)
        if len(path) == 1:
            variant[path[0]] = value
        else:
            parent = variant[path[0]]
            assert isinstance(parent, dict)
            parent[path[1]] = value
        variants.append(variant)
    non_object = copy.deepcopy(base)
    non_object["provider"] = []
    variants.append(non_object)

    for index, variant in enumerate(variants):
        try:
            artifact_provider_v3._validate_receipt(variant)
        except artifact_provider_v3.ArtifactProviderV3Error:
            continue
        pytest.fail(f"invalid receipt variant {index} was accepted")


def test_v3_live_paths_require_isolation_and_no_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _bundle, _finalizer_public, _source, context = _finalized_allow(tmp_path)
    called = False

    def fake_provider(*_args: object, **_kwargs: object) -> bytes:
        nonlocal called
        called = True
        return _provider_output()

    monkeypatch.setattr(
        artifact_provider_v3,
        "run_github_oci_attestation_verify",
        fake_provider,
    )
    path = tmp_path / "same.json"
    with pytest.raises(
        artifact_provider_v3.ArtifactProviderV3Error,
        match="requires GitHubAttestationProviderIsolation",
    ):
        artifact_provider_v3.create_artifact_provider_v3_receipt(
            "ghcr.io/owner/product",
            "sha256:" + "f" * 64,
            str(path),
            str(tmp_path / "raw.json"),
            **_policy_kwargs(),
            expected_finalizer_context=context,
            provider_isolation=None,  # type: ignore[arg-type]
        )
    with pytest.raises(
        artifact_provider_v3.ArtifactProviderV3Error,
        match="paths must differ",
    ):
        artifact_provider_v3.create_artifact_provider_v3_receipt(
            "ghcr.io/owner/product",
            "sha256:" + "f" * 64,
            str(path),
            str(path),
            **_policy_kwargs(),
            expected_finalizer_context=context,
            provider_isolation=_isolation(),
        )
    assert called is False


def test_v3_seal_requires_key_isolation_before_provider_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, finalizer_public, source, context = _finalized_allow(tmp_path)
    admission_private, _admission_public = _keys(tmp_path, "unprotected")
    provider_called = False

    def reject_key(*_args: object, **_kwargs: object) -> str:
        raise github_attestation.GitHubAttestationError("key is provider-readable")

    def fake_provider(*_args: object, **_kwargs: object) -> bytes:
        nonlocal provider_called
        provider_called = True
        return _provider_output()

    monkeypatch.setattr(
        artifact_provider_v3,
        "validate_provider_isolated_signing_key_path",
        reject_key,
    )
    monkeypatch.setattr(
        artifact_provider_v3,
        "run_github_oci_attestation_verify",
        fake_provider,
    )
    with pytest.raises(
        artifact_provider_v3.ArtifactProviderV3Error,
        match="does not protect the admission key",
    ):
        artifact_provider_v3.seal_artifact_provider_v3_admission(
            "ghcr.io/owner/product",
            "sha256:" + "f" * 64,
            str(tmp_path / "receipt.json"),
            str(tmp_path / "raw.json"),
            str(bundle),
            str(tmp_path / "binding.eab"),
            **_policy_kwargs(),
            trusted_finalizer_public_key_path=str(finalizer_public),
            expected_finalizer_source=source,
            expected_finalizer_context=context,
            private_key_path=str(admission_private),
            provider_isolation=_isolation(),
        )
    assert provider_called is False


def test_v3_fresh_reverify_repeats_provider_and_requires_isolation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _bundle, _finalizer_public, _source, context = _finalized_allow(tmp_path)
    _created, receipt, _raw, output = _create_receipt(tmp_path, monkeypatch, context)
    calls = 0

    def fake_provider(*_args: object, **_kwargs: object) -> bytes:
        nonlocal calls
        calls += 1
        return output

    monkeypatch.setattr(
        artifact_provider_v3,
        "run_github_oci_attestation_verify",
        fake_provider,
    )
    fresh = artifact_provider_v3.reverify_artifact_provider_v3_receipt(
        str(receipt),
        "ghcr.io/owner/product",
        "sha256:" + "f" * 64,
        **_policy_kwargs(),
        expected_finalizer_context=context,
        provider_isolation=_isolation(),
    )
    assert fresh.provider_result.workflow_run_id == "987654321"
    assert calls == 1
    with pytest.raises(
        artifact_provider_v3.ArtifactProviderV3Error,
        match="requires GitHubAttestationProviderIsolation",
    ):
        artifact_provider_v3.reverify_artifact_provider_v3_receipt(
            str(receipt),
            "ghcr.io/owner/product",
            "sha256:" + "f" * 64,
            **_policy_kwargs(),
            expected_finalizer_context=context,
            provider_isolation=None,  # type: ignore[arg-type]
        )
    assert calls == 1
