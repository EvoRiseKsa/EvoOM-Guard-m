from __future__ import annotations

import base64
import json
import zipfile
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from evoom_guard import artifact_admission, artifact_digest_admission
from evoom_guard.cli import main as cli_main
from evoom_guard.evidence_bundle import _archive_bytes, _canonical_json
from evoom_guard.guard import guard
from evoom_guard.signing import generate_keypair, verify_bytes
from evoom_guard.trusted_finalizer import create_finalizer_handoff, seal_finalizer_bundle


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _keys(tmp_path: Path, name: str) -> tuple[Path, Path]:
    private = tmp_path / f"{name}.private.pem"
    public = tmp_path / f"{name}.public.pem"
    generate_keypair(str(private), str(public))
    return private, public


def _finalized_allow(tmp_path: Path, *, denied: bool = False):
    repo = tmp_path / "repo"
    tests = repo / "tests"
    tests.mkdir(parents=True)
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tests / "test_app.py").write_text(
        "from app import VALUE\n\n\ndef test_value():\n    assert VALUE == 2\n",
        encoding="utf-8",
    )
    candidate = (
        "<<<FILE: tests/test_app.py>>>\ndef test_value():\n    assert True\n<<<END FILE>>>"
        if denied
        else "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>"
    )
    record = guard(
        str(repo),
        candidate,
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
    return bundle, finalizer_private, finalizer_public, source, context, sealed.decision


def _seal(
    tmp_path: Path,
    *,
    kind: str = "oci-manifest-or-index",
    digest: str = "sha256:" + "a" * 64,
):
    bundle, _finalizer_private, finalizer_public, source, context, decision = _finalized_allow(
        tmp_path
    )
    assert decision == "ALLOW"
    provenance = tmp_path / "provenance.json"
    provenance.write_bytes(b'{"predicate":"opaque-demo"}\n')
    binding_private, binding_public = _keys(tmp_path, "artifact-digest")
    binding = tmp_path / "admission.eab"
    sealed = artifact_digest_admission.seal_artifact_digest_admission(
        kind,
        digest,
        str(provenance),
        "build-provenance:run-42",
        str(bundle),
        str(binding),
        trusted_finalizer_public_key_path=str(finalizer_public),
        expected_finalizer_source=source,
        expected_finalizer_context=context,
        private_key_path=str(binding_private),
    )
    return (
        bundle,
        finalizer_public,
        source,
        context,
        provenance,
        binding_private,
        binding_public,
        binding,
        sealed,
    )


def test_v2_canonical_subject_and_provenance_vectors(tmp_path: Path) -> None:
    subject = artifact_digest_admission.artifact_digest_subject(
        "oci-manifest-or-index",
        "sha256:" + "a" * 64,
    )
    provenance = tmp_path / "provenance.json"
    provenance.write_bytes(b"abc")
    reference = artifact_digest_admission.provenance_reference_from_file(
        str(provenance),
        "opaque:test-vector",
    )

    assert subject.as_dict() == {
        "kind": "oci-manifest-or-index",
        "digest": "sha256:" + "a" * 64,
    }
    assert reference.as_dict() == {
        "format": artifact_digest_admission.OPAQUE_PROVENANCE_REFERENCE_FORMAT,
        "identity": "opaque:test-vector",
        "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "size": 3,
    }


def test_v2_oci_round_trip_is_canonical_and_domain_separated(tmp_path: Path) -> None:
    (
        bundle,
        finalizer_public,
        source,
        context,
        provenance,
        binding_private,
        binding_public,
        binding,
        sealed,
    ) = _seal(tmp_path)

    second = tmp_path / "second.eab"
    artifact_digest_admission.seal_artifact_digest_admission(
        sealed.subject.kind,
        sealed.subject.digest,
        str(provenance),
        sealed.provenance_reference.identity,
        str(bundle),
        str(second),
        trusted_finalizer_public_key_path=str(finalizer_public),
        expected_finalizer_source=source,
        expected_finalizer_context=context,
        private_key_path=str(binding_private),
    )
    assert binding.read_bytes() == second.read_bytes()

    inspected = artifact_digest_admission.inspect_artifact_digest_binding(str(binding))
    assert inspected.payload == sealed.payload
    assert inspected.binding_bytes == _canonical_json(sealed.payload)
    assert verify_bytes(
        artifact_digest_admission.ARTIFACT_DIGEST_BINDING_DOMAIN + inspected.binding_bytes,
        inspected.signature,
        str(binding_public),
    )
    assert not verify_bytes(
        artifact_admission.ARTIFACT_BINDING_DOMAIN + inspected.binding_bytes,
        inspected.signature,
        str(binding_public),
    )
    verified = artifact_digest_admission.verify_artifact_digest_admission(
        str(binding),
        sealed.subject.kind,
        sealed.subject.digest,
        str(provenance),
        sealed.provenance_reference.identity,
        str(bundle),
        trusted_public_key_path=str(binding_public),
        trusted_finalizer_public_key_path=str(finalizer_public),
        expected_finalizer_source=source,
        expected_finalizer_context=context,
    )
    assert verified.subject == sealed.subject
    assert verified.provenance_reference == sealed.provenance_reference
    assert verified.finalizer.decision == "ALLOW"


def test_v2_rejects_subject_provenance_and_finalizer_replays(tmp_path: Path) -> None:
    (
        bundle,
        finalizer_public,
        source,
        context,
        provenance,
        _binding_private,
        binding_public,
        binding,
        sealed,
    ) = _seal(tmp_path)

    kwargs = {
        "trusted_public_key_path": str(binding_public),
        "trusted_finalizer_public_key_path": str(finalizer_public),
        "expected_finalizer_source": source,
        "expected_finalizer_context": context,
    }
    with pytest.raises(artifact_digest_admission.ArtifactDigestAdmissionError, match="subject"):
        artifact_digest_admission.verify_artifact_digest_admission(
            str(binding),
            sealed.subject.kind,
            "sha256:" + "b" * 64,
            str(provenance),
            sealed.provenance_reference.identity,
            str(bundle),
            **kwargs,
        )
    with pytest.raises(artifact_digest_admission.ArtifactDigestAdmissionError, match="subject"):
        artifact_digest_admission.verify_artifact_digest_admission(
            str(binding),
            "artifact-sha256",
            sealed.subject.digest,
            str(provenance),
            sealed.provenance_reference.identity,
            str(bundle),
            **kwargs,
        )

    provenance.write_bytes(b'{"predicate":"substituted"}\n')
    with pytest.raises(
        artifact_digest_admission.ArtifactDigestAdmissionError,
        match="provenance reference",
    ):
        artifact_digest_admission.verify_artifact_digest_admission(
            str(binding),
            sealed.subject.kind,
            sealed.subject.digest,
            str(provenance),
            sealed.provenance_reference.identity,
            str(bundle),
            **kwargs,
        )

    provenance.write_bytes(b'{"predicate":"opaque-demo"}\n')
    with pytest.raises(
        artifact_digest_admission.ArtifactDigestAdmissionError,
        match="provenance reference",
    ):
        artifact_digest_admission.verify_artifact_digest_admission(
            str(binding),
            sealed.subject.kind,
            sealed.subject.digest,
            str(provenance),
            "build-provenance:other-run",
            str(bundle),
            **kwargs,
        )

    with pytest.raises(
        artifact_digest_admission.ArtifactDigestAdmissionError,
        match="finalizer prerequisite",
    ):
        artifact_digest_admission.verify_artifact_digest_admission(
            str(binding),
            sealed.subject.kind,
            sealed.subject.digest,
            str(provenance),
            sealed.provenance_reference.identity,
            str(bundle),
            trusted_public_key_path=str(binding_public),
            trusted_finalizer_public_key_path=str(finalizer_public),
            expected_finalizer_source=dict(source, workflow_run_attempt=2),
            expected_finalizer_context=context,
        )
    with pytest.raises(
        artifact_digest_admission.ArtifactDigestAdmissionError,
        match="finalizer prerequisite",
    ):
        artifact_digest_admission.verify_artifact_digest_admission(
            str(binding),
            sealed.subject.kind,
            sealed.subject.digest,
            str(provenance),
            sealed.provenance_reference.identity,
            str(bundle),
            trusted_public_key_path=str(binding_public),
            trusted_finalizer_public_key_path=str(finalizer_public),
            expected_finalizer_source=source,
            expected_finalizer_context=dict(context, candidate_sha256="f" * 64),
        )


def test_v2_fails_closed_for_tags_unknown_algorithms_and_nonregular_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(artifact_digest_admission.ArtifactDigestAdmissionError, match="digest"):
        artifact_digest_admission.artifact_digest_subject("oci-manifest-or-index", "latest")
    with pytest.raises(artifact_digest_admission.ArtifactDigestAdmissionError, match="digest"):
        artifact_digest_admission.artifact_digest_subject(
            "artifact-sha256",
            "sha512:" + "a" * 128,
        )
    with pytest.raises(artifact_digest_admission.ArtifactDigestAdmissionError, match="kind"):
        artifact_digest_admission.artifact_digest_subject("oci-tag", "sha256:" + "a" * 64)
    with pytest.raises(artifact_digest_admission.ArtifactDigestAdmissionError, match="regular"):
        artifact_digest_admission.provenance_reference_from_file(
            str(tmp_path),
            "opaque:directory",
        )
    with pytest.raises(artifact_digest_admission.ArtifactDigestAdmissionError, match="cannot inspect"):
        artifact_digest_admission.provenance_reference_from_file(
            str(tmp_path / "missing-provenance.json"),
            "opaque:missing",
        )
    target = tmp_path / "provenance.json"
    target.write_bytes(b"opaque")
    link = tmp_path / "provenance-link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pass
    else:
        with pytest.raises(artifact_digest_admission.ArtifactDigestAdmissionError, match="regular"):
            artifact_digest_admission.provenance_reference_from_file(
                str(link),
                "opaque:symlink",
            )
    oversized = tmp_path / "oversized-provenance.json"
    oversized.write_bytes(b"four")
    monkeypatch.setattr(artifact_digest_admission, "MAX_PROVENANCE_REFERENCE_BYTES", 3)
    with pytest.raises(artifact_digest_admission.ArtifactDigestAdmissionError, match="exceeds"):
        artifact_digest_admission.provenance_reference_from_file(
            str(oversized),
            "opaque:oversized",
        )


def test_v2_rejects_finalizer_deny_before_provenance_or_signing_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, _finalizer_private, finalizer_public, source, context, decision = _finalized_allow(
        tmp_path,
        denied=True,
    )
    assert decision == "DENY"
    provenance = tmp_path / "provenance.json"
    provenance.write_bytes(b"opaque")
    private, _public = _keys(tmp_path, "artifact-digest")
    provenance_read = False
    key_loaded = False

    import evoom_guard.signing as signing

    def fail_if_provenance_read(*_args: object, **_kwargs: object):
        nonlocal provenance_read
        provenance_read = True
        raise AssertionError("provenance must not be read before finalizer DENY is rejected")

    def fail_if_key_loaded(*_args: object, **_kwargs: object):
        nonlocal key_loaded
        key_loaded = True
        raise AssertionError("signing key must not be loaded before finalizer DENY is rejected")

    monkeypatch.setattr(
        artifact_digest_admission,
        "provenance_reference_from_file",
        fail_if_provenance_read,
    )
    monkeypatch.setattr(signing, "_load_private_key_snapshot", fail_if_key_loaded)
    with pytest.raises(
        artifact_digest_admission.ArtifactDigestAdmissionError,
        match="requires a verified finalizer ALLOW",
    ):
        artifact_digest_admission.seal_artifact_digest_admission(
            "oci-manifest-or-index",
            "sha256:" + "a" * 64,
            str(provenance),
            "opaque:deny",
            str(bundle),
            str(tmp_path / "never.eab"),
            trusted_finalizer_public_key_path=str(finalizer_public),
            expected_finalizer_source=source,
            expected_finalizer_context=context,
            private_key_path=str(private),
        )
    assert provenance_read is False
    assert key_loaded is False


def test_v2_generic_artifact_digest_is_a_separate_subject_path(tmp_path: Path) -> None:
    (
        bundle,
        finalizer_public,
        source,
        context,
        provenance,
        _binding_private,
        binding_public,
        binding,
        sealed,
    ) = _seal(
        tmp_path,
        kind="artifact-sha256",
        digest="sha256:" + "d" * 64,
    )

    assert sealed.subject.as_dict() == {
        "kind": "artifact-sha256",
        "digest": "sha256:" + "d" * 64,
    }
    verified = artifact_digest_admission.verify_artifact_digest_admission(
        str(binding),
        "artifact-sha256",
        "sha256:" + "d" * 64,
        str(provenance),
        sealed.provenance_reference.identity,
        str(bundle),
        trusted_public_key_path=str(binding_public),
        trusted_finalizer_public_key_path=str(finalizer_public),
        expected_finalizer_source=source,
        expected_finalizer_context=context,
    )
    assert verified.subject.kind == "artifact-sha256"


def test_v2_rejects_finalizer_key_reuse_and_embedded_key_substitution(
    tmp_path: Path,
) -> None:
    bundle, finalizer_private, finalizer_public, source, context, decision = _finalized_allow(
        tmp_path
    )
    assert decision == "ALLOW"
    provenance = tmp_path / "provenance.json"
    provenance.write_bytes(b"opaque")
    subject_digest = "sha256:" + "a" * 64
    with pytest.raises(artifact_digest_admission.ArtifactDigestAdmissionError, match="must differ"):
        artifact_digest_admission.seal_artifact_digest_admission(
            "oci-manifest-or-index",
            subject_digest,
            str(provenance),
            "opaque:key-reuse",
            str(bundle),
            str(tmp_path / "key-reuse.eab"),
            trusted_finalizer_public_key_path=str(finalizer_public),
            expected_finalizer_source=source,
            expected_finalizer_context=context,
            private_key_path=str(finalizer_private),
        )

    binding_private, binding_public = _keys(tmp_path, "artifact-digest")
    binding = tmp_path / "binding.eab"
    artifact_digest_admission.seal_artifact_digest_admission(
        "oci-manifest-or-index",
        subject_digest,
        str(provenance),
        "opaque:key-reuse",
        str(bundle),
        str(binding),
        trusted_finalizer_public_key_path=str(finalizer_public),
        expected_finalizer_source=source,
        expected_finalizer_context=context,
        private_key_path=str(binding_private),
    )
    _other_private, other_public = _keys(tmp_path, "other-admission")
    with pytest.raises(
        artifact_digest_admission.ArtifactDigestAdmissionError,
        match="key_id does not match the externally trusted public key",
    ):
        artifact_digest_admission.verify_artifact_digest_admission(
            str(binding),
            "oci-manifest-or-index",
            subject_digest,
            str(provenance),
            "opaque:key-reuse",
            str(bundle),
            trusted_public_key_path=str(other_public),
            trusted_finalizer_public_key_path=str(finalizer_public),
            expected_finalizer_source=source,
            expected_finalizer_context=context,
        )

    inspected = artifact_digest_admission.inspect_artifact_digest_binding(str(binding))
    changed = dict(inspected.payload)
    changed["authentication"] = dict(
        inspected.payload["authentication"],
        key_id="sha256:" + "f" * 64,
    )
    binding.write_bytes(
        _archive_bytes(
            (
                (
                    artifact_digest_admission.ARTIFACT_DIGEST_BINDING_PATH,
                    _canonical_json(changed),
                ),
                (
                    artifact_digest_admission.ARTIFACT_DIGEST_SIGNATURE_PATH,
                    base64.b64encode(inspected.signature),
                ),
            )
        )
    )
    with pytest.raises(
        artifact_digest_admission.ArtifactDigestAdmissionError,
        match="key_id does not match the externally trusted public key",
    ):
        artifact_digest_admission.verify_artifact_digest_admission(
            str(binding),
            "oci-manifest-or-index",
            subject_digest,
            str(provenance),
            "opaque:key-reuse",
            str(bundle),
            trusted_public_key_path=str(binding_public),
            trusted_finalizer_public_key_path=str(finalizer_public),
            expected_finalizer_source=source,
            expected_finalizer_context=context,
        )


def test_v2_rejects_signature_and_container_metadata_tampering(tmp_path: Path) -> None:
    (
        bundle,
        finalizer_public,
        source,
        context,
        provenance,
        _binding_private,
        binding_public,
        binding,
        sealed,
    ) = _seal(tmp_path)
    inspected = artifact_digest_admission.inspect_artifact_digest_binding(str(binding))
    changed_signature = bytearray(inspected.signature)
    changed_signature[0] ^= 1
    binding.write_bytes(
        _archive_bytes(
            (
                (
                    artifact_digest_admission.ARTIFACT_DIGEST_BINDING_PATH,
                    inspected.binding_bytes,
                ),
                (
                    artifact_digest_admission.ARTIFACT_DIGEST_SIGNATURE_PATH,
                    base64.b64encode(bytes(changed_signature)),
                ),
            )
        )
    )
    with pytest.raises(
        artifact_digest_admission.ArtifactDigestAdmissionError,
        match="signature is invalid",
    ):
        artifact_digest_admission.verify_artifact_digest_admission(
            str(binding),
            sealed.subject.kind,
            sealed.subject.digest,
            str(provenance),
            sealed.provenance_reference.identity,
            str(bundle),
            trusted_public_key_path=str(binding_public),
            trusted_finalizer_public_key_path=str(finalizer_public),
            expected_finalizer_source=source,
            expected_finalizer_context=context,
        )

    metadata_tampered = tmp_path / "metadata-tampered.eab"
    with zipfile.ZipFile(metadata_tampered, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(
            artifact_digest_admission.ARTIFACT_DIGEST_BINDING_PATH,
            inspected.binding_bytes,
        )
        archive.writestr(
            artifact_digest_admission.ARTIFACT_DIGEST_SIGNATURE_PATH,
            base64.b64encode(inspected.signature),
        )
    with pytest.raises(
        artifact_digest_admission.ArtifactDigestAdmissionError,
        match="canonical regular file|metadata",
    ):
        artifact_digest_admission.inspect_artifact_digest_binding(str(metadata_tampered))


def test_v2_cli_round_trip_for_generic_artifact_digest(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle, _finalizer_private, finalizer_public, source, context, decision = _finalized_allow(
        tmp_path
    )
    assert decision == "ALLOW"
    provenance = tmp_path / "provenance.json"
    provenance.write_bytes(b'{"opaque":"bytes"}\n')
    binding_private, binding_public = _keys(tmp_path, "artifact-digest")
    source_path = tmp_path / "source.json"
    context_path = tmp_path / "context.json"
    binding = tmp_path / "admission.eab"
    _write_json(source_path, source)
    _write_json(context_path, context)
    digest = "sha256:" + "f" * 64

    code = cli_main(
        [
            "seal-artifact-digest-admission",
            str(bundle),
            "--subject-kind",
            "artifact-sha256",
            "--subject-digest",
            digest,
            "--provenance",
            str(provenance),
            "--provenance-identity",
            "opaque:cli",
            "--out",
            str(binding),
            "--finalizer-pub",
            str(finalizer_public),
            "--expected-source",
            str(source_path),
            "--expected-context",
            str(context_path),
            "--sign-key",
            str(binding_private),
        ]
    )
    seal_report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert seal_report["status"] == "SEALED"
    assert seal_report["subject"] == {"kind": "artifact-sha256", "digest": digest}

    code = cli_main(
        [
            "verify-artifact-digest-admission",
            str(binding),
            str(bundle),
            "--subject-kind",
            "artifact-sha256",
            "--subject-digest",
            digest,
            "--provenance",
            str(provenance),
            "--provenance-identity",
            "opaque:cli",
            "--trusted-pub",
            str(binding_public),
            "--finalizer-pub",
            str(finalizer_public),
            "--expected-source",
            str(source_path),
            "--expected-context",
            str(context_path),
        ]
    )
    verify_report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert verify_report["status"] == "VERIFIED"


def test_v2_schema_is_valid_and_describes_released_experimental_contract(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    schema = json.loads(
        (root / "evoom_guard" / "schemas" / "artifact-digest-binding-2.schema.json").read_text(
            encoding="utf-8"
        )
    )
    context_schema = json.loads(
        (root / "evoom_guard" / "schemas" / "evidence-context-1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator.check_schema(schema)
    assert schema["$id"] == "urn:evoguard:artifact-digest-binding:2"
    assert "released in v3.8.0" in schema["description"]
    assert "Experimental" in schema["description"]
    assert schema["properties"]["format"]["const"] == (
        artifact_digest_admission.ARTIFACT_DIGEST_BINDING_FORMAT
    )
    assert schema["properties"]["provenance_reference"]["properties"]["format"]["const"] == (
        artifact_digest_admission.OPAQUE_PROVENANCE_REFERENCE_FORMAT
    )

    *_rest, sealed = _seal(tmp_path)
    registry = Registry().with_resource(
        context_schema["$id"],
        Resource.from_contents(context_schema, default_specification=DRAFT202012),
    )
    Draft202012Validator(schema, registry=registry).validate(sealed.payload)
