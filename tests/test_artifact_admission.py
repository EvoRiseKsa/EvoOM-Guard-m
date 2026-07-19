from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from evoom_guard import SCHEMA_ID_RELEASE, artifact_admission, cli
from evoom_guard.cli import main as cli_main
from evoom_guard.evidence_bundle import _archive_bytes, _canonical_json
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


def test_artifact_binding_round_trip_is_file_and_finalizer_bound(tmp_path: Path) -> None:
    bundle, _finalizer_private, finalizer_public, source, context, decision = _finalized_allow(
        tmp_path
    )
    assert decision == "ALLOW"
    artifact = tmp_path / "dist" / "app.whl"
    artifact.parent.mkdir()
    artifact.write_bytes(b"artifact bytes\x00v1")
    binding_private, binding_public = _keys(tmp_path, "artifact")
    binding = tmp_path / "admission.eab"

    sealed = artifact_admission.seal_artifact_admission(
        str(artifact),
        str(bundle),
        str(binding),
        trusted_finalizer_public_key_path=str(finalizer_public),
        expected_finalizer_source=source,
        expected_finalizer_context=context,
        private_key_path=str(binding_private),
    )

    assert sealed.payload["decision"] == "ALLOW"
    assert (
        sealed.payload["subject"]
        == artifact_admission.hash_regular_artifact(str(artifact)).as_dict()
    )
    inspected = artifact_admission.inspect_artifact_binding(str(binding))
    assert inspected.payload == sealed.payload
    verified = artifact_admission.verify_artifact_admission(
        str(binding),
        str(artifact),
        str(bundle),
        trusted_public_key_path=str(binding_public),
        trusted_finalizer_public_key_path=str(finalizer_public),
        expected_finalizer_source=source,
        expected_finalizer_context=context,
    )
    assert verified.subject == sealed.subject
    assert verified.finalizer.decision == "ALLOW"


def test_artifact_binding_rejects_artifact_and_finalizer_replays(tmp_path: Path) -> None:
    bundle, _finalizer_private, finalizer_public, source, context, _decision = _finalized_allow(
        tmp_path
    )
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"first")
    binding_private, binding_public = _keys(tmp_path, "artifact")
    binding = tmp_path / "admission.eab"
    artifact_admission.seal_artifact_admission(
        str(artifact),
        str(bundle),
        str(binding),
        trusted_finalizer_public_key_path=str(finalizer_public),
        expected_finalizer_source=source,
        expected_finalizer_context=context,
        private_key_path=str(binding_private),
    )

    artifact.write_bytes(b"second")
    with pytest.raises(artifact_admission.ArtifactAdmissionError, match="subject"):
        artifact_admission.verify_artifact_admission(
            str(binding),
            str(artifact),
            str(bundle),
            trusted_public_key_path=str(binding_public),
            trusted_finalizer_public_key_path=str(finalizer_public),
            expected_finalizer_source=source,
            expected_finalizer_context=context,
        )

    artifact.write_bytes(b"first")
    with pytest.raises(artifact_admission.ArtifactAdmissionError, match="finalizer prerequisite"):
        artifact_admission.verify_artifact_admission(
            str(binding),
            str(artifact),
            str(bundle),
            trusted_public_key_path=str(binding_public),
            trusted_finalizer_public_key_path=str(finalizer_public),
            expected_finalizer_source=dict(source, workflow_run_attempt=2),
            expected_finalizer_context=context,
        )


def test_artifact_binding_rejects_a_valid_finalizer_deny_before_key_load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, _finalizer_private, finalizer_public, source, context, decision = _finalized_allow(
        tmp_path, denied=True
    )
    assert decision == "DENY"
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"artifact")
    binding_private, _binding_public = _keys(tmp_path, "artifact")
    called = False
    artifact_hashed = False

    import evoom_guard.signing as signing

    def fail_if_loaded(*_args: object, **_kwargs: object):
        nonlocal called
        called = True
        raise AssertionError("artifact key must not be opened for finalizer DENY")

    def fail_if_hashed(*_args: object, **_kwargs: object):
        nonlocal artifact_hashed
        artifact_hashed = True
        raise AssertionError("artifact must not be read before finalizer DENY is rejected")

    monkeypatch.setattr(signing, "_load_private_key_snapshot", fail_if_loaded)
    monkeypatch.setattr(artifact_admission, "hash_regular_artifact", fail_if_hashed)
    with pytest.raises(
        artifact_admission.ArtifactAdmissionError, match="requires a verified finalizer ALLOW"
    ):
        artifact_admission.seal_artifact_admission(
            str(artifact),
            str(bundle),
            str(tmp_path / "never.eab"),
            trusted_finalizer_public_key_path=str(finalizer_public),
            expected_finalizer_source=source,
            expected_finalizer_context=context,
            private_key_path=str(binding_private),
        )
    assert called is False
    assert artifact_hashed is False


def test_artifact_verification_rejects_finalizer_deny_before_artifact_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    allow_bundle, _allow_private, allow_public, allow_source, allow_context, decision = (
        _finalized_allow(tmp_path / "allow")
    )
    assert decision == "ALLOW"
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"artifact")
    binding_private, binding_public = _keys(tmp_path, "artifact")
    binding = tmp_path / "admission.eab"
    artifact_admission.seal_artifact_admission(
        str(artifact),
        str(allow_bundle),
        str(binding),
        trusted_finalizer_public_key_path=str(allow_public),
        expected_finalizer_source=allow_source,
        expected_finalizer_context=allow_context,
        private_key_path=str(binding_private),
    )

    denied_bundle, _denied_private, denied_public, denied_source, denied_context, decision = (
        _finalized_allow(tmp_path / "denied", denied=True)
    )
    assert decision == "DENY"
    hashed = False

    def fail_if_hashed(*_args: object, **_kwargs: object) -> object:
        nonlocal hashed
        hashed = True
        raise AssertionError("artifact must not be read before finalizer DENY is rejected")

    monkeypatch.setattr(artifact_admission, "hash_regular_artifact", fail_if_hashed)
    with pytest.raises(
        artifact_admission.ArtifactAdmissionError, match="requires a verified finalizer ALLOW"
    ):
        artifact_admission.verify_artifact_admission(
            str(binding),
            str(artifact),
            str(denied_bundle),
            trusted_public_key_path=str(binding_public),
            trusted_finalizer_public_key_path=str(denied_public),
            expected_finalizer_source=denied_source,
            expected_finalizer_context=denied_context,
        )
    assert hashed is False


def test_artifact_binding_requires_a_key_distinct_from_the_finalizer(tmp_path: Path) -> None:
    bundle, finalizer_private, finalizer_public, source, context, decision = _finalized_allow(
        tmp_path
    )
    assert decision == "ALLOW"
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"artifact")

    with pytest.raises(artifact_admission.ArtifactAdmissionError, match="must differ"):
        artifact_admission.seal_artifact_admission(
            str(artifact),
            str(bundle),
            str(tmp_path / "never.eab"),
            trusted_finalizer_public_key_path=str(finalizer_public),
            expected_finalizer_source=source,
            expected_finalizer_context=context,
            private_key_path=str(finalizer_private),
        )


def test_artifact_binding_rejects_a_canonical_payload_with_replayed_signature(
    tmp_path: Path,
) -> None:
    bundle, _finalizer_private, finalizer_public, source, context, _decision = _finalized_allow(
        tmp_path
    )
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"artifact")
    binding_private, binding_public = _keys(tmp_path, "artifact")
    binding = tmp_path / "admission.eab"
    artifact_admission.seal_artifact_admission(
        str(artifact),
        str(bundle),
        str(binding),
        trusted_finalizer_public_key_path=str(finalizer_public),
        expected_finalizer_source=source,
        expected_finalizer_context=context,
        private_key_path=str(binding_private),
    )
    inspected = artifact_admission.inspect_artifact_binding(str(binding))
    changed = dict(inspected.payload)
    changed["subject"] = dict(changed["subject"], sha256="f" * 64)
    changed_bytes = _canonical_json(changed)
    replayed = _archive_bytes(
        (
            (artifact_admission.ARTIFACT_BINDING_PATH, changed_bytes),
            (
                artifact_admission.ARTIFACT_SIGNATURE_PATH,
                base64.b64encode(inspected.signature),
            ),
        )
    )
    binding.write_bytes(replayed)

    with pytest.raises(artifact_admission.ArtifactAdmissionError, match="signature is invalid"):
        artifact_admission.verify_artifact_admission(
            str(binding),
            str(artifact),
            str(bundle),
            trusted_public_key_path=str(binding_public),
            trusted_finalizer_public_key_path=str(finalizer_public),
            expected_finalizer_source=source,
            expected_finalizer_context=context,
        )


def test_artifact_binding_refuses_noncanonical_shape_and_non_regular_subject(
    tmp_path: Path,
) -> None:
    with pytest.raises(artifact_admission.ArtifactAdmissionError, match="regular non-symlink"):
        artifact_admission.hash_regular_artifact(str(tmp_path))
    with pytest.raises(artifact_admission.ArtifactAdmissionError, match="subject.kind"):
        artifact_admission._validate_subject({"kind": "oci", "sha256": "a" * 64, "size": 1})
    with pytest.raises(artifact_admission.ArtifactAdmissionError, match="keys are not canonical"):
        artifact_admission._validate_subject(
            {"kind": "file", "sha256": "a" * 64, "size": 1, "url": "https://mutable"}
        )


def test_artifact_hash_rejects_a_file_that_changes_while_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"artifact")
    real_fstat = artifact_admission.os.fstat
    calls = 0

    def changing_fstat(descriptor: int):
        nonlocal calls
        calls += 1
        current = real_fstat(descriptor)
        if calls == 1:
            return current
        return SimpleNamespace(
            st_mode=current.st_mode,
            st_dev=current.st_dev,
            st_ino=current.st_ino,
            st_size=current.st_size,
            st_mtime_ns=current.st_mtime_ns + 1,
            st_ctime_ns=current.st_ctime_ns,
            st_file_attributes=getattr(current, "st_file_attributes", 0),
        )

    monkeypatch.setattr(artifact_admission.os, "fstat", changing_fstat)
    with pytest.raises(
        artifact_admission.ArtifactAdmissionError, match="changed while it was being read"
    ):
        artifact_admission.hash_regular_artifact(str(artifact))


def test_artifact_hash_rejects_a_short_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"artifact")

    class ShortReadHandle:
        def __enter__(self) -> ShortReadHandle:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _size: int) -> bytes:
            return b""

    monkeypatch.setattr(
        artifact_admission.os,
        "fdopen",
        lambda *_args, **_kwargs: ShortReadHandle(),
    )
    with pytest.raises(artifact_admission.ArtifactAdmissionError, match="read length"):
        artifact_admission.hash_regular_artifact(str(artifact))


def test_external_finalizer_json_rejects_a_symlink(tmp_path: Path) -> None:
    target = tmp_path / "source.json"
    target.write_text("{}\n", encoding="utf-8")
    link = tmp_path / "source-link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("the platform does not permit creating symlinks for this test")
    with pytest.raises(ValueError, match="regular non-symlink"):
        cli._read_external_finalizer_object(str(link), label="expected source")


def test_artifact_admission_cli_round_trip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle, _finalizer_private, finalizer_public, source, context, _decision = _finalized_allow(
        tmp_path
    )
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"artifact")
    binding_private, binding_public = _keys(tmp_path, "artifact")
    source_path = tmp_path / "source.json"
    context_path = tmp_path / "context.json"
    binding = tmp_path / "admission.eab"
    _write_json(source_path, source)
    _write_json(context_path, context)

    code = cli_main(
        [
            "seal-artifact-admission",
            str(artifact),
            str(bundle),
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

    code = cli_main(
        [
            "verify-artifact-admission",
            str(binding),
            str(artifact),
            str(bundle),
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


def test_artifact_binding_schema_is_valid_and_release_addressed(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    schema = json.loads(
        (root / "evoom_guard" / "schemas" / "artifact-binding-1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    context_schema = json.loads(
        (root / "evoom_guard" / "schemas" / "evidence-context-1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator.check_schema(schema)
    raw_base = (
        "https://raw.githubusercontent.com/EvoRiseKsa/EvoOM-Guard-m/"
        f"v{SCHEMA_ID_RELEASE}/evoom_guard/schemas/"
    )
    assert schema["$id"] == raw_base + "artifact-binding-1.schema.json"
    assert schema["properties"]["format"]["const"] == artifact_admission.ARTIFACT_BINDING_FORMAT
    assert schema["properties"]["finalizer"]["properties"]["context"] == {
        "$ref": "evidence-context-1.schema.json"
    }

    _bundle, _finalizer_private, _finalizer_public, source, context, _decision = _finalized_allow(
        tmp_path
    )
    payload = {
        "format": artifact_admission.ARTIFACT_BINDING_FORMAT,
        "decision": "ALLOW",
        "subject": {"kind": "file", "sha256": "a" * 64, "size": 0},
        "finalizer": {
            "bundle_sha256": "b" * 64,
            "record_sha256": "c" * 64,
            "key_id": "sha256:" + "d" * 64,
            "source": source,
            "context": context,
        },
        "authentication": {
            "algorithm": "Ed25519",
            "key_id": "sha256:" + "e" * 64,
            "purpose": artifact_admission.ARTIFACT_BINDING_PURPOSE,
            "signature_path": artifact_admission.ARTIFACT_SIGNATURE_PATH,
        },
    }
    registry = Registry().with_resource(
        context_schema["$id"],
        Resource.from_contents(context_schema, default_specification=DRAFT202012),
    )
    Draft202012Validator(schema, registry=registry).validate(payload)
