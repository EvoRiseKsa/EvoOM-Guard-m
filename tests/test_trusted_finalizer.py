from __future__ import annotations

import json
from pathlib import Path

import pytest

from evoom_guard import trusted_finalizer
from evoom_guard.cli import main as cli_main
from evoom_guard.evidence_bundle import (
    EvidenceBundleError,
    EvidenceMaterial,
    finalize_evidence_bundle,
    verify_evidence_bundle,
)
from evoom_guard.guard import guard
from evoom_guard.signing import SigningUnavailableError, generate_keypair


def _write_json(path, value) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _record_context_source(tmp_path, *, denied: bool = False):
    repo = tmp_path / "repo"
    tests = repo / "tests"
    tests.mkdir(parents=True)
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tests / "test_app.py").write_text(
        "from app import VALUE\n\ndef test_value():\n    assert VALUE == 1\n",
        encoding="utf-8",
    )
    if denied:
        candidate = (
            "<<<FILE: tests/test_app.py>>>\n"
            "def test_value():\n    assert True\n"
            "<<<END FILE>>>"
        )
    else:
        candidate = "<<<FILE: app.py>>>\nVALUE = 1\n<<<END FILE>>>"
    record = guard(
        str(repo),
        candidate,
        base_sha="a" * 40,
        head_sha="b" * 40,
        base_tree_sha="c" * 40,
        head_tree_sha="d" * 40,
    ).to_dict()
    attestation = record["attestation"]
    context = {
        "repository": "owner/project",
        "repository_id": "12345",
        "run_id": "seal-987",
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
    source = {
        "pull_request_number": 42,
        "workflow_run_id": "reverify-123",
        "workflow_run_attempt": 1,
        "base_sha": attestation["base_sha"],
        "head_sha": attestation["head_sha"],
    }
    verdict = tmp_path / "verdict.json"
    _write_json(verdict, record)
    return verdict, record, context, source


def _keys(tmp_path):
    private = tmp_path / "judge.private.pem"
    public = tmp_path / "judge.public.pem"
    generate_keypair(str(private), str(public))
    return private, public


def test_handoff_binds_exact_record_context_and_source_then_seals(tmp_path) -> None:
    verdict, record, context, source = _record_context_source(tmp_path)
    handoff_path = tmp_path / "handoff.json"
    archive = tmp_path / "sealed.evb"
    private, public = _keys(tmp_path)

    created = trusted_finalizer.create_finalizer_handoff(
        str(verdict), str(handoff_path), source=source, context=context
    )
    inspected = trusted_finalizer.inspect_finalizer_handoff(str(handoff_path))
    verified = trusted_finalizer.verify_finalizer_handoff(
        inspected,
        verdict_path=str(verdict),
        expected_source=source,
        expected_context=context,
    )
    assert created == inspected.payload
    assert verified.verdict == record
    assert verified.source == source
    assert verified.context == context

    sealed = trusted_finalizer.seal_finalizer_bundle(
        str(handoff_path),
        str(verdict),
        str(archive),
        expected_source=source,
        expected_context=context,
        private_key_path=str(private),
    )
    assert sealed.decision == "ALLOW"
    assert archive.is_file()

    verified_bundle = trusted_finalizer.verify_finalized_bundle(
        str(archive),
        trusted_public_key_path=str(public),
        expected_source=source,
        expected_context=context,
    )
    assert verified_bundle.decision == "ALLOW"
    assert verified_bundle.bundle.record_report["ok"] is True
    assert verified_bundle.handoff.verdict == record


def test_handoff_no_clobber_force_and_format_validation(tmp_path) -> None:
    verdict, _record, context, source = _record_context_source(tmp_path)
    handoff_path = tmp_path / "handoff.json"
    trusted_finalizer.create_finalizer_handoff(
        str(verdict), str(handoff_path), source=source, context=context
    )

    replacement_source = dict(source, workflow_run_id="reverify-124")
    with pytest.raises(trusted_finalizer.FinalizerHandoffError, match="refusing to overwrite"):
        trusted_finalizer.create_finalizer_handoff(
            str(verdict), str(handoff_path), source=replacement_source, context=context
        )
    replacement = trusted_finalizer.create_finalizer_handoff(
        str(verdict),
        str(handoff_path),
        source=replacement_source,
        context=context,
        force=True,
    )
    assert trusted_finalizer.inspect_finalizer_handoff(str(handoff_path)).source == replacement_source

    handoff_path.write_bytes(
        trusted_finalizer._canonical_json(
            dict(replacement, format="EVOGUARD_TRUSTED_FINALIZER_HANDOFF_V0")
        )
    )
    with pytest.raises(trusted_finalizer.FinalizerHandoffError, match="unsupported finalizer handoff"):
        trusted_finalizer.inspect_finalizer_handoff(str(handoff_path))


def test_handoff_parser_rejects_invalid_scalar_fields(tmp_path) -> None:
    _verdict, _record, context, source = _record_context_source(tmp_path)
    with pytest.raises(trusted_finalizer.FinalizerHandoffError, match="non-empty Unicode"):
        trusted_finalizer._bounded_string("", label="value", maximum=10)
    with pytest.raises(trusted_finalizer.FinalizerHandoffError, match="control characters"):
        trusted_finalizer._bounded_string("bad\x01", label="value", maximum=10)
    with pytest.raises(trusted_finalizer.FinalizerHandoffError, match="unpaired surrogate"):
        trusted_finalizer._bounded_string("\ud800", label="value", maximum=10)
    with pytest.raises(trusted_finalizer.FinalizerHandoffError, match="pull_request_number"):
        trusted_finalizer._validate_source(dict(source, pull_request_number=0))
    with pytest.raises(trusted_finalizer.FinalizerHandoffError, match="workflow_run_attempt"):
        trusted_finalizer._validate_source(dict(source, workflow_run_attempt=0))
    with pytest.raises(trusted_finalizer.FinalizerHandoffError, match="source.head_sha"):
        trusted_finalizer._validate_source(dict(source, head_sha="not-a-digest"))
    with pytest.raises(trusted_finalizer.FinalizerHandoffError, match="record.sha256"):
        trusted_finalizer._validate_record_descriptor({"sha256": "bad", "size": 1})
    with pytest.raises(trusted_finalizer.FinalizerHandoffError, match="record.size"):
        trusted_finalizer._validate_record_descriptor({"sha256": "a" * 64, "size": 0})
    assert trusted_finalizer._validate_source_context(source, context) is None


def test_seal_wraps_bundle_writer_failure(tmp_path, monkeypatch) -> None:
    verdict, _record, context, source = _record_context_source(tmp_path)
    handoff_path = tmp_path / "handoff.json"
    private, _public = _keys(tmp_path)
    trusted_finalizer.create_finalizer_handoff(
        str(verdict), str(handoff_path), source=source, context=context
    )

    def bundle_failure(*_args, **_kwargs):
        raise EvidenceBundleError("intentional bundle publication failure")

    monkeypatch.setattr(trusted_finalizer, "finalize_evidence_bundle", bundle_failure)
    with pytest.raises(trusted_finalizer.FinalizerHandoffError, match="could not seal"):
        trusted_finalizer.seal_finalizer_bundle(
            str(handoff_path),
            str(verdict),
            str(tmp_path / "never.evb"),
            expected_source=source,
            expected_context=context,
            private_key_path=str(private),
        )


def test_finalizer_preserves_signed_denial_evidence(tmp_path) -> None:
    verdict, record, context, source = _record_context_source(tmp_path, denied=True)
    handoff_path = tmp_path / "handoff.json"
    archive = tmp_path / "denied.evb"
    private, public = _keys(tmp_path)
    trusted_finalizer.create_finalizer_handoff(
        str(verdict), str(handoff_path), source=source, context=context
    )

    sealed = trusted_finalizer.seal_finalizer_bundle(
        str(handoff_path),
        str(verdict),
        str(archive),
        expected_source=source,
        expected_context=context,
        private_key_path=str(private),
    )
    assert record["verdict"] == "REJECTED"
    assert sealed.decision == "DENY"
    assert trusted_finalizer.verify_finalized_bundle(
        str(archive),
        trusted_public_key_path=str(public),
        expected_source=source,
        expected_context=context,
    ).decision == "DENY"


@pytest.mark.parametrize("field", ["head_sha", "policy_sha256", "run_id"])
def test_handoff_rejects_external_context_replay(tmp_path, field) -> None:
    verdict, _record, context, source = _record_context_source(tmp_path)
    handoff_path = tmp_path / "handoff.json"
    trusted_finalizer.create_finalizer_handoff(
        str(verdict), str(handoff_path), source=source, context=context
    )
    expected_context = dict(context)
    if field == "head_sha":
        expected_context[field] = "f" * 40
        expected_source = dict(source, head_sha="f" * 40)
    elif field == "policy_sha256":
        expected_context[field] = "f" * 64
        expected_source = source
    else:
        expected_context[field] = "another-seal-run"
        expected_source = source
    with pytest.raises(trusted_finalizer.FinalizerHandoffError):
        trusted_finalizer.verify_finalizer_handoff(
            trusted_finalizer.inspect_finalizer_handoff(str(handoff_path)),
            verdict_path=str(verdict),
            expected_source=expected_source,
            expected_context=expected_context,
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("pull_request_number", 43),
        ("workflow_run_id", "different-reverify-run"),
        ("workflow_run_attempt", 2),
    ],
)
def test_handoff_rejects_external_source_replay(tmp_path, field, replacement) -> None:
    verdict, _record, context, source = _record_context_source(tmp_path)
    handoff_path = tmp_path / "handoff.json"
    trusted_finalizer.create_finalizer_handoff(
        str(verdict), str(handoff_path), source=source, context=context
    )
    expected_source = dict(source, **{field: replacement})
    with pytest.raises(trusted_finalizer.FinalizerHandoffError, match="source"):
        trusted_finalizer.verify_finalizer_handoff(
            trusted_finalizer.inspect_finalizer_handoff(str(handoff_path)),
            verdict_path=str(verdict),
            expected_source=expected_source,
            expected_context=context,
        )


def test_handoff_rejects_record_byte_substitution(tmp_path) -> None:
    verdict, record, context, source = _record_context_source(tmp_path)
    handoff_path = tmp_path / "handoff.json"
    trusted_finalizer.create_finalizer_handoff(
        str(verdict), str(handoff_path), source=source, context=context
    )
    substituted = tmp_path / "substituted.json"
    record["attestation"]["candidate_sha256"] = "f" * 64
    _write_json(substituted, record)
    with pytest.raises(trusted_finalizer.FinalizerHandoffError, match="record does not match"):
        trusted_finalizer.verify_finalizer_handoff(
            trusted_finalizer.inspect_finalizer_handoff(str(handoff_path)),
            verdict_path=str(substituted),
            expected_source=source,
            expected_context=context,
        )


def test_handoff_rejects_noncanonical_or_unknown_shape(tmp_path) -> None:
    verdict, _record, context, source = _record_context_source(tmp_path)
    handoff_path = tmp_path / "handoff.json"
    payload = trusted_finalizer.create_finalizer_handoff(
        str(verdict), str(handoff_path), source=source, context=context
    )

    _write_json(handoff_path, payload)
    with pytest.raises(trusted_finalizer.FinalizerHandoffError, match="not canonical JSON"):
        trusted_finalizer.inspect_finalizer_handoff(str(handoff_path))

    handoff_path.write_bytes(trusted_finalizer._canonical_json(dict(payload, unexpected=True)))
    with pytest.raises(trusted_finalizer.FinalizerHandoffError, match="keys are not canonical"):
        trusted_finalizer.inspect_finalizer_handoff(str(handoff_path))


def test_seal_revalidates_before_invoking_bundle_writer(tmp_path, monkeypatch) -> None:
    verdict, _record, context, source = _record_context_source(tmp_path)
    handoff_path = tmp_path / "handoff.json"
    archive = tmp_path / "must-not-exist.evb"
    private, _public = _keys(tmp_path)
    trusted_finalizer.create_finalizer_handoff(
        str(verdict), str(handoff_path), source=source, context=context
    )
    called = False

    def should_not_sign(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("bundle writer must not be reached")

    monkeypatch.setattr(trusted_finalizer, "finalize_evidence_bundle", should_not_sign)
    wrong_context = dict(context, policy_sha256="f" * 64)
    with pytest.raises(trusted_finalizer.FinalizerHandoffError):
        trusted_finalizer.seal_finalizer_bundle(
            str(handoff_path),
            str(verdict),
            str(archive),
            expected_source=source,
            expected_context=wrong_context,
            private_key_path=str(private),
        )
    assert called is False
    assert not archive.exists()


def test_seal_reserves_handoff_material_role(tmp_path) -> None:
    verdict, _record, context, source = _record_context_source(tmp_path)
    handoff_path = tmp_path / "handoff.json"
    archive = tmp_path / "must-not-exist.evb"
    private, _public = _keys(tmp_path)
    trusted_finalizer.create_finalizer_handoff(
        str(verdict), str(handoff_path), source=source, context=context
    )
    with pytest.raises(trusted_finalizer.FinalizerHandoffError, match="reserved"):
        trusted_finalizer.seal_finalizer_bundle(
            str(handoff_path),
            str(verdict),
            str(archive),
            expected_source=source,
            expected_context=context,
            private_key_path=str(private),
            materials=(
                EvidenceMaterial(
                    role=trusted_finalizer.FINALIZER_HANDOFF_ROLE,
                    source_path=str(handoff_path),
                ),
            ),
        )


def test_verify_finalized_refuses_an_ordinary_signed_record_bundle(tmp_path) -> None:
    """A valid signed record alone must never be mistaken for a finalizer verdict."""

    verdict, _record, context, source = _record_context_source(tmp_path)
    archive = tmp_path / "ordinary.evb"
    private, public = _keys(tmp_path)
    finalize_evidence_bundle(
        str(verdict),
        str(archive),
        expected_context=context,
        private_key_path=str(private),
    )

    with pytest.raises(trusted_finalizer.FinalizerHandoffError, match="exactly one"):
        trusted_finalizer.verify_finalized_bundle(
            str(archive),
            trusted_public_key_path=str(public),
            expected_source=source,
            expected_context=context,
        )


def test_verify_finalized_never_writes_beside_the_bundle(tmp_path, monkeypatch) -> None:
    verdict, _record, context, source = _record_context_source(tmp_path)
    handoff_path = tmp_path / "handoff.json"
    archive = tmp_path / "evidence" / "sealed.evb"
    archive.parent.mkdir()
    private, public = _keys(tmp_path)
    trusted_finalizer.create_finalizer_handoff(
        str(verdict), str(handoff_path), source=source, context=context
    )
    trusted_finalizer.seal_finalizer_bundle(
        str(handoff_path),
        str(verdict),
        str(archive),
        expected_source=source,
        expected_context=context,
        private_key_path=str(private),
    )

    original_makedirs = trusted_finalizer.os.makedirs
    archive_parent = archive.parent.resolve()

    def refuse_bundle_directory(path, *args, **kwargs):
        if Path(path).resolve() == archive_parent:
            raise AssertionError("verification must not write beside its bundle")
        return original_makedirs(path, *args, **kwargs)

    monkeypatch.setattr(trusted_finalizer.os, "makedirs", refuse_bundle_directory)
    verified = trusted_finalizer.verify_finalized_bundle(
        str(archive),
        trusted_public_key_path=str(public),
        expected_source=source,
        expected_context=context,
    )
    assert verified.decision == "ALLOW"


def test_handoff_refuses_source_revision_disagreement(tmp_path) -> None:
    verdict, _record, context, source = _record_context_source(tmp_path)
    with pytest.raises(trusted_finalizer.FinalizerHandoffError, match="must exactly match"):
        trusted_finalizer.create_finalizer_handoff(
            str(verdict),
            str(tmp_path / "never.json"),
            source=dict(source, head_sha="f" * 40),
            context=context,
        )


def test_finalizer_cli_round_trip_and_gate_denial(tmp_path, capsys) -> None:
    verdict, _record, context, source = _record_context_source(tmp_path)
    context_path = tmp_path / "context.json"
    source_path = tmp_path / "source.json"
    handoff_path = tmp_path / "handoff.json"
    archive = tmp_path / "sealed.evb"
    private, public = _keys(tmp_path)
    _write_json(context_path, context)
    _write_json(source_path, source)

    code = cli_main(
        [
            "finalizer-handoff",
            str(verdict),
            "--out",
            str(handoff_path),
            "--source",
            str(source_path),
            "--context",
            str(context_path),
        ]
    )
    handoff_report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert handoff_report["status"] == "CREATED"

    code = cli_main(
        [
            "seal-finalizer",
            str(handoff_path),
            str(verdict),
            "--out",
            str(archive),
            "--expected-source",
            str(source_path),
            "--expected-context",
            str(context_path),
            "--sign-key",
            str(private),
            "--require-pass",
        ]
    )
    seal_report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert seal_report["status"] == "FINALIZED"

    code = cli_main(
        [
            "verify-finalized",
            str(archive),
            "--trusted-pub",
            str(public),
            "--expected-source",
            str(source_path),
            "--expected-context",
            str(context_path),
            "--require-pass",
        ]
    )
    verification = json.loads(capsys.readouterr().out)
    assert code == 0
    assert verification["status"] == "VERIFIED"
    assert verification["decision"] == "ALLOW"

    denied_verdict, _denied_record, denied_context, denied_source = _record_context_source(
        tmp_path / "denied", denied=True
    )
    denied_context_path = tmp_path / "denied-context.json"
    denied_source_path = tmp_path / "denied-source.json"
    denied_handoff = tmp_path / "denied-handoff.json"
    denied_archive = tmp_path / "denied.evb"
    _write_json(denied_context_path, denied_context)
    _write_json(denied_source_path, denied_source)
    assert cli_main(
        [
            "finalizer-handoff",
            str(denied_verdict),
            "--out",
            str(denied_handoff),
            "--source",
            str(denied_source_path),
            "--context",
            str(denied_context_path),
        ]
    ) == 0
    capsys.readouterr()
    code = cli_main(
        [
            "seal-finalizer",
            str(denied_handoff),
            str(denied_verdict),
            "--out",
            str(denied_archive),
            "--expected-source",
            str(denied_source_path),
            "--expected-context",
            str(denied_context_path),
            "--sign-key",
            str(private),
            "--require-pass",
        ]
    )
    denied_report = json.loads(capsys.readouterr().out)
    assert code == 1
    assert denied_report["status"] == "DENIED"
    assert denied_archive.is_file()
    code = cli_main(
        [
            "verify-finalized",
            str(denied_archive),
            "--trusted-pub",
            str(public),
            "--expected-source",
            str(denied_source_path),
            "--expected-context",
            str(denied_context_path),
            "--require-pass",
        ]
    )
    denied_verification = json.loads(capsys.readouterr().out)
    assert code == 1
    assert denied_verification["status"] == "DENIED"
    assert denied_verification["verified"] is True
    assert denied_verification["decision"] == "DENY"


def test_verify_finalized_cli_reports_missing_signing_runtime(tmp_path, capsys, monkeypatch) -> None:
    """An optional-signing failure must be a machine-readable operational error."""

    verdict, _record, context, source = _record_context_source(tmp_path)
    context_path = tmp_path / "context.json"
    source_path = tmp_path / "source.json"
    handoff_path = tmp_path / "handoff.json"
    archive = tmp_path / "sealed.evb"
    private, public = _keys(tmp_path)
    _write_json(context_path, context)
    _write_json(source_path, source)
    trusted_finalizer.create_finalizer_handoff(
        str(verdict), str(handoff_path), source=source, context=context
    )
    trusted_finalizer.seal_finalizer_bundle(
        str(handoff_path),
        str(verdict),
        str(archive),
        expected_source=source,
        expected_context=context,
        private_key_path=str(private),
    )

    def unavailable(*_args, **_kwargs) -> None:
        raise SigningUnavailableError("cryptography is unavailable for this verifier")

    monkeypatch.setattr(trusted_finalizer, "verify_bundle_signature", unavailable)
    code = cli_main(
        [
            "verify-finalized",
            str(archive),
            "--trusted-pub",
            str(public),
            "--expected-source",
            str(source_path),
            "--expected-context",
            str(context_path),
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    assert report["status"] == "INCOMPLETE"
    assert report["verified"] is False
    assert "cryptography is unavailable" in report["error"]


@pytest.mark.parametrize(
    ("arguments", "report_format"),
    [
        (
            [
                "finalize-record",
                "-",
                "--out",
                "unused.evb",
                "--expected-context",
                "unused-context.json",
                "--sign-key",
                "unused-key.pem",
            ],
            "EVOGUARD_TRUSTED_FINALIZATION_V1",
        ),
        (
            [
                "finalizer-handoff",
                "-",
                "--out",
                "unused.json",
                "--source",
                "unused-source.json",
                "--context",
                "unused-context.json",
            ],
            "EVOGUARD_TRUSTED_FINALIZER_HANDOFF_V1",
        ),
        (
            [
                "seal-finalizer",
                "unused-handoff.json",
                "-",
                "--out",
                "unused.evb",
                "--expected-source",
                "unused-source.json",
                "--expected-context",
                "unused-context.json",
                "--sign-key",
                "unused-key.pem",
            ],
            "EVOGUARD_TRUSTED_FINALIZATION_V1",
        ),
    ],
)
def test_finalizer_cli_refuses_standard_input_for_records(arguments, report_format, capsys) -> None:
    code = cli_main(arguments)
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    assert report["format"] == report_format
    assert report["status"] == "ERROR"
    assert "regular file" in report["error"]


def test_finalizer_cli_reports_unusable_external_inputs(tmp_path, capsys) -> None:
    verdict, _record, context, source = _record_context_source(tmp_path)
    context_path = tmp_path / "context.json"
    source_path = tmp_path / "source.json"
    _write_json(context_path, context)
    _write_json(source_path, source)
    source_path.write_text("[]\n", encoding="utf-8")

    code = cli_main(
        [
            "finalizer-handoff",
            str(verdict),
            "--out",
            str(tmp_path / "handoff.json"),
            "--source",
            str(source_path),
            "--context",
            str(context_path),
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    assert report["status"] == "ERROR"
    assert "source JSON must be an object" in report["error"]

    _write_json(source_path, source)
    code = cli_main(
        [
            "seal-finalizer",
            "unused-handoff.json",
            str(verdict),
            "--out",
            str(tmp_path / "unused.evb"),
            "--expected-source",
            str(source_path),
            "--expected-context",
            str(context_path),
            "--sign-key",
            "unused-key.pem",
            "--material",
            "not-a-role-path",
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    assert report["status"] == "ERROR"
    assert "invalid --material" in report["error"]

    code = cli_main(
        [
            "verify-finalized",
            "unused.evb",
            "--trusted-pub",
            "unused-public.pem",
            "--expected-source",
            str(tmp_path / "missing-source.json"),
            "--expected-context",
            str(context_path),
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    assert report["status"] == "INCOMPLETE"
    assert "unusable external trust input" in report["error"]


def test_verify_finalized_cli_reports_invalid_bundle(tmp_path, capsys) -> None:
    _verdict, _record, context, source = _record_context_source(tmp_path)
    context_path = tmp_path / "context.json"
    source_path = tmp_path / "source.json"
    bundle = tmp_path / "invalid.evb"
    _write_json(context_path, context)
    _write_json(source_path, source)
    bundle.write_text("not an evidence bundle\n", encoding="utf-8")

    code = cli_main(
        [
            "verify-finalized",
            str(bundle),
            "--trusted-pub",
            str(tmp_path / "unused-public.pem"),
            "--expected-source",
            str(source_path),
            "--expected-context",
            str(context_path),
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 1
    assert report["status"] == "INVALID"
    assert report["verified"] is False


def test_finalize_record_cli_fails_closed_before_signing(tmp_path, capsys) -> None:
    verdict, _record, context, _source = _record_context_source(tmp_path)
    context_path = tmp_path / "context.json"
    invalid_record_path = tmp_path / "not-an-object.json"
    invalid_context_path = tmp_path / "not-an-object-context.json"
    _write_json(context_path, context)
    invalid_record_path.write_text("[]\n", encoding="utf-8")
    invalid_context_path.write_text("[]\n", encoding="utf-8")

    code = cli_main(
        [
            "finalize-record",
            str(invalid_record_path),
            "--out",
            str(tmp_path / "unused-record.evb"),
            "--expected-context",
            str(context_path),
            "--sign-key",
            "unused-key.pem",
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 1
    assert report["status"] == "INVALID_RECORD"

    code = cli_main(
        [
            "finalize-record",
            str(verdict),
            "--out",
            str(tmp_path / "unused-context.evb"),
            "--expected-context",
            str(invalid_context_path),
            "--sign-key",
            "unused-key.pem",
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    assert report["status"] == "ERROR"
    assert "context JSON must be an object" in report["error"]

    code = cli_main(
        [
            "finalize-record",
            str(verdict),
            "--out",
            str(tmp_path / "unused-material.evb"),
            "--expected-context",
            str(context_path),
            "--sign-key",
            "unused-key.pem",
            "--material",
            "missing-separator",
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 2
    assert report["status"] == "ERROR"
    assert "invalid --material" in report["error"]


def test_finalize_record_cli_is_explicitly_provenance_only(tmp_path, capsys) -> None:
    verdict, _record, context, _source = _record_context_source(tmp_path)
    context_path = tmp_path / "context.json"
    archive = tmp_path / "finalized.evb"
    private, public = _keys(tmp_path)
    _write_json(context_path, context)

    code = cli_main(
        [
            "finalize-record",
            str(verdict),
            "--out",
            str(archive),
            "--expected-context",
            str(context_path),
            "--sign-key",
            str(private),
            "--require-pass",
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert report["status"] == "FINALIZED"
    assert report["decision"] == "ALLOW"
    verified = verify_evidence_bundle(
        str(archive),
        trusted_public_key_path=str(public),
        expected_context=context,
    )
    assert verified.verdict["verdict"] == "PASS"
