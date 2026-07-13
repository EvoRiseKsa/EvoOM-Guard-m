"""End-to-end CLI contract for authenticated evidence envelopes."""

from __future__ import annotations

import json

from evoom_guard import evidence_bundle
from evoom_guard.cli import main as cli_main
from evoom_guard.guard import guard
from evoom_guard.signing import generate_keypair


def _record_and_context(tmp_path):
    repo = tmp_path / "repo"
    tests = repo / "tests"
    tests.mkdir(parents=True)
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tests / "test_app.py").write_text(
        "from app import VALUE\n\ndef test_value():\n    assert VALUE == 1\n",
        encoding="utf-8",
    )
    candidate = (
        "<<<FILE: tests/test_app.py>>>\n"
        "def test_value():\n    assert True\n"
        "<<<END FILE>>>\n"
    )
    record = guard(str(repo), candidate).to_dict()
    attestation = record["attestation"]
    context = {
        "repository": "owner/project",
        "repository_id": "12345",
        "run_id": "98765",
        "run_attempt": 1,
        "base_sha": attestation["base_sha"],
        "head_sha": attestation["head_sha"],
        "base_tree_sha": attestation["base_tree_sha"],
        "head_tree_sha": attestation["head_tree_sha"],
        "candidate_sha256": attestation["candidate_sha256"],
        "policy_sha256": attestation["policy_sha256"],
        "verifier_pack_sha256": attestation["verifier_pack_sha256"],
        "guard_artifact_sha256": "c" * 64,
    }
    return record, context


def _write_json(path, value) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def test_bundle_and_verify_cli_require_external_context_and_key(tmp_path, capsys) -> None:
    record, context = _record_and_context(tmp_path)
    verdict = tmp_path / "verdict.json"
    context_path = tmp_path / "context.json"
    archive = tmp_path / "evidence.evb"
    private = tmp_path / "judge.pem"
    public = tmp_path / "judge.pub"
    _write_json(verdict, record)
    _write_json(context_path, context)
    generate_keypair(str(private), str(public))

    code = cli_main(
        [
            "bundle-evidence",
            str(verdict),
            "--out",
            str(archive),
            "--context",
            str(context_path),
            "--sign-key",
            str(private),
        ]
    )
    creation = json.loads(capsys.readouterr().out)
    assert code == 0
    assert creation["status"] == "CREATED"
    assert archive.is_file()

    verified_api = evidence_bundle.verify_evidence_bundle(
        str(archive),
        trusted_public_key_path=str(public),
        expected_context=context,
    )
    assert isinstance(verified_api, evidence_bundle.VerifiedBundle)
    assert isinstance(verified_api.authenticated, evidence_bundle.AuthenticatedBundle)
    assert isinstance(verified_api.inspection, evidence_bundle.InspectedBundle)
    assert verified_api.record_report["ok"] is True
    assert verified_api.verdict["verdict"] == "REJECTED"

    code = cli_main(
        [
            "verify-bundle",
            str(archive),
            "--trusted-pub",
            str(public),
            "--expect-context",
            str(context_path),
        ]
    )
    verification = json.loads(capsys.readouterr().out)
    assert code == 0
    assert verification["status"] == "VERIFIED"
    assert verification["verified"] is True
    assert verification["decision"] == {
        "verdict": "REJECTED",
        "passed": False,
        "reason_code": "protected_harness_edit",
        "exit_code": 1,
    }
    assert verification["pass_gate"] == "DENY"
    assert verification["claims"] == {
        "canonical_container": "pass",
        "expected_context": "pass",
        "external_key_signature": "pass",
        "record_semantics": "pass",
    }

    code = cli_main(
        [
            "verify-bundle",
            str(archive),
            "--trusted-pub",
            str(public),
            "--expect-context",
            str(context_path),
            "--require-pass",
        ]
    )
    denied = json.loads(capsys.readouterr().out)
    assert code == 1
    assert denied["status"] == "DENIED"
    assert denied["verified"] is True
    assert denied["pass_gate"] == "DENY"
    assert denied["decision"]["verdict"] == "REJECTED"

    wrong_context = dict(context)
    wrong_context["repository_id"] = "99999"
    wrong_context_path = tmp_path / "wrong-context.json"
    _write_json(wrong_context_path, wrong_context)
    code = cli_main(
        [
            "verify-bundle",
            str(archive),
            "--trusted-pub",
            str(public),
            "--expect-context",
            str(wrong_context_path),
        ]
    )
    rejected = json.loads(capsys.readouterr().out)
    assert code == 1
    assert rejected["status"] == "INVALID"
    assert rejected["claims"]["expected_context"] == "fail"


def test_bundle_cli_refuses_semantically_invalid_record(tmp_path, capsys) -> None:
    record, context = _record_and_context(tmp_path)
    record["passed"] = True
    verdict = tmp_path / "invalid.json"
    context_path = tmp_path / "context.json"
    archive = tmp_path / "must-not-exist.evb"
    private = tmp_path / "judge.pem"
    public = tmp_path / "judge.pub"
    _write_json(verdict, record)
    _write_json(context_path, context)
    generate_keypair(str(private), str(public))

    code = cli_main(
        [
            "bundle-evidence",
            str(verdict),
            "--out",
            str(archive),
            "--context",
            str(context_path),
            "--sign-key",
            str(private),
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 1
    assert report["status"] == "INVALID_RECORD"
    assert not archive.exists()


def test_verify_bundle_cli_rejects_noncanonical_container(tmp_path, capsys) -> None:
    record, context = _record_and_context(tmp_path)
    verdict = tmp_path / "verdict.json"
    context_path = tmp_path / "context.json"
    archive = tmp_path / "evidence.evb"
    prefixed = tmp_path / "prefixed.evb"
    private = tmp_path / "judge.pem"
    public = tmp_path / "judge.pub"
    _write_json(verdict, record)
    _write_json(context_path, context)
    generate_keypair(str(private), str(public))
    assert (
        cli_main(
            [
                "bundle-evidence",
                str(verdict),
                "--out",
                str(archive),
                "--context",
                str(context_path),
                "--sign-key",
                str(private),
            ]
        )
        == 0
    )
    capsys.readouterr()
    prefixed.write_bytes(b"UNSIGNED" + archive.read_bytes())

    code = cli_main(
        [
            "verify-bundle",
            str(prefixed),
            "--trusted-pub",
            str(public),
            "--expect-context",
            str(context_path),
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert code == 1
    assert report["status"] == "INVALID"
    assert report["claims"]["canonical_container"] == "fail"
