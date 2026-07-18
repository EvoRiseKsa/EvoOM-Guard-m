from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path

import jsonschema
import pytest

from evoom_guard import release_source_finalizer
from evoom_guard.cli import main as cli_main
from evoom_guard.finalizer_derivation import derive_raw_evaluation_bindings
from evoom_guard.pack_manifest import pack_digest
from evoom_guard.record_verifier import verify_record
from evoom_guard.signing import generate_keypair, public_key_id


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        text=True,
        capture_output=True,
    )
    return completed.stdout.strip()


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _make_raw_git_repository(tmp_path: Path) -> tuple[Path, str, str, str, str]:
    repo = tmp_path / "raw-git"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Release Source Test")
    _git(repo, "config", "core.autocrlf", "false")
    pack = repo / "security" / "pack"
    pack.mkdir(parents=True)
    (pack / "pack.json").write_text(
        json.dumps({"id": "release-source-test", "version": "1", "target_type": "python-cli"}),
        encoding="utf-8",
        newline="\n",
    )
    (pack / "test_protocol.py").write_text(
        "def test_protocol():\n    assert True\n", encoding="utf-8", newline="\n"
    )
    pin = pack_digest(str(pack))
    policy = {
        "test_command": ["python", "-m", "pytest"],
        "protected": [],
        "allow": [],
        "verifier_pack": "security/pack",
        "expect_verifier_pack_sha256": pin,
        "blackbox": True,
        "blackbox_only": True,
        "isolation": "docker",
        "docker_image": "python:3.12-slim@sha256:" + "d" * 64,
        "require_report_integrity": "external_process_isolated",
        "require_candidate_isolation": "docker",
    }
    (repo / ".evoguard.json").write_text(json.dumps(policy), encoding="utf-8", newline="\n")
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8", newline="\n")
    parent = _commit(repo, "trusted baseline")
    (repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8", newline="\n")
    target = _commit(repo, "protected main source")
    return (
        repo,
        parent,
        target,
        _git(repo, "rev-parse", f"{parent}^{{tree}}"),
        _git(repo, "rev-parse", f"{target}^{{tree}}"),
    )


def _strong_record(
    *,
    parent: str,
    target: str,
    parent_tree: str,
    target_tree: str,
    raw: dict[str, object],
) -> dict[str, object]:
    fixture = Path(__file__).parent / "fixtures" / "contracts" / "schema-1.11-golden.json"
    record = copy.deepcopy(json.loads(fixture.read_text(encoding="utf-8"))["records"]["valid_composite"])
    attestation = record["attestation"]
    assurance = record["assurance"]
    effective_policy = raw["effective_policy"]
    assert isinstance(attestation, dict)
    assert isinstance(assurance, dict)
    assert isinstance(effective_policy, dict)
    assert raw["verifier_pack_sha256"] is not None

    record.update(
        {
            "execution_phase": "blackbox_pack",
            "isolation": "docker",
            "tests_passed": 1,
            "tests_total": 1,
            "verdict_source": "blackbox",
        }
    )
    assurance.update(
        {
            "execution_phase": "blackbox_pack",
            "candidate_isolation": "docker",
            "suite_isolation": "docker",
            "report_integrity": "external_process_isolated",
            "overall_profile": "black_box_external_judge",
            "repo_native_suite": "not_required_blackbox_only",
        }
    )
    pack = assurance["verifier_pack"]
    assert isinstance(pack, dict)
    pack.update(
        {
            "snapshot_sha256": raw["verifier_pack_sha256"],
            "secrecy": "unmounted_from_candidate",
        }
    )
    attestation.update(
        {
            "candidate_sha256": raw["candidate_sha256"],
            "policy_sha256": raw["policy_sha256"],
            "verifier_pack_sha256": raw["verifier_pack_sha256"],
            "effective_policy": effective_policy,
            "policy_id": effective_policy["policy_id"],
            "policy_version": effective_policy["policy_version"],
            "base_sha": parent,
            "head_sha": target,
            "base_tree_sha": parent_tree,
            "head_tree_sha": target_tree,
            "execution_phase": "blackbox_pack",
            "mode": "blackbox",
            "delivered_isolation": "docker",
            "effective_candidate_isolation": "docker",
            "repo_suite_started": False,
            "repo_suite_completed": False,
            "repo_suite_passed": False,
            "repo_suite_state": "not_required_blackbox_only",
        }
    )
    report = verify_record(record)
    assert report["ok"], [check for check in report["checks"] if check["status"] == "fail"]
    return record


def _release_record_source_context(tmp_path: Path):
    repo, parent, target, parent_tree, target_tree = _make_raw_git_repository(tmp_path)
    source = {
        "repository": "owner/project",
        "repository_id": "12345",
        "default_branch": "main",
        "workflow_run_id": "987654321",
        "workflow_run_attempt": 1,
        "protected_ref": "refs/heads/main",
        "target_commit_sha": target,
        "target_tree_sha": target_tree,
    }
    raw = derive_raw_evaluation_bindings(
        base_repo=str(repo),
        head_repo=str(repo),
        base_sha=parent,
        head_sha=target,
        base_tree_sha=parent_tree,
        head_tree_sha=target_tree,
    )
    record = _strong_record(
        parent=parent,
        target=target,
        parent_tree=parent_tree,
        target_tree=target_tree,
        raw=raw,
    )
    bindings = release_source_finalizer.derive_release_source_bindings(
        git_repository=str(repo), source=source
    )
    context = release_source_finalizer.context_from_release_source_bindings(bindings, record)
    verdict = tmp_path / "verdict.json"
    _write_json(verdict, record)
    return repo, verdict, record, source, context


def _keys(tmp_path: Path, name: str = "release") -> tuple[Path, Path]:
    private = tmp_path / f"{name}.private.pem"
    public = tmp_path / f"{name}.public.pem"
    generate_keypair(str(private), str(public))
    return private, public


def _prohibited_key_id(tmp_path: Path) -> str:
    _private, public = _keys(tmp_path, "pr-finalizer")
    return public_key_id(str(public))


def test_release_source_handoff_and_evidence_have_a_distinct_deny_only_contract(
    tmp_path: Path,
) -> None:
    repo, verdict, record, source, context = _release_record_source_context(tmp_path)
    handoff_path = tmp_path / "release-source.handoff.json"
    bundle_path = tmp_path / "release-source.rse"
    private, public = _keys(tmp_path)
    prohibited = _prohibited_key_id(tmp_path)

    created = release_source_finalizer.create_release_source_handoff(
        str(verdict), str(handoff_path), source=source, context=context
    )
    inspected = release_source_finalizer.inspect_release_source_handoff(str(handoff_path))
    assert created == inspected.payload
    assert inspected.source == source
    assert inspected.context == context

    sealed = release_source_finalizer.seal_release_source_bundle(
        str(handoff_path),
        str(verdict),
        str(bundle_path),
        expected_source=source,
        expected_context=context,
        git_repository=str(repo),
        private_key_path=str(private),
        prohibited_key_ids=[prohibited],
    )
    assert sealed.decision == "DENY"
    assert sealed.manifest["format"] == release_source_finalizer.RELEASE_SOURCE_EVIDENCE_FORMAT
    assert sealed.manifest["authentication"]["key_domain"] == "release-source-finalizer-v1"
    assert sealed.manifest["record"]["sha256"] == release_source_finalizer._sha256(
        verdict.read_bytes()
    )
    forged_manifest = dict(sealed.manifest, decision="ALLOW")
    with pytest.raises(release_source_finalizer.ReleaseSourceFinalizerError, match="deny-only"):
        release_source_finalizer._validate_evidence_manifest(forged_manifest)

    verified = release_source_finalizer.verify_release_source_bundle(
        str(bundle_path),
        trusted_public_key_path=str(public),
        expected_source=source,
        expected_context=context,
        prohibited_key_ids=[prohibited],
    )
    assert verified.decision == "DENY"
    assert verified.record_report["ok"] is True
    assert verified.handoff.verdict == record


def test_release_source_v1_never_admits_an_untrusted_producer_record(tmp_path: Path) -> None:
    _repo, _verdict, record, _source, _context = _release_record_source_context(tmp_path)
    assert release_source_finalizer.release_source_decision(record) == "DENY"
    weak = copy.deepcopy(record)
    weak["assurance"]["report_integrity"] = "same_process_candidate_writable"
    weak["assurance"]["overall_profile"] = "repo_native_same_process"
    assert release_source_finalizer.release_source_decision(weak) == "DENY"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("protected_ref", "refs/heads/release/unsafe", "protected_ref"),
        ("default_branch", "release", "default_branch"),
        ("target_commit_sha", "not-a-git-sha", "target_commit_sha"),
        ("repository", "owner/../unsafe", "repository"),
    ],
)
def test_release_source_rejects_non_main_or_noncanonical_source(
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    _repo, verdict, _record, source, context = _release_record_source_context(tmp_path)
    changed = dict(source, **{field: value})
    with pytest.raises(release_source_finalizer.ReleaseSourceFinalizerError, match=message):
        release_source_finalizer.create_release_source_handoff(
            str(verdict), str(tmp_path / "never.json"), source=changed, context=context
        )


def test_raw_git_mismatch_stops_before_signing_key_is_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, verdict, _record, source, context = _release_record_source_context(tmp_path)
    handoff_path = tmp_path / "handoff.json"
    private, _public = _keys(tmp_path)
    release_source_finalizer.create_release_source_handoff(
        str(verdict), str(handoff_path), source=source, context=context
    )

    def unexpected_key_open(*_args, **_kwargs):
        raise AssertionError("signing key must not be opened after a raw-Git mismatch")

    import evoom_guard.signing as signing

    monkeypatch.setattr(signing, "_load_private_key_snapshot", unexpected_key_open)
    wrong_repo = tmp_path / "wrong-repo"
    wrong_repo.mkdir()
    _git(wrong_repo, "init", "-b", "main")
    _git(wrong_repo, "config", "user.email", "test@example.invalid")
    _git(wrong_repo, "config", "user.name", "Release Source Test")
    _git(wrong_repo, "config", "core.autocrlf", "false")
    (wrong_repo / ".evoguard.json").write_text("{}", encoding="utf-8")
    (wrong_repo / "app.py").write_text("VALUE = 9\n", encoding="utf-8")
    _commit(wrong_repo, "wrong base")
    (wrong_repo / "app.py").write_text("VALUE = 10\n", encoding="utf-8")
    _commit(wrong_repo, "wrong target")
    with pytest.raises(release_source_finalizer.ReleaseSourceFinalizerError, match="refs/heads/main"):
        release_source_finalizer.seal_release_source_bundle(
            str(handoff_path),
            str(verdict),
            str(tmp_path / "never.rse"),
            expected_source=source,
            expected_context=context,
            git_repository=str(wrong_repo),
            private_key_path=str(private),
            prohibited_key_ids=[_prohibited_key_id(tmp_path)],
        )
    assert repo.exists()


def test_release_source_requires_non_release_key_exclusions_before_key_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, verdict, _record, source, context = _release_record_source_context(tmp_path)
    handoff_path = tmp_path / "handoff.json"
    private, _public = _keys(tmp_path)
    release_source_finalizer.create_release_source_handoff(
        str(verdict), str(handoff_path), source=source, context=context
    )

    def unexpected_key_open(*_args, **_kwargs):
        raise AssertionError("signing key must not be opened without exclusions")

    import evoom_guard.signing as signing

    monkeypatch.setattr(signing, "_load_private_key_snapshot", unexpected_key_open)
    with pytest.raises(release_source_finalizer.ReleaseSourceFinalizerError, match="requires one or more"):
        release_source_finalizer.seal_release_source_bundle(
            str(handoff_path),
            str(verdict),
            str(tmp_path / "never.rse"),
            expected_source=source,
            expected_context=context,
            git_repository=str(repo),
            private_key_path=str(private),
        )


def test_release_source_rejects_context_replay_and_pr_finalizer_handoff(tmp_path: Path) -> None:
    _repo, verdict, _record, source, context = _release_record_source_context(tmp_path)
    handoff_path = tmp_path / "handoff.json"
    release_source_finalizer.create_release_source_handoff(
        str(verdict), str(handoff_path), source=source, context=context
    )
    wrong_context = dict(context, target_commit_sha="f" * 40)
    with pytest.raises(release_source_finalizer.ReleaseSourceFinalizerError, match="does not match context"):
        release_source_finalizer.verify_release_source_handoff(
            release_source_finalizer.inspect_release_source_handoff(str(handoff_path)),
            verdict_path=str(verdict),
            expected_source=source,
            expected_context=wrong_context,
        )

    pr_handoff = tmp_path / "pr-handoff.json"
    pr_handoff.write_bytes(
        release_source_finalizer._canonical_json(
            {
                "format": "EVOGUARD_TRUSTED_FINALIZER_HANDOFF_V1",
                "source": {},
                "context": {},
                "record": {},
            }
        )
    )
    with pytest.raises(release_source_finalizer.ReleaseSourceFinalizerError, match="unsupported"):
        release_source_finalizer.inspect_release_source_handoff(str(pr_handoff))


def test_release_source_handoff_schema_is_self_contained(tmp_path: Path) -> None:
    _repo, verdict, _record, source, context = _release_record_source_context(tmp_path)
    handoff_path = tmp_path / "handoff.json"
    handoff = release_source_finalizer.create_release_source_handoff(
        str(verdict), str(handoff_path), source=source, context=context
    )
    schema_path = (
        Path(release_source_finalizer.__file__).parent
        / "schemas"
        / "release-source-handoff-1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(handoff)


def test_release_source_context_schema_is_self_contained(tmp_path: Path) -> None:
    _repo, _verdict, _record, _source, context = _release_record_source_context(tmp_path)
    schema_path = (
        Path(release_source_finalizer.__file__).parent
        / "schemas"
        / "release-source-context-1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(context)


def test_release_source_rejects_a_signing_key_in_the_prohibited_set(tmp_path: Path) -> None:
    repo, verdict, _record, source, context = _release_record_source_context(tmp_path)
    handoff_path = tmp_path / "handoff.json"
    bundle_path = tmp_path / "never.rse"
    private, public = _keys(tmp_path)
    release_source_finalizer.create_release_source_handoff(
        str(verdict), str(handoff_path), source=source, context=context
    )

    with pytest.raises(release_source_finalizer.ReleaseSourceFinalizerError, match="prohibited"):
        release_source_finalizer.seal_release_source_bundle(
            str(handoff_path),
            str(verdict),
            str(bundle_path),
            expected_source=source,
            expected_context=context,
            git_repository=str(repo),
            private_key_path=str(private),
            prohibited_key_ids=[public_key_id(str(public))],
        )


def test_release_source_cli_round_trip_and_stdin_rejection(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo, verdict, _record, source, context = _release_record_source_context(tmp_path)
    source_path = tmp_path / "source.json"
    context_path = tmp_path / "context.json"
    handoff_path = tmp_path / "handoff.json"
    bundle_path = tmp_path / "bundle.rse"
    private, public = _keys(tmp_path)
    prohibited = _prohibited_key_id(tmp_path)
    _write_json(source_path, source)
    _write_json(context_path, context)

    assert (
        cli_main(
            [
                "release-source-handoff",
                "-",
                "--out",
                str(handoff_path),
                "--source",
                str(source_path),
                "--context",
                str(context_path),
            ]
        )
        == 2
    )
    assert "regular file" in capsys.readouterr().out
    assert (
        cli_main(
            [
                "release-source-handoff",
                str(verdict),
                "--out",
                str(handoff_path),
                "--source",
                str(source_path),
                "--context",
                str(context_path),
            ]
        )
        == 0
    )
    assert (
        cli_main(
            [
                "seal-release-source-finalizer",
                str(handoff_path),
                str(verdict),
                "--out",
                str(bundle_path),
                "--expected-source",
                str(source_path),
                "--expected-context",
                str(context_path),
                "--git-repository",
                str(repo),
                "--sign-key",
                str(private),
                "--must-differ-from-key-id",
                prohibited,
            ]
        )
        == 1
    )
    assert (
        cli_main(
            [
                "verify-release-source-finalized",
                str(bundle_path),
                "--trusted-pub",
                str(public),
                "--expected-source",
                str(source_path),
                "--expected-context",
                str(context_path),
                "--must-differ-from-key-id",
                prohibited,
                "--allow-deny-evidence",
            ]
        )
        == 0
    )
    assert (
        cli_main(
            [
                "verify-release-source-finalized",
                str(bundle_path),
                "--trusted-pub",
                str(public),
                "--expected-source",
                str(source_path),
                "--expected-context",
                str(context_path),
                "--must-differ-from-key-id",
                prohibited,
            ]
        )
        == 1
    )
