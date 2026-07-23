from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest
from test_finalizer_derivation import (
    _commit,
    _create_repository,
    _derived,
    _git,
    _record_for_pair,
)

from evoom_guard import finalizer_derivation
from evoom_guard.admission import agent_change
from evoom_guard.cli import main as cli_main
from evoom_guard.finalizer_derivation import (
    context_from_verified_bindings,
    derive_agent_change_bindings,
    write_agent_change_bindings,
    write_finalizer_bindings,
)
from evoom_guard.signing import generate_keypair
from evoom_guard.trusted_finalizer import create_finalizer_handoff


def _git_pin():
    executable = Path(shutil.which("git") or "").resolve()
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    if os.name == "posix":
        return finalizer_derivation.git_executable_pin(str(executable), digest)
    # The protected CLI intentionally requires POSIX stable-snapshot support.
    # Windows unit tests use an unopened value and replace only the pinning
    # transport; the independent pin lifecycle has its own dedicated tests.
    pin = object.__new__(finalizer_derivation.GitExecutablePin)
    object.__setattr__(pin, "executable_path", str(executable))
    object.__setattr__(pin, "executable_sha256", digest)
    return pin


@pytest.fixture(autouse=True)
def _windows_git_pin_transport(monkeypatch):
    if os.name != "nt":
        return
    real_derive = finalizer_derivation.derive_agent_change_bindings

    def derive_without_windows_snapshot(**kwargs):
        kwargs["git_executable"] = None
        return real_derive(**kwargs)

    monkeypatch.setattr(agent_change, "derive_agent_change_bindings", derive_without_windows_snapshot)
    monkeypatch.setattr(finalizer_derivation, "git_executable_pin", lambda _path, _sha: _git_pin())


def _json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def _keys(root: Path, name: str) -> tuple[Path, Path]:
    private = root / f"{name}.private.pem"
    public = root / f"{name}.public.pem"
    generate_keypair(str(private), str(public))
    return private, public


def _agent_bindings(repo: Path, base: str, head: str):
    return derive_agent_change_bindings(
        base_repo=str(repo),
        head_repo=str(repo),
        base_sha=base,
        head_sha=head,
        base_tree_sha=_git(repo, "rev-parse", f"{base}^{{tree}}"),
        head_tree_sha=_git(repo, "rev-parse", f"{head}^{{tree}}"),
    )


def _proposal(bindings, base: str, head: str) -> dict[str, object]:
    return {
        "format": agent_change.AGENT_CHANGE_PROPOSAL_FORMAT,
        "producer": {
            "id": "repair-agent",
            "kind": "automated-repair",
            "version": "1.0.0",
        },
        "source": {
            "repository": "owner/project",
            "pull_request_number": 17,
            "base_sha": base,
            "head_sha": head,
        },
        "intent": {
            "summary": "Repair the application value without changing the judge.",
            "declared_paths": list(bindings.touched_paths),
        },
        "change": {
            "candidate_sha256": bindings.candidate_sha256,
            "candidate_size": bindings.payload["candidate_size"],
            "changed_paths": list(bindings.changed_paths),
            "deleted_paths": list(bindings.deleted_paths),
            "touched_paths": list(bindings.touched_paths),
        },
        "observed_policy": {
            "policy_sha256": bindings.policy_sha256,
            "verifier_pack_sha256": bindings.verifier_pack_sha256,
        },
        "claims": [
            {
                "id": "repo-tests",
                "outcome": "PASS",
                "evidence_sha256": "f" * 64,
            }
        ],
    }


def _authorization_source(repo: Path, base: str, head: str) -> dict[str, object]:
    return {
        "repository": "owner/project",
        "repository_id": "123",
        "pull_request_number": 17,
        "authorization_run_id": "authorize-500",
        "authorization_run_attempt": 1,
        "base_sha": base,
        "head_sha": head,
        "base_tree_sha": _git(repo, "rev-parse", f"{base}^{{tree}}"),
        "head_tree_sha": _git(repo, "rev-parse", f"{head}^{{tree}}"),
    }


def _fixture(
    tmp_path: Path,
    *,
    failing: bool = False,
    extra_files: dict[str, str] | None = None,
) -> dict[str, object]:
    repo, base, head = _create_repository(tmp_path)
    if failing:
        (repo / "app.py").write_text("VALUE = 3\n", encoding="utf-8", newline="\n")
        head = _commit(repo, "failing candidate")
    if extra_files:
        for relative, content in extra_files.items():
            target = repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8", newline="\n")
        head = _commit(repo, "candidate with additional tracked paths")
    agent_bindings = _agent_bindings(repo, base, head)
    finalizer_bindings = _derived(repo, base, head)
    record = _record_for_pair(tmp_path, repo, base, head)
    source, context = context_from_verified_bindings(finalizer_bindings, record)
    verdict = tmp_path / "verdict.json"
    _json(verdict, record)
    handoff = tmp_path / "handoff.json"
    create_finalizer_handoff(
        str(verdict),
        str(handoff),
        source=source,
        context=context,
    )
    proposal_path = tmp_path / "proposal.json"
    agent_change.write_agent_change_proposal(
        _proposal(agent_bindings, base, head), str(proposal_path)
    )
    authorization_private, authorization_public = _keys(tmp_path, "authorization")
    finalizer_private, finalizer_public = _keys(tmp_path, "finalizer")
    authorization_source = _authorization_source(repo, base, head)
    authorization_path = tmp_path / "authorization.aca"
    agent_change.seal_agent_change_authorization(
        str(authorization_path),
        source=authorization_source,
        scope={
            "allowed_patterns": ["app.py"],
            "maximum_touched_paths": len(agent_bindings.touched_paths),
            "maximum_candidate_bytes": 4096,
            "allow_deletions": False,
        },
        required={
            "policy_sha256": agent_bindings.policy_sha256,
            "verifier_pack_sha256": agent_bindings.verifier_pack_sha256,
        },
        private_key_path=str(authorization_private),
    )
    return {
        "repo": repo,
        "base": base,
        "head": head,
        "bindings": agent_bindings,
        "finalizer_bindings": finalizer_bindings,
        "record": record,
        "source": source,
        "context": context,
        "verdict": verdict,
        "handoff": handoff,
        "proposal": proposal_path,
        "authorization": authorization_path,
        "authorization_source": authorization_source,
        "authorization_public": authorization_public,
        "finalizer_private": finalizer_private,
        "finalizer_public": finalizer_public,
        "git_executable": _git_pin(),
    }


def _seal(
    case: dict[str, object],
    output: Path,
    *,
    finalizer_public_key: Path | None = None,
    force: bool = False,
):
    return agent_change.seal_agent_change_finalizer_bundle(
        str(case["proposal"]),
        str(case["authorization"]),
        str(case["handoff"]),
        str(case["verdict"]),
        str(output),
        base_repo=str(case["repo"]),
        head_repo=str(case["repo"]),
        git_executable=case["git_executable"],
        expected_authorization_source=case["authorization_source"],
        authorization_public_key_path=str(case["authorization_public"]),
        expected_finalizer_source=case["source"],
        expected_context=case["context"],
        finalizer_private_key_path=str(case["finalizer_private"]),
        finalizer_public_key_path=str(finalizer_public_key or case["finalizer_public"]),
        expected_derivation=case["finalizer_bindings"].payload,
        force=force,
    )


def test_agent_change_profile_seals_and_verifies_exact_trusted_allow(tmp_path: Path) -> None:
    case = _fixture(tmp_path)
    output = tmp_path / "agent-change.evb"

    sealed = _seal(case, output)
    verified = agent_change.verify_agent_change_finalized_bundle(
        str(output),
        trusted_finalizer_public_key_path=str(case["finalizer_public"]),
        authorization_public_key_path=str(case["authorization_public"]),
        expected_authorization_source=case["authorization_source"],
        expected_finalizer_source=case["source"],
        expected_context=case["context"],
        expected_bindings=case["bindings"],
    )

    assert sealed.decision == "ALLOW"
    assert verified.decision == "ALLOW"
    assert verified.contract.bindings.touched_paths == ("app.py",)


def test_unscoped_agent_change_cannot_hide_raw_git_paths(tmp_path: Path) -> None:
    case = _fixture(tmp_path)
    proposal = json.loads(Path(case["proposal"]).read_text(encoding="utf-8"))
    proposal["change"]["candidate_sha256"] = "0" * 64
    forged = tmp_path / "forged-proposal.json"
    agent_change.write_agent_change_proposal(proposal, str(forged))
    case["proposal"] = forged

    with pytest.raises(
        agent_change.AgentChangeAdmissionError,
        match="candidate_sha256 differs from raw-Git derivation",
    ):
        _seal(case, tmp_path / "forged.evb")


def test_guard_copy_ignore_cannot_hide_tracked_path_from_authorization(tmp_path: Path) -> None:
    case = _fixture(
        tmp_path,
        extra_files={"dist/hidden.txt": "tracked but ignored by candidate serialization\n"},
    )

    assert case["bindings"].touched_paths == ("app.py", "dist/hidden.txt")
    output = tmp_path / "hidden.evb"
    with pytest.raises(
        agent_change.AgentChangeAdmissionError,
        match="outside its trusted authorization: dist/hidden.txt",
    ):
        _seal(case, output)
    assert not output.exists()


def test_guard_copy_ignore_cannot_hide_tracked_deletion(tmp_path: Path) -> None:
    repo, _initial_base, _initial_head = _create_repository(tmp_path)
    hidden = repo / "dist" / "generated.txt"
    hidden.parent.mkdir(parents=True, exist_ok=True)
    hidden.write_text("tracked baseline artifact\n", encoding="utf-8", newline="\n")
    base = _commit(repo, "track ignored-path baseline")

    hidden.unlink()
    (repo / "app.py").write_text("VALUE = 4\n", encoding="utf-8", newline="\n")
    head = _commit(repo, "agent deletes ignored tracked path")

    bindings = _agent_bindings(repo, base, head)
    assert bindings.changed_paths == ("app.py",)
    assert bindings.deleted_paths == ("dist/generated.txt",)
    assert bindings.touched_paths == ("app.py", "dist/generated.txt")


def test_nonaccepting_agent_decision_cannot_produce_admission_side_effect(
    tmp_path: Path,
) -> None:
    case = _fixture(tmp_path, failing=True)
    private_key = Path(case["finalizer_private"])
    before = private_key.stat()

    with pytest.raises(
        agent_change.AgentChangeAdmissionError,
        match="requires a verified Trusted Finalizer ALLOW",
    ):
        _seal(case, tmp_path / "denied.evb")

    assert not (tmp_path / "denied.evb").exists()
    assert private_key.stat().st_mtime_ns == before.st_mtime_ns


def test_wrong_finalizer_public_key_cannot_publish_bundle(tmp_path: Path) -> None:
    case = _fixture(tmp_path)
    _unused_private, wrong_public = _keys(tmp_path, "wrong-finalizer")
    output = tmp_path / "wrong-key.evb"

    with pytest.raises(
        agent_change.AgentChangeAdmissionError,
        match="externally trusted key|signature",
    ):
        _seal(case, output, finalizer_public_key=wrong_public)

    assert not output.exists()


def test_failed_forced_reseal_preserves_existing_output(tmp_path: Path) -> None:
    case = _fixture(tmp_path)
    _unused_private, wrong_public = _keys(tmp_path, "wrong-force-finalizer")
    output = tmp_path / "existing.evb"
    original = b"existing trusted output\n"
    output.write_bytes(original)

    with pytest.raises(
        agent_change.AgentChangeAdmissionError,
        match="externally trusted key|signature",
    ):
        _seal(
            case,
            output,
            finalizer_public_key=wrong_public,
            force=True,
        )

    assert output.read_bytes() == original


def test_success_claim_without_evidence_is_rejected() -> None:
    bindings = {
        "candidate_sha256": "a" * 64,
        "candidate_size": 10,
        "changed_paths": ["app.py"],
        "deleted_paths": [],
        "touched_paths": ["app.py"],
        "policy_sha256": "b" * 64,
        "verifier_pack_sha256": None,
    }
    proposal = {
        "format": agent_change.AGENT_CHANGE_PROPOSAL_FORMAT,
        "producer": {"id": "agent", "kind": "repair", "version": "1"},
        "source": {
            "repository": "owner/project",
            "pull_request_number": 1,
            "base_sha": "c" * 40,
            "head_sha": "d" * 40,
        },
        "intent": {"summary": "repair", "declared_paths": ["app.py"]},
        "change": {
            key: bindings[key]
            for key in (
                "candidate_sha256",
                "candidate_size",
                "changed_paths",
                "deleted_paths",
                "touched_paths",
            )
        },
        "observed_policy": {
            "policy_sha256": bindings["policy_sha256"],
            "verifier_pack_sha256": None,
        },
        "claims": [{"id": "tests", "outcome": "PASS", "evidence_sha256": None}],
    }

    with pytest.raises(agent_change.AgentChangeAdmissionError, match="bind evidence"):
        agent_change.validate_agent_change_proposal(proposal)


def test_cli_malformed_claim_outcome_fails_closed(tmp_path: Path, capsys) -> None:
    case = _fixture(tmp_path)
    proposal = json.loads(Path(case["proposal"]).read_text(encoding="utf-8"))
    proposal["claims"][0]["outcome"] = []
    malformed = tmp_path / "malformed-outcome.json"
    _json(malformed, proposal)

    assert cli_main(["validate-agent-change-proposal", str(malformed)]) == 2
    report = capsys.readouterr().out
    assert '"status": "ERROR"' in report
    assert "outcome is invalid" in report


def test_signed_authorization_cannot_allow_judge_owned_test_path(tmp_path: Path) -> None:
    repo, base, _head = _create_repository(tmp_path)
    (repo / "tests" / "test_app.py").write_text(
        "def test_value():\n    assert True\n", encoding="utf-8", newline="\n"
    )
    head = _commit(repo, "tamper with test")
    bindings = _agent_bindings(repo, base, head)
    proposal_path = tmp_path / "proposal.json"
    proposal = agent_change.write_agent_change_proposal(
        _proposal(bindings, base, head), str(proposal_path)
    )
    auth_private, auth_public = _keys(tmp_path, "auth-test")
    auth_path = tmp_path / "auth-test.aca"
    auth_source = _authorization_source(repo, base, head)
    agent_change.seal_agent_change_authorization(
        str(auth_path),
        source=auth_source,
        scope={
            "allowed_patterns": ["app.py", "tests/**"],
            "maximum_touched_paths": 2,
            "maximum_candidate_bytes": 4096,
            "allow_deletions": False,
        },
        required={
            "policy_sha256": bindings.policy_sha256,
            "verifier_pack_sha256": None,
        },
        private_key_path=str(auth_private),
    )
    authorization = agent_change.verify_agent_change_authorization(
        agent_change.inspect_agent_change_authorization(str(auth_path)),
        trusted_public_key_path=str(auth_public),
        expected_source=auth_source,
    )
    finalizer_source = {
        "pull_request_number": 17,
        "workflow_run_id": "7001",
        "workflow_run_attempt": 1,
        "base_sha": base,
        "head_sha": head,
    }
    context = {
        "repository": "owner/project",
        "repository_id": "123",
        "run_id": "7001",
        "run_attempt": 1,
        "base_sha": base,
        "head_sha": head,
        "base_tree_sha": auth_source["base_tree_sha"],
        "head_tree_sha": auth_source["head_tree_sha"],
        "candidate_sha256": bindings.candidate_sha256,
        "policy_sha256": bindings.policy_sha256,
        "verifier_pack_sha256": None,
        "guard_artifact_sha256": "e" * 64,
    }

    with pytest.raises(agent_change.AgentChangeAdmissionError, match="judge-owned path"):
        agent_change.verify_agent_change_contract(
            proposal,
            authorization,
            bindings,
            expected_finalizer_source=finalizer_source,
            expected_context=context,
        )


def test_authorization_replay_on_another_run_is_rejected(tmp_path: Path) -> None:
    case = _fixture(tmp_path)
    replay = dict(case["authorization_source"])
    replay["authorization_run_id"] = "authorize-501"

    with pytest.raises(agent_change.AgentChangeAdmissionError, match="does not exactly match"):
        agent_change.verify_agent_change_authorization(
            agent_change.inspect_agent_change_authorization(str(case["authorization"])),
            trusted_public_key_path=str(case["authorization_public"]),
            expected_source=replay,
        )


def test_authorization_and_finalizer_key_reuse_is_rejected(tmp_path: Path) -> None:
    case = _fixture(tmp_path)
    reused = tmp_path / "reused.aca"
    agent_change.seal_agent_change_authorization(
        str(reused),
        source=case["authorization_source"],
        scope={
            "allowed_patterns": ["app.py"],
            "maximum_touched_paths": 1,
            "maximum_candidate_bytes": 4096,
            "allow_deletions": False,
        },
        required={
            "policy_sha256": case["bindings"].policy_sha256,
            "verifier_pack_sha256": case["bindings"].verifier_pack_sha256,
        },
        private_key_path=str(case["finalizer_private"]),
    )
    case["authorization"] = reused
    case["authorization_public"] = case["finalizer_public"]

    with pytest.raises(agent_change.AgentChangeAdmissionError, match="distinct keys"):
        _seal(case, tmp_path / "reused.evb")


def test_agent_change_cli_profile_round_trip(tmp_path: Path, capsys) -> None:
    case = _fixture(tmp_path)
    agent_bindings = tmp_path / "agent-bindings.json"
    finalizer_bindings = tmp_path / "finalizer-bindings.json"
    authorization_source = tmp_path / "authorization-source.json"
    expected_source = tmp_path / "expected-source.json"
    expected_context = tmp_path / "expected-context.json"
    output = tmp_path / "cli-agent-change.evb"
    write_agent_change_bindings(
        case["bindings"], bindings_path=str(agent_bindings)
    )
    write_finalizer_bindings(
        case["finalizer_bindings"], bindings_path=str(finalizer_bindings)
    )
    _json(authorization_source, case["authorization_source"])
    _json(expected_source, case["source"])
    _json(expected_context, case["context"])

    assert cli_main(["validate-agent-change-proposal", str(case["proposal"])]) == 0
    assert cli_main(
        [
            "seal-agent-change-finalized",
            str(case["proposal"]),
            str(case["authorization"]),
            str(case["handoff"]),
            str(case["verdict"]),
            "--base-repo",
            str(case["repo"]),
            "--head-repo",
            str(case["repo"]),
            "--git-executable",
            case["git_executable"].executable_path,
            "--git-executable-sha256",
            case["git_executable"].executable_sha256,
            "--finalizer-bindings",
            str(finalizer_bindings),
            "--authorization-source",
            str(authorization_source),
            "--authorization-pub",
            str(case["authorization_public"]),
            "--expected-source",
            str(expected_source),
            "--expected-context",
            str(expected_context),
            "--sign-key",
            str(case["finalizer_private"]),
            "--trusted-pub",
            str(case["finalizer_public"]),
            "--out",
            str(output),
        ]
    ) == 0
    assert cli_main(
        [
            "verify-agent-change-finalized",
            str(output),
            "--agent-bindings",
            str(agent_bindings),
            "--authorization-source",
            str(authorization_source),
            "--authorization-pub",
            str(case["authorization_public"]),
            "--expected-source",
            str(expected_source),
            "--expected-context",
            str(expected_context),
            "--trusted-pub",
            str(case["finalizer_public"]),
        ]
    ) == 0

    reports = capsys.readouterr().out
    assert reports.count('"status": "VALID"') == 1
    assert reports.count('"status": "ALLOW"') == 2
