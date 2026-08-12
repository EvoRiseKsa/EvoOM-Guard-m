from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from evoom_guard import finalizer_derivation, trusted_finalizer
from evoom_guard.cli import main as cli_main
from evoom_guard.finalizer_derivation import (
    FINALIZER_DERIVATION_FORMAT,
    MAX_GIT_STDERR_BYTES,
    FinalizerDerivationError,
    _git_command,
    _GitReader,
    context_from_verified_bindings,
    derive_agent_change_bindings_v2,
    derive_finalizer_bindings,
    read_finalizer_bindings,
    resolve_raw_git_regular_blob,
    write_finalizer_bindings,
)
from evoom_guard.guard import (
    _effective_policy,
    blocks_from_dirs,
    effective_policy_sha256,
    guard,
    serialize_candidate_blocks,
)
from evoom_guard.pack_manifest import pack_digest
from evoom_guard.signing import generate_keypair


def _git(directory: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(directory), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _commit(directory: Path, message: str) -> str:
    _git(directory, "add", "--all")
    _git(
        directory,
        "-c",
        "user.name=EvoGuard Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-m",
        message,
    )
    return _git(directory, "rev-parse", "HEAD")


def _checkout(source: Path, destination: Path, revision: str) -> None:
    subprocess.run(
        ["git", "-c", "core.autocrlf=false", "clone", "--quiet", str(source), str(destination)],
        check=True,
    )
    _git(destination, "config", "core.autocrlf", "false")
    _git(destination, "checkout", "--quiet", revision)


def _source(base: str, head: str) -> dict[str, object]:
    return {
        "pull_request_number": 17,
        "workflow_run_id": "7001",
        "workflow_run_attempt": 1,
        "base_sha": base,
        "head_sha": head,
    }


def _create_repository(tmp_path: Path, *, with_pack: bool = False) -> tuple[Path, str, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    tests = repo / "tests"
    tests.mkdir()
    (tests / "test_app.py").write_text(
        "from app import VALUE\n\ndef test_value():\n    assert VALUE in {1, 2}\n",
        encoding="utf-8",
    )
    policy: dict[str, object] = {}
    if with_pack:
        pack = repo / "security" / "pack"
        pack.mkdir(parents=True)
        (pack / "pack.json").write_text(
            '{"id":"guard-test","version":"1"}\n',
            encoding="utf-8",
            newline="\n",
        )
        (pack / "test_external.py").write_text(
            "def test_external_target():\n    assert True\n",
            encoding="utf-8",
            newline="\n",
        )
        policy["verifier_pack"] = "security/pack"
        policy["expect_verifier_pack_sha256"] = pack_digest(str(pack))
    (repo / ".evoguard.json").write_text(json.dumps(policy) + "\n", encoding="utf-8", newline="\n")
    base = _commit(repo, "base")
    (repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    head = _commit(repo, "candidate")
    return repo, base, head


def _create_harness_repository(tmp_path: Path) -> tuple[Path, str, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    harness = repo / "ci" / "run-suite.py"
    harness.parent.mkdir()
    harness.write_text("print('trusted judge')\n", encoding="utf-8")
    (repo / ".evoguard.json").write_text(
        json.dumps({"harness_inputs": ["ci/run-suite.py"]}) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    base = _commit(repo, "base")
    (repo / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    head = _commit(repo, "candidate")
    return repo, base, head


def test_raw_git_v2_distinguishes_historical_candidate_marker_collision(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "identity-repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    (repo / ".evoguard.json").write_text("{}\n", encoding="utf-8", newline="\n")
    base = _commit(repo, "identity base")

    (repo / "a").write_text("x\n<<<END FILE>>>\n<<<FILE: b>>>\ny", encoding="utf-8", newline="\n")
    first = _commit(repo, "embedded marker")
    _git(repo, "checkout", "--quiet", base)
    (repo / "a").write_text("x", encoding="utf-8", newline="\n")
    (repo / "b").write_text("y", encoding="utf-8", newline="\n")
    second = _commit(repo, "two files")

    def derive(head: str):
        return derive_agent_change_bindings_v2(
            base_repo=str(repo),
            head_repo=str(repo),
            base_sha=base,
            head_sha=head,
            base_tree_sha=_git(repo, "rev-parse", f"{base}^{{tree}}"),
            head_tree_sha=_git(repo, "rev-parse", f"{head}^{{tree}}"),
        )

    embedded = derive(first)
    split = derive(second)
    assert embedded.legacy_guard_candidate_sha256 == split.legacy_guard_candidate_sha256
    assert embedded.candidate_identity["sha256"] != split.candidate_identity["sha256"]
    assert embedded.changed_paths == ("a",)
    assert split.changed_paths == ("a", "b")


def test_v2_candidate_identity_represents_a_deletion_only_change(tmp_path: Path) -> None:
    repo, _initial_base, head = _create_repository(tmp_path)
    base = head
    (repo / "app.py").unlink()
    deletion = _commit(repo, "delete app")

    bindings = derive_agent_change_bindings_v2(
        base_repo=str(repo),
        head_repo=str(repo),
        base_sha=base,
        head_sha=deletion,
        base_tree_sha=_git(repo, "rev-parse", f"{base}^{{tree}}"),
        head_tree_sha=_git(repo, "rev-parse", f"{deletion}^{{tree}}"),
    )

    assert bindings.candidate_identity["file_count"] == 0
    assert bindings.changed_paths == ()
    assert bindings.deleted_paths == ("app.py",)
    assert bindings.candidate_size == 0
    assert bindings.candidate_identity["size"] > 0


def test_v2_candidate_identity_rejects_wrong_evaluable_file_count(tmp_path: Path) -> None:
    repo, base, head = _create_repository(tmp_path)
    bindings = derive_agent_change_bindings_v2(
        base_repo=str(repo),
        head_repo=str(repo),
        base_sha=base,
        head_sha=head,
        base_tree_sha=_git(repo, "rev-parse", f"{base}^{{tree}}"),
        head_tree_sha=_git(repo, "rev-parse", f"{head}^{{tree}}"),
    )
    payload = json.loads(json.dumps(bindings.payload))
    payload["candidate_identity"]["file_count"] = len(payload["changed_paths"]) + 1

    with pytest.raises(
        FinalizerDerivationError,
        match="candidate_identity.file_count does not match evaluable changed_paths",
    ):
        finalizer_derivation.validate_agent_change_bindings(payload)


def test_v2_selection_profile_does_not_follow_mutable_guard_copy_ignore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base, head = _create_repository(tmp_path)

    def derive():
        return derive_agent_change_bindings_v2(
            base_repo=str(repo),
            head_repo=str(repo),
            base_sha=base,
            head_sha=head,
            base_tree_sha=_git(repo, "rev-parse", f"{base}^{{tree}}"),
            head_tree_sha=_git(repo, "rev-parse", f"{head}^{{tree}}"),
        )

    before = derive()
    monkeypatch.setattr(finalizer_derivation, "COPY_IGNORE", ("app.py",))
    after = derive()

    assert after.payload == before.payload
    assert after.payload["candidate_selection_profile"] == (
        "EVOGUARD_AGENT_CHANGE_CANDIDATE_SELECTION_V1"
    )
    assert after.candidate_identity["file_count"] == 1


def test_v2_path_arrays_use_utf8_byte_order() -> None:
    payload = {
        "format": "EVOGUARD_AGENT_CHANGE_GIT_BINDINGS_V2",
        "git_object_format": "sha1",
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "base_tree_sha": "c" * 40,
        "head_tree_sha": "d" * 40,
        "candidate_selection_profile": "EVOGUARD_AGENT_CHANGE_CANDIDATE_SELECTION_V1",
        "candidate_identity": {
            "format": "EVOGUARD_CANDIDATE_TEXT_MAP_V2",
            "sha256": "e" * 64,
            "size": 80,
            "file_count": 2,
        },
        "legacy_guard_candidate_sha256": "f" * 64,
        "legacy_guard_candidate_size": 2,
        "changed_paths": ["\ue000", "\U00010000"],
        "deleted_paths": [],
        "touched_paths": ["\ue000", "\U00010000"],
        "policy_sha256": "1" * 64,
        "verifier_pack_sha256": None,
    }
    assert finalizer_derivation.validate_agent_change_bindings(payload).payload == payload

    payload["changed_paths"] = ["\U00010000", "\ue000"]
    with pytest.raises(FinalizerDerivationError, match="sorted and unique"):
        finalizer_derivation.validate_agent_change_bindings(payload)


def test_v2_unknown_candidate_selection_profile_fails_closed(tmp_path: Path) -> None:
    repo, base, head = _create_repository(tmp_path)
    bindings = derive_agent_change_bindings_v2(
        base_repo=str(repo),
        head_repo=str(repo),
        base_sha=base,
        head_sha=head,
        base_tree_sha=_git(repo, "rev-parse", f"{base}^{{tree}}"),
        head_tree_sha=_git(repo, "rev-parse", f"{head}^{{tree}}"),
    )
    payload = json.loads(json.dumps(bindings.payload))
    payload["candidate_selection_profile"] = "UNKNOWN"
    with pytest.raises(FinalizerDerivationError, match="selection_profile is unsupported"):
        finalizer_derivation.validate_agent_change_bindings(payload)


def _derived(
    repo: Path,
    base: str,
    head: str,
):
    return derive_finalizer_bindings(
        base_repo=str(repo),
        head_repo=str(repo),
        base_sha=base,
        head_sha=head,
        base_tree_sha=_git(repo, "rev-parse", f"{base}^{{tree}}"),
        head_tree_sha=_git(repo, "rev-parse", f"{head}^{{tree}}"),
        source=_source(base, head),
        repository="owner/project",
        repository_id="123",
        guard_artifact_sha256="a" * 64,
    )


def _record_for_pair(
    tmp_path: Path,
    repo: Path,
    base: str,
    head: str,
    *,
    harness_inputs: tuple[str, ...] = (),
) -> dict[str, object]:
    base_dir = tmp_path / "base"
    head_dir = tmp_path / "head"
    _checkout(repo, base_dir, base)
    _checkout(repo, head_dir, head)
    blocks, deleted = blocks_from_dirs(str(base_dir), str(head_dir))
    result = guard(
        str(base_dir),
        serialize_candidate_blocks(blocks),
        deleted=tuple(deleted),
        file_blocks=blocks,
        base_sha=base,
        head_sha=head,
        base_tree_sha=_git(repo, "rev-parse", f"{base}^{{tree}}"),
        head_tree_sha=_git(repo, "rev-parse", f"{head}^{{tree}}"),
        harness_inputs=harness_inputs,
    )
    record = result.to_dict()
    assert record["attestation"] is not None
    return record


def test_finalizer_policy_derivation_preserves_operating_profile() -> None:
    raw_policy = json.dumps(
        {
            "operating_profile": "protected",
            "blackbox": True,
            "blackbox_only": True,
            "isolation": "docker",
            "docker_image": "judge:latest",
            "docker_network": "none",
            "verifier_pack": "security/judge-pack",
            "expect_verifier_pack_sha256": "a" * 64,
            "require_report_integrity": "external_process_isolated",
            "require_candidate_isolation": "docker",
        }
    ).encode()

    policy, pack, pin = finalizer_derivation._effective_policy_from_raw_config(
        raw_policy,
        head_has_package_json=False,
    )

    assert policy["operating_profile"] == "protected"
    assert pack == "security/judge-pack"
    assert pin == "a" * 64


def test_hostile_node_finalizer_preserves_explicit_memory_limit() -> None:
    raw_policy = json.dumps(
        {
            "operating_profile": "hostile",
            "blackbox": True,
            "blackbox_only": True,
            "isolation": "gvisor",
            "docker_image": "judge@sha256:" + "b" * 64,
            "docker_network": "none",
            "verifier_pack": "security/judge-pack",
            "expect_verifier_pack_sha256": "a" * 64,
            "require_report_integrity": "external_process_isolated",
            "require_candidate_isolation": "gvisor",
            "mem_limit": 1024,
        }
    ).encode()

    policy, _pack, _pin = finalizer_derivation._effective_policy_from_raw_config(
        raw_policy,
        head_has_package_json=True,
    )

    assert policy["operating_profile"] == "hostile"
    assert policy["mem_limit_mb"] == 1024


def test_integer_coverage_floor_is_canonical_between_api_and_finalizer() -> None:
    finalizer_policy, pack, pin = finalizer_derivation._effective_policy_from_raw_config(
        json.dumps({"min_diff_coverage": 80}).encode(),
        head_has_package_json=False,
    )
    api_policy = _effective_policy(
        mode="repo",
        isolation="subprocess",
        docker_image=None,
        docker_network="none",
        test_command=None,
        setup_command=None,
        trust_setup_on_host=False,
        setup_output_globs=(),
        protected=(),
        allow=(),
        allow_new_tests=False,
        timeout=120,
        mem_limit_mb=1024,
        verifier_pack=None,
        expect_verifier_pack_sha256=None,
        blackbox=False,
        blackbox_only=False,
        require_report_integrity=None,
        require_candidate_isolation=None,
        min_diff_coverage=80,
        baseline_evidence=False,
        require_demonstrated_fix=False,
        strict_harness=False,
        policy_id=None,
        policy_version=None,
    )

    assert pack is None
    assert pin is None
    assert type(api_policy["min_diff_coverage"]) is float
    assert api_policy == finalizer_policy
    assert effective_policy_sha256(api_policy) == effective_policy_sha256(finalizer_policy)


@pytest.mark.parametrize(
    ("stream", "maximum", "message"),
    [
        ("stdout", 1024, "Git object listing exceeds the finalizer limit"),
        ("stderr", MAX_GIT_STDERR_BYTES, "Git error output exceeds the finalizer limit"),
    ],
)
def test_raw_git_command_bounds_pipes_while_the_child_is_running(
    monkeypatch: pytest.MonkeyPatch,
    stream: str,
    maximum: int,
    message: str,
) -> None:
    """The finalizer kills a noisy Git child instead of buffering it all first."""

    payload = maximum + 1
    script = (
        "import sys\n"
        f"target = sys.{stream}.buffer\n"
        f"target.write(b'x' * {payload})\n"
        "target.flush()\n"
    )
    real_popen = subprocess.Popen
    killed: list[bool] = []

    class TrackingProcess:
        def __init__(self, inner: subprocess.Popen[bytes]) -> None:
            self._inner = inner
            self.stdout = inner.stdout
            self.stderr = inner.stderr

        @property
        def returncode(self) -> int | None:
            return self._inner.returncode

        @property
        def pid(self) -> int:
            return self._inner.pid

        def wait(self, *args: object, **kwargs: object) -> int:
            return self._inner.wait(*args, **kwargs)

        def poll(self) -> int | None:
            return self._inner.poll()

        def kill(self) -> None:
            killed.append(True)
            self._inner.kill()

    def noisy_git(_command: list[str], **kwargs: object) -> TrackingProcess:
        return TrackingProcess(real_popen([sys.executable, "-c", script], **kwargs))

    monkeypatch.setattr(finalizer_derivation.subprocess, "Popen", noisy_git)

    def terminate_noisy_git(process: TrackingProcess, _limits: object) -> bool:
        killed.append(True)
        process.kill()
        process.wait(timeout=3)
        return process.returncode is not None

    monkeypatch.setattr(
        finalizer_derivation,
        "terminate_process_tree",
        terminate_noisy_git,
    )

    with pytest.raises(FinalizerDerivationError, match=message):
        _git_command(".", ["rev-parse", "HEAD"], bare=False, limit=maximum)

    assert killed


def test_raw_git_command_ignores_ambient_repository_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repos: list[tuple[Path, str]] = []
    for name in ("expected", "ambient"):
        repo = tmp_path / name
        repo.mkdir()
        _git(repo, "init", "--quiet")
        (repo / "identity.txt").write_text(name + "\n", encoding="utf-8")
        repos.append((repo, _commit(repo, name)))
    expected_repo, expected_commit = repos[0]
    ambient_repo, ambient_commit = repos[1]
    assert expected_commit != ambient_commit
    expected_bare = tmp_path / "expected.git"
    ambient_bare = tmp_path / "ambient.git"
    for source, destination in (
        (expected_repo, expected_bare),
        (ambient_repo, ambient_bare),
    ):
        subprocess.run(
            ["git", "clone", "--bare", "--quiet", str(source), str(destination)],
            check=True,
        )
    monkeypatch.setenv("GIT_DIR", str(ambient_repo / ".git"))

    observed = _git_command(
        str(expected_repo),
        ["rev-parse", "HEAD"],
        bare=False,
        limit=256,
    )

    assert observed.decode("ascii").strip() == expected_commit
    monkeypatch.delenv("GIT_DIR")
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", str(ambient_bare / "objects"))

    bare_commit = _git_command(
        str(expected_bare),
        ["cat-file", "commit", expected_commit],
        bare=True,
        limit=4096,
    )

    assert bare_commit.endswith(b"\n\nexpected\n")


def test_raw_git_command_scrubs_all_ambient_git_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class FinishedGit:
        stdout = io.BytesIO(b"literal-output\n")
        stderr = io.BytesIO()
        returncode = 0

        def poll(self) -> int:
            return 0

        def wait(self, *, timeout: float | None = None) -> int:
            assert timeout == finalizer_derivation._GIT_KILL_REAP_SECONDS
            return 0

        def kill(self) -> None:  # pragma: no cover - success path only
            raise AssertionError("successful fake Git must not be killed")

    def fake_popen(command: list[str], **kwargs: object) -> FinishedGit:
        observed["command"] = command
        observed["environment"] = kwargs["env"]
        return FinishedGit()

    monkeypatch.setenv("GIT_DIR", "ambient-repository")
    monkeypatch.setenv("gIt_Config_Count", "1")
    monkeypatch.setenv("GIT_OPTIONAL_LOCKS", "ambient-value")
    monkeypatch.setenv("EVOGUARD_ENV_SENTINEL", "preserved")
    monkeypatch.setattr(finalizer_derivation.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        finalizer_derivation,
        "terminate_process_tree",
        lambda *_args: True,
    )

    output = _git_command("explicit-repository", ["rev-parse", "HEAD"], bare=False)

    environment = observed["environment"]
    assert isinstance(environment, dict)
    assert {key for key in environment if key.upper().startswith("GIT_")} == {"GIT_OPTIONAL_LOCKS"}
    assert environment["GIT_OPTIONAL_LOCKS"] == "0"
    assert environment["EVOGUARD_ENV_SENTINEL"] == "preserved"
    assert observed["command"] == [
        "git",
        "--no-replace-objects",
        "-C",
        "explicit-repository",
        "rev-parse",
        "HEAD",
    ]
    assert output == b"literal-output\n"


@pytest.mark.parametrize("bare", [False, True])
def test_raw_git_reader_ignores_replace_refs(tmp_path: Path, bare: bool) -> None:
    repo = tmp_path / "source"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    (repo / "good.txt").write_text("trusted\n", encoding="utf-8")
    expected_commit = _commit(repo, "expected tree")
    expected_tree = _git(repo, "rev-parse", f"{expected_commit}^{{tree}}")
    (repo / "good.txt").unlink()
    (repo / "evil.txt").write_text("replacement\n", encoding="utf-8")
    replacement_commit = _commit(repo, "replacement tree")
    replacement_tree = _git(repo, "rev-parse", f"{replacement_commit}^{{tree}}")

    if bare:
        reader_repo = tmp_path / "objects.git"
        subprocess.run(
            ["git", "clone", "--bare", "--quiet", str(repo), str(reader_repo)],
            check=True,
        )
        prefix = ["git", "--git-dir", str(reader_repo)]
    else:
        reader_repo = repo
        prefix = ["git", "-C", str(reader_repo)]
    subprocess.run(
        [*prefix, "replace", expected_tree, replacement_tree],
        check=True,
        capture_output=True,
    )
    replaced_view = subprocess.run(
        [*prefix, "ls-tree", "-r", "--name-only", expected_commit],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    assert replaced_view == ["evil.txt"]

    reader = _GitReader(str(reader_repo), bare=bare)

    assert reader.commit_tree(expected_commit) == expected_tree
    assert set(reader.tree(expected_commit)) == {"good.txt"}


def test_public_raw_git_regular_blob_boundary_returns_only_regular_blob_id(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "source"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    workflow = repo / ".github" / "workflows" / "admit.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("name: admit\n", encoding="utf-8")
    commit = _commit(repo, "protected workflow")
    tree = _git(repo, "rev-parse", f"{commit}^{{tree}}")
    blob = _git(repo, "rev-parse", f"{commit}:.github/workflows/admit.yml")

    assert (
        resolve_raw_git_regular_blob(
            repository=str(repo),
            treeish=tree,
            path=".github/workflows/admit.yml",
        )
        == blob
    )
    with pytest.raises(FinalizerDerivationError, match="missing or is not a regular"):
        resolve_raw_git_regular_blob(
            repository=str(repo),
            treeish=tree,
            path=".github/workflows/missing.yml",
        )


def test_raw_git_derivation_matches_guard_candidate_and_policy(tmp_path: Path) -> None:
    repo, base, head = _create_repository(tmp_path)
    bindings = _derived(repo, base, head)
    record = _record_for_pair(tmp_path, repo, base, head)

    source, context = context_from_verified_bindings(bindings, record)

    assert bindings.payload["format"] == FINALIZER_DERIVATION_FORMAT
    assert bindings.candidate_sha256 == record["attestation"]["candidate_sha256"]
    assert bindings.policy_sha256 == record["attestation"]["policy_sha256"]
    assert source == _source(base, head)
    assert context["candidate_sha256"] == bindings.candidate_sha256
    assert context["verifier_pack_sha256"] is None


def test_high_assurance_sealing_accepts_matching_raw_git_derivation(tmp_path: Path) -> None:
    repo, base, head = _create_repository(tmp_path)
    bindings = _derived(repo, base, head)
    record = _record_for_pair(tmp_path, repo, base, head)
    source, context = context_from_verified_bindings(bindings, record)
    verdict_path = tmp_path / "verdict.json"
    verdict_path.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
    handoff_path = tmp_path / "handoff.json"
    trusted_finalizer.create_finalizer_handoff(
        str(verdict_path),
        str(handoff_path),
        source=source,
        context=context,
    )
    private_key = tmp_path / "finalizer.private.pem"
    public_key = tmp_path / "finalizer.public.pem"
    generate_keypair(str(private_key), str(public_key))

    sealed = trusted_finalizer.seal_finalizer_bundle(
        str(handoff_path),
        str(verdict_path),
        str(tmp_path / "finalized.evb"),
        expected_source=source,
        expected_context=context,
        private_key_path=str(private_key),
        expected_derivation=bindings.payload,
    )

    assert sealed.decision == "ALLOW"


def test_raw_git_derivation_matches_guard_with_declared_harness_input(
    tmp_path: Path,
) -> None:
    repo, base, head = _create_harness_repository(tmp_path)
    bindings = _derived(repo, base, head)
    record = _record_for_pair(
        tmp_path,
        repo,
        base,
        head,
        harness_inputs=("ci/run-suite.py",),
    )

    _source_payload, context = context_from_verified_bindings(bindings, record)

    assert bindings.effective_policy["harness_inputs"] == ["ci/run-suite.py"]
    assert bindings.policy_sha256 == record["attestation"]["policy_sha256"]
    assert context["candidate_sha256"] == bindings.candidate_sha256


def test_raw_git_derivation_rejects_missing_base_harness_input(tmp_path: Path) -> None:
    repo, base, _head = _create_repository(tmp_path)
    (repo / ".evoguard.json").write_text(
        json.dumps({"harness_inputs": ["ci/missing.py"]}) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    base = _commit(repo, "policy names missing harness input")
    (repo / "app.py").write_text("VALUE = 3\n", encoding="utf-8")
    head = _commit(repo, "candidate")

    with pytest.raises(FinalizerDerivationError, match="exact regular files"):
        _derived(repo, base, head)


def test_raw_git_derivation_rejects_non_regular_base_harness_input(
    tmp_path: Path,
) -> None:
    repo, _base, _head = _create_repository(tmp_path)
    link_target = repo / "link-target.txt"
    link_target.write_text("target\n", encoding="utf-8")
    blob = _git(repo, "hash-object", "-w", "link-target.txt")
    _git(
        repo,
        "update-index",
        "--add",
        "--cacheinfo",
        f"120000,{blob},ci-judge",
    )
    (repo / ".evoguard.json").write_text(
        json.dumps({"harness_inputs": ["ci-judge"]}) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    _git(repo, "add", ".evoguard.json", "link-target.txt")
    _git(
        repo,
        "-c",
        "user.name=EvoGuard Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-m",
        "policy names symlink harness input",
    )
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "app.py").write_text("VALUE = 3\n", encoding="utf-8")
    head = _commit(repo, "candidate")

    with pytest.raises(FinalizerDerivationError, match="exact regular files"):
        _derived(repo, base, head)


def test_raw_git_derivation_rejects_changed_harness_input(tmp_path: Path) -> None:
    repo, base, _head = _create_harness_repository(tmp_path)
    (repo / "ci" / "run-suite.py").write_text(
        "print('candidate judge')\n",
        encoding="utf-8",
    )
    head = _commit(repo, "candidate changes judge")

    with pytest.raises(FinalizerDerivationError, match="changed a policy-bound"):
        _derived(repo, base, head)


def test_raw_git_pack_identity_matches_checkout_bytes_for_lf_fixture(tmp_path: Path) -> None:
    repo, base, head = _create_repository(tmp_path, with_pack=True)
    bindings = _derived(repo, base, head)
    checkout = tmp_path / "base"
    _checkout(repo, checkout, base)

    assert bindings.verifier_pack_sha256 == pack_digest(str(checkout / "security" / "pack"))
    assert bindings.payload["verifier_pack_manifest"] == {"id": "guard-test", "version": "1"}


def test_raw_git_derivation_rejects_changed_binary_path(tmp_path: Path) -> None:
    repo, base, _head = _create_repository(tmp_path)
    (repo / "blob.bin").write_bytes(b"\xffbinary")
    head = _commit(repo, "binary candidate")

    with pytest.raises(FinalizerDerivationError, match="not valid UTF-8"):
        _derived(repo, base, head)


def test_raw_git_derivation_rejects_mode_only_change(tmp_path: Path) -> None:
    repo, base, head = _create_repository(tmp_path)
    _git(repo, "update-index", "--chmod=+x", "app.py")
    # Do not call _commit here: it intentionally refreshes the index with
    # `git add --all`, which resets this index-only mode delta on Linux because
    # the on-disk fixture remains non-executable. Commit the staged Git mode
    # explicitly so the test is portable across Windows and POSIX.
    _git(
        repo,
        "-c",
        "user.name=EvoGuard Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-m",
        "mode candidate",
    )
    mode_head = _git(repo, "rev-parse", "HEAD")

    with pytest.raises(FinalizerDerivationError, match="path mode changed"):
        _derived(repo, base, mode_head)

    assert head != mode_head


def test_checkout_eol_transformation_cannot_silently_match_raw_git(tmp_path: Path) -> None:
    repo, base, head = _create_repository(tmp_path)
    (repo / ".gitattributes").write_text("*.py text eol=crlf\n", encoding="utf-8", newline="\n")
    base = _commit(repo, "eol policy")
    (repo / "app.py").write_text("VALUE = 3\n", encoding="utf-8", newline="\n")
    head = _commit(repo, "eol candidate")
    bindings = _derived(repo, base, head)
    record = _record_for_pair(tmp_path, repo, base, head)

    with pytest.raises(FinalizerDerivationError, match="candidate digest"):
        context_from_verified_bindings(bindings, record)


def test_raw_git_binding_file_is_canonical_and_forged_record_fails(tmp_path: Path) -> None:
    repo, base, head = _create_repository(tmp_path)
    bindings = _derived(repo, base, head)
    binding_path = tmp_path / "bindings.json"
    write_finalizer_bindings(bindings, bindings_path=str(binding_path))
    assert read_finalizer_bindings(str(binding_path)).payload == bindings.payload

    record = _record_for_pair(tmp_path, repo, base, head)
    record["attestation"]["candidate_sha256"] = "f" * 64
    with pytest.raises(FinalizerDerivationError, match="candidate digest"):
        context_from_verified_bindings(bindings, record)


def test_raw_git_derivation_binds_deleted_files_and_implicit_directories(tmp_path: Path) -> None:
    repo, _base, _head = _create_repository(tmp_path)
    removed = repo / "obsolete"
    removed.mkdir()
    (removed / "old.txt").write_text("remove me\n", encoding="utf-8")
    base = _commit(repo, "add obsolete tracked path")
    shutil.rmtree(removed)
    head = _commit(repo, "delete obsolete tracked path")

    bindings = _derived(repo, base, head)
    record = _record_for_pair(tmp_path, repo, base, head)
    assert list(bindings.deleted_paths) == ["obsolete", "obsolete/old.txt"]
    assert record["attestation"]["deleted_paths"] == list(bindings.deleted_paths)
    context_from_verified_bindings(bindings, record)

    record["attestation"]["deleted_paths"] = []
    with pytest.raises(FinalizerDerivationError, match="deleted paths"):
        context_from_verified_bindings(bindings, record)


def test_sealing_rejects_forged_raw_binding_before_bundle_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A raw-Git mismatch must stop before the code path that opens the signing key."""

    repo, base, head = _create_repository(tmp_path)
    bindings = _derived(repo, base, head)
    record = _record_for_pair(tmp_path, repo, base, head)
    source, context = context_from_verified_bindings(bindings, record)
    verdict_path = tmp_path / "verdict.json"
    verdict_path.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
    handoff_path = tmp_path / "handoff.json"
    trusted_finalizer.create_finalizer_handoff(
        str(verdict_path),
        str(handoff_path),
        source=source,
        context=context,
    )
    called = False

    def must_not_reach_bundle_writer(*_args: object, **_kwargs: object) -> object:
        nonlocal called
        called = True
        raise AssertionError("the finalizer must not reach bundle signing")

    monkeypatch.setattr(trusted_finalizer, "finalize_evidence_bundle", must_not_reach_bundle_writer)
    forged = dict(bindings.payload, candidate_sha256="f" * 64)
    with pytest.raises(trusted_finalizer.FinalizerHandoffError, match="raw-Git derivation"):
        trusted_finalizer.seal_finalizer_bundle(
            str(handoff_path),
            str(verdict_path),
            str(tmp_path / "never.evb"),
            expected_source=source,
            expected_context=context,
            expected_derivation=forged,
            private_key_path=str(tmp_path / "signing-key-must-not-be-read.pem"),
        )
    assert called is False


def test_derivation_cli_writes_context_only_after_record_match(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, base, head = _create_repository(tmp_path)
    record = _record_for_pair(tmp_path, repo, base, head)
    record_path = tmp_path / "verdict.json"
    record_path.write_text(json.dumps(record) + "\n", encoding="utf-8", newline="\n")
    binding_path = tmp_path / "bindings.json"
    source_path = tmp_path / "source.json"
    context_path = tmp_path / "context.json"
    base_tree = _git(repo, "rev-parse", f"{base}^{{tree}}")
    head_tree = _git(repo, "rev-parse", f"{head}^{{tree}}")

    assert (
        cli_main(
            [
                "derive-finalizer-bindings",
                "--base-repo",
                str(repo),
                "--head-repo",
                str(repo),
                "--base-sha",
                base,
                "--head-sha",
                head,
                "--base-tree-sha",
                base_tree,
                "--head-tree-sha",
                head_tree,
                "--repository",
                "owner/project",
                "--repository-id",
                "123",
                "--pr-number",
                "17",
                "--run-id",
                "7001",
                "--run-attempt",
                "1",
                "--guard-artifact-sha",
                "a" * 64,
                "--out",
                str(binding_path),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert (
        cli_main(
            [
                "verify-finalizer-bindings",
                str(record_path),
                "--bindings",
                str(binding_path),
                "--source-out",
                str(source_path),
                "--context-out",
                str(context_path),
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "VERIFIED"
    assert json.loads(context_path.read_text(encoding="utf-8"))["head_sha"] == head
