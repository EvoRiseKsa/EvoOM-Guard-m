"""Unit, lookup-timing, and ordering contracts for the repo-candidate owner."""

from __future__ import annotations

import inspect
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from evoom_guard.contracts import VerdictResult
from evoom_guard.verifiers import repo_candidate, repo_verifier


def _admission_services(
    *,
    deleted_paths: tuple[object, ...] = (),
    file_blocks_override: object = None,
    target_files: tuple[object, ...] = (),
    parse_files=lambda _text: {"app.py": "VALUE = 2\n"},
    parse_patches=lambda _text: [],
    parse_lenient=lambda _text, _default=None: ({}, []),
    reject=lambda *_args, **_kwargs: None,
) -> repo_candidate.RepoCandidateAdmissionServices:
    return repo_candidate.RepoCandidateAdmissionServices(
        is_directory=lambda: lambda _path: True,
        deleted_paths=lambda: deleted_paths,
        file_blocks_override=lambda: file_blocks_override,
        target_files=lambda: target_files,
        extra_protected=lambda: (),
        allow=lambda: (),
        allow_new_tests=lambda: False,
        strict_harness=lambda: False,
        parse_file_blocks=lambda: parse_files,
        parse_patch_blocks=lambda: parse_patches,
        parse_blocks_lenient=lambda: parse_lenient,
        discover_local_action_dirs=lambda: lambda _path: (),
        is_safe_relpath=lambda: lambda _path: True,
        join_path=lambda: lambda root, path: f"{root}/{path}",
        path_exists=lambda: lambda _path: True,
        reject_paths=lambda: reject,
    )


def _admitted_candidate() -> repo_candidate.AdmittedRepoCandidate:
    outcome = repo_candidate.admit_repo_candidate(
        repo_candidate.RepoCandidateAdmissionRequest(
            hypothesis="candidate",
            repo_path="repo",
        ),
        services=_admission_services(),
    )
    assert outcome.candidate is not None
    return outcome.candidate


def test_repo_candidate_owner_exposes_immutable_xor_contracts() -> None:
    request = repo_candidate.RepoCandidateAdmissionRequest(
        hypothesis="candidate",
        repo_path="repo",
    )
    outcome = repo_candidate.admit_repo_candidate(
        request,
        services=_admission_services(),
    )
    assert outcome.candidate is not None
    assert outcome.terminal_result is None
    assert repo_candidate.admit_repo_candidate.__module__ == (
        "evoom_guard.verifiers.repo_candidate"
    )

    with pytest.raises(FrozenInstanceError):
        request.repo_path = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        outcome.candidate.repo_path = "changed"  # type: ignore[misc]
    with pytest.raises(TypeError):
        outcome.candidate.file_blocks["late.py"] = "mutation"  # type: ignore[index]

    terminal = VerdictResult(False, 0.0, "terminal")
    for outcome_type in (
        repo_candidate.RepoCandidateAdmissionOutcome,
        repo_candidate.RepoCandidateMaterializationOutcome,
        repo_candidate.RepoCandidateDeletionOutcome,
    ):
        with pytest.raises(ValueError, match="exactly one"):
            outcome_type()
        with pytest.raises(ValueError, match="exactly one"):
            outcome_type(
                candidate=outcome.candidate,
                terminal_result=terminal,
            )


def test_admission_preserves_sorted_changes_and_deletion_input_order() -> None:
    outcome = repo_candidate.admit_repo_candidate(
        repo_candidate.RepoCandidateAdmissionRequest(
            hypothesis="candidate",
            repo_path="repo",
        ),
        services=_admission_services(
            deleted_paths=("second.py", "first.py", "second.py"),
            parse_files=lambda _text: {
                "z.py": "Z = 1\n",
                "a.py": "A = 1\n",
            },
            parse_patches=lambda _text: [
                repo_verifier.PatchBlock("a.py", "A", "B")
            ],
        ),
    )

    assert outcome.candidate is not None
    assert outcome.candidate.files_changed == ("a.py", "z.py")
    assert outcome.candidate.deleted_paths == (
        "second.py",
        "first.py",
        "second.py",
    )


def test_admission_forwards_only_safe_absent_paths_as_new() -> None:
    observed: list[frozenset[str]] = []

    def capture_policy(_paths, _extra, *, new_paths=frozenset(), **_kwargs):
        observed.append(new_paths)
        return None

    services = _admission_services(
        parse_files=lambda _text: {
            "existing.py": "EXISTING = 2\n",
            "new.py": "NEW = True\n",
            "../unsafe.py": "UNSAFE = True\n",
        },
        reject=capture_policy,
    )
    services = repo_candidate.RepoCandidateAdmissionServices(
        **{
            field: getattr(services, field)
            for field in services.__dataclass_fields__
            if field != "path_exists"
        },
        path_exists=lambda: lambda path: path.endswith("existing.py"),
    )

    outcome = repo_candidate.admit_repo_candidate(
        repo_candidate.RepoCandidateAdmissionRequest(
            hypothesis="candidate",
            repo_path="repo",
        ),
        services=repo_candidate.RepoCandidateAdmissionServices(
            **{
                field: getattr(services, field)
                for field in services.__dataclass_fields__
                if field != "is_safe_relpath"
            },
            is_safe_relpath=lambda: lambda path: not path.startswith("../"),
        ),
    )

    assert outcome.candidate is not None
    assert observed == [frozenset({"new.py"})]


def test_deletion_owner_retains_belt_and_braces_safe_path_gate() -> None:
    candidate = repo_candidate.AdmittedRepoCandidate(
        repo_path="repo",
        file_blocks={},
        patch_blocks=(),
        deleted_paths=("../outside.py",),
        files_changed=(),
        strict_harness=False,
    )

    outcome = repo_candidate.apply_repo_candidate_deletions(
        repo_candidate.RepoCandidateDeletionRequest(
            candidate_copy="copy",
            candidate=candidate,
        ),
        services=repo_candidate.RepoCandidateDeletionServices(
            is_safe_relpath=lambda: lambda _path: False,
            delete_path=lambda: lambda *_args: pytest.fail(
                "unsafe deletion reached contained filesystem mutation"
            ),
            deletion_errors=lambda: (OSError,),
        ),
    )

    assert outcome.candidate is candidate
    assert outcome.terminal_result is None


def test_invalid_repo_fails_before_candidate_or_workspace_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected(*_args: object, **_kwargs: object):
        pytest.fail("invalid repository reached a later candidate operation")

    monkeypatch.setattr(repo_verifier, "parse_file_blocks", unexpected)
    monkeypatch.setattr(repo_verifier.tempfile, "mkdtemp", unexpected)

    with pytest.raises(ValueError, match="is not a directory"):
        repo_verifier.RepoVerifier().verify(
            "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
            {"repo_path": "definitely-not-a-directory"},
        )


def test_repo_verifier_resolves_each_parser_at_its_operation_site(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    events: list[str] = []

    def late_patch(_text: str) -> list[repo_verifier.PatchBlock]:
        events.append("late-patch")
        return [repo_verifier.PatchBlock("app.py", "1", "2")]

    def first_file(_text: str) -> dict[str, str]:
        events.append("file")
        monkeypatch.setattr(repo_verifier, "parse_patch_blocks", late_patch)
        return {}

    def stale_patch(_text: str):
        pytest.fail("the patch parser was snapshotted before the FILE parse")

    monkeypatch.setattr(repo_verifier, "parse_file_blocks", first_file)
    monkeypatch.setattr(repo_verifier, "parse_patch_blocks", stale_patch)
    monkeypatch.setattr(
        repo_verifier,
        "apply_blocks_to_copy",
        lambda *_args: "controlled stop",
    )

    result = repo_verifier.RepoVerifier(mem_limit_mb=0).verify(
        "candidate",
        {"repo_path": str(source)},
    )

    assert events == ["file", "late-patch"]
    assert result.score == 0.08
    assert result.diagnostics == "controlled stop"


def test_copy_operation_can_replace_the_later_materialization_seam(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    events: list[str] = []
    original_copy = repo_verifier.copy_repo_tree

    def late_apply(
        _root: str,
        _files: dict[str, str],
        _patches: list[repo_verifier.PatchBlock],
    ) -> str:
        events.append("late-apply")
        return "controlled stop"

    def recording_copy(src: str, dst: str) -> None:
        events.append("copy")
        monkeypatch.setattr(repo_verifier, "apply_blocks_to_copy", late_apply)
        original_copy(src, dst)

    def stale_apply(*_args: object):
        pytest.fail("materialization was snapshotted before repository copy")

    monkeypatch.setattr(repo_verifier, "copy_repo_tree", recording_copy)
    monkeypatch.setattr(repo_verifier, "apply_blocks_to_copy", stale_apply)

    result = repo_verifier.RepoVerifier(mem_limit_mb=0).verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        {"repo_path": str(source)},
    )

    assert events == ["copy", "late-apply"]
    assert result.diagnostics == "controlled stop"


def test_each_deletion_resolves_the_current_facade_seam(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (source / "first.py").write_text("FIRST = True\n", encoding="utf-8")
    (source / "second.py").write_text("SECOND = True\n", encoding="utf-8")
    events: list[str] = []

    def late_delete(_root: str, path: str) -> bool:
        events.append(f"late:{path}")
        return True

    def first_delete(_root: str, path: str) -> bool:
        events.append(f"first:{path}")
        monkeypatch.setattr(
            repo_verifier,
            "delete_path_within_root",
            late_delete,
        )
        return True

    monkeypatch.setattr(
        repo_verifier,
        "delete_path_within_root",
        first_delete,
    )

    result = repo_verifier.RepoVerifier(
        isolation="docker",
        mem_limit_mb=0,
    ).verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        {
            "repo_path": str(source),
            "deleted": ["first.py", "second.py"],
        },
    )

    assert events == ["first:first.py", "late:second.py"]
    assert result.artifact["outcome"] == "isolation_unavailable"


def test_changed_path_gate_can_replace_the_deletion_gate_seam(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    events: list[str] = []

    def deletion_gate(paths, _extra, **_kwargs):
        events.append("deletion:" + ",".join(paths))
        return VerdictResult(
            passed=False,
            score=0.05,
            diagnostics="late deletion rejection",
            artifact={"files_changed": []},
        )

    def changed_gate(paths, _extra, **_kwargs):
        events.append("changed:" + ",".join(paths))
        monkeypatch.setattr(
            repo_verifier,
            "reject_unsafe_or_protected",
            deletion_gate,
        )
        return None

    monkeypatch.setattr(
        repo_verifier,
        "reject_unsafe_or_protected",
        changed_gate,
    )

    result = repo_verifier.RepoVerifier(mem_limit_mb=0).verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        {"repo_path": str(source), "deleted": ["old.py"]},
    )

    assert events == ["changed:app.py", "deletion:old.py"]
    assert result.diagnostics == "late deletion rejection"


def test_pack_intake_failure_prevents_candidate_deletion(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (source / "old.py").write_text("OLD = True\n", encoding="utf-8")

    monkeypatch.setattr(
        repo_verifier,
        "delete_path_within_root",
        lambda *_args: pytest.fail("deletion ran before pack admission succeeded"),
    )

    result = repo_verifier.RepoVerifier(mem_limit_mb=0).verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        {
            "repo_path": str(source),
            "deleted": ["old.py"],
            "expect_verifier_pack_sha256": "a" * 64,
        },
    )

    assert result.artifact["outcome"] == "pack_identity_mismatch"


def test_copy_exception_identity_reaches_final_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    failure = RuntimeError("copy identity")
    observed: list[BaseException | None] = []
    original_cleanup = repo_verifier._cleanup_repo_workspaces

    def fail_copy(_src: str, _dst: str) -> None:
        raise failure

    def record_cleanup(workspaces, *, primary):
        observed.append(primary)
        return original_cleanup(workspaces, primary=primary)

    monkeypatch.setattr(repo_verifier, "copy_repo_tree", fail_copy)
    monkeypatch.setattr(
        repo_verifier,
        "_cleanup_repo_workspaces",
        record_cleanup,
    )

    with pytest.raises(RuntimeError) as raised:
        repo_verifier.RepoVerifier(mem_limit_mb=0).verify(
            "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
            {"repo_path": str(source)},
        )

    assert raised.value is failure
    assert observed == [failure]


def test_deletion_exception_class_is_resolved_after_delete_call(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (source / "old.py").write_text("OLD = True\n", encoding="utf-8")

    class LateUnsafePath(Exception):
        pass

    def fail_delete(_root: str, _path: str) -> bool:
        monkeypatch.setattr(
            repo_verifier,
            "UnsafeWorkspacePath",
            LateUnsafePath,
        )
        raise LateUnsafePath("late unsafe path")

    monkeypatch.setattr(
        repo_verifier,
        "delete_path_within_root",
        fail_delete,
    )

    result = repo_verifier.RepoVerifier(mem_limit_mb=0).verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        {"repo_path": str(source), "deleted": ["old.py"]},
    )

    assert result.score == 0.05
    assert result.diagnostics.endswith("late unsafe path")


def test_repo_verifier_keeps_allocation_pack_and_cleanup_outside_owner() -> None:
    owner_source = inspect.getsource(repo_candidate)
    verifier_source = inspect.getsource(repo_verifier.RepoVerifier._verify)

    assert "tempfile.mkdtemp" not in owner_source
    assert "intake_repo_pack" not in owner_source
    assert "_cleanup_repo_workspaces" not in owner_source
    assert verifier_source.index("admit_repo_candidate(") < verifier_source.index(
        'tempfile.mkdtemp(prefix="evo_repo_")'
    )
    assert verifier_source.index("materialize_repo_candidate(") < verifier_source.index(
        "intake_repo_pack("
    )
    assert verifier_source.index("intake_repo_pack(") < verifier_source.index(
        "apply_repo_candidate_deletions("
    )
    assert "finally:" in verifier_source
    assert "_cleanup_repo_workspaces(" in verifier_source
