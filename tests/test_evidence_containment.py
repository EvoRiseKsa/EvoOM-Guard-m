"""Containment regressions for opt-in changed-line coverage evidence."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

import evoom_guard.evidence as evidence
import evoom_guard.record_verifier as record_verifier
from evoom_guard.verifiers.repo_verifier import _SubprocessOutputLimitExceeded


def _candidate() -> str:
    return "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n"


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    return repo


def _fixed_workspace_allocator(root: Path):
    def allocate(*, prefix: str) -> str:
        assert prefix == "evo_guard_cov_"
        root.mkdir()
        return str(root)

    return allocate


def test_coverage_cleanup_diagnostic_is_bounded_and_schema_valid() -> None:
    note = evidence._coverage_cleanup_failure_note(
        OSError("cleanup denied: " + "x" * 10_000)
    )
    coverage = {
        "measured": False,
        "note": note,
        "unmeasured_files": [],
        "caveat": evidence.EXECUTED_IS_NOT_ASSERTED,
    }

    assert len(note) == 2000
    assert note.startswith("the coverage workspace cleanup could not be proven")
    assert note.endswith("...")
    assert record_verifier._diff_coverage_type_errors(coverage) == []


def test_coverage_report_reader_rejects_oversized_file_before_decode(
    tmp_path: Path, monkeypatch
) -> None:
    report = tmp_path / "judge-coverage.json"
    report.write_bytes(b"x" * 4096)
    monkeypatch.setattr(evidence, "_MAX_COVERAGE_REPORT_BYTES", 1024)

    assert evidence._read_coverage_files(str(report)) is None


def test_diff_coverage_output_limit_degrades_to_explicit_unmeasured_evidence(
    tmp_path: Path, monkeypatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    # ``collect_diff_coverage`` only needs the import to exist before it reaches
    # the mocked judge command; avoid coupling this regression to the extras set.
    monkeypatch.setitem(sys.modules, "coverage", object())

    def overflow(*_args: object, **_kwargs: object) -> None:
        raise _SubprocessOutputLimitExceeded(128)

    monkeypatch.setattr(evidence, "_run_bounded_subprocess", overflow)
    result = evidence.collect_diff_coverage(str(repo), _candidate())

    assert result["measured"] is False
    assert "output exceeded the judge capture limit" in result["note"]


def test_coverage_workspace_cleanup_failure_is_explicitly_unmeasured(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo(tmp_path)
    workspace = tmp_path / "coverage-workspace"
    cleanup_error = PermissionError("coverage workspace busy")
    attempts: list[str] = []

    def fail_remove(path: str) -> None:
        attempts.append(path)
        raise cleanup_error

    monkeypatch.setattr(
        evidence.tempfile,
        "mkdtemp",
        _fixed_workspace_allocator(workspace),
    )
    monkeypatch.setattr(evidence.shutil, "rmtree", fail_remove)

    result = evidence.collect_diff_coverage(
        str(repo),
        _candidate(),
        test_command=["make", "test"],
    )

    assert result["measured"] is False
    assert "coverage workspace cleanup could not be proven" in result["note"]
    assert "PermissionError: coverage workspace busy" in result["note"]
    assert len(attempts) == 1
    assert isinstance(attempts[0], str)
    assert type(attempts[0]) is not str
    assert workspace.is_dir()


def test_successful_coverage_measurement_is_not_returned_when_cleanup_is_unproven(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo(tmp_path)
    workspace = tmp_path / "coverage-workspace"

    def complete_phase(
        command: list[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        if "json" in command:
            output_path = command[command.index("-o") + 1]
            Path(output_path).write_text('{"files": {}}\n', encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(
        evidence.tempfile,
        "mkdtemp",
        _fixed_workspace_allocator(workspace),
    )
    monkeypatch.setattr(evidence, "_run_bounded_subprocess", complete_phase)
    monkeypatch.setattr(
        evidence.shutil,
        "rmtree",
        lambda _path: (_ for _ in ()).throw(OSError("cleanup denied")),
    )

    result = evidence.collect_diff_coverage(str(repo), _candidate())

    assert result["measured"] is False
    assert "coverage workspace cleanup could not be proven" in result["note"]
    assert "OSError: cleanup denied" in result["note"]
    assert workspace.is_dir()


def test_coverage_cleanup_preserves_exact_active_primary_and_notes_secondary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo(tmp_path)
    workspace = tmp_path / "coverage-workspace"
    primary = KeyboardInterrupt("operator interrupted coverage copy")
    cleanup_error = SystemExit("coverage cleanup exited")

    monkeypatch.setattr(
        evidence.tempfile,
        "mkdtemp",
        _fixed_workspace_allocator(workspace),
    )
    monkeypatch.setattr(
        evidence,
        "copy_repo_tree",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(primary),
    )
    monkeypatch.setattr(
        evidence.shutil,
        "rmtree",
        lambda _path: (_ for _ in ()).throw(cleanup_error),
    )

    with pytest.raises(KeyboardInterrupt) as caught:
        evidence.collect_diff_coverage(str(repo), _candidate())

    assert caught.value is primary
    assert any(
        "SystemExit: coverage cleanup exited" in note
        for note in getattr(primary, "__notes__", [])
    )
    assert workspace.is_dir()


def test_coverage_cleanup_control_flow_baseexception_remains_visible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo(tmp_path)
    workspace = tmp_path / "coverage-workspace"
    cleanup_error = SystemExit("coverage cleanup exited")

    monkeypatch.setattr(
        evidence.tempfile,
        "mkdtemp",
        _fixed_workspace_allocator(workspace),
    )
    monkeypatch.setattr(
        evidence.shutil,
        "rmtree",
        lambda _path: (_ for _ in ()).throw(cleanup_error),
    )

    with pytest.raises(SystemExit) as caught:
        evidence.collect_diff_coverage(
            str(repo),
            _candidate(),
            test_command=["make", "test"],
        )

    assert caught.value is cleanup_error
    assert workspace.is_dir()


def test_coverage_cleanup_accepts_filenotfound_only_after_fresh_root_absence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo(tmp_path)
    workspace = tmp_path / "coverage-workspace"
    real_rmtree = shutil.rmtree

    def remove_then_report_race(path: str) -> None:
        real_rmtree(path)
        raise FileNotFoundError("raced child disappeared")

    monkeypatch.setattr(
        evidence.tempfile,
        "mkdtemp",
        _fixed_workspace_allocator(workspace),
    )
    monkeypatch.setattr(evidence.shutil, "rmtree", remove_then_report_race)

    result = evidence.collect_diff_coverage(
        str(repo),
        _candidate(),
        test_command=["make", "test"],
    )

    assert result["measured"] is False
    assert "supports pytest commands only" in result["note"]
    assert not workspace.exists()


def test_coverage_cleanup_rejects_filenotfound_while_root_remains(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo(tmp_path)
    workspace = tmp_path / "coverage-workspace"

    monkeypatch.setattr(
        evidence.tempfile,
        "mkdtemp",
        _fixed_workspace_allocator(workspace),
    )
    monkeypatch.setattr(
        evidence.shutil,
        "rmtree",
        lambda _path: (_ for _ in ()).throw(
            FileNotFoundError("raced child disappeared")
        ),
    )

    result = evidence.collect_diff_coverage(
        str(repo),
        _candidate(),
        test_command=["make", "test"],
    )

    assert result["measured"] is False
    assert "coverage workspace cleanup could not be proven" in result["note"]
    assert "FileNotFoundError: raced child disappeared" in result["note"]
    assert workspace.is_dir()


def test_coverage_cleanup_rejects_remover_success_without_absence_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo(tmp_path)
    workspace = tmp_path / "coverage-workspace"

    monkeypatch.setattr(
        evidence.tempfile,
        "mkdtemp",
        _fixed_workspace_allocator(workspace),
    )
    monkeypatch.setattr(evidence.shutil, "rmtree", lambda _path: None)

    result = evidence.collect_diff_coverage(
        str(repo),
        _candidate(),
        test_command=["make", "test"],
    )

    assert result["measured"] is False
    assert "coverage workspace cleanup could not be proven" in result["note"]
    assert "OwnedWorkspaceRemovalUnproven" in result["note"]
    assert workspace.is_dir()


def test_coverage_cleanup_rejects_replaced_root_without_deleting_either_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo(tmp_path)
    workspace = tmp_path / "coverage-workspace"
    displaced = tmp_path / "displaced-workspace"

    def replace_workspace(_command: list[str], _data_file: str) -> None:
        (workspace / "original.txt").write_text("original\n", encoding="utf-8")
        workspace.rename(displaced)
        workspace.mkdir()
        (workspace / "replacement.txt").write_text(
            "replacement\n",
            encoding="utf-8",
        )
        return None

    monkeypatch.setattr(
        evidence.tempfile,
        "mkdtemp",
        _fixed_workspace_allocator(workspace),
    )
    monkeypatch.setattr(evidence, "_coverage_wrap", replace_workspace)

    result = evidence.collect_diff_coverage(str(repo), _candidate())

    assert result["measured"] is False
    assert "coverage workspace cleanup could not be proven" in result["note"]
    assert "root identity changed" in result["note"]
    assert (displaced / "original.txt").read_text(encoding="utf-8") == "original\n"
    assert (workspace / "replacement.txt").read_text(encoding="utf-8") == (
        "replacement\n"
    )


@pytest.mark.skipif(os.name != "nt", reason="requires Windows READONLY semantics")
def test_coverage_cleanup_removes_real_windows_readonly_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo(tmp_path)
    workspace = tmp_path / "coverage-workspace"

    def leave_readonly_artifact(_command: list[str], _data_file: str) -> None:
        artifact = workspace / "readonly.txt"
        artifact.write_text("candidate artifact\n", encoding="utf-8")
        os.chmod(artifact, stat.S_IREAD)
        return None

    monkeypatch.setattr(
        evidence.tempfile,
        "mkdtemp",
        _fixed_workspace_allocator(workspace),
    )
    monkeypatch.setattr(evidence, "_coverage_wrap", leave_readonly_artifact)

    result = evidence.collect_diff_coverage(str(repo), _candidate())

    assert result["measured"] is False
    assert "supports pytest commands only" in result["note"]
    assert not workspace.exists()
