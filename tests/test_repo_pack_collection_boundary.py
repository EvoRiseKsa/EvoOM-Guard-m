"""Verifier-pack pytest collection must stay inside the accepted snapshot."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import evoom_guard.verifiers.repo_verifier as repo_verifier
from evoom_guard.verifiers.repo_verifier import RepoVerifier


def _candidate() -> str:
    return "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n"


def test_pack_pytest_confcutdir_is_the_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Do not let pytest traverse a shared volatile temp ancestor on Windows.

    A pack snapshot and the candidate copy are sibling trees under the system
    temporary directory.  Without an explicit ``--confcutdir``, pytest walks
    their common ancestors during collection.  Its Windows same-file fallback
    then calls ``lstat`` on unrelated ``evo_repo_*`` siblings which concurrent
    verifiers are allowed to delete, producing a nondeterministic WinError 2.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "test_contract.py").write_text(
        "from app import VALUE\n\n\ndef test_value():\n    assert VALUE == 2\n",
        encoding="utf-8",
    )

    invocations: list[tuple[list[str], str | None]] = []

    def completed(command: list[str], *, cwd: str | None, **_kwargs: object):
        invocations.append((list(command), cwd))
        report_arg = next(arg for arg in command if arg.startswith("--junitxml="))
        Path(report_arg.split("=", 1)[1]).write_text(
            '<testsuite><testcase name="pass"/></testsuite>',
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(repo_verifier, "_run_bounded_subprocess", completed)

    result = RepoVerifier(mem_limit_mb=0).verify(
        _candidate(),
        {"repo_path": str(repo), "verifier_pack": str(pack)},
    )

    assert result.passed is True
    assert len(invocations) == 2
    pack_command, candidate_cwd = invocations[1]
    boundary_arg = next(arg for arg in pack_command if arg.startswith("--confcutdir="))
    snapshot = boundary_arg.split("=", 1)[1]
    assert snapshot in pack_command
    assert Path(snapshot).name == "pack"
    assert Path(snapshot).parent.name.startswith("evo_pack_snapshot_")
    assert candidate_cwd is not None
    assert Path(candidate_cwd).name == "repo"
    assert Path(snapshot).parent != Path(candidate_cwd).parent
