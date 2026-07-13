# -----------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available - see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Raw black-box execution-state facts, independent of GuardResult mapping."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import evoom_guard.blackbox as blackbox_module
from evoom_guard.blackbox import BlackboxResult, run_blackbox
from evoom_guard.candidate_runner import IsolationUnavailable


class _Evidence:
    def as_dict(self) -> dict[str, object]:
        return {
            "requested": "subprocess",
            "delivered": "subprocess",
            "note": "test boundary",
        }


@pytest.fixture
def repo_and_pack(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    pack = tmp_path / "pack"
    repo.mkdir()
    pack.mkdir()
    (repo / "app.py").write_text("value = 1\n", encoding="utf-8")
    (pack / "test_protocol.py").write_text(
        "def test_protocol():\n    assert True\n", encoding="utf-8"
    )
    return repo, pack


def _candidate() -> str:
    return "<<<FILE: app.py>>>\nvalue = 2\n<<<END FILE>>>\n"


def _prepare(*_args: object, **_kwargs: object) -> tuple[str, dict[str, str], _Evidence]:
    return "launcher", {"EVOGUARD_TARGET": "candidate"}, _Evidence()


def _assert_not_started(result: BlackboxResult, *, pack_present: bool) -> None:
    assert result.ran is False
    assert result.started is False
    assert result.completed is False
    assert result.execution_state == "not_started"
    assert result.execution_phase == "preflight"
    assert result.pack_present is pack_present


def _assert_completed(result: BlackboxResult) -> None:
    assert result.started is True
    assert result.completed is True
    assert result.execution_state == "completed"
    assert result.execution_phase == "blackbox_pack"
    assert result.pack_present is True


def test_namedtuple_legacy_construction_keeps_execution_defaults() -> None:
    result = BlackboxResult(False, 0, 0, "", False, None)

    assert result.execution_state == "not_started"
    assert result.execution_phase == "preflight"
    assert result.pack_present is None


def test_missing_pack_is_a_not_started_preflight(tmp_path: Path) -> None:
    result = run_blackbox(str(tmp_path), "", str(tmp_path / "missing"))

    _assert_not_started(result, pack_present=False)
    assert result.error and "not found" in result.error


def test_invalid_pack_is_a_not_started_preflight(
    repo_and_pack: tuple[Path, Path],
) -> None:
    repo, pack = repo_and_pack
    (pack / "pack.json").write_text("{broken", encoding="utf-8")

    result = run_blackbox(str(repo), _candidate(), str(pack))

    _assert_not_started(result, pack_present=True)
    assert result.error == "verifier pack invalid"


def test_pack_identity_mismatch_is_a_not_started_preflight(
    repo_and_pack: tuple[Path, Path],
) -> None:
    repo, pack = repo_and_pack

    result = run_blackbox(
        str(repo),
        _candidate(),
        str(pack),
        expect_verifier_pack_sha256="0" * 64,
    )

    _assert_not_started(result, pack_present=True)
    assert result.error == "verifier pack identity mismatch"


def test_patch_apply_failure_is_a_not_started_preflight(
    repo_and_pack: tuple[Path, Path],
) -> None:
    repo, pack = repo_and_pack
    missing_patch = (
        "<<<PATCH: missing.py>>>\n<<<SEARCH>>>\nold\n"
        "<<<REPLACE>>>\nnew\n<<<END PATCH>>>\n"
    )

    result = run_blackbox(str(repo), missing_patch, str(pack))

    _assert_not_started(result, pack_present=True)
    assert result.error == "patch did not apply"


def test_isolation_unavailable_is_a_not_started_preflight(
    repo_and_pack: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack = repo_and_pack

    def unavailable(*_args: object, **_kwargs: object) -> None:
        raise IsolationUnavailable("boundary unavailable")

    monkeypatch.setattr(blackbox_module.CandidateRunner, "prepare", unavailable)
    result = run_blackbox(str(repo), _candidate(), str(pack))

    _assert_not_started(result, pack_present=True)
    assert result.error == "isolation unavailable"


def test_timeout_is_started_but_incomplete(
    repo_and_pack: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack = repo_and_pack
    monkeypatch.setattr(blackbox_module.CandidateRunner, "prepare", _prepare)

    def timeout(*_args: object, **_kwargs: object) -> None:
        raise subprocess.TimeoutExpired(cmd=["pytest"], timeout=1)

    monkeypatch.setattr(blackbox_module, "_run_judge_process", timeout)
    result = run_blackbox(str(repo), _candidate(), str(pack), timeout=1)

    assert result.ran is False
    assert result.started is True
    assert result.completed is False
    assert result.execution_state == "started_incomplete"
    assert result.execution_phase == "blackbox_pack"
    assert result.pack_present is True
    assert result.error == "timeout"


def test_surviving_judge_group_is_an_explicit_incomplete_error(
    repo_and_pack: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack = repo_and_pack
    monkeypatch.setattr(blackbox_module.CandidateRunner, "prepare", _prepare)

    def cleanup_failed(*_args: object, **_kwargs: object) -> None:
        raise blackbox_module.JudgeProcessCleanupError(
            "judge process group survived SIGKILL"
        )

    monkeypatch.setattr(blackbox_module, "_run_judge_process", cleanup_failed)
    result = run_blackbox(str(repo), _candidate(), str(pack), timeout=1)

    assert result.passed is False
    assert result.ran is False
    assert result.error == "judge process cleanup failed"
    assert result.diagnostics == "judge process group survived SIGKILL"
    assert result.started is True
    assert result.completed is False
    assert result.execution_state == "started_incomplete"


@pytest.mark.parametrize(
    ("returncode", "xml", "expected_error", "expected_ran"),
    [
        (
            5,
            '<testsuites><testsuite tests="0" failures="0" errors="0"/></testsuites>',
            "black-box pack produced no judge-owned test results",
            False,
        ),
        (
            0,
            '<testsuites><testsuite tests="1" failures="1" errors="0">'
            '<testcase name="bad"><failure/></testcase></testsuite></testsuites>',
            "black-box JUnit/exit mismatch",
            False,
        ),
        (
            2,
            '<testsuites><testsuite tests="1" failures="0" errors="0">'
            '<testcase name="collected"/></testsuite></testsuites>',
            "black-box pack did not run cleanly (pytest exit 2)",
            False,
        ),
        (
            0,
            '<testsuites><testsuite tests="1" failures="0" errors="0">'
            '<testcase name="ok"/></testsuite></testsuites>',
            None,
            True,
        ),
    ],
)
def test_returned_pytest_is_completed_even_without_a_gradeable_verdict(
    repo_and_pack: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    xml: str,
    expected_error: str | None,
    expected_ran: bool,
) -> None:
    repo, pack = repo_and_pack
    monkeypatch.setattr(blackbox_module.CandidateRunner, "prepare", _prepare)

    def completed(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        xml_arg = next(part for part in command if part.startswith("--junitxml="))
        Path(xml_arg.split("=", 1)[1]).write_text(xml, encoding="utf-8")
        return subprocess.CompletedProcess(command, returncode, "", "")

    monkeypatch.setattr(blackbox_module, "_run_judge_process", completed)
    result = run_blackbox(str(repo), _candidate(), str(pack), timeout=1)

    _assert_completed(result)
    assert result.ran is expected_ran
    assert result.error == expected_error
