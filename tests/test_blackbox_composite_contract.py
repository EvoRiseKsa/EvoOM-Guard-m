# -----------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available - see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""End-to-end contract for black-box invocation and composite evidence."""

from __future__ import annotations

from pathlib import Path

import pytest

import evoom_guard.blackbox as blackbox_module
from evoom_guard.blackbox import BlackboxResult
from evoom_guard.contracts import VerdictResult
from evoom_guard.guard import (
    ERROR,
    FAIL,
    PASS,
    REASON_ASSURANCE_REQUIREMENT_NOT_MET,
    REASON_CANDIDATE_NOT_EXERCISED,
    guard,
)
from evoom_guard.verifiers.repo_verifier import RepoVerifier


@pytest.fixture
def repo_and_pack(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    pack = tmp_path / "pack"
    (repo / "tests").mkdir(parents=True)
    pack.mkdir()
    (repo / "app.py").write_text("value = 1\n", encoding="utf-8")
    (repo / "tests" / "test_app.py").write_text(
        "def test_app():\n    assert True\n", encoding="utf-8"
    )
    (pack / "test_protocol.py").write_text(
        "def test_protocol():\n    assert True\n", encoding="utf-8"
    )
    return repo, pack


def _candidate() -> str:
    return "<<<FILE: app.py>>>\nvalue = 2\n<<<END FILE>>>\n"


def _blackbox_result(*, observed: bool = True) -> BlackboxResult:
    return BlackboxResult(
        passed=True,
        tests_passed=1,
        tests_total=1,
        diagnostics="",
        ran=True,
        error=None,
        pack_sha256="a" * 64,
        isolation={
            "requested": "subprocess",
            "delivered": "subprocess" if observed else "not_run",
            **({} if observed else {"prepared": "subprocess"}),
            "candidate_invocations": int(observed),
            "candidate_launcher_invocation_observed": observed,
        },
        started=True,
        completed=True,
        execution_state="completed",
        execution_phase="blackbox_pack",
        pack_present=True,
        candidate_invocations=int(observed),
        candidate_launcher_invocation_observed=observed,
    )


def _repo_result(*, passed: bool = True) -> VerdictResult:
    return VerdictResult(
        passed=passed,
        score=1.0 if passed else 0.5,
        diagnostics="repo failed" if not passed else "",
        artifact={
            "execution_state": "completed",
            "execution_phase": "repo_suite",
            "test_command_started": True,
            "test_command_completed": True,
            "delivered_isolation": "subprocess",
            "verdict_source": "junit+exit",
            "tests_passed": 2 if passed else 1,
            "tests_total": 2,
            "junit_sha256": "b" * 64,
            "isolation_evidence": {
                "requested": "subprocess",
                "delivered": "subprocess",
            },
            "repo_suite_isolation_evidence": {
                "requested": "subprocess",
                "delivered": "subprocess",
            },
        },
    )


def test_vacuous_blackbox_pack_is_refused_and_repo_phase_is_not_run(
    repo_and_pack: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, pack = repo_and_pack
    monkeypatch.setattr(
        blackbox_module, "run_blackbox", lambda *_args, **_kwargs: _blackbox_result(observed=False)
    )

    def must_not_run(*_args: object, **_kwargs: object) -> VerdictResult:
        raise AssertionError("repo suite must not rescue a vacuous black-box pack")

    monkeypatch.setattr(RepoVerifier, "verify", must_not_run)
    result = guard(str(repo), _candidate(), verifier_pack=str(pack), blackbox=True)

    assert result.verdict == ERROR
    assert result.reason_code == REASON_CANDIDATE_NOT_EXERCISED
    assert result.verdict_source is None
    assert result.isolation == "not_run"
    assert result.assurance is not None
    assert result.assurance["candidate_isolation"] == "not_run"
    assert result.assurance["repo_native_suite"] == "required_not_run_short_circuit"
    assert result.assurance["verifier_pack"]["secrecy"] == (
        "not_evaluated_no_candidate_execution"
    )
    assert result.attestation is not None
    assert result.attestation["delivered_isolation"] == "not_run"
    assert result.attestation["isolation_evidence"]["delivered"] == "not_run"
    assert result.attestation["isolation_evidence"]["prepared"] == "subprocess"
    assert result.attestation["candidate_invocations"] == 0
    assert result.attestation["candidate_launcher_invocation_observed"] is False


def test_completed_composite_sums_counts_and_uses_weakest_report_channel(
    repo_and_pack: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, pack = repo_and_pack
    monkeypatch.setattr(
        blackbox_module, "run_blackbox", lambda *_args, **_kwargs: _blackbox_result()
    )
    monkeypatch.setattr(
        RepoVerifier, "verify", lambda *_args, **_kwargs: _repo_result()
    )

    result = guard(str(repo), _candidate(), verifier_pack=str(pack), blackbox=True)

    assert result.verdict == PASS
    assert result.verdict_source == "composite:blackbox+repo"
    assert (result.tests_passed, result.tests_total) == (3, 3)
    assert result.execution_state == "completed"
    assert result.execution_phase == "repo_suite"
    assert result.assurance is not None
    assert result.assurance["report_integrity"] == "same_process_candidate_writable"
    assert result.assurance["overall_profile"] == "composite_blackbox_repo_native"
    assert result.assurance["repo_native_suite"] == "composed_completed"
    assert result.attestation is not None
    assert result.attestation["repo_suite_started"] is True
    assert result.attestation["repo_suite_completed"] is True
    assert result.attestation["repo_suite_state"] == "composed_completed"
    assert result.attestation["repo_suite_passed"] is True


def test_external_report_floor_requires_blackbox_only(
    repo_and_pack: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, pack = repo_and_pack
    monkeypatch.setattr(
        blackbox_module, "run_blackbox", lambda *_args, **_kwargs: _blackbox_result()
    )
    monkeypatch.setattr(
        RepoVerifier, "verify", lambda *_args, **_kwargs: _repo_result()
    )

    composite = guard(
        str(repo),
        _candidate(),
        verifier_pack=str(pack),
        blackbox=True,
        require_report_integrity="external_process_isolated",
    )
    blackbox_only = guard(
        str(repo),
        _candidate(),
        verifier_pack=str(pack),
        blackbox=True,
        blackbox_only=True,
        require_report_integrity="external_process_isolated",
    )

    assert composite.verdict == ERROR
    assert composite.reason_code == REASON_ASSURANCE_REQUIREMENT_NOT_MET
    assert blackbox_only.verdict == PASS
    assert blackbox_only.verdict_source == "blackbox"
    assert blackbox_only.assurance is not None
    assert blackbox_only.assurance["report_integrity"] == "external_process_isolated"
    assert blackbox_only.assurance["overall_profile"] == "black_box_external_judge"


def test_completed_composite_failure_keeps_repo_phase_and_composed_counts(
    repo_and_pack: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, pack = repo_and_pack
    monkeypatch.setattr(
        blackbox_module, "run_blackbox", lambda *_args, **_kwargs: _blackbox_result()
    )
    monkeypatch.setattr(
        RepoVerifier, "verify", lambda *_args, **_kwargs: _repo_result(passed=False)
    )

    result = guard(str(repo), _candidate(), verifier_pack=str(pack), blackbox=True)

    assert result.verdict == FAIL
    assert result.verdict_source == "composite:blackbox+repo"
    assert (result.tests_passed, result.tests_total) == (2, 3)
    assert result.execution_phase == "repo_suite"


def test_repo_preflight_failure_is_not_labelled_as_an_executed_composite(
    repo_and_pack: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, pack = repo_and_pack
    monkeypatch.setattr(
        blackbox_module, "run_blackbox", lambda *_args, **_kwargs: _blackbox_result()
    )
    no_start = VerdictResult(
        passed=False,
        score=0.0,
        diagnostics="command missing",
        artifact={
            "outcome": "test_command_unavailable",
            "execution_state": "not_started",
            "execution_phase": "preflight",
            "test_command_started": False,
            "test_command_completed": False,
            "delivered_isolation": "not_run",
            "verdict_source": None,
        },
    )
    monkeypatch.setattr(RepoVerifier, "verify", lambda *_args, **_kwargs: no_start)

    result = guard(str(repo), _candidate(), verifier_pack=str(pack), blackbox=True)

    assert result.verdict == ERROR
    assert result.verdict_source is None
    assert result.execution_state == "started_incomplete"
    assert result.execution_phase == "preflight"
    assert result.tests_passed is None
    assert result.tests_total is None
    assert result.assurance is not None
    assert result.assurance["repo_native_suite"] == "required_not_started"
    assert result.assurance["report_integrity"] == "external_process_isolated"
    assert result.attestation is not None
    assert result.attestation["repo_suite_started"] is False
    assert result.attestation["repo_suite_completed"] is False
    assert result.attestation["repo_suite_passed"] is None
