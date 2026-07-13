# -----------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available - see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Public execution-state and delivered-assurance contract.

These tests deliberately exercise :func:`guard`, not just runner artifacts.
Configuration is not evidence: requested Docker, a verifier-pack path, or
black-box mode must not be reported as delivered until the corresponding
command actually starts.  Conversely, a timed-out command did start even
though it produced no gradeable verdict.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import evoom_guard.blackbox as blackbox_module
from evoom_guard.blackbox import BlackboxResult
from evoom_guard.candidate_runner import CandidateRunner
from evoom_guard.contracts import VerdictResult
from evoom_guard.guard import (
    ERROR,
    PASS,
    REASON_ASSURANCE_REQUIREMENT_NOT_MET,
    REASON_NO_TEST_VERDICT,
    REASON_POLICY_REQUIREMENT_UNSUPPORTED,
    REASON_RUNTIME_CLEANUP_FAILED,
    REASON_SETUP_FAILED,
    REASON_SETUP_TIMEOUT,
    REASON_TEST_TIMEOUT,
    REASON_TESTS_PASSED,
    REASON_VERIFIER_PACK_INVALID,
    REASON_VERIFIER_PACK_NOT_FOUND,
    REASON_VERIFIER_PACK_REQUIRED,
    guard,
    render_report,
    to_sarif,
)
from evoom_guard.verifiers.repo_verifier import RepoVerifier


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    tests = root / "tests"
    tests.mkdir(parents=True)
    (root / "app.py").write_text(
        "def answer():\n    return 42\n", encoding="utf-8"
    )
    (tests / "test_app.py").write_text(
        "from app import answer\n\n"
        "def test_answer():\n    assert answer() == 42\n",
        encoding="utf-8",
    )
    return root


@pytest.fixture
def valid_pack(tmp_path: Path) -> Path:
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "test_protocol.py").write_text(
        "def test_protocol():\n    assert True\n", encoding="utf-8"
    )
    return pack


def _candidate() -> str:
    return (
        "<<<FILE: app.py>>>\n"
        "def answer():\n"
        "    \"\"\"Return the stable public answer.\"\"\"\n"
        "    return 42\n"
        "<<<END FILE>>>\n"
    )


def _assert_public_views(
    result,
    *,
    state: str,
    phase: str,
    command_started: bool,
) -> None:
    """Pin the same facts in all three public report formats."""
    payload = result.to_dict()
    assert payload["execution_state"] == state
    assert payload["execution_phase"] == phase
    assert payload["test_command_ran"] is command_started
    assert payload["verdict_source"] == result.verdict_source

    markdown = render_report(result)
    assert f"`{state}`" in markdown
    assert f"phase `{phase}`" in markdown
    assert (
        f"Test command started | {'yes' if command_started else 'no'}"
        in markdown
    )

    sarif_results = to_sarif(result)["runs"][0]["results"]
    if result.verdict == PASS:
        assert sarif_results == []
    else:
        assert len(sarif_results) == 1
        properties = sarif_results[0]["properties"]
        assert properties["execution_state"] == state
        assert properties["execution_phase"] == phase
        assert properties["test_command_ran"] is command_started
        assert properties["isolation"] == result.isolation


def _assert_no_runtime_assurance(result) -> None:
    assert result.isolation == "not_run"
    assurance = result.assurance
    assert assurance is not None
    assert assurance["overall_profile"] == "preflight"
    assert assurance["candidate_isolation"] == "not_run"
    assert assurance["suite_isolation"] == "not_run"
    assert assurance["report_integrity"] == "not_applicable_not_run"


def test_unsupported_policy_is_a_truthful_preflight(repo: Path) -> None:
    result = guard(
        str(repo),
        _candidate(),
        isolation="docker",
        docker_image="python:3.12",
        min_diff_coverage=80,
    )

    assert result.verdict == ERROR
    assert result.reason_code == REASON_POLICY_REQUIREMENT_UNSUPPORTED
    assert result.verdict_source is None
    _assert_no_runtime_assurance(result)
    assert result.assurance["verifier_pack"] is None
    assert result.attestation is not None
    assert result.attestation["effective_policy"]["isolation"] == "docker"
    assert result.attestation["isolation_evidence"] is None
    _assert_public_views(
        result, state="not_started", phase="preflight", command_started=False
    )


def test_blackbox_without_pack_never_starts_an_external_judge(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def must_not_run(*_args: object, **_kwargs: object) -> BlackboxResult:
        raise AssertionError("black-box judge started without a verifier pack")

    monkeypatch.setattr(blackbox_module, "run_blackbox", must_not_run)
    result = guard(str(repo), _candidate(), blackbox=True, blackbox_only=True)

    assert result.verdict == ERROR
    assert result.reason_code == REASON_VERIFIER_PACK_REQUIRED
    assert result.verdict_source is None
    _assert_no_runtime_assurance(result)
    assert result.assurance["verifier_pack"] is None
    _assert_public_views(
        result, state="not_started", phase="preflight", command_started=False
    )


def test_invalid_repo_pack_reports_presence_but_no_execution(
    repo: Path, tmp_path: Path
) -> None:
    pack = tmp_path / "invalid-pack"
    pack.mkdir()
    (pack / "test_protocol.py").write_text(
        "def test_protocol():\n    assert True\n", encoding="utf-8"
    )
    (pack / "pack.json").write_text("{broken", encoding="utf-8")

    result = guard(str(repo), _candidate(), verifier_pack=str(pack))

    assert result.verdict == ERROR
    assert result.reason_code == REASON_VERIFIER_PACK_INVALID
    assert result.verdict_source is None
    _assert_no_runtime_assurance(result)
    pack_assurance = result.assurance["verifier_pack"]
    assert pack_assurance["configured"] is True
    assert pack_assurance["present"] is True
    assert pack_assurance["integrity"] == "invalid"
    assert pack_assurance["execution_state"] == "not_started"
    _assert_public_views(
        result, state="not_started", phase="preflight", command_started=False
    )


def test_missing_repo_pack_is_not_misreported_as_invalid_present_pack(
    repo: Path, tmp_path: Path
) -> None:
    missing = tmp_path / "does-not-exist"

    result = guard(str(repo), _candidate(), verifier_pack=str(missing))

    assert result.verdict == ERROR
    assert result.reason_code == REASON_VERIFIER_PACK_NOT_FOUND
    assert result.verdict_source is None
    _assert_no_runtime_assurance(result)
    pack_assurance = result.assurance["verifier_pack"]
    assert pack_assurance["configured"] is True
    assert pack_assurance["present"] is False
    assert pack_assurance["integrity"] == "not_evaluated_missing"
    assert pack_assurance["execution_state"] == "not_started"
    _assert_public_views(
        result, state="not_started", phase="preflight", command_started=False
    )


@pytest.mark.parametrize("blackbox", [False, True], ids=["repo", "blackbox"])
def test_existing_non_directory_pack_is_present_but_invalid(
    repo: Path, tmp_path: Path, blackbox: bool
) -> None:
    pack_file = tmp_path / "pack-file"
    pack_file.write_text("not a directory\n", encoding="utf-8")

    result = guard(
        str(repo),
        _candidate(),
        verifier_pack=str(pack_file),
        blackbox=blackbox,
        blackbox_only=blackbox,
    )

    assert result.verdict == ERROR
    assert result.reason_code == REASON_VERIFIER_PACK_INVALID
    pack_assurance = result.assurance["verifier_pack"]
    assert pack_assurance["present"] is True
    assert pack_assurance["integrity"] == "invalid"
    _assert_public_views(
        result, state="not_started", phase="preflight", command_started=False
    )


def test_requested_docker_without_image_claims_no_docker_delivery(repo: Path) -> None:
    result = guard(str(repo), _candidate(), isolation="docker")

    assert result.verdict == ERROR
    assert result.reason_code == REASON_ASSURANCE_REQUIREMENT_NOT_MET
    assert result.verdict_source is None
    _assert_no_runtime_assurance(result)
    assert result.attestation is not None
    assert result.attestation["effective_policy"]["isolation"] == "docker"
    isolation_evidence = result.attestation["isolation_evidence"]
    assert isolation_evidence is not None
    assert isolation_evidence["requested"] == "docker"
    assert isolation_evidence["delivered"] == "unavailable"
    assert isolation_evidence["image_digest"] is None
    _assert_public_views(
        result, state="not_started", phase="preflight", command_started=False
    )


def test_missing_setup_command_does_not_claim_a_started_suite(repo: Path) -> None:
    result = guard(
        str(repo),
        _candidate(),
        setup_command=["definitely-not-an-evoguard-command"],
    )

    assert result.verdict == ERROR
    assert result.reason_code == REASON_SETUP_FAILED
    assert result.verdict_source is None
    _assert_no_runtime_assurance(result)
    # Merely selecting the subprocess setup path is not delivery evidence: the
    # executable was absent, so no setup boundary started either.
    assert result.assurance["setup_isolation"] is None
    _assert_public_views(
        result, state="not_started", phase="setup", command_started=False
    )


@pytest.mark.parametrize(
    ("setup_command", "timeout", "reason_code"),
    [
        ([sys.executable, "-c", "raise SystemExit(7)"], 5, REASON_SETUP_FAILED),
        (
            [sys.executable, "-c", "import time; time.sleep(5)"],
            0.05,
            REASON_SETUP_TIMEOUT,
        ),
    ],
    ids=["nonzero", "timeout"],
)
def test_started_but_unsuccessful_setup_is_not_a_started_test_command(
    repo: Path,
    setup_command: list[str],
    timeout: float,
    reason_code: str,
) -> None:
    result = guard(
        str(repo),
        _candidate(),
        setup_command=setup_command,
        timeout=timeout,
    )

    assert result.verdict == ERROR
    assert result.reason_code == reason_code
    assert result.verdict_source is None
    # A setup process did start, hence the overall execution is incomplete; the
    # repo test command itself did not, so no suite/report assurance is claimed.
    assert result.isolation == "not_run"
    assurance = result.assurance
    assert assurance is not None
    assert assurance["overall_profile"] == "execution_incomplete_before_tests"
    assert assurance["candidate_isolation"] == "not_run"
    assert assurance["suite_isolation"] == "not_run"
    assert assurance["report_integrity"] == "not_applicable_not_run"
    assert assurance["setup_isolation"] == "subprocess"
    _assert_public_views(
        result,
        state="started_incomplete",
        phase="setup",
        command_started=False,
    )


def test_repo_suite_timeout_records_started_incomplete_without_source(
    repo: Path,
) -> None:
    result = guard(
        str(repo),
        _candidate(),
        test_command=[sys.executable, "-c", "import time; time.sleep(5)"],
        timeout=0.05,
    )

    assert result.verdict != PASS
    assert result.reason_code == REASON_TEST_TIMEOUT
    assert result.verdict_source is None
    assert result.isolation == "subprocess"
    assurance = result.assurance
    assert assurance is not None
    assert assurance["overall_profile"] == "execution_incomplete"
    assert assurance["candidate_isolation"] == "subprocess"
    assert assurance["suite_isolation"] == "subprocess"
    assert assurance["report_integrity"] == "same_process_candidate_writable"
    _assert_public_views(
        result,
        state="started_incomplete",
        phase="repo_suite",
        command_started=True,
    )


def test_completed_repo_pass_is_the_positive_control(repo: Path) -> None:
    result = guard(str(repo), _candidate(), timeout=30)

    assert result.verdict == PASS
    assert result.reason_code == REASON_TESTS_PASSED
    assert result.verdict_source == "junit+exit"
    assert result.tests_total == 1
    assert result.tests_passed == 1
    assert result.isolation == "subprocess"
    assurance = result.assurance
    assert assurance is not None
    assert assurance["overall_profile"] == "repo_native_same_process"
    assert assurance["candidate_isolation"] == "subprocess"
    assert assurance["suite_isolation"] == "subprocess"
    assert assurance["report_integrity"] == "same_process_candidate_writable"
    _assert_public_views(
        result, state="completed", phase="repo_suite", command_started=True
    )


def test_blackbox_timeout_preserves_that_external_command_started(
    repo: Path, valid_pack: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def timed_out(*_args: object, **_kwargs: object) -> BlackboxResult:
        return BlackboxResult(
            False,
            0,
            0,
            "judge exceeded deadline",
            False,
            "timeout",
            "a" * 64,
            None,
            None,
            {"requested": "subprocess", "delivered": "subprocess"},
            [],
            started=True,
            completed=False,
            execution_state="started_incomplete",
            execution_phase="blackbox_pack",
            pack_present=True,
            candidate_invocations=1,
            candidate_launcher_invocation_observed=True,
        )

    monkeypatch.setattr(blackbox_module, "run_blackbox", timed_out)
    result = guard(
        str(repo),
        _candidate(),
        verifier_pack=str(valid_pack),
        blackbox=True,
        blackbox_only=True,
    )

    assert result.verdict == ERROR
    assert result.reason_code == REASON_TEST_TIMEOUT
    assert result.verdict_source is None
    assert result.tests_passed is None
    assert result.tests_total is None
    assert result.isolation == "subprocess"
    assurance = result.assurance
    assert assurance is not None
    assert assurance["overall_profile"] == "execution_incomplete"
    assert assurance["candidate_isolation"] == "subprocess"
    assert assurance["report_integrity"] == "external_process_isolated"
    pack_assurance = assurance["verifier_pack"]
    assert pack_assurance["present"] is True
    assert pack_assurance["execution_state"] == "started_incomplete"
    _assert_public_views(
        result,
        state="started_incomplete",
        phase="blackbox_pack",
        command_started=True,
    )


def test_blackbox_docker_prepare_timeout_is_not_started_unavailable(
    repo: Path, valid_pack: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def timed_out_prepare(
        _runner: CandidateRunner, _workdir: str, _target: str
    ) -> None:
        raise subprocess.TimeoutExpired(["docker", "version"], timeout=30)

    def prepare_after_platform_gate(
        runner: CandidateRunner, workdir: str, target: str
    ) -> tuple[str, dict[str, str], object]:
        return runner._prepare_supported_host(workdir, target)

    monkeypatch.setattr(CandidateRunner, "_prepare_container", timed_out_prepare)
    monkeypatch.setattr(CandidateRunner, "prepare", prepare_after_platform_gate)

    result = guard(
        str(repo),
        _candidate(),
        verifier_pack=str(valid_pack),
        blackbox=True,
        blackbox_only=True,
        isolation="docker",
        docker_image="python:3.12-slim",
    )

    assert result.verdict == ERROR
    assert result.reason_code == REASON_ASSURANCE_REQUIREMENT_NOT_MET
    assert result.execution_state == "not_started"
    assert result.test_command_ran is False
    assert result.isolation == "not_run"
    assert result.assurance is not None
    assert result.assurance["candidate_isolation"] == "not_run"
    assert result.attestation is not None
    assert result.attestation["isolation_evidence"]["delivered"] == "unavailable"


def test_blackbox_container_cleanup_failure_is_public_error_not_pass(
    repo: Path, valid_pack: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def cleanup_failed(*_args: object, **_kwargs: object) -> BlackboxResult:
        return BlackboxResult(
            False,
            0,
            0,
            "candidate container cleanup could not prove absence",
            False,
            "candidate container cleanup failed",
            "a" * 64,
            None,
            None,
            {
                "requested": "docker",
                "delivered": "docker",
                "candidate_launcher_invocation_observed": True,
            },
            [],
            started=True,
            completed=False,
            execution_state="started_incomplete",
            execution_phase="blackbox_pack",
            pack_present=True,
            candidate_invocations=1,
            candidate_launcher_invocation_observed=True,
        )

    monkeypatch.setattr(blackbox_module, "run_blackbox", cleanup_failed)
    result = guard(
        str(repo),
        _candidate(),
        verifier_pack=str(valid_pack),
        blackbox=True,
        blackbox_only=True,
        isolation="docker",
        docker_image="python:3.12-slim",
    )

    assert result.verdict == ERROR
    assert result.passed is False
    assert result.reason_code == REASON_RUNTIME_CLEANUP_FAILED
    assert result.execution_state == "started_incomplete"
    assert "cleanup could not prove absence" in result.reason


def test_blackbox_zero_results_reports_completed_but_ungradeable_evidence(
    repo: Path, valid_pack: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def zero_results(*_args: object, **_kwargs: object) -> BlackboxResult:
        return BlackboxResult(
            False,
            0,
            0,
            "collected 0 items",
            False,
            "black-box pack produced no judge-owned test results",
            "b" * 64,
            None,
            "c" * 64,
            {"requested": "subprocess", "delivered": "subprocess"},
            [],
            started=True,
            completed=True,
            execution_state="completed",
            execution_phase="blackbox_pack",
            pack_present=True,
            candidate_invocations=1,
            candidate_launcher_invocation_observed=True,
        )

    monkeypatch.setattr(blackbox_module, "run_blackbox", zero_results)
    result = guard(
        str(repo),
        _candidate(),
        verifier_pack=str(valid_pack),
        blackbox=True,
        blackbox_only=True,
    )

    assert result.verdict == ERROR
    assert result.reason_code == REASON_NO_TEST_VERDICT
    assert result.verdict_source is None
    # Zero is observed evidence from a completed judge, unlike ``None`` (not
    # observed/not started), so the public contract must preserve 0/0.
    assert result.tests_passed == 0
    assert result.tests_total == 0
    assert result.isolation == "subprocess"
    assurance = result.assurance
    assert assurance is not None
    assert assurance["overall_profile"] == "black_box_external_judge"
    assert assurance["report_integrity"] == "external_process_isolated"
    pack_assurance = assurance["verifier_pack"]
    assert pack_assurance["present"] is True
    assert pack_assurance["execution_state"] == "completed"
    _assert_public_views(
        result, state="completed", phase="blackbox_pack", command_started=True
    )


def test_repo_pack_collecting_zero_tests_is_not_mislabelled_patch_failure(
    repo: Path, tmp_path: Path
) -> None:
    pack = tmp_path / "zero-pack"
    pack.mkdir()
    (pack / "test_none.py").write_text(
        "# valid test-shaped pack file with no collected test\n", encoding="utf-8"
    )

    result = guard(
        str(repo),
        _candidate(),
        verifier_pack=str(pack),
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
    )

    assert result.verdict == ERROR
    assert result.reason_code == REASON_NO_TEST_VERDICT
    assert "zero tests" in (result.diagnostics + result.reason).lower()
    assert result.execution_state == "completed"
    assert result.execution_phase == "verifier_pack"
    assert result.test_command_ran is True
    assert result.verdict_source is None
    assert result.reason_code != "patch_apply_failed"


def test_passing_repo_cannot_mask_zero_test_verifier_pack(
    repo: Path, tmp_path: Path
) -> None:
    pack = tmp_path / "zero-pack-with-real-repo-suite"
    pack.mkdir()
    (pack / "test_none.py").write_text(
        "# valid test-shaped pack file with no collected test\n", encoding="utf-8"
    )

    result = guard(str(repo), _candidate(), verifier_pack=str(pack))

    # The repo's real pytest phase passed 1/1. The required verifier pack did
    # not produce a verdict, so this is an infrastructure/policy ERROR rather
    # than a false attribution to failing repo tests.
    assert result.verdict == ERROR
    assert result.reason_code == REASON_NO_TEST_VERDICT
    assert "zero tests" in (result.diagnostics + result.reason).lower()
    assert "repo's tests fail" not in result.reason.lower()
    assert (result.tests_passed, result.tests_total) == (1, 1)
    assert result.execution_state == "completed"
    assert result.execution_phase == "verifier_pack"
    assert result.test_command_ran is True
    assert result.verdict_source is None
    assert result.attestation is not None
    assert result.attestation["verifier_pack_tests_passed"] == 0
    assert result.attestation["verifier_pack_tests_total"] == 0


def test_ungradeable_repo_exit_has_no_clean_source(repo: Path) -> None:
    result = guard(
        str(repo),
        _candidate(),
        test_command=[sys.executable, "-c", "raise SystemExit(2)"],
    )

    assert result.verdict == ERROR
    assert result.reason_code == REASON_NO_TEST_VERDICT
    assert result.verdict_source is None
    assert result.execution_state == "completed"
    assert result.execution_phase == "repo_suite"
    assert result.test_command_ran is True


def test_top_level_isolation_is_the_effective_candidate_boundary(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mocked = VerdictResult(
        passed=True,
        score=1.0,
        diagnostics="",
        artifact={
            "tests_passed": 1,
            "tests_total": 1,
            "verdict_source": "junit+exit",
            "execution_state": "completed",
            "execution_phase": "repo_suite",
            "test_command_started": True,
            "test_command_completed": True,
            "delivered_isolation": "docker",
            "setup_isolation": "subprocess_host_opt_in",
            "isolation_evidence": {
                "requested": "docker",
                "delivered": "docker",
            },
        },
    )
    monkeypatch.setattr(RepoVerifier, "verify", lambda *_args, **_kwargs: mocked)

    result = guard(
        str(repo),
        _candidate(),
        isolation="docker",
        docker_image="sha256:" + "d" * 64,
        setup_command=[sys.executable, "-c", "pass"],
        trust_setup_on_host=True,
        require_candidate_isolation="docker",
    )

    assert result.verdict == ERROR
    assert result.reason_code == REASON_ASSURANCE_REQUIREMENT_NOT_MET
    assert result.isolation == "subprocess"
    assert result.to_dict()["isolation"] == "subprocess"
    assert result.assurance is not None
    assert result.assurance["suite_isolation"] == "docker"
    assert result.assurance["candidate_isolation"] == "subprocess"
    assert result.attestation is not None
    assert result.attestation["delivered_isolation"] == "docker"
    assert result.attestation["effective_candidate_isolation"] == "subprocess"
    sarif = to_sarif(result)["runs"][0]["results"][0]
    assert sarif["properties"]["isolation"] == "subprocess"
