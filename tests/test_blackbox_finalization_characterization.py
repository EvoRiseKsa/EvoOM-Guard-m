"""Frozen boundary and ordering facts for black-box Guard finalization.

These tests deliberately exercise the public ``guard()`` facade.  They pin the
observable seam before the post-judge sequence moves into an application
coordinator: runtime cleanup must finish before finalization starts, a
composite repository verifier is conditional, and the eager assurance gate
must remain before attestation.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from assurance_decision_gate_characterization_harness import capture_case

from evoom_guard.blackbox import BlackboxResult
from evoom_guard.contracts import VerdictResult
from evoom_guard.guard import guard

guard_module = importlib.import_module("evoom_guard.guard")
blackbox_module = importlib.import_module("evoom_guard.blackbox")

_CANDIDATE = """\
<<<FILE: app.py>>>
VALUE = 2
<<<END FILE>>>
"""


def _inputs(root: Path) -> tuple[Path, Path]:
    repo = root / "repo"
    pack = root / "pack"
    (repo / "tests").mkdir(parents=True)
    pack.mkdir()
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repo / "tests" / "test_app.py").write_text(
        "def test_app():\n    assert True\n",
        encoding="utf-8",
    )
    (pack / "test_protocol.py").write_text(
        "def test_protocol():\n    assert True\n",
        encoding="utf-8",
    )
    return repo, pack


def test_blackbox_only_finalization_order_is_frozen(tmp_path: Path) -> None:
    case = capture_case("blackbox_completed_pass_none", tmp_path)

    assert case["timeline"] == [
        "blackbox:run",
        "profile:runtime",
        "shortfall:call",
        "attestation:build",
    ]
    assert case["decision"] == {
        "verdict": "PASS",
        "passed": True,
        "reason_code": "tests_passed",
        "reason": (
            "the black-box pack passed (1/1) — the candidate satisfied the "
            "judge-owned protocol tests, judged from outside its own process"
        ),
        "execution_state": "completed",
        "execution_phase": "blackbox_pack",
        "verdict_source": "blackbox",
        "isolation": "subprocess",
    }
    assert case["result_assurance_is_profile_source"] is True
    assert case["result_attestation_is_source"] is True


def test_composite_finalization_keeps_repo_effect_before_evidence(
    tmp_path: Path,
) -> None:
    case = capture_case("blackbox_composite_external_floor", tmp_path)

    assert case["timeline"] == [
        "blackbox:run",
        "verifier:init",
        "verifier:verify",
        "profile:runtime",
        "shortfall:call",
        "attestation:build",
    ]
    assert case["verifier_calls"] == ["init", "verify"]
    assert case["profile_calls"][0]["keywords"]["repo_suite_state"] == (
        "composed_completed"
    )
    assert case["profile_calls"][0]["keywords"]["composed_repo_suite"] is True


@pytest.mark.parametrize(
    ("failure", "expected_type"),
    (
        (KeyboardInterrupt("synthetic primary interrupt"), "KeyboardInterrupt"),
        (SystemExit("synthetic cleanup exit"), "SystemExit"),
    ),
)
def test_runtime_baseexception_precedes_all_finalization_services(
    tmp_path: Path,
    failure: BaseException,
    expected_type: str,
) -> None:
    repo, pack = _inputs(tmp_path)
    calls: list[str] = []

    def fail_blackbox(*_args: Any, **_kwargs: Any) -> Any:
        calls.append("blackbox:run")
        raise failure

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        calls.append("finalization:entered")
        raise AssertionError("finalization must not run after runtime cleanup fails")

    with (
        patch.object(blackbox_module, "run_blackbox", fail_blackbox),
        patch.object(guard_module, "_assurance_profile", forbidden),
        patch.object(guard_module, "_assurance_shortfall", forbidden),
        patch.object(guard_module, "_build_attestation", forbidden),
        pytest.raises(BaseException) as caught,
    ):
        guard(
            str(repo),
            _CANDIDATE,
            test_command=["python", "-c", "raise SystemExit(0)"],
            verifier_pack=str(pack),
            blackbox=True,
            blackbox_only=True,
        )

    assert type(caught.value).__name__ == expected_type
    assert caught.value is failure
    assert calls == ["blackbox:run"]


def test_finalization_helpers_are_resolved_after_blackbox_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack = _inputs(tmp_path)
    timeline: list[str] = []
    original_profile = guard_module._assurance_profile
    original_attestation = guard_module._build_attestation

    def early(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("finalization helper was captured before runtime")

    def late_profile(*args: Any, **kwargs: Any) -> dict[str, Any]:
        timeline.append("profile:late")
        return original_profile(*args, **kwargs)

    def late_shortfall(*_args: Any, **_kwargs: Any) -> None:
        timeline.append("shortfall:late")

    def late_attestation(*args: Any, **kwargs: Any) -> dict[str, Any]:
        timeline.append("attestation:late")
        return original_attestation(*args, **kwargs)

    def complete_blackbox(*_args: Any, **_kwargs: Any) -> BlackboxResult:
        timeline.append("blackbox:cleanup-complete")
        return BlackboxResult(
            passed=True,
            tests_passed=1,
            tests_total=1,
            diagnostics="",
            ran=True,
            error=None,
            pack_sha256="a" * 64,
            pack_manifest={"id": "probe", "version": "1.0.0"},
            junit_sha256="b" * 64,
            isolation={
                "requested": "subprocess",
                "delivered": "subprocess",
            },
            deleted_applied=[],
            started=True,
            completed=True,
            execution_state="completed",
            execution_phase="blackbox_pack",
            pack_present=True,
            candidate_invocations=1,
            candidate_launcher_invocation_observed=True,
        )

    class RebindingRepoVerifier:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def verify(
            self,
            _candidate: str,
            _problem: dict[str, Any],
        ) -> VerdictResult:
            timeline.append("repo:verify")
            monkeypatch.setattr(
                guard_module, "_assurance_profile", late_profile
            )
            monkeypatch.setattr(
                guard_module, "_assurance_shortfall", late_shortfall
            )
            monkeypatch.setattr(
                guard_module, "_build_attestation", late_attestation
            )
            return VerdictResult(
                passed=True,
                score=1.0,
                diagnostics="",
                artifact={
                    "execution_state": "completed",
                    "execution_phase": "repo_suite",
                    "test_command_started": True,
                    "test_command_completed": True,
                    "delivered_isolation": "subprocess",
                    "verdict_source": "junit+exit",
                    "tests_passed": 1,
                    "tests_total": 1,
                    "repo_suite_started": True,
                    "repo_suite_completed": True,
                    "repo_suite_passed": True,
                },
            )

    monkeypatch.setattr(guard_module, "_assurance_profile", early)
    monkeypatch.setattr(guard_module, "_assurance_shortfall", early)
    monkeypatch.setattr(guard_module, "_build_attestation", early)
    monkeypatch.setattr(guard_module, "RepoVerifier", RebindingRepoVerifier)
    monkeypatch.setattr(blackbox_module, "run_blackbox", complete_blackbox)

    result = guard(
        str(repo),
        _CANDIDATE,
        test_command=["python", "-c", "raise SystemExit(0)"],
        verifier_pack=str(pack),
        blackbox=True,
    )

    assert result.passed is True
    assert timeline == [
        "blackbox:cleanup-complete",
        "repo:verify",
        "profile:late",
        "shortfall:late",
        "attestation:late",
    ]
