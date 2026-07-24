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
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from assurance_decision_gate_characterization_harness import capture_case

from evoom_guard.blackbox import BlackboxResult
from evoom_guard.contracts import VerdictResult
from evoom_guard.domain.decision import GuardDecision as DomainGuardDecision
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


def _completed_runtime() -> BlackboxResult:
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


def test_verification_pipeline_lookup_remains_live_at_composition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Match the pre-extraction module-global lookup after prior effects."""

    repo, pack = _inputs(tmp_path)
    timeline: list[str] = []
    original_profile = guard_module._assurance_profile
    original_pipeline = guard_module.VerificationPipeline

    class PrematurePipeline:
        @classmethod
        def from_decision(cls, _decision: object) -> object:
            pytest.fail("VerificationPipeline was captured before composition")

    class LivePipeline:
        @classmethod
        def from_decision(cls, decision: object) -> object:
            timeline.append("pipeline:live")
            return original_pipeline.from_decision(decision)

    def rebind_during_profile(
        *args: Any,
        **kwargs: Any,
    ) -> dict[str, Any]:
        timeline.append("profile:rebind-pipeline")
        monkeypatch.setattr(
            guard_module,
            "VerificationPipeline",
            LivePipeline,
        )
        return original_profile(*args, **kwargs)

    monkeypatch.setattr(
        guard_module,
        "VerificationPipeline",
        PrematurePipeline,
    )
    monkeypatch.setattr(
        guard_module,
        "_assurance_profile",
        rebind_during_profile,
    )
    monkeypatch.setattr(
        blackbox_module,
        "run_blackbox",
        lambda *a, **k: _completed_runtime(),
    )

    result = guard(
        str(repo),
        _CANDIDATE,
        test_command=["python", "-c", "raise SystemExit(0)"],
        verifier_pack=str(pack),
        blackbox=True,
        blackbox_only=True,
    )

    assert result.passed is True
    assert timeline == ["profile:rebind-pipeline", "pipeline:live"]


def test_guard_decision_reexport_and_lookup_remain_live_at_composition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Freeze both Guard's historical ABI and its late class lookup."""

    assert guard_module.GuardDecision is DomainGuardDecision

    repo, pack = _inputs(tmp_path)
    timeline: list[str] = []
    original_profile = guard_module._assurance_profile

    def premature_decision(**_kwargs: Any) -> DomainGuardDecision:
        pytest.fail("GuardDecision was captured before composition")

    def live_decision(**kwargs: Any) -> DomainGuardDecision:
        timeline.append("decision:live")
        return DomainGuardDecision(**kwargs)

    def rebind_during_profile(
        *args: Any,
        **kwargs: Any,
    ) -> dict[str, Any]:
        timeline.append("profile:rebind-decision")
        monkeypatch.setattr(guard_module, "GuardDecision", live_decision)
        return original_profile(*args, **kwargs)

    monkeypatch.setattr(
        guard_module,
        "GuardDecision",
        premature_decision,
    )
    monkeypatch.setattr(
        guard_module,
        "_assurance_profile",
        rebind_during_profile,
    )
    monkeypatch.setattr(
        blackbox_module,
        "run_blackbox",
        lambda *a, **k: _completed_runtime(),
    )

    result = guard(
        str(repo),
        _CANDIDATE,
        test_command=["python", "-c", "raise SystemExit(0)"],
        verifier_pack=str(pack),
        blackbox=True,
        blackbox_only=True,
    )

    assert result.passed is True
    assert timeline == ["profile:rebind-decision", "decision:live"]


def test_guard_result_factory_is_snapshotted_before_final_wire_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Freeze decision reads before the historical result-factory lookup."""

    repo, pack = _inputs(tmp_path)
    timeline: list[str] = []
    original_result = guard_module.GuardResult
    original_attestation = guard_module._build_attestation

    class RuntimeProbe:
        passed = True
        tests_passed = 1
        tests_total = 1
        ran = True
        error = None
        pack_sha256 = "a" * 64
        pack_manifest = {"id": "probe", "version": "1.0.0"}
        junit_sha256 = "b" * 64
        isolation = {
            "requested": "subprocess",
            "delivered": "subprocess",
        }
        deleted_applied: list[str] = []
        started = True
        completed = True
        execution_state = "completed"
        execution_phase = "blackbox_pack"
        pack_present = True
        candidate_invocations = 1
        candidate_launcher_invocation_observed = True

        @property
        def diagnostics(self) -> str:
            timeline.append("runtime:diagnostics")
            return ""

    class RiskProbe:
        @property
        def level(self) -> str:
            timeline.append("risk:level")
            monkeypatch.setattr(guard_module, "GuardResult", late_factory)
            return "low"

        @property
        def score(self) -> float:
            timeline.append("risk:score")
            return 0.1

    class DecisionProbe:
        def __init__(
            self,
            *,
            verdict: str,
            reason_code: str,
            reason: str,
        ) -> None:
            self._verdict = verdict
            self._reason_code = reason_code
            self._reason = reason

        @property
        def verdict(self) -> str:
            timeline.append("decision:verdict")
            monkeypatch.setattr(guard_module, "GuardResult", selected_factory)
            return self._verdict

        @property
        def reason_code(self) -> str:
            timeline.append("decision:reason-code")
            return self._reason_code

        @property
        def reason(self) -> str:
            timeline.append("decision:reason")
            return self._reason

    def premature_factory(**_kwargs: Any) -> object:
        pytest.fail("GuardResult was captured before decision projection")

    def selected_factory(**kwargs: Any) -> object:
        timeline.append("factory:selected")
        return original_result(**kwargs)

    def late_factory(**_kwargs: Any) -> object:
        pytest.fail("GuardResult was resolved after keyword evaluation began")

    def risk_score_probe(*_args: Any, **_kwargs: Any) -> RiskProbe:
        return RiskProbe()

    def attestation_probe(
        *args: Any,
        **kwargs: Any,
    ) -> dict[str, Any]:
        timeline.append("attestation:build")
        monkeypatch.setattr(guard_module, "GuardResult", late_factory)
        return original_attestation(*args, **kwargs)

    monkeypatch.setattr(guard_module, "GuardResult", premature_factory)
    monkeypatch.setattr(guard_module, "GuardDecision", DecisionProbe)
    monkeypatch.setattr(
        guard_module,
        "_assurance_shortfall",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(guard_module, "risk_score", risk_score_probe)
    monkeypatch.setattr(
        guard_module,
        "_build_attestation",
        attestation_probe,
    )
    monkeypatch.setattr(
        blackbox_module,
        "run_blackbox",
        lambda *a, **k: RuntimeProbe(),
    )

    result = guard(
        str(repo),
        _CANDIDATE,
        test_command=["python", "-c", "raise SystemExit(0)"],
        verifier_pack=str(pack),
        blackbox=True,
        blackbox_only=True,
        baseline_evidence=True,
        diff_coverage=True,
    )

    assert isinstance(result, original_result)
    assert result.passed is True
    assert timeline == [
        "decision:verdict",
        "decision:reason-code",
        "decision:reason",
        "risk:level",
        "risk:score",
        "runtime:diagnostics",
        "attestation:build",
        "factory:selected",
    ]


def test_attestation_can_delete_guard_result_after_callable_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No facade type cast may perform a second runtime global lookup."""

    repo, pack = _inputs(tmp_path)
    original_result = guard_module.GuardResult
    original_attestation = guard_module._build_attestation

    def deleting_attestation(
        *args: Any,
        **kwargs: Any,
    ) -> dict[str, Any]:
        monkeypatch.delattr(guard_module, "GuardResult")
        return original_attestation(*args, **kwargs)

    monkeypatch.setattr(
        guard_module,
        "_build_attestation",
        deleting_attestation,
    )
    monkeypatch.setattr(
        blackbox_module,
        "run_blackbox",
        lambda *a, **k: _completed_runtime(),
    )

    result = guard(
        str(repo),
        _CANDIDATE,
        test_command=["python", "-c", "raise SystemExit(0)"],
        verifier_pack=str(pack),
        blackbox=True,
        blackbox_only=True,
    )

    assert isinstance(result, original_result)
    assert result.passed is True


@pytest.mark.parametrize(
    (
        "passed",
        "ran",
        "error",
        "verdict_symbol",
        "reason_symbol",
    ),
    (
        (
            True,
            True,
            None,
            "PASS",
            "REASON_TESTS_PASSED",
        ),
        (
            False,
            True,
            None,
            "FAIL",
            "REASON_TESTS_FAILED",
        ),
        (
            False,
            False,
            "timeout",
            "ERROR",
            "REASON_TEST_TIMEOUT",
        ),
        (
            False,
            False,
            "verifier pack snapshot changed",
            "TAMPERED",
            "REASON_VERIFIER_PACK_SNAPSHOT_CHANGED",
        ),
    ),
)
def test_blackbox_decision_vocabulary_remains_live_after_risk_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    passed: bool,
    ran: bool,
    error: str | None,
    verdict_symbol: str,
    reason_symbol: str,
) -> None:
    repo, pack = _inputs(tmp_path)
    runtime = BlackboxResult(
        passed=passed,
        tests_passed=1 if passed else 0,
        tests_total=1 if ran else 0,
        diagnostics="",
        ran=ran,
        error=error,
        pack_sha256="a" * 64,
        pack_manifest={"id": "probe", "version": "1.0.0"},
        junit_sha256="b" * 64 if ran else None,
        isolation={
            "requested": "subprocess",
            "delivered": "subprocess",
        },
        deleted_applied=[],
        started=True,
        completed=ran,
        execution_state="completed" if ran else "started_incomplete",
        execution_phase="blackbox_pack",
        pack_present=True,
        candidate_invocations=1 if ran else 0,
        candidate_launcher_invocation_observed=ran,
    )
    live_verdict = f"LIVE_{verdict_symbol}"
    live_reason = f"LIVE_{reason_symbol}"

    def rebind_during_risk(
        *_args: Any,
        **_kwargs: Any,
    ) -> SimpleNamespace:
        monkeypatch.setattr(guard_module, verdict_symbol, live_verdict)
        monkeypatch.setattr(guard_module, reason_symbol, live_reason)
        return SimpleNamespace(level="low", score=0.1)

    monkeypatch.setattr(blackbox_module, "run_blackbox", lambda *a, **k: runtime)
    monkeypatch.setattr(guard_module, "risk_score", rebind_during_risk)

    result = guard(
        str(repo),
        _CANDIDATE,
        test_command=["python", "-c", "raise SystemExit(0)"],
        verifier_pack=str(pack),
        blackbox=True,
        blackbox_only=True,
    )

    assert result.verdict == live_verdict
    assert result.reason_code == live_reason
    assert result.passed is (verdict_symbol == "PASS")


@pytest.mark.parametrize(
    ("policy_name", "expected_verdict", "expected_reason"),
    (
        (
            "_OUTCOME_REASON",
            "LIVE_POLICY_ERROR",
            "live_policy_reason",
        ),
        (
            "_TAMPER_OUTCOME_REASON",
            "LIVE_TAMPERED",
            "live_tamper_reason",
        ),
    ),
)
def test_repo_outcome_policies_remain_live_after_composed_repo_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    policy_name: str,
    expected_verdict: str,
    expected_reason: str,
) -> None:
    repo, pack = _inputs(tmp_path)
    runtime = BlackboxResult(
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
    outcome = "late_custom_outcome"

    class RebindingRepoVerifier:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def verify(
            self,
            _candidate: str,
            _problem: dict[str, Any],
        ) -> VerdictResult:
            if policy_name == "_OUTCOME_REASON":
                monkeypatch.setattr(
                    guard_module,
                    policy_name,
                    {outcome: (expected_verdict, expected_reason)},
                )
            else:
                monkeypatch.setattr(
                    guard_module,
                    "TAMPERED",
                    expected_verdict,
                )
                monkeypatch.setattr(
                    guard_module,
                    policy_name,
                    {outcome: (expected_reason, "late tamper summary")},
                )
            return VerdictResult(
                passed=False,
                score=0.5,
                diagnostics="late repo failure",
                artifact={
                    "outcome": outcome,
                    "execution_state": "completed",
                    "execution_phase": "repo_suite",
                    "test_command_started": True,
                    "verdict_source": "junit+exit",
                    "tests_passed": 0,
                    "tests_total": 1,
                },
            )

    monkeypatch.setattr(blackbox_module, "run_blackbox", lambda *a, **k: runtime)
    monkeypatch.setattr(guard_module, "RepoVerifier", RebindingRepoVerifier)

    result = guard(
        str(repo),
        _CANDIDATE,
        test_command=["python", "-c", "raise SystemExit(0)"],
        verifier_pack=str(pack),
        blackbox=True,
    )

    assert result.verdict == expected_verdict
    assert result.reason_code == expected_reason


def test_execution_vocabulary_remains_live_after_composed_repo_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack = _inputs(tmp_path)
    runtime = BlackboxResult(
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
            monkeypatch.setattr(
                guard_module,
                "EXECUTION_COMPLETED",
                "LIVE_COMPLETED",
            )
            monkeypatch.setattr(
                guard_module,
                "EXECUTION_STARTED_INCOMPLETE",
                "LIVE_STARTED_INCOMPLETE",
            )
            return VerdictResult(
                passed=True,
                score=1.0,
                diagnostics="",
                artifact={
                    "execution_state": "completed",
                    "execution_phase": "repo_suite",
                    "test_command_started": True,
                    "verdict_source": "junit+exit",
                    "tests_passed": 1,
                    "tests_total": 1,
                },
            )

    monkeypatch.setattr(blackbox_module, "run_blackbox", lambda *a, **k: runtime)
    monkeypatch.setattr(guard_module, "RepoVerifier", RebindingRepoVerifier)

    result = guard(
        str(repo),
        _CANDIDATE,
        test_command=["python", "-c", "raise SystemExit(0)"],
        verifier_pack=str(pack),
        blackbox=True,
    )

    assert result.execution_state == "LIVE_STARTED_INCOMPLETE"
    assert result.tests_passed is None
    assert result.tests_total is None
