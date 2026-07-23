"""Deterministic pre-extraction characterization for demonstrated-fix demotion.

The harness drives Guard's public repository path but replaces the repository,
baseline, coverage, and assurance effects with deterministic in-memory fakes.
It freezes the current repair-effect mapping reads/writes, decision priority,
fail-loud behavior, and ordering relative to the later assurance gate without
executing candidate code.
"""

from __future__ import annotations

import copy
import importlib
import json
from collections.abc import Iterator, Mapping, MutableMapping
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from evoom_guard.contracts import VerdictResult
from evoom_guard.guard import guard

guard_module = importlib.import_module("evoom_guard.guard")
evidence_module = importlib.import_module("evoom_guard.evidence")

SCHEMA_VERSION = "demonstrated-fix-gate-characterization-v1"
NORMALIZED_FIELDS: tuple[str, ...] = ()

CANDIDATE = """\
<<<FILE: app.py>>>
VALUE = 2
<<<END FILE>>>
"""
TEST_COMMAND = ["python", "-c", "raise SystemExit(0)"]

CASE_NAMES = (
    "optional_baseline_pass",
    "prior_core_fail_preserved",
    "prior_diff_coverage_fail_preserved",
    "prior_error_preserved_without_baseline",
    "required_baseline_pass",
    "required_baseline_pass_precedes_assurance",
    "required_demonstrated",
    "required_demonstrated_allows_assurance",
    "required_missing_repair_effect",
    "required_missing_verdict",
    "required_no_clean_verdict",
)


class TracedBaseline(MutableMapping[str, Any]):
    """Mutable mapping exposing every Guard access without observer reads."""

    def __init__(
        self,
        values: Mapping[str, Any],
        trace: list[str],
        timeline: list[str],
        *,
        drop_repair_effect_write: bool = False,
    ) -> None:
        self._values = dict(values)
        self._trace = trace
        self._timeline = timeline
        self._drop_repair_effect_write = drop_repair_effect_write

    def __getitem__(self, key: str) -> Any:
        event = f"getitem:{key}"
        self._trace.append(event)
        self._timeline.append(f"baseline:{event}")
        return self._values[key]

    def __setitem__(self, key: str, value: Any) -> None:
        event = f"setitem:{key}"
        self._trace.append(event)
        self._timeline.append(f"baseline:{event}")
        if key == "repair_effect" and self._drop_repair_effect_write:
            return
        self._values[key] = value

    def __delitem__(self, key: str) -> None:
        event = f"delitem:{key}"
        self._trace.append(event)
        self._timeline.append(f"baseline:{event}")
        del self._values[key]

    def __iter__(self) -> Iterator[str]:
        self._trace.append("iter")
        self._timeline.append("baseline:iter")
        return iter(self._values)

    def __len__(self) -> int:
        self._trace.append("len")
        self._timeline.append("baseline:len")
        return len(self._values)

    def get(self, key: str, default: Any = None) -> Any:
        event = f"get:{key}"
        self._trace.append(event)
        self._timeline.append(f"baseline:{event}")
        return self._values.get(key, default)

    def snapshot(self) -> dict[str, Any]:
        """Return current values without adding characterization reads."""

        return copy.deepcopy(self._values)


def _completed_artifact(*, passed: bool) -> dict[str, Any]:
    return {
        "execution_state": "completed",
        "execution_phase": "repo_suite",
        "test_command_started": True,
        "test_command_completed": True,
        "delivered_isolation": "subprocess",
        "verdict_source": "exit_code",
        "tests_passed": 1 if passed else 0,
        "tests_total": 1,
        "repo_suite_started": True,
        "repo_suite_completed": True,
        "repo_suite_state": "repo_phase_completed",
        "repo_suite_passed": passed,
    }


def _verifier_result(initial: str) -> VerdictResult:
    if initial == "PASS":
        return VerdictResult(
            passed=True,
            score=1.0,
            diagnostics="",
            artifact=_completed_artifact(passed=True),
        )
    if initial == "FAIL":
        return VerdictResult(
            passed=False,
            score=0.5,
            diagnostics="synthetic test failure",
            artifact=_completed_artifact(passed=False),
        )
    if initial == "ERROR":
        return VerdictResult(
            passed=False,
            score=0.5,
            diagnostics="synthetic setup failure",
            artifact={
                "execution_state": "started_incomplete",
                "execution_phase": "setup",
                "test_command_started": False,
                "test_command_completed": False,
                "delivered_isolation": "not_run",
                "outcome": "setup_failed",
            },
        )
    raise ValueError(f"unknown initial verdict: {initial}")


def _case_spec(case_name: str) -> dict[str, Any]:
    pass_baseline = {
        "verdict": "PASS",
        "tests_passed": 1,
        "tests_total": 1,
    }
    fail_baseline = {
        "verdict": "FAIL",
        "tests_passed": 0,
        "tests_total": 1,
    }
    specs: dict[str, dict[str, Any]] = {
        "optional_baseline_pass": {
            "baseline_evidence": True,
            "require_demonstrated_fix": False,
            "baseline": pass_baseline,
        },
        "prior_core_fail_preserved": {
            "initial": "FAIL",
            "require_demonstrated_fix": True,
            "baseline": pass_baseline,
        },
        "prior_diff_coverage_fail_preserved": {
            "require_demonstrated_fix": True,
            "baseline": pass_baseline,
            "diff_failure": True,
            "require_report_integrity": "external_process_isolated",
        },
        "prior_error_preserved_without_baseline": {
            "initial": "ERROR",
            "require_demonstrated_fix": True,
            "baseline": pass_baseline,
        },
        "required_baseline_pass": {
            "require_demonstrated_fix": True,
            "baseline": pass_baseline,
        },
        "required_baseline_pass_precedes_assurance": {
            "require_demonstrated_fix": True,
            "baseline": pass_baseline,
            "require_report_integrity": "external_process_isolated",
        },
        "required_demonstrated": {
            "require_demonstrated_fix": True,
            "baseline": fail_baseline,
        },
        "required_demonstrated_allows_assurance": {
            "require_demonstrated_fix": True,
            "baseline": fail_baseline,
            "require_report_integrity": "external_process_isolated",
        },
        "required_missing_repair_effect": {
            "require_demonstrated_fix": True,
            "baseline": pass_baseline,
            "drop_repair_effect_write": True,
        },
        "required_missing_verdict": {
            "require_demonstrated_fix": True,
            "baseline": {
                "tests_passed": None,
                "tests_total": None,
            },
        },
        "required_no_clean_verdict": {
            "require_demonstrated_fix": True,
            "baseline": {
                "verdict": "NO_CLEAN_VERDICT",
                "tests_passed": None,
                "tests_total": None,
            },
        },
    }
    if case_name not in specs:
        raise ValueError(f"unknown demonstrated-fix characterization case: {case_name}")
    spec = copy.deepcopy(specs[case_name])
    spec.setdefault("initial", "PASS")
    spec.setdefault("baseline_evidence", False)
    spec.setdefault("require_demonstrated_fix", False)
    spec.setdefault("drop_repair_effect_write", False)
    spec.setdefault("diff_failure", False)
    spec.setdefault("require_report_integrity", None)
    return spec


def _write_repo(root: Path) -> None:
    root.mkdir(parents=True)
    (root / "app.py").write_text("VALUE = 1\n", encoding="utf-8")


def _json_safe(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def capture_case(case_name: str, workspace: Path) -> dict[str, Any]:
    """Capture one demonstrated-fix outcome and its exact access order."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown demonstrated-fix characterization case: {case_name}")
    spec = _case_spec(case_name)
    repo = workspace / case_name
    _write_repo(repo)

    timeline: list[str] = []
    baseline_trace: list[str] = []
    baseline_calls: list[dict[str, Any]] = []
    assurance_profile_calls = 0
    assurance_shortfall_calls = 0
    baseline = TracedBaseline(
        spec["baseline"],
        baseline_trace,
        timeline,
        drop_repair_effect_write=spec["drop_repair_effect_write"],
    )
    verifier_result = _verifier_result(spec["initial"])

    class FakeRepoVerifier:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def verify(
            self,
            _hypothesis: str,
            _problem: Mapping[str, Any],
        ) -> VerdictResult:
            timeline.append("verifier:verify")
            return copy.deepcopy(verifier_result)

    def fake_baseline(repo_argument: str, **kwargs: Any) -> dict[str, Any]:
        timeline.append("baseline:run")
        baseline_calls.append(
            {
                "repo_argument_is_case_root": (Path(repo_argument).resolve() == repo.resolve()),
                "keyword_order": list(kwargs),
                "keywords": _json_safe(kwargs),
            }
        )
        return cast(dict[str, Any], baseline)

    def fake_collect(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        timeline.append("coverage:collect")
        return {
            "measured": True,
            "executed": 0,
            "total": 1,
            "percent": 0.0,
            "note": "synthetic below-floor coverage",
        }

    original_assurance_profile = guard_module._assurance_profile
    original_assurance_shortfall = guard_module._assurance_shortfall

    def traced_assurance_profile(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal assurance_profile_calls
        assurance_profile_calls += 1
        timeline.append("assurance:profile")
        return cast(dict[str, Any], original_assurance_profile(*args, **kwargs))

    def traced_assurance_shortfall(*args: Any, **kwargs: Any) -> str | None:
        nonlocal assurance_shortfall_calls
        assurance_shortfall_calls += 1
        timeline.append("assurance:shortfall")
        return cast(str | None, original_assurance_shortfall(*args, **kwargs))

    call_kwargs: dict[str, Any] = {
        "test_command": TEST_COMMAND,
        "baseline_evidence": spec["baseline_evidence"],
        "require_demonstrated_fix": spec["require_demonstrated_fix"],
        "diff_coverage": spec["diff_failure"],
        "min_diff_coverage": 100 if spec["diff_failure"] else None,
        "require_report_integrity": spec["require_report_integrity"],
    }

    decision: dict[str, Any] | None = None
    exception: dict[str, str] | None = None
    result_baseline_is_source: bool | None = None
    with (
        patch.object(guard_module, "RepoVerifier", FakeRepoVerifier),
        patch.object(guard_module, "_run_baseline_suite", fake_baseline),
        patch.object(evidence_module, "collect_diff_coverage", fake_collect),
        patch.object(
            guard_module,
            "_assurance_profile",
            traced_assurance_profile,
        ),
        patch.object(
            guard_module,
            "_assurance_shortfall",
            traced_assurance_shortfall,
        ),
    ):
        try:
            result = guard(str(repo), CANDIDATE, **call_kwargs)
        except Exception as error:  # noqa: BLE001 - fail-loud behavior is frozen
            exception = {
                "type": type(error).__name__,
                "message": str(error),
            }
        else:
            decision = {
                "verdict": result.verdict,
                "passed": result.passed,
                "reason_code": result.reason_code,
                "reason": result.reason,
            }
            result_baseline_is_source = cast(object, result.baseline) is baseline

    return {
        "inputs": {
            "initial_verdict": spec["initial"],
            "baseline_evidence": spec["baseline_evidence"],
            "require_demonstrated_fix": spec["require_demonstrated_fix"],
            "baseline_source": copy.deepcopy(spec["baseline"]),
            "drop_repair_effect_write": spec["drop_repair_effect_write"],
            "diff_failure": spec["diff_failure"],
            "require_report_integrity": spec["require_report_integrity"],
        },
        "decision": decision,
        "exception": exception,
        "baseline": baseline.snapshot(),
        "baseline_access_trace": baseline_trace,
        "baseline_calls": baseline_calls,
        "result_baseline_is_source": result_baseline_is_source,
        "assurance_profile_calls": assurance_profile_calls,
        "assurance_shortfall_calls": assurance_shortfall_calls,
        "timeline": timeline,
    }


def capture_all(workspace: Path) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "normalization": list(NORMALIZED_FIELDS),
        "cases": {name: capture_case(name, workspace) for name in CASE_NAMES},
    }


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    raise SystemExit("use tools/ci/capture_demonstrated_fix_gate_characterization.py")
