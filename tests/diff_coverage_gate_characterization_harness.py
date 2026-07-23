"""Deterministic pre-extraction characterization for the diff-coverage gate.

The harness exercises Guard's public repository path while replacing only the
effectful repository and coverage runners with deterministic fakes.  It
therefore freezes the current decision demotion, mapping-access order, and
priority relative to later baseline/assurance gates without spawning candidate
code.
"""

from __future__ import annotations

import copy
import importlib
import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from evoom_guard.contracts import VerdictResult
from evoom_guard.guard import guard

guard_module = importlib.import_module("evoom_guard.guard")
evidence_module = importlib.import_module("evoom_guard.evidence")

SCHEMA_VERSION = "diff-coverage-gate-characterization-v1"
NORMALIZED_FIELDS: tuple[str, ...] = ()

CANDIDATE = """\
<<<FILE: app.py>>>
VALUE = 2
<<<END FILE>>>
"""
TEST_COMMAND = ["python", "-c", "raise SystemExit(0)"]

CASE_NAMES = (
    "above_integer_floor",
    "below_exact_float_ratio",
    "below_floor_precedes_later_gates",
    "below_integer_floor",
    "equal_float_ratio",
    "equal_floor_allows_later_assurance_gate",
    "equal_floor_allows_later_baseline_gate",
    "equal_integer_floor",
    "malformed_executed_value",
    "malformed_measured_access",
    "malformed_missing_executed",
    "optional_no_floor",
    "prior_error_does_not_collect_or_access",
    "prior_fail_collects_without_access",
    "required_unmeasured",
    "total_zero",
)


class TracedCoverage(Mapping[str, Any]):
    """Mapping whose exact Guard reads are visible to the frozen vector."""

    def __init__(
        self,
        values: Mapping[str, Any],
        trace: list[str],
        *,
        raise_on_get: str | None = None,
    ) -> None:
        self._values = dict(values)
        self._trace = trace
        self._raise_on_get = raise_on_get

    def __getitem__(self, key: str) -> Any:
        self._trace.append(f"getitem:{key}")
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        self._trace.append("iter")
        return iter(self._values)

    def __len__(self) -> int:
        self._trace.append("len")
        return len(self._values)

    def get(self, key: str, default: Any = None) -> Any:
        self._trace.append(f"get:{key}")
        if key == self._raise_on_get:
            raise RuntimeError(f"synthetic get failure: {key}")
        return self._values.get(key, default)

    def snapshot(self) -> dict[str, Any]:
        """Return the source payload without adding observer reads to the trace."""

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
    measured_80 = {
        "measured": True,
        "executed": 80,
        "total": 100,
        "percent": 80.0,
        "note": "synthetic measured coverage",
    }
    specs: dict[str, dict[str, Any]] = {
        "optional_no_floor": {
            "floor": None,
            "coverage": {
                "measured": False,
                "note": "optional measurement unavailable",
            },
        },
        "required_unmeasured": {
            "floor": 80.0,
            "coverage": {
                "measured": False,
                "note": "required measurement unavailable",
            },
        },
        "below_integer_floor": {
            "floor": 80,
            "coverage": {
                "measured": True,
                "executed": 79,
                "total": 100,
                "percent": 79.0,
                "note": "synthetic measured coverage",
            },
        },
        "equal_integer_floor": {
            "floor": 80,
            "coverage": measured_80,
        },
        "above_integer_floor": {
            "floor": 80,
            "coverage": {
                "measured": True,
                "executed": 81,
                "total": 100,
                "percent": 81.0,
                "note": "synthetic measured coverage",
            },
        },
        "below_exact_float_ratio": {
            "floor": 66.66666666666667,
            "coverage": {
                "measured": True,
                "executed": 2,
                "total": 3,
                "percent": 66.7,
                "note": "rounded display must not control the floor",
            },
        },
        "equal_float_ratio": {
            "floor": 12.5,
            "coverage": {
                "measured": True,
                "executed": 1,
                "total": 8,
                "percent": 12.5,
                "note": "exact binary float ratio",
            },
        },
        "total_zero": {
            "floor": 100,
            "coverage": {
                "measured": True,
                "executed": 0,
                "total": 0,
                "percent": 100.0,
                "note": "no changed executable lines",
            },
        },
        "prior_fail_collects_without_access": {
            "initial": "FAIL",
            "floor": 100,
            "coverage": {
                "measured": True,
                "executed": "must-not-be-read",
                "total": "must-not-be-read",
                "percent": "must-not-be-read",
            },
        },
        "prior_error_does_not_collect_or_access": {
            "initial": "ERROR",
            "floor": 100,
            "coverage": {
                "measured": True,
                "executed": "must-not-be-read",
                "total": "must-not-be-read",
                "percent": "must-not-be-read",
            },
        },
        "malformed_missing_executed": {
            "floor": 80,
            "coverage": {
                "measured": True,
                "total": 1,
                "percent": 0.0,
            },
        },
        "malformed_executed_value": {
            "floor": 80,
            "coverage": {
                "measured": True,
                "executed": "not-an-integer",
                "total": 1,
                "percent": 0.0,
            },
        },
        "malformed_measured_access": {
            "floor": 80,
            "coverage": measured_80,
            "raise_on_get": "measured",
        },
        "below_floor_precedes_later_gates": {
            "floor": 100,
            "coverage": {
                "measured": True,
                "executed": 0,
                "total": 1,
                "percent": 0.0,
                "note": "synthetic measured coverage",
            },
            "baseline": "PASS",
            "require_demonstrated_fix": True,
            "require_report_integrity": "external_process_isolated",
        },
        "equal_floor_allows_later_baseline_gate": {
            "floor": 100,
            "coverage": {
                "measured": True,
                "executed": 1,
                "total": 1,
                "percent": 100.0,
                "note": "synthetic measured coverage",
            },
            "baseline": "PASS",
            "require_demonstrated_fix": True,
        },
        "equal_floor_allows_later_assurance_gate": {
            "floor": 100,
            "coverage": {
                "measured": True,
                "executed": 1,
                "total": 1,
                "percent": 100.0,
                "note": "synthetic measured coverage",
            },
            "require_report_integrity": "external_process_isolated",
        },
    }
    if case_name not in specs:
        raise ValueError(f"unknown diff-coverage characterization case: {case_name}")
    spec = copy.deepcopy(specs[case_name])
    spec.setdefault("initial", "PASS")
    spec.setdefault("raise_on_get", None)
    spec.setdefault("baseline", None)
    spec.setdefault("require_demonstrated_fix", False)
    spec.setdefault("require_report_integrity", None)
    return spec


def _write_repo(root: Path) -> None:
    root.mkdir(parents=True)
    (root / "app.py").write_text("VALUE = 1\n", encoding="utf-8")


def _json_safe(value: Any) -> Any:
    """Normalize recorded call arguments to JSON's owned value vocabulary."""

    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def capture_case(case_name: str, workspace: Path) -> dict[str, Any]:
    """Capture one decision outcome, access trace, and exception contract."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown diff-coverage characterization case: {case_name}")
    spec = _case_spec(case_name)
    repo = workspace / case_name
    _write_repo(repo)

    trace: list[str] = []
    collector_calls: list[dict[str, Any]] = []
    baseline_calls = 0
    assurance_shortfall_calls = 0
    coverage = TracedCoverage(
        spec["coverage"],
        trace,
        raise_on_get=spec["raise_on_get"],
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
            return copy.deepcopy(verifier_result)

    def fake_collect(*args: Any, **kwargs: Any) -> Mapping[str, Any]:
        collector_calls.append(
            {
                "positional_count": len(args),
                "repo_argument_is_case_root": (
                    len(args) >= 1 and Path(args[0]).resolve() == repo.resolve()
                ),
                "candidate_argument_matches": len(args) >= 2 and args[1] == CANDIDATE,
                "keyword_order": list(kwargs),
                "keywords": _json_safe(kwargs),
            }
        )
        return coverage

    def fake_baseline(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        nonlocal baseline_calls
        baseline_calls += 1
        return {
            "verdict": spec["baseline"],
            "tests_passed": 1,
            "tests_total": 1,
        }

    original_assurance_shortfall = guard_module._assurance_shortfall

    def traced_assurance_shortfall(*args: Any, **kwargs: Any) -> str | None:
        nonlocal assurance_shortfall_calls
        assurance_shortfall_calls += 1
        return cast(str | None, original_assurance_shortfall(*args, **kwargs))

    call_kwargs: dict[str, Any] = {
        "test_command": TEST_COMMAND,
        "diff_coverage": True,
        "min_diff_coverage": spec["floor"],
        "baseline_evidence": spec["baseline"] is not None,
        "require_demonstrated_fix": spec["require_demonstrated_fix"],
        "require_report_integrity": spec["require_report_integrity"],
    }

    decision: dict[str, Any] | None = None
    exception: dict[str, str] | None = None
    baseline_result: dict[str, Any] | None = None
    result_coverage_is_source: bool | None = None
    with (
        patch.object(guard_module, "RepoVerifier", FakeRepoVerifier),
        patch.object(evidence_module, "collect_diff_coverage", fake_collect),
        patch.object(guard_module, "_run_baseline_suite", fake_baseline),
        patch.object(
            guard_module,
            "_assurance_shortfall",
            traced_assurance_shortfall,
        ),
    ):
        try:
            result = guard(str(repo), CANDIDATE, **call_kwargs)
        except Exception as error:  # noqa: BLE001 - exception behavior is the contract
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
            baseline_result = copy.deepcopy(result.baseline)
            result_coverage_is_source = cast(object, result.diff_coverage) is coverage

    return {
        "inputs": {
            "initial_verdict": spec["initial"],
            "min_diff_coverage": spec["floor"],
            "coverage": coverage.snapshot(),
            "require_demonstrated_fix": spec["require_demonstrated_fix"],
            "require_report_integrity": spec["require_report_integrity"],
        },
        "decision": decision,
        "exception": exception,
        "coverage_access_trace": trace,
        "collector_calls": collector_calls,
        "result_coverage_is_source": result_coverage_is_source,
        "baseline_calls": baseline_calls,
        "baseline": baseline_result,
        "assurance_shortfall_calls": assurance_shortfall_calls,
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
    raise SystemExit("use tools/ci/capture_diff_coverage_gate_characterization.py")
