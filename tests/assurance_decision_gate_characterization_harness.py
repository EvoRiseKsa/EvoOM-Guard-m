"""Deterministic characterization of Guard's final assurance decision gate.

The harness drives both repository-native and black-box orchestration with
in-memory verifier results.  It freezes the intentionally different timing of
the two historical paths without launching candidate or judge processes.
"""

from __future__ import annotations

import copy
import importlib
import json
from collections.abc import Iterator, Mapping, MutableMapping
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from evoom_guard.blackbox import BlackboxResult
from evoom_guard.contracts import VerdictResult
from evoom_guard.guard import guard

guard_module = importlib.import_module("evoom_guard.guard")
blackbox_module = importlib.import_module("evoom_guard.blackbox")

SCHEMA_VERSION = "assurance-decision-gate-characterization-v1"
NORMALIZED_FIELDS = (
    "profile_calls[].positional verifier-pack path -> <VERIFIER_PACK>",
)

CANDIDATE = """\
<<<FILE: app.py>>>
VALUE = 2
<<<END FILE>>>
"""
PROTECTED_CANDIDATE = """\
<<<FILE: tests/test_app.py>>>
def test_app():
    assert False
<<<END FILE>>>
"""
TEST_COMMAND = ["python", "-c", "raise SystemExit(0)"]

# Alphabetical order is deliberate: canonical JSON sorts mapping keys.
CASE_NAMES = (
    "blackbox_attestation_exception_after_shortfall",
    "blackbox_completed_fail_eager_preserves_prior",
    "blackbox_completed_pass_empty_shortfall",
    "blackbox_completed_pass_none",
    "blackbox_composite_external_floor",
    "blackbox_incomplete_error_eager_preserves_prior",
    "blackbox_not_started_error_eager_preserves_prior",
    "blackbox_only_external_floor",
    "blackbox_profile_exception_precedes_shortfall_attestation",
    "blackbox_shortfall_exception_precedes_attestation",
    "repo_attestation_exception_precedes_profile",
    "repo_completed_fail_preserves_prior_without_shortfall",
    "repo_completed_pass_empty_shortfall",
    "repo_completed_pass_none",
    "repo_incomplete_error_skips_shortfall",
    "repo_profile_exception_after_attestation",
    "repo_shortfall_exception_after_attestation_profile",
    "repo_static_rejection_skips_runtime_gate",
)


class ProbeError(RuntimeError):
    """Deterministic observer failure used to freeze exception ordering."""


class TracedAssurance(MutableMapping[str, Any]):
    """Mapping that records gate/shortfall reads without observer side effects."""

    def __init__(self, values: Mapping[str, Any], trace: list[str]) -> None:
        self._values = copy.deepcopy(dict(values))
        self._trace = trace

    def __getitem__(self, key: str) -> Any:
        self._trace.append(f"getitem:{key}")
        return self._values[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self._trace.append(f"setitem:{key}")
        self._values[key] = value

    def __delitem__(self, key: str) -> None:
        self._trace.append(f"delitem:{key}")
        del self._values[key]

    def __iter__(self) -> Iterator[str]:
        self._trace.append("iter")
        return iter(self._values)

    def __len__(self) -> int:
        self._trace.append("len")
        return len(self._values)

    def get(self, key: str, default: Any = None) -> Any:
        self._trace.append(f"get:{key}")
        return self._values.get(key, default)

    def snapshot(self) -> dict[str, Any]:
        """Copy values without adding characterization reads."""

        return copy.deepcopy(self._values)


def _case_spec(case_name: str) -> dict[str, Any]:
    specs: dict[str, dict[str, Any]] = {
        "blackbox_attestation_exception_after_shortfall": {
            "mode": "blackbox",
            "runtime": "completed_pass",
            "shortfall": None,
            "attestation": "raise",
        },
        "blackbox_completed_fail_eager_preserves_prior": {
            "mode": "blackbox",
            "runtime": "completed_fail",
            "shortfall": "synthetic assurance shortfall",
        },
        "blackbox_completed_pass_empty_shortfall": {
            "mode": "blackbox",
            "runtime": "completed_pass",
            "shortfall": "",
        },
        "blackbox_completed_pass_none": {
            "mode": "blackbox",
            "runtime": "completed_pass",
            "shortfall": None,
        },
        "blackbox_composite_external_floor": {
            "mode": "blackbox",
            "runtime": "completed_pass",
            "blackbox_only": False,
            "shortfall": "real",
            "require_report_integrity": "external_process_isolated",
        },
        "blackbox_incomplete_error_eager_preserves_prior": {
            "mode": "blackbox",
            "runtime": "incomplete_error",
            "shortfall": "synthetic assurance shortfall",
        },
        "blackbox_not_started_error_eager_preserves_prior": {
            "mode": "blackbox",
            "runtime": "not_started_error",
            "shortfall": "synthetic assurance shortfall",
        },
        "blackbox_only_external_floor": {
            "mode": "blackbox",
            "runtime": "completed_pass",
            "blackbox_only": True,
            "shortfall": "real",
            "require_report_integrity": "external_process_isolated",
        },
        "blackbox_profile_exception_precedes_shortfall_attestation": {
            "mode": "blackbox",
            "runtime": "completed_pass",
            "profile": "raise",
            "shortfall": None,
        },
        "blackbox_shortfall_exception_precedes_attestation": {
            "mode": "blackbox",
            "runtime": "completed_pass",
            "shortfall": "raise",
        },
        "repo_attestation_exception_precedes_profile": {
            "mode": "repo",
            "runtime": "completed_pass",
            "shortfall": None,
            "attestation": "raise",
        },
        "repo_completed_fail_preserves_prior_without_shortfall": {
            "mode": "repo",
            "runtime": "completed_fail",
            "shortfall": "raise",
        },
        "repo_completed_pass_empty_shortfall": {
            "mode": "repo",
            "runtime": "completed_pass",
            "shortfall": "",
        },
        "repo_completed_pass_none": {
            "mode": "repo",
            "runtime": "completed_pass",
            "shortfall": None,
        },
        "repo_incomplete_error_skips_shortfall": {
            "mode": "repo",
            "runtime": "incomplete_error",
            "shortfall": "raise",
        },
        "repo_profile_exception_after_attestation": {
            "mode": "repo",
            "runtime": "completed_pass",
            "profile": "raise",
            "shortfall": None,
        },
        "repo_shortfall_exception_after_attestation_profile": {
            "mode": "repo",
            "runtime": "completed_pass",
            "shortfall": "raise",
        },
        "repo_static_rejection_skips_runtime_gate": {
            "mode": "repo",
            "runtime": "static_rejected",
            "shortfall": "raise",
            "require_report_integrity": "external_process_isolated",
        },
    }
    if case_name not in specs:
        raise ValueError(f"unknown assurance decision gate case: {case_name}")
    spec = copy.deepcopy(specs[case_name])
    spec.setdefault("blackbox_only", spec["mode"] == "blackbox")
    spec.setdefault("profile", "normal")
    spec.setdefault("attestation", "normal")
    spec.setdefault("require_report_integrity", None)
    spec.setdefault("require_candidate_isolation", None)
    return spec


def _write_inputs(root: Path) -> tuple[Path, Path]:
    repo = root / "repo"
    pack = root / "pack"
    (repo / "tests").mkdir(parents=True)
    pack.mkdir(parents=True)
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


def _completed_repo_result(*, passed: bool) -> VerdictResult:
    return VerdictResult(
        passed=passed,
        score=1.0 if passed else 0.5,
        diagnostics="" if passed else "synthetic repo test failure",
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
            "junit_digest_format": "JUNIT_XML_SHA256",
            "repo_suite_started": True,
            "repo_suite_completed": True,
            "repo_suite_state": "repo_phase_completed",
            "repo_suite_passed": passed,
            "setup_isolation": None,
            "runtime_continuity": "continuous",
        },
    )


def _incomplete_repo_result() -> VerdictResult:
    return VerdictResult(
        passed=False,
        score=0.5,
        diagnostics="synthetic setup failure",
        artifact={
            "outcome": "setup_failed",
            "execution_state": "started_incomplete",
            "execution_phase": "setup",
            "test_command_started": False,
            "test_command_completed": False,
            "delivered_isolation": "not_run",
            "verdict_source": None,
            "setup_isolation": "subprocess",
            "runtime_continuity": "not_established",
        },
    )


def _repo_result(runtime: str) -> VerdictResult:
    if runtime == "completed_pass":
        return _completed_repo_result(passed=True)
    if runtime == "completed_fail":
        return _completed_repo_result(passed=False)
    if runtime == "incomplete_error":
        return _incomplete_repo_result()
    raise ValueError(f"runtime has no repository result: {runtime}")


def _blackbox_result(runtime: str) -> BlackboxResult:
    if runtime in {"completed_pass", "completed_fail"}:
        passed = runtime == "completed_pass"
        return BlackboxResult(
            passed=passed,
            tests_passed=1 if passed else 0,
            tests_total=1,
            diagnostics="" if passed else "synthetic black-box test failure",
            ran=True,
            error=None,
            pack_sha256="a" * 64,
            pack_manifest={"id": "synthetic-pack", "version": "1.0.0"},
            junit_sha256="c" * 64,
            isolation={
                "requested": "subprocess",
                "delivered": "subprocess",
                "candidate_invocations": 1,
                "candidate_launcher_invocation_observed": True,
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
    if runtime == "incomplete_error":
        return BlackboxResult(
            passed=False,
            tests_passed=0,
            tests_total=0,
            diagnostics="synthetic black-box timeout",
            ran=False,
            error="timeout",
            pack_sha256="a" * 64,
            isolation={
                "requested": "subprocess",
                "delivered": "subprocess",
                "candidate_invocations": 1,
                "candidate_launcher_invocation_observed": True,
            },
            started=True,
            completed=False,
            execution_state="started_incomplete",
            execution_phase="blackbox_pack",
            pack_present=True,
            candidate_invocations=1,
            candidate_launcher_invocation_observed=True,
        )
    if runtime == "not_started_error":
        return BlackboxResult(
            passed=False,
            tests_passed=0,
            tests_total=0,
            diagnostics="synthetic verifier pack invalid",
            ran=False,
            error="verifier pack invalid",
            pack_sha256=None,
            isolation=None,
            started=False,
            completed=False,
            execution_state="not_started",
            execution_phase="preflight",
            pack_present=True,
            candidate_invocations=0,
            candidate_launcher_invocation_observed=False,
        )
    raise ValueError(f"runtime has no black-box result: {runtime}")


def _json_safe(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def capture_case(case_name: str, workspace: Path) -> dict[str, Any]:
    """Capture one path's decision, call order, identity, and mapping reads."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown assurance decision gate case: {case_name}")
    spec = _case_spec(case_name)
    repo, pack = _write_inputs(workspace / case_name)

    timeline: list[str] = []
    profile_calls: list[dict[str, Any]] = []
    shortfall_calls: list[dict[str, Any]] = []
    attestation_calls: list[dict[str, Any]] = []
    assurance_access_trace: list[str] = []
    verifier_calls: list[str] = []
    profile_source: TracedAssurance | None = None
    attestation_source: dict[str, Any] | None = None

    class FakeRepoVerifier:
        def __init__(self, **_kwargs: Any) -> None:
            verifier_calls.append("init")
            timeline.append("verifier:init")

        def verify(
            self,
            _hypothesis: str,
            _problem: Mapping[str, Any],
        ) -> VerdictResult:
            verifier_calls.append("verify")
            timeline.append("verifier:verify")
            return copy.deepcopy(_repo_result(spec["runtime"]))

    def fake_blackbox(*_args: Any, **_kwargs: Any) -> BlackboxResult:
        timeline.append("blackbox:run")
        return copy.deepcopy(_blackbox_result(spec["runtime"]))

    original_profile = guard_module._assurance_profile
    original_static_profile = guard_module._static_assurance_profile
    original_shortfall = guard_module._assurance_shortfall

    def _record_profile(
        kind: str,
        payload: Mapping[str, Any],
        args: tuple[Any, ...],
        kwargs: Mapping[str, Any],
    ) -> TracedAssurance:
        nonlocal profile_source
        profile_source = TracedAssurance(payload, assurance_access_trace)
        normalized_args = tuple(
            "<VERIFIER_PACK>"
            if isinstance(value, str) and Path(value) == pack
            else value
            for value in args
        )
        profile_calls.append(
            {
                "kind": kind,
                "positional": _json_safe(normalized_args),
                "keyword_order": list(kwargs),
                "keywords": _json_safe(kwargs),
                "profile_source_created": True,
            }
        )
        return profile_source

    def traced_profile(*args: Any, **kwargs: Any) -> dict[str, Any]:
        timeline.append("profile:runtime")
        if spec["profile"] == "raise":
            raise ProbeError("synthetic profile failure")
        payload = original_profile(*args, **kwargs)
        return cast(dict[str, Any], _record_profile("runtime", payload, args, kwargs))

    def traced_static_profile(*args: Any, **kwargs: Any) -> dict[str, Any]:
        timeline.append("profile:static")
        if spec["profile"] == "raise":
            raise ProbeError("synthetic profile failure")
        payload = original_static_profile(*args, **kwargs)
        return cast(dict[str, Any], _record_profile("static", payload, args, kwargs))

    def traced_shortfall(
        assurance: dict[str, Any],
        **kwargs: Any,
    ) -> str | None:
        timeline.append("shortfall:call")
        shortfall_calls.append(
            {
                "assurance_is_profile_source": assurance is profile_source,
                "keyword_order": list(kwargs),
                "keywords": _json_safe(kwargs),
            }
        )
        configured = spec["shortfall"]
        if configured == "raise":
            raise ProbeError("synthetic shortfall failure")
        if configured == "real":
            result = original_shortfall(assurance, **kwargs)
        else:
            # Prove the exact profile mapping—not a detached copy—reaches the
            # policy callback while keeping scripted outcomes deterministic.
            assurance.get("report_integrity")
            assurance.get("candidate_isolation")
            result = cast(str | None, configured)
        shortfall_calls[-1]["returned"] = result
        return result

    def traced_attestation(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal attestation_source
        timeline.append("attestation:build")
        art = cast(Mapping[str, Any], kwargs["art"])
        attestation_calls.append(
            {
                "positional_count": len(args),
                "keyword_order": list(kwargs),
                "mode": kwargs["mode"],
                "execution_state": art.get("execution_state"),
                "execution_phase": art.get("execution_phase"),
                "test_command_started": art.get("test_command_started"),
            }
        )
        if spec["attestation"] == "raise":
            raise ProbeError("synthetic attestation failure")
        attestation_source = {
            "probe": "assurance-decision-gate",
            "mode": kwargs["mode"],
        }
        return attestation_source

    candidate = PROTECTED_CANDIDATE if spec["runtime"] == "static_rejected" else CANDIDATE
    call_kwargs: dict[str, Any] = {
        "test_command": TEST_COMMAND,
        "require_report_integrity": spec["require_report_integrity"],
        "require_candidate_isolation": spec["require_candidate_isolation"],
    }
    if spec["mode"] == "blackbox":
        call_kwargs.update(
            {
                "verifier_pack": str(pack),
                "blackbox": True,
                "blackbox_only": spec["blackbox_only"],
            }
        )

    result: Any = None
    exception: dict[str, str] | None = None
    with (
        patch.object(guard_module, "RepoVerifier", FakeRepoVerifier),
        patch.object(blackbox_module, "run_blackbox", fake_blackbox),
        patch.object(guard_module, "_assurance_profile", traced_profile),
        patch.object(guard_module, "_static_assurance_profile", traced_static_profile),
        patch.object(guard_module, "_assurance_shortfall", traced_shortfall),
        patch.object(guard_module, "_build_attestation", traced_attestation),
    ):
        try:
            result = guard(str(repo), candidate, **call_kwargs)
        except Exception as error:  # noqa: BLE001 - fail-loud order is the contract
            exception = {
                "type": type(error).__name__,
                "message": str(error),
            }

    decision: dict[str, Any] | None = None
    result_assurance_is_profile_source: bool | None = None
    result_attestation_is_source: bool | None = None
    if result is not None:
        decision = {
            "verdict": result.verdict,
            "passed": result.passed,
            "reason_code": result.reason_code,
            "reason": result.reason,
            "execution_state": result.execution_state,
            "execution_phase": result.execution_phase,
            "verdict_source": result.verdict_source,
            "isolation": result.isolation,
        }
        result_assurance_is_profile_source = result.assurance is profile_source
        result_attestation_is_source = result.attestation is attestation_source

    return {
        "inputs": {
            "mode": spec["mode"],
            "runtime": spec["runtime"],
            "blackbox_only": spec["blackbox_only"],
            "shortfall": spec["shortfall"],
            "profile": spec["profile"],
            "attestation": spec["attestation"],
            "require_report_integrity": spec["require_report_integrity"],
            "require_candidate_isolation": spec["require_candidate_isolation"],
        },
        "decision": decision,
        "exception": exception,
        "timeline": timeline,
        "verifier_calls": verifier_calls,
        "profile_calls": profile_calls,
        "profile_snapshot": (
            profile_source.snapshot() if profile_source is not None else None
        ),
        "shortfall_calls": shortfall_calls,
        "assurance_access_trace": assurance_access_trace,
        "attestation_calls": attestation_calls,
        "result_assurance_is_profile_source": result_assurance_is_profile_source,
        "result_attestation_is_source": result_attestation_is_source,
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
    raise SystemExit(
        "use tools/ci/capture_assurance_decision_gate_characterization.py"
    )
