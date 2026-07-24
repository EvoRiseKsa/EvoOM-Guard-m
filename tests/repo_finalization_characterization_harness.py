"""Deterministic characterization of Guard's repo-native finalization order.

The harness drives the public ``guard()`` path with in-memory repository,
coverage, baseline, attestation, and assurance fakes.  It freezes the effect
order, exception cut-offs, late provider lookup, evidence identity, and trusted
attestation override order before the orchestration is moved out of ``guard.py``.
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

SCHEMA_VERSION = "repo-finalization-characterization-v1"
NORMALIZED_FIELDS = (
    "provider arguments retain values but temporary paths are reduced to booleans",
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

CASE_NAMES = (
    "attestation_exception_stops_profile",
    "baseline_exception_stops_attestation",
    "core_fail_collects_without_gate_reads",
    "coverage_demotion_keeps_baseline_effect",
    "coverage_exception_stops_baseline",
    "incomplete_error_skips_optional_effects",
    "live_provider_rebinding",
    "pack_presence_inference_precedes_attestation",
    "profile_exception_follows_attestation",
    "repo_completed_pass_full_pipeline",
    "shortfall_exception_follows_profile",
    "static_rejection_uses_static_profile",
)


class ProbeError(RuntimeError):
    """Deterministic observer failure used to freeze exception boundaries."""


class TracedEvidence(MutableMapping[str, Any]):
    """Mutable mapping that records Guard reads and writes without copy noise."""

    def __init__(
        self,
        values: Mapping[str, Any],
        trace: list[str],
        label: str,
    ) -> None:
        self._values = copy.deepcopy(dict(values))
        self._trace = trace
        self._label = label

    def __getitem__(self, key: str) -> Any:
        self._trace.append(f"{self._label}:getitem:{key}")
        return self._values[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self._trace.append(f"{self._label}:setitem:{key}")
        self._values[key] = value

    def __delitem__(self, key: str) -> None:
        self._trace.append(f"{self._label}:delitem:{key}")
        del self._values[key]

    def __iter__(self) -> Iterator[str]:
        self._trace.append(f"{self._label}:iter")
        return iter(self._values)

    def __len__(self) -> int:
        self._trace.append(f"{self._label}:len")
        return len(self._values)

    def get(self, key: str, default: Any = None) -> Any:
        self._trace.append(f"{self._label}:get:{key}")
        return self._values.get(key, default)

    def snapshot(self) -> dict[str, Any]:
        """Copy values without recording observer-only accesses."""

        return copy.deepcopy(self._values)


def _completed_artifact(*, passed: bool) -> dict[str, Any]:
    return {
        "execution_state": "completed",
        "execution_phase": "repo_suite",
        "test_command_started": True,
        "test_command_completed": True,
        "delivered_isolation": "subprocess",
        "verdict_source": "junit+exit",
        "tests_passed": 2 if passed else 1,
        "tests_total": 2,
        "junit_sha256": "a" * 64,
        "junit_digest_format": "JUNIT_XML_SHA256",
        "repo_suite_started": True,
        "repo_suite_completed": True,
        "repo_suite_state": "repo_phase_completed",
        "repo_suite_passed": passed,
        "setup_isolation": None,
        "runtime_continuity": "continuous",
        "base_sha": "artifact-controlled-base",
        "head_sha": "artifact-controlled-head",
        "policy_id": "artifact-controlled-policy",
        "raw_marker": "preserved",
    }


def _verifier_result(runtime: str) -> VerdictResult:
    if runtime == "PASS":
        return VerdictResult(
            passed=True,
            score=1.0,
            diagnostics="",
            artifact=_completed_artifact(passed=True),
        )
    if runtime == "FAIL":
        return VerdictResult(
            passed=False,
            score=0.5,
            diagnostics="synthetic repo failure",
            artifact=_completed_artifact(passed=False),
        )
    if runtime == "ERROR":
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
            },
        )
    if runtime == "PACK_INVALID":
        return VerdictResult(
            passed=False,
            score=0.5,
            diagnostics="synthetic invalid pack",
            artifact={
                "outcome": "pack_invalid",
                "execution_state": "not_started",
                "execution_phase": "preflight",
                "test_command_started": False,
                "test_command_completed": False,
                "delivered_isolation": "not_run",
                "verdict_source": None,
                "verifier_pack_present": None,
            },
        )
    raise ValueError(f"unknown runtime: {runtime}")


def _case_spec(case_name: str) -> dict[str, Any]:
    common = {
        "runtime": "PASS",
        "coverage": True,
        "coverage_below": False,
        "baseline": True,
        "raise_at": None,
        "static": False,
        "live_rebinding": False,
        "verifier_pack": False,
    }
    overrides: dict[str, dict[str, Any]] = {
        "repo_completed_pass_full_pipeline": {},
        "coverage_demotion_keeps_baseline_effect": {
            "coverage_below": True,
        },
        "core_fail_collects_without_gate_reads": {
            "runtime": "FAIL",
        },
        "incomplete_error_skips_optional_effects": {
            "runtime": "ERROR",
        },
        "coverage_exception_stops_baseline": {
            "raise_at": "coverage",
        },
        "baseline_exception_stops_attestation": {
            "raise_at": "baseline",
        },
        "attestation_exception_stops_profile": {
            "raise_at": "attestation",
        },
        "profile_exception_follows_attestation": {
            "raise_at": "profile",
        },
        "shortfall_exception_follows_profile": {
            "raise_at": "shortfall",
        },
        "live_provider_rebinding": {
            "live_rebinding": True,
        },
        "pack_presence_inference_precedes_attestation": {
            "runtime": "PACK_INVALID",
            "coverage": False,
            "baseline": False,
            "verifier_pack": True,
        },
        "static_rejection_uses_static_profile": {
            "coverage": False,
            "baseline": False,
            "static": True,
        },
    }
    if case_name not in overrides:
        raise ValueError(f"unknown repo-finalization case: {case_name}")
    return {**common, **copy.deepcopy(overrides[case_name])}


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


def _json_safe(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def capture_case(case_name: str, workspace: Path) -> dict[str, Any]:
    """Capture one public Guard path with deterministic effect providers."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown repo-finalization case: {case_name}")
    spec = _case_spec(case_name)
    repo, pack = _write_inputs(workspace / case_name)
    timeline: list[str] = []
    access_trace: list[str] = []
    provider_calls: list[dict[str, Any]] = []
    pack_isdir_calls: list[bool] = []

    coverage = TracedEvidence(
        {
            "measured": True,
            "executed": 0 if spec["coverage_below"] else 1,
            "total": 1,
            "percent": 0.0 if spec["coverage_below"] else 100.0,
            "note": "synthetic coverage",
        },
        access_trace,
        "coverage",
    )
    baseline = TracedEvidence(
        {
            "verdict": "FAIL",
            "tests_passed": 0,
            "tests_total": 1,
        },
        access_trace,
        "baseline",
    )
    assurance = TracedEvidence(
        {
            "execution_state": "completed",
            "execution_phase": "repo_suite",
            "report_integrity": "same_process_candidate_writable",
            "candidate_isolation": "subprocess",
        },
        access_trace,
        "assurance",
    )
    attestation_source: dict[str, Any] = {"probe": "repo-finalization"}

    class FakeRepoVerifier:
        def __init__(self, **_kwargs: Any) -> None:
            timeline.append("verifier:init")

        def verify(
            self,
            _hypothesis: str,
            _problem: Mapping[str, Any],
        ) -> VerdictResult:
            timeline.append("verifier:verify")
            return copy.deepcopy(_verifier_result(spec["runtime"]))

    def late_baseline(*_args: Any, **kwargs: Any) -> MutableMapping[str, Any]:
        timeline.append("baseline:late")
        provider_calls.append(
            {
                "provider": "baseline:late",
                "keyword_order": list(kwargs),
            }
        )
        guard_module._build_attestation = late_attestation
        return baseline

    def early_baseline(*_args: Any, **kwargs: Any) -> MutableMapping[str, Any]:
        timeline.append("baseline:early")
        if spec["raise_at"] == "baseline":
            raise ProbeError("synthetic baseline failure")
        return baseline

    def late_attestation(*_args: Any, **kwargs: Any) -> dict[str, Any]:
        timeline.append("attestation:late")
        guard_module._assurance_profile = late_profile
        return attestation_source

    def early_attestation(*_args: Any, **kwargs: Any) -> dict[str, Any]:
        timeline.append("attestation:build")
        artifacts = cast(Mapping[str, Any], kwargs["art"])
        provider_calls.append(
            {
                "provider": "attestation",
                "keyword_order": list(kwargs),
                "artifact_key_order": list(artifacts),
                "trusted_bindings": {
                    "base_sha": artifacts.get("base_sha"),
                    "head_sha": artifacts.get("head_sha"),
                    "policy_id": artifacts.get("policy_id"),
                    "execution_state": artifacts.get("execution_state"),
                    "repo_suite_passed": artifacts.get("repo_suite_passed"),
                    "raw_marker": artifacts.get("raw_marker"),
                },
            }
        )
        if spec["raise_at"] == "attestation":
            raise ProbeError("synthetic attestation failure")
        return attestation_source

    def late_profile(*_args: Any, **_kwargs: Any) -> MutableMapping[str, Any]:
        timeline.append("profile:late")
        guard_module._assurance_shortfall = late_shortfall
        return assurance

    def early_profile(*_args: Any, **kwargs: Any) -> MutableMapping[str, Any]:
        timeline.append("profile:runtime")
        provider_calls.append(
            {
                "provider": "profile:runtime",
                "keyword_order": list(kwargs),
            }
        )
        if spec["raise_at"] == "profile":
            raise ProbeError("synthetic profile failure")
        return assurance

    def static_profile(*_args: Any, **_kwargs: Any) -> MutableMapping[str, Any]:
        timeline.append("profile:static")
        return assurance

    def late_shortfall(
        supplied: Mapping[str, Any],
        **_kwargs: Any,
    ) -> None:
        timeline.append("shortfall:late")
        provider_calls.append(
            {
                "provider": "shortfall:late",
                "assurance_identity": supplied is assurance,
            }
        )
        return None

    def early_shortfall(
        supplied: Mapping[str, Any],
        **kwargs: Any,
    ) -> None:
        timeline.append("shortfall:call")
        provider_calls.append(
            {
                "provider": "shortfall",
                "assurance_identity": supplied is assurance,
                "keyword_order": list(kwargs),
            }
        )
        if spec["raise_at"] == "shortfall":
            raise ProbeError("synthetic shortfall failure")
        return None

    def fake_collect(*args: Any, **kwargs: Any) -> Mapping[str, Any]:
        timeline.append("coverage:collect")
        provider_calls.append(
            {
                "provider": "coverage",
                "positional_count": len(args),
                "repo_matches": len(args) >= 1 and Path(args[0]).resolve() == repo.resolve(),
                "candidate_matches": len(args) >= 2 and args[1] == CANDIDATE,
                "keyword_order": list(kwargs),
                "require_passing_suite": kwargs.get("require_passing_suite"),
            }
        )
        if spec["live_rebinding"]:
            guard_module._run_baseline_suite = late_baseline
        if spec["raise_at"] == "coverage":
            raise ProbeError("synthetic coverage failure")
        return coverage

    original_isdir = guard_module.os.path.isdir

    def traced_isdir(value: Any) -> bool:
        is_pack = Path(value).resolve() == pack.resolve()
        if is_pack:
            timeline.append("pack:isdir")
            pack_isdir_calls.append(True)
        return bool(original_isdir(value))

    candidate = PROTECTED_CANDIDATE if spec["static"] else CANDIDATE
    call_kwargs: dict[str, Any] = {
        "test_command": TEST_COMMAND,
        "diff_coverage": spec["coverage"],
        "min_diff_coverage": 100.0 if spec["coverage"] else None,
        "baseline_evidence": spec["baseline"],
        "base_sha": "trusted-base",
        "head_sha": "trusted-head",
        "policy_id": "trusted-policy",
    }
    if spec["verifier_pack"]:
        call_kwargs["verifier_pack"] = str(pack)

    result: Any = None
    exception: dict[str, str] | None = None
    with (
        patch.object(guard_module, "RepoVerifier", FakeRepoVerifier),
        patch.object(evidence_module, "collect_diff_coverage", fake_collect),
        patch.object(guard_module, "_run_baseline_suite", early_baseline),
        patch.object(guard_module, "_build_attestation", early_attestation),
        patch.object(guard_module, "_assurance_profile", early_profile),
        patch.object(guard_module, "_static_assurance_profile", static_profile),
        patch.object(guard_module, "_assurance_shortfall", early_shortfall),
        patch.object(guard_module.os.path, "isdir", traced_isdir),
    ):
        try:
            result = guard(str(repo), candidate, **call_kwargs)
        except Exception as error:  # noqa: BLE001 - fail-loud order is the contract
            exception = {
                "type": type(error).__name__,
                "message": str(error),
            }

    decision: dict[str, Any] | None = None
    identities: dict[str, bool] | None = None
    if result is not None:
        decision = {
            "verdict": result.verdict,
            "passed": result.passed,
            "reason_code": result.reason_code,
            "execution_state": result.execution_state,
            "execution_phase": result.execution_phase,
            "isolation": result.isolation,
            "tests_passed": result.tests_passed,
            "tests_total": result.tests_total,
            "verdict_source": result.verdict_source,
        }
        identities = {
            "coverage": result.diff_coverage is coverage if spec["coverage"] else False,
            "baseline": result.baseline is baseline if spec["baseline"] else False,
            "attestation": result.attestation is attestation_source,
            "assurance": result.assurance is assurance,
        }

    return {
        "inputs": {
            "runtime": spec["runtime"],
            "coverage": spec["coverage"],
            "coverage_below": spec["coverage_below"],
            "baseline": spec["baseline"],
            "raise_at": spec["raise_at"],
            "static": spec["static"],
            "live_rebinding": spec["live_rebinding"],
            "verifier_pack": spec["verifier_pack"],
        },
        "decision": decision,
        "exception": exception,
        "timeline": timeline,
        "access_trace": access_trace,
        "provider_calls": _json_safe(provider_calls),
        "pack_isdir_calls": pack_isdir_calls,
        "coverage_snapshot": coverage.snapshot(),
        "baseline_snapshot": baseline.snapshot(),
        "assurance_snapshot": assurance.snapshot(),
        "result_identities": identities,
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
    raise SystemExit("use tools/ci/capture_repo_finalization_characterization.py")
