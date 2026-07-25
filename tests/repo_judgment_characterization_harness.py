"""Public-Guard characterization for repo-native pre-finalization judgment.

The harness replaces execution and finalization effects but enters through
``guard()``.  It freezes the exact seam between candidate preflight and the
already-extracted repo finalizer before that judgment stage gains an owner.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, cast

from evoom_guard import guard as guard_module
from evoom_guard.domain.decision import GuardDecision
from evoom_guard.domain.verdict import (
    EXECUTION_COMPLETED,
    FAIL,
    PASS,
    REJECTED,
)

SCHEMA_VERSION = "repo-judgment-characterization-v1"
CASE_NAMES = (
    "artifact_empty_fallback",
    "artifact_identity_preserved",
    "artifact_none_fallback",
    "diagnostics_none_normalized",
    "evidence_projection_failure",
    "no_suite_static_facts",
    "provider_midcall_rebinding",
    "risk_deletion_added",
    "risk_existing_deletion_not_read",
    "risk_read_failure",
    "verifier_failed_result",
    "verifier_failure",
)


def canonical_json(value: Any) -> str:
    """Return the stable human-reviewable vector encoding."""

    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _project(value: object) -> object:
    if isinstance(value, dict):
        return {
            str(key): _project(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_project(item) for item in value]
    if value is None or isinstance(value, (bool, float, int, str)):
        return value
    return f"<{type(value).__name__}>"


def capture_case(case_name: str) -> dict[str, object]:
    """Capture one reviewed judgment path through the public Guard facade."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown repo-judgment case: {case_name}")

    events: list[dict[str, object]] = []
    exception: dict[str, str] | None = None
    result_projection: dict[str, object] | None = None

    candidate = "<<<FILE:src/app.py>>>\nVALUE = 2\n<<<END FILE>>>\n"
    file_blocks = {"src/app.py": "VALUE = 2\n"}
    deleted = ("src/deleted.py",)
    effective_policy = {"policy_id": "org/strict", "timeout": 17}
    artifact: dict[str, object] | None
    if case_name == "artifact_none_fallback":
        artifact = None
    elif case_name == "artifact_empty_fallback":
        artifact = {}
    else:
        artifact = {
            "execution_state": "completed",
            "execution_phase": "verifier_pack",
            "test_command_started": True,
            "tests_passed": 3,
            "tests_total": 4,
        }

    class FakeVerdict:
        def __init__(self) -> None:
            self._artifact = artifact
            self._diagnostics: str | None = (
                None
                if case_name == "diagnostics_none_normalized"
                else "controlled diagnostics"
            )
            self._passed = case_name != "verifier_failed_result"
            self._score = 1.0 if self._passed else 0.25

        @property
        def artifact(self) -> dict[str, object] | None:
            events.append({"op": "verdict-artifact"})
            return self._artifact

        @property
        def diagnostics(self) -> str | None:
            events.append({"op": "verdict-diagnostics"})
            return self._diagnostics

        @property
        def passed(self) -> bool:
            events.append({"op": "verdict-passed", "value": self._passed})
            return self._passed

        @property
        def score(self) -> float:
            events.append({"op": "verdict-score", "value": self._score})
            return self._score

    verifier_result = FakeVerdict()
    evidence = SimpleNamespace(
        tests_passed=3,
        tests_total=4,
        verdict_source="junit+exit",
    )
    risk_result = SimpleNamespace(level="medium", score=0.42)
    pipeline_token: object | None = None
    problem_seen: dict[str, object] | None = None
    expected_artifact = artifact

    changed_paths = ["src/app.py"]
    all_touched_paths = ["src/app.py", "src/deleted.py"]
    unsafe_paths: list[str] = []
    protected_violations: list[str] = []
    safe_deleted_paths = ["src/deleted.py"]
    may_execute = case_name != "no_suite_static_facts"
    if not may_execute:
        changed_paths.clear()
        all_touched_paths.clear()
        unsafe_paths.append("../escape.py")
        protected_violations.append("tests/test_gate.py")
        safe_deleted_paths.clear()

    compatibility = SimpleNamespace(
        repository_path="/repo",
        candidate_text=candidate,
        deleted_paths=deleted,
        file_blocks=file_blocks,
        base_sha="a" * 40,
        head_sha="b" * 40,
        base_tree_sha="c" * 40,
        head_tree_sha="d" * 40,
        test_command=["python", "-m", "pytest", "-q"],
        setup_command=["python", "-m", "pip", "--version"],
        trust_setup_on_host=False,
        setup_output_globs=(),
        protected=("company/**",),
        allow=(),
        allow_new_tests=False,
        timeout=17,
        mem_limit_mb=256,
        isolation="subprocess",
        docker_image=None,
        docker_network="none",
        verifier_pack_path="/trusted/pack",
        expect_verifier_pack_sha256="e" * 64,
        collect_diff_coverage=False,
        min_diff_coverage=None,
        blackbox=False,
        blackbox_only=False,
        require_report_integrity=None,
        require_candidate_isolation=None,
        policy_id="org/strict",
        policy_version="7",
        baseline_evidence=False,
        require_demonstrated_fix=False,
        strict_harness=True,
    )
    prepared = SimpleNamespace(
        effective_policy=effective_policy,
        compatibility=compatibility,
    )
    preflight = SimpleNamespace(
        changed_paths=tuple(changed_paths),
        all_touched_paths=tuple(all_touched_paths),
        unsafe_paths=tuple(unsafe_paths),
        protected_violations=tuple(protected_violations),
        safe_deleted_paths=tuple(safe_deleted_paths),
        may_execute=may_execute,
    )

    originals = {
        "VerificationPipeline": guard_module.VerificationPipeline,
        "_PROTECTED_GLOBS": guard_module._PROTECTED_GLOBS,
        "_read_repo_file": guard_module._read_repo_file,
        "_risk_map": guard_module._risk_map,
        "abspath": guard_module.os.path.abspath,
        "evaluate_candidate_preflight": guard_module.evaluate_candidate_preflight,
        "finalize_repo_verification": guard_module.finalize_repo_verification,
        "prepare_guard_request": guard_module.prepare_guard_request,
        "repo_evidence": guard_module.repo_verification_evidence_from_artifact,
        "RepoVerifier": guard_module.RepoVerifier,
        "risk_score": guard_module.risk_score,
    }

    def prepare_guard_request(request: object, *, services: object) -> object:
        del request, services
        events.append({"op": "prepare"})
        return prepared

    def evaluate_preflight(request: object, *, services: object) -> object:
        del request, services
        events.append({"op": "preflight", "may_execute": may_execute})
        return preflight

    def absolute_path(path: str) -> str:
        return "/absolute/" + path.strip("/\\")

    class FakeVerifier:
        def verify(self, received_candidate: str, problem: dict[str, object]) -> FakeVerdict:
            nonlocal problem_seen
            problem_seen = problem
            events.append(
                {
                    "op": "verify",
                    "candidate_same": received_candidate is candidate,
                    "problem": _project(problem),
                }
            )
            if case_name == "verifier_failure":
                raise RuntimeError("controlled verifier failure")
            if case_name == "provider_midcall_rebinding":
                guard_module.repo_verification_evidence_from_artifact = late_evidence
            return verifier_result

    def repo_verifier(**kwargs: object) -> FakeVerifier:
        events.append({"op": "repo-verifier", "kwargs": _project(kwargs)})
        return FakeVerifier()

    def evidence_projector(
        received_artifact: dict[str, object],
        *,
        default_isolation: str,
    ) -> object:
        events.append(
            {
                "op": "evidence",
                "artifact_same": received_artifact is expected_artifact,
                "artifact": _project(received_artifact),
                "default_isolation": default_isolation,
            }
        )
        if case_name == "evidence_projection_failure":
            raise ValueError("controlled evidence failure")
        return evidence

    def late_evidence(
        received_artifact: dict[str, object],
        *,
        default_isolation: str,
    ) -> object:
        events.append(
            {
                "op": "evidence-late",
                "artifact_same": received_artifact is expected_artifact,
                "default_isolation": default_isolation,
            }
        )
        guard_module._risk_map = late_risk_map
        return evidence

    def initial_risk_map(
        repo_path: str,
        received_candidate: str,
        received_blocks: dict[str, str] | None,
    ) -> dict[str, tuple[int, int]]:
        events.append(
            {
                "op": "risk-map",
                "repo": repo_path,
                "candidate_same": received_candidate is candidate,
                "blocks_same": received_blocks is file_blocks,
            }
        )
        if case_name in {"risk_deletion_added", "risk_read_failure"}:
            return {"src/app.py": (2, 1)}
        if case_name == "no_suite_static_facts":
            return {}
        return {"src/app.py": (2, 1), "src/deleted.py": (0, 2)}

    def late_risk_map(
        repo_path: str,
        received_candidate: str,
        received_blocks: dict[str, str] | None,
    ) -> dict[str, tuple[int, int]]:
        events.append(
            {
                "op": "risk-map-late",
                "repo": repo_path,
                "candidate_same": received_candidate is candidate,
                "blocks_same": received_blocks is file_blocks,
            }
        )
        guard_module._read_repo_file = late_reader
        return {"src/app.py": (2, 1)}

    def read_repo_file(repo_path: str, relative_path: str) -> str:
        events.append(
            {"op": "read-repo-file", "repo": repo_path, "path": relative_path}
        )
        if case_name == "risk_read_failure":
            raise OSError("controlled risk read failure")
        return "line one\nline two\nline three\n"

    def late_reader(repo_path: str, relative_path: str) -> str:
        events.append(
            {
                "op": "read-repo-file-late",
                "repo": repo_path,
                "path": relative_path,
            }
        )
        guard_module.risk_score = late_risk_score
        return "late one\nlate two\n"

    def score_risk(
        risk_map: dict[str, tuple[int, int]],
        *,
        protected: tuple[str, ...],
    ) -> object:
        events.append(
            {
                "op": "risk-score",
                "risk_map": _project(risk_map),
                "protected": list(protected),
            }
        )
        return risk_result

    def late_risk_score(
        risk_map: dict[str, tuple[int, int]],
        *,
        protected: tuple[str, ...],
    ) -> object:
        events.append(
            {
                "op": "risk-score-late",
                "risk_map": _project(risk_map),
                "protected": list(protected),
            }
        )
        verifier_result._passed = False
        verifier_result._score = 0.91
        guard_module.VerificationPipeline = LatePipeline
        return SimpleNamespace(level="high", score=0.91)

    class _PipelineMeta(type):
        def __getattribute__(cls, name: str) -> object:
            if name == "from_repo_facts":
                label = type.__getattribute__(cls, "label")
                events.append({"op": "resolve-pipeline-method", "label": label})
            return type.__getattribute__(cls, name)

    class InitialPipeline(metaclass=_PipelineMeta):
        label = "initial"

        @classmethod
        def from_repo_facts(cls, **kwargs: object) -> object:
            nonlocal pipeline_token
            events.append(
                {
                    "op": "pipeline",
                    "label": cls.label,
                    "kwargs": _project(kwargs),
                    "unsafe_same": kwargs["unsafe_paths"] is unsafe_paths,
                    "violations_same": (
                        kwargs["protected_violations"] is protected_violations
                    ),
                    "evidence_same": kwargs["evidence"] is evidence,
                }
            )
            pipeline_token = SimpleNamespace(label=cls.label, facts=kwargs)
            return pipeline_token

    class LatePipeline(InitialPipeline):
        label = "late"

    def finalize(request: object, *, services: object) -> object:
        del services
        finalization_request = cast(Any, request)
        raw_artifact = finalization_request.raw_artifact
        request_evidence = finalization_request.verification_evidence
        request_pipeline = finalization_request.pipeline
        events.append(
            {
                "op": "finalize",
                "run_suite": finalization_request.run_suite,
                "artifact_same": raw_artifact is expected_artifact,
                "artifact": _project(raw_artifact),
                "evidence_same": request_evidence is evidence,
                "pipeline_same": request_pipeline is pipeline_token,
            }
        )
        if case_name == "no_suite_static_facts":
            decision = GuardDecision(
                verdict=REJECTED,
                reason_code="controlled_static",
                reason="controlled static refusal",
            )
            test_started = False
        elif case_name == "verifier_failed_result":
            decision = GuardDecision(
                verdict=FAIL,
                reason_code="controlled_failure",
                reason="controlled verifier failure result",
            )
            test_started = True
        else:
            decision = GuardDecision(
                verdict=PASS,
                reason_code="controlled_pass",
                reason="controlled pass",
            )
            test_started = may_execute
        return SimpleNamespace(
            decision=decision,
            execution_state=EXECUTION_COMPLETED,
            execution_phase="complete",
            test_command_started=test_started,
            effective_candidate_isolation="subprocess",
            diff_coverage=None,
            baseline=None,
            attestation={"mode": "repo"},
            assurance={"candidate_isolation": "subprocess"},
        )

    guard_module.prepare_guard_request = prepare_guard_request
    guard_module.evaluate_candidate_preflight = evaluate_preflight
    guard_module.os.path.abspath = absolute_path
    guard_module.RepoVerifier = repo_verifier
    guard_module.repo_verification_evidence_from_artifact = evidence_projector
    guard_module._risk_map = initial_risk_map
    guard_module._read_repo_file = read_repo_file
    guard_module.risk_score = score_risk
    guard_module.VerificationPipeline = InitialPipeline
    guard_module.finalize_repo_verification = finalize
    guard_module._PROTECTED_GLOBS = ("tests/**", ".evoguard.json")

    try:
        try:
            result = guard_module.guard("/ignored", "ignored")
            result_projection = {
                "verdict": result.verdict,
                "passed": result.passed,
                "reason": result.reason,
                "reason_code": result.reason_code,
                "files_changed": result.files_changed,
                "protected_violations": result.protected_violations,
                "risk_level": result.risk_level,
                "risk_score": result.risk_score,
                "tests_passed": result.tests_passed,
                "tests_total": result.tests_total,
                "verdict_source": result.verdict_source,
                "diagnostics": result.diagnostics,
            }
        except Exception as exc:  # noqa: BLE001 - freeze exact propagation
            exception = {"type": type(exc).__name__, "message": str(exc)}
        return {
            "events": events,
            "exception": exception,
            "problem_seen": _project(problem_seen),
            "result": result_projection,
        }
    finally:
        guard_module.VerificationPipeline = originals["VerificationPipeline"]
        guard_module._PROTECTED_GLOBS = originals["_PROTECTED_GLOBS"]
        guard_module._read_repo_file = originals["_read_repo_file"]
        guard_module._risk_map = originals["_risk_map"]
        guard_module.os.path.abspath = originals["abspath"]
        guard_module.evaluate_candidate_preflight = originals[
            "evaluate_candidate_preflight"
        ]
        guard_module.finalize_repo_verification = originals[
            "finalize_repo_verification"
        ]
        guard_module.prepare_guard_request = originals["prepare_guard_request"]
        guard_module.repo_verification_evidence_from_artifact = originals[
            "repo_evidence"
        ]
        guard_module.RepoVerifier = originals["RepoVerifier"]
        guard_module.risk_score = originals["risk_score"]


def capture_all() -> dict[str, object]:
    """Capture the complete reviewed matrix."""

    return {
        "cases": {name: capture_case(name) for name in CASE_NAMES},
        "schema_version": SCHEMA_VERSION,
    }


if __name__ == "__main__":
    print(canonical_json(capture_all()), end="")
