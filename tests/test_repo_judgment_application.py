"""Architecture and identity contracts for repo-native initial judgment."""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest

import evoom_guard.application as application
from evoom_guard.application.repo_judgment import (
    RepoJudgmentInput,
    RepoJudgmentOutcome,
    RepoJudgmentServices,
    build_repo_judgment,
)


def _request(
    *,
    run_suite: bool = True,
    problem: dict[str, object] | None = None,
    all_touched_paths: list[str] | None = None,
    deleted_paths: list[str] | tuple[str, ...] | None = None,
    protected_patterns: list[str] | tuple[str, ...] | None = None,
) -> RepoJudgmentInput:
    return RepoJudgmentInput(
        run_suite=run_suite,
        repository_path="/repo",
        candidate_text="candidate",
        problem=problem if problem is not None else {"name": "guard"},
        all_touched_paths=(
            all_touched_paths
            if all_touched_paths is not None
            else ["src/app.py", "src/deleted.py"]
        ),
        unsafe_paths=[],
        protected_violations=[],
        deleted_paths=(
            deleted_paths
            if deleted_paths is not None
            else ("src/deleted.py",)
        ),
        protected_patterns=(
            protected_patterns
            if protected_patterns is not None
            else ("company/**",)
        ),
        file_blocks={"src/app.py": "VALUE = 2\n"},
        timeout=17,
        mem_limit_mb=256,
        isolation="subprocess",
        docker_image=None,
        docker_network="none",
        trust_setup_on_host=False,
        setup_output_globs=(),
        strict_harness=True,
    )


def test_repo_judgment_is_public_and_contracts_are_frozen_slotted() -> None:
    request = _request()
    verifier = object()
    artifact: dict[str, object] = {"tests_passed": 1}
    evidence = object()
    risk = object()
    pipeline = object()
    outcome: RepoJudgmentOutcome[object, object, object] = (
        RepoJudgmentOutcome(
            run_suite=True,
            verifier_result=verifier,  # type: ignore[arg-type]
            raw_artifact=artifact,
            verification_evidence=evidence,
            diagnostics="ok",
            risk=risk,
            pipeline=pipeline,
            all_touched_paths=request.all_touched_paths,
        )
    )

    assert application.build_repo_judgment is build_repo_judgment
    assert application.RepoJudgmentInput is RepoJudgmentInput
    assert application.RepoJudgmentOutcome is RepoJudgmentOutcome
    assert application.RepoJudgmentServices is RepoJudgmentServices
    assert not hasattr(request, "__dict__")
    assert not hasattr(outcome, "__dict__")
    assert outcome.raw_artifact is artifact
    assert outcome.verification_evidence is evidence
    assert outcome.risk is risk
    assert outcome.pipeline is pipeline
    assert outcome.all_touched_paths is request.all_touched_paths
    with pytest.raises(FrozenInstanceError):
        outcome.diagnostics = "changed"  # type: ignore[misc]


def test_judgment_preserves_live_lookup_order_and_object_identity() -> None:
    events: list[str] = []
    problem = {"name": "guard"}
    all_touched = ["src/app.py"]
    deleted_paths: list[str] = []
    protected_patterns = ["company/**"]
    request = _request(
        problem=problem,
        all_touched_paths=all_touched,
        deleted_paths=deleted_paths,
        protected_patterns=protected_patterns,
    )
    artifact: dict[str, object] = {"token": object()}
    evidence = object()
    risk = object()
    pipeline = object()
    risk_map: dict[str, tuple[int, int]] = {"src/app.py": (1, 0)}
    seen: dict[str, object] = {}

    class Verdict:
        @property
        def artifact(self) -> dict[str, object]:
            events.append("read-artifact")
            return artifact

        @property
        def diagnostics(self) -> str:
            events.append("read-diagnostics")
            return "controlled"

        @property
        def passed(self) -> bool:
            events.append("read-passed")
            return True

        @property
        def score(self) -> float:
            events.append("read-score")
            return 0.75

    verdict = Verdict()

    class Verifier:
        def verify(
            self,
            candidate: str,
            received_problem: dict[str, object],
        ) -> Verdict:
            events.append("verify")
            seen["candidate"] = candidate
            seen["problem"] = received_problem
            return verdict

    def verifier_factory(**kwargs: object) -> Verifier:
        events.append("construct-verifier")
        seen["verifier-kwargs"] = kwargs
        return Verifier()

    def verifier_provider() -> Any:
        events.append("resolve-verifier")
        return verifier_factory

    def evidence_projector(
        received_artifact: dict[str, object],
        *,
        default_isolation: str,
    ) -> object:
        events.append("project-evidence")
        seen["artifact"] = received_artifact
        seen["default-isolation"] = default_isolation
        return evidence

    def evidence_provider() -> Any:
        events.append("resolve-evidence")
        return evidence_projector

    def risk_map_builder(
        repository_path: str,
        candidate_text: str,
        file_blocks: dict[str, str] | None,
    ) -> dict[str, tuple[int, int]]:
        events.append("build-risk-map")
        all_touched.append("src/deleted.py")
        deleted_paths.append("src/deleted.py")
        protected_patterns.append("late/**")
        seen["risk-map-args"] = (
            repository_path,
            candidate_text,
            file_blocks,
        )
        return risk_map

    def risk_map_provider() -> Any:
        events.append("resolve-risk-map")
        return risk_map_builder

    def read_repo_file(repository_path: str, path: str) -> str:
        events.append("read-deleted-base")
        seen["reader-args"] = (repository_path, path)
        return "one\ntwo\nthree\n"

    def reader_provider() -> Any:
        events.append("resolve-reader")
        return read_repo_file

    def risk_scorer(
        received_risk_map: dict[str, tuple[int, int]],
        *,
        protected: tuple[str, ...],
    ) -> object:
        events.append("score-risk")
        seen["risk-map"] = received_risk_map
        seen["protected"] = protected
        return risk

    def risk_scorer_provider() -> Any:
        events.append("resolve-risk-scorer")
        return risk_scorer

    def protected_globs_provider() -> tuple[str, ...]:
        events.append("resolve-protected-globs")
        return ("tests/**",)

    def pipeline_builder(**facts: object) -> object:
        events.append("build-pipeline")
        seen["pipeline-facts"] = facts
        return pipeline

    class PipelineFactory:
        @property
        def from_repo_facts(self) -> Any:
            events.append("resolve-pipeline-method")
            return pipeline_builder

    pipeline_factory = PipelineFactory()

    def pipeline_provider() -> Any:
        events.append("resolve-pipeline")
        return pipeline_factory

    outcome = build_repo_judgment(
        request,
        services=RepoJudgmentServices(
            repo_verifier_provider=verifier_provider,
            evidence_projector_provider=evidence_provider,
            risk_map_provider=risk_map_provider,
            repo_file_reader_provider=reader_provider,
            risk_scorer_provider=risk_scorer_provider,
            protected_globs_provider=protected_globs_provider,
            verification_pipeline_provider=pipeline_provider,
        ),
    )

    assert events == [
        "resolve-verifier",
        "construct-verifier",
        "verify",
        "read-artifact",
        "resolve-evidence",
        "project-evidence",
        "read-diagnostics",
        "resolve-risk-map",
        "build-risk-map",
        "resolve-reader",
        "read-deleted-base",
        "resolve-risk-scorer",
        "resolve-protected-globs",
        "score-risk",
        "resolve-pipeline",
        "resolve-pipeline-method",
        "read-passed",
        "read-score",
        "build-pipeline",
    ]
    assert outcome.verifier_result is verdict
    assert outcome.raw_artifact is artifact
    assert outcome.verification_evidence is evidence
    assert outcome.risk is risk
    assert outcome.pipeline is pipeline
    assert outcome.all_touched_paths is all_touched
    assert seen["problem"] is problem
    assert seen["artifact"] is artifact
    assert seen["risk-map"] is risk_map
    assert risk_map["src/deleted.py"] == (0, 3)
    assert seen["protected"] == (
        "tests/**",
        "company/**",
        "late/**",
    )


def test_static_judgment_skips_verifier_and_evidence_providers() -> None:
    events: list[str] = []
    all_touched: list[str] = []
    pipeline = object()
    risk = object()

    def forbidden_provider() -> Any:
        raise AssertionError("static judgment resolved a runtime-only provider")

    def risk_map_provider() -> Any:
        events.append("resolve-risk-map")
        return lambda *_args: {}

    def risk_scorer_provider() -> Any:
        events.append("resolve-risk-scorer")
        return lambda _risk_map, *, protected: risk

    def protected_globs_provider() -> tuple[str, ...]:
        events.append("resolve-protected-globs")
        return ()

    def pipeline_provider() -> Any:
        events.append("resolve-pipeline")

        class Pipeline:
            @staticmethod
            def from_repo_facts(**facts: object) -> object:
                events.append("build-pipeline")
                assert facts["verifier_present"] is False
                assert facts["verifier_passed"] is None
                assert facts["verifier_score"] is None
                assert facts["evidence"] is None
                return pipeline

        return Pipeline

    outcome = build_repo_judgment(
        _request(run_suite=False, all_touched_paths=all_touched),
        services=RepoJudgmentServices(
            repo_verifier_provider=forbidden_provider,
            evidence_projector_provider=forbidden_provider,
            risk_map_provider=risk_map_provider,
            repo_file_reader_provider=forbidden_provider,
            risk_scorer_provider=risk_scorer_provider,
            protected_globs_provider=protected_globs_provider,
            verification_pipeline_provider=pipeline_provider,
        ),
    )

    assert events == [
        "resolve-risk-map",
        "resolve-risk-scorer",
        "resolve-protected-globs",
        "resolve-pipeline",
        "build-pipeline",
    ]
    assert outcome.verifier_result is None
    assert outcome.raw_artifact == {}
    assert outcome.verification_evidence is None
    assert outcome.diagnostics == ""
    assert outcome.risk is risk
    assert outcome.pipeline is pipeline
    assert outcome.all_touched_paths is all_touched


def test_owner_has_only_standard_library_imports() -> None:
    root = Path(__file__).resolve().parents[1]
    tree = ast.parse(
        (
            root
            / "evoom_guard"
            / "application"
            / "repo_judgment.py"
        ).read_text(encoding="utf-8")
    )
    imported_modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }

    assert imported_modules == {
        "__future__",
        "collections.abc",
        "dataclasses",
        "typing",
    }


def test_guard_delegates_initial_repo_judgment_before_finalization() -> None:
    root = Path(__file__).resolve().parents[1]
    tree = ast.parse(
        (root / "evoom_guard" / "guard.py").read_text(encoding="utf-8")
    )
    guard_function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "guard"
    )
    calls = [
        node
        for node in ast.walk(guard_function)
        if isinstance(node, ast.Call)
    ]
    judgment_calls = [
        node
        for node in calls
        if isinstance(node.func, ast.Name)
        and node.func.id == "build_repo_judgment"
    ]
    finalization_calls = [
        node
        for node in calls
        if isinstance(node.func, ast.Name)
        and node.func.id == "finalize_repo_verification"
    ]
    forbidden_calls = {
        "RepoVerifier",
        "repo_verification_evidence_from_artifact",
        "_risk_map",
        "_read_repo_file",
        "risk_score",
    }

    assert len(judgment_calls) == 1
    assert len(finalization_calls) == 1
    assert judgment_calls[0].lineno < finalization_calls[0].lineno
    retained_blackbox_calls = [
        node
        for node in calls
        if isinstance(node.func, ast.Name)
        and node.func.id in forbidden_calls
    ]
    assert retained_blackbox_calls
    assert all(
        node.lineno < judgment_calls[0].lineno
        for node in retained_blackbox_calls
    )


def test_owner_does_not_absorb_finalization_or_public_result() -> None:
    root = Path(__file__).resolve().parents[1]
    tree = ast.parse(
        (
            root
            / "evoom_guard"
            / "application"
            / "repo_judgment.py"
        ).read_text(encoding="utf-8")
    )
    referenced_names = {
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
    }
    defined_functions = {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    assert "finalize_repo_verification" not in referenced_names
    assert "GuardResult" not in referenced_names
    assert "run_blackbox" not in referenced_names
    assert defined_functions == {"build_repo_judgment"}
