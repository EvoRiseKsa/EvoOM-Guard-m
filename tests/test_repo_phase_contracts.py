"""Unit and architecture contracts for pure repository phase interpretation."""

from __future__ import annotations

import ast
import inspect
import textwrap
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from evoom_guard.verifiers import (
    repo_phase_contracts,
    repo_suite,
    repo_verifier,
)
from evoom_guard.verifiers.junit_oracle import JUnitCounts
from evoom_guard.verifiers.repo_phase_contracts import (
    CompletedRunEvidence,
    evaluate_pack_phase,
)


def test_phase_contract_module_has_no_effectful_stdlib_imports() -> None:
    source = Path(repo_phase_contracts.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_roots = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_roots.update(
        node.module.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    )

    assert imported_roots.isdisjoint(
        {"os", "pathlib", "shutil", "subprocess", "tempfile", "threading"}
    )


def test_pack_with_tests_but_no_clean_exit_pair_has_no_verdict() -> None:
    result = evaluate_pack_phase(
        CompletedRunEvidence(
            returncode=2,
            junit=JUnitCounts(passed=1, total=1, failures=0, errors=0),
            report_expected=True,
            stdout="pack:usage-error",
            stderr="pack:stderr",
            junit_text="<testsuite/>",
            junit_sha256="a" * 64,
            junit_digest_format="JUNIT_XML_SHA256",
        )
    )

    assert result.passed is False
    assert result.score == 0.0
    assert result.verdict_source is None
    assert result.outcome == "pack_no_verdict"
    assert result.output_suffix.startswith(
        "\nverifier pack produced no clean pass/fail verdict"
    )


def test_phase_results_are_immutable() -> None:
    result = evaluate_pack_phase(
        CompletedRunEvidence(
            returncode=0,
            junit=JUnitCounts(passed=1, total=1, failures=0, errors=0),
            report_expected=True,
            stdout="",
            stderr="",
            junit_text="<testsuite/>",
            junit_sha256="b" * 64,
            junit_digest_format="JUNIT_XML_SHA256",
        )
    )

    with pytest.raises(FrozenInstanceError):
        result.passed = False  # type: ignore[misc]


def test_repo_verifier_forwards_strict_harness_to_phase_contract() -> None:
    verifier_tree = ast.parse(
        textwrap.dedent(inspect.getsource(repo_verifier.RepoVerifier._verify))
    )
    request_calls = [
        node
        for node in ast.walk(verifier_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "RepoSuiteInterpretationRequest"
    ]
    assert len(request_calls) == 1
    keywords = {
        keyword.arg: ast.unparse(keyword.value)
        for keyword in request_calls[0].keywords
        if keyword.arg is not None
    }
    assert keywords["strict_harness"] == "strict_harness"

    owner_tree = ast.parse(
        textwrap.dedent(inspect.getsource(repo_suite.interpret_repo_suite))
    )
    evaluation_calls = [
        node
        for node in ast.walk(owner_tree)
        if isinstance(node, ast.Call)
        and any(
            keyword.arg == "strict_harness"
            for keyword in node.keywords
        )
    ]
    assert len(evaluation_calls) == 1
    owner_keywords = {
        keyword.arg: ast.unparse(keyword.value)
        for keyword in evaluation_calls[0].keywords
        if keyword.arg is not None
    }
    assert owner_keywords["strict_harness"] == "request.strict_harness"
