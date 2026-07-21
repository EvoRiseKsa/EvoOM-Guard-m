"""Focused regression coverage for the opt-in strict harness profile."""

from __future__ import annotations

import ast
import inspect
import os
import sys
import textwrap
from types import SimpleNamespace

import pytest

import evoom_guard.execution.process as process_module
import evoom_guard.guard as guard_module
from evoom_guard.guard import (
    ERROR,
    PASS,
    REASON_NO_TEST_VERDICT,
    REASON_RUNTIME_CLEANUP_FAILED,
    REJECTED,
    guard,
)
from evoom_guard.verifiers import repo_phase_contracts, repo_verifier
from evoom_guard.verifiers.harness_policy import (
    is_protected_config,
    reject_unsafe_or_protected,
)


@pytest.mark.parametrize(
    "path",
    (
        "requirements.txt",
        "deps/requirements-dev.txt",
        "uv.lock",
        "Pipfile.lock",
        "go.mod",
        "Cargo.toml",
        "web/tsconfig.build.json",
        "babel.config.js",
    ),
)
def test_strict_harness_protects_execution_manifests_only_when_enabled(path: str) -> None:
    assert is_protected_config(path) is False
    assert is_protected_config(path, strict_harness=True) is True


def test_strict_harness_manifest_cannot_be_allowlisted() -> None:
    rejected = reject_unsafe_or_protected(
        ["requirements.txt"],
        ("requirements.txt",),
        allow=("requirements.txt",),
        strict_harness=True,
    )

    assert rejected is not None
    assert rejected.passed is False
    assert "configuration is forbidden" in rejected.diagnostics


def test_strict_harness_rejects_manifest_edit_before_execution(tmp_path) -> None:
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    candidate = "<<<FILE: requirements.txt>>>\nunsafe-dependency==1\n<<<END FILE>>>"

    result = guard(
        str(tmp_path),
        candidate,
        strict_harness=True,
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
    )

    assert result.verdict == REJECTED
    assert result.test_command_ran is False
    assert result.protected_violations == ["requirements.txt"]


def test_default_profile_preserves_exit_only_compatibility(tmp_path) -> None:
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    candidate = "<<<FILE: app.py>>>\nvalue = 2\n<<<END FILE>>>"

    result = guard(
        str(tmp_path),
        candidate,
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
    )

    assert result.verdict == PASS
    assert result.tests_passed == result.tests_total == 0
    assert result.attestation is not None
    assert result.attestation["effective_policy"]["strict_harness"] is False


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process-group proof")
def test_strict_harness_refuses_exit_only_zero_test_pass(tmp_path) -> None:
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    candidate = "<<<FILE: app.py>>>\nvalue = 2\n<<<END FILE>>>"

    result = guard(
        str(tmp_path),
        candidate,
        strict_harness=True,
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
    )

    assert result.verdict == ERROR
    assert result.reason_code == REASON_NO_TEST_VERDICT
    assert result.tests_passed == result.tests_total == 0
    assert result.attestation is not None
    assert result.attestation["effective_policy"]["strict_harness"] is True


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process-group proof")
def test_strict_harness_accepts_nonempty_junit_verdict(tmp_path) -> None:
    pytest.importorskip("pytest")
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_app.py").write_text(
        "def test_ok():\n    assert True\n", encoding="utf-8"
    )
    candidate = "<<<FILE: app.py>>>\nvalue = 2\n<<<END FILE>>>"

    result = guard(
        str(tmp_path),
        candidate,
        strict_harness=True,
        test_command=[sys.executable, "-m", "pytest", "-q"],
    )

    assert result.verdict == PASS, result.diagnostics
    assert result.tests_passed == result.tests_total == 1
    assert result.verdict_source == "junit+exit"


def test_strict_harness_refuses_unsupported_group_proof_before_launch(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    launches: list[list[str]] = []
    monkeypatch.setattr(
        process_module,
        "os",
        SimpleNamespace(name="nt", killpg=lambda *_args: None),
    )

    def unexpected_popen(command: list[str], **_kwargs: object) -> None:
        launches.append(command)
        raise AssertionError("strict_harness must preflight proof before Popen")

    monkeypatch.setattr(process_module.subprocess, "Popen", unexpected_popen)

    result = guard(
        str(tmp_path),
        "<<<FILE: app.py>>>\nvalue = 2\n<<<END FILE>>>",
        strict_harness=True,
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
    )

    assert result.verdict == ERROR
    assert result.reason_code == REASON_RUNTIME_CLEANUP_FAILED
    assert launches == []


def _calls_named(function: object, name: str) -> list[ast.Call]:
    tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == name
    ]


def _assert_strict_cleanup_keyword(call: ast.Call, expected: str) -> None:
    values = {
        keyword.arg: ast.unparse(keyword.value)
        for keyword in call.keywords
        if keyword.arg is not None
    }
    assert values.get("require_process_group_cleanup_proof") == expected


def test_strict_harness_zero_test_guard_cannot_be_disabled() -> None:
    """Keep the no-verdict rejection contract testable on every platform."""

    tree = ast.parse(
        textwrap.dedent(inspect.getsource(repo_phase_contracts.evaluate_repo_phase))
    )
    guards = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.If)
        and ast.unparse(node.test)
        == "strict_harness and (evidence.junit is None or evidence.junit.total <= 0)"
    ]

    assert len(guards) == 1


def test_repo_verifier_strict_harness_requires_group_proof_for_every_host_phase() -> None:
    calls = _calls_named(repo_verifier.RepoVerifier._verify, "_run_bounded_subprocess")

    # Host setup, repo suite, and verifier pack. A new host phase must make an
    # explicit strict-harness cleanup decision instead of inheriting a default.
    assert len(calls) == 3
    for call in calls:
        _assert_strict_cleanup_keyword(call, "self.strict_harness")


def test_strict_baseline_requires_group_proof_for_every_host_phase() -> None:
    calls = _calls_named(guard_module._run_baseline_suite, "_run_bounded_subprocess")

    assert len(calls) == 2
    for call in calls:
        _assert_strict_cleanup_keyword(call, "strict_harness")
