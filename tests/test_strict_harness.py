"""Focused regression coverage for the opt-in strict harness profile."""

from __future__ import annotations

import ast
import inspect
import os
import subprocess
import sys
import textwrap
from pathlib import Path
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
from evoom_guard.verifiers import (
    repo_pack,
    repo_phase_contracts,
    repo_setup,
    repo_suite,
    repo_verifier,
)
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
        and (
            isinstance(node.func, ast.Name)
            and node.func.id == name
            or isinstance(node.func, ast.Attribute)
            and node.func.attr == name
        )
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

    # Setup, the repository suite, and the verifier pack each cross a separate
    # typed call-through seam checked below.
    assert calls == []

    pack_tree = ast.parse(
        textwrap.dedent(inspect.getsource(repo_pack.execute_repo_pack))
    )
    pack_calls = [
        node
        for node in ast.walk(pack_tree)
        if isinstance(node, ast.Call)
        and any(
            keyword.arg == "require_process_group_cleanup_proof"
            for keyword in node.keywords
        )
    ]
    assert len(pack_calls) == 1
    _assert_strict_cleanup_keyword(
        pack_calls[0],
        "request.strict_harness",
    )

    suite_tree = ast.parse(
        textwrap.dedent(inspect.getsource(repo_suite.execute_repo_suite))
    )
    suite_calls = [
        node
        for node in ast.walk(suite_tree)
        if isinstance(node, ast.Call)
        and any(
            keyword.arg == "require_process_group_cleanup_proof"
            for keyword in node.keywords
        )
    ]
    assert len(suite_calls) == 1
    _assert_strict_cleanup_keyword(
        suite_calls[0],
        "request.strict_harness",
    )

    setup_tree = ast.parse(
        textwrap.dedent(inspect.getsource(repo_setup.execute_repo_setup))
    )
    setup_calls = [
        node
        for node in ast.walk(setup_tree)
        if isinstance(node, ast.Call)
        and any(
            keyword.arg == "require_process_group_cleanup_proof"
            for keyword in node.keywords
        )
    ]
    assert len(setup_calls) == 1
    _assert_strict_cleanup_keyword(setup_calls[0], "services.strict_harness()")

    setup_services = _calls_named(
        repo_verifier.RepoVerifier._verify,
        "RepoSetupServices",
    )
    assert len(setup_services) == 1
    service_keywords = {
        keyword.arg: keyword.value
        for keyword in setup_services[0].keywords
        if keyword.arg is not None
    }
    strict_harness_provider = service_keywords.get("strict_harness")
    assert isinstance(strict_harness_provider, ast.Lambda)
    assert not strict_harness_provider.args.args
    assert ast.dump(strict_harness_provider.body, include_attributes=False) == ast.dump(
        ast.parse("strict_harness", mode="eval").body,
        include_attributes=False,
    )


def test_problem_strict_harness_reaches_every_repo_host_phase(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The problem-level opt-in is one effective policy for setup/suite/pack."""

    source = tmp_path / "source"
    pack = tmp_path / "pack"
    source.mkdir()
    pack.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (pack / "test_contract.py").write_text(
        "def test_contract():\n    assert True\n",
        encoding="utf-8",
    )
    cleanup_requirements: list[bool] = []

    def completed_host_phase(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        cleanup_requirements.append(
            bool(kwargs["require_process_group_cleanup_proof"])
        )
        for token in command:
            if token.startswith("--junitxml="):
                report = Path(token.split("=", 1)[1])
                report.parent.mkdir(parents=True, exist_ok=True)
                report.write_text(
                    '<testsuite tests="1" failures="0" errors="0" skipped="0">'
                    '<testcase name="pass"/></testsuite>',
                    encoding="utf-8",
                )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(
        repo_verifier,
        "_run_bounded_subprocess",
        completed_host_phase,
    )

    result = repo_verifier.RepoVerifier(
        test_command=[sys.executable, "-m", "pytest"],
        mem_limit_mb=0,
    ).verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        {
            "repo_path": str(source),
            "setup_command": [sys.executable, "-c", "pass"],
            "verifier_pack": str(pack),
            "strict_harness": True,
        },
    )

    assert result.passed, result.diagnostics
    assert cleanup_requirements == [True, True, True]


def test_strict_baseline_requires_group_proof_for_every_host_phase() -> None:
    calls = _calls_named(guard_module._run_baseline_suite, "_run_bounded_subprocess")

    assert len(calls) == 2
    for call in calls:
        _assert_strict_cleanup_keyword(call, "strict_harness")
