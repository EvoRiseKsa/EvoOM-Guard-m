"""Focused regression coverage for the opt-in strict harness profile."""

from __future__ import annotations

import sys

import pytest

from evoom_guard.guard import ERROR, PASS, REASON_NO_TEST_VERDICT, REJECTED, guard
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
