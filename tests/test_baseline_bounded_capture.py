"""Baseline evidence must retain the same bounded execution boundary as a suite."""

from __future__ import annotations

import subprocess
import sys

import evoom_guard.guard as guard_module
from evoom_guard.execution import ProcessContainmentError, ProcessOutputLimitExceeded
from evoom_guard.guard import _run_baseline_suite
from evoom_guard.verifiers import repo_verifier


def _repo(tmp_path) -> str:
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    return str(tmp_path)


def test_baseline_output_limit_is_not_clean_evidence(tmp_path, monkeypatch) -> None:
    def overflow(*_args, **_kwargs):
        raise ProcessOutputLimitExceeded()

    monkeypatch.setattr(guard_module, "_run_bounded_subprocess", overflow)

    result = _run_baseline_suite(
        _repo(tmp_path),
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
        setup_command=None,
        setup_output_globs=(),
        timeout=10,
        mem_limit_mb=0,
        strict_harness=False,
    )

    assert result == {
        "verdict": "NO_CLEAN_VERDICT",
        "tests_passed": None,
        "tests_total": None,
    }


def test_baseline_containment_failure_in_setup_is_not_clean_evidence(tmp_path, monkeypatch) -> None:
    def containment_failure(*_args, **_kwargs):
        raise ProcessContainmentError("cleanup unproven")

    monkeypatch.setattr(guard_module, "_run_bounded_subprocess", containment_failure)

    result = _run_baseline_suite(
        _repo(tmp_path),
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
        setup_command=[sys.executable, "-c", "raise SystemExit(0)"],
        setup_output_globs=(),
        timeout=10,
        mem_limit_mb=0,
        strict_harness=False,
    )

    assert result == {
        "verdict": "NO_CLEAN_VERDICT",
        "tests_passed": None,
        "tests_total": None,
        "setup_fidelity": "unverified",
    }


def test_baseline_reads_junit_through_bounded_oracle(tmp_path, monkeypatch) -> None:
    observed: list[str] = []

    def completed(*_args, **_kwargs):
        return subprocess.CompletedProcess(["judge"], 0, "", "")

    def read_oracle(path: str) -> str:
        observed.append(path)
        return "<testsuite><testcase name='ok'/></testsuite>"

    monkeypatch.setattr(guard_module, "_run_bounded_subprocess", completed)
    monkeypatch.setattr(repo_verifier, "read_junit_xml", read_oracle)

    result = _run_baseline_suite(
        _repo(tmp_path),
        test_command=[sys.executable, "-m", "pytest", "-q"],
        setup_command=None,
        setup_output_globs=(),
        timeout=10,
        mem_limit_mb=0,
        strict_harness=True,
    )

    assert result == {"verdict": "PASS", "tests_passed": 1, "tests_total": 1}
    assert len(observed) == 1
    assert observed[0].endswith("judge-result.xml")
