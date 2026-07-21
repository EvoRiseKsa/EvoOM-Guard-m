"""Frozen observable contract for repository/pack result composition."""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from evoom_guard.verifiers import repo_verifier
from evoom_guard.verifiers.repo_verifier import RepoVerifier

_PASS_XML = (
    '<testsuite tests="1" failures="0" errors="0" skipped="0">'
    '<testcase name="pass"/></testsuite>'
)
_FAIL_XML = (
    '<testsuite tests="2" failures="1" errors="0" skipped="0">'
    '<testcase name="pass"/><testcase name="fail">'
    '<failure message="deterministic"/></testcase></testsuite>'
)
_ZERO_XML = '<testsuite tests="0" failures="0" errors="0" skipped="0"/>'


@dataclass(frozen=True, slots=True)
class _RunSpec:
    returncode: int
    xml: str | None
    stdout: str
    stderr: str
    report_set: bool = False


@dataclass(frozen=True, slots=True)
class _Case:
    repo: _RunSpec
    pack: _RunSpec
    test_command: tuple[str, ...] = (sys.executable, "-m", "pytest")


_CASES = {
    "repo_pass_pack_pass_v2": _Case(
        _RunSpec(0, _PASS_XML, "repo:pass", "repo:stderr"),
        _RunSpec(0, _PASS_XML, "pack:pass", "pack:stderr"),
    ),
    "repo_fail_pack_pass_v2": _Case(
        _RunSpec(1, _FAIL_XML, "repo:fail", "repo:stderr"),
        _RunSpec(0, _PASS_XML, "pack:pass", "pack:stderr"),
    ),
    "repo_pass_pack_fail_v2": _Case(
        _RunSpec(0, _PASS_XML, "repo:pass", "repo:stderr"),
        _RunSpec(1, _FAIL_XML, "pack:fail", "pack:stderr"),
    ),
    "repo_fail_pack_fail_v2": _Case(
        _RunSpec(1, _FAIL_XML, "repo:fail", "repo:stderr"),
        _RunSpec(1, _FAIL_XML, "pack:fail", "pack:stderr"),
    ),
    "repo_missing_verdict_pack_pass": _Case(
        _RunSpec(0, None, "repo:missing", "repo:stderr"),
        _RunSpec(0, _PASS_XML, "pack:pass", "pack:stderr"),
    ),
    "repo_exit_junit_tamper": _Case(
        _RunSpec(0, _FAIL_XML, "repo:tamper", "repo:stderr"),
        _RunSpec(0, _PASS_XML, "pack:pass", "pack:stderr"),
    ),
    "pack_zero_tests_v2": _Case(
        _RunSpec(0, _PASS_XML, "repo:pass", "repo:stderr"),
        _RunSpec(0, _ZERO_XML, "pack:zero", "pack:stderr"),
    ),
    "pack_missing_verdict": _Case(
        _RunSpec(0, _PASS_XML, "repo:pass", "repo:stderr"),
        _RunSpec(0, None, "pack:missing", "pack:stderr"),
    ),
    "pack_exit_junit_tamper": _Case(
        _RunSpec(0, _PASS_XML, "repo:pass", "repo:stderr"),
        _RunSpec(0, _FAIL_XML, "pack:tamper", "pack:stderr"),
    ),
    "exit_repo_pack_pass_v1": _Case(
        _RunSpec(0, None, "repo:exit", "repo:stderr"),
        _RunSpec(0, _PASS_XML, "pack:pass", "pack:stderr"),
        test_command=(sys.executable, "-c", "raise SystemExit(0)"),
    ),
    "report_set_repo_pack_pass_v2": _Case(
        _RunSpec(0, _PASS_XML, "repo:maven", "repo:stderr", report_set=True),
        _RunSpec(0, _PASS_XML, "pack:pass", "pack:stderr"),
        test_command=("mvn", "test"),
    ),
}


_PHASE_FIELDS = (
    "returncode",
    "tests_passed",
    "tests_total",
    "verdict_source",
    "outcome",
    "tamper",
    "junit_sha256",
    "junit_digest_format",
    "verifier_pack_tests_passed",
    "verifier_pack_tests_total",
    "verifier_pack_junit_sha256",
    "verifier_pack_junit_digest_format",
    "repo_suite_passed",
    "repo_suite_tests_passed",
    "repo_suite_tests_total",
    "repo_suite_verdict_source",
    "repo_suite_returncode",
    "repo_suite_junit_sha256",
    "repo_suite_junit_digest_format",
    "execution_phase",
    "execution_state",
)


def _report_path(command: list[str]) -> tuple[Path | None, bool]:
    for token in command:
        if token.startswith("--junitxml="):
            return Path(token.split("=", 1)[1]), False
        if token.startswith("-Dsurefire.reportsDirectory="):
            return Path(token.split("=", 1)[1]), True
    return None, False


def _capture(
    case: _Case,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, object]:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "test_contract.py").write_text(
        "def test_contract():\n    assert True\n", encoding="utf-8"
    )
    specs = [case.repo, case.pack]
    calls = 0

    def fake_run(
        command: list[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        spec = specs[calls]
        calls += 1
        report, directory_report = _report_path(command)
        if report is not None:
            assert directory_report is spec.report_set
        if spec.xml is not None and report is not None:
            if directory_report:
                report.mkdir(parents=True)
                (report / "TEST-contract.xml").write_text(
                    spec.xml, encoding="utf-8"
                )
            else:
                report.parent.mkdir(parents=True, exist_ok=True)
                report.write_text(spec.xml, encoding="utf-8")
        return subprocess.CompletedProcess(
            command,
            spec.returncode,
            spec.stdout,
            spec.stderr,
        )

    monkeypatch.setattr(repo_verifier, "_run_bounded_subprocess", fake_run)
    result = RepoVerifier(
        test_command=list(case.test_command),
        mem_limit_mb=0,
    ).verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n",
        {"repo_path": str(repo), "verifier_pack": str(pack)},
    )
    assert calls == 2
    return {
        "passed": result.passed,
        "score": result.score,
        "diagnostics": result.diagnostics,
        "artifact": {field: result.artifact.get(field) for field in _PHASE_FIELDS},
    }


_VECTOR = (
    Path(__file__).parent
    / "fixtures"
    / "refactor-safety"
    / "repo-phase-composition-v1.json"
)


def _expected() -> dict[str, dict[str, object]]:
    return json.loads(_VECTOR.read_text(encoding="utf-8"))


def test_repo_phase_vector_case_names_are_exact() -> None:
    assert set(_expected()) == set(_CASES)


@pytest.mark.parametrize("case_name", tuple(_CASES))
def test_repo_phase_composition_is_frozen(
    case_name: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _capture(_CASES[case_name], tmp_path, monkeypatch) == _expected()[case_name]
