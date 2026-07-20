"""Deterministic pre-refactor characterization harness for ``RepoVerifier``.

This module intentionally lives under ``tests/``.  It captures the observable
``VerdictResult`` seam without becoming a second runtime implementation.  Only
wall-clock duration is removed; verdicts, diagnostics, digests, phase evidence,
and containment claims remain byte-for-byte comparable with the frozen vector.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

from evoom_guard.contracts import VerdictResult
from evoom_guard.verifiers.repo_verifier import RepoVerifier

SCHEMA_VERSION = "repo-verifier-characterization-v1"
NORMALIZED_FIELDS = ("artifact.elapsed",)
CASE_NAMES = (
    "no_parseable_blocks",
    "protected_test_edit",
    "unsafe_path_escape",
    "deleted_protected_test",
    "expected_pack_missing",
    "exit_only_pass",
    "strict_exit_only_rejected",
    "junit_pass",
    "junit_tamper",
)

_APP_EDIT = "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n"
_RUNNER = """\
from pathlib import Path
import sys

mode = sys.argv[1]
report_arg = next(arg for arg in sys.argv[2:] if arg.startswith("--junitxml="))
report = Path(report_arg.split("=", 1)[1])
failure = '<failure message="deterministic"/>' if mode == "tamper" else ""
report.write_text(
    '<testsuite tests="1" failures="%d" errors="0" skipped="0">'
    '<testcase name="case">%s</testcase></testsuite>' % (bool(failure), failure),
    encoding="utf-8",
)
sys.stdout.write("runner:" + mode)
raise SystemExit(0)
"""


def _write_source_repo(root: Path) -> None:
    (root / "tests").mkdir(parents=True)
    (root / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "tests" / "test_app.py").write_text(
        "from app import VALUE\n\n\ndef test_value():\n    assert VALUE == 2\n",
        encoding="utf-8",
    )
    # The token contains "pytest", so the production adapter binds the exact
    # report path.  The tiny runner writes timestamp-free JUnit for stable hashes.
    (root / "fake_pytest_runner.py").write_text(_RUNNER, encoding="utf-8")


def _normalized_result(result: VerdictResult) -> dict[str, Any]:
    artifact = copy.deepcopy(result.artifact)
    artifact.pop("elapsed", None)
    return {
        "passed": result.passed,
        "score": result.score,
        "diagnostics": result.diagnostics,
        "artifact": artifact,
    }


def capture_case(case_name: str, workspace: Path) -> dict[str, Any]:
    """Run one named case and return its canonical, time-independent result."""
    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown characterization case: {case_name}")

    source = workspace / f"source-{case_name}"
    _write_source_repo(source)
    problem: dict[str, Any] = {"name": case_name, "repo_path": str(source)}
    hypothesis = _APP_EDIT
    verifier_options: dict[str, Any] = {
        "timeout": 10,
        "mem_limit_mb": 0,
        "test_command": [sys.executable, "-c", "raise SystemExit(0)"],
    }

    if case_name == "no_parseable_blocks":
        hypothesis = "plain prose without an edit"
    elif case_name == "protected_test_edit":
        hypothesis = (
            "<<<FILE: tests/test_app.py>>>\n"
            "def test_value():\n    assert True\n"
            "<<<END FILE>>>\n"
        )
    elif case_name == "unsafe_path_escape":
        hypothesis = "<<<FILE: ../outside.py>>>\nOWNED = True\n<<<END FILE>>>\n"
    elif case_name == "deleted_protected_test":
        problem["deleted"] = ["tests/test_app.py"]
    elif case_name == "expected_pack_missing":
        problem["expect_verifier_pack_sha256"] = "a" * 64
    elif case_name == "strict_exit_only_rejected":
        verifier_options["strict_harness"] = True
    elif case_name in ("junit_pass", "junit_tamper"):
        mode = "tamper" if case_name == "junit_tamper" else "pass"
        verifier_options["test_command"] = [
            sys.executable,
            "fake_pytest_runner.py",
            mode,
        ]

    result = RepoVerifier(**verifier_options).verify(hypothesis, problem)
    return _normalized_result(result)


def capture_all(workspace: Path) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "normalization": list(NORMALIZED_FIELDS),
        "cases": {name: capture_case(name, workspace) for name in CASE_NAMES},
    }


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
