# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available - see LICENSE for permitted use.
# Original creator: Mana Alharbi.
# -----------------------------------------------------------------------------
"""Deterministic wire characterization for Guard output publication."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from evoom_guard.guard import (
    ERROR,
    PASS,
    REJECTED,
    TAMPERED,
    GuardResult,
    render_report,
    to_sarif,
    write_json,
    write_sarif,
)

SCHEMA_VERSION = "guard-output-characterization-v1"
CASE_NAMES = (
    "incomplete_error",
    "pass_full_evidence",
    "static_rejection",
    "tampered_gvisor",
)


def canonical_json(value: object) -> str:
    """Return the stable review representation used by the frozen vector."""

    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def _pass_full_evidence() -> tuple[GuardResult, list[str], str]:
    files = [f"src/module_{index:02d}.py" for index in range(16)]
    result = GuardResult(
        verdict=PASS,
        passed=True,
        reason="the selected judge accepted the candidate",
        files_changed=files,
        protected_violations=[],
        risk_level="medium",
        risk_score=0.45678,
        tests_passed=17,
        tests_total=17,
        verdict_source="junit+exit",
        diagnostics="not rendered on PASS",
        source="diff",
        base_reconstruction="ok",
        reason_code="tests_passed",
        isolation="docker",
        diff_coverage={
            "measured": True,
            "executed": 8,
            "total": 10,
            "percent": 80.0,
            "caveat": "branch evidence is scoped to changed executable lines",
            "files": {
                "src/module_00.py": {"missed": [7, 11]},
                "src/module_01.py": {"missed": []},
            },
        },
        baseline={
            "verdict": "FAIL",
            "tests_passed": 16,
            "tests_total": 17,
            "repair_effect": "demonstrated",
        },
        attestation={
            "policy_id": "org/default",
            "policy_version": "9",
            "verifier_pack_sha256": "a" * 64,
        },
        assurance={
            "harness_integrity": "protected",
            "report_integrity": "same_process_candidate_writable",
            "candidate_isolation": "container",
        },
        test_command_ran=True,
        execution_state="completed",
        execution_phase="complete",
    )
    return result, ["src/removed.py"], "EvoGuard Characterization"


def _static_rejection() -> tuple[GuardResult, list[str], str]:
    result = GuardResult(
        verdict=REJECTED,
        passed=False,
        reason="candidate changed the judging harness",
        files_changed=["tests/test_gate.py"],
        protected_violations=["tests/test_gate.py"],
        risk_level="high",
        risk_score=0.91,
        reason_code="protected_harness_edit",
        isolation="not_run",
        assurance={
            "harness_integrity": "violated",
            "report_integrity": "not_run",
            "candidate_isolation": "not_run",
        },
        test_command_ran=False,
        execution_state="static_gate",
        execution_phase="pre_gate",
    )
    return result, [], "EvoGuard"


def _tampered_gvisor() -> tuple[GuardResult, list[str], str]:
    result = GuardResult(
        verdict=TAMPERED,
        passed=False,
        reason="the process exit and judge-owned report disagree",
        files_changed=["src/service.py"],
        protected_violations=[],
        risk_level="critical",
        risk_score=1.0,
        tests_passed=4,
        tests_total=4,
        verdict_source="junit+exit",
        diagnostics="exit=1\njunit failures=0\ncandidate marker: <untrusted>",
        reason_code="junit_exit_mismatch",
        isolation="gvisor",
        assurance={
            "harness_integrity": "protected",
            "report_integrity": "judge_owned",
            "candidate_isolation": "gvisor",
        },
        test_command_ran=True,
        execution_state="completed",
        execution_phase="complete",
    )
    return result, [], "EvoGuard"


def _incomplete_error() -> tuple[GuardResult, list[str], str]:
    result = GuardResult(
        verdict=ERROR,
        passed=False,
        reason="setup began but cleanup could not be proved",
        files_changed=["src/bootstrap.py"],
        protected_violations=[],
        risk_level="medium",
        risk_score=0.5,
        diagnostics="cleanup proof unavailable",
        reason_code="runtime_cleanup_failed",
        isolation="subprocess",
        test_command_ran=True,
        execution_state="started_incomplete",
        execution_phase="setup",
    )
    return result, [], "EvoGuard"


def _case(case_name: str) -> tuple[GuardResult, list[str], str]:
    factories = {
        "incomplete_error": _incomplete_error,
        "pass_full_evidence": _pass_full_evidence,
        "static_rejection": _static_rejection,
        "tampered_gvisor": _tampered_gvisor,
    }
    try:
        return factories[case_name]()
    except KeyError as exc:
        raise ValueError(f"unknown Guard output characterization case: {case_name}") from exc


def capture_case(case_name: str, root: Path) -> dict[str, Any]:
    """Capture all four historical output surfaces for one result."""

    result, deleted, title = _case(case_name)
    json_path = root / f"{case_name}.json"
    sarif_path = root / f"{case_name}.sarif"
    write_json(result, str(json_path), deleted=deleted)
    write_sarif(result, str(sarif_path))
    return {
        "report": render_report(result, deleted=deleted, title=title),
        "json_text": json_path.read_text(encoding="utf-8"),
        "sarif": to_sarif(result),
        "sarif_text": sarif_path.read_text(encoding="utf-8"),
    }


def capture_all() -> dict[str, Any]:
    """Capture every reviewed case without retaining temporary effects."""

    with tempfile.TemporaryDirectory(prefix="guard_output_characterization_") as temp:
        root = Path(temp)
        return {
            "schema_version": SCHEMA_VERSION,
            "cases": {
                case_name: capture_case(case_name, root)
                for case_name in CASE_NAMES
            },
        }


if __name__ == "__main__":  # pragma: no cover - explicit capture tool owns writes
    raise SystemExit("use tools/ci/capture_guard_output_characterization.py")
