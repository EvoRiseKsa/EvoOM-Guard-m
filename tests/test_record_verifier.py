"""Semantic verification contract for schema-1.11 verdict records."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import evoom_guard.evidence as evidence
from evoom_guard import __version__
from evoom_guard.cli import main as cli_main
from evoom_guard.guard import SCHEMA_VERSION, guard
from evoom_guard.pack_manifest import PACK_DIGEST_FORMAT
from evoom_guard.record_verifier import (
    SUPPORTED_SCHEMA_VERSIONS,
    strict_json_loads,
    verify_record,
)


def _policy_digest(policy: dict[str, object]) -> str:
    return hashlib.sha256(json.dumps(policy, sort_keys=True).encode("utf-8")).hexdigest()


def _valid_composite_record() -> dict[str, object]:
    policy: dict[str, object] = {
        "mode": "blackbox",
        "isolation": "subprocess",
        "docker_image": None,
        "docker_network": "none",
        "test_command": "default:python -m pytest",
        "setup_command": None,
        "trust_setup_on_host": False,
        "setup_output_globs": [],
        "protected": [],
        "allow": [],
        "allow_new_tests": False,
        "timeout": 120,
        "mem_limit_mb": 1024,
        "blackbox": True,
        "blackbox_only": False,
        "verifier_pack_required": True,
        "expect_verifier_pack_sha256": None,
        "require_report_integrity": None,
        "require_candidate_isolation": None,
        "min_diff_coverage": None,
        "baseline_evidence": False,
        "require_demonstrated_fix": False,
        "policy_id": "strict-ci",
        "policy_version": "1",
    }
    pack_sha = "a" * 64
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "evoguard",
        "tool_version": __version__,
        "verdict": "PASS",
        "passed": True,
        "exit_code": 0,
        "reason_code": "tests_passed",
        "reason": "all required phases passed",
        "files_changed": ["app.py"],
        "protected_violations": [],
        "risk_level": "low",
        "risk_score": 0.1,
        "tests_passed": 3,
        "tests_total": 3,
        "test_command_ran": True,
        "execution_state": "completed",
        "execution_phase": "repo_suite",
        "verdict_source": "composite:blackbox+repo",
        "isolation": "subprocess",
        "source": "diff",
        "base_reconstruction": "ok",
        "assurance": {
            "execution_state": "completed",
            "execution_phase": "repo_suite",
            "harness_integrity": "pre_gate_enforced",
            "report_integrity": "same_process_candidate_writable",
            "candidate_isolation": "subprocess",
            "suite_isolation": "subprocess",
            "setup_isolation": None,
            "runtime_continuity": "not_applicable",
            "verifier_pack": {
                "configured": True,
                "present": True,
                "integrity": "verified_snapshot_pre_post",
                "identity_verified": True,
                "execution_state": "completed",
                "secrecy": "reachable_same_host",
                "snapshot_sha256": pack_sha,
            },
            "repo_native_suite": "composed_completed",
            "overall_profile": "composite_blackbox_repo_native",
        },
        "diff_coverage": None,
        "baseline": None,
        "attestation": {
            "created_utc": "2026-07-13T00:00:00Z",
            "guard_version": __version__,
            "mode": "blackbox",
            "candidate_sha256": "b" * 64,
            "effective_policy": policy,
            "policy_sha256": _policy_digest(policy),
            "policy_id": "strict-ci",
            "policy_version": "1",
            "junit_sha256": "c" * 64,
            "junit_digest_format": "JUNIT_XML_SHA256",
            "execution_state": "completed",
            "execution_phase": "repo_suite",
            "test_command_started": True,
            "delivered_isolation": "subprocess",
            "effective_candidate_isolation": "subprocess",
            "candidate_invocations": 1,
            "candidate_launcher_invocation_observed": True,
            "verifier_pack_sha256": pack_sha,
            "verifier_pack_digest_format": PACK_DIGEST_FORMAT,
            "verifier_pack_tests_passed": 1,
            "verifier_pack_tests_total": 1,
            "verifier_pack_junit_sha256": "c" * 64,
            "verifier_pack_junit_digest_format": "JUNIT_XML_SHA256",
            "verifier_pack_present": True,
            "verifier_pack_started": True,
            "verifier_pack_completed": True,
            "repo_suite_started": True,
            "repo_suite_completed": True,
            "repo_suite_state": "composed_completed",
            "repo_suite_passed": True,
        },
        "diagnostics": "",
    }


def _valid_preflight_record(reason_code: str) -> dict[str, object]:
    record = _valid_composite_record()
    record.update(
        {
            "verdict": "ERROR",
            "passed": False,
            "exit_code": 1,
            "reason_code": reason_code,
            "reason": "the requested policy could not start",
            "tests_passed": None,
            "tests_total": None,
            "test_command_ran": False,
            "execution_state": "not_started",
            "execution_phase": "preflight",
            "verdict_source": None,
            "isolation": "not_run",
        }
    )
    assurance = record["assurance"]
    assert isinstance(assurance, dict)
    assurance.update(
        {
            "execution_state": "not_started",
            "execution_phase": "preflight",
            "report_integrity": "not_applicable_not_run",
            "candidate_isolation": "not_run",
            "suite_isolation": "not_run",
            "verifier_pack": None,
            "overall_profile": "preflight",
        }
    )
    assurance.pop("repo_native_suite", None)
    attestation = record["attestation"]
    assert isinstance(attestation, dict)
    policy = attestation["effective_policy"]
    assert isinstance(policy, dict)
    policy["verifier_pack_required"] = False
    attestation.update(
        {
            "policy_sha256": _policy_digest(policy),
            "execution_state": "not_started",
            "execution_phase": "preflight",
            "test_command_started": False,
            "delivered_isolation": "not_run",
            "effective_candidate_isolation": None,
            "candidate_invocations": None,
            "candidate_launcher_invocation_observed": None,
            "verifier_pack_sha256": None,
            "verifier_pack_digest_format": None,
            "verifier_pack_tests_passed": None,
            "verifier_pack_tests_total": None,
            "verifier_pack_junit_sha256": None,
            "verifier_pack_junit_digest_format": None,
            "junit_sha256": None,
            "junit_digest_format": None,
            "verifier_pack_present": None,
            "verifier_pack_started": False,
            "verifier_pack_completed": False,
            "repo_suite_started": False,
            "repo_suite_completed": False,
            "repo_suite_state": "required_not_started",
            "repo_suite_passed": None,
        }
    )
    return record


def _valid_blackbox_only_record() -> dict[str, object]:
    record = _valid_composite_record()
    attestation = record["attestation"]
    assurance = record["assurance"]
    assert isinstance(attestation, dict)
    assert isinstance(assurance, dict)
    policy = attestation["effective_policy"]
    assert isinstance(policy, dict)
    policy["blackbox_only"] = True
    attestation["policy_sha256"] = _policy_digest(policy)
    record.update(
        {
            "verdict_source": "blackbox",
            "execution_phase": "blackbox_pack",
            "tests_passed": 1,
            "tests_total": 1,
        }
    )
    attestation.update(
        {
            "execution_phase": "blackbox_pack",
            "repo_suite_started": False,
            "repo_suite_completed": False,
            "repo_suite_state": "not_required_blackbox_only",
            "repo_suite_passed": None,
        }
    )
    assurance.update(
        {
            "execution_phase": "blackbox_pack",
            "report_integrity": "external_process_isolated",
            "suite_isolation": "subprocess",
            "repo_native_suite": "not_required_blackbox_only",
            "overall_profile": "black_box_external_judge",
        }
    )
    return record


def _check(report: dict[str, object], check_id: str) -> dict[str, str]:
    checks = report["checks"]
    assert isinstance(checks, list)
    return next(item for item in checks if item["id"] == check_id)


def _effective_policy(record: dict[str, object]) -> tuple[dict[str, object], dict[str, object]]:
    attestation = record["attestation"]
    assert isinstance(attestation, dict)
    policy = attestation["effective_policy"]
    assert isinstance(policy, dict)
    return attestation, policy


def _refresh_policy_digest(record: dict[str, object]) -> dict[str, object]:
    attestation, policy = _effective_policy(record)
    attestation["policy_sha256"] = _policy_digest(policy)
    return policy


def _coverage_repo(tmp_path: Path) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    (tmp_path / "app.py").write_text(
        "def covered(x):\n    return x + 1\n\n"
        "def uncovered(x):\n    return x - 1\n",
        encoding="utf-8",
    )
    (tests / "test_app.py").write_text(
        "from app import covered\n\ndef test_covered():\n    assert covered(1) == 2\n",
        encoding="utf-8",
    )


def test_valid_composite_record_passes_all_available_claims() -> None:
    report = verify_record(_valid_composite_record())

    assert report["ok"] is True
    assert report["signature_checked"] is False
    assert report["summary"]["failed"] == 0
    assert _check(report, "policy.digest")["status"] == "pass"
    assert _check(report, "candidate_receipt.zero_nonzero")["status"] == "pass"
    assert _check(report, "composite.phase_semantics")["status"] == "pass"


def test_schema_1_11_accepts_optional_strict_harness_without_rejecting_old_records() -> None:
    # Published 1.11 records omit this later additive policy fact and must stay
    # valid.  New producer records state it explicitly and are valid too.
    legacy = _valid_composite_record()
    legacy["tool_version"] = "4.0.1"
    legacy_attestation = legacy["attestation"]
    assert isinstance(legacy_attestation, dict)
    legacy_attestation["guard_version"] = "4.0.1"
    legacy_attestation.pop("verifier_pack_junit_sha256")
    legacy_attestation.pop("verifier_pack_junit_digest_format")
    assert verify_record(legacy)["ok"] is True

    strict = _valid_composite_record()
    policy = _refresh_policy_digest(strict)
    policy["strict_harness"] = True
    _refresh_policy_digest(strict)
    assert verify_record(strict)["ok"] is True

    malformed = _valid_composite_record()
    policy = _refresh_policy_digest(malformed)
    policy["strict_harness"] = "true"
    _refresh_policy_digest(malformed)
    assert verify_record(malformed)["ok"] is False


def test_real_static_guard_record_is_semantically_valid(tmp_path) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_app.py").write_text("def test_app():\n    assert True\n", encoding="utf-8")
    candidate = (
        "<<<FILE: tests/test_app.py>>>\n"
        "def test_app():\n    assert False\n"
        "<<<END FILE>>>\n"
    )

    record = guard(str(tmp_path), candidate).to_dict()
    report = verify_record(record)

    assert record["verdict"] == "REJECTED"
    assert report["ok"] is True
    assert report["summary"]["failed"] == 0


@pytest.mark.parametrize("with_pack", [False, True])
def test_real_completed_repo_records_are_semantically_valid(tmp_path, with_pack: bool) -> None:
    repo = tmp_path / "repo"
    tests = repo / "tests"
    tests.mkdir(parents=True)
    (repo / "app.py").write_text("def value():\n    return 1\n", encoding="utf-8")
    (tests / "test_app.py").write_text(
        "from app import value\n\ndef test_value():\n    assert value() == 2\n",
        encoding="utf-8",
    )
    candidate = "<<<FILE: app.py>>>\ndef value():\n    return 2\n<<<END FILE>>>\n"
    pack_path = None
    if with_pack:
        pack = tmp_path / "pack"
        pack.mkdir()
        (pack / "test_contract.py").write_text(
            "from app import value\n\ndef test_contract():\n    assert value() == 2\n",
            encoding="utf-8",
        )
        pack_path = str(pack)

    record = guard(str(repo), candidate, verifier_pack=pack_path).to_dict()
    report = verify_record(record)

    assert record["verdict"] == "PASS"
    assert report["ok"] is True, report
    assert report["summary"]["failed"] == 0
    if not with_pack:
        forged = copy.deepcopy(record)
        forged["attestation"]["junit_digest_format"] = (
            "EVOGUARD_JUNIT_COMPOSITE_V2"
        )
        forged_report = verify_record(forged)
        assert forged_report["ok"] is False
        assert _check(forged_report, "source.mode_policy")["status"] == "fail"

        missing_current_identity = copy.deepcopy(record)
        missing_current_identity["attestation"]["junit_sha256"] = None
        missing_current_identity["attestation"]["junit_digest_format"] = None
        missing_current_report = verify_record(missing_current_identity)
        assert missing_current_report["ok"] is False
        assert (
            _check(missing_current_report, "source.mode_policy")["status"]
            == "fail"
        )

        # v4.0.1 Maven/Surefire records could carry clean structured counts but
        # no top digest because the directory report set was not yet bound.
        legacy_maven = copy.deepcopy(record)
        legacy_maven["tool_version"] = "4.0.1"
        legacy_attestation = legacy_maven["attestation"]
        legacy_attestation["guard_version"] = "4.0.1"
        legacy_attestation["junit_sha256"] = None
        legacy_attestation["junit_digest_format"] = None
        assert verify_record(legacy_maven)["ok"] is True


def test_pack_failure_preserves_repo_suite_baseline_effect(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    tests = repo / "tests"
    tests.mkdir(parents=True)
    (repo / "app.py").write_text(
        "def fixed():\n    return 0\n\ndef hidden():\n    return 1\n",
        encoding="utf-8",
    )
    (tests / "test_app.py").write_text(
        "from app import fixed\n\ndef test_fixed():\n    assert fixed() == 1\n",
        encoding="utf-8",
    )
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "test_contract.py").write_text(
        "from app import hidden\n\ndef test_hidden():\n    assert hidden() == 1\n",
        encoding="utf-8",
    )
    candidate = (
        "<<<FILE: app.py>>>\n"
        "def fixed():\n    return 1\n\ndef hidden():\n    return 2\n"
        "<<<END FILE>>>\n"
    )

    record = guard(
        str(repo),
        candidate,
        verifier_pack=str(pack),
        baseline_evidence=True,
    ).to_dict()

    assert record["verdict"] == "FAIL"
    assert record["reason_code"] == "tests_failed"
    assert record["verdict_source"] == "composite:repo+verifier-pack"
    assert (record["tests_passed"], record["tests_total"]) == (1, 2)
    assert record["baseline"]["verdict"] == "FAIL"
    assert record["baseline"]["repair_effect"] == "demonstrated"
    attestation = record["attestation"]
    assert attestation["repo_suite_state"] == "repo_phase_completed"
    assert attestation["repo_suite_passed"] is True
    assert attestation["repo_suite_tests_passed"] == 1
    assert attestation["repo_suite_tests_total"] == 1
    assert attestation["repo_suite_verdict_source"] == "junit+exit"
    assert attestation["repo_suite_returncode"] == 0
    assert isinstance(attestation["repo_suite_junit_sha256"], str)
    assert len(attestation["repo_suite_junit_sha256"]) == 64
    assert attestation["repo_suite_junit_digest_format"] == "JUNIT_XML_SHA256"
    assert verify_record(record)["ok"] is True

    forged = copy.deepcopy(record)
    forged["attestation"]["repo_suite_passed"] = False
    report = verify_record(forged)
    assert report["ok"] is False
    assert _check(report, "baseline.policy_semantics")["status"] == "fail"
    assert _check(report, "composite.phase_semantics")["status"] == "fail"

    forged_digest = copy.deepcopy(record)
    forged_digest["attestation"]["repo_suite_junit_sha256"] = "garbage"
    digest_report = verify_record(forged_digest)
    assert digest_report["ok"] is False
    assert _check(digest_report, "attestation.shape")["status"] == "fail"
    assert _check(digest_report, "composite.phase_semantics")["status"] == "fail"

    forged_valid_digest = copy.deepcopy(record)
    forged_valid_digest["attestation"]["repo_suite_junit_sha256"] = "a" * 64
    valid_digest_report = verify_record(forged_valid_digest)
    assert valid_digest_report["ok"] is False
    assert _check(valid_digest_report, "attestation.shape")["status"] == "pass"
    assert (
        _check(valid_digest_report, "composite.phase_semantics")["status"]
        == "fail"
    )

    missing_phase = copy.deepcopy(record)
    for field in (
        "repo_suite_started",
        "repo_suite_completed",
        "repo_suite_state",
        "repo_suite_passed",
        "repo_suite_tests_passed",
        "repo_suite_tests_total",
        "repo_suite_verdict_source",
        "repo_suite_returncode",
        "repo_suite_junit_sha256",
        "repo_suite_junit_digest_format",
    ):
        missing_phase["attestation"][field] = None
    missing_report = verify_record(missing_phase)
    assert missing_report["ok"] is False
    assert _check(missing_report, "composite.phase_semantics")["status"] == "fail"


def test_completed_zero_test_pack_is_a_valid_no_verdict_error(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    tests = repo / "tests"
    tests.mkdir(parents=True)
    (repo / "app.py").write_text("VALUE = 0\n", encoding="utf-8")
    (tests / "test_app.py").write_text(
        "import app\n\ndef test_value():\n    assert app.VALUE == 1\n",
        encoding="utf-8",
    )
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "test_contract.py").write_text(
        "from app import VALUE\n",
        encoding="utf-8",
    )

    record = guard(
        str(repo),
        "<<<FILE: app.py>>>\nVALUE = 1\n<<<END FILE>>>\n",
        verifier_pack=str(pack),
        baseline_evidence=True,
    ).to_dict()
    report = verify_record(record)

    assert record["verdict"] == "ERROR"
    assert record["reason_code"] == "no_test_verdict"
    assert record["verdict_source"] is None
    assert record["attestation"]["verifier_pack_completed"] is True
    assert record["attestation"]["verifier_pack_tests_passed"] == 0
    assert record["attestation"]["verifier_pack_tests_total"] == 0
    assert record["baseline"]["repair_effect"] == "demonstrated"
    assert report["ok"] is True, [
        check for check in report["checks"] if check["status"] == "fail"
    ]


def test_tests_failed_cannot_claim_that_every_recorded_test_passed(tmp_path) -> None:
    repo = tmp_path / "repo"
    tests = repo / "tests"
    tests.mkdir(parents=True)
    (repo / "app.py").write_text("def value():\n    return 1\n", encoding="utf-8")
    (tests / "test_app.py").write_text(
        "from app import value\n\ndef test_value():\n    assert value() == 2\n",
        encoding="utf-8",
    )
    candidate = "<<<FILE: app.py>>>\ndef value():\n    return 3\n<<<END FILE>>>\n"
    record = guard(str(repo), candidate).to_dict()

    assert record["reason_code"] == "tests_failed"
    assert verify_record(record)["ok"] is True
    record["tests_passed"] = 1
    record["tests_total"] = 1

    report = verify_record(record)

    assert report["ok"] is False
    assert _check(report, "verdict.failure_evidence")["status"] == "fail"


def test_junit_exit_mismatch_requires_non_empty_junit_counts(tmp_path) -> None:
    repo = tmp_path / "repo"
    tests = repo / "tests"
    tests.mkdir(parents=True)
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repo / "conftest.py").write_text(
        "def pytest_sessionfinish(session, exitstatus):\n"
        "    session.exitstatus = 1\n",
        encoding="utf-8",
    )
    (tests / "test_app.py").write_text(
        "from app import VALUE\n\ndef test_value():\n    assert VALUE == 1\n",
        encoding="utf-8",
    )
    candidate = "<<<FILE: note.py>>>\n# harmless source addition\n<<<END FILE>>>\n"
    record = guard(str(repo), candidate).to_dict()

    assert record["reason_code"] == "junit_exit_mismatch"
    assert record["tests_total"] == 1
    assert verify_record(record)["ok"] is True
    record["tests_passed"] = 0
    record["tests_total"] = 0

    report = verify_record(record)

    assert report["ok"] is False
    assert _check(report, "verdict.tamper_evidence")["status"] == "fail"


def test_clean_exit_only_pass_with_zero_structured_counts_is_valid(tmp_path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    candidate = "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n"
    record = guard(
        str(repo),
        candidate,
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
    ).to_dict()

    assert record["verdict"] == "PASS"
    assert record["verdict_source"] == "exit"
    assert record["tests_passed"] == record["tests_total"] == 0

    report = verify_record(record)

    assert report["ok"] is True, report
    assert _check(report, "verdict.pass_evidence")["status"] == "pass"

    record["tests_passed"] = 1
    record["tests_total"] = 1
    mutated_report = verify_record(record)
    assert mutated_report["ok"] is False
    assert _check(mutated_report, "counts.source_semantics")["status"] == "fail"


def test_failed_baseline_cannot_claim_all_recorded_tests_passed() -> None:
    record = _valid_composite_record()
    policy = _refresh_policy_digest(record)
    policy["baseline_evidence"] = True
    _refresh_policy_digest(record)
    record["baseline"] = {
        "verdict": "FAIL",
        "tests_passed": 1,
        "tests_total": 1,
        "repair_effect": "demonstrated",
        "scope": "repo_suite_only",
        "note": "mutated baseline",
    }

    report = verify_record(record)

    assert report["ok"] is False
    assert _check(report, "baseline.shape")["status"] == "fail"


def test_completed_pack_counts_cannot_be_empty() -> None:
    record = _valid_composite_record()
    attestation = record["attestation"]
    assert isinstance(attestation, dict)
    attestation["verifier_pack_tests_passed"] = 0
    attestation["verifier_pack_tests_total"] = 0

    report = verify_record(record)

    assert report["ok"] is False
    assert _check(report, "pack.counts")["status"] == "fail"


def test_blackbox_only_top_counts_must_equal_external_pack_counts() -> None:
    record = _valid_blackbox_only_record()
    assert verify_record(record)["ok"] is True
    record["tests_passed"] = 99
    record["tests_total"] = 99

    report = verify_record(record)

    assert report["ok"] is False
    assert _check(report, "pack.blackbox_count_parity")["status"] == "fail"


@pytest.mark.parametrize(
    "reason_code",
    ["verifier_pack_required", "policy_requirement_unsupported"],
)
def test_preflight_no_run_allows_null_candidate_receipt_and_effective_isolation(
    reason_code: str,
) -> None:
    report = verify_record(_valid_preflight_record(reason_code))

    assert report["ok"] is True, report
    assert _check(report, "attestation.types")["status"] == "pass"
    assert _check(report, "candidate_receipt.zero_nonzero")["status"] == "pass"
    assert _check(report, "candidate_receipt.isolation")["status"] == "pass"
    assert _check(report, "isolation.attestation_parity")["status"] == "pass"


def test_preflight_no_run_also_accepts_explicit_zero_receipt() -> None:
    record = _valid_preflight_record("verifier_pack_required")
    attestation = record["attestation"]
    assert isinstance(attestation, dict)
    attestation["candidate_invocations"] = 0
    attestation["candidate_launcher_invocation_observed"] = False

    report = verify_record(record)

    assert report["ok"] is True, report
    assert _check(report, "candidate_receipt.zero_nonzero")["status"] == "pass"


def test_lifecycle_mutation_is_rejected() -> None:
    record = _valid_composite_record()
    record["execution_phase"] = "blackbox_pack"

    report = verify_record(record)

    assert report["ok"] is False
    assert _check(report, "lifecycle.assurance_parity")["status"] == "fail"
    assert _check(report, "lifecycle.attestation_parity")["status"] == "fail"


def test_verdict_and_count_mutations_are_rejected() -> None:
    record = _valid_composite_record()
    record["passed"] = False
    record["tests_passed"] = 4

    report = verify_record(record)

    assert _check(report, "verdict.boolean_exit")["status"] == "fail"
    assert _check(report, "counts.range_pair")["status"] == "fail"


def test_effective_policy_mutation_breaks_digest() -> None:
    record = _valid_composite_record()
    attestation = record["attestation"]
    assert isinstance(attestation, dict)
    policy = attestation["effective_policy"]
    assert isinstance(policy, dict)
    policy["blackbox_only"] = True

    report = verify_record(record)

    assert _check(report, "policy.digest")["status"] == "fail"


def test_candidate_receipt_zero_nonzero_mutation_is_rejected() -> None:
    record = _valid_composite_record()
    attestation = record["attestation"]
    assert isinstance(attestation, dict)
    attestation["candidate_invocations"] = 0

    report = verify_record(record)

    assert _check(report, "candidate_receipt.zero_nonzero")["status"] == "fail"


def test_isolation_and_pack_identity_mutations_are_rejected() -> None:
    record = _valid_composite_record()
    record["isolation"] = "docker"
    assurance = record["assurance"]
    assert isinstance(assurance, dict)
    pack = assurance["verifier_pack"]
    assert isinstance(pack, dict)
    pack["snapshot_sha256"] = "c" * 64

    report = verify_record(record)

    assert _check(report, "isolation.assurance_parity")["status"] == "fail"
    assert _check(report, "pack.identity_parity")["status"] == "fail"


def test_composite_count_mutation_is_rejected() -> None:
    record = _valid_composite_record()
    attestation = record["attestation"]
    assert isinstance(attestation, dict)
    attestation["verifier_pack_tests_total"] = 4

    report = verify_record(record)

    assert _check(report, "composite.counts")["status"] == "fail"


def test_null_attestation_is_explicitly_skipped_not_falsely_verified() -> None:
    record = _valid_composite_record()
    record["verdict_source"] = "junit+exit"
    record["attestation"] = None
    assurance = record["assurance"]
    assert isinstance(assurance, dict)
    assurance["verifier_pack"] = None

    report = verify_record(record)

    assert report["ok"] is True
    assert _check(report, "policy.digest")["status"] == "skip"
    assert report["summary"]["skipped"] > 0


def test_cli_outputs_json_and_uses_distinct_exit_codes(tmp_path, capsys) -> None:
    path = tmp_path / "verdict.json"
    path.write_text(json.dumps(_valid_composite_record()), encoding="utf-8")

    assert cli_main(["verify-record", str(path)]) == 0
    valid_report = json.loads(capsys.readouterr().out)
    assert valid_report["ok"] is True

    mutated = _valid_composite_record()
    mutated["exit_code"] = 1
    path.write_text(json.dumps(mutated), encoding="utf-8")
    assert cli_main(["verify-record", str(path)]) == 1
    invalid_report = json.loads(capsys.readouterr().out)
    assert invalid_report["ok"] is False

    path.write_text("{not json", encoding="utf-8")
    assert cli_main(["verify-record", str(path)]) == 2
    unreadable_report = json.loads(capsys.readouterr().out)
    assert _check(unreadable_report, "document.json")["status"] == "fail"
    assert unreadable_report["input_sha256"] == hashlib.sha256(
        path.read_bytes()
    ).hexdigest()
    assert unreadable_report["input_size"] == path.stat().st_size


@pytest.mark.parametrize(
    "invalid_json",
    [
        '{"schema_version":"1.11","schema_version":"1.11"}',
        '{"risk_score":NaN}',
        '{"risk_score":Infinity}',
    ],
)
def test_cli_rejects_ambiguous_or_nonstandard_json(
    tmp_path, capsys, invalid_json: str
) -> None:
    path = tmp_path / "invalid.json"
    path.write_text(invalid_json, encoding="utf-8")

    assert cli_main(["verify-record", str(path)]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is False
    assert _check(report, "document.json")["status"] == "fail"
    assert report["input_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert report["input_size"] == path.stat().st_size


def test_strict_json_rejects_float_overflow_and_excessive_nesting() -> None:
    with pytest.raises(ValueError, match="non-finite"):
        strict_json_loads('{"risk_score":1e9999}')

    deeply_nested = "[" * 4000 + "0" + "]" * 4000
    with pytest.raises(ValueError, match="nesting"):
        strict_json_loads(deeply_nested)

    with pytest.raises(ValueError, match="128-digit"):
        strict_json_loads('{"count":' + "1" * 129 + "}")


@pytest.mark.parametrize(
    ("field", "malformed"),
    [
        ("schema_version", []),
        ("verdict", {}),
        ("reason_code", []),
        ("risk_level", {}),
        ("execution_state", []),
        ("verdict_source", {}),
        ("isolation", []),
        ("protected_violations", {}),
    ],
)
def test_arbitrary_top_level_json_types_return_failures_not_exceptions(
    field: str, malformed: object
) -> None:
    record = _valid_composite_record()
    record[field] = malformed

    report = verify_record(record)

    assert report["ok"] is False
    assert _check(report, "envelope.types")["status"] == "fail"
    assert all(item["id"] != "document.semantic_processing" for item in report["checks"])


@pytest.mark.parametrize(
    ("reason_code", "verdict", "state"),
    [
        ("tests_passed", "FAIL", "completed"),
        ("protected_harness_edit", "ERROR", "static_gate"),
        ("tests_failed", "ERROR", "completed"),
        ("policy_requirement_unsupported", "ERROR", "completed"),
        ("verifier_pack_snapshot_changed", "TAMPERED", "static_gate"),
        ("candidate_not_exercised", "FAIL", "completed"),
    ],
)
def test_reason_code_cannot_be_rebound_to_another_verdict_or_lifecycle(
    reason_code: str, verdict: str, state: str
) -> None:
    record = _valid_composite_record()
    record["reason_code"] = reason_code
    record["verdict"] = verdict
    record["execution_state"] = state

    report = verify_record(record)

    assert _check(report, "verdict.reason_code")["status"] == "fail"


@pytest.mark.parametrize(
    ("reason_code", "verdict", "state"),
    [
        ("verifier_pack_snapshot_changed", "TAMPERED", "not_started"),
        ("verifier_pack_snapshot_changed", "TAMPERED", "started_incomplete"),
        ("verifier_pack_snapshot_changed", "TAMPERED", "completed"),
        ("candidate_tree_changed_during_run", "TAMPERED", "started_incomplete"),
        ("candidate_tree_changed_during_run", "TAMPERED", "completed"),
        ("test_command_unavailable", "ERROR", "started_incomplete"),
        ("assurance_requirement_not_met", "ERROR", "started_incomplete"),
    ],
)
def test_reason_mapping_accepts_every_multiphase_state_emitted_by_guard(
    reason_code: str, verdict: str, state: str
) -> None:
    record = _valid_composite_record()
    record["reason_code"] = reason_code
    record["verdict"] = verdict
    record["execution_state"] = state

    report = verify_record(record)

    assert _check(report, "verdict.reason_code")["status"] == "pass"


@pytest.mark.parametrize(
    ("source", "phase"),
    [
        ("blackbox", "blackbox_pack"),
        ("composite:blackbox+repo", "blackbox_pack"),
        ("junit+exit", "repo_suite"),
    ],
)
def test_composite_blackbox_policy_cannot_drop_or_relabel_a_required_channel(
    source: str, phase: str
) -> None:
    record = _valid_composite_record()
    record["verdict_source"] = source
    record["execution_phase"] = phase
    assurance = record["assurance"]
    attestation = record["attestation"]
    assert isinstance(assurance, dict)
    assert isinstance(attestation, dict)
    assurance["execution_phase"] = phase
    attestation["execution_phase"] = phase

    report = verify_record(record)

    assert _check(report, "source.mode_policy")["status"] == "fail"


def test_blackbox_only_policy_cannot_claim_a_composite_source() -> None:
    record = _valid_composite_record()
    assurance = record["assurance"]
    attestation = record["attestation"]
    assert isinstance(assurance, dict)
    assert isinstance(attestation, dict)
    policy = attestation["effective_policy"]
    assert isinstance(policy, dict)
    policy["blackbox_only"] = True
    attestation["policy_sha256"] = _policy_digest(policy)

    report = verify_record(record)

    assert _check(report, "source.mode_policy")["status"] == "fail"


@pytest.mark.parametrize(
    ("pack_field", "malformed"),
    [
        ("present", False),
        ("identity_verified", False),
        ("integrity", "verified_snapshot_pre_execution"),
        ("execution_state", "not_started"),
    ],
)
def test_pack_backed_pass_requires_complete_trusted_pack_evidence(
    pack_field: str, malformed: object
) -> None:
    record = _valid_composite_record()
    assurance = record["assurance"]
    assert isinstance(assurance, dict)
    pack = assurance["verifier_pack"]
    assert isinstance(pack, dict)
    pack[pack_field] = malformed

    report = verify_record(record)

    assert _check(report, "pack.pass_evidence")["status"] == "fail"


def test_pack_cannot_be_completed_under_a_not_started_record() -> None:
    record = _valid_preflight_record("verifier_pack_required")
    assurance = record["assurance"]
    attestation = record["attestation"]
    assert isinstance(assurance, dict)
    assert isinstance(attestation, dict)
    assurance["verifier_pack"] = {
        "configured": True,
        "present": True,
        "integrity": "verified_snapshot_pre_post",
        "identity_verified": True,
        "execution_state": "completed",
        "secrecy": "reachable_same_host",
        "snapshot_sha256": "a" * 64,
    }
    attestation.update(
        {
            "verifier_pack_sha256": "a" * 64,
            "verifier_pack_digest_format": PACK_DIGEST_FORMAT,
            "verifier_pack_present": True,
            "verifier_pack_started": True,
            "verifier_pack_completed": True,
            "verifier_pack_tests_passed": 1,
            "verifier_pack_tests_total": 1,
        }
    )
    policy = attestation["effective_policy"]
    assert isinstance(policy, dict)
    policy["verifier_pack_required"] = True
    attestation["policy_sha256"] = _policy_digest(policy)

    report = verify_record(record)

    assert _check(report, "pack.lifecycle_parity")["status"] == "fail"


@pytest.mark.parametrize(
    "reason_code",
    ["verifier_pack_snapshot_changed", "candidate_tree_changed_during_run"],
)
def test_post_execution_tamper_may_withhold_unconsumed_pack_counts(
    reason_code: str,
) -> None:
    record = _valid_composite_record()
    record.update(
        {
            "verdict": "TAMPERED",
            "passed": False,
            "exit_code": 1,
            "reason_code": reason_code,
            "verdict_source": None,
            "tests_passed": None,
            "tests_total": None,
        }
    )
    attestation = record["attestation"]
    assert isinstance(attestation, dict)
    attestation["verifier_pack_tests_passed"] = None
    attestation["verifier_pack_tests_total"] = None

    report = verify_record(record)

    assert _check(report, "pack.counts")["status"] == "pass"


def test_unconfigured_pack_rejects_dangling_identity_fields() -> None:
    record = _valid_preflight_record("verifier_pack_required")
    attestation = record["attestation"]
    assert isinstance(attestation, dict)
    attestation["verifier_pack_sha256"] = "a" * 64
    attestation["verifier_pack_digest_format"] = PACK_DIGEST_FORMAT

    report = verify_record(record)

    assert _check(report, "pack.identity_parity")["status"] == "fail"


def test_started_incomplete_cannot_carry_source_or_top_level_counts() -> None:
    record = _valid_composite_record()
    record["execution_state"] = "started_incomplete"
    assurance = record["assurance"]
    attestation = record["attestation"]
    assert isinstance(assurance, dict)
    assert isinstance(attestation, dict)
    assurance["execution_state"] = "started_incomplete"
    attestation["execution_state"] = "started_incomplete"

    report = verify_record(record)

    assert _check(report, "lifecycle.state_semantics")["status"] == "fail"


@pytest.mark.parametrize(
    ("target", "field", "malformed", "check_id"),
    [
        ("attestation", "candidate_sha256", "ABC", "attestation.shape"),
        ("attestation", "created_utc", "2026-99-99", "attestation.shape"),
        ("attestation", "created_utc", "2026-1-01T00:00:00Z", "attestation.shape"),
        ("assurance", "candidate_isolation", "vm", "assurance.shape"),
        ("assurance", "report_integrity", [], "assurance.shape"),
    ],
)
def test_nested_identity_and_assurance_shapes_are_enforced(
    target: str, field: str, malformed: object, check_id: str
) -> None:
    record = _valid_composite_record()
    nested = record[target]
    assert isinstance(nested, dict)
    nested[field] = malformed

    report = verify_record(record)

    assert _check(report, check_id)["status"] == "fail"


def test_diagnostics_are_bounded() -> None:
    record = _valid_composite_record()
    record["diagnostics"] = "x" * 2001

    report = verify_record(record)

    assert _check(report, "envelope.shape")["status"] == "fail"


def test_pack_assurance_requires_the_complete_nested_contract() -> None:
    record = _valid_composite_record()
    assurance = record["assurance"]
    assert isinstance(assurance, dict)
    pack = assurance["verifier_pack"]
    assert isinstance(pack, dict)
    del pack["secrecy"]

    report = verify_record(record)

    assert _check(report, "assurance.shape")["status"] == "fail"


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("missing", None),
        ("timeout", True),
        ("min_diff_coverage", float("inf")),
        pytest.param(
            "min_diff_coverage", 10**10000, id="min-diff-coverage-huge-int"
        ),
    ],
)
def test_effective_policy_requires_all_24_typed_fields(
    mutation: str, value: object
) -> None:
    record = _valid_composite_record()
    attestation = record["attestation"]
    assert isinstance(attestation, dict)
    policy = attestation["effective_policy"]
    assert isinstance(policy, dict)
    if mutation == "missing":
        del policy["allow"]
    else:
        policy[mutation] = value

    report = verify_record(record)

    assert _check(report, "policy.contract")["status"] == "fail"


def test_protected_violations_are_exclusive_to_rejected_verdicts() -> None:
    record = _valid_composite_record()
    record["protected_violations"] = ["tests/test_guard.py"]

    report = verify_record(record)

    assert _check(report, "verdict.protected_violations")["status"] == "fail"


def test_assurance_profile_cannot_upgrade_composite_report_integrity() -> None:
    record = _valid_composite_record()
    assurance = record["assurance"]
    assert isinstance(assurance, dict)
    assurance["report_integrity"] = "external_process_isolated"

    report = verify_record(record)

    assert _check(report, "assurance.lifecycle_profile")["status"] == "fail"


def test_real_below_threshold_record_passes_then_percent_forgery_fails(
    tmp_path: Path,
) -> None:
    _coverage_repo(tmp_path)
    candidate = (
        "<<<FILE: app.py>>>\n"
        "def covered(x):\n    return x + 1\n\n"
        "def uncovered(x):\n    return x - 2\n"
        "<<<END FILE>>>\n"
    )
    record = guard(
        str(tmp_path),
        candidate,
        diff_coverage=True,
        min_diff_coverage=80.0,
    ).to_dict()

    assert record["reason_code"] == "diff_coverage_below_threshold"
    assert verify_record(record)["ok"] is True
    zero_count_record = copy.deepcopy(record)
    zero_count_record["tests_passed"] = 0
    zero_count_record["tests_total"] = 0
    zero_count_report = verify_record(zero_count_record)
    assert zero_count_report["ok"] is False
    assert (
        _check(zero_count_report, "diff_coverage.policy_semantics")["status"]
        == "fail"
    )

    coverage = record["diff_coverage"]
    assert isinstance(coverage, dict)
    coverage["percent"] = 100.0

    report = verify_record(record)

    assert report["ok"] is False
    assert _check(report, "diff_coverage.shape")["status"] == "fail"
    assert _check(report, "diff_coverage.policy_semantics")["status"] == "fail"


def test_real_fix_gate_record_passes_then_demonstrated_effect_forgery_fails(
    tmp_path: Path,
) -> None:
    _coverage_repo(tmp_path)
    candidate = (
        "<<<FILE: app.py>>>\n"
        "def covered(x):\n    return x + 1\n\n"
        "def uncovered(x):\n    return x - 1\n"
        "<<<END FILE>>>\n"
    )
    record = guard(
        str(tmp_path), candidate, require_demonstrated_fix=True
    ).to_dict()

    assert record["reason_code"] == "fix_not_demonstrated"
    assert verify_record(record)["ok"] is True
    baseline = record["baseline"]
    assert isinstance(baseline, dict)
    baseline["repair_effect"] = "demonstrated"

    report = verify_record(record)

    assert report["ok"] is False
    assert _check(report, "baseline.policy_semantics")["status"] == "fail"


def test_real_coverage_gated_pass_requires_its_measured_evidence(tmp_path: Path) -> None:
    _coverage_repo(tmp_path)
    candidate = (
        "<<<FILE: app.py>>>\n"
        "def covered(x):\n    return 1 + x\n\n"
        "def uncovered(x):\n    return x - 1\n"
        "<<<END FILE>>>\n"
    )
    record = guard(
        str(tmp_path),
        candidate,
        diff_coverage=True,
        min_diff_coverage=80.0,
    ).to_dict()

    assert record["verdict"] == "PASS"
    assert verify_record(record)["ok"] is True
    record["diff_coverage"] = None

    report = verify_record(record)

    assert report["ok"] is False
    assert _check(report, "diff_coverage.policy_semantics")["status"] == "fail"


def test_required_unmeasured_coverage_record_is_a_valid_assurance_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _coverage_repo(tmp_path)
    candidate = (
        "<<<FILE: app.py>>>\n"
        "def covered(x):\n    return 1 + x\n\n"
        "def uncovered(x):\n    return x - 1\n"
        "<<<END FILE>>>\n"
    )
    monkeypatch.setattr(
        evidence,
        "collect_diff_coverage",
        lambda *_args, **_kwargs: {
            "measured": False,
            "note": "coverage report was unavailable",
            "unmeasured_files": [],
            "caveat": evidence.EXECUTED_IS_NOT_ASSERTED,
        },
    )

    record = guard(
        str(tmp_path),
        candidate,
        diff_coverage=True,
        min_diff_coverage=80.0,
    ).to_dict()
    report = verify_record(record)

    assert record["verdict"] == "ERROR"
    assert record["reason_code"] == "assurance_requirement_not_met"
    assert report["ok"] is True, [
        check for check in report["checks"] if check["status"] == "fail"
    ]
    assert _check(report, "diff_coverage.policy_semantics")["status"] == "pass"
    assert _check(report, "policy.assurance_floors")["status"] == "pass"


@pytest.mark.parametrize(
    ("floor", "value"),
    [
        ("require_report_integrity", "external_process_isolated"),
        ("require_candidate_isolation", "docker"),
    ],
)
def test_pass_cannot_claim_less_than_a_required_assurance_floor(
    floor: str, value: str
) -> None:
    record = _valid_composite_record()
    policy = _refresh_policy_digest(record)
    policy[floor] = value
    _refresh_policy_digest(record)

    report = verify_record(record)

    assert report["ok"] is False
    assert _check(report, "policy.assurance_floors")["status"] == "fail"


def test_completed_assurance_shortfall_reason_requires_an_actual_floor_gap() -> None:
    record = _valid_composite_record()
    record.update(
        {
            "verdict": "ERROR",
            "passed": False,
            "exit_code": 1,
            "reason_code": "assurance_requirement_not_met",
        }
    )

    without_floor = verify_record(record)
    assert _check(without_floor, "policy.assurance_floors")["status"] == "fail"

    policy = _refresh_policy_digest(record)
    policy["require_report_integrity"] = "external_process_isolated"
    _refresh_policy_digest(record)
    with_floor = verify_record(record)
    assert _check(with_floor, "policy.assurance_floors")["status"] == "pass"


def test_pass_must_match_the_expected_verifier_pack_digest() -> None:
    record = _valid_composite_record()
    policy = _refresh_policy_digest(record)
    policy["expect_verifier_pack_sha256"] = "d" * 64
    _refresh_policy_digest(record)

    report = verify_record(record)

    assert report["ok"] is False
    assert _check(report, "policy.pack_digest_pin")["status"] == "fail"


def test_machine_readable_schema_is_valid_json() -> None:
    with open(
        "evoom_guard/schemas/verdict-record-1.11.schema.json", encoding="utf-8"
    ) as stream:
        schema = json.load(stream)

    Draft202012Validator.check_schema(schema)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["schema_version"]["const"] == SCHEMA_VERSION
    assert set(schema["required"]) >= {
        "schema_version",
        "assurance",
        "attestation",
        "execution_state",
    }
    effective_policy = schema["$defs"]["effectivePolicy"]
    assert len(effective_policy["required"]) == 24
    assert effective_policy["additionalProperties"] is False
    assert schema["$defs"]["packAssurance"]["properties"]["integrity"]["enum"]
    assert schema["properties"]["diff_coverage"]["oneOf"][0]["$ref"] == (
        "#/$defs/diffCoverage"
    )
    assert schema["properties"]["baseline"]["oneOf"][0]["$ref"] == (
        "#/$defs/baseline"
    )
    assert schema["properties"]["diagnostics"]["maxLength"] == 2000
    assert SUPPORTED_SCHEMA_VERSIONS == frozenset({"1.11"})


def test_valid_record_matches_schema_and_required_field_mutation_does_not() -> None:
    schema_path = Path("evoom_guard/schemas/verdict-record-1.11.schema.json")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    record = _valid_composite_record()

    validator.validate(record)
    del record["execution_state"]

    errors = list(validator.iter_errors(record))
    assert any(error.validator == "required" for error in errors)


def test_mutations_do_not_modify_the_fixture_factory() -> None:
    first = _valid_composite_record()
    second = copy.deepcopy(first)
    second["verdict"] = "FAIL"

    assert _valid_composite_record()["verdict"] == "PASS"
