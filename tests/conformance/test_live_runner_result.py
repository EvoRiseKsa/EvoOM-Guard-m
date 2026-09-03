"""Regression coverage for exact live-runner matrix evidence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from tools.conformance import live_runner_result
from tools.conformance.live_runner_result import (
    LiveRunnerResultError,
    build_result,
    load_result,
    parse_exact_junit,
    validate_result,
    verify_result,
    write_result,
)

ROOT = Path(__file__).parents[2]
EXPECTED_NAMES = (
    "test_pytest_honest_fix_is_pass_with_junit_source",
    "test_pytest_broken_fix_is_fail_with_real_counts",
    "test_pytest_protected_test_rewrite_is_rejected_before_execution",
    "test_parse_node_toplevel_cases_no_suite_wrapper",
    "test_parse_node_mixed_suite_and_toplevel_counts_all_cases",
    "test_parse_node_skipped_excluded_from_total",
    "test_pytest_suite_attribute_fallback_still_works",
    "test_node_test_honest_fix_is_pass_with_junit_source",
    "test_node_test_broken_fix_is_fail_with_real_counts",
    "test_parse_vitest_junit_counts",
    "test_vitest_honest_fix_is_pass_with_junit_source",
    "test_vitest_broken_fix_is_fail_with_real_counts",
    "test_vitest_baseline_and_candidate_resolve_the_same_runner",
)


def _junit(*, mutation: str = "") -> bytes:
    cases = "".join(f'<testcase name="{name}">{mutation}</testcase>' for name in EXPECTED_NAMES)
    return f'<?xml version="1.0"?><testsuites><testsuite>{cases}</testsuite></testsuites>'.encode()


def test_exact_junit_requires_every_live_oracle_without_skip() -> None:
    parsed = parse_exact_junit(_junit())
    assert parsed["tests"] == 13
    assert parsed["skipped"] == 0
    assert parsed["test_names"] == sorted(EXPECTED_NAMES)

    with pytest.raises(LiveRunnerResultError, match="not clean"):
        parse_exact_junit(_junit(mutation="<skipped/>"))
    with pytest.raises(LiveRunnerResultError, match="differs"):
        parse_exact_junit(
            _junit().replace(EXPECTED_NAMES[0].encode(), b"test_missing_contract")
        )


def test_junit_rejects_duplicate_names_and_entity_declarations() -> None:
    duplicate = _junit().replace(EXPECTED_NAMES[1].encode(), EXPECTED_NAMES[0].encode())
    with pytest.raises(LiveRunnerResultError, match="unique"):
        parse_exact_junit(duplicate)
    with pytest.raises(LiveRunnerResultError, match="DTD/entity"):
        parse_exact_junit(b"<!DOCTYPE x><testsuites/>")


def test_build_write_load_verify_pipeline_rejects_later_junit_or_source_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    junit_path = tmp_path / "live.xml"
    result_path = tmp_path / "live.json"
    junit_path.write_bytes(_junit())
    source = ({relative: {"sha256": "3" * 64, "size": 1} for relative in live_runner_result._SOURCE_PATHS}, "4" * 64)
    environment = {
        "matrix_os": "ubuntu-latest",
        "matrix_python": "3.12",
        "node": "v22.0.0",
        "python": "3.12.0",
        "python_packages_count": 1,
        "python_packages_sha256": "5" * 64,
        "pytest_plugin_autoload_disabled": True,
        "runner_arch": "X64",
        "runner_environment": "github-hosted",
        "runner_image": "ubuntu24",
        "runner_image_version": "20260901.1",
        "runner_os": "Linux",
        "vitest": "vitest/4.1.10",
    }
    execution = {
        "event_name": "pull_request",
        "git_commit": "1" * 40,
        "git_tree": "2" * 40,
        "repository": "EvoRiseKsa/EvoOM-Guard-m",
        "ref": "refs/pull/1/merge",
        "run_attempt": "1",
        "run_id": "1",
        "sha": "1" * 40,
        "workflow_ref": "EvoRiseKsa/EvoOM-Guard-m/.github/workflows/runner-live-conformance.yml@refs/pull/1/merge",
        "workflow_sha": "3" * 40,
    }
    monkeypatch.setattr(live_runner_result, "_source_inventory", lambda: source)
    monkeypatch.setattr(live_runner_result, "_environment_identity", lambda: environment)
    monkeypatch.setattr(live_runner_result, "_execution_identity", lambda: execution)

    write_result(build_result(junit_path), result_path)
    retained = load_result(result_path)
    verify_result(retained, junit_path)

    junit_path.write_bytes(_junit().replace(b"?>", b"?>\n", 1))
    with pytest.raises(LiveRunnerResultError, match="differs from current exact evidence"):
        verify_result(retained, junit_path)
    junit_path.write_bytes(_junit())
    monkeypatch.setattr(
        live_runner_result,
        "_source_inventory",
        lambda: (source[0], "6" * 64),
    )
    with pytest.raises(LiveRunnerResultError, match="differs from current exact evidence"):
        verify_result(retained, junit_path)


def test_execution_identity_binds_event_ref_workflow_and_checked_out_sha(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = {
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REF": "refs/pull/7/merge",
        "GITHUB_REPOSITORY": "EvoRiseKsa/EvoOM-Guard-m",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_RUN_ID": "73",
        "GITHUB_SHA": "1" * 40,
        "GITHUB_WORKFLOW_REF": (
            "EvoRiseKsa/EvoOM-Guard-m/.github/workflows/"
            "runner-live-conformance.yml@refs/pull/7/merge"
        ),
        "GITHUB_WORKFLOW_SHA": "3" * 40,
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(
        live_runner_result, "_git_state", lambda: ("1" * 40, "2" * 40, False)
    )

    identity = live_runner_result._execution_identity()
    assert identity["git_commit"] == identity["sha"] == "1" * 40

    monkeypatch.setattr(
        live_runner_result, "_git_state", lambda: ("2" * 40, "3" * 40, False)
    )
    with pytest.raises(LiveRunnerResultError, match="differs from GITHUB_SHA"):
        live_runner_result._execution_identity()

    monkeypatch.setattr(
        live_runner_result, "_git_state", lambda: ("1" * 40, "2" * 40, True)
    )
    with pytest.raises(LiveRunnerResultError, match="tracked source changed"):
        live_runner_result._execution_identity()

    monkeypatch.setattr(
        live_runner_result, "_git_state", lambda: ("1" * 40, "2" * 40, False)
    )
    monkeypatch.setenv("GITHUB_WORKFLOW_REF", values["GITHUB_WORKFLOW_REF"] + "-other")
    with pytest.raises(LiveRunnerResultError, match="execution ref disagree"):
        live_runner_result._execution_identity()


def test_environment_identity_requires_github_hosted_x64_and_plugin_isolation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = {
        "EVOGUARD_MATRIX_OS": "ubuntu-latest",
        "EVOGUARD_MATRIX_PYTHON": "3.12",
        "ImageOS": "ubuntu24",
        "ImageVersion": "20260901.1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "RUNNER_ARCH": "X64",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(live_runner_result.platform, "python_version", lambda: "3.12.9")
    monkeypatch.setattr(
        live_runner_result,
        "_bounded_version",
        lambda argv, *, label: "v22.1.0" if label == "Node" else "vitest/4.1.10",
    )
    monkeypatch.setattr(
        live_runner_result, "_python_packages_identity", lambda: (7, "a" * 64)
    )

    identity = live_runner_result._environment_identity()
    assert identity["runner_environment"] == "github-hosted"
    assert identity["runner_arch"] == "X64"
    assert identity["python_packages_count"] == 7
    assert identity["pytest_plugin_autoload_disabled"] is True

    monkeypatch.setenv("RUNNER_ENVIRONMENT", "self-hosted")
    with pytest.raises(LiveRunnerResultError, match="GitHub-hosted"):
        live_runner_result._environment_identity()


def test_result_writer_is_create_only_and_loader_rejects_tamper(tmp_path: Path) -> None:
    result = {
        "$schema": "tools/conformance/live-runner-result.schema.json",
        "claims": {
            "external_runner_suites_executed": True,
            "hostile_code_production": False,
            "independent_evaluation": False,
            "matrix_cell_only": True,
        },
        "environment": {
            "matrix_os": "ubuntu-latest",
            "matrix_python": "3.12",
            "node": "v22.0.0",
            "python": "3.12.0",
            "python_packages_count": 1,
            "python_packages_sha256": "5" * 64,
            "pytest_plugin_autoload_disabled": True,
            "runner_arch": "X64",
            "runner_environment": "github-hosted",
            "runner_image": "ubuntu24",
            "runner_image_version": "20260901.1",
            "runner_os": "Linux",
            "vitest": "vitest/4.1.10",
        },
        "execution": {
            "event_name": "pull_request",
            "git_commit": "1" * 40,
            "git_tree": "2" * 40,
            "repository": "EvoRiseKsa/EvoOM-Guard-m",
            "ref": "refs/pull/1/merge",
            "run_attempt": "1",
            "run_id": "1",
            "sha": "1" * 40,
            "workflow_ref": "EvoRiseKsa/EvoOM-Guard-m/.github/workflows/runner-live-conformance.yml@refs/pull/1/merge",
            "workflow_sha": "3" * 40,
        },
        "schema_version": "evoguard-live-runner-conformance-v1",
        "source": {
            "aggregate_sha256": "2" * 64,
            "reviewed_files": {
                relative: {"sha256": "3" * 64, "size": 1}
                for relative in (
                    ".github/workflows/runner-live-conformance.yml",
                    "evoom_guard/runners/node_test.py",
                    "evoom_guard/runners/pytest.py",
                    "evoom_guard/runners/vitest.py",
                    "evoom_guard/verifiers/repo_verifier.py",
                    "tests/test_node_oracle.py",
                    "tests/test_pytest_oracle.py",
                    "tests/test_vitest_oracle.py",
                    "requirements/ci.lock",
                    "tools/ci-vitest/package-lock.json",
                    "tools/ci-vitest/package.json",
                    "tools/conformance/secure_io.py",
                    "tools/conformance/live_runner_result.py",
                    "tools/conformance/run_live_runner_conformance.py",
                    "pyproject.toml",
                    "tools/conformance/live-runner-result.schema.json",
                )
            },
        },
        "status": "pass",
        "status_basis": "real_guard_oracle_tests_only",
        "suite": {
            "errors": 0,
            "failures": 0,
            "junit_sha256": "4" * 64,
            "junit_size": 1,
            "skipped": 0,
            "test_names": sorted(EXPECTED_NAMES),
            "tests": 13,
        },
    }
    path = tmp_path / "result.json"
    write_result(result, path)
    with pytest.raises(FileExistsError):
        write_result(result, path)

    loaded = json.loads(path.read_text(encoding="utf-8"))
    loaded["status"] = "fail"
    path.write_text(json.dumps(loaded, sort_keys=True, separators=(",", ":")) + "\n")
    with pytest.raises(LiveRunnerResultError, match="status"):
        load_result(path)

    result["execution"]["workflow_ref"] = "owner/repo/.github/workflows/fake.yml@main"
    with pytest.raises(LiveRunnerResultError, match="workflow_ref"):
        validate_result(result)

    result["execution"]["workflow_ref"] = (
        "EvoRiseKsa/EvoOM-Guard-m/.github/workflows/"
        "runner-live-conformance.yml@refs/pull/1/merge"
    )
    result["environment"]["node"] = "v24.0.0"
    with pytest.raises(LiveRunnerResultError, match="not Node 22"):
        validate_result(result)
    result["environment"]["node"] = "v22.1." + ("1" * 4091)
    with pytest.raises(LiveRunnerResultError, match="node is oversized"):
        validate_result(result)
    result["environment"]["node"] = "v22.0.0"
    result["environment"]["vitest"] = "vitest/4.1.10 " + ("x" * 4083)
    with pytest.raises(LiveRunnerResultError, match="vitest is oversized"):
        validate_result(result)
    result["environment"]["vitest"] = "vitest/4.1.10"
    result["suite"]["junit_size"] = live_runner_result.MAX_JUNIT_BYTES + 1
    with pytest.raises(LiveRunnerResultError, match="JUnit byte limit"):
        validate_result(result)


@pytest.mark.parametrize(
    ("claim", "numeric_value"),
    (
        ("external_runner_suites_executed", 1),
        ("hostile_code_production", 0),
        ("independent_evaluation", 0),
        ("matrix_cell_only", 1),
    ),
)
def test_loader_rejects_numeric_claims_that_compare_equal_to_booleans(
    tmp_path: Path,
    claim: str,
    numeric_value: int,
) -> None:
    result_path = tmp_path / "result.json"
    schema = json.loads(
        (ROOT / "tools" / "conformance" / "live-runner-result.schema.json").read_text(
            encoding="utf-8"
        )
    )

    # Start from the complete, already closed fixture used by the writer test.
    result = {
        "$schema": "tools/conformance/live-runner-result.schema.json",
        "claims": {
            "external_runner_suites_executed": True,
            "hostile_code_production": False,
            "independent_evaluation": False,
            "matrix_cell_only": True,
        },
        "environment": {
            "matrix_os": "ubuntu-latest",
            "matrix_python": "3.12",
            "node": "v22.0.0",
            "python": "3.12.0",
            "python_packages_count": 1,
            "python_packages_sha256": "5" * 64,
            "pytest_plugin_autoload_disabled": True,
            "runner_arch": "X64",
            "runner_environment": "github-hosted",
            "runner_image": "ubuntu24",
            "runner_image_version": "20260901.1",
            "runner_os": "Linux",
            "vitest": "vitest/4.1.10",
        },
        "execution": {
            "event_name": "pull_request",
            "git_commit": "1" * 40,
            "git_tree": "2" * 40,
            "repository": "EvoRiseKsa/EvoOM-Guard-m",
            "ref": "refs/pull/1/merge",
            "run_attempt": "1",
            "run_id": "1",
            "sha": "1" * 40,
            "workflow_ref": "EvoRiseKsa/EvoOM-Guard-m/.github/workflows/runner-live-conformance.yml@refs/pull/1/merge",
            "workflow_sha": "3" * 40,
        },
        "schema_version": "evoguard-live-runner-conformance-v1",
        "source": {
            "aggregate_sha256": "2" * 64,
            "reviewed_files": {
                relative: {"sha256": "3" * 64, "size": 1}
                for relative in live_runner_result._SOURCE_PATHS
            },
        },
        "status": "pass",
        "status_basis": "real_guard_oracle_tests_only",
        "suite": {
            "errors": 0,
            "failures": 0,
            "junit_sha256": "4" * 64,
            "junit_size": 1,
            "skipped": 0,
            "test_names": sorted(EXPECTED_NAMES),
            "tests": 13,
        },
    }
    result["claims"][claim] = numeric_value
    result_path.write_text(
        json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(LiveRunnerResultError, match="claim boundary"):
        load_result(result_path)
    with pytest.raises(LiveRunnerResultError, match="claim boundary"):
        verify_result(result, tmp_path / "not-read-before-claim-validation.xml")
    assert list(Draft202012Validator(schema).iter_errors(result))


def test_live_workflow_has_exact_matrix_and_fail_closed_aggregate() -> None:
    text = (ROOT / ".github" / "workflows" / "runner-live-conformance.yml").read_text(
        encoding="utf-8"
    )

    assert text.count("os: ubuntu-latest") == 3
    assert text.count("os: windows-latest") == 1
    assert "tests/test_pytest_oracle.py" in text
    assert "tests/test_node_oracle.py" in text
    assert "tests/test_vitest_oracle.py" in text
    assert "--verify \"${{ runner.temp }}/live-runner.json\"" in text
    assert "id: retain" in text
    assert "steps.retain.outputs.artifact-id" in text
    assert "steps.retain.outputs.artifact-digest" in text
    assert (
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
        in text
    )
    assert "digest-mismatch: error" in text
    assert "retained-live-runner/live-runner.xml" in text
    assert "retained-live-runner/live-runner.json" in text
    assert text.count("tools.conformance.run_live_runner_conformance") == 3
    assert 'run: test "$LIVE_RESULT" = "success"' in text
    assert "retention-days: 30" in text
    assert "timeout-minutes: 30" in text
    assert "timeout-minutes: 5" in text
