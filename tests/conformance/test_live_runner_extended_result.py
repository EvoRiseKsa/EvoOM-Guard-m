"""Regression coverage for exact extended live-runner evidence."""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from tools.conformance import (
    live_runner_extended_result,
    run_live_runner_extended_conformance,
)
from tools.conformance.live_runner_extended_result import (
    LiveRunnerExtendedResultError,
    build_result,
    load_result,
    parse_exact_junit,
    validate_result,
    verify_result,
    write_result,
)

ROOT = Path(__file__).parents[2]
EXPECTED_NAMES = tuple(
    sorted(
        {
            "test_extended_parse_jest_junit_counts",
            "test_extended_jest_honest_fix_is_pass",
            "test_extended_jest_broken_fix_is_fail",
            "test_extended_jest_protected_test_rewrite_is_rejected",
            "test_extended_parse_gotestsum_junit_counts",
            "test_extended_gotestsum_honest_fix_is_pass",
            "test_extended_gotestsum_broken_fix_is_fail",
            "test_extended_gotestsum_green_baseline_remains_green_with_private_cache",
            "test_extended_parse_rspec_junit_counts",
            "test_extended_rspec_honest_fix_is_pass",
            "test_extended_rspec_broken_fix_is_fail",
            "test_extended_parse_mocha_junit_counts",
            "test_extended_mocha_honest_fix_is_pass",
            "test_extended_mocha_broken_fix_is_fail",
            "test_extended_parse_maven_junit_counts",
            "test_extended_maven_honest_fix_is_pass",
            "test_extended_maven_broken_fix_is_fail",
            "test_extended_shell_honest_fix_is_pass",
            "test_extended_shell_broken_fix_is_fail",
        }
    )
)


def _junit(*, mutation: str = "") -> bytes:
    cases = "".join(
        f'<testcase name="{name}">{mutation}</testcase>' for name in EXPECTED_NAMES
    )
    return (
        '<?xml version="1.0"?><testsuites>'
        f'<testsuite tests="{len(EXPECTED_NAMES)}" failures="0" '
        f'errors="0" skipped="0">{cases}'
        "</testsuite></testsuites>"
    ).encode()


def _tools(runner_os: str = "Linux") -> dict[str, str]:
    return {
        "bash_path": (
            "/usr/bin/bash"
            if runner_os == "Linux"
            else r"C:\Program Files\Git\bin\bash.exe"
        ),
        "bash_version": (
            "GNU bash, version 5.2.21(1)-release (x86_64-pc-linux-gnu)"
            if runner_os == "Linux"
            else "GNU bash, version 5.2.37(1)-release (x86_64-pc-msys)"
        ),
        "bundler": "4.0.20",
        "go": "1.27.1",
        "gotestsum": "1.13.0",
        "java": "21.0.9",
        "jest_cli": "30.5.0",
        "jest_junit": "17.0.0",
        "jest_package": "30.5.1",
        "maven": "3.9.16",
        "mocha": "12.0.0",
        "node": "22.23.2",
        "rspec": "3.13.2",
        "rspec_junit_formatter": "0.6.0",
        "ruby": "3.4.10",
    }


def _environment(matrix_os: str = "ubuntu-latest") -> dict[str, Any]:
    runner_os = "Linux" if matrix_os == "ubuntu-latest" else "Windows"
    return {
        "matrix_os": matrix_os,
        "matrix_python": "3.12.10",
        "python": "3.12.10",
        "python_packages_count": 17,
        "python_packages_sha256": "5" * 64,
        "pytest_plugin_autoload_disabled": True,
        "runner_arch": "X64",
        "runner_environment": "github-hosted",
        "runner_image": "ubuntu24" if runner_os == "Linux" else "win22",
        "runner_image_version": "20260901.1",
        "runner_os": runner_os,
        "tools": _tools(runner_os),
    }


def _execution() -> dict[str, str]:
    ref = "refs/pull/7/merge"
    return {
        "event_name": "pull_request",
        "git_commit": "1" * 40,
        "git_tree": "2" * 40,
        "repository": "EvoRiseKsa/EvoOM-Guard-m",
        "ref": ref,
        "run_attempt": "1",
        "run_id": "73",
        "sha": "1" * 40,
        "workflow_ref": (
            "EvoRiseKsa/EvoOM-Guard-m/.github/workflows/"
            f"runner-live-conformance.yml@{ref}"
        ),
        "workflow_sha": "3" * 40,
    }


def _source() -> tuple[dict[str, dict[str, Any]], str]:
    return (
        {
            relative: {"sha256": "3" * 64, "size": 1}
            for relative in live_runner_extended_result._SOURCE_PATHS
        },
        "4" * 64,
    )


def _result() -> dict[str, Any]:
    source, aggregate = _source()
    return {
        "$schema": "tools/conformance/live-runner-extended-result.schema.json",
        "claims": {
            "external_runner_suites_executed": True,
            "hostile_code_production": False,
            "independent_evaluation": False,
            "matrix_cell_only": True,
        },
        "environment": _environment(),
        "execution": _execution(),
        "schema_version": "evoguard-live-runner-extended-conformance-v1",
        "source": {"aggregate_sha256": aggregate, "reviewed_files": source},
        "status": "pass",
        "status_basis": "real_extended_guard_oracle_tests_only",
        "suite": {
            "errors": 0,
            "failures": 0,
            "junit_sha256": "6" * 64,
            "junit_size": 1,
            "skipped": 0,
            "test_names": list(EXPECTED_NAMES),
            "tests": len(EXPECTED_NAMES),
        },
    }


def test_exact_junit_requires_all_19_oracles_without_nonpass_outcomes() -> None:
    parsed = parse_exact_junit(_junit())
    assert parsed == {
        "errors": 0,
        "failures": 0,
        "skipped": 0,
        "test_names": list(EXPECTED_NAMES),
        "tests": len(EXPECTED_NAMES),
    }

    for element in ("failure", "error", "skipped"):
        with pytest.raises(LiveRunnerExtendedResultError, match="not clean"):
            parse_exact_junit(_junit(mutation=f"<{element}/>") )

    changed = _junit().replace(EXPECTED_NAMES[0].encode(), b"test_unreviewed_oracle")
    with pytest.raises(LiveRunnerExtendedResultError, match="differs"):
        parse_exact_junit(changed)


def test_junit_rejects_missing_extra_duplicate_wrong_root_and_entities() -> None:
    first_case = f'<testcase name="{EXPECTED_NAMES[0]}"></testcase>'.encode()
    with pytest.raises(LiveRunnerExtendedResultError, match="differs"):
        parse_exact_junit(_junit().replace(first_case, b"", 1))

    extra = _junit().replace(
        b"</testsuite>", b'<testcase name="test_extra"/></testsuite>', 1
    )
    with pytest.raises(LiveRunnerExtendedResultError, match="differs"):
        parse_exact_junit(extra)

    duplicate = _junit().replace(EXPECTED_NAMES[1].encode(), EXPECTED_NAMES[0].encode())
    with pytest.raises(LiveRunnerExtendedResultError, match="unique"):
        parse_exact_junit(duplicate)
    with pytest.raises(LiveRunnerExtendedResultError, match="root"):
        parse_exact_junit(b"<testsuite/>")
    with pytest.raises(LiveRunnerExtendedResultError, match="DTD/entity"):
        parse_exact_junit(b"<!DOCTYPE x><testsuites/>")

    declared_failure = _junit().replace(b'failures="0"', b'failures="1"', 1)
    with pytest.raises(LiveRunnerExtendedResultError, match="testsuite.failures"):
        parse_exact_junit(declared_failure)

    missing_counter = _junit().replace(b' skipped="0"', b"", 1)
    with pytest.raises(LiveRunnerExtendedResultError, match="testsuite.skipped"):
        parse_exact_junit(missing_counter)


def test_pipeline_rederives_junit_source_environment_and_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    junit_path = tmp_path / "extended.xml"
    result_path = tmp_path / "extended.json"
    junit_path.write_bytes(_junit())
    source = _source()
    environment = _environment()
    execution = _execution()
    monkeypatch.setattr(
        live_runner_extended_result,
        "_source_inventory",
        lambda: copy.deepcopy(source),
    )
    monkeypatch.setattr(
        live_runner_extended_result,
        "_environment_identity",
        lambda: copy.deepcopy(environment),
    )
    monkeypatch.setattr(
        live_runner_extended_result,
        "_execution_identity",
        lambda: copy.deepcopy(execution),
    )

    write_result(build_result(junit_path), result_path)
    retained = load_result(result_path)
    verify_result(retained, junit_path)

    junit_path.write_bytes(_junit().replace(b"?>", b"?>\n", 1))
    with pytest.raises(LiveRunnerExtendedResultError, match="current exact"):
        verify_result(retained, junit_path)
    junit_path.write_bytes(_junit())

    source = (source[0], "7" * 64)
    with pytest.raises(LiveRunnerExtendedResultError, match="current exact"):
        verify_result(retained, junit_path)
    source = _source()

    environment["runner_image_version"] = "20260902.1"
    with pytest.raises(LiveRunnerExtendedResultError, match="current exact"):
        verify_result(retained, junit_path)
    environment = _environment()

    execution["run_attempt"] = "2"
    with pytest.raises(LiveRunnerExtendedResultError, match="current exact"):
        verify_result(retained, junit_path)


def test_execution_identity_binds_ref_run_sha_tree_and_clean_checkout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = {
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REF": "refs/pull/7/merge",
        "GITHUB_REPOSITORY": "EvoRiseKsa/EvoOM-Guard-m",
        "GITHUB_RUN_ATTEMPT": "2",
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
        live_runner_extended_result,
        "_git_state",
        lambda: ("1" * 40, "2" * 40, False),
    )

    identity = live_runner_extended_result._execution_identity()
    assert identity["run_id"] == "73"
    assert identity["run_attempt"] == "2"
    assert identity["git_tree"] == "2" * 40

    monkeypatch.setattr(
        live_runner_extended_result,
        "_git_state",
        lambda: ("4" * 40, "2" * 40, False),
    )
    with pytest.raises(LiveRunnerExtendedResultError, match="differs from GITHUB_SHA"):
        live_runner_extended_result._execution_identity()

    monkeypatch.setattr(
        live_runner_extended_result,
        "_git_state",
        lambda: ("1" * 40, "2" * 40, True),
    )
    with pytest.raises(LiveRunnerExtendedResultError, match="tracked source changed"):
        live_runner_extended_result._execution_identity()

    monkeypatch.setattr(
        live_runner_extended_result,
        "_git_state",
        lambda: ("1" * 40, "2" * 40, False),
    )
    monkeypatch.setenv("GITHUB_WORKFLOW_REF", values["GITHUB_WORKFLOW_REF"] + "-other")
    with pytest.raises(LiveRunnerExtendedResultError, match="execution ref disagree"):
        live_runner_extended_result._execution_identity()


@pytest.mark.parametrize(
    ("matrix_os", "runner_os"),
    (("ubuntu-latest", "Linux"), ("windows-latest", "Windows")),
)
def test_environment_identity_allows_only_two_exact_github_hosted_cells(
    matrix_os: str,
    runner_os: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = {
        "EVOGUARD_MATRIX_OS": matrix_os,
        "EVOGUARD_MATRIX_PYTHON": "3.12.10",
        "ImageOS": "image",
        "ImageVersion": "20260901.1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "RUNNER_ARCH": "X64",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": runner_os,
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(
        live_runner_extended_result.platform,
        "python_version",
        lambda: "3.12.10",
    )
    monkeypatch.setattr(
        live_runner_extended_result,
        "_python_packages_identity",
        lambda: (17, "5" * 64),
    )
    monkeypatch.setattr(
        live_runner_extended_result,
        "_tool_identity",
        lambda observed_os: _tools(observed_os),
    )

    identity = live_runner_extended_result._environment_identity()
    assert identity["matrix_os"] == matrix_os
    assert identity["matrix_python"] == identity["python"] == "3.12.10"
    assert identity["runner_os"] == runner_os
    assert identity["runner_arch"] == "X64"
    assert identity["runner_environment"] == "github-hosted"

    monkeypatch.setenv("EVOGUARD_MATRIX_PYTHON", "3.12")
    with pytest.raises(LiveRunnerExtendedResultError, match="exact Python 3.12.10"):
        live_runner_extended_result._environment_identity()


def test_tool_identity_requires_every_pinned_version_and_exact_maven_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mocha = tmp_path / "mocha"
    mocha.write_text("fixture", encoding="utf-8")
    monkeypatch.setenv("EVOGUARD_EXTENDED_MOCHA", str(mocha))
    monkeypatch.setattr(
        live_runner_extended_result,
        "_exact_local_node_tool",
        lambda name: str(mocha),
    )
    outputs = {
        "Bash": "unused",
        "Bundler": "4.0.20",
        "Go": "go version go1.27.1 linux/amd64",
        "gotestsum": "gotestsum version v1.13.0",
        "Java": (
            'openjdk version "21.0.9" 2025-10-21 LTS\n'
            "OpenJDK Runtime Environment Temurin-21.0.9+10 "
            "(build 21.0.9+10-LTS)"
        ),
        "Jest CLI": "30.5.0",
        "Maven": (
            "Apache Maven 3.9.16 "
            "(2bdd9fddda4b155ebf8000e807eb73fd829a51d5)\nMaven home: /maven"
        ),
        "Mocha": "12.0.0",
        "Node": "v22.23.2",
        "Ruby": "ruby 3.4.10 (2026-07-01 revision 1) +PRISM [x86_64-linux]",
    }
    commands: dict[str, tuple[str, ...]] = {}

    def bounded(
        argv: tuple[str, ...],
        *,
        label: str,
        cwd: Path = live_runner_extended_result.REPOSITORY_ROOT,
    ) -> str:
        del cwd
        commands[label] = argv
        return outputs[label]

    monkeypatch.setattr(live_runner_extended_result, "_bounded_version", bounded)
    monkeypatch.setattr(
        live_runner_extended_result,
        "_node_package_version",
        lambda package: {"jest": "30.5.1", "jest-junit": "17.0.0"}[package],
    )
    monkeypatch.setattr(
        live_runner_extended_result,
        "_ruby_package_version",
        lambda package: {
            "rspec": "3.13.2",
            "rspec_junit_formatter": "0.6.0",
        }[package],
    )
    monkeypatch.setattr(
        live_runner_extended_result,
        "_bash_identity",
        lambda runner_os: (
            "/usr/bin/bash",
            "GNU bash, version 5.2.21(1)-release (x86_64-pc-linux-gnu)",
        ),
    )

    assert live_runner_extended_result._tool_identity("Linux") == _tools()
    assert commands["Bundler"] == ("bundle", "--version")
    assert commands["Maven"] == ("mvn", "-o", "--version")

    outputs["Bundler"] = "Bundler version 4.0.20"
    with pytest.raises(LiveRunnerExtendedResultError, match="Bundler version"):
        live_runner_extended_result._tool_identity("Linux")
    outputs["Bundler"] = "4.0.20"

    outputs["Maven"] = "Apache Maven 3.9.16"
    with pytest.raises(LiveRunnerExtendedResultError, match="Maven version"):
        live_runner_extended_result._tool_identity("Linux")

    outputs["Maven"] = (
        "Apache Maven 3.9.16 "
        "(2bdd9fddda4b155ebf8000e807eb73fd829a51d5)"
    )
    outputs["Java"] = (
        'openjdk version "21.0.9" 2025-10-21 LTS\n'
        "OpenJDK Runtime Environment Temurin-21.0.9+11 (build 21.0.9+11-LTS)"
    )
    with pytest.raises(LiveRunnerExtendedResultError, match="Java build"):
        live_runner_extended_result._tool_identity("Linux")

    outputs["Java"] = 'openjdk version "21.0.9" 2025-10-21 LTS'
    with pytest.raises(LiveRunnerExtendedResultError, match="Java build"):
        live_runner_extended_result._tool_identity("Linux")


def test_ruby_package_identity_loads_the_locked_bundle_without_a_batch_wrapper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}

    def bounded(
        argv: tuple[str, ...],
        *,
        label: str,
        cwd: Path,
    ) -> str:
        observed.update(argv=argv, label=label, cwd=cwd)
        return "3.13.2"

    monkeypatch.setattr(live_runner_extended_result, "_bounded_version", bounded)

    assert live_runner_extended_result._ruby_package_version("rspec") == "3.13.2"
    assert observed == {
        "argv": (
            "ruby",
            "-rbundler/setup",
            "-e",
            "puts Gem.loaded_specs.fetch('rspec').version.to_s",
        ),
        "label": "rspec package",
        "cwd": live_runner_extended_result.RUBY_PROJECT,
    }


@pytest.mark.parametrize(
    ("runner_os", "expected_path", "version"),
    (
        (
            "Linux",
            "/usr/bin/bash",
            "GNU bash, version 5.2.21(1)-release (x86_64-pc-linux-gnu)",
        ),
        (
            "Windows",
            r"C:\Program Files\Git\bin\bash.exe",
            "GNU bash, version 5.2.37(1)-release (x86_64-pc-msys)",
        ),
    ),
)
def test_bash_identity_requires_the_cell_path_and_records_exact_version(
    runner_os: str,
    expected_path: str,
    version: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StubPath:
        def __init__(self, value: str) -> None:
            self.value = value

        def resolve(self, *, strict: bool) -> StubPath:
            assert strict is True
            return self

        def __str__(self) -> str:
            return self.value

    monkeypatch.setenv("EVOGUARD_EXTENDED_BASH", expected_path)
    monkeypatch.setattr(live_runner_extended_result, "Path", StubPath)
    monkeypatch.setattr(
        live_runner_extended_result,
        "_bounded_version",
        lambda argv, *, label: version,
    )
    assert live_runner_extended_result._bash_identity(runner_os) == (
        expected_path,
        version,
    )

    monkeypatch.setenv("EVOGUARD_EXTENDED_BASH", expected_path + ".other")
    with pytest.raises(LiveRunnerExtendedResultError, match="path"):
        live_runner_extended_result._bash_identity(runner_os)

    with pytest.raises(LiveRunnerExtendedResultError, match="runner OS"):
        live_runner_extended_result._bash_identity("Other")

def test_schema_and_python_validator_close_claims_tools_sources_and_names() -> None:
    schema = json.loads(
        (ROOT / "tools/conformance/live-runner-extended-result.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    result = _result()
    validate_result(result)
    assert not list(validator.iter_errors(result))
    assert tuple(result["suite"]["test_names"]) == EXPECTED_NAMES
    assert set(result["source"]["reviewed_files"]) == set(
        live_runner_extended_result._SOURCE_PATHS
    )

    mutations: list[dict[str, Any]] = []
    numeric_claim = copy.deepcopy(result)
    numeric_claim["claims"]["matrix_cell_only"] = 1
    mutations.append(numeric_claim)
    wrong_tool = copy.deepcopy(result)
    wrong_tool["environment"]["tools"]["java"] = "21.0.12"
    mutations.append(wrong_tool)
    crossed_cell = copy.deepcopy(result)
    crossed_cell["environment"]["runner_os"] = "Windows"
    mutations.append(crossed_cell)
    missing_source = copy.deepcopy(result)
    missing_source["source"]["reviewed_files"].pop(next(iter(missing_source["source"]["reviewed_files"])))
    mutations.append(missing_source)
    wrong_name = copy.deepcopy(result)
    wrong_name["suite"]["test_names"][0] = "test_unreviewed"
    mutations.append(wrong_name)
    extra_key = copy.deepcopy(result)
    extra_key["unexpected"] = True
    mutations.append(extra_key)

    for mutation in mutations:
        with pytest.raises(LiveRunnerExtendedResultError):
            validate_result(mutation)
        assert list(validator.iter_errors(mutation))


def test_source_contract_matches_schema_and_every_required_file_exists() -> None:
    schema = json.loads(
        (ROOT / "tools/conformance/live-runner-extended-result.schema.json").read_text(
            encoding="utf-8"
        )
    )
    schema_paths = schema["properties"]["source"]["properties"]["reviewed_files"][
        "propertyNames"
    ]["enum"]
    assert len(schema_paths) == len(set(schema_paths)) == 48
    assert set(schema_paths) == set(live_runner_extended_result._SOURCE_PATHS)
    assert all((ROOT / relative).is_file() for relative in schema_paths)
    assert "tools/conformance/live_runner_result.py" not in schema_paths


def test_writer_is_canonical_create_only_and_loader_rejects_tamper(
    tmp_path: Path,
) -> None:
    result = _result()
    path = tmp_path / "result.json"
    write_result(result, path)
    assert path.read_bytes() == (
        json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()
    assert load_result(path) == result
    with pytest.raises(FileExistsError):
        write_result(result, path)

    noncanonical = tmp_path / "noncanonical.json"
    noncanonical.write_text(json.dumps(result, indent=2), encoding="utf-8")
    with pytest.raises(LiveRunnerExtendedResultError, match="not canonical"):
        load_result(noncanonical)

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"status":"pass","status":"pass"}\n', encoding="utf-8")
    with pytest.raises(LiveRunnerExtendedResultError, match="duplicate JSON key"):
        load_result(duplicate)


def test_cli_delegates_create_and_verify_modes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    junit = tmp_path / "junit.xml"
    output = tmp_path / "result.json"
    retained = tmp_path / "retained.json"
    calls: list[tuple[object, ...]] = []
    result = _result()
    monkeypatch.setattr(
        run_live_runner_extended_conformance,
        "build_result",
        lambda path: calls.append(("build", path)) or result,
    )
    monkeypatch.setattr(
        run_live_runner_extended_conformance,
        "write_result",
        lambda value, path: calls.append(("write", value, path)),
    )
    assert (
        run_live_runner_extended_conformance.main(
            ["--junit", str(junit), "--output", str(output)]
        )
        == 0
    )
    assert calls == [("build", junit), ("write", result, output)]

    calls.clear()
    monkeypatch.setattr(
        run_live_runner_extended_conformance,
        "load_result",
        lambda path: calls.append(("load", path)) or result,
    )
    monkeypatch.setattr(
        run_live_runner_extended_conformance,
        "verify_result",
        lambda value, path: calls.append(("verify", value, path)),
    )
    assert (
        run_live_runner_extended_conformance.main(
            ["--junit", str(junit), "--verify", str(retained)]
        )
        == 0
    )
    assert calls == [("load", retained), ("verify", result, junit)]


def test_extended_workflow_has_exact_cells_pins_and_retained_reverification() -> None:
    text = (ROOT / ".github/workflows/runner-live-conformance.yml").read_text(
        encoding="utf-8"
    )
    match = re.search(
        r"(?ms)^  extended:\n(?P<extended>.*?)(?=^  runner-live-conformance:\n)",
        text,
    )
    assert match is not None
    extended = match.group("extended")

    assert extended.count("- os: ubuntu-latest") == 1
    assert extended.count("- os: windows-latest") == 1
    assert extended.count("- os:") == 2
    assert "bash: /usr/bin/bash" in extended
    assert r"bash: C:\Program Files\Git\bin\bash.exe" in extended
    assert "EVOGUARD_MATRIX_PYTHON: \"3.12.10\"" in extended
    assert "EVOGUARD_LIVE_EXTENDED: \"1\"" in extended
    job_environment = extended.split("    steps:\n", 1)[0]
    assert "${{ runner." not in job_environment
    assert "- name: Configure runner-local paths" in extended
    assert "shell: python" in extended
    for name, relative in (
        ("BUNDLE_PATH", "bundle"),
        ("EVOGUARD_EXTENDED_BUNDLE_PATH", "bundle"),
        ("EVOGUARD_EXTENDED_MAVEN_REPO", "maven-repository"),
        ("EVOGUARD_EXTENDED_NPM_CACHE", "npm-cache"),
        ("GOBIN", "go-bin"),
        ("GOCACHE", "go-build-cache"),
    ):
        assert f'"{name}": runner_temp / "{relative}"' in extended

    pins = (
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
        "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
        "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
        "actions/setup-java@dd06d9cba3e5552c54d9f8ea23572deb30010f7c",
        "ruby/setup-ruby@95ef2b042f9d7a56d8268cba8559e2842e2ad01b",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    )
    for pin in pins:
        assert extended.count(pin) == 1

    for setting in (
        'node-version: "22.23.2"',
        'python-version: "3.12.10"',
        'go-version: "1.27.1"',
        "distribution: temurin",
        'java-version: "21.0.9+10.0.LTS"',
        'ruby-version: "3.4.10"',
        'bundler: "4.0.20"',
        "go install gotest.tools/gotestsum",
        "npm ci --ignore-scripts --prefix tools/ci-live-runners/node",
        "bundle install --jobs 4 --retry 3",
        "fetch_live_runner_maven_cache",
        "verify_live_runner_maven_cache",
    ):
        assert setting in extended

    for oracle in (
        "tests/test_jest_live_oracle.py",
        "tests/test_gotestsum_live_oracle.py",
        "tests/test_rspec_live_oracle.py",
        "tests/test_mocha_live_oracle.py",
        "tests/test_maven_live_oracle.py",
        "tests/test_shell_live_oracle.py",
    ):
        assert extended.count(oracle) == 1

    assert extended.count("tools.conformance.run_live_runner_extended_conformance") == 3
    assert "id: retain-extended" in extended
    assert "steps.retain-extended.outputs.artifact-id" in extended
    assert "steps.retain-extended.outputs.artifact-digest" in extended
    assert "artifact-ids: ${{ steps.retain-extended.outputs.artifact-id }}" in extended
    assert "digest-mismatch: error" in extended
    assert "retained-live-runner-extended/live-runner-extended.xml" in extended
    assert "retained-live-runner-extended/live-runner-extended.json" in extended
    assert "if-no-files-found: error" in extended
    assert "retention-days: 30" in extended
    assert "continue-on-error" not in extended
    maven_commands = [
        line.strip()
        for line in extended.splitlines()
        if line.strip().startswith("mvn ")
    ]
    assert maven_commands
    assert all(" -o " in command for command in maven_commands)

    aggregate = text.split("\n  runner-live-conformance:\n", 1)[1]
    assert "if: always()" in aggregate
    assert "needs: [live, extended]" in aggregate
    assert "EXTENDED_RESULT: ${{ needs.extended.result }}" in aggregate
    assert "LIVE_RESULT: ${{ needs.live.result }}" in aggregate
    assert (
        'test "$LIVE_RESULT" = "success" && test "$EXTENDED_RESULT" = "success"'
        in aggregate
    )
