"""Adversarial contract tests for explicit, policy-bound harness inputs."""

from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import evoom_guard.blackbox as blackbox_module
import evoom_guard.cli as guard_cli
import evoom_guard.verifiers.repo_verifier as repo_verifier_module
from evoom_guard.evidence import collect_diff_coverage
from evoom_guard.guard import _run_baseline_suite, guard
from evoom_guard.policy import (
    ConfigError,
    HarnessInputPolicyError,
    build_effective_policy,
    effective_policy_payload,
    effective_policy_sha256,
    harness_input_path_conflicts,
    is_harness_input_path,
    load_config,
    normalize_harness_inputs,
    setup_output_harness_conflicts,
)
from evoom_guard.record_verifier import verify_record
from evoom_guard.verifiers.harness_policy import (
    candidate_path_targets_harness_input,
    is_safe_relpath,
    validate_harness_input_files,
)

_HARNESS_PATH = "ci/scripts/run-tests.py"


def _build_policy(*, harness_inputs: tuple[str, ...] = ()):
    return build_effective_policy(
        mode="repo",
        isolation="subprocess",
        docker_image=None,
        docker_network="none",
        test_command=None,
        setup_command=None,
        trust_setup_on_host=False,
        setup_output_globs=(),
        protected=(),
        allow=(),
        allow_new_tests=False,
        timeout=120,
        mem_limit_mb=1024,
        verifier_pack=None,
        expect_verifier_pack_sha256=None,
        blackbox=False,
        blackbox_only=False,
        require_report_integrity=None,
        require_candidate_isolation=None,
        min_diff_coverage=None,
        baseline_evidence=False,
        require_demonstrated_fix=False,
        strict_harness=False,
        policy_id=None,
        policy_version=None,
        harness_inputs=harness_inputs,
    )


def _make_harness_repo(root: Path) -> Path:
    harness = root / Path(*_HARNESS_PATH.split("/"))
    harness.parent.mkdir(parents=True)
    harness.write_text("# trusted judge wrapper\n", encoding="utf-8")
    (root / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    return harness


def _policy_schema_errors(
    version: str,
    policy: dict[str, object],
) -> list[str]:
    schema_path = (
        Path(__file__).parents[1]
        / "evoom_guard"
        / "schemas"
        / f"verdict-record-{version}.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    return [
        error.message
        for error in validator.descend(
            policy,
            schema["$defs"]["effectivePolicy"],
        )
    ]


def _find_check(report: dict[str, object], check_id: str) -> dict[str, str]:
    checks = report["checks"]
    assert isinstance(checks, list)
    return next(check for check in checks if check["id"] == check_id)


@pytest.fixture
def valid_harness_record(tmp_path: Path) -> dict[str, object]:
    _make_harness_repo(tmp_path)
    result = guard(
        str(tmp_path),
        "structured candidate",
        file_blocks={"app.py": "VALUE = 2\n"},
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
        harness_inputs=(_HARNESS_PATH,),
    )
    record = result.to_dict()
    report = verify_record(record)
    assert result.verdict == "PASS"
    assert report["ok"] is True, report
    return record


def test_normalization_is_sorted_and_matching_remains_exact() -> None:
    assert normalize_harness_inputs(()) == ()
    declared = normalize_harness_inputs(
        ("qa/z-helper.py", _HARNESS_PATH, "ci/a-helper.py")
    )

    assert declared == (
        "ci/a-helper.py",
        _HARNESS_PATH,
        "qa/z-helper.py",
    )
    assert is_harness_input_path("CI/SCRIPTS/RUN-TESTS.PY", declared)
    assert not is_harness_input_path("ci/scripts", declared)
    assert harness_input_path_conflicts("ci/scripts", declared)
    assert not is_harness_input_path(
        "ci/scripts/run-tests.py/attacker.py",
        declared,
    )


@pytest.mark.parametrize(
    "invalid",
    [
        "ci/run-tests.py",
        ("",),
        ("../ci/run-tests.py",),
        ("./ci/run-tests.py",),
        ("ci//run-tests.py",),
        ("/ci/run-tests.py",),
        ("C:/ci/run-tests.py",),
        (r"ci\run-tests.py",),
        ("ci/*.py",),
        ("ci/{run,check}.py",),
        ("ci/run.py.",),
        ("ci/run.py ",),
        ("ci/run.py:stream",),
        ("ci/CON.py",),
        ("ci/com1.txt",),
        ("ci/RUN-TE~1.PY",),
        ("ci/\x00run.py",),
        (1,),
        ("ci/run.py", "ci/run.py"),
        ("ci/Run.py", "ci/run.py"),
    ],
)
def test_normalization_rejects_ambiguous_or_noncanonical_declarations(
    invalid,
) -> None:
    with pytest.raises(HarnessInputPolicyError):
        normalize_harness_inputs(invalid)


@pytest.mark.parametrize(
    "pattern",
    ["ci", "**/scripts", "**/scripts/**", "CI/SCRIPTS/"],
)
def test_setup_output_cannot_hide_a_harness_input_via_ancestor_or_recursive_glob(
    pattern: str,
) -> None:
    assert setup_output_harness_conflicts(
        (_HARNESS_PATH,),
        (pattern,),
    ) == (_HARNESS_PATH,)
    assert (
        setup_output_harness_conflicts(
            (_HARNESS_PATH,),
            ("build/**",),
        )
        == ()
    )


@pytest.mark.parametrize(
    "pattern",
    ["ci", "**/scripts", "**/scripts/**", "CI/SCRIPTS/"],
)
def test_trusted_config_rejects_setup_output_harness_intersections(
    tmp_path: Path,
    pattern: str,
) -> None:
    config_path = tmp_path / ".evoguard.json"
    config_path.write_text(
        json.dumps(
            {
                "harness_inputs": [_HARNESS_PATH],
                "setup_output_globs": [pattern],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        ConfigError,
        match="cannot exclude harness_inputs",
    ):
        load_config(str(config_path), required=True)


def test_base_binding_rejects_missing_directory_and_case_aliases(
    tmp_path: Path,
) -> None:
    _make_harness_repo(tmp_path)
    problems = validate_harness_input_files(
        str(tmp_path),
        (
            "absent.py",
            "ci/scripts",
            "ci/scripts/RUN-TESTS.PY",
        ),
    )

    assert any("absent.py: path is absent" in problem for problem in problems)
    assert any(
        "ci/scripts: harness input must be a regular base file" in problem
        for problem in problems
    )
    assert any(
        "RUN-TESTS.PY: path case differs" in problem
        for problem in problems
    )


def test_base_binding_rejects_symlink_or_reparse_harness_inputs(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.py"
    target.write_text("# target\n", encoding="utf-8")
    link = tmp_path / "linked-helper.py"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    problems = validate_harness_input_files(
        str(tmp_path),
        ("linked-helper.py",),
    )

    assert any("symlink/reparse" in problem for problem in problems)


@pytest.mark.parametrize(
    "alias",
    [
        "ci/scripts/run-tests.py.",
        "ci/scripts/run-tests.py ",
        "ci/scripts/RUN-TE~1.PY",
    ],
)
def test_windows_namespace_alias_spellings_are_rejected_before_execution(
    tmp_path: Path,
    alias: str,
) -> None:
    harness = _make_harness_repo(tmp_path)
    harness.write_text("raise SystemExit(1)\n", encoding="utf-8")

    result = guard(
        str(tmp_path),
        "adversarial candidate",
        file_blocks={alias: "raise SystemExit(0)\n"},
        test_command=[sys.executable, _HARNESS_PATH],
        harness_inputs=(_HARNESS_PATH,),
    )
    payload = result.to_dict()

    assert is_safe_relpath(alias) is False
    assert result.verdict == "ERROR"
    assert result.reason_code == "unsafe_path"
    assert payload["test_command_ran"] is False
    assert harness.read_text(encoding="utf-8") == "raise SystemExit(1)\n"


def test_declared_harness_input_ancestor_deletion_is_static_rejection(
    tmp_path: Path,
) -> None:
    _make_harness_repo(tmp_path)
    sentinel = tmp_path / "candidate-command-ran"

    result = guard(
        str(tmp_path),
        "adversarial candidate",
        file_blocks={"app.py": "VALUE = 2\n"},
        deleted=("ci",),
        test_command=[
            sys.executable,
            "-c",
            (
                "from pathlib import Path; "
                f"Path({str(sentinel)!r}).write_text('ran')"
            ),
        ],
        harness_inputs=(_HARNESS_PATH,),
    )
    payload = result.to_dict()

    assert result.verdict == "REJECTED"
    assert result.reason_code == "protected_harness_edit"
    assert result.protected_violations == ["ci"]
    assert payload["test_command_ran"] is False
    assert not sentinel.exists()


def test_filesystem_alias_to_declared_harness_input_is_static_rejection(
    tmp_path: Path,
) -> None:
    harness = _make_harness_repo(tmp_path)
    alias = tmp_path / "judge-alias.py"
    try:
        alias.symlink_to(harness)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    assert candidate_path_targets_harness_input(
        str(tmp_path),
        "judge-alias.py",
        (_HARNESS_PATH,),
    )
    result = guard(
        str(tmp_path),
        "adversarial candidate",
        file_blocks={"judge-alias.py": "# attacker\n"},
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
        harness_inputs=(_HARNESS_PATH,),
    )

    assert result.verdict == "REJECTED"
    assert result.reason_code == "protected_harness_edit"
    assert result.protected_violations == ["judge-alias.py"]


def test_trusted_harness_snapshot_precedes_candidate_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _make_harness_repo(tmp_path)
    sentinel = tmp_path / "candidate-command-ran"
    original_capture = (
        repo_verifier_module.capture_harness_input_snapshot
    )
    capture_calls = 0

    def capture_with_materialization_alias(
        repo_path: str,
        harness_inputs: tuple[str, ...],
    ) -> dict[str, tuple[str, int, str]]:
        nonlocal capture_calls
        capture_calls += 1
        snapshot = original_capture(repo_path, harness_inputs)
        if capture_calls == 2:
            kind, mode, _digest = snapshot[_HARNESS_PATH]
            snapshot[_HARNESS_PATH] = (kind, mode, "0" * 64)
        return snapshot

    monkeypatch.setattr(
        repo_verifier_module,
        "capture_harness_input_snapshot",
        capture_with_materialization_alias,
    )
    result = guard(
        str(tmp_path),
        "adversarial candidate",
        file_blocks={"app.py": "VALUE = 2\n"},
        test_command=[
            sys.executable,
            "-c",
            (
                "from pathlib import Path; "
                f"Path({str(sentinel)!r}).write_text('ran')"
            ),
        ],
        harness_inputs=(_HARNESS_PATH,),
    )
    payload = result.to_dict()

    assert capture_calls == 2
    assert result.verdict == "TAMPERED"
    assert result.reason_code == "candidate_tree_changed_during_run"
    assert payload["test_command_ran"] is False
    assert not sentinel.exists()
    report = verify_record(payload)
    assert report["ok"] is True, report

    legacy = copy.deepcopy(payload)
    legacy["schema_version"] = "1.11"
    attestation = legacy["attestation"]
    assert isinstance(attestation, dict)
    policy = attestation["effective_policy"]
    assert isinstance(policy, dict)
    policy.pop("harness_inputs")
    attestation["policy_sha256"] = effective_policy_sha256(policy)
    legacy_report = verify_record(legacy)
    legacy_reason_check = _find_check(
        legacy_report,
        "verdict.reason_code",
    )
    assert legacy_report["ok"] is False
    assert legacy_reason_check["status"] == "fail"


def test_blackbox_materialization_is_bound_to_trusted_harness_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _make_harness_repo(tmp_path)
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "test_protocol.py").write_text(
        "def test_never_reached():\n"
        "    raise AssertionError('pack must not start')\n",
        encoding="utf-8",
    )
    original_capture = blackbox_module.capture_harness_input_snapshot
    capture_calls = 0

    def capture_with_materialization_drift(
        repo_path: str,
        harness_inputs: tuple[str, ...],
    ) -> dict[str, tuple[str, int, str]]:
        nonlocal capture_calls
        capture_calls += 1
        snapshot = original_capture(repo_path, harness_inputs)
        if capture_calls == 2:
            kind, mode, _digest = snapshot[_HARNESS_PATH]
            snapshot[_HARNESS_PATH] = (kind, mode, "0" * 64)
        return snapshot

    monkeypatch.setattr(
        blackbox_module,
        "capture_harness_input_snapshot",
        capture_with_materialization_drift,
    )
    result = guard(
        str(tmp_path),
        "adversarial black-box candidate",
        file_blocks={"app.py": "VALUE = 2\n"},
        verifier_pack=str(pack),
        blackbox=True,
        blackbox_only=True,
        harness_inputs=(_HARNESS_PATH,),
        timeout=30,
    )
    payload = result.to_dict()

    assert capture_calls == 2
    assert result.verdict == "TAMPERED"
    assert result.reason_code == "candidate_tree_changed_during_run"
    assert payload["test_command_ran"] is False
    assert payload["execution_state"] == "not_started"
    assert payload["verdict_source"] is None
    assert _HARNESS_PATH in payload["diagnostics"]
    report = verify_record(payload)
    assert report["ok"] is True, report
    assert _find_check(
        report,
        "policy.harness_reason_scope",
    )["status"] == "pass"

    unscoped = copy.deepcopy(payload)
    attestation = unscoped["attestation"]
    assert isinstance(attestation, dict)
    policy = attestation["effective_policy"]
    assert isinstance(policy, dict)
    policy.pop("harness_inputs")
    policy["operating_profile"] = "local"
    attestation["policy_sha256"] = effective_policy_sha256(policy)

    unscoped_report = verify_record(unscoped)
    scope_check = _find_check(
        unscoped_report,
        "policy.harness_reason_scope",
    )
    assert unscoped["schema_version"] == "1.12"
    assert unscoped_report["ok"] is False
    assert scope_check["status"] == "fail"


@pytest.mark.skipif(
    os.name == "nt",
    reason="black-box candidate launching requires a POSIX host",
)
def test_blackbox_only_rejects_persistent_runtime_harness_drift(
    tmp_path: Path,
) -> None:
    harness = _make_harness_repo(tmp_path)
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "test_protocol.py").write_text(
        "import os\n"
        "import subprocess\n"
        "import sys\n"
        "from pathlib import Path\n\n"
        "def test_candidate_runtime():\n"
        "    process = subprocess.run(\n"
        "        [\n"
        "            os.environ['EVOGUARD_EXEC'],\n"
        "            os.environ.get('EVOGUARD_PYTHON', sys.executable),\n"
        "            'app.py',\n"
        "        ],\n"
        "        capture_output=True,\n"
        "        text=True,\n"
        "    )\n"
        "    assert process.returncode == 0\n"
        "    target = Path(os.environ['EVOGUARD_TARGET'])\n"
        f"    assert (target / {_HARNESS_PATH!r}).read_text() == "
        "'# runtime attacker\\n'\n",
        encoding="utf-8",
    )
    candidate_source = (
        "from pathlib import Path\n"
        f"Path({_HARNESS_PATH!r}).write_text('# runtime attacker\\n')\n"
        "print('candidate completed')\n"
    )

    result = guard(
        str(tmp_path),
        "adversarial black-box candidate",
        file_blocks={"app.py": candidate_source},
        verifier_pack=str(pack),
        blackbox=True,
        blackbox_only=True,
        harness_inputs=(_HARNESS_PATH,),
        timeout=30,
    )
    payload = result.to_dict()

    assert result.verdict == "TAMPERED"
    assert result.reason_code == "candidate_tree_changed_during_run"
    assert payload["schema_version"] == "1.12"
    assert payload["test_command_ran"] is True
    assert payload["execution_state"] == "completed"
    assert payload["verdict_source"] is None
    assert _HARNESS_PATH in payload["diagnostics"]
    assert harness.read_text(encoding="utf-8") == "# trusted judge wrapper\n"
    report = verify_record(payload)
    assert report["ok"] is True, report


@pytest.mark.parametrize("candidate_operation", ["edit", "delete"])
def test_edit_or_delete_is_rejected_before_execution_despite_all_allow_controls(
    tmp_path: Path,
    candidate_operation: str,
) -> None:
    harness = _make_harness_repo(tmp_path)
    sentinel = tmp_path / "candidate-command-ran"
    edit = candidate_operation == "edit"

    result = guard(
        str(tmp_path),
        "adversarial candidate",
        file_blocks=(
            {_HARNESS_PATH: "# attacker-owned wrapper\n"}
            if edit
            else {}
        ),
        deleted=() if edit else (_HARNESS_PATH,),
        test_command=[
            sys.executable,
            "-c",
            (
                "from pathlib import Path; "
                f"Path({str(sentinel)!r}).write_text('ran')"
            ),
        ],
        protected=("ci/**",),
        allow=("ci/**",),
        allow_new_tests=True,
        harness_inputs=(_HARNESS_PATH,),
    )
    payload = result.to_dict()

    assert result.verdict == "REJECTED"
    assert result.protected_violations == [_HARNESS_PATH]
    assert payload["test_command_ran"] is False
    assert not sentinel.exists()
    assert harness.read_text(encoding="utf-8") == "# trusted judge wrapper\n"


def test_runtime_mutation_of_declared_helper_is_reported_as_tampering(
    tmp_path: Path,
) -> None:
    harness = _make_harness_repo(tmp_path)
    result = guard(
        str(tmp_path),
        "structured candidate",
        file_blocks={"app.py": "VALUE = 2\n"},
        test_command=[
            sys.executable,
            "-c",
            (
                "from pathlib import Path; "
                f"Path({_HARNESS_PATH!r}).write_text('# runtime attacker\\n')"
            ),
        ],
        harness_inputs=(_HARNESS_PATH,),
    )
    payload = result.to_dict()

    assert result.verdict == "TAMPERED"
    assert result.reason_code == "candidate_tree_changed_during_run"
    assert _HARNESS_PATH in result.reason
    assert payload["test_command_ran"] is True
    assert harness.read_text(encoding="utf-8") == "# trusted judge wrapper\n"
    assert verify_record(payload)["ok"] is True


def test_setup_mutation_of_declared_helper_stops_before_repository_suite(
    tmp_path: Path,
) -> None:
    harness = _make_harness_repo(tmp_path)
    suite_sentinel = tmp_path / "repository-suite-ran"

    result = guard(
        str(tmp_path),
        "structured candidate",
        file_blocks={"app.py": "VALUE = 2\n"},
        setup_command=[
            sys.executable,
            "-c",
            (
                "from pathlib import Path; "
                f"Path({_HARNESS_PATH!r}).write_text('# setup attacker\\n')"
            ),
        ],
        test_command=[
            sys.executable,
            "-c",
            (
                "from pathlib import Path; "
                f"Path({str(suite_sentinel)!r}).write_text('ran')"
            ),
        ],
        harness_inputs=(_HARNESS_PATH,),
    )
    payload = result.to_dict()

    assert result.verdict == "ERROR"
    assert result.reason_code == "setup_failed"
    assert _HARNESS_PATH in result.reason
    assert payload["test_command_ran"] is False
    assert not suite_sentinel.exists()
    assert harness.read_text(encoding="utf-8") == "# trusted judge wrapper\n"
    assert verify_record(payload)["ok"] is True


def test_setup_output_conflict_fails_before_setup_or_suite_execution(
    tmp_path: Path,
) -> None:
    _make_harness_repo(tmp_path)
    sentinel = tmp_path / "command-ran"
    command = [
        sys.executable,
        "-c",
        (
            "from pathlib import Path; "
            f"Path({str(sentinel)!r}).write_text('ran')"
        ),
    ]

    with pytest.raises(
        HarnessInputPolicyError,
        match="setup_output_globs cannot exclude harness_inputs",
    ):
        guard(
            str(tmp_path),
            "structured candidate",
            file_blocks={"app.py": "VALUE = 2\n"},
            setup_command=command,
            setup_output_globs=("**/scripts",),
            test_command=command,
            harness_inputs=(_HARNESS_PATH,),
        )

    assert not sentinel.exists()


def test_repository_command_tokens_are_not_mined_for_implicit_harness_inputs(
    tmp_path: Path,
) -> None:
    harness = _make_harness_repo(tmp_path)
    harness.write_text("raise SystemExit(1)\n", encoding="utf-8")

    result = guard(
        str(tmp_path),
        "structured candidate",
        file_blocks={_HARNESS_PATH: "raise SystemExit(0)\n"},
        test_command=[sys.executable, _HARNESS_PATH],
    )
    payload = result.to_dict()

    assert result.verdict == "PASS"
    assert payload["schema_version"] == "1.11"
    policy = payload["attestation"]["effective_policy"]
    assert "harness_inputs" not in policy


def test_harness_inputs_are_additive_schema_1_12_and_digest_bound() -> None:
    legacy_payload = effective_policy_payload(_build_policy())
    policy = _build_policy(
        harness_inputs=("qa/z-helper.py", _HARNESS_PATH),
    )
    payload = effective_policy_payload(policy)

    assert "harness_inputs" not in legacy_payload
    assert payload["harness_inputs"] == [
        _HARNESS_PATH,
        "qa/z-helper.py",
    ]
    assert effective_policy_sha256(payload) != effective_policy_sha256(
        legacy_payload
    )
    changed = dict(payload)
    changed["harness_inputs"] = [_HARNESS_PATH]
    assert effective_policy_sha256(payload) != effective_policy_sha256(changed)

    assert any(
        "harness_inputs" in error
        for error in _policy_schema_errors("1.11", payload)
    )
    assert _policy_schema_errors("1.12", payload) == []
    for invalid_path in (
        "ci/**/*.py",
        "ci/run.py.",
        "ci/run.py ",
        "ci/RUN~1.PY",
        "ci/CON.py",
        "ci/com1.txt",
    ):
        invalid = dict(payload)
        invalid["harness_inputs"] = [invalid_path]
        assert _policy_schema_errors("1.12", invalid)


@pytest.mark.parametrize("touched_field", ["files_changed", "deleted_paths"])
def test_record_verifier_rejects_pass_intersection_with_declared_harness_input(
    valid_harness_record: dict[str, object],
    touched_field: str,
) -> None:
    forged = copy.deepcopy(valid_harness_record)
    if touched_field == "files_changed":
        changed = forged["files_changed"]
        assert isinstance(changed, list)
        changed.append(_HARNESS_PATH.upper())
    else:
        attestation = forged["attestation"]
        assert isinstance(attestation, dict)
        deleted = attestation["deleted_paths"]
        assert isinstance(deleted, list)
        deleted.append(_HARNESS_PATH.upper())

    report = verify_record(forged)
    check = _find_check(report, "policy.harness_change_exclusion")

    assert report["ok"] is False
    assert check["status"] == "fail"
    assert _HARNESS_PATH.upper() in check["message"]


@pytest.mark.parametrize(
    "touched_path",
    [
        "ci",
        "ci/scripts/run-tests.py.",
        "ci/scripts/run-tests.py ",
        "ci/scripts/RUN-TE~1.PY",
    ],
)
def test_record_verifier_rejects_pass_namespace_alias_or_ancestor(
    valid_harness_record: dict[str, object],
    touched_path: str,
) -> None:
    forged = copy.deepcopy(valid_harness_record)
    changed = forged["files_changed"]
    assert isinstance(changed, list)
    changed.append(touched_path)

    report = verify_record(forged)
    check = _find_check(report, "policy.harness_change_exclusion")

    assert report["ok"] is False
    assert check["status"] == "fail"
    assert touched_path in check["message"]


@pytest.mark.parametrize(
    "pattern",
    ["ci", "**/scripts", "**/scripts/**", "CI/SCRIPTS/"],
)
def test_record_verifier_independently_rejects_setup_output_intersection(
    valid_harness_record: dict[str, object],
    pattern: str,
) -> None:
    forged = copy.deepcopy(valid_harness_record)
    attestation = forged["attestation"]
    assert isinstance(attestation, dict)
    policy = attestation["effective_policy"]
    assert isinstance(policy, dict)
    policy["setup_output_globs"] = [pattern]
    attestation["policy_sha256"] = effective_policy_sha256(policy)

    report = verify_record(forged)
    check = _find_check(report, "policy.contract")

    assert report["ok"] is False
    assert check["status"] == "fail"
    assert "cannot exclude harness_inputs" in check["message"]


def test_base_binding_rejects_hardlinked_harness_input(tmp_path: Path) -> None:
    target = tmp_path / "trusted-helper.py"
    target.write_text("# trusted\n", encoding="utf-8")
    hardlink = tmp_path / "hardlinked-helper.py"
    try:
        os.link(target, hardlink)
    except OSError as exc:
        pytest.skip(f"hardlink creation is unavailable: {exc}")

    problems = validate_harness_input_files(
        str(tmp_path),
        ("hardlinked-helper.py",),
    )

    assert any("hardlinked harness inputs are forbidden" in item for item in problems)


def test_cli_reports_missing_base_harness_input_without_a_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repo / ".evoguard.json").write_text(
        json.dumps({"harness_inputs": ["ci/missing-wrapper.py"]}),
        encoding="utf-8",
    )
    patch = tmp_path / "candidate.txt"
    patch.write_text(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        encoding="utf-8",
    )

    exit_code = guard_cli.main(
        ["guard", str(repo), "--patch", str(patch)]
    )
    output = capsys.readouterr()

    assert exit_code == 2
    assert "invalid trusted harness_inputs policy" in output.out
    assert "Traceback" not in output.out + output.err


def test_baseline_runner_does_not_consume_a_persistently_mutated_harness_input(
    tmp_path: Path,
) -> None:
    _make_harness_repo(tmp_path)

    evidence = _run_baseline_suite(
        str(tmp_path),
        test_command=[
            sys.executable,
            "-c",
            (
                "from pathlib import Path; "
                f"Path({_HARNESS_PATH!r}).write_text('# baseline attacker\\n')"
            ),
        ],
        setup_command=None,
        setup_output_globs=(),
        timeout=30,
        mem_limit_mb=0,
        strict_harness=False,
        harness_inputs=(_HARNESS_PATH,),
    )

    assert evidence["verdict"] == "NO_CLEAN_VERDICT"
    assert evidence["tests_passed"] is None
    assert evidence["tests_total"] is None


def test_diff_coverage_does_not_report_measurement_after_harness_drift(
    tmp_path: Path,
) -> None:
    _make_harness_repo(tmp_path)
    (tmp_path / "test_app.py").write_text(
        "from app import value\n\n"
        "def test_value():\n"
        "    assert value() == 2\n",
        encoding="utf-8",
    )
    candidate_source = (
        "from pathlib import Path\n\n"
        "def value():\n"
        f"    Path({_HARNESS_PATH!r}).write_text('# coverage attacker\\n')\n"
        "    return 2\n"
    )

    evidence = collect_diff_coverage(
        str(tmp_path),
        "structured candidate",
        test_command=[
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "test_app.py",
        ],
        timeout=60,
        mem_limit_mb=0,
        file_blocks={"app.py": candidate_source},
        require_passing_suite=True,
        harness_inputs=(_HARNESS_PATH,),
    )

    assert evidence["measured"] is False
    assert "coverage run changed declared harness inputs" in evidence["note"]
