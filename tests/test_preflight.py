"""Focused contract tests for static repository preflight."""

from __future__ import annotations

from pathlib import Path

from evoom_guard.policy.preflight import analyze_preflight, normalize_test_command


def _which(*available: str):
    paths = {name: f"/trusted/bin/{name}" for name in available}
    return paths.get


def _codes(report, status: str | None = None) -> set[str]:
    return {
        check.code
        for check in report.checks
        if status is None or check.status == status
    }


def test_normalize_command_preserves_guard_compatibility() -> None:
    assert normalize_test_command("python -m pytest -q") == (
        "python",
        "-m",
        "pytest",
        "-q",
    )
    assert normalize_test_command("python -m pytest && echo done") == (
        "sh",
        "-c",
        "python -m pytest && echo done",
    )
    assert normalize_test_command(None, default_python="/python") == (
        "/python",
        "-m",
        "pytest",
        "-q",
        "--color=no",
        "-p",
        "no:cacheprovider",
    )
    assert normalize_test_command("", default_python="python") == (
        "python",
        "-m",
        "pytest",
        "-q",
        "--color=no",
        "-p",
        "no:cacheprovider",
    )
    assert normalize_test_command([], default_python="python") == (
        "python",
        "-m",
        "pytest",
        "-q",
        "--color=no",
        "-p",
        "no:cacheprovider",
    )


def test_demo_python_isolated_mode_predicts_bytecode_tree_drift(tmp_path: Path) -> None:
    command = normalize_test_command(
        "python -I -c (__import__('sys').path.insert(0,'src'),__import__('click'))[1]"
    )
    report = analyze_preflight(
        repository=str(tmp_path),
        command=command,
        raw_command=(
            "python -I -c "
            "(__import__('sys').path.insert(0,'src'),__import__('click'))[1]"
        ),
        verifier_pack_configured=True,
        which=_which("python"),
    )

    assert not report.ready
    assert "runtime_write.python_environment_ignored" in _codes(report, "error")
    check = next(
        item
        for item in report.checks
        if item.code == "runtime_write.python_environment_ignored"
    )
    assert "-B" in str(check.remediation)
    assert "__pycache__" in check.message


def test_explicit_python_no_bytecode_option_clears_that_blocker(tmp_path: Path) -> None:
    report = analyze_preflight(
        repository=str(tmp_path),
        command=("python", "-I", "-B", "-c", "import click"),
        verifier_pack_configured=True,
        which=_which("python"),
    )

    assert "runtime_write.python_environment_ignored" not in _codes(report)
    assert "runtime_write.python_bytecode" in _codes(report, "pass")
    # Arbitrary candidate writes remain explicitly unproven, not silently safe.
    assert "runtime_write.static_scope" in _codes(report, "info")


def test_pytest_cache_must_be_disabled_for_suite_to_pack_continuity(
    tmp_path: Path,
) -> None:
    risky = analyze_preflight(
        repository=str(tmp_path),
        command=("python", "-m", "pytest", "-q"),
        verifier_pack_configured=True,
        which=_which("python"),
    )
    safe_cache = analyze_preflight(
        repository=str(tmp_path),
        command=(
            "python",
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
        ),
        verifier_pack_configured=True,
        which=_which("python"),
    )

    assert "runtime_write.pytest_cache" in _codes(risky, "error")
    assert "runtime_write.pytest_cache" in _codes(safe_cache, "pass")
    assert risky.ready is False
    assert safe_cache.ready is True


def test_python_options_before_module_do_not_hide_pytest_cache(tmp_path: Path) -> None:
    report = analyze_preflight(
        repository=str(tmp_path),
        command=("python", "-I", "-B", "-X", "dev", "-m", "pytest", "-q"),
        verifier_pack_configured=True,
        which=_which("python"),
    )

    assert "runtime_write.python_bytecode" in _codes(report, "pass")
    assert "runtime_write.pytest_cache" in _codes(report, "error")
    assert report.ready is False


def test_value_options_and_py_launcher_preserve_later_isolation_flags(
    tmp_path: Path,
) -> None:
    report = analyze_preflight(
        repository=str(tmp_path),
        command=("py", "-3.12", "-X", "dev", "-I", "-m", "pytest"),
        verifier_pack_configured=True,
        platform_name="win32",
        which=_which("py"),
    )

    assert "runtime_write.python_environment_ignored" in _codes(report, "error")
    assert "runtime_write.pytest_cache" in _codes(report, "error")


def test_known_wrapper_preserves_python_module_parsing(tmp_path: Path) -> None:
    report = analyze_preflight(
        repository=str(tmp_path),
        command=(
            "uv",
            "run",
            "python",
            "-IB",
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
        ),
        verifier_pack_configured=True,
        which=_which("uv"),
    )

    assert "runtime_write.python_environment_ignored" not in _codes(report)
    assert "runtime_write.python_bytecode" in _codes(report, "pass")
    assert "runtime_write.pytest_cache" in _codes(report, "pass")


def test_missing_host_interpreter_is_a_deterministic_blocker(tmp_path: Path) -> None:
    report = analyze_preflight(
        repository=str(tmp_path),
        command=("missing-python", "-m", "pytest"),
        which=_which(),
    )

    assert not report.ready
    assert "test_command.executable_available" in _codes(report, "error")


def test_shell_string_reports_windows_portability_and_missing_sh(
    tmp_path: Path,
) -> None:
    raw = "python -m pytest && python smoke.py"
    report = analyze_preflight(
        repository=str(tmp_path),
        command=normalize_test_command(raw),
        raw_command=raw,
        platform_name="win32",
        which=_which(),
    )

    assert "test_command.shell_dependency" in _codes(report, "warning")
    assert "test_command.platform_launcher" in _codes(report, "warning")
    assert "test_command.executable_available" in _codes(report, "error")


def test_quoted_plain_string_is_reported_as_lossy(tmp_path: Path) -> None:
    raw = 'python -c "print(1)"'
    report = analyze_preflight(
        repository=str(tmp_path),
        command=normalize_test_command(raw),
        raw_command=raw,
        which=_which("python"),
    )

    assert "test_command.lossy_string_split" in _codes(report, "warning")


def test_container_preflight_checks_docker_without_claiming_image_contents(
    tmp_path: Path,
) -> None:
    report = analyze_preflight(
        repository=str(tmp_path),
        command=("python", "-m", "pytest", "-p", "no:cacheprovider"),
        isolation="docker",
        docker_image="python:3.12@sha256:" + "a" * 64,
        which=_which("docker"),
    )

    assert "container_runtime.available" in _codes(report, "pass")
    assert "test_command.container_executable" in _codes(report, "info")
    assert "test_command.executable_available" not in _codes(report)


def test_container_command_is_not_judged_against_host_platform(tmp_path: Path) -> None:
    report = analyze_preflight(
        repository=str(tmp_path),
        command=("sh", "-c", "python -m pytest"),
        isolation="docker",
        docker_image="python:3.12@sha256:" + "a" * 64,
        platform_name="win32",
        which=_which("docker"),
    )

    assert "test_command.platform_launcher" not in _codes(report)
    assert "test_command.container_executable" in _codes(report, "info")


def test_mutable_container_reference_is_ready_but_warned(tmp_path: Path) -> None:
    report = analyze_preflight(
        repository=str(tmp_path),
        command=("python", "-m", "pytest", "-p", "no:cacheprovider"),
        isolation="docker",
        docker_image="python:3.12",
        which=_which("docker"),
    )

    assert report.ready
    assert "policy.container_image_configured" in _codes(report, "pass")
    assert "policy.container_image_mutable_reference" in _codes(
        report,
        "warning",
    )


def test_blackbox_only_suppresses_irrelevant_repo_suite_write_blockers(
    tmp_path: Path,
) -> None:
    report = analyze_preflight(
        repository=str(tmp_path),
        command=("python", "-I", "-c", "import click"),
        verifier_pack_configured=True,
        blackbox_only=True,
        which=_which("python"),
    )

    assert report.repo_suite_enabled is False
    assert report.runtime_continuity_required is False
    assert "runtime_write.python_environment_ignored" not in _codes(report)
    assert "runtime_write.continuity_not_required" in _codes(report, "pass")


def test_project_output_runner_is_blocked_under_exact_continuity(
    tmp_path: Path,
) -> None:
    report = analyze_preflight(
        repository=str(tmp_path),
        command=("mvn", "test"),
        verifier_pack_configured=True,
        which=_which("mvn"),
    )

    assert "runtime_write.project_output" in _codes(report, "error")
    assert not report.ready


def test_report_dict_is_typed_and_counts_findings(tmp_path: Path) -> None:
    report = analyze_preflight(
        repository=str(tmp_path),
        command=("python", "-m", "pytest", "-p", "no:cacheprovider"),
        verifier_pack_configured=True,
        which=_which("python"),
    )
    payload = report.to_dict()

    assert payload["schema_version"] == "evoguard/preflight/v1"
    assert payload["ready"] is True
    assert payload["test_command"] == [
        "python",
        "-m",
        "pytest",
        "-p",
        "no:cacheprovider",
    ]
    summary = payload["summary"]
    assert isinstance(summary, dict)
    assert sum(summary.values()) == len(report.checks)


def test_missing_repository_is_reported_without_touching_it() -> None:
    report = analyze_preflight(
        repository="/missing/repository",
        command=("python", "-m", "pytest"),
        which=_which("python"),
        is_directory=lambda _path: False,
    )

    assert "repository.available" in _codes(report, "error")
    assert not report.ready


def test_explicit_non_executable_uses_execution_locator(tmp_path: Path) -> None:
    runner = tmp_path / "runner"
    runner.write_text("#!/bin/sh\n", encoding="utf-8")

    report = analyze_preflight(
        repository=str(tmp_path),
        command=("./runner",),
        which=lambda _executable: None,
    )

    assert "test_command.executable_available" in _codes(report, "error")
    assert not report.ready


def test_bare_command_resolved_inside_candidate_is_warned(tmp_path: Path) -> None:
    runner = tmp_path / "runner"
    report = analyze_preflight(
        repository=str(tmp_path),
        command=("runner",),
        which=lambda _executable: str(runner),
    )

    assert "test_command.candidate_relative_executable" in _codes(
        report,
        "warning",
    )


def test_policy_compatibility_and_windows_strict_harness_are_blockers(
    tmp_path: Path,
) -> None:
    report = analyze_preflight(
        repository=str(tmp_path),
        command=("python", "-m", "pytest"),
        setup_command=("missing-setup",),
        blackbox=True,
        verifier_pack_configured=True,
        require_demonstrated_fix=True,
        min_diff_coverage=80.0,
        strict_harness=True,
        platform_name="win32",
        which=_which("python"),
    )

    error_codes = _codes(report, "error")
    assert "policy.requirement_unsupported" in error_codes
    assert "policy.strict_harness_process_group_unavailable" in error_codes
    assert "setup_command.executable_available" in error_codes


def test_container_runtime_continuity_uses_read_only_mount_not_host_write_model(
    tmp_path: Path,
) -> None:
    report = analyze_preflight(
        repository=str(tmp_path),
        command=("python", "-I", "-m", "pytest"),
        isolation="docker",
        docker_image="python@sha256:" + "a" * 64,
        verifier_pack_configured=True,
        which=_which("docker"),
    )

    assert report.ready
    assert "runtime_write.read_only_container" in _codes(report, "pass")
    assert "runtime_write.python_environment_ignored" not in _codes(report)
