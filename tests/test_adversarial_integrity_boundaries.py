# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""High-value adversarial boundaries not covered by the main verifier corpus."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

import evoom_guard.verifiers.junit_oracle as junit_oracle_module
import evoom_guard.verifiers.repo_verifier as repo_verifier_module
from evoom_guard.verifiers.junit_oracle import (
    detect_tamper,
    grade_repo_run,
    parse_junit_dir,
    parse_junit_xml,
)
from evoom_guard.verifiers.repo_verifier import RepoVerifier


def test_testcases_override_forged_all_pass_aggregate_attributes() -> None:
    report = (
        '<testsuite tests="999" failures="0" errors="0">'
        '<testcase name="actually-failed"><failure message="boom"/></testcase>'
        "</testsuite>"
    )

    counts = parse_junit_xml(report)

    assert counts is not None
    assert (counts.passed, counts.total, counts.failures, counts.errors) == (0, 1, 1, 0)
    passed, _score, tests_passed, tests_total = grade_repo_run(
        0, counts, report_expected=True
    )
    assert not passed
    assert (tests_passed, tests_total) == (0, 1)
    assert detect_tamper(0, counts, report_expected=True)


def test_junit_directory_rejects_a_symlinked_report_fail_closed(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    controlled_external = tmp_path / "controlled-external.xml"
    controlled_external.write_text(
        '<testsuite><testcase name="external-pass"/></testsuite>',
        encoding="utf-8",
    )
    linked_report = reports / "TEST-controlled.xml"
    try:
        linked_report.symlink_to(controlled_external)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"file symlinks are unavailable: {exc}")

    counts = parse_junit_dir(str(reports))

    assert counts is None


def test_junit_directory_rejects_a_malformed_sibling_fail_closed(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "TEST-valid.xml").write_text(
        '<testsuite><testcase name="only-visible-pass"/></testsuite>',
        encoding="utf-8",
    )
    (reports / "TEST-malformed.xml").write_text("<testsuite>", encoding="utf-8")

    counts = parse_junit_dir(str(reports))

    assert counts is None
    assert grade_repo_run(0, counts, report_expected=True)[0] is False


def test_junit_directory_rejects_a_non_regular_xml_entry(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "TEST-valid.xml").write_text(
        '<testsuite><testcase name="visible-pass"/></testsuite>',
        encoding="utf-8",
    )
    (reports / "TEST-directory.xml").mkdir()

    assert parse_junit_dir(str(reports)) is None


def test_junit_directory_rejects_an_unreadable_xml_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    report = reports / "TEST-unreadable.xml"
    report.write_text('<testsuite tests="1"/>', encoding="utf-8")
    real_read = junit_oracle_module._read_text_or_none

    def unreadable(path: str) -> str | None:
        if path == str(report):
            return None
        return real_read(path)

    monkeypatch.setattr(junit_oracle_module, "_read_text_or_none", unreadable)

    assert parse_junit_dir(str(reports)) is None


def test_junit_directory_rejects_an_oversized_xml_entry(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "TEST-too-large.xml").write_text(
        " " * (junit_oracle_module._MAX_REPORT_CHARS + 1),
        encoding="utf-8",
    )

    assert parse_junit_dir(str(reports)) is None


def test_pack_self_mutation_during_real_execution_is_detected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("value = 1\n", encoding="utf-8")
    pack = tmp_path / "pack"
    pack.mkdir()
    pack_test = pack / "test_mutating_contract.py"
    original = (
        "from pathlib import Path\n\n"
        "def test_mutates_accepted_snapshot():\n"
        "    current = Path(__file__)\n"
        "    current.write_text(current.read_text(encoding='utf-8') + "
        "'# changed during execution\\n', encoding='utf-8')\n"
        "    assert True\n"
    )
    pack_test.write_text(original, encoding="utf-8")

    result = RepoVerifier(
        test_command=[sys.executable, "-c", "raise SystemExit(0)"],
        mem_limit_mb=0,
    ).verify(
        "<<<FILE: app.py>>>\nvalue = 2\n<<<END FILE>>>",
        {"repo_path": str(repo), "verifier_pack": str(pack)},
    )

    assert not result.passed
    assert result.artifact["outcome"] == "pack_snapshot_changed"
    assert result.artifact["tamper"] is True
    assert "changed while executing" in result.diagnostics
    assert pack_test.read_text(encoding="utf-8") == original


def test_docker_timeout_forcibly_removes_the_exact_named_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    fixed_name = "evoguard_timeout_fixed"

    def fake_run(command, **_kwargs):
        calls.append(list(command))
        if command[:3] == ["docker", "run", "--rm"]:
            raise subprocess.TimeoutExpired(command, 7)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(repo_verifier_module, "_docker_container_name", lambda _stage: fixed_name)
    monkeypatch.setattr(repo_verifier_module.subprocess, "run", fake_run)
    verifier = RepoVerifier(
        timeout=7,
        mem_limit_mb=0,
        isolation="docker",
        docker_image="python:3.12-slim",
    )
    verifier._resolved_docker_image = "sha256:fixed"

    with pytest.raises(subprocess.TimeoutExpired):
        verifier._run_docker(
            ["python", "-m", "pytest"],
            str(tmp_path / "copy"),
            str(tmp_path / "judge"),
        )

    assert len(calls) == 2
    assert calls[0][:3] == ["docker", "run", "--rm"]
    assert calls[1] == ["docker", "rm", "-f", fixed_name]


def test_limit_hook_sets_cpu_and_address_space_caps(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResource:
        RLIMIT_CPU = 1
        RLIMIT_AS = 2

        def __init__(self) -> None:
            self.calls: list[tuple[int, tuple[int, int]]] = []

        def setrlimit(self, resource_id: int, limits: tuple[int, int]) -> None:
            self.calls.append((resource_id, limits))

    fake = FakeResource()
    monkeypatch.setattr(repo_verifier_module, "resource", fake)
    verifier = RepoVerifier(timeout=7, mem_limit_mb=64)

    apply_limits = verifier._limits()

    assert apply_limits is not None
    apply_limits()
    assert fake.calls == [
        (fake.RLIMIT_CPU, (8, 8)),
        (fake.RLIMIT_AS, (64 * 1024 * 1024, 64 * 1024 * 1024)),
    ]


def test_container_name_sanitizes_and_bounds_an_adversarial_stage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        repo_verifier_module.secrets,
        "token_hex",
        lambda byte_count: "a" * (byte_count * 2),
    )
    stage = ("../../\\n--privileged/☃/" * 20) + "tail"

    name = repo_verifier_module._docker_container_name(stage)

    assert re.fullmatch(r"[A-Za-z0-9_.-]+", name)
    assert len(name) <= len("evoguard_") + 32 + 1 + 16
    assert "privileged" in name
    assert "/" not in name and "\\n" not in name
