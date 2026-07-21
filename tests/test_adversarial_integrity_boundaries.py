# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""High-value adversarial boundaries not covered by the main verifier corpus."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

import evoom_guard.verifiers.junit_oracle as junit_oracle_module
import evoom_guard.verifiers.repo_verifier as repo_verifier_module
from evoom_guard.verifiers.junit_oracle import (
    JUNIT_COMPOSITE_DIGEST_FORMAT,
    JUNIT_REPORT_SET_DIGEST_FORMAT,
    detect_tamper,
    grade_repo_run,
    parse_junit_dir,
    parse_junit_dir_with_digest,
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


def test_junit_report_set_digest_is_deterministic_and_content_bound(
    tmp_path: Path,
) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    second = reports / "TEST-z.xml"
    first = reports / "TEST-a.xml"
    second.write_text(
        '<testsuite><testcase name="second"/></testsuite>', encoding="utf-8"
    )
    first.write_text(
        '<testsuite><testcase name="first"/></testsuite>', encoding="utf-8"
    )

    initial = parse_junit_dir_with_digest(str(reports))
    repeated = parse_junit_dir_with_digest(str(reports))

    assert initial is not None and repeated is not None
    counts, digest = initial
    assert counts.passed == counts.total == 2
    assert digest == repeated[1]
    assert re.fullmatch(r"[0-9a-f]{64}", digest)

    second.write_text(
        '<testsuite><testcase name="alterd"/></testsuite>', encoding="utf-8"
    )
    changed = parse_junit_dir_with_digest(str(reports))
    assert changed is not None
    assert changed[1] != digest


@pytest.mark.skipif(os.name != "posix", reason="surrogateescape filenames are POSIX-only")
def test_junit_report_set_rejects_a_non_utf8_filename_without_raising(
    tmp_path: Path,
) -> None:
    reports = tmp_path / "reports"
    reports.mkdir()
    raw_path = os.path.join(os.fsencode(reports), b"TEST-\xff.xml")
    descriptor = os.open(raw_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(
            descriptor,
            b'<testsuite><testcase name="valid-content"/></testsuite>',
        )
    finally:
        os.close(descriptor)

    assert parse_junit_dir_with_digest(str(reports)) is None


def test_maven_report_set_and_pack_are_both_bound_into_composite_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    source = repo / "src" / "main" / "java"
    source.mkdir(parents=True)
    (source / "App.java").write_text("class App {}\n", encoding="utf-8")
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "test_contract.py").write_text(
        "def test_contract():\n    assert True\n", encoding="utf-8"
    )

    pack_xml = '<testsuite><testcase name="pack"/></testsuite>'

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        report_dir_arg = next(
            (
                arg
                for arg in command
                if arg.startswith("-Dsurefire.reportsDirectory=")
            ),
            None,
        )
        if report_dir_arg is not None:
            report_dir = Path(report_dir_arg.split("=", 1)[1])
            report_dir.mkdir(parents=True, exist_ok=True)
            (report_dir / "TEST-a.xml").write_text(
                '<testsuite><testcase name="repo-a"/></testsuite>',
                encoding="utf-8",
            )
            (report_dir / "TEST-b.xml").write_text(
                '<testsuite><testcase name="repo-b"/></testsuite>',
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(command, 0, "repo passed", "")
        pack_report = next(
            (arg.split("=", 1)[1] for arg in command if arg.startswith("--junitxml=")),
            None,
        )
        if pack_report is not None:
            Path(pack_report).write_text(pack_xml, encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "pack passed", "")
        raise AssertionError(f"unexpected command: {command!r}")

    monkeypatch.setattr(repo_verifier_module, "_run_bounded_subprocess", fake_run)

    result = RepoVerifier(test_command=["mvn", "test"], mem_limit_mb=0).verify(
        "<<<FILE: src/main/java/App.java>>>\nclass App { int value = 1; }\n"
        "<<<END FILE>>>",
        {"repo_path": str(repo), "verifier_pack": str(pack)},
    )

    assert result.passed, result.diagnostics
    artifact = result.artifact
    assert artifact["repo_suite_tests_passed"] == 2
    assert artifact["repo_suite_tests_total"] == 2
    assert re.fullmatch(r"[0-9a-f]{64}", artifact["repo_suite_junit_sha256"])
    assert artifact["repo_suite_junit_digest_format"] == JUNIT_REPORT_SET_DIGEST_FORMAT
    assert artifact["verifier_pack_junit_sha256"] == hashlib.sha256(
        pack_xml.encode("utf-8")
    ).hexdigest()
    assert re.fullmatch(r"[0-9a-f]{64}", artifact["junit_sha256"])
    assert artifact["junit_digest_format"] == JUNIT_COMPOSITE_DIGEST_FORMAT
    expected_identity = (
        JUNIT_COMPOSITE_DIGEST_FORMAT
        + "\0repo\0"
        + JUNIT_REPORT_SET_DIGEST_FORMAT
        + "\0"
        + artifact["repo_suite_junit_sha256"]
        + "\0verifier-pack\0JUNIT_XML_SHA256\0"
        + artifact["verifier_pack_junit_sha256"]
    )
    assert artifact["junit_sha256"] == hashlib.sha256(
        expected_identity.encode("utf-8")
    ).hexdigest()


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
    removed = False

    def fake_run(command, **_kwargs):
        nonlocal removed
        calls.append(list(command))
        if command[:3] == ["docker", "run", "--rm"]:
            raise subprocess.TimeoutExpired(command, 7)
        if command[:3] == ["docker", "rm", "-f"]:
            removed = True
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(command, 1 if removed else 0, "", "")
        if command[:4] == ["docker", "container", "ls", "--all"]:
            names = "" if removed else fixed_name + "\n"
            return subprocess.CompletedProcess(command, 0, names, "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(repo_verifier_module, "_docker_container_name", lambda _stage: fixed_name)
    monkeypatch.setattr(repo_verifier_module, "_run_bounded_subprocess", fake_run)
    monkeypatch.setattr(repo_verifier_module.time, "sleep", lambda _seconds: None)
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

    assert calls[0][:3] == ["docker", "run", "--rm"]
    assert calls[1] == [
        "docker", "inspect", "--format", "{{.State.StartedAt}}", fixed_name
    ]
    assert calls[2] == ["docker", "rm", "-f", fixed_name]
    queries = [call for call in calls if call[:3] == ["docker", "container", "ls"]]
    assert len(queries) == repo_verifier_module._DOCKER_CLEANUP_RECONCILE_ATTEMPTS
    assert all("--all" in call for call in queries)
    assert all(
        call[call.index("--filter") + 1] == f"name={fixed_name}"
        for call in queries
    )


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
