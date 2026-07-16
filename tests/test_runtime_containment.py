"""Bounded native-runner and JUnit-file containment regressions."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

import evoom_guard.verifiers.junit_oracle as junit_oracle
import evoom_guard.verifiers.repo_verifier as repo_verifier
from evoom_guard.verifiers.repo_verifier import RepoVerifier


def _candidate() -> str:
    return "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n"


def test_native_runner_bounds_combined_stdout_stderr_before_oom(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A live process that floods stdout is stopped at the explicit cap."""
    monkeypatch.setattr(repo_verifier, "_MAX_SUBPROCESS_OUTPUT_BYTES", 8 * 1024)

    with pytest.raises(repo_verifier._SubprocessOutputLimitExceeded) as exc:
        repo_verifier._run_bounded_subprocess(
            [
                sys.executable,
                "-c",
                (
                    "import sys, time; "
                    "sys.stdout.buffer.write(b'x' * 200000); "
                    "sys.stdout.flush(); time.sleep(60)"
                ),
            ],
            cwd=str(tmp_path),
            env=os.environ.copy(),
            timeout=10,
        )

    assert exc.value.limit == 8 * 1024


def test_repo_verifier_returns_a_structured_error_for_output_flood(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The native repo judge reports a checked failure instead of allocating logs."""
    monkeypatch.setattr(repo_verifier, "_MAX_SUBPROCESS_OUTPUT_BYTES", 8 * 1024)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")

    result = RepoVerifier(
        test_command=[
            sys.executable,
            "-c",
            (
                "import sys, time; "
                "sys.stderr.buffer.write(b'x' * 200000); "
                "sys.stderr.flush(); time.sleep(60)"
            ),
        ],
        mem_limit_mb=0,
    ).verify(_candidate(), {"repo_path": str(repo)})

    assert not result.passed
    assert result.score == 0.0
    assert result.artifact["outcome"] == "test_output_limit"
    assert "capture limit" in result.diagnostics


def test_junit_file_reader_rejects_oversized_file_before_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The file reader uses stat + a bounded binary read, not read-to-EOF."""
    report = tmp_path / "judge-result.xml"
    report.write_bytes(b"x" * 4096)
    monkeypatch.setattr(junit_oracle, "_MAX_REPORT_BYTES", 1024)

    assert junit_oracle.read_junit_xml(str(report)) is None


def test_launcher_uses_a_tree_containment_boundary_on_each_supported_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(repo_verifier.os, "name", "posix")
    assert repo_verifier._subprocess_group_kwargs() == {"start_new_session": True}

    monkeypatch.setattr(repo_verifier.os, "name", "nt")
    assert "creationflags" in repo_verifier._subprocess_group_kwargs()


def test_timeout_terminates_a_child_process_tree_before_it_can_survive(
    tmp_path: Path,
) -> None:
    """Exercise the real cleanup path without relying on platform-specific ps."""
    marker = tmp_path / "child-survived.txt"
    child = (
        "from pathlib import Path; import sys, time; "
        "time.sleep(0.8); Path(sys.argv[1]).write_text('survived', encoding='utf-8')"
    )
    parent = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {child!r}, sys.argv[1]]); "
        "time.sleep(60)"
    )

    with pytest.raises(subprocess.TimeoutExpired):
        repo_verifier._run_bounded_subprocess(
            [sys.executable, "-c", parent, str(marker)],
            cwd=str(tmp_path),
            env=os.environ.copy(),
            timeout=0.15,
        )

    # If /T (Windows) or killpg (POSIX) did not contain descendants, the child
    # deterministically writes this marker after the judge has returned.
    time.sleep(1.0)
    assert not marker.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group contract")
def test_clean_exit_reaps_background_descendant_that_closed_stdio(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A clean leader exit alone must not leave a candidate child on the host."""
    ready = tmp_path / "child-ready"
    survived = tmp_path / "child-survived"
    child = (
        "import signal, sys, time; from pathlib import Path; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "Path(sys.argv[1]).write_text('ready'); time.sleep(0.8); "
        "Path(sys.argv[2]).write_text('survived')"
    )
    parent = (
        "import subprocess, sys, time; from pathlib import Path; "
        "subprocess.Popen([sys.executable, '-c', sys.argv[3], sys.argv[1], sys.argv[2]], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
        "stderr=subprocess.DEVNULL, close_fds=True); "
        "deadline=time.monotonic()+3; "
        "\nwhile not Path(sys.argv[1]).exists() and time.monotonic()<deadline: time.sleep(0.01); "
        "\nraise SystemExit(0 if Path(sys.argv[1]).exists() else 2)"
    )
    monkeypatch.setattr(repo_verifier, "_PROCESS_TERM_GRACE_SECONDS", 0.2)

    completed = repo_verifier._run_bounded_subprocess(
        [sys.executable, "-c", parent, str(ready), str(survived), child],
        cwd=str(tmp_path),
        env=os.environ.copy(),
        timeout=5,
    )

    assert completed.returncode == 0
    assert ready.exists()
    # The child ignored TERM and closed the captured streams; only the
    # post-completion process-group cleanup can stop it before this marker.
    time.sleep(0.9)
    assert not survived.exists()
