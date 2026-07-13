# -----------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available - see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""A prepared black-box launcher is not proof that the candidate ever ran."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from evoom_guard.blackbox import (
    BlackboxResult,
    _attach_candidate_execution_evidence,
    run_blackbox,
)
from evoom_guard.candidate_runner import CANDIDATE_CID_DIRNAME

_CID = "a" * 64


def _repo_candidate(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("value = 1\n", encoding="utf-8")
    candidate = "<<<FILE: app.py>>>\nvalue = 2\n<<<END FILE>>>\n"
    return repo, candidate


@pytest.mark.skipif(os.name == "nt", reason="POSIX executable launcher contract")
def test_passing_pack_that_never_invokes_launcher_has_no_invocation_evidence(
    tmp_path: Path,
) -> None:
    repo, candidate = _repo_candidate(tmp_path)
    pack = tmp_path / "constant-pack"
    pack.mkdir()
    (pack / "test_protocol.py").write_text(
        "def test_constant_pass():\n    assert True\n",
        encoding="utf-8",
    )

    result = run_blackbox(str(repo), candidate, str(pack))

    assert result.passed is True
    assert result.ran is True
    assert result.candidate_invocations == 0
    assert result.candidate_launcher_invocation_observed is False
    assert result.isolation is not None
    assert result.isolation["delivered"] == "not_run"
    assert result.isolation["prepared"] == "subprocess"
    assert result.isolation["candidate_launcher_events"] == 0
    assert result.isolation["candidate_launcher_invocation_observed"] is False


@pytest.mark.skipif(os.name == "nt", reason="POSIX executable launcher contract")
def test_pack_invoking_evoguard_exec_records_subprocess_launcher_invocation(
    tmp_path: Path,
) -> None:
    repo, candidate = _repo_candidate(tmp_path)
    pack = tmp_path / "invoking-pack"
    pack.mkdir()
    (pack / "test_protocol.py").write_text(
        "import os\n"
        "import subprocess\n\n"
        "def test_candidate():\n"
        "    completed = subprocess.run(\n"
        "        [os.environ['EVOGUARD_EXEC'], os.environ['EVOGUARD_PYTHON'], "
        "'-c', \"print('candidate-ok')\"],\n"
        "        capture_output=True, text=True, timeout=20, check=False,\n"
        "    )\n"
        "    assert completed.returncode == 0\n"
        "    assert completed.stdout.strip() == 'candidate-ok'\n",
        encoding="utf-8",
    )

    result = run_blackbox(str(repo), candidate, str(pack))

    assert result.passed is True
    assert result.ran is True
    assert result.candidate_invocations == 1
    assert result.candidate_launcher_invocation_observed is True
    assert result.isolation is not None
    assert result.isolation["delivered"] == "subprocess"
    assert result.isolation["candidate_launcher_events"] == 1


class _ReceiptCount:
    def __init__(self, count: int) -> None:
        self.count = count

    def drain(self) -> int:
        return self.count


@pytest.mark.parametrize(
    ("receipt_count", "write_valid_cid", "expected_observed"),
    [
        (0, False, False),
        (1, False, False),
        (0, True, False),
        (1, True, True),
    ],
)
def test_docker_invocation_requires_both_launcher_receipt_and_valid_cid(
    tmp_path: Path,
    receipt_count: int,
    write_valid_cid: bool,
    expected_observed: bool,
) -> None:
    cidfile_dir = tmp_path / CANDIDATE_CID_DIRNAME
    cidfile_dir.mkdir()
    if write_valid_cid:
        (cidfile_dir / "candidate.cid").write_text(_CID, encoding="ascii")
    result = BlackboxResult(
        passed=True,
        tests_passed=1,
        tests_total=1,
        diagnostics="",
        ran=True,
        error=None,
        isolation={"requested": "docker", "delivered": "docker"},
        started=True,
        completed=True,
        execution_state="completed",
        execution_phase="blackbox_pack",
        pack_present=True,
    )

    observed = _attach_candidate_execution_evidence(
        result,
        recorder=_ReceiptCount(receipt_count),  # type: ignore[arg-type]
        cidfile_dir=str(cidfile_dir),
    )

    assert observed.candidate_launcher_invocation_observed is expected_observed
    assert observed.candidate_invocations == int(expected_observed)
    assert observed.isolation is not None
    assert observed.isolation["candidate_launcher_events"] == receipt_count
    assert observed.isolation["candidate_container_ids_observed"] == int(
        write_valid_cid
    )
    if expected_observed:
        assert observed.isolation["delivered"] == "docker"
        assert "prepared" not in observed.isolation
    else:
        assert observed.isolation["delivered"] == "not_run"
        assert observed.isolation["prepared"] == "docker"


def test_unavailable_boundary_is_not_relabelled_as_prepared(tmp_path: Path) -> None:
    result = BlackboxResult(
        False,
        0,
        0,
        "daemon unavailable",
        False,
        "isolation unavailable",
        isolation={"requested": "docker", "delivered": "unavailable"},
    )

    observed = _attach_candidate_execution_evidence(
        result,
        recorder=_ReceiptCount(0),  # type: ignore[arg-type]
        cidfile_dir=str(tmp_path / CANDIDATE_CID_DIRNAME),
    )

    assert observed.isolation is not None
    assert observed.isolation["delivered"] == "unavailable"
    assert "prepared" not in observed.isolation
    assert observed.candidate_launcher_invocation_observed is False
