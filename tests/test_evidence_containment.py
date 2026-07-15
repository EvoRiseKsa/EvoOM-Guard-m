"""Containment regressions for opt-in changed-line coverage evidence."""

from __future__ import annotations

import sys
from pathlib import Path

import evoom_guard.evidence as evidence
from evoom_guard.verifiers.repo_verifier import _SubprocessOutputLimitExceeded


def _candidate() -> str:
    return "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n"


def test_coverage_report_reader_rejects_oversized_file_before_decode(
    tmp_path: Path, monkeypatch
) -> None:
    report = tmp_path / "judge-coverage.json"
    report.write_bytes(b"x" * 4096)
    monkeypatch.setattr(evidence, "_MAX_COVERAGE_REPORT_BYTES", 1024)

    assert evidence._read_coverage_files(str(report)) is None


def test_diff_coverage_output_limit_degrades_to_explicit_unmeasured_evidence(
    tmp_path: Path, monkeypatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    # ``collect_diff_coverage`` only needs the import to exist before it reaches
    # the mocked judge command; avoid coupling this regression to the extras set.
    monkeypatch.setitem(sys.modules, "coverage", object())

    def overflow(*_args: object, **_kwargs: object) -> None:
        raise _SubprocessOutputLimitExceeded(128)

    monkeypatch.setattr(evidence, "_run_bounded_subprocess", overflow)
    result = evidence.collect_diff_coverage(str(repo), _candidate())

    assert result["measured"] is False
    assert "output exceeded the judge capture limit" in result["note"]
