"""Trust-boundary regressions for required changed-line coverage."""

from __future__ import annotations

import copy
import os
import sys
from pathlib import Path
from typing import Any

import pytest

import evoom_guard.evidence as evidence
from evoom_guard.guard import (
    ERROR,
    PASS,
    REASON_ASSURANCE_REQUIREMENT_NOT_MET,
    guard,
)
from evoom_guard.record_verifier import verify_record

try:
    import coverage as _coverage  # noqa: F401

    HAVE_COVERAGE = True
except ImportError:  # pragma: no cover - depends on the optional cov extra
    HAVE_COVERAGE = False


def _write(root: Path, relative: str, content: str) -> None:
    path = root.joinpath(*relative.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _block(path: str, content: str) -> str:
    return f"<<<FILE: {path}>>>\n{content}<<<END FILE>>>\n"


def _passing_candidate_repo(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write(repo, "app.py", "VALUE = 1\n")
    _write(
        repo,
        "test_app.py",
        "import app\n\n"
        "def test_value():\n"
        "    assert app.VALUE == 2\n",
    )
    return repo, _block("app.py", "VALUE = 2\n")


@pytest.mark.skipif(not HAVE_COVERAGE, reason="needs the optional 'cov' extra")
def test_candidate_coverage_module_and_config_cannot_disable_measurement(
    tmp_path: Path,
) -> None:
    repo, candidate = _passing_candidate_repo(tmp_path)
    candidate += _block("coverage/__init__.py", "")
    candidate += _block("coverage/__main__.py", "raise SystemExit(0)\n")
    candidate += _block(".coveragerc", "[run]\nomit = *\n")

    result = evidence.collect_diff_coverage(str(repo), candidate)

    assert result["measured"] is True
    assert result["files"]["app.py"]["executed"] == [1]


@pytest.mark.skipif(not HAVE_COVERAGE, reason="needs the optional 'cov' extra")
def test_same_process_candidate_can_mutate_live_coverage_data(
    tmp_path: Path,
) -> None:
    """Prove the platform-neutral primitive behind the coverage boundary."""
    from coverage import Coverage

    candidate_path = tmp_path / "candidate.py"
    collector = Coverage(
        data_file=str(tmp_path / "coverage.db"), config_file=False, branch=False
    )
    namespace: dict[str, Any] = {"__file__": str(candidate_path)}
    collector.start()
    try:
        exec(
            compile(
                "from coverage import Coverage\n"
                "current = Coverage.current()\n"
                "assert current is not None\n"
                "current.get_data().add_lines({__file__: {777}})\n"
                "forged = 777 in (current.get_data().lines(__file__) or [])\n",
                str(candidate_path),
                "exec",
            ),
            namespace,
        )
    finally:
        collector.stop()

    assert namespace["forged"] is True


@pytest.mark.skipif(not HAVE_COVERAGE, reason="needs the optional 'cov' extra")
@pytest.mark.skipif(
    os.name == "nt",
    reason=(
        "coverage.py flush ordering makes the end-to-end false-PASS outcome "
        "platform-dependent on Windows; live data writability is pinned separately"
    ),
)
def test_same_process_coverage_state_forgery_is_a_pinned_boundary(
    tmp_path: Path,
) -> None:
    """Pin the honest limit until coverage is produced outside candidate control.

    Isolated startup prevents module/config shadowing, but imported candidate
    code still shares the live coverage object. This test deliberately asserts
    today's stable POSIX false PASS so documentation cannot drift back to an
    adversarial integrity claim. The platform-neutral primitive is pinned by the
    preceding test. When an independently controlled producer lands, invert this
    expectation and update the emitted caveat together.
    """
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    _write(
        repo,
        "app.py",
        "def used():\n"
        "    return 1\n\n"
        "def unused():\n"
        "    return 0\n",
    )
    _write(
        repo,
        "tests/test_app.py",
        "from app import used\n\n"
        "def test_used():\n"
        "    assert used() == 1\n",
    )
    candidate = _block(
        "app.py",
        "from coverage import Coverage\n"
        "_cov = Coverage.current()\n"
        "if _cov is not None:\n"
        "    _cov.get_data().add_lines({__file__: set(range(1, 100))})\n\n"
        "def used():\n"
        "    return 1\n\n"
        "def unused():\n"
        "    secret = 41\n"
        "    return secret + 1\n",
    )

    result = guard(str(repo), candidate, min_diff_coverage=100.0)

    assert result.verdict == PASS
    assert result.diff_coverage is not None
    assert result.diff_coverage["percent"] == 100.0
    assert {10, 11}.issubset(result.diff_coverage["files"]["app.py"]["executed"])
    assert "candidate-writable" in result.diff_coverage["caveat"]


def test_coverage_commands_use_isolated_python_and_ignore_repo_config() -> None:
    data_file = os.path.abspath("judge-coverage.db")
    output_file = os.path.abspath("judge-coverage.json")

    command = evidence._coverage_wrap(
        [sys.executable, "-m", "pytest", "-q"], data_file
    )
    report_command = evidence._coverage_report_command(data_file, output_file)

    assert command == [
        sys.executable,
        "-I",
        "-c",
        evidence._TRUSTED_COVERAGE_LAUNCHER,
        "run",
        f"--rcfile={os.devnull}",
        f"--data-file={data_file}",
        "-m",
        "pytest",
        "-q",
    ]
    assert report_command == [
        sys.executable,
        "-I",
        "-c",
        evidence._TRUSTED_COVERAGE_LAUNCHER,
        "json",
        f"--rcfile={os.devnull}",
        f"--data-file={data_file}",
        "-o",
        output_file,
        "-q",
    ]


def test_external_or_cross_drive_coverage_paths_are_ignored_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def cross_drive_relpath(_path: str, _root: str) -> str:
        raise ValueError("path is on mount 'D:', start on mount 'C:'")

    monkeypatch.setattr(evidence.os.path, "isabs", lambda _path: True)
    monkeypatch.setattr(evidence.os.path, "relpath", cross_drive_relpath)

    assert evidence._normalize_coverage_report_path("D:\\shared\\helper.py", "C:\\repo") is None


def test_coverage_path_normalization_accepts_only_repo_relative_paths(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    assert evidence._normalize_coverage_report_path("pkg\\app.py", str(repo)) == (
        "pkg/app.py"
    )
    assert evidence._normalize_coverage_report_path("../outside.py", str(repo)) is None


def test_coverage_command_preserves_trusted_interpreter_and_wrapper_prefixes() -> None:
    data_file = os.path.abspath("judge-coverage.db")
    output_file = os.path.abspath("judge-coverage.json")

    interpreter_command = evidence._coverage_wrap(
        [".venv/python", "-m", "pytest", "pytest", "-q"], data_file
    )
    wrapper_command = evidence._coverage_wrap(
        ["uv", "run", "pytest", "-q"], data_file
    )
    marker_command = evidence._coverage_wrap(
        ["uv", "run", "pytest", "-m", "pytest"], data_file
    )
    windows_launcher_command = evidence._coverage_wrap(
        ["py", "-3.12", "-m", "pytest", "-q"], data_file
    )
    wrapper_report_command = evidence._coverage_report_command(
        data_file, output_file, ["uv", "run", "pytest", "-q"]
    )

    isolated_tail = [
        "-I",
        "-c",
        evidence._TRUSTED_COVERAGE_LAUNCHER,
        "run",
        f"--rcfile={os.devnull}",
        f"--data-file={data_file}",
        "-m",
        "pytest",
        "-q",
    ]
    assert interpreter_command == [
        ".venv/python",
        *isolated_tail[:-1],
        "pytest",
        "-q",
    ]
    assert wrapper_command == ["uv", "run", "python", *isolated_tail]
    assert marker_command == [
        "uv",
        "run",
        "python",
        *isolated_tail[:-1],
        "-m",
        "pytest",
    ]
    assert windows_launcher_command == ["py", "-3.12", *isolated_tail]
    assert wrapper_report_command == [
        "uv",
        "run",
        "python",
        "-I",
        "-c",
        evidence._TRUSTED_COVERAGE_LAUNCHER,
        "json",
        f"--rcfile={os.devnull}",
        f"--data-file={data_file}",
        "-o",
        output_file,
        "-q",
    ]
    assert evidence._coverage_wrap(["sh", "-c", "pytest -q"], data_file) is None
    assert evidence._coverage_wrap(["sh", "-c", "pytest"], data_file) is None


@pytest.mark.skipif(not HAVE_COVERAGE, reason="needs the optional 'cov' extra")
def test_optional_evidence_can_measure_a_failing_suite(tmp_path: Path) -> None:
    repo, _candidate = _passing_candidate_repo(tmp_path)

    result = evidence.collect_diff_coverage(
        str(repo), _block("app.py", "VALUE = 3\n")
    )

    assert result["measured"] is True
    assert result["files"]["app.py"]["executed"] == [1]


@pytest.mark.skipif(not HAVE_COVERAGE, reason="needs the optional 'cov' extra")
def test_required_coverage_rejects_a_wrapped_suite_that_does_not_pass(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write(repo, "app.py", "VALUE = 1\n")
    _write(
        repo,
        "test_app.py",
        "import sys\n\n"
        "import app\n\n"
        "def test_value():\n"
        "    assert app.VALUE == 2\n"
        "    assert 'coverage' not in sys.modules\n",
    )

    result = guard(
        str(repo),
        _block("app.py", "VALUE = 2\n"),
        diff_coverage=True,
        min_diff_coverage=80.0,
        test_command=[sys.executable, "-m", "pytest", "-p", "no:cov", "-q"],
    )

    assert result.verdict == ERROR
    assert result.reason_code == REASON_ASSURANCE_REQUIREMENT_NOT_MET
    assert "coverage-wrapped pytest run did not pass" in result.reason


@pytest.mark.skipif(not HAVE_COVERAGE, reason="needs the optional 'cov' extra")
def test_inline_no_cover_cannot_remove_changed_statements_from_the_floor(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write(
        repo,
        "app.py",
        "def covered():\n"
        "    return 1\n",
    )
    _write(
        repo,
        "test_app.py",
        "from app import covered\n\n"
        "def test_covered():\n"
        "    assert covered() == 1\n",
    )
    candidate = _block(
        "app.py",
        "def covered():\n"
        "    return 1 + 0\n\n"
        "def hidden():  # pragma: no cover\n"
        "    return 2\n",
    )

    result = guard(str(repo), candidate, min_diff_coverage=80.0)

    assert result.verdict == "FAIL"
    assert result.diff_coverage is not None
    assert result.diff_coverage["executed"] < result.diff_coverage["total"]
    detail = result.diff_coverage["files"]["app.py"]
    assert detail["missed"]
    assert "excluded" in detail["note"]


@pytest.mark.skipif(not HAVE_COVERAGE, reason="needs the optional 'cov' extra")
def test_multiline_statement_continuation_cannot_disappear_from_the_floor(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write(
        repo,
        "app.py",
        "def covered():\n"
        "    return 1\n\n"
        "def hidden():\n"
        "    return (\n"
        "        1\n"
        "    )\n",
    )
    _write(
        repo,
        "test_app.py",
        "from app import covered\n\n"
        "def test_covered():\n"
        "    assert covered() == 1\n",
    )
    candidate = _block(
        "app.py",
        "def covered():\n"
        "    return 1\n\n"
        "def hidden():\n"
        "    return (\n"
        "        2\n"
        "    )\n",
    )

    result = guard(str(repo), candidate, min_diff_coverage=100.0)

    assert result.verdict == "FAIL"
    assert result.diff_coverage is not None
    assert result.diff_coverage["executed"] == 0
    assert result.diff_coverage["total"] == 1


@pytest.mark.skipif(not HAVE_COVERAGE, reason="needs the optional 'cov' extra")
def test_short_circuited_continuation_is_not_inferred_executed(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write(
        repo,
        "app.py",
        "VALUE = (\n"
        "    True or\n"
        "    (1 / 0)\n"
        ")\n",
    )
    _write(
        repo,
        "test_app.py",
        "import app\n\n"
        "def test_value():\n"
        "    assert app.VALUE is True\n",
    )
    candidate = _block(
        "app.py",
        "VALUE = (\n"
        "    True or\n"
        "    (999 / 0)\n"
        ")\n",
    )

    result = guard(str(repo), candidate, min_diff_coverage=100.0)

    assert result.verdict == "FAIL"
    assert result.diff_coverage is not None
    assert result.diff_coverage["executed"] == 0
    assert result.diff_coverage["total"] == 1
    assert result.diff_coverage["files"]["app.py"]["missed"] == [3]


@pytest.mark.skipif(not HAVE_COVERAGE, reason="needs the optional 'cov' extra")
def test_docstring_only_change_is_not_a_false_coverage_gap(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write(
        repo,
        "app.py",
        "def value():\n"
        "    '''old documentation'''\n"
        "    return 1\n",
    )
    _write(
        repo,
        "test_app.py",
        "from app import value\n\n"
        "def test_value():\n"
        "    assert value() == 1\n",
    )
    candidate = _block(
        "app.py",
        "def value():\n"
        "    '''new documentation'''\n"
        "    return 1\n",
    )

    result = guard(str(repo), candidate, min_diff_coverage=100.0)

    assert result.verdict == PASS
    assert result.diff_coverage is not None
    assert result.diff_coverage["total"] == 0


@pytest.mark.skipif(not HAVE_COVERAGE, reason="needs the optional 'cov' extra")
def test_code_after_docstring_on_the_same_line_remains_in_the_floor(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write(
        repo,
        "app.py",
        "def covered():\n"
        "    return 1\n\n"
        "def hidden():\n"
        "    'old'; return 1\n",
    )
    _write(
        repo,
        "test_app.py",
        "from app import covered\n\n"
        "def test_covered():\n"
        "    assert covered() == 1\n",
    )
    candidate = _block(
        "app.py",
        "def covered():\n"
        "    return 1\n\n"
        "def hidden():\n"
        "    'new'; return 999\n",
    )

    result = guard(str(repo), candidate, min_diff_coverage=100.0)

    assert result.verdict == "FAIL"
    assert result.diff_coverage is not None
    assert result.diff_coverage["executed"] == 0
    assert result.diff_coverage["total"] == 1
    assert result.diff_coverage["files"]["app.py"]["missed"] == [5]


@pytest.mark.skipif(not HAVE_COVERAGE, reason="needs the optional 'cov' extra")
def test_tokenizer_failure_counts_touched_lines_conservatively(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write(repo, "unused.py", "VALUE = 1\n")
    _write(repo, "test_smoke.py", "def test_smoke():\n    assert True\n")

    result = guard(
        str(repo), _block("unused.py", "'''unterminated\n"), min_diff_coverage=100.0
    )

    assert result.verdict == "FAIL"
    assert result.diff_coverage is not None
    assert result.diff_coverage["executed"] == 0
    assert result.diff_coverage["total"] == 1
    assert result.diff_coverage["files"]["unused.py"]["missed"] == [1]


@pytest.mark.skipif(not HAVE_COVERAGE, reason="needs the optional 'cov' extra")
def test_comment_only_change_in_unimported_file_is_not_a_false_gap(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write(repo, "unused.py", "# old comment\nVALUE = 1\n")
    _write(
        repo,
        "test_smoke.py",
        "def test_smoke():\n"
        "    assert True\n",
    )
    candidate = _block("unused.py", "# new comment\nVALUE = 1\n")

    result = guard(str(repo), candidate, min_diff_coverage=100.0)

    assert result.verdict == PASS
    assert result.diff_coverage is not None
    assert result.diff_coverage["total"] == 0
    assert result.diff_coverage["files"]["unused.py"]["missed"] == []


@pytest.mark.skipif(not HAVE_COVERAGE, reason="needs the optional 'cov' extra")
def test_structured_file_blocks_are_the_coverage_diff_ground_truth(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    base = (
        "MARKER = '''<<<END FILE>>>'''\n\n"
        "def covered():\n"
        "    return 1\n\n"
        "def hidden():\n"
        "    return 1\n"
    )
    head = base.replace("return 1\n\n", "return 1 + 0\n\n", 1).replace(
        "    return 1\n", "    return 2\n", 1
    )
    _write(repo, "app.py", base)
    _write(
        repo,
        "test_app.py",
        "from app import covered\n\n"
        "def test_covered():\n"
        "    assert covered() == 1\n",
    )
    candidate = _block("app.py", head)

    result = guard(
        str(repo),
        candidate,
        file_blocks={"app.py": head},
        min_diff_coverage=80.0,
    )

    assert result.verdict == "FAIL"
    assert result.diff_coverage is not None
    assert result.diff_coverage["executed"] < result.diff_coverage["total"]


@pytest.mark.skipif(not HAVE_COVERAGE, reason="needs the optional 'cov' extra")
def test_python_api_coverage_floor_implies_measurement(tmp_path: Path) -> None:
    repo, candidate = _passing_candidate_repo(tmp_path)

    result = guard(str(repo), candidate, min_diff_coverage=100.0)

    assert result.verdict == PASS
    assert result.diff_coverage is not None
    assert result.diff_coverage["measured"] is True


@pytest.mark.skipif(not HAVE_COVERAGE, reason="needs the optional 'cov' extra")
def test_coverage_replays_setup_with_the_main_fidelity_policy(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write(
        repo,
        "app.py",
        "from generated import VALUE\n\n"
        "def value():\n"
        "    return VALUE\n",
    )
    _write(
        repo,
        "test_app.py",
        "from app import value\n\n"
        "def test_value():\n"
        "    assert value() == 1\n",
    )
    setup_command = [
        sys.executable,
        "-c",
        (
            "from pathlib import Path; "
            "Path('generated.py').write_text('VALUE = 1\\n', encoding='utf-8')"
        ),
    ]
    candidate = _block(
        "app.py",
        "from generated import VALUE\n\n"
        "def value():\n"
        "    return VALUE + 0\n",
    )

    result = guard(
        str(repo),
        candidate,
        setup_command=setup_command,
        setup_output_globs=("generated.py",),
        min_diff_coverage=100.0,
    )

    assert result.verdict == PASS
    assert result.diff_coverage is not None
    assert result.diff_coverage["executed"] == 1
    assert result.diff_coverage["total"] == 1


@pytest.mark.skipif(not HAVE_COVERAGE, reason="needs the optional 'cov' extra")
def test_coverage_setup_cannot_rewrite_judged_source(tmp_path: Path) -> None:
    repo, candidate = _passing_candidate_repo(tmp_path)
    setup_command = [
        sys.executable,
        "-c",
        "from pathlib import Path; Path('app.py').write_text('VALUE = 3\\n')",
    ]

    result = evidence.collect_diff_coverage(
        str(repo), candidate, setup_command=setup_command
    )

    assert result["measured"] is False
    assert "changed judged paths outside declared outputs" in result["note"]
    assert "app.py" in result["note"]


@pytest.mark.skipif(not HAVE_COVERAGE, reason="needs the optional 'cov' extra")
def test_coverage_subprocesses_receive_the_main_resource_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, candidate = _passing_candidate_repo(tmp_path)
    original_run = evidence._run_bounded_subprocess
    sentinel = object()
    observed: list[object] = []

    monkeypatch.setattr(
        evidence, "_coverage_preexec", lambda *_args, **_kwargs: sentinel
    )

    def recording_run(*args: object, **kwargs: Any) -> Any:
        observed.append(kwargs.get("preexec_fn"))
        kwargs["preexec_fn"] = None
        return original_run(*args, **kwargs)

    monkeypatch.setattr(evidence, "_run_bounded_subprocess", recording_run)

    result = evidence.collect_diff_coverage(
        str(repo),
        candidate,
        setup_command=[sys.executable, "-c", "pass"],
        mem_limit_mb=64,
    )

    assert result["measured"] is True
    assert observed == [sentinel, sentinel, sentinel]


def test_guard_forwards_the_configured_memory_limit_to_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, candidate = _passing_candidate_repo(tmp_path)
    observed: dict[str, Any] = {}

    def measured(*_args: object, **kwargs: Any) -> dict[str, Any]:
        observed.update(kwargs)
        return {
            "measured": True,
            "percent": 100.0,
            "executed": 1,
            "total": 1,
            "files": {"app.py": {"executed": [1], "missed": []}},
            "unmeasured_files": [],
            "caveat": evidence.EXECUTED_IS_NOT_ASSERTED,
        }

    monkeypatch.setattr(evidence, "collect_diff_coverage", measured)

    result = guard(
        str(repo), candidate, mem_limit_mb=0, min_diff_coverage=100.0
    )

    assert result.verdict == PASS
    assert observed["mem_limit_mb"] == 0


@pytest.mark.skipif(not HAVE_COVERAGE, reason="needs the optional 'cov' extra")
def test_exact_ratio_not_rounded_display_controls_the_floor(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write(
        repo,
        "app.py",
        "def first():\n    return 1\n\n"
        "def second():\n    return 1\n\n"
        "def hidden():\n    return 1\n",
    )
    _write(
        repo,
        "test_app.py",
        "from app import first, second\n\n"
        "def test_visible():\n"
        "    assert first() == 1\n"
        "    assert second() == 1\n",
    )
    candidate = _block(
        "app.py",
        "def first():\n    return 1 + 0\n\n"
        "def second():\n    return 1 + 0\n\n"
        "def hidden():\n    return 2\n",
    )

    # This float is just above the exact 2/3 ratio. Multiplying it by three
    # rounds to 200.0, so float cross-multiplication would incorrectly pass too.
    result = guard(
        str(repo), candidate, min_diff_coverage=66.66666666666667
    )

    assert result.verdict == "FAIL"
    assert result.reason_code == "diff_coverage_below_threshold"
    assert result.diff_coverage is not None
    assert result.diff_coverage["executed"] == 2
    assert result.diff_coverage["total"] == 3
    assert result.diff_coverage["percent"] == 66.7
    report = verify_record(result.to_dict())
    assert report["ok"] is True, [
        check for check in report["checks"] if check["status"] == "fail"
    ]


@pytest.mark.skipif(not HAVE_COVERAGE, reason="needs the optional 'cov' extra")
def test_baseline_effect_survives_a_later_coverage_gate_demotion(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write(
        repo,
        "app.py",
        "def fixed():\n    return 0\n\ndef untested():\n    return 0\n",
    )
    _write(
        repo,
        "test_app.py",
        "from app import fixed\n\ndef test_fixed():\n    assert fixed() == 1\n",
    )
    candidate = _block(
        "app.py",
        "def fixed():\n    return 1\n\ndef untested():\n    return 2\n",
    )

    record = guard(
        str(repo),
        candidate,
        min_diff_coverage=100.0,
        baseline_evidence=True,
        require_demonstrated_fix=True,
    ).to_dict()

    assert record["verdict"] == "FAIL"
    assert record["reason_code"] == "diff_coverage_below_threshold"
    assert record["baseline"]["verdict"] == "FAIL"
    assert record["baseline"]["repair_effect"] == "demonstrated"
    assert verify_record(record)["ok"] is True

    forged = copy.deepcopy(record)
    forged["baseline"]["repair_effect"] = "not_demonstrated"
    report = verify_record(forged)
    assert report["ok"] is False
    baseline_check = next(
        check
        for check in report["checks"]
        if check["id"] == "baseline.policy_semantics"
    )
    assert baseline_check["status"] == "fail"


def test_required_coverage_fails_closed_when_measurement_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, candidate = _passing_candidate_repo(tmp_path)

    def unavailable(*_args: object, **_kwargs: object) -> dict[str, Any]:
        return {
            "measured": False,
            "note": "coverage report was unavailable",
            "unmeasured_files": [],
            "caveat": evidence.EXECUTED_IS_NOT_ASSERTED,
        }

    monkeypatch.setattr(evidence, "collect_diff_coverage", unavailable)

    result = guard(
        str(repo), candidate, diff_coverage=True, min_diff_coverage=80.0
    )

    assert result.verdict == ERROR
    assert result.reason_code == REASON_ASSURANCE_REQUIREMENT_NOT_MET
    assert "required changed-line coverage could not be measured" in result.reason


def test_optional_coverage_remains_evidence_only_when_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, candidate = _passing_candidate_repo(tmp_path)

    def unavailable(*_args: object, **_kwargs: object) -> dict[str, Any]:
        return {
            "measured": False,
            "note": "coverage report was unavailable",
            "unmeasured_files": [],
            "caveat": evidence.EXECUTED_IS_NOT_ASSERTED,
        }

    monkeypatch.setattr(evidence, "collect_diff_coverage", unavailable)

    result = guard(str(repo), candidate, diff_coverage=True)

    assert result.verdict == PASS
    assert result.diff_coverage is not None
    assert result.diff_coverage["measured"] is False
