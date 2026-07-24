"""Frozen equivalence gates for the bounded ``guard`` command extraction."""

from __future__ import annotations

import difflib
import json
from pathlib import Path

import pytest

from evoom_guard import cli
from evoom_guard import guard as guard_module
from evoom_guard import signing as signing_module
from evoom_guard.guard import PASS, GuardResult
from tests.cli_guard_command_characterization_harness import (
    CASE_NAMES,
    SCHEMA_VERSION,
    canonical_json,
    capture_case,
)

VECTOR = (
    Path(__file__).parent
    / "fixtures"
    / "refactor-safety"
    / "cli-guard-command-v1.json"
)


def _frozen() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_cli_guard_command_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_cli_guard_command_behavior(case_name: str) -> None:
    expected = _frozen()["cases"][case_name]
    actual = capture_case(case_name)
    if actual != expected:
        diff = "".join(
            difflib.unified_diff(
                canonical_json(expected).splitlines(keepends=True),
                canonical_json(actual).splitlines(keepends=True),
                fromfile=f"frozen/{case_name}",
                tofile=f"current/{case_name}",
            )
        )
        pytest.fail("CLI guard command behavior drifted:\n" + diff)


def _passing_result() -> GuardResult:
    return GuardResult(
        verdict=PASS,
        passed=True,
        reason="controlled pass",
        files_changed=["src/app.py"],
        protected_violations=[],
        risk_level="low",
        risk_score=0.0,
        tests_passed=1,
        tests_total=1,
        verdict_source="junit+exit",
    )


def test_facade_preserves_entry_snapshot_and_later_global_lookups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Guard imports snapshot at entry; later CLI globals resolve at each use."""

    events: list[str] = []

    def early_guard(
        _repo: str, _candidate: str, **_kwargs: object
    ) -> GuardResult:
        events.append("early-guard")
        return _passing_result()

    def late_guard(
        _repo: str, _candidate: str, **_kwargs: object
    ) -> GuardResult:
        pytest.fail("the entry-time Guard import was not retained")

    def early_render(
        _result: GuardResult, *, deleted: list[str]
    ) -> str:
        assert deleted == []
        events.append("early-render")
        return "rendered"

    def late_render(
        _result: GuardResult, *, deleted: list[str]
    ) -> str:
        pytest.fail("the entry-time report import was not retained")

    def late_load(
        _path: str,
        *,
        required: bool,
        out: object,
    ) -> dict[str, object]:
        del out
        assert required is False
        events.append("late-load")
        return {}

    def late_read(_path: str) -> str:
        events.append("late-read")
        return "CANDIDATE"

    def config_path(_args: object) -> str:
        events.append("config-path")
        monkeypatch.setattr(cli, "_load_config", late_load)
        monkeypatch.setattr(cli, "_read_text", late_read)
        monkeypatch.setattr(guard_module, "guard", late_guard)
        monkeypatch.setattr(guard_module, "render_report", late_render)
        return "trusted-policy.json"

    monkeypatch.setattr(guard_module, "guard", early_guard)
    monkeypatch.setattr(guard_module, "render_report", early_render)
    monkeypatch.setattr(cli, "_config_path_for_guard", config_path)
    args = cli.build_parser().parse_args(
        ["guard", "repo", "--patch", "candidate.txt"]
    )

    assert cli.cmd_guard(args, out=lambda message: events.append(message)) == 0
    assert events == [
        "config-path",
        "late-load",
        "late-read",
        "early-guard",
        "early-render",
        "rendered",
    ]


def test_signing_provider_is_resolved_after_json_publication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The historical late signing import remains later than ``write_json``."""

    events: list[str] = []

    def early_sign(_path: str, _key: str) -> str:
        pytest.fail("the signing callable was snapshotted before JSON output")

    def late_sign(path: str, key: str) -> str:
        events.append(f"late-sign:{path}:{key}")
        return path + ".sig"

    def write_json(
        _result: GuardResult, path: str, *, deleted: list[str]
    ) -> None:
        assert deleted == []
        events.append(f"write-json:{path}")
        monkeypatch.setattr(signing_module, "sign_file", late_sign)

    monkeypatch.setattr(signing_module, "sign_file", early_sign)
    monkeypatch.setattr(cli, "_config_path_for_guard", lambda _args: None)
    monkeypatch.setattr(cli, "_read_text", lambda _path: "CANDIDATE")
    monkeypatch.setattr(guard_module, "guard", lambda *_args, **_kwargs: _passing_result())
    monkeypatch.setattr(guard_module, "render_report", lambda *_args, **_kwargs: "report")
    monkeypatch.setattr(guard_module, "write_json", write_json)
    args = cli.build_parser().parse_args(
        [
            "guard",
            "repo",
            "--patch",
            "candidate.txt",
            "--no-config",
            "--json",
            "verdict.json",
            "--sign-key",
            "private.key",
        ]
    )

    assert cli.cmd_guard(args, out=lambda message: events.append(message)) == 0
    assert events == [
        "report",
        "write-json:verdict.json",
        "late-sign:verdict.json:private.key",
        "signed verdict.json -> verdict.json.sig",
    ]
