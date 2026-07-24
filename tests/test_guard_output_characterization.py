"""Frozen byte and lookup contracts for the Guard-output extraction."""

from __future__ import annotations

import builtins
import difflib
import inspect
import io
import json
import os
from pathlib import Path
from typing import Any

import pytest

from evoom_guard import guard as guard_module
from evoom_guard.guard import ERROR, PASS, GuardResult
from tests.guard_output_characterization_harness import (
    CASE_NAMES,
    SCHEMA_VERSION,
    canonical_json,
    capture_case,
)

VECTOR = (
    Path(__file__).parent
    / "fixtures"
    / "refactor-safety"
    / "guard-output-v1.json"
)


def _frozen() -> dict[str, Any]:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def _result(verdict: str = PASS) -> GuardResult:
    return GuardResult(
        verdict=verdict,
        passed=verdict == PASS,
        reason="controlled",
        files_changed=["src/app.py"],
        protected_violations=[],
        risk_level="low",
        risk_score=0.1,
        reason_code="tests_passed" if verdict == PASS else "controlled_error",
    )


def test_guard_output_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == CASE_NAMES


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_guard_output_matches_frozen_wire_behavior(
    case_name: str,
    tmp_path: Path,
) -> None:
    expected = _frozen()["cases"][case_name]
    actual = capture_case(case_name, tmp_path)
    if actual != expected:
        diff = "".join(
            difflib.unified_diff(
                canonical_json(expected).splitlines(keepends=True),
                canonical_json(actual).splitlines(keepends=True),
                fromfile=f"frozen/{case_name}",
                tofile=f"current/{case_name}",
            )
        )
        pytest.fail("Guard output wire behavior drifted:\n" + diff)


@pytest.mark.parametrize("case_name", CASE_NAMES)
@pytest.mark.parametrize("field", ("json_text", "sarif_text"))
def test_guard_output_writers_match_platform_bytes_exactly(
    case_name: str,
    field: str,
    tmp_path: Path,
) -> None:
    actual = capture_case(case_name, tmp_path)
    expected_text = _frozen()["cases"][case_name][field]
    expected_bytes = expected_text.replace("\n", os.linesep).encode("utf-8")
    suffix = ".json" if field == "json_text" else ".sarif"
    assert (tmp_path / f"{case_name}{suffix}").read_bytes() == expected_bytes
    assert actual[field] == expected_text


def test_guard_output_public_facade_signatures_are_frozen() -> None:
    assert str(inspect.signature(guard_module.render_report)) == (
        "(result: 'GuardResult', *, deleted: 'list[str] | None' = None, "
        "title: 'str' = 'EvoGuard') -> 'str'"
    )
    assert str(inspect.signature(guard_module.write_json)) == (
        "(result: 'GuardResult', path: 'str', *, "
        "deleted: 'list[str] | None' = None) -> 'None'"
    )
    assert str(inspect.signature(guard_module.to_sarif)) == (
        "(result: 'GuardResult') -> 'dict[str, Any]'"
    )
    assert str(inspect.signature(guard_module.write_sarif)) == (
        "(result: 'GuardResult', path: 'str') -> 'None'"
    )


def test_write_sarif_resolves_converter_after_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Freeze the historical lookup: the converter resolves inside the open."""

    events: list[str] = []

    def early_converter(_result: GuardResult) -> dict[str, Any]:
        pytest.fail("to_sarif was snapshotted before opening the destination")

    def late_converter(_result: GuardResult) -> dict[str, Any]:
        events.append("late-converter")
        return {"late": True}

    class RebindingWriter(io.StringIO):
        def __enter__(self) -> RebindingWriter:
            events.append("open")
            monkeypatch.setattr(guard_module, "to_sarif", late_converter)
            return self

        def __exit__(self, *_args: object) -> bool:
            return False

    writer = RebindingWriter()
    monkeypatch.setattr(guard_module, "to_sarif", early_converter)
    monkeypatch.setattr(builtins, "open", lambda *_args, **_kwargs: writer)

    guard_module.write_sarif(_result(ERROR), "ignored.sarif")

    assert events == ["open", "late-converter"]
    assert writer.getvalue() == '{\n  "late": true\n}'


def test_render_report_resolves_the_compatibility_badge_mapping_live(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(guard_module, "_BADGE", {PASS: "CONTROLLED BADGE"})

    assert guard_module.render_report(_result()).startswith(
        "## EvoGuard — CONTROLLED BADGE"
    )


def test_guard_output_facades_delegate_to_the_live_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The compatibility facade must not snapshot the extracted provider."""

    from evoom_guard.integrations import guard_output

    events: list[str] = []

    def late_owner(
        _result: object,
        *,
        deleted: list[str] | None,
        title: str,
        badge_provider: object,
        **_providers: object,
    ) -> str:
        del badge_provider
        events.append(f"{title}:{deleted}")
        return "owned"

    monkeypatch.setattr(guard_output, "render_report", late_owner)

    assert guard_module.render_report(_result(), deleted=["gone.py"]) == "owned"
    assert events == ["EvoGuard:['gone.py']"]


def test_output_owner_sarif_non_pass_is_not_suppressed() -> None:
    result = guard_module.to_sarif(_result(ERROR))

    assert len(result["runs"][0]["results"]) == 1
    assert result["runs"][0]["results"][0]["level"] == "error"
