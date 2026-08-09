# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
"""Tests for the deterministic C901 architecture-debt ratchet."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.ci.check_complexity_ratchet import (
    BASELINE_FORMAT,
    ComplexityFinding,
    baseline_document,
    check_complexity_ratchet,
    compare_findings,
    parse_baseline,
    parse_ruff_findings,
)


def _finding(complexity: int = 12) -> ComplexityFinding:
    return ComplexityFinding(
        path="evoom_guard/example.py",
        symbol="decide",
        complexity=complexity,
        threshold=10,
    )


def test_parse_ruff_findings_uses_stable_path_and_symbol(tmp_path: Path) -> None:
    source = tmp_path / "evoom_guard" / "example.py"
    source.parent.mkdir()
    source.touch()

    findings = parse_ruff_findings(
        [
            {
                "code": "C901",
                "filename": str(source),
                "message": "`decide` is too complex (12 > 10)",
            }
        ],
        root=tmp_path,
    )

    assert findings == (_finding(),)


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({"format": "wrong", "rule": "C901", "entries": []}, "format"),
        (
            {
                "format": BASELINE_FORMAT,
                "rule": "C901",
                "entries": [
                    {"path": "../outside.py", "symbol": "f", "max_complexity": 11}
                ],
            },
            "source path",
        ),
        (
            {
                "format": BASELINE_FORMAT,
                "rule": "C901",
                "entries": [
                    {"path": "evoom_guard/a.py", "symbol": "f", "max_complexity": 10}
                ],
            },
            "ceiling",
        ),
    ],
)
def test_parse_baseline_fails_closed(document: object, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_baseline(document)


def test_compare_findings_rejects_new_and_increased_hotspots() -> None:
    baseline = {_finding().key: 11}
    regressions, improvements = compare_findings(
        [_finding(), ComplexityFinding("evoom_guard/new.py", "new", 11, 10)],
        baseline,
    )

    assert len(regressions) == 2
    assert not improvements
    assert "increased" in regressions[0]
    assert "new C901 hotspot" in regressions[1]


def test_compare_findings_reports_decrease_and_removal() -> None:
    old_key = ("evoom_guard/removed.py", "old")
    regressions, improvements = compare_findings([_finding(11)], {_finding().key: 12, old_key: 13})

    assert not regressions
    assert len(improvements) == 2
    assert "decreased" in improvements[0]
    assert "no longer exceeds" in improvements[1]


def test_baseline_document_is_deterministic() -> None:
    later = ComplexityFinding("evoom_guard/z.py", "z", 13, 10)
    document = baseline_document([later, _finding()])

    assert document["format"] == BASELINE_FORMAT
    assert document["entries"][0]["path"] == "evoom_guard/example.py"


def test_repository_complexity_matches_reviewed_baseline() -> None:
    regressions, improvements = check_complexity_ratchet()

    assert not regressions, "\n".join(regressions)
    assert not improvements, (
        "the complexity baseline must be lowered in the same change:\n"
        + "\n".join(improvements)
    )


def test_committed_baseline_is_canonical_json() -> None:
    path = Path(__file__).parents[2] / "tools" / "ci" / "complexity_baseline.json"
    document = json.loads(path.read_text(encoding="utf-8"))

    assert path.read_text(encoding="utf-8") == json.dumps(document, indent=2) + "\n"
