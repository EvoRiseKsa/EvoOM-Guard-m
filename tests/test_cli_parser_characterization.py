"""Frozen parser characterization for the bounded parser-owner extraction."""

from __future__ import annotations

import json
from pathlib import Path

from tests.cli_parser_characterization_harness import snapshot

FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "cli_parser_characterization_v1.json"
)


def test_cli_parser_matches_frozen_characterization() -> None:
    expected = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert snapshot() == expected
