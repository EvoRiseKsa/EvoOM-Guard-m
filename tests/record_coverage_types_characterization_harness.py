# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Deterministic pre-extraction characterization for coverage-record validation."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import random
from pathlib import Path
from typing import Any, cast

from evoom_guard import record_verifier

ROOT = Path(__file__).resolve().parents[1]
GOLDEN_RECORD = ROOT / "tests/fixtures/contracts/schema-1.11-golden.json"


def valid_measured() -> dict[str, Any]:
    return {
        "measured": True,
        "percent": 66.7,
        "executed": 2,
        "total": 3,
        "files": {
            "src/a.py": {
                "executed": [1, 3],
                "missed": [2],
                "note": "branch-aware source lines",
            }
        },
        "unmeasured_files": ["README.md"],
        "caveat": "non-Python files are not measured",
    }


def valid_unmeasured(*, detailed: bool = False) -> dict[str, Any]:
    value: dict[str, Any] = {
        "measured": False,
        "note": "coverage collection unavailable",
    }
    if detailed:
        value.update(
            {
                "unmeasured_files": ["README.md"],
                "caveat": "no supported line collector",
            }
        )
    return value


def _updated(
    base: dict[str, Any],
    *,
    updates: dict[object, Any] | None = None,
    removed: tuple[str, ...] = (),
) -> dict[str, Any]:
    value = copy.deepcopy(base)
    for field in removed:
        value.pop(field, None)
    if updates:
        for field, item in updates.items():
            value[cast(str, field)] = copy.deepcopy(item)
    return value


def cases() -> dict[str, dict[str, Any]]:
    measured = valid_measured()
    unmeasured = valid_unmeasured()
    detailed = valid_unmeasured(detailed=True)
    return {
        "valid_measured": measured,
        "valid_unmeasured": unmeasured,
        "valid_unmeasured_detailed": detailed,
        "non_string_top_key": _updated(measured, updates={7: "value"}),
        "measured_missing_and_extra": _updated(
            measured,
            removed=("caveat",),
            updates={"extra": True},
        ),
        "percent_bool": _updated(measured, updates={"percent": True}),
        "percent_non_finite": _updated(measured, updates={"percent": math.inf}),
        "percent_out_of_range": _updated(measured, updates={"percent": 100.1}),
        "counts_bool_and_negative": _updated(
            measured,
            updates={"executed": True, "total": -1},
        ),
        "files_not_object": _updated(measured, updates={"files": []}),
        "unsafe_python_paths": _updated(
            measured,
            updates={
                "files": {
                    "/abs.py": {"executed": [1], "missed": []},
                    "src\\alias.py": {"executed": [1], "missed": []},
                    "src/../escape.py": {"executed": [1], "missed": []},
                    "src/not-python.txt": {"executed": [1], "missed": []},
                }
            },
        ),
        "detail_not_object": _updated(
            measured,
            updates={"files": {"src/a.py": []}},
        ),
        "detail_non_string_key": _updated(
            measured,
            updates={"files": {"src/a.py": {7: [], "executed": [1], "missed": []}}},
        ),
        "detail_invalid_shape": _updated(
            measured,
            updates={"files": {"src/a.py": {"executed": [1], "missed": [], "extra": True}}},
        ),
        "line_arrays_invalid": _updated(
            measured,
            updates={"files": {"src/a.py": {"executed": [2, 1, 1], "missed": [True, 0]}}},
        ),
        "line_arrays_overlap": _updated(
            measured,
            updates={"files": {"src/a.py": {"executed": [1, 2], "missed": [2, 3]}}},
        ),
        "detail_note_empty": _updated(
            measured,
            updates={"files": {"src/a.py": {"executed": [1, 3], "missed": [2], "note": ""}}},
        ),
        "unsafe_unmeasured_paths": _updated(
            measured,
            updates={"unmeasured_files": ["README.md", "src/a.py"]},
        ),
        "coverage_caveat_empty": _updated(measured, updates={"caveat": ""}),
        "executed_total_mismatch": _updated(
            measured,
            updates={"executed": 1, "total": 4},
        ),
        "percent_mismatch": _updated(measured, updates={"percent": 66.6}),
        "unmeasured_invalid_shape": _updated(unmeasured, updates={"extra": True}),
        "unmeasured_note_empty": _updated(unmeasured, updates={"note": ""}),
        "unmeasured_files_unsorted": _updated(
            detailed,
            updates={"unmeasured_files": ["z", "a", "a"]},
        ),
        "unmeasured_caveat_empty": _updated(detailed, updates={"caveat": ""}),
        "measured_not_boolean": _updated(measured, updates={"measured": 1}),
    }


def capture(value: dict[str, Any]) -> list[str]:
    before = copy.deepcopy(value)
    result = record_verifier._diff_coverage_type_errors(value)
    assert value == before
    return result


def capture_all() -> dict[str, list[str]]:
    return {name: capture(value) for name, value in cases().items()}


def public_cases() -> dict[str, dict[str, Any]]:
    payload = json.loads(GOLDEN_RECORD.read_text(encoding="utf-8"))
    base = cast(dict[str, Any], payload["records"]["valid_composite"])
    result: dict[str, dict[str, Any]] = {}
    for name in (
        "valid_measured",
        "line_arrays_overlap",
        "executed_total_mismatch",
        "measured_not_boolean",
    ):
        record = copy.deepcopy(base)
        record["diff_coverage"] = copy.deepcopy(cases()[name])
        result[name] = record
    return result


def capture_public_all() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for name, record in public_cases().items():
        before = copy.deepcopy(record)
        result[name] = record_verifier.verify_record(record)
        assert record == before
    return result


def generated_trace_digest(*, count: int = 20_000) -> str:
    randomizer = random.Random(0xE70C0A6E)
    fields = (
        "measured",
        "percent",
        "executed",
        "total",
        "files",
        "unmeasured_files",
        "caveat",
        "note",
    )
    values: tuple[Any, ...] = (
        None,
        False,
        True,
        -1,
        0,
        1,
        50.0,
        100.0,
        "",
        "value",
        [],
        ["a", "b"],
        {},
        {"src/a.py": {"executed": [1], "missed": []}},
    )
    digest = hashlib.sha256()
    for _ in range(count):
        base = valid_measured() if randomizer.randrange(2) else valid_unmeasured(detailed=True)
        for _ in range(1 + randomizer.randrange(4)):
            field = randomizer.choice(fields)
            if randomizer.randrange(5) == 0:
                base.pop(field, None)
            else:
                base[field] = copy.deepcopy(randomizer.choice(values))
        trace = capture(base)
        digest.update(json.dumps(trace, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()
