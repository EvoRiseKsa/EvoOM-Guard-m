# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Deterministic pre-extraction characterization for record envelope types."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import random
from collections import UserDict
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeGuard, cast

from evoom_guard import record_verifier

ROOT = Path(__file__).resolve().parents[1]
GOLDEN_RECORD = ROOT / "tests/fixtures/contracts/schema-1.11-golden.json"

_STRING_FIELDS = (
    "schema_version",
    "tool",
    "tool_version",
    "verdict",
    "reason_code",
    "reason",
    "risk_level",
    "execution_state",
    "execution_phase",
    "isolation",
    "diagnostics",
)
_BOOLEAN_FIELDS = ("passed", "test_command_ran")
_NULLABLE_INTEGER_FIELDS = ("tests_passed", "tests_total")
_STRING_LIST_FIELDS = ("files_changed", "protected_violations")
_NULLABLE_STRING_FIELDS = ("verdict_source", "source", "base_reconstruction")
_NULLABLE_OBJECT_FIELDS = ("diff_coverage", "baseline")

Projector = Callable[[dict[str, Any]], list[str] | tuple[str, ...]]


class CoverageDict(dict[str, Any]):
    pass


class BaselineDict(dict[str, Any]):
    pass


class AssuranceDict(dict[str, Any]):
    pass


class AttestationDict(dict[str, Any]):
    pass


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> TypeGuard[int | float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return isinstance(value, int) or math.isfinite(value)


def _is_string_list(value: object) -> TypeGuard[list[str]]:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _is_nullable_int(value: object) -> bool:
    return value is None or _is_int(value)


def _is_nullable_string(value: object) -> bool:
    return value is None or isinstance(value, str)


def legacy_top_level_type_errors(record: dict[str, Any]) -> list[str]:
    """Frozen exact implementation from protected main before extraction."""

    errors: list[str] = []
    for field in _STRING_FIELDS:
        if field in record and not isinstance(record[field], str):
            errors.append(f"{field} must be a string")
    for field in _BOOLEAN_FIELDS:
        if field in record and not isinstance(record[field], bool):
            errors.append(f"{field} must be a boolean")
    if "exit_code" in record and not _is_int(record["exit_code"]):
        errors.append("exit_code must be an integer")
    if "risk_score" in record and not _is_number(record["risk_score"]):
        errors.append("risk_score must be a number")
    for field in _NULLABLE_INTEGER_FIELDS:
        if field in record and not _is_nullable_int(record[field]):
            errors.append(f"{field} must be a non-boolean integer or null")
    for field in _STRING_LIST_FIELDS:
        if field in record and not _is_string_list(record[field]):
            errors.append(f"{field} must be an array of strings")
    for field in _NULLABLE_STRING_FIELDS:
        if field in record and not _is_nullable_string(record[field]):
            errors.append(f"{field} must be a string or null")
    for field in _NULLABLE_OBJECT_FIELDS:
        if field in record and record[field] is not None and not isinstance(
            record[field], dict
        ):
            errors.append(f"{field} must be an object or null")
    if "assurance" in record and not isinstance(record["assurance"], dict):
        errors.append("assurance must be an object")
    if (
        "attestation" in record
        and record["attestation"] is not None
        and not isinstance(record["attestation"], dict)
    ):
        errors.append("attestation must be an object or null")
    return errors


def valid_envelope() -> dict[str, Any]:
    return {
        "schema_version": "1.11",
        "tool": "evoguard",
        "tool_version": "characterization",
        "verdict": "PASS",
        "reason_code": "tests_passed",
        "reason": "all required phases passed",
        "risk_level": "low",
        "execution_state": "completed",
        "execution_phase": "repo_suite",
        "isolation": "subprocess",
        "diagnostics": "",
        "passed": True,
        "test_command_ran": True,
        "exit_code": 0,
        "risk_score": 0.5,
        "tests_passed": 3,
        "tests_total": 3,
        "files_changed": ["src/app.py"],
        "protected_violations": [],
        "verdict_source": "composite:blackbox+repo",
        "source": "diff",
        "base_reconstruction": "ok",
        "diff_coverage": {"measured": True},
        "baseline": None,
        "assurance": {},
        "attestation": None,
    }


def _updated(base: dict[str, Any], **updates: Any) -> dict[str, Any]:
    result = copy.deepcopy(base)
    result.update(copy.deepcopy(updates))
    return result


def cases() -> dict[str, dict[str, Any]]:
    valid = valid_envelope()
    result: dict[str, dict[str, Any]] = {
        "valid_all": valid,
        "valid_empty": {},
        "valid_nullable_fields": _updated(
            valid,
            tests_passed=None,
            tests_total=None,
            verdict_source=None,
            source=None,
            base_reconstruction=None,
            diff_coverage=None,
            baseline=None,
            attestation=None,
        ),
        "valid_dict_subclasses": _updated(
            valid,
            diff_coverage=CoverageDict({"measured": True}),
            baseline=BaselineDict(),
            assurance=AssuranceDict(),
            attestation=AttestationDict(),
        ),
    }
    for field in _STRING_FIELDS:
        result[f"{field}_not_string"] = _updated(valid, **{field: []})
    for field in _BOOLEAN_FIELDS:
        result[f"{field}_not_boolean"] = _updated(valid, **{field: 1})
    result.update(
        {
            "exit_code_boolean": _updated(valid, exit_code=True),
            "exit_code_float": _updated(valid, exit_code=0.0),
            "risk_score_boolean": _updated(valid, risk_score=False),
            "risk_score_string": _updated(valid, risk_score="0.5"),
            "risk_score_nan": _updated(valid, risk_score=float("nan")),
            "risk_score_positive_infinity": _updated(valid, risk_score=float("inf")),
            "risk_score_negative_infinity": _updated(valid, risk_score=float("-inf")),
            "tests_passed_boolean": _updated(valid, tests_passed=True),
            "tests_total_float": _updated(valid, tests_total=3.0),
            "files_changed_tuple": _updated(valid, files_changed=("src/app.py",)),
            "files_changed_mixed": _updated(valid, files_changed=["src/app.py", 7]),
            "protected_violations_object": _updated(valid, protected_violations={}),
            "verdict_source_object": _updated(valid, verdict_source={}),
            "source_integer": _updated(valid, source=1),
            "base_reconstruction_boolean": _updated(valid, base_reconstruction=False),
            "diff_coverage_array": _updated(valid, diff_coverage=[]),
            "baseline_mapping_not_dict": _updated(
                valid, baseline=UserDict({"scope": "repo_suite_only"})
            ),
            "assurance_null": _updated(valid, assurance=None),
            "assurance_array": _updated(valid, assurance=[]),
            "attestation_array": _updated(valid, attestation=[]),
            "ordered_multiple_faults": {
                "schema_version": [],
                "diagnostics": 7,
                "passed": 1,
                "test_command_ran": "true",
                "exit_code": True,
                "risk_score": float("inf"),
                "tests_passed": False,
                "tests_total": 1.0,
                "files_changed": ("src/app.py",),
                "protected_violations": ["ok", 7],
                "verdict_source": {},
                "source": 1,
                "base_reconstruction": False,
                "diff_coverage": [],
                "baseline": UserDict(),
                "assurance": None,
                "attestation": [],
            },
        }
    )
    return result


def capture(
    value: dict[str, Any],
    *,
    projector: Projector = record_verifier._top_level_type_errors,
) -> list[str]:
    return list(projector(value))


def capture_all(
    *, projector: Projector = record_verifier._top_level_type_errors
) -> dict[str, list[str]]:
    return {name: capture(value, projector=projector) for name, value in cases().items()}


def _public_base(*, schema_version: str) -> dict[str, Any]:
    payload = json.loads(GOLDEN_RECORD.read_text(encoding="utf-8"))
    record = copy.deepcopy(cast(dict[str, Any], payload["records"]["valid_composite"]))
    if schema_version == "1.12":
        record["schema_version"] = "1.12"
        attestation = cast(dict[str, Any], record["attestation"])
        policy = cast(dict[str, Any], attestation["effective_policy"])
        policy["operating_profile"] = "local"
        attestation["policy_sha256"] = record_verifier._policy_sha256(policy)
    return record


def public_cases() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for schema_version in ("1.11", "1.12"):
        result[f"schema_{schema_version}_risk_boolean"] = _updated(
            _public_base(schema_version=schema_version), risk_score=True
        )
        result[f"schema_{schema_version}_ordered_faults"] = _updated(
            _public_base(schema_version=schema_version),
            schema_version=[],
            diagnostics=7,
            passed=1,
            exit_code=True,
            risk_score=float("inf"),
            files_changed=("src/app.py",),
            assurance=None,
            attestation=[],
        )
    return result


def capture_public_all() -> dict[str, dict[str, Any]]:
    reports: dict[str, dict[str, Any]] = {}
    for name, record in public_cases().items():
        before = copy.deepcopy(record)
        reports[name] = record_verifier.verify_record(record)
        assert record == before
    return reports


class TrackingRecord(dict[str, Any]):
    """Record exact membership and item-read behavior of the dict contract."""

    def __init__(self, value: dict[str, Any]) -> None:
        super().__init__(value)
        self.events: list[str] = []

    def __contains__(self, key: object) -> bool:
        self.events.append(f"contains:{key}")
        return super().__contains__(key)

    def __getitem__(self, key: str) -> Any:
        self.events.append(f"getitem:{key}")
        return super().__getitem__(key)


def access_traces(*, projector: Projector = record_verifier._top_level_type_errors) -> dict[str, list[str]]:
    selected = {
        "valid_all": valid_envelope(),
        "valid_empty": {},
        "nullable_objects": _updated(
            valid_envelope(), diff_coverage=None, baseline=None, attestation=None
        ),
        "invalid_objects": _updated(
            valid_envelope(), diff_coverage=[], baseline=[], assurance=[], attestation=[]
        ),
    }
    result: dict[str, list[str]] = {}
    for name, value in selected.items():
        tracked = TrackingRecord(value)
        projector(tracked)
        result[name] = tracked.events
    return result


def raising_baseline_trace(
    *, projector: Projector = record_verifier._top_level_type_errors
) -> list[str]:
    sentinel = RuntimeError("second baseline lookup failed")

    class RaisingRecord(TrackingRecord):
        def __init__(self, value: dict[str, Any]) -> None:
            super().__init__(value)
            self.baseline_reads = 0

        def __getitem__(self, key: str) -> Any:
            value = super().__getitem__(key)
            if key == "baseline":
                self.baseline_reads += 1
                if self.baseline_reads == 2:
                    raise sentinel
            return value

    record = RaisingRecord(_updated(valid_envelope(), baseline={}))
    try:
        projector(record)
    except RuntimeError as exc:
        assert exc is sentinel
    else:
        raise AssertionError("the second baseline lookup did not propagate")
    return record.events


def _generated_record(randomizer: random.Random) -> dict[str, Any]:
    fields = (
        *_STRING_FIELDS,
        *_BOOLEAN_FIELDS,
        "exit_code",
        "risk_score",
        *_NULLABLE_INTEGER_FIELDS,
        *_STRING_LIST_FIELDS,
        *_NULLABLE_STRING_FIELDS,
        *_NULLABLE_OBJECT_FIELDS,
        "assurance",
        "attestation",
    )
    values: tuple[Any, ...] = (
        None,
        False,
        True,
        -1,
        0,
        1,
        0.0,
        0.5,
        float("nan"),
        float("inf"),
        "",
        "value",
        [],
        ["a.py"],
        ["a.py", 7],
        (),
        {},
        {"key": "value"},
    )
    record = valid_envelope() if randomizer.randrange(2) else {}
    for _ in range(1 + randomizer.randrange(8)):
        field = randomizer.choice(fields)
        if randomizer.randrange(5) == 0:
            record.pop(field, None)
        else:
            record[field] = copy.deepcopy(randomizer.choice(values))
    return record


def generated_differential_digest(
    *,
    count: int = 20_000,
    candidate: Projector = record_verifier._top_level_type_errors,
) -> str:
    """Compare frozen legacy and candidate results across a deterministic corpus."""

    randomizer = random.Random(0xE70E10E)
    digest = hashlib.sha256()
    for _ in range(count):
        record = _generated_record(randomizer)
        expected = legacy_top_level_type_errors(copy.deepcopy(record))
        observed = list(candidate(copy.deepcopy(record)))
        if observed != expected:
            raise AssertionError((record, expected, observed))
        digest.update(
            json.dumps(observed, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
        )
        digest.update(b"\n")
    return digest.hexdigest()
