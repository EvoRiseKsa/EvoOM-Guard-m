# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Frozen compatibility checks for the public verdict-record 1.11 contract.

The expected values live in a hand-reviewed JSON fixture.  In particular, the
fixture is not generated from the central contract module: producer, verifier,
schema, and legacy imports are all compared with the same independent oracle.
"""

from __future__ import annotations

import copy
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

import evoom_guard.guard as guard_module
import evoom_guard.record_verifier as record_verifier
import evoom_guard.verdict_contract_v1_11 as contract

ROOT = Path(__file__).resolve().parents[1]
GOLDEN_PATH = ROOT / "tests" / "fixtures" / "contracts" / "schema-1.11-golden.json"
SCHEMA_PATH = ROOT / "evoom_guard" / "schemas" / "verdict-record-1.11.schema.json"


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _normalise_reason_contract(
    value: Mapping[str, tuple[frozenset[str], frozenset[str]]],
) -> dict[str, dict[str, list[str]]]:
    return {
        reason: {
            "verdicts": sorted(verdicts),
            "execution_states": sorted(execution_states),
        }
        for reason, (verdicts, execution_states) in value.items()
    }


def _report_snapshot(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": report["ok"],
        "summary": report["summary"],
        "checks": [[check["id"], check["status"]] for check in report["checks"]],
    }


def test_schema_1_11_surfaces_match_frozen_contract() -> None:
    golden = _load_json(GOLDEN_PATH)
    schema = _load_json(SCHEMA_PATH)
    required = golden["required_keys"]

    assert contract.SCHEMA_VERSION == golden["schema_version"]
    assert record_verifier.SUPPORTED_SCHEMA_VERSIONS == frozenset(
        {golden["schema_version"]}
    )

    assert sorted(contract.VERDICTS) == golden["verdicts"]
    assert sorted(contract.EXECUTION_STATES) == golden["execution_states"]
    assert sorted(contract.REASON_CODES) == sorted(golden["reason_contract"])
    assert sorted(contract.POLICY_KEYS) == golden["policy_keys"]
    assert sorted(contract.REQUIRED_TOP_LEVEL) == required["top_level"]
    assert sorted(contract.REQUIRED_ASSURANCE) == required["assurance"]
    assert sorted(contract.REQUIRED_ATTESTATION) == required["attestation"]

    # The independent verifier must continue to enforce the same vocabulary,
    # even if its implementation remains deliberately separate from producer logic.
    assert sorted(record_verifier._VERDICTS) == golden["verdicts"]
    assert sorted(record_verifier._EXECUTION_STATES) == golden["execution_states"]
    assert sorted(record_verifier._REASON_CODES) == sorted(golden["reason_contract"])
    assert sorted(record_verifier._POLICY_KEYS) == golden["policy_keys"]
    assert sorted(record_verifier._REQUIRED_TOP_LEVEL) == required["top_level"]
    assert sorted(record_verifier._REQUIRED_ASSURANCE) == required["assurance"]
    assert sorted(record_verifier._REQUIRED_ATTESTATION) == required["attestation"]

    assert schema["properties"]["schema_version"]["const"] == golden["schema_version"]
    assert sorted(schema["properties"]["verdict"]["enum"]) == golden["verdicts"]
    assert sorted(schema["$defs"]["executionState"]["enum"]) == golden[
        "execution_states"
    ]
    assert sorted(schema["properties"]["reason_code"]["enum"]) == sorted(
        golden["reason_contract"]
    )
    assert sorted(schema["required"]) == required["top_level"]
    assert sorted(schema["$defs"]["effectivePolicy"]["required"]) == golden[
        "policy_keys"
    ]
    assert sorted(schema["$defs"]["assurance"]["required"]) == required["assurance"]
    assert sorted(schema["$defs"]["attestation"]["required"]) == required[
        "attestation"
    ]


def test_reason_verdict_lifecycle_truth_table_is_frozen() -> None:
    golden = _load_json(GOLDEN_PATH)
    expected = golden["reason_contract"]

    assert _normalise_reason_contract(contract.REASON_CONTRACT) == expected
    assert _normalise_reason_contract(record_verifier._REASON_CONTRACT) == expected


def test_reason_contract_is_not_runtime_mutable() -> None:
    with pytest.raises(TypeError):
        contract.REASON_CONTRACT["invented_reason"] = (  # type: ignore[index]
            frozenset({"PASS"}),
            frozenset({"completed"}),
        )


def test_guard_legacy_contract_symbols_remain_import_compatible() -> None:
    golden = _load_json(GOLDEN_PATH)

    for name, expected in golden["legacy_symbols"].items():
        assert getattr(contract, name) == expected, name
        assert getattr(guard_module, name) == expected, name


def test_frozen_schema_1_11_record_remains_valid() -> None:
    golden = _load_json(GOLDEN_PATH)
    schema = _load_json(SCHEMA_PATH)
    record = golden["records"]["valid_composite"]

    Draft202012Validator(schema).validate(record)
    assert record_verifier.verify_record(record)["ok"] is True


def test_real_producer_records_validate_across_all_lifecycles(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_app.py").write_text(
        "def test_ok():\n    assert True\n", encoding="utf-8"
    )
    source_candidate = "<<<FILE: app.py>>>\nvalue = 2\n<<<END FILE>>>"
    cases = (
        (
            "static_gate",
            "<<<FILE: tests/test_app.py>>>\ndef test_ok():\n    assert False\n"
            "<<<END FILE>>>",
            [sys.executable, "-c", "raise SystemExit(0)"],
            120,
        ),
        (
            "not_started",
            source_candidate,
            ["definitely-missing-evoguard-command"],
            120,
        ),
        (
            "completed",
            source_candidate,
            [sys.executable, "-c", "raise SystemExit(0)"],
            120,
        ),
        (
            "started_incomplete",
            source_candidate,
            [sys.executable, "-c", "import time; time.sleep(5)"],
            1,
        ),
    )
    validator = Draft202012Validator(_load_json(SCHEMA_PATH))

    observed: set[str] = set()
    for expected_state, candidate, command, timeout in cases:
        record = guard_module.guard(
            str(tmp_path),
            candidate,
            test_command=command,
            timeout=timeout,
            mem_limit_mb=0,
        ).to_dict()
        assert record["execution_state"] == expected_state
        validator.validate(record)
        assert record_verifier.verify_record(record)["ok"] is True
        observed.add(expected_state)

    assert observed == set(_load_json(GOLDEN_PATH)["execution_states"])


def test_verify_record_reports_match_frozen_id_status_goldens() -> None:
    golden = _load_json(GOLDEN_PATH)
    valid_record = golden["records"]["valid_composite"]
    tampered_record = copy.deepcopy(valid_record)
    tampered_record["exit_code"] = 1

    assert _report_snapshot(record_verifier.verify_record(valid_record)) == golden[
        "reports"
    ]["valid"]
    assert _report_snapshot(record_verifier.verify_record(tampered_record)) == golden[
        "reports"
    ]["tampered"]
