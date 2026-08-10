# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Deterministic pre-extraction characterization for baseline validation."""

from __future__ import annotations

import copy
import hashlib
import json
import random
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

from evoom_guard import record_verifier

ROOT = Path(__file__).resolve().parents[1]
GOLDEN_RECORD = ROOT / "tests/fixtures/contracts/schema-1.11-golden.json"


def valid_fail() -> dict[str, Any]:
    return {
        "verdict": "FAIL",
        "tests_passed": 2,
        "tests_total": 3,
        "repair_effect": "demonstrated",
        "scope": "repo_suite_only",
        "note": "the pristine base failed under the same repository judge",
    }


def valid_pass() -> dict[str, Any]:
    value = valid_fail()
    value.update(
        {
            "verdict": "PASS",
            "tests_passed": 3,
            "repair_effect": "not_demonstrated",
        }
    )
    return value


def valid_no_clean() -> dict[str, Any]:
    value = valid_fail()
    value.update(
        {
            "verdict": "NO_CLEAN_VERDICT",
            "tests_passed": None,
            "tests_total": None,
            "repair_effect": "unmeasured",
        }
    )
    return value


def valid_unsupported() -> dict[str, Any]:
    value = valid_no_clean()
    value.update({"verdict": None, "scope": "unsupported_mode"})
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
        for update_field, item in updates.items():
            value[cast(str, update_field)] = copy.deepcopy(item)
    return value


def cases() -> dict[str, dict[str, Any]]:
    failed = valid_fail()
    passed = valid_pass()
    no_clean = valid_no_clean()
    unsupported = valid_unsupported()
    changed = _updated(
        no_clean,
        updates={
            "setup_fidelity": "changed_judged_tree",
            "setup_fidelity_changes": ["pkg/a.py", "pkg/z.py"],
        },
    )
    return {
        "valid_fail": failed,
        "valid_pass": passed,
        "valid_exit_only_fail": _updated(
            failed,
            updates={"tests_passed": 0, "tests_total": 0},
        ),
        "valid_no_clean": no_clean,
        "valid_changed_tree": changed,
        "valid_unsupported": unsupported,
        "non_string_key": _updated(failed, updates={7: "value"}),
        "missing_and_unknown_keys": _updated(
            failed,
            removed=("note",),
            updates={"extra": True},
        ),
        "empty_note": _updated(failed, updates={"note": ""}),
        "unsupported_with_setup": _updated(
            unsupported,
            updates={"setup_fidelity": "unverified"},
        ),
        "unsupported_non_null_evidence": _updated(
            unsupported,
            updates={
                "verdict": "FAIL",
                "tests_passed": 0,
                "tests_total": 1,
            },
        ),
        "invalid_scope": _updated(passed, updates={"scope": "blackbox"}),
        "invalid_verdict": _updated(failed, updates={"verdict": "UNKNOWN"}),
        "boolean_counts": _updated(
            passed,
            updates={"tests_passed": True, "tests_total": True},
        ),
        "null_clean_counts": _updated(
            passed,
            updates={"tests_passed": None, "tests_total": None},
        ),
        "negative_pass_counts": _updated(
            passed,
            updates={"tests_passed": -1, "tests_total": 3},
        ),
        "out_of_order_pass_counts": _updated(
            passed,
            updates={"tests_passed": 4, "tests_total": 3},
        ),
        "partial_pass_counts": _updated(
            passed,
            updates={"tests_passed": 2, "tests_total": 3},
        ),
        "all_passing_fail_counts": _updated(
            failed,
            updates={"tests_passed": 3, "tests_total": 3},
        ),
        "no_clean_measured_effect": _updated(
            no_clean,
            updates={"repair_effect": "demonstrated"},
        ),
        "clean_unmeasured_effect": _updated(
            failed,
            updates={"repair_effect": "unmeasured"},
        ),
        "invalid_setup_fidelity": _updated(
            no_clean,
            updates={"setup_fidelity": "unknown"},
        ),
        "setup_failure_with_clean_verdict": _updated(
            passed,
            updates={"setup_fidelity": "setup_failed"},
        ),
        "changed_tree_empty_paths": _updated(
            changed,
            updates={"setup_fidelity_changes": []},
        ),
        "changed_tree_unsorted_duplicate_paths": _updated(
            changed,
            updates={"setup_fidelity_changes": ["z.py", "a.py", "a.py"]},
        ),
        "changed_tree_non_string_paths": _updated(
            changed,
            updates={"setup_fidelity_changes": ["a.py", 7]},
        ),
        "changes_without_changed_tree": _updated(
            no_clean,
            updates={
                "setup_fidelity": "unverified",
                "setup_fidelity_changes": ["a.py"],
            },
        ),
        "changes_without_setup_field": _updated(
            no_clean,
            updates={"setup_fidelity_changes": ["a.py"]},
        ),
        "ordered_multiple_faults": _updated(
            failed,
            removed=("note",),
            updates={
                "extra": True,
                "scope": "invalid",
                "verdict": "PASS",
                "tests_passed": True,
                "tests_total": -1,
                "repair_effect": "unmeasured",
                "setup_fidelity": "changed_judged_tree",
                "setup_fidelity_changes": ["z.py", "a.py", "a.py"],
            },
        ),
    }


def capture(value: dict[str, Any]) -> list[str]:
    before = copy.deepcopy(value)
    result = record_verifier._baseline_type_errors(value)
    assert value == before
    return result


def capture_all() -> dict[str, list[str]]:
    return {name: capture(value) for name, value in cases().items()}


def _public_base() -> dict[str, Any]:
    payload = json.loads(GOLDEN_RECORD.read_text(encoding="utf-8"))
    record = copy.deepcopy(cast(dict[str, Any], payload["records"]["valid_composite"]))
    attestation = cast(dict[str, Any], record["attestation"])
    policy = cast(dict[str, Any], attestation["effective_policy"])
    policy["baseline_evidence"] = True
    attestation["policy_sha256"] = record_verifier._policy_sha256(policy)
    return record


def public_cases() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for name in (
        "valid_fail",
        "partial_pass_counts",
        "valid_changed_tree",
        "unsupported_with_setup",
    ):
        record = _public_base()
        record["baseline"] = copy.deepcopy(cases()[name])
        result[name] = record
    return result


def capture_public_all() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for name, record in public_cases().items():
        before = copy.deepcopy(record)
        result[name] = record_verifier.verify_record(record)
        assert record == before
    return result


class TrackingBaseline(dict[str, Any]):
    """Record observable mapping operations without changing dict semantics."""

    def __init__(self, value: dict[str, Any]) -> None:
        super().__init__(value)
        self.events: list[str] = []

    def __iter__(self) -> Iterator[str]:
        self.events.append("iter")
        return super().__iter__()

    def get(self, key: str, default: object = None) -> object:
        self.events.append(f"get:{key}")
        return super().get(key, default)

    def __contains__(self, key: object) -> bool:
        self.events.append(f"contains:{key}")
        return super().__contains__(key)


def access_traces() -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for name, value in {
        "repo_suite": valid_fail(),
        "unsupported": valid_unsupported(),
    }.items():
        tracked = TrackingBaseline(value)
        record_verifier._baseline_type_errors(tracked)
        result[name] = tracked.events
    non_string = TrackingBaseline(valid_fail())
    non_string[7] = "value"  # type: ignore[index]
    record_verifier._baseline_type_errors(non_string)
    result["non_string_key"] = non_string.events
    return result


def generated_trace_digest(*, count: int = 20_000) -> str:
    randomizer = random.Random(0xE70BA5E)
    fields = (
        "verdict",
        "tests_passed",
        "tests_total",
        "repair_effect",
        "scope",
        "note",
        "setup_fidelity",
        "setup_fidelity_changes",
    )
    values: tuple[Any, ...] = (
        None,
        False,
        True,
        -1,
        0,
        1,
        3,
        "",
        "PASS",
        "FAIL",
        "NO_CLEAN_VERDICT",
        "demonstrated",
        "not_demonstrated",
        "unmeasured",
        "repo_suite_only",
        "unsupported_mode",
        "changed_judged_tree",
        [],
        ["a.py"],
        ["z.py", "a.py"],
        {},
    )
    factories = (valid_fail, valid_pass, valid_no_clean, valid_unsupported)
    digest = hashlib.sha256()
    for _ in range(count):
        base = randomizer.choice(factories)()
        for _ in range(1 + randomizer.randrange(4)):
            field = randomizer.choice(fields)
            if randomizer.randrange(5) == 0:
                base.pop(field, None)
            else:
                base[field] = copy.deepcopy(randomizer.choice(values))
        if randomizer.randrange(37) == 0:
            base[7] = "value"  # type: ignore[index]
        trace = capture(base)
        digest.update(
            json.dumps(trace, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
        digest.update(b"\n")
    return digest.hexdigest()
