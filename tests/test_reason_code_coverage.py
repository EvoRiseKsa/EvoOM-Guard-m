# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Automated reason-code conformance coverage for the 1.11 contract.

Every reason code the frozen contract names must be backed by a golden record
in ``tests/fixtures/contracts/reason-corpus.jsonl`` that the producer actually
emitted and the independent verifier accepts.  The corpus is a hand-reviewed
frozen artifact regenerated with ``ops/generate_reason_corpus.py``: each row
records real ``guard()``/``guard_from_diff()`` output; the three rows whose
runtime the host cannot provide (black-box launcher facts) stub
``run_blackbox`` the same way this repository's own tests do and say so in
their ``provenance``.

The point is drift prevention in both directions: a reason code added to the
contract without a producing scenario fails here, and a corpus row whose
reason code the contract no longer names fails here too.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

import evoom_guard.guard as guard_module
import evoom_guard.record_verifier as record_verifier
import evoom_guard.verdict_contract_v1_11 as contract

ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "tests" / "fixtures" / "contracts" / "reason-corpus.jsonl"
SCHEMA_PATH = ROOT / "evoom_guard" / "schemas" / "verdict-record-1.11.schema.json"

# The only accepted generation paths. "producer" rows ran the real judge end to
# end; "producer-stubbed-blackbox" rows ran the real guard() composition over a
# stubbed run_blackbox result (launcher facts the host cannot produce natively).
KNOWN_PROVENANCE = frozenset({"producer", "producer-stubbed-blackbox"})


def _corpus_rows() -> list[dict[str, Any]]:
    rows = [
        json.loads(line)
        for line in CORPUS_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert rows, "reason corpus fixture is empty"
    return rows


def _validator() -> Draft202012Validator:
    return Draft202012Validator(
        json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    )


def test_every_contract_reason_code_has_exactly_one_golden_record() -> None:
    covered = [row["reason_code"] for row in _corpus_rows()]
    assert sorted(covered) == sorted(contract.REASON_CODES), (
        "the reason corpus and the frozen contract vocabulary have drifted; "
        "regenerate tests/fixtures/contracts/reason-corpus.jsonl with "
        "ops/generate_reason_corpus.py and hand-review the diff"
    )


def test_corpus_rows_declare_a_known_provenance() -> None:
    for row in _corpus_rows():
        assert row["provenance"] in KNOWN_PROVENANCE, row["reason_code"]


@pytest.mark.parametrize(
    "row", _corpus_rows(), ids=lambda row: row["reason_code"]
)
def test_golden_record_is_schema_valid_and_verifier_accepted(
    row: dict[str, Any],
) -> None:
    record = row["record"]
    assert record["reason_code"] == row["reason_code"]
    _validator().validate(record)
    report = record_verifier.verify_record(record)
    assert report["ok"] is True, [
        check["id"] for check in report["checks"] if check["status"] == "fail"
    ]


@pytest.mark.parametrize(
    "row", _corpus_rows(), ids=lambda row: row["reason_code"]
)
def test_golden_record_obeys_the_frozen_reason_contract(
    row: dict[str, Any],
) -> None:
    verdicts, execution_states = contract.REASON_CONTRACT[row["reason_code"]]
    assert row["record"]["verdict"] in verdicts
    assert row["record"]["execution_state"] in execution_states


def test_known_gap_contradictory_policy_records_fail_verification(
    tmp_path: Path,
) -> None:
    """KNOWN GAP: two producer inputs yield records verify_record rejects.

    ``guard()`` answers a self-contradictory policy request (``blackbox_only``
    without ``blackbox``; an expected pack digest without a pack) with an
    ``ERROR``/``policy_requirement_unsupported`` record whose attestation
    faithfully echoes the contradictory request — and ``verify_record``
    rejects exactly that echo (``policy.contract``).  Producer records are
    therefore not universally verifiable today.  In the adversarial-corpus
    convention, this test must stay green only while the limitation
    reproduces: whichever side is fixed (the producer refusing to attest a
    contradictory policy, or the verifier accepting it under this reason
    code) must invert these assertions instead of deleting them.
    """
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    candidate = "<<<FILE: app.py>>>\nvalue = 2\n<<<END FILE>>>"
    for kwargs in (
        {"blackbox_only": True},
        {"expect_verifier_pack_sha256": "0" * 64},
    ):
        record = guard_module.guard(
            str(tmp_path),
            candidate,
            test_command=[sys.executable, "-c", "raise SystemExit(0)"],
            mem_limit_mb=0,
            **kwargs,
        ).to_dict()
        assert record["reason_code"] == "policy_requirement_unsupported"
        report = record_verifier.verify_record(record)
        assert report["ok"] is False, kwargs
        failed = {
            check["id"] for check in report["checks"] if check["status"] == "fail"
        }
        assert failed == {"policy.contract"}, failed
