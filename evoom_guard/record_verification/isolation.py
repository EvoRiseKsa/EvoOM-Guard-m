# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Isolation-parity checks for schema-1.11 verdict records."""

from __future__ import annotations

from typing import Any

from evoom_guard.record_verification.report import _Checks


def check_isolation(
    checks: _Checks,
    record: dict[str, Any],
    assurance: dict[str, Any] | None,
    attestation: dict[str, Any] | None,
) -> None:
    """Append isolation parity checks without changing their established order."""
    if assurance is None:
        checks.skip("isolation.assurance_parity", "assurance is unavailable")
    else:
        checks.expect(
            "isolation.assurance_parity",
            assurance.get("candidate_isolation") == record.get("isolation"),
            "top-level isolation matches assurance.candidate_isolation",
            "top-level isolation contradicts assurance.candidate_isolation",
        )
    if attestation is None:
        checks.skip("isolation.attestation_parity", "attestation is unavailable")
        return
    effective = attestation.get("effective_candidate_isolation")
    valid = effective == record.get("isolation")
    if (
        record.get("execution_state") == "not_started"
        and record.get("test_command_ran") is False
        and record.get("isolation") == "not_run"
        and effective is None
    ):
        # Schema 1.11 producer records from preflight refusals distinguish an
        # unavailable candidate boundary (null) from the public delivered view
        # (not_run). No execution claim is made by either representation.
        valid = True
    if assurance is not None:
        valid = valid and (
            attestation.get("delivered_isolation") == assurance.get("suite_isolation")
        )
    checks.expect(
        "isolation.attestation_parity",
        valid,
        "effective/suite isolation views agree across the record",
        "attestation isolation contradicts top-level or assurance isolation",
    )
