"""Frozen wire and ownership equivalence seam for attestation extraction."""

from __future__ import annotations

import difflib
import json
from pathlib import Path
from typing import Any, cast

import pytest
from attestation_builder_characterization_harness import (
    ATTESTATION_KEY_COUNT,
    ATTESTATION_KEY_ORDER,
    CASE_NAMES,
    NORMALIZED_FIELDS,
    SCHEMA_VERSION,
    canonical_json,
    capture_case,
)

VECTOR = Path(__file__).parent / "fixtures" / "refactor-safety" / "attestation-builder-v1.json"


def _frozen() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(VECTOR.read_text(encoding="utf-8")))


def test_attestation_characterization_metadata_and_57_key_contract_are_exact() -> None:
    frozen = _frozen()
    assert ATTESTATION_KEY_COUNT == 57
    assert len(ATTESTATION_KEY_ORDER) == ATTESTATION_KEY_COUNT
    assert len(set(ATTESTATION_KEY_ORDER)) == ATTESTATION_KEY_COUNT
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert frozen["normalization"] == list(NORMALIZED_FIELDS)
    assert frozen["contract"] == {
        "clock_calls_per_build": 1,
        "key_count": 57,
        "key_order": list(ATTESTATION_KEY_ORDER),
    }
    assert tuple(frozen["cases"]) == CASE_NAMES


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_attestation_payload_key_order_and_ownership(case_name: str) -> None:
    expected = _frozen()["cases"][case_name]
    actual = capture_case(case_name)
    assert actual["observed_key_count"] == 57
    assert tuple(actual["observed_key_order"]) == ATTESTATION_KEY_ORDER
    assert actual["ownership"]["clock_calls"] == 1
    if actual != expected:
        diff = "".join(
            difflib.unified_diff(
                canonical_json(expected).splitlines(keepends=True),
                canonical_json(actual).splitlines(keepends=True),
                fromfile=f"frozen/{case_name}",
                tofile=f"current/{case_name}",
            )
        )
        pytest.fail("Guard attestation payload or ownership drifted:\n" + diff)


def test_full_case_copy_and_reference_semantics_are_explicit() -> None:
    ownership = capture_case("full_repo")["ownership"]
    assert ownership == {
        "clock_calls": 1,
        "deleted_paths_is_source": False,
        "deleted_paths_source_mutation_observed": False,
        "effective_policy_is_source": True,
        "effective_policy_source_mutation_observed": True,
        "isolation_evidence_is_source": True,
        "isolation_evidence_source_mutation_observed": True,
        "test_command_is_source": False,
        "test_command_source_mutation_observed": False,
        "verifier_pack_manifest_is_source": True,
        "verifier_pack_manifest_source_mutation_observed": True,
    }


def test_falsey_case_keeps_default_command_and_omits_pack_digest_format() -> None:
    attestation = capture_case("falsey")["attestation"]
    assert attestation["test_command"] == "default:python -m pytest"
    assert attestation["verifier_pack_sha256"] == ""
    assert attestation["verifier_pack_digest_format"] is None
    assert attestation["repo_suite_returncode"] == 0
    assert attestation["repo_suite_passed"] is False
