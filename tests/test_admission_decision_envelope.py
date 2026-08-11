# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from test_agent_change_admission import _fixture, _seal

from evoom_guard import finalizer_derivation
from evoom_guard.admission import agent_change, decision_envelope, decision_sources
from evoom_guard.evidence_bundle import canonical_json_bytes


@pytest.fixture(autouse=True)
def _windows_git_pin_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the existing Windows unit-test transport used by Agent Change tests."""

    if os.name != "nt":
        return
    real_derive = finalizer_derivation.derive_agent_change_bindings

    def derive_without_windows_snapshot(**kwargs: object):
        kwargs["git_executable"] = None
        return real_derive(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        agent_change, "derive_agent_change_bindings", derive_without_windows_snapshot
    )


def _payload() -> dict[str, object]:
    return decision_envelope.build_agent_change_admission_decision_envelope(
        subject={
            "kind": "git-change",
            "repository": "owner/project",
            "repository_id": "123",
            "pull_request_number": 17,
            "base_sha": "a" * 40,
            "base_tree_sha": "b" * 40,
            "head_sha": "c" * 40,
            "head_tree_sha": "d" * 40,
            "candidate_sha256": "e" * 64,
            "candidate_size": 4096,
        },
        controls={
            "policy_sha256": "f" * 64,
            "verifier_pack_sha256": None,
        },
        proof={
            "format": decision_envelope.ADMISSION_DECISION_PROOF_FORMAT,
            "sha256": "1" * 64,
            "size": 8192,
            "authentication": {
                "finalizer": {
                    "algorithm": "Ed25519",
                    "key_id": "sha256:" + "2" * 64,
                    "purpose": "evoguard-evidence-envelope",
                },
                "change_authorization": {
                    "algorithm": "Ed25519",
                    "key_id": "sha256:" + "3" * 64,
                    "purpose": "evoguard-agent-change-authorization-v1",
                },
            },
        },
    )


def _canonical() -> bytes:
    return decision_envelope.canonical_admission_decision_envelope_bytes(_payload())


def test_envelope_is_deterministic_canonical_in_toto_statement() -> None:
    first = _canonical()
    second = _canonical()
    inspected = decision_envelope.inspect_admission_decision_envelope_bytes(first)

    assert first == second
    assert first.endswith(b"\n")
    assert inspected.envelope_bytes == first
    assert inspected.payload["_type"] == "https://in-toto.io/Statement/v1"
    assert inspected.payload["subject"][0]["digest"] == {"gitCommit": "c" * 40}
    assert inspected.payload["predicate"]["authority"] == {
        "mode": "PROOF_BOUND_PROJECTION",
        "admission_scope": "repository-change",
        "merge": False,
        "publication": False,
        "deployment": False,
        "external_action": False,
    }

    caller_view = inspected.payload
    caller_view["predicate"]["authority"]["merge"] = True
    assert inspected.payload["predicate"]["authority"]["merge"] is False


def test_schema_and_runtime_accept_the_same_representative_envelope() -> None:
    root = Path(__file__).parents[1]
    schema = json.loads(
        (root / "evoom_guard/schemas/admission-decision-envelope-1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(_payload())
    assert schema["$id"].endswith("/admission-decision-envelope-1.schema.json")


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("_type",), "https://in-toto.io/Statement/v0.1"),
        (("predicateType",), "https://example.invalid/predicate"),
        (("predicate", "format"), "EVOGUARD_ADMISSION_DECISION_ENVELOPE_V2"),
        (("predicate", "profile"), "generic"),
        (("predicate", "decision"), "DENY"),
        (("predicate", "subject", "repository_id"), "0"),
        (("predicate", "subject", "base_sha"), "c" * 40),
        (
            ("predicate", "proof", "authentication", "finalizer", "purpose"),
            "evoguard-agent-change-authorization-v1",
        ),
        (("predicate", "authority", "merge"), True),
        (("predicate", "authority", "publication"), True),
        (("predicate", "authority", "deployment"), True),
        (("predicate", "authority", "external_action"), True),
    ],
)
def test_mutated_contract_fields_fail_closed(
    path: tuple[str | int, ...], replacement: object
) -> None:
    payload = copy.deepcopy(_payload())
    cursor = payload
    for component in path[:-1]:
        cursor = cursor[component]  # type: ignore[index]
    cursor[path[-1]] = replacement  # type: ignore[index]

    with pytest.raises(decision_envelope.AdmissionDecisionEnvelopeError):
        decision_envelope.validate_admission_decision_envelope(payload)


def test_statement_subject_cannot_diverge_from_predicate_subject() -> None:
    payload = _payload()
    payload["subject"][0]["digest"]["gitCommit"] = "0" * 40  # type: ignore[index]
    with pytest.raises(
        decision_envelope.AdmissionDecisionEnvelopeError,
        match="does not match the admitted Git commit",
    ):
        decision_envelope.validate_admission_decision_envelope(payload)


def test_unknown_keys_and_bool_as_integer_fail_closed() -> None:
    extra = _payload()
    extra["predicate"]["authority"]["risk_score"] = 0  # type: ignore[index]
    with pytest.raises(
        decision_envelope.AdmissionDecisionEnvelopeError, match="keys are not exact"
    ):
        decision_envelope.validate_admission_decision_envelope(extra)

    for field in ("pull_request_number", "candidate_size"):
        value = _payload()
        value["predicate"]["subject"][field] = True  # type: ignore[index]
        with pytest.raises(decision_envelope.AdmissionDecisionEnvelopeError):
            decision_envelope.validate_admission_decision_envelope(value)

    value = _payload()
    value["predicate"]["proof"]["size"] = True  # type: ignore[index]
    with pytest.raises(decision_envelope.AdmissionDecisionEnvelopeError):
        decision_envelope.validate_admission_decision_envelope(value)

    overlapping_keys = _payload()
    overlapping_keys["predicate"]["proof"]["authentication"]["change_authorization"]["key_id"] = (
        overlapping_keys["predicate"]["proof"]["authentication"]["finalizer"]["key_id"]
    )  # type: ignore[index]
    with pytest.raises(
        decision_envelope.AdmissionDecisionEnvelopeError,
        match="key roles must be separate",
    ):
        decision_envelope.validate_admission_decision_envelope(overlapping_keys)


def test_noncanonical_and_duplicate_json_are_rejected() -> None:
    pretty = json.dumps(_payload(), indent=2).encode("utf-8")
    with pytest.raises(decision_envelope.AdmissionDecisionEnvelopeError, match="not canonical"):
        decision_envelope.inspect_admission_decision_envelope_bytes(pretty)

    duplicate = _canonical().replace(
        b'"decision":"ALLOW"',
        b'"decision":"ALLOW","decision":"ALLOW"',
        1,
    )
    with pytest.raises(decision_envelope.AdmissionDecisionEnvelopeError):
        decision_envelope.inspect_admission_decision_envelope_bytes(duplicate)

    with pytest.raises(decision_envelope.AdmissionDecisionEnvelopeError, match="not canonical"):
        decision_envelope.InspectedAdmissionDecisionEnvelope(pretty)


def _adapter_arguments(case: dict[str, object]) -> dict[str, object]:
    return {
        "trusted_finalizer_public_key_path": str(case["finalizer_public"]),
        "authorization_public_key_path": str(case["authorization_public"]),
        "expected_authorization_source": case["authorization_source"],
        "expected_finalizer_source": case["source"],
        "expected_context": case["context"],
        "expected_bindings": case["bindings"],
    }


def test_agent_change_adapter_reverifies_and_reprojects_exact_proof(tmp_path: Path) -> None:
    case = _fixture(tmp_path)
    proof = tmp_path / "agent-change.evb"
    _seal(case, proof)
    arguments = _adapter_arguments(case)

    first = decision_sources.derive_agent_change_admission_decision(
        str(proof),
        **arguments,  # type: ignore[arg-type]
    )
    second = decision_sources.derive_agent_change_admission_decision(
        str(proof),
        **arguments,  # type: ignore[arg-type]
    )
    verified = decision_sources.verify_agent_change_admission_decision(
        first.envelope_bytes,
        str(proof),
        **arguments,  # type: ignore[arg-type]
    )

    assert first.envelope_bytes == second.envelope_bytes == verified.envelope_bytes
    assert first.payload["predicate"]["subject"]["repository"] == "owner/project"
    assert (
        first.payload["predicate"]["proof"]["sha256"]
        == hashlib.sha256(proof.read_bytes()).hexdigest()
    )
    assert first.payload["predicate"]["authority"]["merge"] is False


def test_structurally_valid_projection_tamper_and_proof_tamper_fail(
    tmp_path: Path,
) -> None:
    case = _fixture(tmp_path)
    proof = tmp_path / "agent-change.evb"
    _seal(case, proof)
    arguments = _adapter_arguments(case)
    derived = decision_sources.derive_agent_change_admission_decision(
        str(proof),
        **arguments,  # type: ignore[arg-type]
    )

    for section, field in (
        ("proof", "sha256"),
        ("controls", "policy_sha256"),
        ("subject", "candidate_sha256"),
    ):
        payload = copy.deepcopy(derived.payload)
        payload["predicate"][section][field] = "0" * 64
        forged = canonical_json_bytes(payload)
        with pytest.raises(
            decision_envelope.AdmissionDecisionEnvelopeError,
            match="not the exact projection",
        ):
            decision_sources.verify_agent_change_admission_decision(
                forged,
                str(proof),
                **arguments,  # type: ignore[arg-type]
            )

    corrupted = bytearray(proof.read_bytes())
    corrupted[-1] ^= 1
    proof.write_bytes(corrupted)
    with pytest.raises(
        decision_envelope.AdmissionDecisionEnvelopeError,
        match="proof did not verify",
    ):
        decision_sources.derive_agent_change_admission_decision(
            str(proof),
            **arguments,  # type: ignore[arg-type]
        )
