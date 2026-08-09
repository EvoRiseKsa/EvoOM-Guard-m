# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Adversarial contract tests for the bounded change-attempt observation.

The fixture records come from the existing hand-reviewed reason corpus.  Each
record is placed in a real signed Trusted Finalizer bundle before projection;
no test passes a parsed verdict to the producer as a trusted substitute.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from evoom_guard import change_attempt_observation as change_attempt
from evoom_guard import trusted_finalizer
from evoom_guard.evidence_bundle import canonical_json_bytes
from evoom_guard.signing import SigningUnavailableError, generate_keypair

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "change_attempt_observation"
REASON_CORPUS = ROOT / "tests" / "fixtures" / "contracts" / "reason-corpus.jsonl"
SCHEMA_PATH = ROOT / "evoom_guard" / "schemas" / "change-attempt-observation-1.schema.json"

MATRIX = json.loads((FIXTURE_ROOT / "verdict-matrix.json").read_text(encoding="utf-8"))
WIRE_SHAPE = json.loads((FIXTURE_ROOT / "wire-shape.json").read_text(encoding="utf-8"))
GOLDEN = json.loads((FIXTURE_ROOT / "golden-vectors.json").read_text(encoding="utf-8"))
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
CASES = tuple(MATRIX["cases"])


@dataclass(frozen=True)
class _AttemptFixture:
    bundle: Path
    record_path: Path
    public_key: Path
    source: dict[str, Any]
    context: dict[str, Any]
    record: dict[str, Any]


def _corpus_record(reason_code: str) -> dict[str, Any]:
    for line in REASON_CORPUS.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        row = json.loads(line)
        if row["reason_code"] == reason_code:
            record = copy.deepcopy(row["record"])
            assert isinstance(record.get("attestation"), dict)
            # These values are semantically irrelevant to the verdict but are
            # deliberately sensitive and must never escape the allowlisted
            # projection.
            record["reason"] = "PRIVACY_REASON_SENTINEL"
            record["diagnostics"] = "PRIVACY_DIAGNOSTICS_SENTINEL"
            record["future_private"] = "PRIVACY_EXTENSION_SENTINEL"
            return record
    raise AssertionError(f"reason corpus has no row for {reason_code}")


def _git_identity(label: str, field: str) -> str:
    return hashlib.sha256(f"{label}:{field}".encode()).hexdigest()[:40]


def _keys(
    directory: Path,
    prefix: str,
    *,
    public_fixture_label: str | None = None,
) -> tuple[Path, Path]:
    private_key = directory / f"{prefix}.private.pem"
    public_key = directory / f"{prefix}.public.pem"
    if public_fixture_label is None:
        generate_keypair(str(private_key), str(public_key))
        return private_key, public_key

    # This deterministic key is public test material, not a production secret.
    # It exists only to make the producer's exact canonical bytes reproducible.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = hashlib.sha256(f"evoom-change-attempt-golden:{public_fixture_label}".encode()).digest()
    key = Ed25519PrivateKey.from_private_bytes(seed)
    private_key.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_key.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    private_key.chmod(0o600)
    public_key.chmod(0o644)
    return private_key, public_key


def _signed_attempt_fixture(
    tmp_path: Path,
    matrix_case: dict[str, Any],
    *,
    prefix: str,
    public_fixture_key_label: str | None = None,
    record_schema_version: str | None = None,
) -> _AttemptFixture:
    directory = tmp_path / prefix
    directory.mkdir()
    record = _corpus_record(matrix_case["reason_code"])
    if record_schema_version is not None:
        record["schema_version"] = record_schema_version
    assert record["verdict"] == matrix_case["verdict"]
    assert record["passed"] is matrix_case["passed"]
    attestation = record["attestation"]

    base_sha = _git_identity(prefix, "base")
    head_sha = _git_identity(prefix, "head")
    context = {
        "repository": "owner/project",
        "repository_id": "12345",
        "run_id": f"{prefix}-context-run",
        "run_attempt": 7,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "base_tree_sha": _git_identity(prefix, "base-tree"),
        "head_tree_sha": _git_identity(prefix, "head-tree"),
        "candidate_sha256": attestation["candidate_sha256"],
        "policy_sha256": attestation["policy_sha256"],
        "verifier_pack_sha256": attestation["verifier_pack_sha256"],
        "guard_artifact_sha256": hashlib.sha256(f"{prefix}:guard-artifact".encode()).hexdigest(),
    }
    source = {
        "pull_request_number": 42,
        "workflow_run_id": f"{prefix}-handoff-run",
        "workflow_run_attempt": 3,
        "base_sha": base_sha,
        "head_sha": head_sha,
    }

    record_path = directory / "verdict.json"
    record_path.write_bytes(canonical_json_bytes(record))
    handoff_path = directory / "handoff.json"
    trusted_finalizer.create_finalizer_handoff(
        str(record_path),
        str(handoff_path),
        source=source,
        context=context,
    )
    private_key, public_key = _keys(
        directory,
        "finalizer",
        public_fixture_label=public_fixture_key_label,
    )
    bundle = directory / "attempt.evb"
    sealed = trusted_finalizer.seal_finalizer_bundle_without_derivation(
        str(handoff_path),
        str(record_path),
        str(bundle),
        expected_source=source,
        expected_context=context,
        private_key_path=str(private_key),
    )
    assert sealed.decision == matrix_case["decision"]
    return _AttemptFixture(
        bundle=bundle,
        record_path=record_path,
        public_key=public_key,
        source=source,
        context=context,
        record=record,
    )


def _produce(
    fixture: _AttemptFixture,
    output: Path,
    *,
    force: bool = False,
):
    return change_attempt.produce_change_attempt_observation(
        str(fixture.bundle),
        str(output),
        trusted_finalizer_public_key_path=str(fixture.public_key),
        expected_source=fixture.source,
        expected_context=fixture.context,
        force=force,
    )


def _canonical_mutation(
    payload: dict[str, Any],
    mutator,
) -> bytes:
    mutated = copy.deepcopy(payload)
    mutator(mutated)
    return canonical_json_bytes(mutated)


def _recursive_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for nested in value.values() for key in _recursive_keys(nested)}
    if isinstance(value, list):
        return {key for nested in value for key in _recursive_keys(nested)}
    return set()


def _set_json_pointer(payload: dict[str, Any], pointer: str, value: object) -> None:
    parts = pointer.removeprefix("/").split("/")
    current: Any = payload
    for part in parts[:-1]:
        current = current[part]
    current[parts[-1]] = value


@pytest.mark.parametrize("matrix_case", CASES, ids=lambda row: row["id"])
def test_all_five_verdicts_project_the_exact_finalizer_decision_and_closed_wire(
    tmp_path: Path,
    matrix_case: dict[str, Any],
) -> None:
    fixture = _signed_attempt_fixture(
        tmp_path,
        matrix_case,
        prefix=matrix_case["id"],
    )
    output = tmp_path / f"{matrix_case['id']}.observation.json"

    produced = _produce(fixture, output)
    payload = produced.inspection.payload
    wire = produced.inspection.observation_bytes

    assert output.read_bytes() == wire
    assert wire == canonical_json_bytes(payload)
    Draft202012Validator(SCHEMA).validate(payload)
    assert sorted(payload) == WIRE_SHAPE["root_keys"]
    assert sorted(payload["source"]) == WIRE_SHAPE["source_keys"]
    assert "agent_change_context" not in payload
    assert payload["outcome"] == {
        "decision": matrix_case["decision"],
        "verdict": matrix_case["verdict"],
        "passed": matrix_case["passed"],
        "reason_code": matrix_case["reason_code"],
        "execution_state": fixture.record["execution_state"],
        "execution_phase": fixture.record["execution_phase"],
        "verdict_source": fixture.record["verdict_source"],
    }
    assert produced.finalized.decision == matrix_case["decision"]

    source = payload["source"]
    assert source["repository"] == fixture.context["repository"]
    assert source["repository_id"] == fixture.context["repository_id"]
    assert source["pull_request_number"] == fixture.source["pull_request_number"]
    assert source["handoff_workflow_run_id"] == fixture.source["workflow_run_id"]
    assert source["handoff_workflow_run_attempt"] == fixture.source["workflow_run_attempt"]
    assert source["context_run_id"] == fixture.context["run_id"]
    assert source["context_run_attempt"] == fixture.context["run_attempt"]
    assert source["effective_policy_sha256"] == fixture.context["policy_sha256"]

    signed = payload["signed_evidence"]
    bundle_sha256 = hashlib.sha256(fixture.bundle.read_bytes()).hexdigest()
    assert signed["bundle_sha256"] == bundle_sha256
    assert (
        signed["verdict_record_sha256"]
        == hashlib.sha256(fixture.record_path.read_bytes()).hexdigest()
    )
    assert produced.observation_sha256 == hashlib.sha256(wire).hexdigest()

    channels = payload["evidence_channels"]
    assert sorted(channels) == MATRIX["channel_ids"]
    for channel_id, channel in channels.items():
        assert channel["scope"] == WIRE_SHAPE["channel_scopes"][channel_id]
        provenance = channel["provenance"]
        assert sorted(provenance) == WIRE_SHAPE["provenance_keys"]
        assert provenance == {
            "origin": "SIGNED_FINALIZER_BUNDLE",
            "receipt_format": signed["bundle_format"],
            "receipt_sha256": signed["bundle_sha256"],
            "producer_key_id": signed["finalizer_key_id"],
            "correlation_group_id": signed["correlation_group_id"],
            "independently_countable": False,
        }
    raw_git = channels["raw_git_binding"]
    assert raw_git["availability"] == "UNAVAILABLE"
    assert raw_git["bound_identity_count"] is None
    assert raw_git["binding_sha256"] is None
    runtime = channels["runtime_identity"]
    assert runtime["exported_identity_count"] in {0, 1}
    assert (runtime["availability"] == "AVAILABLE") == (runtime["exported_identity_count"] == 1)
    pack = channels["verifier_pack"]
    if source["verifier_pack_sha256"] is None:
        assert pack["availability"] == "NOT_APPLICABLE"
        assert all(
            pack[field] is None
            for field in (
                "present",
                "started",
                "completed",
                "tests_passed",
                "tests_total",
                "result_sha256",
            )
        )

    # Inspection returns fresh parsed views rather than a mutable trust cache.
    first_view = produced.inspection.payload
    first_view["format"] = "MUTATED"
    assert produced.inspection.payload["format"] == "EVOGUARD_CHANGE_ATTEMPT_OBSERVATION_V1"

    inspected_bytes = change_attempt.inspect_change_attempt_observation_bytes(wire)
    inspected_path = change_attempt.inspect_change_attempt_observation(str(output))
    assert inspected_bytes.observation_bytes == wire
    assert inspected_path.payload == payload

    verified_bytes = change_attempt.verify_change_attempt_observation_bytes(
        wire,
        bundle_path=str(fixture.bundle),
        trusted_finalizer_public_key_path=str(fixture.public_key),
        expected_source=fixture.source,
        expected_context=fixture.context,
    )
    verified_path = change_attempt.verify_change_attempt_observation(
        str(output),
        bundle_path=str(fixture.bundle),
        trusted_finalizer_public_key_path=str(fixture.public_key),
        expected_source=fixture.source,
        expected_context=fixture.context,
    )
    assert verified_bytes.inspection.observation_bytes == wire
    assert verified_path.inspection.observation_bytes == wire

    # Local runtime provenance exists only in the wrapper, never in wire facts.
    assert hasattr(produced, "verifier_id")
    assert hasattr(produced, "verified_at")
    assert b"verifier_id" not in wire
    assert b"verified_at" not in wire
    assert b"observation_sha256" not in wire


def test_blackbox_only_repository_suite_is_not_applicable(
    tmp_path: Path,
) -> None:
    blackbox_case = {
        "id": "blackbox-only",
        "reason_code": "candidate_not_exercised",
        "verdict": "ERROR",
        "passed": False,
        "decision": "DENY",
    }
    fixture = _signed_attempt_fixture(
        tmp_path,
        blackbox_case,
        prefix="blackbox-only",
    )
    produced = _produce(fixture, tmp_path / "blackbox-only.json")
    channels = produced.inspection.payload["evidence_channels"]

    repository_suite = channels["repository_suite"]
    assert repository_suite["availability"] == "NOT_APPLICABLE"
    assert all(
        repository_suite[field] is None
        for field in (
            "started",
            "completed",
            "passed",
            "tests_passed",
            "tests_total",
            "result_sha256",
        )
    )
    assert channels["verifier_pack"]["availability"] == "AVAILABLE"


def test_public_projection_name_and_schema_112_channel_rich_record(
    tmp_path: Path,
) -> None:
    rich_case = {
        "id": "schema-1.12-channel-rich",
        "reason_code": "verifier_pack_snapshot_changed",
        "verdict": "TAMPERED",
        "passed": False,
        "decision": "DENY",
    }
    fixture = _signed_attempt_fixture(
        tmp_path,
        rich_case,
        prefix="schema-1.12-channel-rich",
        record_schema_version="1.12",
    )
    produced = _produce(fixture, tmp_path / "schema-1.12-channel-rich.json")
    payload = produced.inspection.payload

    assert isinstance(produced, change_attempt.VerifiedChangeAttemptObservation)
    assert not hasattr(change_attempt, "VerifiedChangeAttemptEvidence")
    assert payload["signed_evidence"]["record_schema"] == "1.12"
    Draft202012Validator(SCHEMA).validate(payload)

    repository_suite = payload["evidence_channels"]["repository_suite"]
    assert repository_suite == {
        "scope": "SIGNED_RECORD_CLAIM",
        "availability": "AVAILABLE",
        "started": True,
        "completed": True,
        "passed": True,
        "tests_passed": 0,
        "tests_total": 0,
        "result_sha256": None,
        "provenance": repository_suite["provenance"],
    }
    runtime = payload["evidence_channels"]["runtime_identity"]
    assert runtime["availability"] == "AVAILABLE"
    assert runtime["exported_identity_count"] == 1
    assert runtime["tree_sha256"] == fixture.record["attestation"]["runtime_tree_sha256"]
    assert runtime["tree_entries"] == fixture.record["attestation"]["runtime_tree_entries"]
    assert runtime["tree_bytes"] == fixture.record["attestation"]["runtime_tree_bytes"]
    verifier_pack = payload["evidence_channels"]["verifier_pack"]
    assert verifier_pack["availability"] == "AVAILABLE"
    assert verifier_pack["present"] is True
    assert verifier_pack["started"] is False
    assert verifier_pack["completed"] is False


def test_published_golden_producer_and_consumer_vector_is_byte_exact(
    tmp_path: Path,
) -> None:
    producer = GOLDEN["producer"]
    matrix_case = next(row for row in CASES if row["id"] == producer["case_id"])
    fixture = _signed_attempt_fixture(
        tmp_path,
        matrix_case,
        prefix=producer["fixture_prefix"],
        public_fixture_key_label=producer["public_fixture_key_label"],
    )
    output = tmp_path / "golden.observation.json"
    produced = _produce(fixture, output)

    golden_path = FIXTURE_ROOT / producer["observation_file"]
    golden_payload = json.loads(golden_path.read_text(encoding="utf-8"))
    golden_bytes = canonical_json_bytes(golden_payload)

    assert (
        hashlib.sha256(fixture.public_key.read_bytes()).hexdigest()
        == (producer["public_key_pem_sha256"])
    )
    assert hashlib.sha256(fixture.bundle.read_bytes()).hexdigest() == (producer["bundle_sha256"])
    assert len(golden_bytes) == producer["observation_size"]
    assert hashlib.sha256(golden_bytes).hexdigest() == producer["observation_sha256"]
    assert produced.inspection.observation_bytes == golden_bytes
    assert output.read_bytes() == golden_bytes
    assert (
        change_attempt.inspect_change_attempt_observation_bytes(golden_bytes).observation_bytes
        == golden_bytes
    )
    assert (
        change_attempt.verify_change_attempt_observation_bytes(
            golden_bytes,
            bundle_path=str(fixture.bundle),
            trusted_finalizer_public_key_path=str(fixture.public_key),
            expected_source=fixture.source,
            expected_context=fixture.context,
        ).inspection.observation_bytes
        == golden_bytes
    )


@pytest.mark.parametrize(
    "consumer_vector",
    GOLDEN["consumer"]["reject"],
    ids=lambda row: row["id"],
)
def test_published_golden_consumer_rejection_vectors_fail_closed(
    consumer_vector: dict[str, Any],
) -> None:
    producer = GOLDEN["producer"]
    golden_payload = json.loads(
        (FIXTURE_ROOT / producer["observation_file"]).read_text(encoding="utf-8")
    )
    _set_json_pointer(
        golden_payload,
        consumer_vector["pointer"],
        consumer_vector["value"],
    )

    with pytest.raises(change_attempt.ChangeAttemptObservationError):
        change_attempt.inspect_change_attempt_observation_bytes(
            canonical_json_bytes(golden_payload)
        )


def test_production_is_canonical_deterministic_no_clobber_and_force_explicit(
    tmp_path: Path,
) -> None:
    fixture = _signed_attempt_fixture(tmp_path, CASES[0], prefix="deterministic")
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"

    first = _produce(fixture, first_path)
    second = _produce(fixture, second_path)
    assert first.inspection.observation_bytes == second.inspection.observation_bytes
    assert first.observation_sha256 == second.observation_sha256

    with pytest.raises(change_attempt.ChangeAttemptObservationError):
        _produce(fixture, first_path)
    forced = _produce(fixture, first_path, force=True)
    assert forced.inspection.observation_bytes == first.inspection.observation_bytes


def test_wrong_key_source_and_context_fail_before_observation_publication(
    tmp_path: Path,
) -> None:
    fixture = _signed_attempt_fixture(tmp_path, CASES[0], prefix="trust-inputs")
    _wrong_private, wrong_public = _keys(tmp_path, "wrong")
    attempts = (
        {
            "trusted_finalizer_public_key_path": str(wrong_public),
            "expected_source": fixture.source,
            "expected_context": fixture.context,
        },
        {
            "trusted_finalizer_public_key_path": str(fixture.public_key),
            "expected_source": dict(
                fixture.source,
                workflow_run_id="transplanted-handoff-run",
            ),
            "expected_context": fixture.context,
        },
        {
            "trusted_finalizer_public_key_path": str(fixture.public_key),
            "expected_source": fixture.source,
            "expected_context": dict(
                fixture.context,
                run_id="transplanted-context-run",
            ),
        },
    )

    for index, kwargs in enumerate(attempts):
        output = tmp_path / f"must-not-exist-{index}.json"
        with pytest.raises(change_attempt.ChangeAttemptObservationError):
            change_attempt.produce_change_attempt_observation(
                str(fixture.bundle),
                str(output),
                **kwargs,
            )
        assert not output.exists()


@pytest.mark.parametrize("security_input", ("bundle", "public-key"))
@pytest.mark.parametrize("alias_kind", ("exact", "normalized", "hardlink"))
def test_output_must_not_alias_a_bundle_or_trusted_public_key(
    tmp_path: Path,
    security_input: str,
    alias_kind: str,
) -> None:
    fixture = _signed_attempt_fixture(
        tmp_path,
        CASES[0],
        prefix=f"alias-{security_input}-{alias_kind}",
    )
    target = fixture.bundle if security_input == "bundle" else fixture.public_key
    target_before = target.read_bytes()

    if alias_kind == "exact":
        output = str(target)
    elif alias_kind == "normalized":
        output = os.path.join(str(target.parent), ".", target.name)
    else:
        alias = tmp_path / f"{security_input}-hardlink.json"
        os.link(target, alias)
        output = str(alias)

    with pytest.raises(
        change_attempt.ChangeAttemptObservationError,
        match="must not alias a security input",
    ):
        change_attempt.produce_change_attempt_observation(
            str(fixture.bundle),
            output,
            trusted_finalizer_public_key_path=str(fixture.public_key),
            expected_source=fixture.source,
            expected_context=fixture.context,
            force=True,
        )

    assert target.read_bytes() == target_before
    assert fixture.bundle.exists()
    assert fixture.public_key.exists()
    if alias_kind == "hardlink":
        assert Path(output).read_bytes() == target_before


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("pull_request_number", 43),
        ("workflow_run_id", "other-handoff-run"),
        ("workflow_run_attempt", 4),
        ("base_sha", "1" * 40),
        ("head_sha", "2" * 40),
    ),
)
def test_every_external_handoff_source_identity_is_bound_exactly(
    tmp_path: Path,
    field: str,
    replacement: object,
) -> None:
    fixture = _signed_attempt_fixture(
        tmp_path,
        CASES[0],
        prefix=f"source-{field}",
    )
    expected_source = dict(fixture.source)
    expected_source[field] = replacement
    output = tmp_path / f"wrong-source-{field}.json"

    with pytest.raises(change_attempt.ChangeAttemptObservationError):
        change_attempt.produce_change_attempt_observation(
            str(fixture.bundle),
            str(output),
            trusted_finalizer_public_key_path=str(fixture.public_key),
            expected_source=expected_source,
            expected_context=fixture.context,
        )
    assert not output.exists()


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("repository", "other/project"),
        ("repository_id", "99999"),
        ("run_id", "other-context-run"),
        ("run_attempt", 8),
        ("base_sha", "1" * 40),
        ("head_sha", "2" * 40),
        ("base_tree_sha", "3" * 40),
        ("head_tree_sha", "4" * 40),
        ("candidate_sha256", "5" * 64),
        ("policy_sha256", "6" * 64),
        ("verifier_pack_sha256", "7" * 64),
        ("guard_artifact_sha256", "8" * 64),
    ),
)
def test_every_external_bundle_context_identity_is_bound_exactly(
    tmp_path: Path,
    field: str,
    replacement: object,
) -> None:
    fixture = _signed_attempt_fixture(
        tmp_path,
        CASES[0],
        prefix=f"context-{field}",
    )
    expected_context = dict(fixture.context)
    expected_context[field] = replacement
    output = tmp_path / f"wrong-context-{field}.json"

    with pytest.raises(change_attempt.ChangeAttemptObservationError):
        change_attempt.produce_change_attempt_observation(
            str(fixture.bundle),
            str(output),
            trusted_finalizer_public_key_path=str(fixture.public_key),
            expected_source=fixture.source,
            expected_context=expected_context,
        )
    assert not output.exists()


@pytest.mark.parametrize("matrix_case", CASES, ids=lambda row: row["id"])
def test_tampered_finalizer_bundle_never_projects_any_of_the_five_verdicts(
    tmp_path: Path,
    matrix_case: dict[str, Any],
) -> None:
    fixture = _signed_attempt_fixture(
        tmp_path,
        matrix_case,
        prefix=f"tampered-{matrix_case['id']}",
    )
    tampered = bytearray(fixture.bundle.read_bytes())
    tampered[20] ^= 0x01
    tampered_bundle = tmp_path / f"{matrix_case['id']}-tampered.evb"
    tampered_bundle.write_bytes(tampered)
    output = tmp_path / f"{matrix_case['id']}-must-not-project.json"

    with pytest.raises(change_attempt.ChangeAttemptObservationError):
        change_attempt.produce_change_attempt_observation(
            str(tampered_bundle),
            str(output),
            trusted_finalizer_public_key_path=str(fixture.public_key),
            expected_source=fixture.source,
            expected_context=fixture.context,
        )
    assert not output.exists()


def test_inspector_rejects_unknown_duplicate_and_noncanonical_observation_bytes(
    tmp_path: Path,
) -> None:
    fixture = _signed_attempt_fixture(tmp_path, CASES[0], prefix="wire-parser")
    produced = _produce(fixture, tmp_path / "wire.json")
    payload = produced.inspection.payload
    wire = produced.inspection.observation_bytes

    unknown_root = _canonical_mutation(
        payload,
        lambda value: value.__setitem__(
            "unexpected_private",
            "PRIVACY_EXTENSION_SENTINEL",
        ),
    )
    with pytest.raises(change_attempt.ChangeAttemptObservationError) as error:
        change_attempt.inspect_change_attempt_observation_bytes(unknown_root)
    assert "PRIVACY_EXTENSION_SENTINEL" not in str(error.value)

    unknown_channel = _canonical_mutation(
        payload,
        lambda value: value["evidence_channels"].__setitem__(
            "guard_execution_copy",
            copy.deepcopy(value["evidence_channels"]["guard_execution"]),
        ),
    )
    with pytest.raises(change_attempt.ChangeAttemptObservationError):
        change_attempt.inspect_change_attempt_observation_bytes(unknown_channel)

    duplicate_format = wire.replace(
        b'"format":"EVOGUARD_CHANGE_ATTEMPT_OBSERVATION_V1"',
        (
            b'"format":"EVOGUARD_CHANGE_ATTEMPT_OBSERVATION_V1",'
            b'"format":"EVOGUARD_CHANGE_ATTEMPT_OBSERVATION_V1"'
        ),
        1,
    )
    assert duplicate_format != wire
    with pytest.raises(change_attempt.ChangeAttemptObservationError):
        change_attempt.inspect_change_attempt_observation_bytes(duplicate_format)

    with pytest.raises(change_attempt.ChangeAttemptObservationError):
        change_attempt.inspect_change_attempt_observation_bytes(b" " + wire)


@pytest.mark.parametrize(
    ("pointer", "terminator"),
    (
        ("/source/candidate_sha256", "\n"),
        ("/source/base_sha", "\n"),
        ("/source/repository", "\n"),
        ("/source/repository_id", "\n"),
        ("/source/handoff_workflow_run_id", "\n"),
        ("/source/context_run_id", "\n"),
        ("/signed_evidence/finalizer_key_id", "\n"),
        ("/signed_evidence/correlation_group_id", "\n"),
        ("/signed_evidence/record_tool_version", "\n"),
        ("/signed_evidence/record_tool_version", "\u2028"),
    ),
)
def test_schema_and_runtime_both_reject_trailing_line_terminators(
    tmp_path: Path,
    pointer: str,
    terminator: str,
) -> None:
    fixture = _signed_attempt_fixture(
        tmp_path,
        CASES[0],
        prefix=f"terminator-{hashlib.sha256(pointer.encode()).hexdigest()[:8]}",
    )
    payload = _produce(fixture, tmp_path / "terminator.json").inspection.payload
    parts = pointer.removeprefix("/").split("/")
    current: Any = payload
    for part in parts[:-1]:
        current = current[part]
    current[parts[-1]] += terminator

    assert list(Draft202012Validator(SCHEMA).iter_errors(payload))
    with pytest.raises(change_attempt.ChangeAttemptObservationError):
        change_attempt.inspect_change_attempt_observation_bytes(canonical_json_bytes(payload))


def test_inspector_rejects_cross_contract_and_incomplete_channel_contradictions(
    tmp_path: Path,
) -> None:
    fixture = _signed_attempt_fixture(tmp_path, CASES[0], prefix="cross-contract")
    payload = _produce(fixture, tmp_path / "cross-contract.json").inspection.payload

    mutations = (
        lambda value: value["evidence_channels"]["verifier_pack"].update(
            {
                "availability": "AVAILABLE",
                "present": False,
                "started": False,
                "completed": False,
            }
        ),
        lambda value: value["evidence_channels"]["runtime_identity"].update(
            {
                "availability": "AVAILABLE",
                "exported_identity_count": 1,
                "tree_sha256": "1" * 64,
                "tree_entries": 1,
                "tree_bytes": 1,
            }
        ),
        lambda value: value["assurance"].__setitem__(
            "report_integrity",
            "not_applicable_static_gate",
        ),
        lambda value: value["evidence_channels"]["repository_suite"].update(
            {
                "availability": "AVAILABLE",
                "started": False,
                "completed": False,
                "passed": False,
            }
        ),
        lambda value: value["evidence_channels"]["guard_execution"].__setitem__(
            "execution_evidence_sha256",
            None,
        ),
    )
    for mutate in mutations:
        claim = _canonical_mutation(payload, mutate)
        with pytest.raises(change_attempt.ChangeAttemptObservationError):
            change_attempt.inspect_change_attempt_observation_bytes(claim)

    schema_mismatch = copy.deepcopy(payload)
    schema_mismatch["evidence_channels"]["guard_execution"]["execution_evidence_sha256"] = None
    assert list(Draft202012Validator(SCHEMA).iter_errors(schema_mismatch))

    blackbox_case = {
        "id": "blackbox-cross-contract",
        "reason_code": "candidate_not_exercised",
        "verdict": "ERROR",
        "passed": False,
        "decision": "DENY",
    }
    blackbox = _signed_attempt_fixture(
        tmp_path,
        blackbox_case,
        prefix="blackbox-cross-contract",
    )
    blackbox_payload = _produce(
        blackbox,
        tmp_path / "blackbox-cross-contract.json",
    ).inspection.payload

    def make_repository_suite_available(value: dict[str, Any]) -> None:
        value["evidence_channels"]["repository_suite"].update(
            {
                "availability": "AVAILABLE",
                "started": False,
                "completed": False,
                "passed": None,
            }
        )

    with pytest.raises(change_attempt.ChangeAttemptObservationError):
        change_attempt.inspect_change_attempt_observation_bytes(
            _canonical_mutation(
                blackbox_payload,
                make_repository_suite_available,
            )
        )


def test_exact_verifier_rejects_outcome_and_correlation_mutations(
    tmp_path: Path,
) -> None:
    fixture = _signed_attempt_fixture(tmp_path, CASES[0], prefix="semantic-tamper")
    produced = _produce(fixture, tmp_path / "semantic.json")
    payload = produced.inspection.payload

    mutations = (
        lambda value: value["outcome"].__setitem__("reason_code", "tests_failed"),
        lambda value: value["outcome"].__setitem__("decision", "DENY"),
        lambda value: value["evidence_channels"]["guard_execution"]["provenance"].__setitem__(
            "correlation_group_id",
            "cg:sha256:" + "0" * 64,
        ),
        lambda value: value["evidence_channels"]["guard_execution"].__setitem__(
            "scope",
            "RAW_GIT_BINDING",
        ),
        lambda value: value["evidence_channels"]["guard_execution"]["provenance"].__setitem__(
            "independently_countable",
            True,
        ),
    )
    for mutate in mutations:
        claim = _canonical_mutation(payload, mutate)
        with pytest.raises(change_attempt.ChangeAttemptObservationError):
            change_attempt.verify_change_attempt_observation_bytes(
                claim,
                bundle_path=str(fixture.bundle),
                trusted_finalizer_public_key_path=str(fixture.public_key),
                expected_source=fixture.source,
                expected_context=fixture.context,
            )

    def relabel_every_group(value: dict[str, Any]) -> None:
        fake = "cg:sha256:" + "f" * 64
        value["signed_evidence"]["correlation_group_id"] = fake
        for channel in value["evidence_channels"].values():
            channel["provenance"]["correlation_group_id"] = fake

    consistently_relabeled = _canonical_mutation(payload, relabel_every_group)
    with pytest.raises(change_attempt.ChangeAttemptObservationError):
        change_attempt.verify_change_attempt_observation_bytes(
            consistently_relabeled,
            bundle_path=str(fixture.bundle),
            trusted_finalizer_public_key_path=str(fixture.public_key),
            expected_source=fixture.source,
            expected_context=fixture.context,
        )


def test_duplicate_channel_key_is_rejected_by_the_strict_json_reader(
    tmp_path: Path,
) -> None:
    fixture = _signed_attempt_fixture(tmp_path, CASES[0], prefix="duplicate-channel")
    produced = _produce(fixture, tmp_path / "duplicate-source.json")
    payload = produced.inspection.payload
    wire = produced.inspection.observation_bytes

    duplicate_entry = canonical_json_bytes(
        {
            "guard_execution": payload["evidence_channels"]["guard_execution"],
        }
    )[1:-2]
    marker = b'"evidence_channels":{'
    duplicate = wire.replace(marker, marker + duplicate_entry + b",", 1)
    assert duplicate != wire
    with pytest.raises(change_attempt.ChangeAttemptObservationError):
        change_attempt.inspect_change_attempt_observation_bytes(duplicate)


def test_cross_run_observation_and_channel_transplants_fail_closed(
    tmp_path: Path,
) -> None:
    first = _signed_attempt_fixture(tmp_path, CASES[0], prefix="run-a")
    second = _signed_attempt_fixture(tmp_path, CASES[2], prefix="run-b")
    first_result = _produce(first, tmp_path / "run-a.json")
    second_result = _produce(second, tmp_path / "run-b.json")

    with pytest.raises(change_attempt.ChangeAttemptObservationError):
        change_attempt.verify_change_attempt_observation_bytes(
            first_result.inspection.observation_bytes,
            bundle_path=str(second.bundle),
            trusted_finalizer_public_key_path=str(second.public_key),
            expected_source=second.source,
            expected_context=second.context,
        )

    first_payload = first_result.inspection.payload
    second_payload = second_result.inspection.payload

    def transplant_channel(value: dict[str, Any]) -> None:
        foreign = copy.deepcopy(second_payload["evidence_channels"]["guard_execution"])
        # Even an attacker who relabels the foreign channel with the local
        # provenance cannot turn it into the exact local signed-record claim.
        foreign["provenance"] = copy.deepcopy(
            value["evidence_channels"]["guard_execution"]["provenance"]
        )
        value["evidence_channels"]["guard_execution"] = foreign

    transplanted = _canonical_mutation(first_payload, transplant_channel)
    with pytest.raises(change_attempt.ChangeAttemptObservationError):
        change_attempt.verify_change_attempt_observation_bytes(
            transplanted,
            bundle_path=str(first.bundle),
            trusted_finalizer_public_key_path=str(first.public_key),
            expected_source=first.source,
            expected_context=first.context,
        )


def test_projection_does_not_export_private_record_content_or_authority(
    tmp_path: Path,
) -> None:
    fixture = _signed_attempt_fixture(tmp_path, CASES[0], prefix="privacy")
    produced = _produce(fixture, tmp_path / "privacy.json")
    payload = produced.inspection.payload
    wire_text = produced.inspection.observation_bytes.decode("ascii")

    keys = _recursive_keys(payload)
    assert not (set(MATRIX["forbidden_wire_keys"]) & keys)
    for token in MATRIX["forbidden_wire_tokens"]:
        assert token not in wire_text
    for token in (
        "app.py",
        "python",
        "pytest",
        "stdout",
        "stderr",
        "tests/test",
    ):
        assert token not in wire_text.lower()
    wrapper_repr = repr(produced)
    assert "finalized=" not in wrapper_repr
    for token in MATRIX["forbidden_wire_tokens"]:
        assert token not in wrapper_repr
    assert "python" not in wrapper_repr
    assert "pytest" not in wrapper_repr
    assert payload["authority"] == {
        "mode": "ADVISORY_ONLY",
        "admission": False,
        "merge": False,
        "deployment": False,
        "promotion": False,
        "external_action": False,
    }


def test_bundle_is_snapshotted_once_before_hash_and_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _signed_attempt_fixture(tmp_path, CASES[0], prefix="snapshot-a")
    second = _signed_attempt_fixture(tmp_path, CASES[2], prefix="snapshot-b")
    expected_verdict = first.record["verdict"]
    replacement = second.bundle.read_bytes()
    real_reader = change_attempt.read_regular_file_bytes
    reads = 0

    def swap_after_snapshot(path: str, *, limit: int, label: str) -> bytes:
        nonlocal reads
        data = real_reader(path, limit=limit, label=label)
        if Path(path).resolve() == first.bundle.resolve():
            reads += 1
            if reads == 1:
                first.bundle.write_bytes(replacement)
        return data

    monkeypatch.setattr(
        change_attempt,
        "read_regular_file_bytes",
        swap_after_snapshot,
    )
    produced = _produce(first, tmp_path / "snapshotted.json")
    assert reads == 1
    assert produced.inspection.payload["outcome"]["verdict"] == expected_verdict


def test_caller_owned_trust_mappings_are_snapshotted_before_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _signed_attempt_fixture(tmp_path, CASES[0], prefix="mapping-snapshot")
    expected_source = dict(fixture.source)
    expected_context = dict(fixture.context)
    original_source = dict(expected_source)
    original_context = dict(expected_context)
    real_verifier = change_attempt.verify_finalized_bundle_without_derivation

    def mutate_caller_mappings_before_upstream_verification(
        bundle_path: str,
        *,
        trusted_public_key_path: str,
        expected_source: dict[str, Any],
        expected_context: dict[str, Any],
    ):
        assert expected_source == original_source
        assert expected_context == original_context
        expected_source_snapshot = dict(expected_source)
        expected_context_snapshot = dict(expected_context)
        globals_source["workflow_run_id"] = "mutated-after-snapshot"
        globals_context["run_id"] = "mutated-after-snapshot"
        return real_verifier(
            bundle_path,
            trusted_public_key_path=trusted_public_key_path,
            expected_source=expected_source_snapshot,
            expected_context=expected_context_snapshot,
        )

    globals_source = expected_source
    globals_context = expected_context
    monkeypatch.setattr(
        change_attempt,
        "verify_finalized_bundle_without_derivation",
        mutate_caller_mappings_before_upstream_verification,
    )
    produced = change_attempt.produce_change_attempt_observation(
        str(fixture.bundle),
        str(tmp_path / "mapping-snapshot.json"),
        trusted_finalizer_public_key_path=str(fixture.public_key),
        expected_source=expected_source,
        expected_context=expected_context,
    )

    assert produced.inspection.payload["source"]["context_run_id"] == (original_context["run_id"])
    assert expected_source["workflow_run_id"] == "mutated-after-snapshot"
    assert expected_context["run_id"] == "mutated-after-snapshot"


def test_committed_no_clobber_publication_survives_temp_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _signed_attempt_fixture(tmp_path, CASES[0], prefix="cleanup-failure")
    output = tmp_path / "cleanup-failure.json"
    real_unlink = change_attempt.os.unlink

    def fail_output_temp_cleanup(path: str, *args: Any, **kwargs: Any) -> None:
        candidate = Path(path)
        if candidate.parent.resolve() == tmp_path.resolve() and candidate.name.startswith(
            ".evoguard-change-attempt-"
        ):
            raise OSError("simulated post-commit cleanup failure")
        real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(change_attempt.os, "unlink", fail_output_temp_cleanup)
    produced = _produce(fixture, output)

    assert output.read_bytes() == produced.inspection.observation_bytes
    assert any(path.name.startswith(".evoguard-change-attempt-") for path in tmp_path.iterdir())


def test_producer_reads_back_the_published_path_and_fails_on_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _signed_attempt_fixture(tmp_path, CASES[0], prefix="readback")
    output = tmp_path / "readback.json"
    real_publisher = change_attempt._published_observation

    def corrupt_after_publish(path: str, data: bytes, *, force: bool) -> str:
        published = real_publisher(path, data, force=force)
        Path(published).write_bytes(b"{}\n")
        return published

    monkeypatch.setattr(
        change_attempt,
        "_published_observation",
        corrupt_after_publish,
    )
    with pytest.raises(
        change_attempt.ChangeAttemptObservationError,
        match="does not match the verified bytes",
    ):
        _produce(fixture, output)


def test_verification_errors_do_not_echo_untrusted_input_paths(
    tmp_path: Path,
) -> None:
    sentinel = "PRIVATE_PATH_SENTINEL"
    missing = tmp_path / f"{sentinel}.evb"
    output = tmp_path / "must-not-exist.json"

    with pytest.raises(change_attempt.ChangeAttemptObservationError) as error:
        change_attempt.produce_change_attempt_observation(
            str(missing),
            str(output),
            trusted_finalizer_public_key_path=str(tmp_path / "missing-public.pem"),
            expected_source={},
            expected_context={},
        )

    assert sentinel not in str(error.value)
    assert not output.exists()


def test_missing_optional_signing_runtime_remains_an_operational_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _signed_attempt_fixture(tmp_path, CASES[0], prefix="signing-unavailable")

    def unavailable(*_args: Any, **_kwargs: Any) -> None:
        raise SigningUnavailableError("cryptography unavailable")

    monkeypatch.setattr(
        change_attempt,
        "verify_finalized_bundle_without_derivation",
        unavailable,
    )
    with pytest.raises(SigningUnavailableError, match="cryptography unavailable"):
        _produce(fixture, tmp_path / "must-not-exist.json")


def test_producer_writes_only_the_requested_output_not_beside_the_bundle(
    tmp_path: Path,
) -> None:
    fixture = _signed_attempt_fixture(tmp_path, CASES[0], prefix="no-sidecar")
    evidence_directory = fixture.bundle.parent
    before = {
        path.name: path.read_bytes() for path in evidence_directory.iterdir() if path.is_file()
    }
    output_directory = tmp_path / "separate-output"
    output = output_directory / "observation.json"

    produced = _produce(fixture, output)

    after = {
        path.name: path.read_bytes() for path in evidence_directory.iterdir() if path.is_file()
    }
    assert after == before
    assert output.read_bytes() == produced.inspection.observation_bytes
