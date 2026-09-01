"""Fail-closed tests for agent-origin evaluation metadata."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from evoom_guard.signing import generate_keypair, public_key_id, sign_bytes
from tools.evaluation import agent_origin

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "tools" / "evaluation" / "schemas" / "agent-origin-1.schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _record() -> dict[str, object]:
    return {
        "schema_version": "evoguard-agent-origin-v1",
        "claims": {
            "agent": {
                "provider": "example-provider",
                "model": "example-model",
                "model_version": "2026-08-31",
                "agent": "example-coding-agent",
                "agent_version": "1.2.3",
            },
            "task": {
                "repository_sha256": _digest("frozen repository tree"),
                "task_sha256": _digest("frozen task descriptor"),
            },
            "run": {
                "run_id": "eval-run-0001",
                "started_utc": "2026-09-01T00:00:00Z",
                "completed_utc": "2026-09-01T00:03:00Z",
                "attempt": 1,
                "max_attempts": 3,
                "retry_of_run_id": None,
            },
            "prompt": {
                "sha256": _digest("exact prompt bytes"),
                "size_bytes": len(b"exact prompt bytes"),
                "content_disclosure": "retained_external",
            },
            "execution": {
                "tools": [
                    {
                        "name": "browser",
                        "version": "1",
                        "descriptor_sha256": _digest("browser descriptor"),
                    },
                    {
                        "name": "shell",
                        "version": "2",
                        "descriptor_sha256": _digest("shell descriptor"),
                    },
                ],
                "permissions": [
                    {
                        "capability": "filesystem",
                        "access": "write",
                        "scope_sha256": _digest("workspace only"),
                    },
                    {
                        "capability": "network",
                        "access": "none",
                        "scope_sha256": _digest("no destinations"),
                    },
                ],
                "randomization": {
                    "mode": "deterministic",
                    "seed": 7,
                    "settings_sha256": _digest("temperature=0;seed=7"),
                },
            },
            "change": {
                "candidate_format": "EVOGUARD_CANDIDATE_TEXT_MAP_V2",
                "candidate_sha256": _digest("candidate text map"),
            },
        },
        "assurance": {"status": "declared_unverified", "attestation": None},
    }


def _bytes(record: dict[str, object]) -> bytes:
    return agent_origin.canonical_json_bytes(record)


def _external_bindings(record: dict[str, object]) -> dict[str, object]:
    claims = record["claims"]
    assert isinstance(claims, dict)
    task = claims["task"]
    change = claims["change"]
    prompt = claims["prompt"]
    assert isinstance(task, dict)
    assert isinstance(change, dict)
    assert isinstance(prompt, dict)
    return {
        "expected_candidate_sha256": change["candidate_sha256"],
        "expected_candidate_format": change["candidate_format"],
        "expected_prompt_sha256": prompt["sha256"],
        "expected_prompt_size_bytes": prompt["size_bytes"],
        "expected_repository_sha256": task["repository_sha256"],
        "expected_task_sha256": task["task_sha256"],
    }


def _validate(record: dict[str, object], **kwargs: object) -> agent_origin.VerifiedAgentOrigin:
    return agent_origin.validate_agent_origin_bytes(
        _bytes(record),
        **_external_bindings(record),
        **kwargs,
    )


def test_declared_record_is_canonical_schema_valid_and_explicitly_unverified() -> None:
    record = _record()
    Draft202012Validator.check_schema(SCHEMA)
    Draft202012Validator(SCHEMA).validate(record)

    verified = _validate(record)

    assert verified.status == "declared_unverified"
    assert verified.attestation_key_id is None
    assert verified.canonical_bytes == _bytes(record)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.__setitem__("unexpected", True), "keys differ"),
        (
            lambda value: value["claims"]["agent"].__setitem__("provider", "bad\nvalue"),
            "control character",
        ),
        (
            lambda value: value["claims"]["agent"].__setitem__(
                "provider", " example-provider"
            ),
            "leading or trailing whitespace",
        ),
        (
            lambda value: value["claims"]["agent"].__setitem__(
                "model", "example-model "
            ),
            "leading or trailing whitespace",
        ),
        (
            lambda value: value["claims"]["run"].__setitem__("run_id", "e\u0301val-run"),
            "NFC-normalized Unicode",
        ),
        (
            lambda value: value["claims"]["agent"].__setitem__(
                "provider", "example\u202eprovider"
            ),
            "control character",
        ),
        (
            lambda value: value["claims"]["agent"].__setitem__(
                "provider", "example\u0085provider"
            ),
            "control character",
        ),
        (
            lambda value: value["claims"]["run"].__setitem__(
                "completed_utc", "2026-08-31T23:59:59Z"
            ),
            "precedes",
        ),
        (
            lambda value: value["claims"]["run"].__setitem__("attempt", True),
            "must be an integer",
        ),
        (
            lambda value: value["claims"]["run"].update(
                {"attempt": 2, "retry_of_run_id": None}
            ),
            "retry_of_run_id",
        ),
        (
            lambda value: value["claims"]["execution"]["tools"].reverse(),
            "canonically sorted",
        ),
        (
            lambda value: value["claims"]["execution"]["permissions"].reverse(),
            "canonically sorted",
        ),
        (
            lambda value: value["claims"]["execution"]["randomization"].__setitem__(
                "seed", None
            ),
            "requires an explicit seed",
        ),
        (
            lambda value: value["claims"]["execution"]["randomization"].__setitem__(
                "mode", []
            ),
            "mode is unsupported",
        ),
        (
            lambda value: value["assurance"].__setitem__("status", []),
            "status is unsupported",
        ),
    ],
)
def test_semantic_validator_rejects_malformed_or_ambiguous_records(
    mutation,
    message: str,
) -> None:
    record = _record()
    mutation(record)

    with pytest.raises(agent_origin.AgentOriginError, match=message):
        _validate(record)


def test_validator_rejects_noncanonical_json_duplicate_keys_and_size_limit() -> None:
    record = _record()
    pretty = json.dumps(record, sort_keys=True, ensure_ascii=False).encode()
    claims = record["claims"]
    assert isinstance(claims, dict)
    with pytest.raises(agent_origin.AgentOriginError, match="not canonical JSON"):
        agent_origin.validate_agent_origin_bytes(
            pretty,
            **_external_bindings(record),
        )
    with pytest.raises(agent_origin.AgentOriginError, match="duplicate JSON key"):
        agent_origin.validate_agent_origin_bytes(
            b'{"schema_version":"x","schema_version":"y"}',
            **_external_bindings(record),
        )
    with pytest.raises(agent_origin.AgentOriginError, match="exceeds"):
        agent_origin.validate_agent_origin_bytes(
            b"{" + b" " * agent_origin.MAX_AGENT_ORIGIN_BYTES + b"}",
            **_external_bindings(record),
        )


def test_external_candidate_and_prompt_bindings_are_mandatory_when_declared() -> None:
    record = _record()
    bindings = _external_bindings(record)

    with pytest.raises(agent_origin.AgentOriginError, match="candidate digest differs"):
        wrong = dict(bindings, expected_candidate_sha256=_digest("another candidate"))
        agent_origin.validate_agent_origin_bytes(
            _bytes(record),
            **wrong,
        )
    with pytest.raises(agent_origin.AgentOriginError, match="prompt digest differs"):
        wrong = dict(bindings, expected_prompt_sha256=_digest("another prompt"))
        agent_origin.validate_agent_origin_bytes(
            _bytes(record),
            **wrong,
        )


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        (
            "expected_candidate_format",
            "sha256_opaque_candidate_bytes",
            "candidate format differs",
        ),
        ("expected_prompt_size_bytes", 0, "prompt size differs"),
        (
            "expected_repository_sha256",
            _digest("another repository"),
            "repository digest differs",
        ),
        (
            "expected_task_sha256",
            _digest("another task"),
            "task digest differs",
        ),
    ],
)
def test_external_descriptor_bindings_reject_semantic_relabels(
    field: str,
    replacement: object,
    message: str,
) -> None:
    record = _record()
    bindings = _external_bindings(record)
    bindings[field] = replacement

    with pytest.raises(agent_origin.AgentOriginError, match=message):
        agent_origin.validate_agent_origin_bytes(_bytes(record), **bindings)


def test_declared_status_cannot_be_upgraded_by_passing_unrelated_trust_inputs(
    tmp_path: Path,
) -> None:
    record = _record()
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    generate_keypair(str(private_key), str(public_key))

    with pytest.raises(agent_origin.AgentOriginError, match="must not be upgraded"):
        _validate(
            record,
            trusted_attestation_public_key_path=str(public_key),
            attestation_signature=b"x" * 64,
        )


def _attested_record(record: dict[str, object], public_key: Path) -> tuple[dict[str, object], bytes]:
    attested = copy.deepcopy(record)
    claims = attested["claims"]
    assert isinstance(claims, dict)
    attester = "Externally configured evaluation launcher"
    statement = agent_origin.agent_origin_attestation_bytes(claims, attester=attester)
    assurance = attested["assurance"]
    assert isinstance(assurance, dict)
    assurance.update(
        {
            "status": "attested",
            "attestation": {
                "format": "EVOGUARD_AGENT_ORIGIN_ATTESTATION_V1",
                "statement_sha256": hashlib.sha256(statement).hexdigest(),
                "signature_algorithm": "Ed25519",
                "key_id": public_key_id(str(public_key)),
                "attester": attester,
            },
        }
    )
    return attested, statement


def test_attested_status_requires_and_verifies_external_signature_and_key(
    tmp_path: Path,
) -> None:
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    generate_keypair(str(private_key), str(public_key))
    record, statement = _attested_record(_record(), public_key)
    signature = sign_bytes(statement, str(private_key))

    with pytest.raises(agent_origin.AgentOriginError, match="requires a trusted public key"):
        _validate(record)

    verified = _validate(
        record,
        trusted_attestation_public_key_path=str(public_key),
        attestation_signature=signature,
    )

    assert verified.status == "attested"
    assert verified.attestation_key_id == public_key_id(str(public_key))

    claims = verified.payload["claims"]
    assert isinstance(claims, dict) is False
    with pytest.raises(TypeError):
        claims["agent"] = {}  # type: ignore[index]
    agent = claims["agent"]
    with pytest.raises(TypeError):
        agent["provider"] = "changed after verification"  # type: ignore[index]
    execution = claims["execution"]
    with pytest.raises(AttributeError):
        execution["tools"].append({})


def test_attester_identity_rejects_textual_aliases(tmp_path: Path) -> None:
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    generate_keypair(str(private_key), str(public_key))
    record, statement = _attested_record(_record(), public_key)
    record["assurance"]["attestation"]["attester"] = " External launcher"

    with pytest.raises(agent_origin.AgentOriginError, match="leading or trailing whitespace"):
        _validate(
            record,
            trusted_attestation_public_key_path=str(public_key),
            attestation_signature=sign_bytes(statement, str(private_key)),
        )


def test_attested_status_fails_closed_on_statement_key_or_signature_mismatch(
    tmp_path: Path,
) -> None:
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    other_private = tmp_path / "other-private.pem"
    other_public = tmp_path / "other-public.pem"
    generate_keypair(str(private_key), str(public_key))
    generate_keypair(str(other_private), str(other_public))
    record, statement = _attested_record(_record(), public_key)

    bad_statement = copy.deepcopy(record)
    bad_statement["assurance"]["attestation"]["statement_sha256"] = _digest("wrong")
    with pytest.raises(agent_origin.AgentOriginError, match="does not bind the claims"):
        _validate(
            bad_statement,
            trusted_attestation_public_key_path=str(public_key),
            attestation_signature=sign_bytes(statement, str(private_key)),
        )

    with pytest.raises(agent_origin.AgentOriginError, match="key ID differs"):
        _validate(
            record,
            trusted_attestation_public_key_path=str(other_public),
            attestation_signature=sign_bytes(statement, str(other_private)),
        )

    with pytest.raises(agent_origin.AgentOriginError, match="signature is invalid"):
        _validate(
            record,
            trusted_attestation_public_key_path=str(public_key),
            attestation_signature=sign_bytes(b"different statement", str(private_key)),
        )

    changed_attester = copy.deepcopy(record)
    changed_attester["assurance"]["attestation"]["attester"] = "Another organization"
    changed_claims = changed_attester["claims"]
    changed_attestation = changed_attester["assurance"]["attestation"]
    changed_statement = agent_origin.agent_origin_attestation_bytes(
        changed_claims,
        attester=changed_attestation["attester"],
    )
    changed_attestation["statement_sha256"] = hashlib.sha256(changed_statement).hexdigest()
    with pytest.raises(agent_origin.AgentOriginError, match="signature is invalid"):
        _validate(
            changed_attester,
            trusted_attestation_public_key_path=str(public_key),
            attestation_signature=sign_bytes(statement, str(private_key)),
        )


def _retry_record(
    *,
    attempt: int,
    run_id: str,
    retry_of: str | None,
    started: str,
    completed: str,
) -> dict[str, object]:
    record = _record()
    claims = record["claims"]
    assert isinstance(claims, dict)
    run = claims["run"]
    change = claims["change"]
    assert isinstance(run, dict)
    assert isinstance(change, dict)
    run.update(
        {
            "run_id": run_id,
            "attempt": attempt,
            "retry_of_run_id": retry_of,
            "started_utc": started,
            "completed_utc": completed,
        }
    )
    change["candidate_sha256"] = _digest(f"candidate attempt {attempt}")
    return record


def _valid_retry_records() -> list[dict[str, object]]:
    return [
        _retry_record(
            attempt=1,
            run_id="run-1",
            retry_of=None,
            started="2026-09-01T00:00:00Z",
            completed="2026-09-01T00:01:00Z",
        ),
        _retry_record(
            attempt=2,
            run_id="run-2",
            retry_of="run-1",
            started="2026-09-01T00:01:00Z",
            completed="2026-09-01T00:02:00Z",
        ),
        _retry_record(
            attempt=3,
            run_id="run-3",
            retry_of="run-2",
            started="2026-09-01T00:02:00Z",
            completed="2026-09-01T00:03:00Z",
        ),
    ]


def _retry_input(
    record: dict[str, object],
    *,
    trusted_key: str | None = None,
    signature: bytes | None = None,
) -> agent_origin.AgentOriginRetryInput:
    claims = record["claims"]
    assert isinstance(claims, dict)
    change = claims["change"]
    prompt = claims["prompt"]
    assert isinstance(change, dict) and isinstance(prompt, dict)
    return agent_origin.AgentOriginRetryInput(
        record_bytes=_bytes(record),
        expected_candidate_sha256=change["candidate_sha256"],
        expected_candidate_format=change["candidate_format"],
        expected_prompt_sha256=prompt["sha256"],
        expected_prompt_size_bytes=prompt["size_bytes"],
        trusted_attestation_public_key_path=trusted_key,
        attestation_signature=signature,
    )


def _validate_chain(
    records: list[dict[str, object]],
    *,
    expected_attempt_count: int | None = None,
    expected_run_ids: tuple[str, ...] | None = None,
) -> tuple[agent_origin.VerifiedAgentOrigin, ...]:
    return agent_origin.validate_agent_origin_retry_chain(
        [_retry_input(record) for record in records],
        expected_repository_sha256=_digest("frozen repository tree"),
        expected_task_sha256=_digest("frozen task descriptor"),
        expected_attempt_count=(
            len(records) if expected_attempt_count is None else expected_attempt_count
        ),
        expected_run_ids=(
            tuple(
                record["claims"]["run"]["run_id"]  # type: ignore[index]
                for record in sorted(
                    records,
                    key=lambda item: item["claims"]["run"]["attempt"],  # type: ignore[index]
                )
            )
            if expected_run_ids is None
            else expected_run_ids
        ),
    )


def test_retry_chain_is_complete_ordered_and_not_counted_as_independent_runs() -> None:
    records = _valid_retry_records()

    verified = _validate_chain([records[2], records[0], records[1]])

    assert [item.payload["claims"]["run"]["attempt"] for item in verified] == [
        1,
        2,
        3,
    ]


def test_verified_result_cannot_be_constructed_by_a_caller() -> None:
    with pytest.raises(TypeError):
        agent_origin.VerifiedAgentOrigin()  # type: ignore[call-arg]


def test_retry_chain_rejects_a_truncated_prefix() -> None:
    with pytest.raises(agent_origin.AgentOriginError, match="expected attempt count"):
        _validate_chain(_valid_retry_records()[:2], expected_attempt_count=3)


def test_retry_chain_rejects_an_external_branch_or_run_roster_drift() -> None:
    with pytest.raises(agent_origin.AgentOriginError, match="external frozen roster"):
        _validate_chain(
            _valid_retry_records(),
            expected_run_ids=("run-1", "alternate-run-2", "run-3"),
        )


def test_retry_chain_rejects_assurance_or_attester_drift(tmp_path: Path) -> None:
    records = _valid_retry_records()
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    generate_keypair(str(private_key), str(public_key))
    attested_record, statement = _attested_record(records[1], public_key)
    signature = sign_bytes(statement, str(private_key))

    with pytest.raises(agent_origin.AgentOriginError, match="assurance status"):
        agent_origin.validate_agent_origin_retry_chain(
            [
                _retry_input(records[0]),
                _retry_input(
                    attested_record,
                    trusted_key=str(public_key),
                    signature=signature,
                ),
            ],
            expected_repository_sha256=_digest("frozen repository tree"),
            expected_task_sha256=_digest("frozen task descriptor"),
            expected_attempt_count=2,
            expected_run_ids=("run-1", "run-2"),
        )


def test_retry_chain_revalidates_attested_bytes_and_requires_signature(
    tmp_path: Path,
) -> None:
    record = _valid_retry_records()[0]
    public_key = tmp_path / "public.pem"
    private_key = tmp_path / "private.pem"
    generate_keypair(str(private_key), str(public_key))
    attested_record, _statement = _attested_record(record, public_key)

    with pytest.raises(agent_origin.AgentOriginError, match="requires a trusted"):
        agent_origin.validate_agent_origin_retry_chain(
            [_retry_input(attested_record)],
            expected_repository_sha256=_digest("frozen repository tree"),
            expected_task_sha256=_digest("frozen task descriptor"),
            expected_attempt_count=1,
            expected_run_ids=("run-1",),
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda records: records.pop(0),
            "consecutive from 1",
        ),
        (
            lambda records: records[1]["claims"]["run"].__setitem__(
                "retry_of_run_id", "unknown-run"
            ),
            "immediately preceding run",
        ),
        (
            lambda records: records[1]["claims"]["run"].update(
                {
                    "started_utc": "2026-09-01T00:00:30Z",
                    "completed_utc": "2026-09-01T00:01:30Z",
                }
            ),
            "overlap",
        ),
        (
            lambda records: records[1]["claims"]["agent"].__setitem__(
                "model", "drifted-model"
            ),
            "settings drifted",
        ),
        (
            lambda records: records[1]["claims"]["run"].__setitem__(
                "max_attempts", 4
            ),
            "max_attempts must remain stable",
        ),
    ],
)
def test_retry_chain_rejects_missing_parent_time_overlap_or_setting_drift(
    mutation,
    message: str,
) -> None:
    records = _valid_retry_records()
    mutation(records)

    with pytest.raises(agent_origin.AgentOriginError, match=message):
        _validate_chain(records)


def test_retry_chain_rejects_external_task_relabel() -> None:
    retry_inputs = [_retry_input(record) for record in _valid_retry_records()]

    with pytest.raises(agent_origin.AgentOriginError, match="task digest differs"):
        agent_origin.validate_agent_origin_retry_chain(
            retry_inputs,
            expected_repository_sha256=_digest("frozen repository tree"),
            expected_task_sha256=_digest("different task"),
            expected_attempt_count=3,
            expected_run_ids=("run-1", "run-2", "run-3"),
        )


def test_json_schema_forbids_false_attested_shape() -> None:
    record = _record()
    record["assurance"] = {"status": "attested", "attestation": None}

    errors = list(Draft202012Validator(SCHEMA).iter_errors(record))

    assert errors
