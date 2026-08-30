"""Golden-vector and wire-mapping contracts for the field-ledger thin client.

The golden values are the ledger pilot's frozen deterministic vectors: the
Ed25519 signer seed ``bytes(range(32))``, the fixed clock instant
``2026-08-03T12:34:56Z``, the exact 580-byte canonical first-transition
request, and the receipt the pilot deterministically issues for it.  They
must never be regenerated from runtime expectations.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import evoom_guard.round_ledger_client as client

GOLDEN_SIGNER_SEED = bytes(range(32))
GOLDEN_KEY_ID = (
    "sha256:a050837d85070582ccf7394b0988847cc312cb88259b894899f6f239cf1791a5"
)
GOLDEN_REQUEST_SHA256 = (
    "8f57fe08d05a80caaee1c4c25f32f54c9ccb14e23444dc2d2f62b6d706809eca"
)
GOLDEN_REQUEST_LENGTH = 580
GOLDEN_RECEIPT_SHA256 = (
    "f9a8daef5aa4baf39265b95b8ed044fa85cabe5da58061f9301ee73886713074"
)
GOLDEN_RECEIPT_SIGNATURE = (
    "S/h3fw931op5CZ6KpZkJL5Vd6/93nVMNOYR8baPFpmi3S9h+2vBBmx4pn4FwiXesdTYVpKVC9I9j"
    "ob/bXZNODA=="
)
GOLDEN_ISSUED_AT = "2026-08-03T12:34:56Z"

ENDPOINT = "https://ledger.example/transitions"


def _golden_private_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(GOLDEN_SIGNER_SEED)


def _golden_public_key() -> ed25519.Ed25519PublicKey:
    return _golden_private_key().public_key()


def _golden_request_bytes() -> bytes:
    return client.build_transition_request(
        ledger_id="field-ledger-01",
        slot_id="1" * 64,
        previous_state=None,
        state="RESERVED",
        input_sha256="2" * 64,
        idempotency_key="3" * 64,
        expected_sequence=0,
        expected_previous_receipt_sha256=None,
    )


def _golden_receipt() -> dict[str, Any]:
    request = json.loads(_golden_request_bytes())
    return {
        "schema_version": client.RECEIPT_SCHEMA,
        "signature_domain": client.SIGNATURE_DOMAIN,
        "signature_purpose": client.SIGNATURE_PURPOSE,
        "ledger_id": request["ledger_id"],
        "sequence": 1,
        "slot_id": request["slot_id"],
        "previous_state": request["previous_state"],
        "state": request["state"],
        "input_sha256": request["input_sha256"],
        "previous_receipt_sha256": None,
        "idempotency_key": request["idempotency_key"],
        "compare_and_swap": request["compare_and_swap"],
        "request_sha256": GOLDEN_REQUEST_SHA256,
        "issued_at": GOLDEN_ISSUED_AT,
        "authentication": {
            "algorithm": "Ed25519",
            "key_id": GOLDEN_KEY_ID,
            "signature_encoding": "base64",
            "signature": GOLDEN_RECEIPT_SIGNATURE,
        },
    }


def _golden_receipt_bytes() -> bytes:
    return client.canonical_json_bytes(_golden_receipt())


# --- golden vectors ---------------------------------------------------------


def test_golden_request_bytes_are_frozen() -> None:
    body = _golden_request_bytes()
    assert len(body) == GOLDEN_REQUEST_LENGTH
    assert hashlib.sha256(body).hexdigest() == GOLDEN_REQUEST_SHA256
    assert client.parse_canonical_request(body)["state"] == "RESERVED"


def test_golden_key_id_derives_from_the_deterministic_seed() -> None:
    raw = _golden_public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert client.key_id_from_raw_public_key(raw) == GOLDEN_KEY_ID
    spki = _golden_public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert "sha256:" + hashlib.sha256(spki).hexdigest() == GOLDEN_KEY_ID


def test_golden_receipt_bytes_are_frozen_and_verify() -> None:
    receipt_bytes = _golden_receipt_bytes()
    assert hashlib.sha256(receipt_bytes).hexdigest() == GOLDEN_RECEIPT_SHA256
    verified = client.verify_receipt(
        receipt_bytes,
        _golden_request_bytes(),
        pinned_key_id=GOLDEN_KEY_ID,
        verifier=_golden_public_key(),
    )
    assert verified["sequence"] == 1
    assert verified["issued_at"] == GOLDEN_ISSUED_AT


def test_golden_receipt_signature_is_deterministically_reproducible() -> None:
    projection = client.receipt_projection(_golden_receipt())
    message = client.ledger_signature_message(projection)
    signature = _golden_private_key().sign(message)
    assert base64.b64encode(signature).decode("ascii") == GOLDEN_RECEIPT_SIGNATURE


def test_signature_message_framing_is_exact() -> None:
    projection = client.receipt_projection(_golden_receipt())
    payload = client.canonical_json_bytes(projection)
    domain = client.SIGNATURE_DOMAIN.encode("ascii")
    purpose = client.SIGNATURE_PURPOSE.encode("ascii")
    expected = bytearray(client.SIGNATURE_MAGIC)
    for label, value in (
        (b"domain", domain),
        (b"purpose", purpose),
        (b"canonical_json", payload),
    ):
        expected += len(label).to_bytes(2, "big") + label
        expected += len(value).to_bytes(8, "big") + value
    assert client.ledger_signature_message(projection) == bytes(expected)


def test_verify_receipt_rejects_request_binding_drift() -> None:
    receipt = _golden_receipt()
    receipt["input_sha256"] = "4" * 64
    receipt_bytes = client.canonical_json_bytes(receipt)
    with pytest.raises(client.ReceiptVerificationError):
        client.verify_receipt(
            receipt_bytes,
            _golden_request_bytes(),
            pinned_key_id=GOLDEN_KEY_ID,
            verifier=_golden_public_key(),
        )


def test_verify_receipt_rejects_an_unpinned_signer_key() -> None:
    other_key_id = "sha256:" + "b" * 64
    with pytest.raises(client.ReceiptVerificationError):
        client.verify_receipt(
            _golden_receipt_bytes(),
            _golden_request_bytes(),
            pinned_key_id=other_key_id,
            verifier=_golden_public_key(),
        )


# --- canonicalization and mutation vectors ----------------------------------


def test_canonical_json_rejects_floats_and_deep_nesting() -> None:
    with pytest.raises(client.LedgerProtocolError):
        client.canonical_json_bytes({"value": 1.5})
    nested: Any = "leaf"
    for _ in range(40):
        nested = [nested]
    with pytest.raises(client.LedgerProtocolError):
        client.canonical_json_bytes(nested)
    with pytest.raises(client.LedgerProtocolError):
        client.canonical_json_bytes({"n": 2**63})


@pytest.mark.parametrize(
    "mutation",
    [
        lambda body: b" " + body,
        lambda body: body + b"\n",
        lambda body: body.replace(b'"state":"RESERVED"', b'"state":"reserved"'),
        lambda body: body.replace(b"field-ledger-01", b"FIELD-LEDGER-01"),
        lambda body: b"",
        lambda body: b"[]",
        lambda body: b"\xff",
        lambda body: body.replace(
            b'"expected_sequence":0', b'"expected_sequence":false'
        ),
    ],
)
def test_mutated_request_bytes_are_rejected(mutation: Any) -> None:
    body = mutation(_golden_request_bytes())
    with pytest.raises(client.LedgerProtocolError):
        client.parse_canonical_request(body)


def test_oversized_integer_literals_are_rejected() -> None:
    body = _golden_request_bytes().replace(
        b'"expected_sequence":0', b'"expected_sequence":' + b"9" * 5000
    )
    with pytest.raises(client.LedgerProtocolError):
        client.parse_canonical_request(body)


def test_duplicate_keys_are_rejected() -> None:
    body = _golden_request_bytes().replace(
        b'"state":"RESERVED"', b'"state":"RESERVED","state":"RESERVED"'
    )
    with pytest.raises(client.LedgerProtocolError):
        client.parse_canonical_request(body)


def test_lifecycle_edges_are_enforced() -> None:
    assert client.validate_transition(None, "RESERVED") == (None, "RESERVED")
    assert client.validate_transition("RESERVED", "RUNNING") == (
        "RESERVED",
        "RUNNING",
    )
    with pytest.raises(client.LedgerProtocolError):
        client.validate_transition(None, "RUNNING")
    with pytest.raises(client.LedgerProtocolError):
        client.validate_transition("RESERVED", "OBSERVED")
    with pytest.raises(client.LedgerProtocolError):
        client.validate_transition("INCLUDED", "RESERVED")


def test_cas_zero_and_null_must_coincide() -> None:
    with pytest.raises(client.LedgerProtocolError):
        client.validate_cas(
            {"expected_sequence": 0, "expected_previous_receipt_sha256": "a" * 64}
        )
    with pytest.raises(client.LedgerProtocolError):
        client.validate_cas(
            {"expected_sequence": 1, "expected_previous_receipt_sha256": None}
        )


# --- HTTP surface -----------------------------------------------------------


def _response(
    status: int,
    body: bytes,
    *,
    marker: str | None = None,
    extra: tuple[tuple[str, str], ...] = (),
) -> client.HttpResponse:
    headers = [
        ("content-type", "application/json"),
        ("content-length", str(len(body))),
        ("cache-control", "no-store"),
        ("x-evoom-ledger-proof-level", "reference-pilot"),
    ]
    if marker is not None:
        headers.append(("x-evoom-ledger-result", marker))
    headers.extend(extra)
    return client.HttpResponse(status=status, headers=tuple(headers), body=body)


def _error_bytes(code: str, message: str) -> bytes:
    return client.canonical_json_bytes(
        {
            "error": {"code": code, "message": message},
            "proof_level": "reference-pilot",
        }
    )


def _transport_returning(response: client.HttpResponse) -> Any:
    calls: list[tuple[str, str, dict[str, str], bytes | None]] = []

    def _send(
        method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> client.HttpResponse:
        calls.append((method, url, headers, body))
        return response

    _send.calls = calls  # type: ignore[attr-defined]
    return _send


def test_append_created_and_replayed_are_classified() -> None:
    request_bytes = _golden_request_bytes()
    receipt_bytes = _golden_receipt_bytes()
    created = client.append_exact_request(
        request_bytes,
        endpoint=ENDPOINT,
        transport=_transport_returning(
            _response(201, receipt_bytes, marker="created")
        ),
    )
    assert created.created is True
    assert created.receipt_bytes == receipt_bytes
    replayed = client.append_exact_request(
        request_bytes,
        endpoint=ENDPOINT,
        transport=_transport_returning(
            _response(200, receipt_bytes, marker="replayed")
        ),
    )
    assert replayed.created is False


def test_append_sends_the_exact_bytes_and_idempotency_header() -> None:
    request_bytes = _golden_request_bytes()
    transport = _transport_returning(
        _response(201, _golden_receipt_bytes(), marker="created")
    )
    client.append_exact_request(
        request_bytes, endpoint=ENDPOINT, transport=transport
    )
    ((method, url, headers, body),) = transport.calls
    assert method == "POST"
    assert url == ENDPOINT
    assert body == request_bytes
    assert headers["Idempotency-Key"] == "3" * 64
    assert headers["Content-Type"] == "application/json"
    assert headers["Accept"] == "application/json"


def test_append_rejects_an_inconsistent_result_marker() -> None:
    with pytest.raises(client.LedgerProtocolError):
        client.append_exact_request(
            _golden_request_bytes(),
            endpoint=ENDPOINT,
            transport=_transport_returning(
                _response(201, _golden_receipt_bytes(), marker="replayed")
            ),
        )


@pytest.mark.parametrize(
    "code",
    ["idempotency_mismatch", "signer_mismatch", "cas_conflict", "slot_conflict"],
)
def test_append_conflicts_carry_their_code(code: str) -> None:
    with pytest.raises(client.LedgerConflictError) as excinfo:
        client.append_exact_request(
            _golden_request_bytes(),
            endpoint=ENDPOINT,
            transport=_transport_returning(
                _response(409, _error_bytes(code, "conflict"))
            ),
        )
    assert excinfo.value.code == code


def test_append_rejects_unknown_conflict_codes_and_markers() -> None:
    with pytest.raises(client.LedgerProtocolError):
        client.append_exact_request(
            _golden_request_bytes(),
            endpoint=ENDPOINT,
            transport=_transport_returning(
                _response(409, _error_bytes("mystery_code", "conflict"))
            ),
        )
    with pytest.raises(client.LedgerProtocolError):
        client.append_exact_request(
            _golden_request_bytes(),
            endpoint=ENDPOINT,
            transport=_transport_returning(
                _response(
                    409, _error_bytes("cas_conflict", "conflict"), marker="created"
                )
            ),
        )


def test_append_definite_rejection_is_not_ambiguous() -> None:
    with pytest.raises(client.LedgerRejectedError):
        client.append_exact_request(
            _golden_request_bytes(),
            endpoint=ENDPOINT,
            transport=_transport_returning(
                _response(400, _error_bytes("invalid_request", "bad"))
            ),
        )


@pytest.mark.parametrize("status", [100, 302, 408, 425, 429, 500, 502, 503])
def test_append_ambiguous_statuses_demand_exact_retry(status: int) -> None:
    with pytest.raises(client.LedgerAmbiguousOutcome):
        client.append_exact_request(
            _golden_request_bytes(),
            endpoint=ENDPOINT,
            transport=_transport_returning(
                client.HttpResponse(status=status, headers=(), body=b"")
            ),
        )


def test_append_transport_failure_is_ambiguous() -> None:
    def _broken(
        method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> client.HttpResponse:
        raise OSError("connection reset")

    with pytest.raises(client.LedgerAmbiguousOutcome):
        client.append_exact_request(
            _golden_request_bytes(), endpoint=ENDPOINT, transport=_broken
        )


def test_lookup_returns_none_only_on_the_exact_not_found_body() -> None:
    absent = client.lookup_receipt(
        _golden_request_bytes(),
        endpoint=ENDPOINT,
        transport=_transport_returning(
            _response(404, _error_bytes("receipt_not_found", "receipt not found"))
        ),
        pinned_key_id=GOLDEN_KEY_ID,
        verifier=_golden_public_key(),
    )
    assert absent is None
    with pytest.raises(client.LedgerProtocolError):
        client.lookup_receipt(
            _golden_request_bytes(),
            endpoint=ENDPOINT,
            transport=_transport_returning(
                _response(404, _error_bytes("ledger_not_found", "ledger not found"))
            ),
            pinned_key_id=GOLDEN_KEY_ID,
            verifier=_golden_public_key(),
        )


def test_lookup_verifies_the_recovered_receipt_bytes() -> None:
    receipt_bytes = _golden_receipt_bytes()
    transport = _transport_returning(_response(200, receipt_bytes))
    recovered = client.lookup_receipt(
        _golden_request_bytes(),
        endpoint=ENDPOINT,
        transport=transport,
        pinned_key_id=GOLDEN_KEY_ID,
        verifier=_golden_public_key(),
    )
    assert recovered == receipt_bytes
    ((method, url, headers, body),) = transport.calls
    assert method == "GET"
    assert url == (
        "https://ledger.example/v1/ledgers/field-ledger-01"
        "/receipts/by-idempotency/" + "3" * 64
    )
    assert body is None


def test_recovery_rejects_result_markers_and_location_headers() -> None:
    with pytest.raises(client.LedgerProtocolError):
        client.lookup_receipt(
            _golden_request_bytes(),
            endpoint=ENDPOINT,
            transport=_transport_returning(
                _response(200, _golden_receipt_bytes(), marker="created")
            ),
            pinned_key_id=GOLDEN_KEY_ID,
            verifier=_golden_public_key(),
        )


def test_observed_head_verifies_and_reports_absence() -> None:
    head_projection = {
        "schema_version": client.HEAD_ASSERTION_SCHEMA,
        "signature_domain": client.HEAD_SIGNATURE_DOMAIN,
        "signature_purpose": client.HEAD_SIGNATURE_PURPOSE,
        "proof_level": client.REFERENCE_PROOF_LEVEL,
        "ledger_id": "field-ledger-01",
        "head": {"receipt_sha256": GOLDEN_RECEIPT_SHA256, "sequence": 1},
        "limitations": list(client.HEAD_ASSERTION_LIMITATIONS),
    }
    signature = _golden_private_key().sign(
        client.head_signature_message(dict(head_projection))
    )
    assertion = {
        **head_projection,
        "authentication": {
            "algorithm": "Ed25519",
            "key_id": GOLDEN_KEY_ID,
            "signature_encoding": "base64",
            "signature": base64.b64encode(signature).decode("ascii"),
        },
    }
    assertion_bytes = client.canonical_json_bytes(assertion)
    head = client.observed_head(
        "field-ledger-01",
        endpoint=ENDPOINT,
        transport=_transport_returning(_response(200, assertion_bytes)),
        pinned_key_id=GOLDEN_KEY_ID,
        verifier=_golden_public_key(),
    )
    assert head is not None
    assert head["head"]["sequence"] == 1
    absent = client.observed_head(
        "field-ledger-01",
        endpoint=ENDPOINT,
        transport=_transport_returning(
            _response(404, _error_bytes("ledger_not_found", "ledger not found"))
        ),
        pinned_key_id=GOLDEN_KEY_ID,
        verifier=_golden_public_key(),
    )
    assert absent is None


def test_endpoint_validation_refuses_unsafe_urls() -> None:
    for bad in (
        "http://ledger.example/transitions",
        "https://ledger.example/transitions?x=1",
        "https://user:pw@ledger.example/transitions",
        "https://ledger.example/other",
        "https://ledger.example//transitions",
        "https://ledger.example/%2e/transitions",
    ):
        with pytest.raises(client.LedgerProtocolError):
            client.validate_endpoint(bad)
    assert client.validate_endpoint(ENDPOINT) == ("https://ledger.example", "/v1")
    assert client.validate_endpoint("https://ledger.example/v1/transitions") == (
        "https://ledger.example",
        "/v1",
    )
