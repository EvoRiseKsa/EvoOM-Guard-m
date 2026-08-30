"""Golden-vector and wire-mapping contracts for the remote-signer thin client.

Two independent frozen sources hold the client to the pilot's exact bytes:

- ``tests/fixtures/remote-signer-request-authentication-v1/vector-001/`` —
  the on-disk request-authentication vector (seed, operation, framed
  messages, deterministic signatures, closing manifest).
- ``tests/frozen_remote_signer_v1.py`` — the embedded golden operation,
  receipt, and authority-signature message with pinned lengths + digests.

All key material here is public test material; none of it is a credential.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import frozen_remote_signer_v1 as frozen
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import evoom_guard.remote_signer_client as client

VECTOR_DIR = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "remote-signer-request-authentication-v1"
    / "vector-001"
)
BASE_URL = "https://signer.example"

AUTHORITY_SEED = bytes(range(65, 97))
RECEIPT_KEY_SEED = bytes(range(97, 129))


def _vector(name: str) -> bytes:
    return (VECTOR_DIR / name).read_bytes()


def _raw_public(private: ed25519.Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _requester_private_key() -> ed25519.Ed25519PrivateKey:
    seed = _vector("requester-public-test-seed.bin")
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def _post_authentication() -> dict[str, Any]:
    return json.loads(_vector("post-authentication.json"))


def _get_authentication() -> dict[str, Any]:
    return json.loads(_vector("get-authentication.json"))


def _service_identity() -> str:
    manifest = json.loads(_vector("manifest.json"))
    return str(manifest["trust_context"]["signer_service_identity_sha256"])


def _operation_id() -> str:
    return _vector("operation-id.txt").decode("ascii")


# --- fixture vector-001: request authentication -----------------------------


def test_requester_key_id_derives_from_the_fixture_seed() -> None:
    key_id = client.key_id_from_raw_public_key(_raw_public(_requester_private_key()))
    assert key_id == _post_authentication()["requester_key_id"]
    assert key_id == _get_authentication()["requester_key_id"]


def test_operation_fixture_reserializes_byte_exactly() -> None:
    operation_bytes = _vector("operation.json")
    operation = client.parse_operation_bytes(operation_bytes)
    assert client.canonical_json_bytes(operation) == operation_bytes
    assert operation["operation_id"] == _operation_id()


def test_post_signature_message_matches_the_frozen_bytes() -> None:
    operation_bytes = _vector("operation.json")
    message = client.request_signature_message(
        method="POST",
        path=client.SIGNATURE_PATH,
        signer_service_identity_sha256=_service_identity(),
        operation_id=_operation_id(),
        body=operation_bytes,
        requester_key_id=_post_authentication()["requester_key_id"],
    )
    assert message == _vector("post-signature-message.bin")


def test_get_signature_message_matches_the_frozen_bytes() -> None:
    message = client.request_signature_message(
        method="GET",
        path=client.OPERATION_LOOKUP_PATH_PREFIX + _operation_id(),
        signer_service_identity_sha256=_service_identity(),
        operation_id=_operation_id(),
        body=b"",
        requester_key_id=_get_authentication()["requester_key_id"],
    )
    assert message == _vector("get-signature-message.bin")


def test_deterministic_signatures_reproduce_the_fixture_records() -> None:
    private = _requester_private_key()
    post_signature = private.sign(_vector("post-signature-message.bin"))
    get_signature = private.sign(_vector("get-signature-message.bin"))
    assert (
        base64.b64encode(post_signature).decode("ascii")
        == _post_authentication()["signature"]
    )
    assert (
        base64.b64encode(get_signature).decode("ascii")
        == _get_authentication()["signature"]
    )


def test_request_auth_headers_carry_the_frozen_signature() -> None:
    private = _requester_private_key()
    headers = client.request_auth_headers(
        method="POST",
        path=client.SIGNATURE_PATH,
        signer_service_identity_sha256=_service_identity(),
        operation_id=_operation_id(),
        body=_vector("operation.json"),
        requester_key_id=_post_authentication()["requester_key_id"],
        sign=private.sign,
    )
    assert headers == {
        client.REQUESTER_KEY_ID_HEADER: _post_authentication()["requester_key_id"],
        client.REQUESTER_SIGNATURE_HEADER: _post_authentication()["signature"],
    }


# --- embedded golden vector: operation, message, receipt --------------------


def test_embedded_golden_measurements_are_intact() -> None:
    artifacts = {
        "GATE_CONTRACT_ENVELOPE_BYTES": frozen.GATE_CONTRACT_ENVELOPE_BYTES,
        "OPERATION_BYTES": frozen.OPERATION_BYTES,
        "RECEIPT_BYTES": frozen.RECEIPT_BYTES,
        "POLICY_ROOT_PUBLIC_PEM": frozen.POLICY_ROOT_PUBLIC_PEM,
        "LEDGER_PUBLIC_PEM": frozen.LEDGER_PUBLIC_PEM,
        "SIGNATURE_MESSAGE_BYTES": frozen.SIGNATURE_MESSAGE_BYTES,
    }
    assert {
        name: (len(payload), hashlib.sha256(payload).hexdigest())
        for name, payload in artifacts.items()
    } == frozen.EXPECTED_MEASUREMENTS


def test_embedded_operation_parses_and_rebinds_its_id() -> None:
    operation = client.parse_operation_bytes(frozen.OPERATION_BYTES)
    assert operation["operation_id"] == frozen.EXPECTED_OPERATION_ID
    assert client.canonical_json_bytes(operation) == frozen.OPERATION_BYTES


def test_signature_message_reproduces_the_frozen_authority_message() -> None:
    assert (
        client.signature_message(frozen.OPERATION_BYTES)
        == frozen.SIGNATURE_MESSAGE_BYTES
    )


def test_build_operation_reproduces_the_embedded_bytes() -> None:
    operation = client.parse_operation_bytes(frozen.OPERATION_BYTES)
    authorization_bytes = client.decode_canonical_base64(
        operation["authorization_receipt_canonical_base64"],
        label="authorization receipt",
        maximum=client.MAX_AUTHORIZATION_RECEIPT_BYTES,
    )
    payload_bytes = client.operation_payload_bytes(operation)
    operation_id, request_bytes = client.build_operation(
        gate_contract_sha256=operation["gate_contract_sha256"],
        authorization_receipt_bytes=authorization_bytes,
        authority_role=operation["authority_role"],
        authority_key_id=operation["authority_key_id"],
        signature_purpose=operation["signature_purpose"],
        round_id=operation["round_id"],
        slot_id=operation["slot_id"],
        payload_bytes=payload_bytes,
    )
    assert operation_id == frozen.EXPECTED_OPERATION_ID
    assert request_bytes == frozen.OPERATION_BYTES


def test_embedded_receipt_verifies_end_to_end() -> None:
    authority_private = ed25519.Ed25519PrivateKey.from_private_bytes(AUTHORITY_SEED)
    receipt_private = ed25519.Ed25519PrivateKey.from_private_bytes(RECEIPT_KEY_SEED)
    authority_key_id = client.key_id_from_raw_public_key(_raw_public(authority_private))
    receipt_key_id = client.key_id_from_raw_public_key(_raw_public(receipt_private))
    operation = client.parse_operation_bytes(frozen.OPERATION_BYTES)
    assert authority_key_id == operation["authority_key_id"]
    verified = client.verify_receipt(
        frozen.RECEIPT_BYTES,
        frozen.OPERATION_BYTES,
        pinned_authority_verifiers={authority_key_id: authority_private.public_key()},
        signer_receipt_key_id=receipt_key_id,
        signer_receipt_verifier=receipt_private.public_key(),
        expected_signer_service_identity_sha256=(
            frozen.SIGNER_SERVICE_IDENTITY_SHA256
        ),
        expected_authenticated_requester_identity_sha256=(
            frozen.REQUESTER_IDENTITY_SHA256
        ),
    )
    assert verified["operation_id"] == frozen.EXPECTED_OPERATION_ID


def test_embedded_receipt_signatures_are_deterministically_reproducible() -> None:
    authority_private = ed25519.Ed25519PrivateKey.from_private_bytes(AUTHORITY_SEED)
    receipt_private = ed25519.Ed25519PrivateKey.from_private_bytes(RECEIPT_KEY_SEED)
    receipt = client.validate_receipt(
        client.parse_canonical_object(
            frozen.RECEIPT_BYTES,
            label="runtime signer receipt",
            maximum=client.MAX_RECEIPT_BYTES,
        )
    )
    authority_signature = authority_private.sign(frozen.SIGNATURE_MESSAGE_BYTES)
    assert (
        base64.b64encode(authority_signature).decode("ascii")
        == receipt["authority_signature"]["signature"]
    )
    projection = dict(receipt)
    projection.pop("service_authentication")
    service_signature = receipt_private.sign(
        client.signer_receipt_signature_message(projection)
    )
    assert (
        base64.b64encode(service_signature).decode("ascii")
        == receipt["service_authentication"]["signature"]
    )


def test_verify_receipt_rejects_binding_drift() -> None:
    authority_private = ed25519.Ed25519PrivateKey.from_private_bytes(AUTHORITY_SEED)
    receipt_private = ed25519.Ed25519PrivateKey.from_private_bytes(RECEIPT_KEY_SEED)
    authority_key_id = client.key_id_from_raw_public_key(_raw_public(authority_private))
    receipt_key_id = client.key_id_from_raw_public_key(_raw_public(receipt_private))
    with pytest.raises(client.ReceiptVerificationError):
        client.verify_receipt(
            frozen.RECEIPT_BYTES,
            frozen.OPERATION_BYTES,
            pinned_authority_verifiers={
                authority_key_id: authority_private.public_key()
            },
            signer_receipt_key_id=receipt_key_id,
            signer_receipt_verifier=receipt_private.public_key(),
            expected_signer_service_identity_sha256="5" * 64,
            expected_authenticated_requester_identity_sha256=(
                frozen.REQUESTER_IDENTITY_SHA256
            ),
        )


# --- local validation properties --------------------------------------------


def test_operations_must_preserve_all_engineering_nonclaims() -> None:
    operation = client.parse_operation_bytes(frozen.OPERATION_BYTES)
    for nonclaim in sorted(client.NONCLAIM_KEYS):
        tampered = dict(operation)
        tampered[nonclaim] = True
        with pytest.raises(client.SignerProtocolError):
            client.validate_operation(tampered)


def test_tampered_operation_id_binding_is_rejected() -> None:
    operation = client.parse_operation_bytes(frozen.OPERATION_BYTES)
    tampered = dict(operation)
    tampered["operation_id"] = "0" * 64
    with pytest.raises(client.SignerProtocolError):
        client.validate_operation(tampered)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda body: b" " + body,
        lambda body: body + b"\n",
        lambda body: b"",
        lambda body: b"[]",
        lambda body: b"\xff",
    ],
)
def test_mutated_operation_bytes_are_rejected(mutation: Any) -> None:
    with pytest.raises(client.SignerProtocolError):
        client.parse_operation_bytes(mutation(frozen.OPERATION_BYTES))


def test_canonical_json_enforces_the_signer_profile() -> None:
    with pytest.raises(client.SignerProtocolError):
        client.canonical_json_bytes({"value": 1.5})
    with pytest.raises(client.SignerProtocolError):
        client.canonical_json_bytes({"value": "e\u0301"})  # NFD, non-NFC
    with pytest.raises(client.SignerProtocolError):
        client.canonical_json_bytes({"ключ": "value"})  # non-ASCII key
    nested: Any = "leaf"
    for _ in range(140):
        nested = [nested]
    with pytest.raises(client.SignerProtocolError):
        client.canonical_json_bytes(nested)


def test_request_signature_message_refuses_unsafe_shapes() -> None:
    with pytest.raises(client.SignerProtocolError):
        client.request_signature_message(
            method="POST",
            path="/v1/signatures?x=1",
            signer_service_identity_sha256="4" * 64,
            operation_id=_operation_id(),
            body=b"{}",
            requester_key_id="sha256:" + "a" * 64,
        )
    with pytest.raises(client.SignerProtocolError):
        client.request_signature_message(
            method="POST",
            path=client.SIGNATURE_PATH,
            signer_service_identity_sha256="4" * 64,
            operation_id=_operation_id(),
            body=b"",
            requester_key_id="sha256:" + "a" * 64,
        )
    with pytest.raises(client.SignerProtocolError):
        client.request_signature_message(
            method="GET",
            path=client.SIGNATURE_PATH,
            signer_service_identity_sha256="4" * 64,
            operation_id=_operation_id(),
            body=b"{}",
            requester_key_id="sha256:" + "a" * 64,
        )


# --- HTTP surface -----------------------------------------------------------


def _response(
    status: int,
    body: bytes,
    *,
    marker: str | None = None,
) -> client.HttpResponse:
    headers = [
        ("content-type", "application/json"),
        ("content-length", str(len(body))),
        ("cache-control", "no-store"),
    ]
    if marker is not None:
        headers.append(("x-evoom-signer-result", marker))
    return client.HttpResponse(status=status, headers=tuple(headers), body=body)


def _error_bytes(code: str) -> bytes:
    return client.canonical_json_bytes({"error": code})


def _transport_returning(response: client.HttpResponse) -> Any:
    calls: list[tuple[str, str, dict[str, str], bytes | None]] = []

    def _send(
        method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> client.HttpResponse:
        calls.append((method, url, headers, body))
        return response

    _send.calls = calls  # type: ignore[attr-defined]
    return _send


def _post(transport: Any) -> client.SignerOutcome:
    return client.post_signature(
        frozen.OPERATION_BYTES,
        base_url=BASE_URL,
        signer_service_identity_sha256=frozen.SIGNER_SERVICE_IDENTITY_SHA256,
        requester_key_id=_post_authentication()["requester_key_id"],
        sign=_requester_private_key().sign,
        transport=transport,
    )


def test_post_created_and_replayed_are_classified() -> None:
    created = _post(
        _transport_returning(_response(201, frozen.RECEIPT_BYTES, marker="created"))
    )
    assert created.created is True
    assert created.receipt_bytes == frozen.RECEIPT_BYTES
    replayed = _post(
        _transport_returning(_response(200, frozen.RECEIPT_BYTES, marker="replayed"))
    )
    assert replayed.created is False


def test_post_sends_exact_headers_and_body() -> None:
    transport = _transport_returning(
        _response(201, frozen.RECEIPT_BYTES, marker="created")
    )
    _post(transport)
    ((method, url, headers, body),) = transport.calls
    assert method == "POST"
    assert url == BASE_URL + client.SIGNATURE_PATH
    assert body == frozen.OPERATION_BYTES
    assert headers["Idempotency-Key"] == frozen.EXPECTED_OPERATION_ID
    assert headers["Accept"] == "application/json"
    assert headers["Content-Type"] == "application/json"
    assert headers["Content-Length"] == str(len(frozen.OPERATION_BYTES))
    assert client.REQUESTER_KEY_ID_HEADER in headers
    assert client.REQUESTER_SIGNATURE_HEADER in headers


def test_post_quarantine_is_terminal_not_ambiguous() -> None:
    with pytest.raises(client.SignerUnresolvedError):
        _post(
            _transport_returning(
                _response(409, _error_bytes("operation_unresolved"))
            )
        )


def test_post_conflict_and_rejections_carry_their_codes() -> None:
    with pytest.raises(client.SignerRejectedError) as conflict:
        _post(_transport_returning(_response(409, _error_bytes("operation_conflict"))))
    assert conflict.value.code == "operation_conflict"
    for status, code in (
        (400, "invalid_request"),
        (401, "authentication_failed"),
        (403, "authorization_rejected"),
    ):
        with pytest.raises(client.SignerRejectedError) as rejected:
            _post(_transport_returning(_response(status, _error_bytes(code))))
        assert rejected.value.code == code


def test_post_unavailability_is_ambiguous() -> None:
    with pytest.raises(client.SignerAmbiguousOutcome):
        _post(
            _transport_returning(_response(503, _error_bytes("service_unavailable")))
        )

    def _broken(
        method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> client.HttpResponse:
        raise OSError("connection reset")

    with pytest.raises(client.SignerAmbiguousOutcome):
        _post(_broken)


def test_post_rejects_an_inconsistent_result_marker() -> None:
    with pytest.raises(client.SignerProtocolError):
        _post(
            _transport_returning(
                _response(201, frozen.RECEIPT_BYTES, marker="replayed")
            )
        )


def _get(transport: Any) -> bytes | None:
    return client.get_receipt(
        frozen.EXPECTED_OPERATION_ID,
        base_url=BASE_URL,
        signer_service_identity_sha256=frozen.SIGNER_SERVICE_IDENTITY_SHA256,
        requester_key_id=_post_authentication()["requester_key_id"],
        sign=_requester_private_key().sign,
        transport=transport,
    )


def test_get_found_not_found_and_unresolved_are_classified() -> None:
    found = _get(
        _transport_returning(_response(200, frozen.RECEIPT_BYTES, marker="found"))
    )
    assert found == frozen.RECEIPT_BYTES
    not_found_body = client.canonical_json_bytes(
        {"error": "operation_not_found", "operation_id": frozen.EXPECTED_OPERATION_ID}
    )
    absent = _get(
        _transport_returning(_response(404, not_found_body, marker="not-found"))
    )
    assert absent is None
    with pytest.raises(client.SignerUnresolvedError):
        _get(
            _transport_returning(
                _response(409, _error_bytes("operation_unresolved"))
            )
        )


def test_get_sends_an_empty_body_and_the_lookup_path() -> None:
    transport = _transport_returning(
        _response(200, frozen.RECEIPT_BYTES, marker="found")
    )
    _get(transport)
    ((method, url, headers, body),) = transport.calls
    assert method == "GET"
    assert url == (
        BASE_URL + client.OPERATION_LOOKUP_PATH_PREFIX + frozen.EXPECTED_OPERATION_ID
    )
    assert body is None


def test_base_url_validation_refuses_unsafe_origins() -> None:
    for bad in (
        "http://signer.example",
        "https://signer.example/api",
        "https://signer.example?x=1",
        "https://user:pw@signer.example",
    ):
        with pytest.raises(client.SignerProtocolError):
            client.validate_base_url(bad)
    assert client.validate_base_url(BASE_URL) == BASE_URL
    assert client.validate_base_url(BASE_URL + "/") == BASE_URL
