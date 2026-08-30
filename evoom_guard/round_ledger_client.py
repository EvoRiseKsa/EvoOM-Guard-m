# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Thin client for the frozen EvoOM Guard field-ledger v1 wire contract.

This module speaks the byte-exact protocol served by the reference ledger
pilot (``evoom-guard-ledger-pilot``) and consumed by the private evaluation
harness.  It is dormant by default: nothing in the gate imports it, and it
performs no network traffic unless a caller explicitly drives it.

Byte stability is the whole contract.  Canonical JSON, the TLV signature
framing, the request key grammar, and the exact request bytes retained for
replay must never drift — a single byte of drift turns a safe idempotent
retry into a ``409 idempotency_mismatch`` or breaks a receipt signature.
The golden vectors pinned in ``tests/test_round_ledger_client.py`` hold this
module to the pilot's frozen bytes.

Ed25519 verification is deliberately not implemented here (it is not in the
Python standard library).  Callers inject a verifier object exposing
``verify(signature: bytes, message: bytes) -> None`` that raises on mismatch
— a ``cryptography`` ``Ed25519PublicKey`` satisfies this directly.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import http.client
import json
import re
import ssl
import urllib.parse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

REQUEST_SCHEMA = "evoom-guard/field-ledger-transition-request/v1"
RECEIPT_SCHEMA = "evoom-guard/field-ledger-transition-receipt/v1"
SIGNATURE_DOMAIN = RECEIPT_SCHEMA
SIGNATURE_PURPOSE = "attempt-state-transition"
SIGNATURE_MAGIC = b"EVOGUARD_FIELD_LEDGER_RECEIPT_SIGNATURE_V1\x00"
HEAD_ASSERTION_SCHEMA = "evoom-guard/reference-ledger-head-assertion/v1"
HEAD_SIGNATURE_DOMAIN = HEAD_ASSERTION_SCHEMA
HEAD_SIGNATURE_PURPOSE = "assert-observed-ledger-head"
HEAD_SIGNATURE_MAGIC = b"EVOGUARD_REFERENCE_LEDGER_HEAD_ASSERTION_SIGNATURE_V1\x00"
REFERENCE_PROOF_LEVEL = "reference-pilot"
HEAD_ASSERTION_LIMITATIONS = (
    "This signed head is not independently witnessed.",
    "This signed head does not prove rollback resistance or non-forking operation.",
    "This observed head can be stale or replayed and carries no freshness proof.",
    "Receipt absence is not a signed proof of non-membership.",
)

MAX_REQUEST_BYTES = 64 * 1024
MAX_RECEIPT_BYTES = 16 * 1024
MAX_HEAD_ASSERTION_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024

RESULT_HEADER = "x-evoom-ledger-result"
PROOF_LEVEL_HEADER = "x-evoom-ledger-proof-level"

IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
KEY_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:[0-2][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)

STATES = (
    "RESERVED",
    "RUNNING",
    "OBSERVED",
    "BASELINE_RUNNING",
    "BASELINE_OBSERVED",
    "BASELINE_FAILED",
    "FINALIZING",
    "FINALIZED",
    "VERIFIED",
    "INCLUDED",
)
NEXT_STATES: dict[str, frozenset[str]] = {
    "RESERVED": frozenset({"RUNNING"}),
    "RUNNING": frozenset({"OBSERVED"}),
    "OBSERVED": frozenset({"BASELINE_RUNNING"}),
    "BASELINE_RUNNING": frozenset({"BASELINE_OBSERVED", "BASELINE_FAILED"}),
    "BASELINE_OBSERVED": frozenset({"FINALIZING"}),
    "BASELINE_FAILED": frozenset(),
    "FINALIZING": frozenset({"FINALIZED"}),
    "FINALIZED": frozenset({"VERIFIED"}),
    "VERIFIED": frozenset({"INCLUDED"}),
    "INCLUDED": frozenset(),
}

CONFLICT_CODES = frozenset(
    {"idempotency_mismatch", "signer_mismatch", "cas_conflict", "slot_conflict"}
)

# Ed25519 SubjectPublicKeyInfo DER prefix (RFC 8410): the 12 fixed bytes that
# precede the 32 raw public-key bytes.
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")

REQUEST_KEYS = frozenset(
    {
        "schema_version",
        "signature_domain",
        "signature_purpose",
        "ledger_id",
        "slot_id",
        "previous_state",
        "state",
        "input_sha256",
        "idempotency_key",
        "compare_and_swap",
    }
)
RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "signature_domain",
        "signature_purpose",
        "ledger_id",
        "sequence",
        "slot_id",
        "previous_state",
        "state",
        "input_sha256",
        "previous_receipt_sha256",
        "idempotency_key",
        "compare_and_swap",
        "request_sha256",
        "issued_at",
        "authentication",
    }
)
# The request fields a receipt must copy verbatim (verify_receipt checks all).
REQUEST_COPIED_KEYS = (
    "signature_domain",
    "signature_purpose",
    "ledger_id",
    "slot_id",
    "previous_state",
    "state",
    "input_sha256",
    "idempotency_key",
    "compare_and_swap",
)
HEAD_ASSERTION_KEYS = frozenset(
    {
        "schema_version",
        "signature_domain",
        "signature_purpose",
        "proof_level",
        "ledger_id",
        "head",
        "limitations",
        "authentication",
    }
)


class LedgerClientError(ValueError):
    """Base class for every failure raised by this client."""


class LedgerProtocolError(LedgerClientError):
    """Bytes (local or served) are outside the frozen v1 contract."""


class LedgerRejectedError(LedgerClientError):
    """The service definitively rejected the request (HTTP 400)."""


class LedgerConflictError(LedgerClientError):
    """The service answered 409; ``code`` carries the conflict class."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


class LedgerAmbiguousOutcome(LedgerClientError):
    """The commit outcome is unknown.

    The only safe continuations are re-POSTing the byte-identical retained
    request, or recovering via the by-idempotency lookup.  Never rebuild the
    request bytes and never advance CAS after this error.
    """


class ReceiptVerificationError(LedgerClientError):
    """A receipt or head assertion failed a binding or signature check."""


class Ed25519Verifier(Protocol):
    """Duck-typed Ed25519 verifier (``cryptography`` public keys conform)."""

    def verify(self, signature: bytes, message: bytes) -> None: ...


# --- canonical JSON (must match the pilot's protocol byte-for-byte) ---------


def _validate_json_value(value: Any, *, depth: int = 0) -> None:
    if depth > 32:
        raise LedgerProtocolError("JSON nesting exceeds the protocol limit")
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if not -(2**63) <= value <= 2**63 - 1:
            raise LedgerProtocolError("JSON integer is outside the 64-bit range")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise LedgerProtocolError("JSON object keys must be text")
        for item in value.values():
            _validate_json_value(item, depth=depth + 1)
        return
    raise LedgerProtocolError("floats and non-JSON values are forbidden")


def canonical_json_bytes(value: Any) -> bytes:
    """Match the ledger service's canonical serialization byte-for-byte."""
    _validate_json_value(value)
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (RecursionError, UnicodeEncodeError) as exc:
        raise LedgerProtocolError(
            "JSON cannot be represented as canonical UTF-8"
        ) from exc


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def key_id_from_raw_public_key(raw_public_key: bytes) -> str:
    """Derive the ``sha256:<hex>`` key ID from 32 raw Ed25519 public bytes."""
    if not isinstance(raw_public_key, bytes) or len(raw_public_key) != 32:
        raise LedgerProtocolError("raw Ed25519 public key must be exactly 32 bytes")
    return "sha256:" + sha256_hex(_ED25519_SPKI_PREFIX + raw_public_key)


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LedgerProtocolError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise LedgerProtocolError(f"non-finite JSON number is forbidden: {value}")


def _parse_integer_literal(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > 19:
        raise LedgerProtocolError("JSON integer literal exceeds the protocol limit")
    try:
        return int(value)
    except ValueError as exc:
        raise LedgerProtocolError("JSON integer literal is invalid") from exc


def _parse_canonical_document(
    body: Any, *, label: str, maximum_bytes: int
) -> dict[str, Any]:
    if not isinstance(body, bytes) or not body or len(body) > maximum_bytes:
        raise LedgerProtocolError(f"{label} is empty, oversized, or not bytes")
    try:
        document = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
            parse_int=_parse_integer_literal,
        )
    except LedgerProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise LedgerProtocolError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise LedgerProtocolError(f"{label} must be a JSON object")
    return document


# --- field grammar ----------------------------------------------------------


def _identifier(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise LedgerProtocolError(f"{label} is not a valid identifier")
    return value


def _sha(value: Any, *, label: str, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise LedgerProtocolError(f"{label} must be one lowercase SHA-256 value")
    return value


def _integer(value: Any, *, label: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise LedgerProtocolError(f"{label} is outside the allowed integer range")
    return value


def _state(value: Any, *, label: str, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or value not in STATES:
        raise LedgerProtocolError(f"{label} is not a supported lifecycle state")
    return value


def validate_transition(previous_state: Any, state: Any) -> tuple[str | None, str]:
    previous = _state(previous_state, label="previous_state", nullable=True)
    current = _state(state, label="state")
    assert isinstance(current, str)
    if previous is None:
        if current != "RESERVED":
            raise LedgerProtocolError("an initial slot transition must enter RESERVED")
    elif current not in NEXT_STATES[previous]:
        raise LedgerProtocolError(
            f"invalid lifecycle transition: {previous} -> {current}"
        )
    return previous, current


def validate_cas(value: Any) -> tuple[int, str | None]:
    if not isinstance(value, dict) or set(value) != {
        "expected_sequence",
        "expected_previous_receipt_sha256",
    }:
        raise LedgerProtocolError("compare_and_swap schema is invalid")
    sequence = _integer(
        value["expected_sequence"],
        label="compare_and_swap.expected_sequence",
        minimum=0,
        maximum=2**63 - 2,
    )
    previous = _sha(
        value["expected_previous_receipt_sha256"],
        label="compare_and_swap.expected_previous_receipt_sha256",
        nullable=True,
    )
    if (sequence == 0) != (previous is None):
        raise LedgerProtocolError(
            "CAS sequence zero and a null previous digest must coincide"
        )
    return sequence, previous


# --- request ----------------------------------------------------------------


def validate_request(request: Any) -> dict[str, Any]:
    if not isinstance(request, dict) or set(request) != REQUEST_KEYS:
        raise LedgerProtocolError("ledger request schema is invalid")
    if (
        request.get("schema_version") != REQUEST_SCHEMA
        or request.get("signature_domain") != SIGNATURE_DOMAIN
        or request.get("signature_purpose") != SIGNATURE_PURPOSE
    ):
        raise LedgerProtocolError("ledger request version/domain/purpose is invalid")
    _identifier(request["ledger_id"], label="ledger_id")
    _sha(request["slot_id"], label="slot_id")
    validate_transition(request["previous_state"], request["state"])
    _sha(request["input_sha256"], label="input_sha256")
    _sha(request["idempotency_key"], label="idempotency_key")
    validate_cas(request["compare_and_swap"])
    canonical_json_bytes(request)
    return request


def parse_canonical_request(body: bytes) -> dict[str, Any]:
    request = _parse_canonical_document(
        body, label="request", maximum_bytes=MAX_REQUEST_BYTES
    )
    validate_request(request)
    if body != canonical_json_bytes(request):
        raise LedgerProtocolError("request is not exact canonical JSON")
    return request


def build_transition_request(
    *,
    ledger_id: str,
    slot_id: str,
    previous_state: str | None,
    state: str,
    input_sha256: str,
    idempotency_key: str,
    expected_sequence: int,
    expected_previous_receipt_sha256: str | None,
) -> bytes:
    """Build the exact canonical request bytes for one transition.

    Retain the returned bytes verbatim: they are the only safe input to a
    retry (`append_exact_request`) or a recovery lookup after an ambiguous
    outcome.
    """
    request = {
        "schema_version": REQUEST_SCHEMA,
        "signature_domain": SIGNATURE_DOMAIN,
        "signature_purpose": SIGNATURE_PURPOSE,
        "ledger_id": ledger_id,
        "slot_id": slot_id,
        "previous_state": previous_state,
        "state": state,
        "input_sha256": input_sha256,
        "idempotency_key": idempotency_key,
        "compare_and_swap": {
            "expected_sequence": expected_sequence,
            "expected_previous_receipt_sha256": expected_previous_receipt_sha256,
        },
    }
    validate_request(request)
    body = canonical_json_bytes(request)
    if len(body) > MAX_REQUEST_BYTES:
        raise LedgerProtocolError("ledger request is oversized")
    return body


# --- receipt ----------------------------------------------------------------


def _validate_authentication(value: Any, *, label: str) -> bytes:
    if not isinstance(value, dict) or set(value) != {
        "algorithm",
        "key_id",
        "signature_encoding",
        "signature",
    }:
        raise LedgerProtocolError(f"{label} schema is invalid")
    if (
        value.get("algorithm") != "Ed25519"
        or value.get("signature_encoding") != "base64"
        or not isinstance(value.get("key_id"), str)
        or not KEY_ID_RE.fullmatch(value["key_id"])
    ):
        raise LedgerProtocolError(f"{label} metadata is invalid")
    encoded = value.get("signature")
    if not isinstance(encoded, str):
        raise LedgerProtocolError(f"{label} signature is not text")
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise LedgerProtocolError(f"{label} signature is not canonical base64") from exc
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != encoded:
        raise LedgerProtocolError(f"{label} signature is not one Ed25519 value")
    return signature


def validate_receipt(receipt: Any) -> dict[str, Any]:
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_KEYS:
        raise LedgerProtocolError("ledger receipt schema is invalid")
    if (
        receipt.get("schema_version") != RECEIPT_SCHEMA
        or receipt.get("signature_domain") != SIGNATURE_DOMAIN
        or receipt.get("signature_purpose") != SIGNATURE_PURPOSE
    ):
        raise LedgerProtocolError("ledger receipt version/domain/purpose is invalid")
    _identifier(receipt["ledger_id"], label="ledger_id")
    sequence = _integer(
        receipt["sequence"], label="sequence", minimum=1, maximum=2**63 - 1
    )
    _sha(receipt["slot_id"], label="slot_id")
    validate_transition(receipt["previous_state"], receipt["state"])
    _sha(receipt["input_sha256"], label="input_sha256")
    previous = _sha(
        receipt["previous_receipt_sha256"],
        label="previous_receipt_sha256",
        nullable=True,
    )
    _sha(receipt["idempotency_key"], label="idempotency_key")
    expected_sequence, expected_previous = validate_cas(receipt["compare_and_swap"])
    if sequence != expected_sequence + 1:
        raise LedgerProtocolError(
            "receipt sequence does not satisfy its CAS precondition"
        )
    if previous != expected_previous:
        raise LedgerProtocolError(
            "receipt previous digest does not satisfy its CAS precondition"
        )
    _sha(receipt["request_sha256"], label="request_sha256")
    issued_at = receipt["issued_at"]
    if not isinstance(issued_at, str) or not TIMESTAMP_RE.fullmatch(issued_at):
        raise LedgerProtocolError("issued_at must be canonical UTC seconds")
    try:
        datetime.strptime(issued_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise LedgerProtocolError("issued_at is not a real UTC calendar instant") from exc
    _validate_authentication(receipt["authentication"], label="ledger receipt")
    canonical_json_bytes(receipt)
    return receipt


def parse_canonical_receipt(body: bytes) -> dict[str, Any]:
    receipt = _parse_canonical_document(
        body, label="receipt", maximum_bytes=MAX_RECEIPT_BYTES
    )
    validate_receipt(receipt)
    if body != canonical_json_bytes(receipt):
        raise LedgerProtocolError("receipt is not exact canonical JSON")
    return receipt


def receipt_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in receipt.items() if key != "authentication"}


def _framed(magic: bytes, fields: Sequence[tuple[bytes, bytes]]) -> bytes:
    message = bytearray(magic)
    for label, value in fields:
        message.extend(len(label).to_bytes(2, "big"))
        message.extend(label)
        message.extend(len(value).to_bytes(8, "big"))
        message.extend(value)
    return bytes(message)


def ledger_signature_message(receipt_without_authentication: Any) -> bytes:
    """Frame a receipt projection exactly as the signer does."""
    projection = receipt_without_authentication
    if not isinstance(projection, dict):
        raise LedgerProtocolError("receipt signature projection must be an object")
    if projection.get("signature_domain") != SIGNATURE_DOMAIN:
        raise LedgerProtocolError("receipt signature domain is invalid")
    if projection.get("signature_purpose") != SIGNATURE_PURPOSE:
        raise LedgerProtocolError("receipt signature purpose is invalid")
    payload = canonical_json_bytes(projection)
    return _framed(
        SIGNATURE_MAGIC,
        (
            (b"domain", SIGNATURE_DOMAIN.encode("ascii")),
            (b"purpose", SIGNATURE_PURPOSE.encode("ascii")),
            (b"canonical_json", payload),
        ),
    )


def verify_receipt(
    receipt_bytes: bytes,
    request_bytes: bytes,
    *,
    pinned_key_id: str,
    verifier: Ed25519Verifier,
) -> dict[str, Any]:
    """Verify a served receipt against the exact retained request bytes."""
    if not isinstance(pinned_key_id, str) or not KEY_ID_RE.fullmatch(pinned_key_id):
        raise ReceiptVerificationError("pinned key ID is invalid")
    request = parse_canonical_request(request_bytes)
    receipt = parse_canonical_receipt(receipt_bytes)
    for key in REQUEST_COPIED_KEYS:
        if receipt[key] != request[key]:
            raise ReceiptVerificationError(
                f"receipt field {key} does not match the retained request"
            )
    if receipt["request_sha256"] != sha256_hex(request_bytes):
        raise ReceiptVerificationError(
            "receipt request digest does not match the retained request bytes"
        )
    authentication = receipt["authentication"]
    if authentication["key_id"] != pinned_key_id:
        raise ReceiptVerificationError("receipt signer key is not the pinned key")
    signature = _validate_authentication(authentication, label="ledger receipt")
    message = ledger_signature_message(receipt_projection(receipt))
    try:
        verifier.verify(signature, message)
    except Exception as exc:
        raise ReceiptVerificationError("ledger receipt signature is invalid") from exc
    return receipt


# --- signed observed-head assertion -----------------------------------------


def validate_head_assertion(assertion: Any) -> dict[str, Any]:
    if not isinstance(assertion, dict) or set(assertion) != HEAD_ASSERTION_KEYS:
        raise LedgerProtocolError("head assertion schema is invalid")
    if (
        assertion.get("schema_version") != HEAD_ASSERTION_SCHEMA
        or assertion.get("signature_domain") != HEAD_SIGNATURE_DOMAIN
        or assertion.get("signature_purpose") != HEAD_SIGNATURE_PURPOSE
        or assertion.get("proof_level") != REFERENCE_PROOF_LEVEL
    ):
        raise LedgerProtocolError("head assertion version/domain/purpose is invalid")
    _identifier(assertion["ledger_id"], label="ledger_id")
    head = assertion["head"]
    if not isinstance(head, dict) or set(head) != {"receipt_sha256", "sequence"}:
        raise LedgerProtocolError("head assertion head schema is invalid")
    _sha(head["receipt_sha256"], label="head.receipt_sha256")
    _integer(head["sequence"], label="head.sequence", minimum=1, maximum=2**63 - 1)
    limitations = assertion["limitations"]
    if not isinstance(limitations, list) or limitations != list(
        HEAD_ASSERTION_LIMITATIONS
    ):
        raise LedgerProtocolError("head assertion limitations are not verbatim")
    _validate_authentication(assertion["authentication"], label="head assertion")
    canonical_json_bytes(assertion)
    return assertion


def head_signature_message(assertion_without_authentication: Any) -> bytes:
    projection = assertion_without_authentication
    if not isinstance(projection, dict):
        raise LedgerProtocolError("head signature projection must be an object")
    if projection.get("signature_domain") != HEAD_SIGNATURE_DOMAIN:
        raise LedgerProtocolError("head signature domain is invalid")
    if projection.get("signature_purpose") != HEAD_SIGNATURE_PURPOSE:
        raise LedgerProtocolError("head signature purpose is invalid")
    payload = canonical_json_bytes(projection)
    return _framed(
        HEAD_SIGNATURE_MAGIC,
        (
            (b"domain", HEAD_SIGNATURE_DOMAIN.encode("ascii")),
            (b"purpose", HEAD_SIGNATURE_PURPOSE.encode("ascii")),
            (b"canonical_json", payload),
        ),
    )


def verify_head_assertion(
    assertion_bytes: bytes,
    *,
    ledger_id: str,
    pinned_key_id: str,
    verifier: Ed25519Verifier,
) -> dict[str, Any]:
    """Verify a signed observed-head assertion.

    The result is an authenticated diagnostic and initial-CAS hint only: it
    can be stale or replayed, carries no freshness proof, and never proves
    non-forking operation.
    """
    if not isinstance(pinned_key_id, str) or not KEY_ID_RE.fullmatch(pinned_key_id):
        raise ReceiptVerificationError("pinned key ID is invalid")
    assertion = _parse_canonical_document(
        assertion_bytes, label="head assertion", maximum_bytes=MAX_HEAD_ASSERTION_BYTES
    )
    validate_head_assertion(assertion)
    if assertion_bytes != canonical_json_bytes(assertion):
        raise LedgerProtocolError("head assertion is not exact canonical JSON")
    if assertion["ledger_id"] != ledger_id:
        raise ReceiptVerificationError(
            "head assertion names a different ledger than requested"
        )
    authentication = assertion["authentication"]
    if authentication["key_id"] != pinned_key_id:
        raise ReceiptVerificationError("head assertion signer is not the pinned key")
    signature = _validate_authentication(authentication, label="head assertion")
    projection = {
        key: value for key, value in assertion.items() if key != "authentication"
    }
    try:
        verifier.verify(signature, head_signature_message(projection))
    except Exception as exc:
        raise ReceiptVerificationError("head assertion signature is invalid") from exc
    return assertion


# --- HTTP surface -----------------------------------------------------------

Transport = Any  # Callable[[str, str, dict[str, str], bytes | None], HttpResponse]


@dataclass(frozen=True)
class HttpResponse:
    """One complete HTTP exchange result as seen by this client."""

    status: int
    headers: tuple[tuple[str, str], ...]  # lowercased names, order preserved
    body: bytes


@dataclass(frozen=True)
class AppendOutcome:
    """A definitively committed transition."""

    created: bool  # True on 201 created, False on 200 replayed
    receipt_bytes: bytes


def validate_endpoint(endpoint: str) -> tuple[str, str]:
    """Validate the POST endpoint and derive (origin, recovery_root_path)."""
    parsed = urllib.parse.urlsplit(endpoint)
    try:
        port = parsed.port
    except ValueError as exc:
        raise LedgerProtocolError("ledger endpoint port is invalid") from exc
    if port == 0:
        raise LedgerProtocolError("ledger endpoint port is invalid")
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or "%" in endpoint
        or "\\" in endpoint
    ):
        raise LedgerProtocolError("ledger endpoint must be a plain https URL")
    path = parsed.path
    if "//" in path or any(part in {".", ".."} for part in path.split("/")):
        raise LedgerProtocolError("ledger endpoint path contains unsafe segments")
    if path not in ("/transitions", "/v1/transitions"):
        raise LedgerProtocolError(
            "ledger endpoint path must be /transitions or /v1/transitions"
        )
    origin = f"https://{parsed.netloc}"
    return origin, "/v1"


def default_transport(*, timeout: float = 30.0) -> Transport:
    """A stdlib https transport: TLS verified, no redirects followed."""

    def _send(
        method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> HttpResponse:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise LedgerProtocolError("transport requires an https URL")
        context = ssl.create_default_context()
        connection = http.client.HTTPSConnection(
            parsed.hostname,
            parsed.port or 443,
            timeout=timeout,
            context=context,
        )
        try:
            target = parsed.path or "/"
            connection.request(method, target, body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read(MAX_RESPONSE_BYTES + 1)
            if len(payload) > MAX_RESPONSE_BYTES:
                raise LedgerProtocolError("ledger response is oversized")
            header_items = tuple(
                (name.lower(), value) for name, value in response.getheaders()
            )
            return HttpResponse(
                status=response.status, headers=header_items, body=payload
            )
        finally:
            connection.close()

    return _send


def _header_map(response: HttpResponse) -> dict[str, str]:
    seen: dict[str, str] = {}
    for name, value in response.headers:
        if name in seen:
            raise LedgerProtocolError(f"duplicate response header: {name}")
        seen[name] = value
    return seen


def _require_common_headers(headers: Mapping[str, str], body: bytes) -> None:
    if headers.get("content-type") != "application/json":
        raise LedgerProtocolError("ledger response content-type is invalid")
    if headers.get("cache-control") != "no-store":
        raise LedgerProtocolError("ledger response cache-control is invalid")
    if headers.get(PROOF_LEVEL_HEADER) != REFERENCE_PROOF_LEVEL:
        raise LedgerProtocolError("ledger response proof-level header is invalid")
    length = headers.get("content-length")
    if length is not None and length != str(len(body)):
        raise LedgerProtocolError("ledger response content-length is inconsistent")


def _error_body(body: bytes) -> tuple[str, str]:
    document = _parse_canonical_document(
        body, label="error body", maximum_bytes=MAX_RESPONSE_BYTES
    )
    if set(document) != {"error", "proof_level"} or document.get(
        "proof_level"
    ) != REFERENCE_PROOF_LEVEL:
        raise LedgerProtocolError("ledger error body shape is invalid")
    error = document["error"]
    if not isinstance(error, dict) or set(error) != {"code", "message"}:
        raise LedgerProtocolError("ledger error body shape is invalid")
    code, message = error["code"], error["message"]
    if not isinstance(code, str) or not isinstance(message, str):
        raise LedgerProtocolError("ledger error body shape is invalid")
    if body != canonical_json_bytes(document):
        raise LedgerProtocolError("ledger error body is not canonical")
    return code, message


def _is_definite_rejection(status: int) -> bool:
    """4xx statuses are definite non-commits, except the retryable trio."""
    return 400 <= status <= 499 and status not in (408, 425, 429)


def _rejection_detail(response: HttpResponse) -> str:
    """Best-effort code/message from a definite rejection body."""
    try:
        code, message = _error_body(response.body)
    except LedgerClientError:
        return f"http {response.status}"
    return f"{code}: {message}"


def append_exact_request(
    request_bytes: bytes,
    *,
    endpoint: str,
    transport: Transport,
    pinned_key_id: str,
    verifier: Ed25519Verifier,
) -> AppendOutcome:
    """POST the exact retained request bytes; classify the outcome.

    A returned :class:`AppendOutcome` carries receipt bytes that passed full
    verification against the retained request — every request-copied field,
    the request digest, the pinned signer key, and the Ed25519 signature.

    Raises :class:`LedgerAmbiguousOutcome` whenever the commit state is
    unknown — the caller retries with the same bytes or recovers via
    :func:`lookup_receipt`; it must never rebuild the request.
    """
    request = parse_canonical_request(request_bytes)
    validate_endpoint(endpoint)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Idempotency-Key": str(request["idempotency_key"]),
        "Content-Length": str(len(request_bytes)),
    }
    try:
        response: HttpResponse = transport("POST", endpoint, headers, request_bytes)
    except Exception as exc:
        # Any transport-level failure — including this module's own
        # oversized/mangled-response errors — happens after the request may
        # have been delivered, so the commit state is unknown.
        raise LedgerAmbiguousOutcome(f"transport failure: {exc}") from exc
    status = response.status
    if status in (200, 201):
        header_map = _header_map(response)
        _require_common_headers(header_map, response.body)
        marker = header_map.get(RESULT_HEADER)
        expected_marker = "created" if status == 201 else "replayed"
        if marker != expected_marker:
            raise LedgerProtocolError("ledger result marker is inconsistent")
        verify_receipt(
            response.body,
            request_bytes,
            pinned_key_id=pinned_key_id,
            verifier=verifier,
        )
        return AppendOutcome(created=(status == 201), receipt_bytes=response.body)
    if status == 409:
        header_map = _header_map(response)
        _require_common_headers(header_map, response.body)
        if RESULT_HEADER in header_map:
            raise LedgerProtocolError(
                "conflict responses never carry a result marker"
            )
        code, message = _error_body(response.body)
        if code not in CONFLICT_CODES:
            raise LedgerProtocolError(f"unknown ledger conflict code: {code}")
        raise LedgerConflictError(code, message)
    if _is_definite_rejection(status):
        # Definite non-commit (400 from the service, or a 403/404/413/...
        # from the service or an intermediary): surface it, never retry-loop.
        raise LedgerRejectedError(_rejection_detail(response))
    # 1xx/3xx/408/425/429/5xx leave the commit state unknown.
    raise LedgerAmbiguousOutcome(f"unexpected ledger response status {status}")


def _recovery_get(
    path: str,
    *,
    endpoint: str,
    transport: Transport,
) -> HttpResponse:
    origin, root = validate_endpoint(endpoint)
    url = f"{origin}{root}{path}"
    headers = {"Accept": "application/json", "Cache-Control": "no-cache"}
    try:
        response: HttpResponse = transport("GET", url, headers, None)
    except Exception as exc:
        raise LedgerAmbiguousOutcome(f"transport failure: {exc}") from exc
    if response.status not in (200, 404):
        if _is_definite_rejection(response.status):
            raise LedgerRejectedError(_rejection_detail(response))
        raise LedgerAmbiguousOutcome(
            f"unexpected ledger recovery status {response.status}"
        )
    header_map = _header_map(response)
    if RESULT_HEADER in header_map or "location" in header_map:
        raise LedgerProtocolError("recovery responses never carry result markers")
    _require_common_headers(header_map, response.body)
    return response


def lookup_receipt(
    request_bytes: bytes,
    *,
    endpoint: str,
    transport: Transport,
    pinned_key_id: str,
    verifier: Ed25519Verifier,
) -> bytes | None:
    """Recover the committed receipt for the retained request bytes, if any.

    Returns the exact stored receipt bytes after full verification against
    the retained request, or ``None`` only on the service's exact
    receipt-not-found answer.  Absence is NOT proof of non-membership.
    """
    request = parse_canonical_request(request_bytes)
    ledger_id = str(request["ledger_id"])
    idempotency_key = str(request["idempotency_key"])
    response = _recovery_get(
        f"/ledgers/{ledger_id}/receipts/by-idempotency/{idempotency_key}",
        endpoint=endpoint,
        transport=transport,
    )
    if response.status == 404:
        code, message = _error_body(response.body)
        if code == "receipt_not_found" and message == "receipt not found":
            return None
        raise LedgerProtocolError(f"unexpected ledger lookup error: {code}")
    verify_receipt(
        response.body, request_bytes, pinned_key_id=pinned_key_id, verifier=verifier
    )
    return response.body


def observed_head(
    ledger_id: str,
    *,
    endpoint: str,
    transport: Transport,
    pinned_key_id: str,
    verifier: Ed25519Verifier,
) -> dict[str, Any] | None:
    """Fetch and verify the signed observed head — a stale-able hint only."""
    _identifier(ledger_id, label="ledger_id")
    response = _recovery_get(
        f"/ledgers/{ledger_id}/head", endpoint=endpoint, transport=transport
    )
    if response.status == 404:
        code, message = _error_body(response.body)
        if code == "ledger_not_found" and message == "ledger not found":
            return None
        raise LedgerProtocolError(f"unexpected ledger head error: {code}")
    return verify_head_assertion(
        response.body,
        ledger_id=ledger_id,
        pinned_key_id=pinned_key_id,
        verifier=verifier,
    )


__all__ = [
    "REQUEST_SCHEMA",
    "RECEIPT_SCHEMA",
    "SIGNATURE_DOMAIN",
    "SIGNATURE_PURPOSE",
    "SIGNATURE_MAGIC",
    "HEAD_ASSERTION_SCHEMA",
    "HEAD_SIGNATURE_DOMAIN",
    "HEAD_SIGNATURE_PURPOSE",
    "HEAD_SIGNATURE_MAGIC",
    "REFERENCE_PROOF_LEVEL",
    "HEAD_ASSERTION_LIMITATIONS",
    "MAX_REQUEST_BYTES",
    "MAX_RECEIPT_BYTES",
    "MAX_HEAD_ASSERTION_BYTES",
    "STATES",
    "NEXT_STATES",
    "CONFLICT_CODES",
    "LedgerClientError",
    "LedgerProtocolError",
    "LedgerRejectedError",
    "LedgerConflictError",
    "LedgerAmbiguousOutcome",
    "ReceiptVerificationError",
    "Ed25519Verifier",
    "HttpResponse",
    "AppendOutcome",
    "canonical_json_bytes",
    "sha256_hex",
    "key_id_from_raw_public_key",
    "validate_transition",
    "validate_cas",
    "validate_request",
    "parse_canonical_request",
    "build_transition_request",
    "validate_receipt",
    "parse_canonical_receipt",
    "receipt_projection",
    "ledger_signature_message",
    "verify_receipt",
    "validate_head_assertion",
    "head_signature_message",
    "verify_head_assertion",
    "validate_endpoint",
    "default_transport",
    "append_exact_request",
    "lookup_receipt",
    "observed_head",
]
