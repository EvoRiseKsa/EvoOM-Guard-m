# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Thin client for the frozen EvoOM Guard Remote Signer v1 wire contract.

This module speaks the byte-exact protocol served by the remote signer pilot
(``evoom-guard-signer-pilot``).  It is dormant by default: nothing in the
gate imports it, and it performs no network traffic unless a caller
explicitly drives it.

Byte stability is the whole contract: canonical JSON, canonical padded
base64, the TLV ``frame_message`` layout, the operation-id derivation, the
request-authentication message, and the cached POST body used for retries
must never drift.  The frozen vectors under
``tests/fixtures/remote-signer-request-authentication-v1/`` and the embedded
golden constants in ``tests/frozen_remote_signer_v1.py`` hold this module to
the pilot's exact bytes.

Ed25519 is deliberately not implemented here (it is not in the Python
standard library).  Callers inject a ``sign(message) -> bytes`` callable for
request authentication and verifier objects exposing
``verify(signature, message) -> None`` for receipt verification — a
``cryptography`` ``Ed25519PrivateKey.sign`` / ``Ed25519PublicKey`` pair
satisfies both seams directly.

The three engineering nonclaims (``field_claim_authorized``,
``runtime_gate_complete``, ``non_forking_proven``) are always ``False`` and
this client refuses to build or accept anything else: a signature from this
lane never asserts a field claim, a complete runtime gate, or non-forking
operation.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import http.client
import json
import re
import ssl
import unicodedata
import urllib.parse
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

OPERATION_SCHEMA = "evoom-guard/runtime-signer-operation/v1"
RECEIPT_SCHEMA = "evoom-guard/runtime-signer-receipt/v1"
DETACHED_SIGNATURE_SCHEMA = "evoom-guard/private-eval-signature-envelope/v2"
REQUEST_AUTHENTICATION_SCHEMA = "evoom-guard/signer-request-authentication/v1"

OPERATION_ID_MAGIC = b"EVOGUARD_RUNTIME_SIGNER_OPERATION_ID_V1\x00"
DETACHED_SIGNATURE_MAGIC = b"EVOGUARD_PRIVATE_EVAL_SIGNATURE_V1\x00"
SIGNER_RECEIPT_SIGNATURE_MAGIC = b"EVOGUARD_RUNTIME_SIGNER_RECEIPT_SIGNATURE_V1\x00"
SIGNER_RECEIPT_SIGNATURE_DOMAIN = RECEIPT_SCHEMA
SIGNER_RECEIPT_SIGNATURE_PURPOSE = "attest-runtime-signature-operation"
REQUEST_AUTHENTICATION_MAGIC = b"EVOGUARD_SIGNER_REQUEST_AUTHENTICATION_V1\x00"

SIGNATURE_PATH = "/v1/signatures"
OPERATION_LOOKUP_PATH_PREFIX = "/v1/signatures/operations/"
REQUESTER_KEY_ID_HEADER = "X-EvoOM-Requester-Key-Id"
REQUESTER_SIGNATURE_HEADER = "X-EvoOM-Requester-Signature"
RESULT_HEADER = "x-evoom-signer-result"

MAX_JSON_DEPTH = 128
MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
MAX_AUTHORIZATION_RECEIPT_BYTES = 1024 * 1024
MAX_OPERATION_BYTES = 24 * 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024
MAX_PATH_BYTES = 2048
MAX_RESPONSE_BYTES = 1024 * 1024

SUPPORTED_SIGNATURE_PURPOSES = frozenset(
    {
        "label",
        "execution-freeze",
        "attempt-reservation",
        "supervisor-receipt",
        "baseline-supervisor-receipt",
        "baseline-supervisor-failure",
        "result",
        "finalizer-receipt",
        "verified-result-set",
    }
)

IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
ROLE_RE = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
PURPOSE_RE = re.compile(r"^[a-z][a-z0-9._-]{2,127}$")
DOMAIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:+-]{2,191}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
KEY_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

NONCLAIM_KEYS = frozenset(
    {"field_claim_authorized", "runtime_gate_complete", "non_forking_proven"}
)
OPERATION_KEYS = frozenset(
    {
        "schema_version",
        "operation_id",
        "gate_contract_sha256",
        "authorization_receipt_sha256",
        "authorization_receipt_canonical_base64",
        "authority_role",
        "authority_key_id",
        "signature_domain",
        "signature_purpose",
        "round_id",
        "slot_id",
        "payload_sha256",
        "payload_size_bytes",
        "payload_canonical_base64",
        *NONCLAIM_KEYS,
    }
)
RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "operation_id",
        "request_sha256",
        "gate_contract_sha256",
        "authorization_receipt_sha256",
        "signer_service_identity_sha256",
        "signer_receipt_key_id",
        "authenticated_requester_identity_sha256",
        "authority_role",
        "authority_key_id",
        "signature_domain",
        "signature_purpose",
        "round_id",
        "slot_id",
        "payload_sha256",
        "payload_size_bytes",
        "signature_message_sha256",
        "authority_signature",
        "service_authentication",
        *NONCLAIM_KEYS,
    }
)
RECEIPT_PROJECTION_KEYS = RECEIPT_KEYS - {"service_authentication"}

# Ed25519 SubjectPublicKeyInfo DER prefix (RFC 8410): the 12 fixed bytes that
# precede the 32 raw public-key bytes.
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class SignerClientError(ValueError):
    """Base class for every failure raised by this client."""


class SignerProtocolError(SignerClientError):
    """Bytes (local or served) are outside the frozen v1 contract."""


class SignerRejectedError(SignerClientError):
    """The service definitively rejected the request (400/401/403/409-conflict)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class SignerUnresolvedError(SignerClientError):
    """The operation is quarantined (409 operation_unresolved).

    Permanent for the wire client: there is no reset, lease, expiry, or
    takeover path.  Only an out-of-band, separately authenticated
    reconciliation can resolve it; do not rebuild the operation under new
    identifiers to dodge the quarantine.
    """


class SignerAmbiguousOutcome(SignerClientError):
    """The signing outcome is unknown.

    The only safe continuation is retrying with the byte-identical cached
    operation body (the deterministic auth signature is then identical too),
    or the authenticated GET lookup.
    """


class ReceiptVerificationError(SignerClientError):
    """A signer receipt failed a binding or signature check."""


class Ed25519Verifier(Protocol):
    """Duck-typed Ed25519 verifier (``cryptography`` public keys conform)."""

    def verify(self, signature: bytes, message: bytes) -> None: ...


# --- canonical JSON (signer profile: NFC text, ASCII keys, depth 128) -------


def _validate_json_scalar(value: Any) -> None:
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise SignerProtocolError("non-NFC JSON text is forbidden")
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if not -(2**63) <= value <= 2**63 - 1:
            raise SignerProtocolError("integer is outside signed 64-bit range")
        return
    if isinstance(value, float):
        raise SignerProtocolError("floating-point JSON is forbidden")
    raise SignerProtocolError(f"unsupported JSON type: {type(value).__name__}")


def _validate_json_value(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise SignerProtocolError("JSON nesting exceeds the protocol limit")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise SignerProtocolError("JSON object keys must be ASCII text")
            _validate_json_value(item, depth=depth + 1)
        return
    _validate_json_scalar(value)


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize the signer contract's strict canonical JSON profile."""
    try:
        _validate_json_value(value)
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except SignerProtocolError:
        raise
    except (RecursionError, UnicodeEncodeError, ValueError) as exc:
        raise SignerProtocolError(
            "JSON cannot be represented as canonical UTF-8"
        ) from exc


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SignerProtocolError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise SignerProtocolError(f"non-finite JSON number is forbidden: {value}")


def _parse_integer_literal(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > 19:
        raise SignerProtocolError("JSON integer literal exceeds the protocol limit")
    try:
        return int(value)
    except ValueError as exc:
        raise SignerProtocolError("JSON integer literal is invalid") from exc


def parse_canonical_object(raw: bytes, *, label: str, maximum: int) -> dict[str, Any]:
    """Parse exactly one bounded byte-canonical JSON object."""
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum:
        raise SignerProtocolError(f"{label} is empty, oversized, or not bytes")
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
            parse_int=_parse_integer_literal,
        )
    except SignerProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise SignerProtocolError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise SignerProtocolError(f"{label} must be a JSON object")
    if raw != canonical_json_bytes(document):
        raise SignerProtocolError(f"{label} is not exact canonical JSON")
    return document


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def require_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise SignerProtocolError(f"{label} is not one lowercase SHA-256 value")
    return value


def require_key_id(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not KEY_ID_RE.fullmatch(value):
        raise SignerProtocolError(f"{label} is not a canonical key ID")
    return value


def _require_text(value: Any, *, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise SignerProtocolError(f"{label} is not canonical text")
    return value


def _require_size(value: Any, *, label: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise SignerProtocolError(f"{label} is outside its allowed range")
    return value


def _require_nonclaims(value: Mapping[str, Any], *, label: str) -> None:
    if any(value.get(key) is not False for key in NONCLAIM_KEYS):
        raise SignerProtocolError(f"{label} must preserve all engineering nonclaims")


def decode_canonical_base64(value: Any, *, label: str, maximum: int) -> bytes:
    encoded_limit = ((maximum + 2) // 3) * 4
    if not isinstance(value, str) or not value or len(value) > encoded_limit:
        raise SignerProtocolError(f"{label} is empty, oversized, or not text")
    try:
        raw = base64.b64decode(value.encode("ascii", "strict"), validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
        raise SignerProtocolError(f"{label} is not canonical base64") from exc
    if not raw or len(raw) > maximum or base64.b64encode(raw).decode("ascii") != value:
        raise SignerProtocolError(f"{label} is not one bounded canonical value")
    return raw


def key_id_from_raw_public_key(raw_public_key: bytes) -> str:
    """Derive the ``sha256:<hex>`` key ID from 32 raw Ed25519 public bytes."""
    if not isinstance(raw_public_key, bytes) or len(raw_public_key) != 32:
        raise SignerProtocolError("raw Ed25519 public key must be exactly 32 bytes")
    return "sha256:" + sha256_hex(_ED25519_SPKI_PREFIX + raw_public_key)


# --- framing ----------------------------------------------------------------


def frame_message(magic: bytes, fields: Iterable[tuple[str, bytes]]) -> bytes:
    """Length-prefix named byte fields using the contract's stable framing."""
    if not isinstance(magic, bytes) or not magic:
        raise SignerProtocolError("frame magic must be non-empty bytes")
    framed = bytearray(magic)
    for name, payload in fields:
        try:
            name_bytes = name.encode("ascii", "strict")
        except (AttributeError, UnicodeEncodeError) as exc:
            raise SignerProtocolError("frame field name must be ASCII text") from exc
        if not name_bytes or len(name_bytes) > 0xFFFF or not isinstance(payload, bytes):
            raise SignerProtocolError("frame field is invalid")
        framed.extend(len(name_bytes).to_bytes(2, "big"))
        framed.extend(name_bytes)
        framed.extend(len(payload).to_bytes(8, "big"))
        framed.extend(payload)
    return bytes(framed)


# --- operation --------------------------------------------------------------


def derive_operation_id(
    *,
    gate_contract_sha256: str,
    authorization_receipt_sha256: str,
    authority_role: str,
    authority_key_id: str,
    signature_domain: str,
    signature_purpose: str,
    round_id: str,
    slot_id: str,
    payload_sha256: str,
    payload_size_bytes: int,
) -> str:
    """Derive the immutable ID for one exact authorized signature operation."""
    gate_digest = require_sha256(gate_contract_sha256, label="gate_contract_sha256")
    authorization_digest = require_sha256(
        authorization_receipt_sha256, label="authorization_receipt_sha256"
    )
    role = _require_text(authority_role, label="authority_role", pattern=ROLE_RE)
    key_id = require_key_id(authority_key_id, label="authority_key_id")
    domain = _require_text(signature_domain, label="signature_domain", pattern=DOMAIN_RE)
    purpose = _require_text(
        signature_purpose, label="signature_purpose", pattern=PURPOSE_RE
    )
    if domain != DETACHED_SIGNATURE_SCHEMA:
        raise SignerProtocolError(
            "signature_domain is not the existing detached-envelope profile"
        )
    if purpose not in SUPPORTED_SIGNATURE_PURPOSES:
        raise SignerProtocolError("signature_purpose is not supported by the project")
    round_value = _require_text(round_id, label="round_id", pattern=IDENTIFIER_RE)
    slot_value = bytes.fromhex(require_sha256(slot_id, label="slot_id"))
    payload_digest = require_sha256(payload_sha256, label="payload_sha256")
    payload_size = _require_size(
        payload_size_bytes, label="payload_size_bytes", maximum=MAX_PAYLOAD_BYTES
    )
    return sha256_hex(
        frame_message(
            OPERATION_ID_MAGIC,
            (
                ("gate_contract_sha256", bytes.fromhex(gate_digest)),
                ("authorization_receipt_sha256", bytes.fromhex(authorization_digest)),
                ("authority_role", role.encode("ascii")),
                ("authority_key_id", key_id.encode("ascii")),
                ("signature_domain", domain.encode("ascii")),
                ("signature_purpose", purpose.encode("ascii")),
                ("round_id", round_value.encode("ascii")),
                ("slot_id_present", b"\x01"),
                ("slot_id", slot_value),
                ("payload_sha256", bytes.fromhex(payload_digest)),
                ("payload_size_bytes", payload_size.to_bytes(8, "big")),
            ),
        )
    )


def build_operation(
    *,
    gate_contract_sha256: str,
    authorization_receipt_bytes: bytes,
    authority_role: str,
    authority_key_id: str,
    signature_purpose: str,
    round_id: str,
    slot_id: str,
    payload_bytes: bytes,
) -> tuple[str, bytes]:
    """Build one closed operation; returns ``(operation_id, request_bytes)``.

    The authorization receipt and payload are carried as opaque exact bytes
    produced upstream — this client never re-serializes them.  Retain the
    returned request bytes verbatim; they are the only safe retry input.
    """
    parse_canonical_object(
        authorization_receipt_bytes,
        label="authorization receipt",
        maximum=MAX_AUTHORIZATION_RECEIPT_BYTES,
    )
    parse_canonical_object(
        payload_bytes, label="signature payload", maximum=MAX_PAYLOAD_BYTES
    )
    authorization_digest = sha256_hex(authorization_receipt_bytes)
    payload_digest = sha256_hex(payload_bytes)
    operation_id = derive_operation_id(
        gate_contract_sha256=gate_contract_sha256,
        authorization_receipt_sha256=authorization_digest,
        authority_role=authority_role,
        authority_key_id=authority_key_id,
        signature_domain=DETACHED_SIGNATURE_SCHEMA,
        signature_purpose=signature_purpose,
        round_id=round_id,
        slot_id=slot_id,
        payload_sha256=payload_digest,
        payload_size_bytes=len(payload_bytes),
    )
    operation = {
        "schema_version": OPERATION_SCHEMA,
        "operation_id": operation_id,
        "gate_contract_sha256": gate_contract_sha256,
        "authorization_receipt_sha256": authorization_digest,
        "authorization_receipt_canonical_base64": base64.b64encode(
            authorization_receipt_bytes
        ).decode("ascii"),
        "authority_role": authority_role,
        "authority_key_id": authority_key_id,
        "signature_domain": DETACHED_SIGNATURE_SCHEMA,
        "signature_purpose": signature_purpose,
        "round_id": round_id,
        "slot_id": slot_id,
        "payload_sha256": payload_digest,
        "payload_size_bytes": len(payload_bytes),
        "payload_canonical_base64": base64.b64encode(payload_bytes).decode("ascii"),
        "field_claim_authorized": False,
        "runtime_gate_complete": False,
        "non_forking_proven": False,
    }
    validate_operation(operation)
    request_bytes = canonical_json_bytes(operation)
    if len(request_bytes) > MAX_OPERATION_BYTES:
        raise SignerProtocolError("runtime signer operation is oversized")
    return operation_id, request_bytes


def validate_operation(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != OPERATION_KEYS:
        raise SignerProtocolError("runtime signer operation schema is invalid")
    if value.get("schema_version") != OPERATION_SCHEMA:
        raise SignerProtocolError("runtime signer operation version is invalid")
    _require_nonclaims(value, label="runtime signer operation")
    require_sha256(value.get("operation_id"), label="operation_id")
    gate_digest = require_sha256(
        value.get("gate_contract_sha256"), label="gate_contract_sha256"
    )
    authorization_digest = require_sha256(
        value.get("authorization_receipt_sha256"),
        label="authorization_receipt_sha256",
    )
    role = _require_text(
        value.get("authority_role"), label="authority_role", pattern=ROLE_RE
    )
    key_id = require_key_id(value.get("authority_key_id"), label="authority_key_id")
    domain = _require_text(
        value.get("signature_domain"), label="signature_domain", pattern=DOMAIN_RE
    )
    purpose = _require_text(
        value.get("signature_purpose"), label="signature_purpose", pattern=PURPOSE_RE
    )
    if domain != DETACHED_SIGNATURE_SCHEMA:
        raise SignerProtocolError(
            "signature_domain is not the existing detached-envelope profile"
        )
    if purpose not in SUPPORTED_SIGNATURE_PURPOSES:
        raise SignerProtocolError("signature_purpose is not supported by the project")
    round_value = _require_text(
        value.get("round_id"), label="round_id", pattern=IDENTIFIER_RE
    )
    slot_value = require_sha256(value.get("slot_id"), label="slot_id")
    payload_digest = require_sha256(value.get("payload_sha256"), label="payload_sha256")
    payload_size = _require_size(
        value.get("payload_size_bytes"),
        label="payload_size_bytes",
        maximum=MAX_PAYLOAD_BYTES,
    )
    authorization_bytes = decode_canonical_base64(
        value.get("authorization_receipt_canonical_base64"),
        label="authorization_receipt_canonical_base64",
        maximum=MAX_AUTHORIZATION_RECEIPT_BYTES,
    )
    payload_bytes = decode_canonical_base64(
        value.get("payload_canonical_base64"),
        label="payload_canonical_base64",
        maximum=MAX_PAYLOAD_BYTES,
    )
    parse_canonical_object(
        authorization_bytes,
        label="authorization receipt",
        maximum=MAX_AUTHORIZATION_RECEIPT_BYTES,
    )
    parse_canonical_object(
        payload_bytes, label="signature payload", maximum=MAX_PAYLOAD_BYTES
    )
    if (
        sha256_hex(authorization_bytes) != authorization_digest
        or sha256_hex(payload_bytes) != payload_digest
        or len(payload_bytes) != payload_size
    ):
        raise SignerProtocolError("runtime signer embedded-byte binding is invalid")
    expected_id = derive_operation_id(
        gate_contract_sha256=gate_digest,
        authorization_receipt_sha256=authorization_digest,
        authority_role=role,
        authority_key_id=key_id,
        signature_domain=domain,
        signature_purpose=purpose,
        round_id=round_value,
        slot_id=slot_value,
        payload_sha256=payload_digest,
        payload_size_bytes=payload_size,
    )
    if value.get("operation_id") != expected_id:
        raise SignerProtocolError("runtime signer operation ID binding is invalid")
    canonical_json_bytes(value)
    return dict(value)


def parse_operation_bytes(raw: bytes) -> dict[str, Any]:
    """Parse and fully validate one exact canonical operation body."""
    operation = parse_canonical_object(
        raw, label="runtime signer operation", maximum=MAX_OPERATION_BYTES
    )
    return validate_operation(operation)


def operation_payload_bytes(operation: Mapping[str, Any]) -> bytes:
    """The exact payload bytes embedded in a validated operation."""
    return decode_canonical_base64(
        operation.get("payload_canonical_base64"),
        label="payload_canonical_base64",
        maximum=MAX_PAYLOAD_BYTES,
    )


def signature_message(operation_bytes: bytes) -> bytes:
    """The frozen detached-envelope v2 authority-signature message."""
    operation = parse_operation_bytes(operation_bytes)
    return frame_message(
        DETACHED_SIGNATURE_MAGIC,
        (
            ("round_id", str(operation["round_id"]).encode("ascii")),
            ("purpose", str(operation["signature_purpose"]).encode("ascii")),
            ("canonical_json", operation_payload_bytes(operation)),
        ),
    )


# --- receipt ----------------------------------------------------------------


def _validate_signature_record(value: Any, *, expected_key_id: str, label: str) -> bytes:
    if not isinstance(value, dict) or set(value) != {
        "algorithm",
        "key_id",
        "signature_encoding",
        "signature",
    }:
        raise SignerProtocolError(f"{label} is invalid")
    if (
        value.get("algorithm") != "Ed25519"
        or value.get("key_id") != expected_key_id
        or value.get("signature_encoding") != "base64"
    ):
        raise SignerProtocolError(f"{label} fields differ")
    signature = decode_canonical_base64(
        value.get("signature"), label=f"{label} signature", maximum=64
    )
    if len(signature) != 64:
        raise SignerProtocolError(f"{label} signature length is invalid")
    return signature


def validate_receipt(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != RECEIPT_KEYS:
        raise SignerProtocolError("runtime signer receipt schema is invalid")
    if value.get("schema_version") != RECEIPT_SCHEMA:
        raise SignerProtocolError("runtime signer receipt version is invalid")
    _require_nonclaims(value, label="runtime signer receipt")
    for field in (
        "operation_id",
        "request_sha256",
        "gate_contract_sha256",
        "authorization_receipt_sha256",
        "signer_service_identity_sha256",
        "authenticated_requester_identity_sha256",
        "payload_sha256",
        "signature_message_sha256",
    ):
        require_sha256(value.get(field), label=field)
    _require_text(value.get("authority_role"), label="authority_role", pattern=ROLE_RE)
    authority_key_id = require_key_id(
        value.get("authority_key_id"), label="authority_key_id"
    )
    receipt_key_id = require_key_id(
        value.get("signer_receipt_key_id"), label="signer_receipt_key_id"
    )
    if receipt_key_id == authority_key_id:
        raise SignerProtocolError("authority and signer receipt key IDs must be distinct")
    _require_text(
        value.get("signature_domain"), label="signature_domain", pattern=DOMAIN_RE
    )
    _require_text(
        value.get("signature_purpose"), label="signature_purpose", pattern=PURPOSE_RE
    )
    _require_text(value.get("round_id"), label="round_id", pattern=IDENTIFIER_RE)
    require_sha256(value.get("slot_id"), label="slot_id")
    _require_size(
        value.get("payload_size_bytes"),
        label="payload_size_bytes",
        maximum=MAX_PAYLOAD_BYTES,
    )
    _validate_signature_record(
        value.get("authority_signature"),
        expected_key_id=authority_key_id,
        label="runtime signer authority signature",
    )
    _validate_signature_record(
        value.get("service_authentication"),
        expected_key_id=receipt_key_id,
        label="runtime signer service authentication",
    )
    encoded = canonical_json_bytes(value)
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise SignerProtocolError("runtime signer receipt is oversized")
    return dict(value)


def signer_receipt_signature_message(projection: Mapping[str, Any]) -> bytes:
    """Frame the exact receipt projection signed by the service key."""
    if not isinstance(projection, Mapping):
        raise SignerProtocolError("runtime signer receipt projection is invalid")
    value = dict(projection)
    if set(value) != RECEIPT_PROJECTION_KEYS:
        raise SignerProtocolError("runtime signer receipt projection schema is invalid")
    receipt_key_id = require_key_id(
        value.get("signer_receipt_key_id"), label="signer_receipt_key_id"
    )
    validate_receipt(
        {
            **value,
            "service_authentication": {
                "algorithm": "Ed25519",
                "key_id": receipt_key_id,
                "signature_encoding": "base64",
                "signature": base64.b64encode(b"\x00" * 64).decode("ascii"),
            },
        }
    )
    payload = canonical_json_bytes(value)
    if len(payload) > MAX_RECEIPT_BYTES:
        raise SignerProtocolError("runtime signer receipt projection is oversized")
    return frame_message(
        SIGNER_RECEIPT_SIGNATURE_MAGIC,
        (
            ("domain", SIGNER_RECEIPT_SIGNATURE_DOMAIN.encode("ascii")),
            ("purpose", SIGNER_RECEIPT_SIGNATURE_PURPOSE.encode("ascii")),
            ("canonical_json", payload),
        ),
    )


def verify_receipt(
    receipt_bytes: bytes,
    request_bytes: bytes,
    *,
    pinned_authority_verifiers: Mapping[str, Ed25519Verifier],
    signer_receipt_key_id: str,
    signer_receipt_verifier: Ed25519Verifier,
    expected_signer_service_identity_sha256: str,
    expected_authenticated_requester_identity_sha256: str,
) -> dict[str, Any]:
    """Verify both receipt signatures and every exact-operation binding."""
    operation = parse_operation_bytes(request_bytes)
    receipt_value = parse_canonical_object(
        receipt_bytes, label="runtime signer receipt", maximum=MAX_RECEIPT_BYTES
    )
    receipt = validate_receipt(receipt_value)
    expected_service_identity = require_sha256(
        expected_signer_service_identity_sha256,
        label="expected_signer_service_identity_sha256",
    )
    expected_requester_identity = require_sha256(
        expected_authenticated_requester_identity_sha256,
        label="expected_authenticated_requester_identity_sha256",
    )
    receipt_key_id = require_key_id(
        signer_receipt_key_id, label="signer_receipt_key_id"
    )
    if not isinstance(pinned_authority_verifiers, Mapping):
        raise ReceiptVerificationError("authority public-key pins are invalid")
    if receipt_key_id in pinned_authority_verifiers:
        raise ReceiptVerificationError(
            "authority and pinned signer receipt key IDs must be distinct"
        )
    expected = {
        "operation_id": operation["operation_id"],
        "request_sha256": sha256_hex(request_bytes),
        "gate_contract_sha256": operation["gate_contract_sha256"],
        "authorization_receipt_sha256": operation["authorization_receipt_sha256"],
        "signer_service_identity_sha256": expected_service_identity,
        "signer_receipt_key_id": receipt_key_id,
        "authenticated_requester_identity_sha256": expected_requester_identity,
        "authority_role": operation["authority_role"],
        "authority_key_id": operation["authority_key_id"],
        "signature_domain": operation["signature_domain"],
        "signature_purpose": operation["signature_purpose"],
        "round_id": operation["round_id"],
        "slot_id": operation["slot_id"],
        "payload_sha256": operation["payload_sha256"],
        "payload_size_bytes": operation["payload_size_bytes"],
        "signature_message_sha256": sha256_hex(signature_message(request_bytes)),
    }
    if any(receipt.get(name) != item for name, item in expected.items()):
        raise ReceiptVerificationError(
            "runtime signer receipt does not bind the exact operation request"
        )
    service_signature = _validate_signature_record(
        receipt["service_authentication"],
        expected_key_id=receipt_key_id,
        label="runtime signer service authentication",
    )
    projection = dict(receipt)
    projection.pop("service_authentication")
    try:
        signer_receipt_verifier.verify(
            service_signature, signer_receipt_signature_message(projection)
        )
    except Exception as exc:
        raise ReceiptVerificationError(
            "runtime signer service authentication is invalid"
        ) from exc
    authority_verifier = pinned_authority_verifiers.get(
        str(operation["authority_key_id"])
    )
    if authority_verifier is None:
        raise ReceiptVerificationError("runtime signer authority key is not pinned")
    authority_signature = _validate_signature_record(
        receipt["authority_signature"],
        expected_key_id=str(operation["authority_key_id"]),
        label="runtime signer authority signature",
    )
    try:
        authority_verifier.verify(authority_signature, signature_message(request_bytes))
    except Exception as exc:
        raise ReceiptVerificationError("runtime signer signature is invalid") from exc
    return receipt


# --- requester authentication -----------------------------------------------


def request_signature_message(
    *,
    method: str,
    path: str,
    signer_service_identity_sha256: str,
    operation_id: str,
    body: bytes,
    requester_key_id: str,
) -> bytes:
    """Frame the exact application request authenticated by the requester."""
    if method not in ("POST", "GET"):
        raise SignerProtocolError("request method must be exact uppercase POST or GET")
    try:
        raw_path = path.encode("ascii", "strict")
    except (AttributeError, UnicodeEncodeError) as exc:
        raise SignerProtocolError("request path must be exact ASCII") from exc
    if (
        not raw_path
        or len(raw_path) > MAX_PATH_BYTES
        or not raw_path.startswith(b"/")
        or b"?" in raw_path
        or b"#" in raw_path
        or any(item in raw_path for item in (b"\x00", b"\r", b"\n"))
    ):
        raise SignerProtocolError(
            "request path must be one bounded origin-form path without query/fragment"
        )
    if not isinstance(body, bytes) or len(body) > MAX_OPERATION_BYTES:
        raise SignerProtocolError("authenticated request body is invalid")
    if method == "POST" and not body:
        raise SignerProtocolError("authenticated POST body must not be empty")
    if method == "GET" and body:
        raise SignerProtocolError("authenticated GET body must be empty")
    service_identity = require_sha256(
        signer_service_identity_sha256, label="signer_service_identity_sha256"
    )
    exact_operation_id = require_sha256(operation_id, label="operation_id")
    exact_requester_key_id = require_key_id(
        requester_key_id, label="requester_key_id"
    )
    return frame_message(
        REQUEST_AUTHENTICATION_MAGIC,
        (
            ("domain", REQUEST_AUTHENTICATION_SCHEMA.encode("ascii")),
            ("method", method.encode("ascii")),
            ("path", raw_path),
            ("signer_service_identity_sha256", bytes.fromhex(service_identity)),
            ("operation_id", bytes.fromhex(exact_operation_id)),
            ("requester_key_id", exact_requester_key_id.encode("ascii")),
            ("body_size_bytes", len(body).to_bytes(8, "big")),
            ("body_sha256", hashlib.sha256(body).digest()),
        ),
    )


def request_auth_headers(
    *,
    method: str,
    path: str,
    signer_service_identity_sha256: str,
    operation_id: str,
    body: bytes,
    requester_key_id: str,
    sign: Callable[[bytes], bytes],
) -> dict[str, str]:
    """Build the two requester-authentication headers for one exact request."""
    message = request_signature_message(
        method=method,
        path=path,
        signer_service_identity_sha256=signer_service_identity_sha256,
        operation_id=operation_id,
        body=body,
        requester_key_id=requester_key_id,
    )
    signature = sign(message)
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise SignerProtocolError("Ed25519 signer returned a non-canonical signature")
    return {
        REQUESTER_KEY_ID_HEADER: requester_key_id,
        REQUESTER_SIGNATURE_HEADER: base64.b64encode(signature).decode("ascii"),
    }


# --- HTTP surface -----------------------------------------------------------

Transport = Any  # Callable[[str, str, dict[str, str], bytes | None], HttpResponse]


@dataclass(frozen=True)
class HttpResponse:
    """One complete HTTP exchange result as seen by this client."""

    status: int
    headers: tuple[tuple[str, str], ...]  # lowercased names, order preserved
    body: bytes


@dataclass(frozen=True)
class SignerOutcome:
    """A definitively signed operation."""

    created: bool  # True on 201 created, False on 200 replayed
    receipt_bytes: bytes


def validate_base_url(base_url: str) -> str:
    """Validate the service origin; returns it without a trailing slash."""
    parsed = urllib.parse.urlsplit(base_url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise SignerProtocolError("signer base URL port is invalid") from exc
    if port == 0:
        raise SignerProtocolError("signer base URL port is invalid")
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or "%" in base_url
        or "\\" in base_url
    ):
        raise SignerProtocolError(
            "signer base URL must be a plain https origin with no path"
        )
    return f"https://{parsed.netloc}"


def default_transport(*, timeout: float = 30.0) -> Transport:
    """A stdlib https transport: TLS verified, no redirects followed."""

    def _send(
        method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> HttpResponse:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise SignerProtocolError("transport requires an https URL")
        context = ssl.create_default_context()
        connection = http.client.HTTPSConnection(
            parsed.hostname,
            parsed.port or 443,
            timeout=timeout,
            context=context,
        )
        try:
            connection.request(method, parsed.path or "/", body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read(MAX_RESPONSE_BYTES + 1)
            if len(payload) > MAX_RESPONSE_BYTES:
                raise SignerProtocolError("signer response is oversized")
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
            raise SignerProtocolError(f"duplicate response header: {name}")
        seen[name] = value
    return seen


def _require_common_headers(headers: Mapping[str, str], body: bytes) -> None:
    if headers.get("content-type") != "application/json":
        raise SignerProtocolError("signer response content-type is invalid")
    if headers.get("cache-control") != "no-store":
        raise SignerProtocolError("signer response cache-control is invalid")
    length = headers.get("content-length")
    if length is not None and length != str(len(body)):
        raise SignerProtocolError("signer response content-length is inconsistent")


def _error_code(body: bytes) -> str:
    document = parse_canonical_object(
        body, label="signer error body", maximum=MAX_RESPONSE_BYTES
    )
    code = document.get("error")
    if not isinstance(code, str) or not (
        set(document) == {"error"} or set(document) == {"error", "operation_id"}
    ):
        raise SignerProtocolError("signer error body shape is invalid")
    return code


def _is_definite_rejection(status: int) -> bool:
    """4xx statuses are definite non-commits, except the retryable trio."""
    return 400 <= status <= 499 and status not in (408, 425, 429)


def _rejection_code(response: HttpResponse) -> str:
    """Best-effort error code from a definite rejection body."""
    try:
        return _error_code(response.body)
    except SignerClientError:
        return f"http_{response.status}"


def _classify_error(status: int, code: str) -> SignerClientError:
    if status == 409 and code == "operation_unresolved":
        return SignerUnresolvedError(
            "operation is quarantined pending out-of-band reconciliation"
        )
    if _is_definite_rejection(status):
        return SignerRejectedError(code)
    return SignerAmbiguousOutcome(f"signer answered {status}: {code}")


def post_signature(
    operation_body: bytes,
    *,
    base_url: str,
    signer_service_identity_sha256: str,
    requester_key_id: str,
    sign: Callable[[bytes], bytes],
    transport: Transport,
) -> SignerOutcome:
    """POST one exact operation body; classify the outcome.

    On :class:`SignerAmbiguousOutcome` the caller retries with the same
    cached body bytes — the deterministic auth signature is then identical
    too.  Never rebuild the operation after an ambiguous outcome.
    """
    operation = parse_operation_bytes(operation_body)
    operation_id = str(operation["operation_id"])
    origin = validate_base_url(base_url)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Content-Length": str(len(operation_body)),
        "Idempotency-Key": operation_id,
        **request_auth_headers(
            method="POST",
            path=SIGNATURE_PATH,
            signer_service_identity_sha256=signer_service_identity_sha256,
            operation_id=operation_id,
            body=operation_body,
            requester_key_id=requester_key_id,
            sign=sign,
        ),
    }
    try:
        response: HttpResponse = transport(
            "POST", origin + SIGNATURE_PATH, headers, operation_body
        )
    except Exception as exc:
        # Any transport-level failure — including this module's own
        # oversized/mangled-response errors — happens after the request may
        # have been delivered, so the signing outcome is unknown.
        raise SignerAmbiguousOutcome(f"transport failure: {exc}") from exc
    status = response.status
    if status in (200, 201):
        header_map = _header_map(response)
        _require_common_headers(header_map, response.body)
        marker = header_map.get(RESULT_HEADER)
        expected_marker = "created" if status == 201 else "replayed"
        if marker != expected_marker:
            raise SignerProtocolError("signer result marker is inconsistent")
        receipt = validate_receipt(
            parse_canonical_object(
                response.body,
                label="runtime signer receipt",
                maximum=MAX_RECEIPT_BYTES,
            )
        )
        if receipt["operation_id"] != operation_id:
            raise SignerProtocolError("served receipt names a different operation")
        return SignerOutcome(created=(status == 201), receipt_bytes=response.body)
    if _is_definite_rejection(status):
        # Definite non-signing (a service 400/401/403/404/409, or a
        # 405/413/... from an intermediary): surface it, never retry-loop.
        raise _classify_error(status, _rejection_code(response))
    # 1xx/3xx/408/425/429/5xx leave the signing outcome unknown.
    raise SignerAmbiguousOutcome(f"unexpected signer response status {status}")


def get_receipt(
    operation_id: str,
    *,
    base_url: str,
    signer_service_identity_sha256: str,
    requester_key_id: str,
    sign: Callable[[bytes], bytes],
    transport: Transport,
) -> bytes | None:
    """Look up the stored receipt for one operation id.

    Returns ``None`` only on the service's definitive not-found answer
    (which also covers PREPARED records and foreign-requester records).
    Raises :class:`SignerUnresolvedError` for quarantined operations.
    """
    exact_operation_id = require_sha256(operation_id, label="operation_id")
    origin = validate_base_url(base_url)
    path = OPERATION_LOOKUP_PATH_PREFIX + exact_operation_id
    headers = {
        "Accept": "application/json",
        **request_auth_headers(
            method="GET",
            path=path,
            signer_service_identity_sha256=signer_service_identity_sha256,
            operation_id=exact_operation_id,
            body=b"",
            requester_key_id=requester_key_id,
            sign=sign,
        ),
    }
    try:
        response: HttpResponse = transport("GET", origin + path, headers, None)
    except Exception as exc:
        raise SignerAmbiguousOutcome(f"transport failure: {exc}") from exc
    if response.status != 200 and not _is_definite_rejection(response.status):
        raise SignerAmbiguousOutcome(
            f"unexpected signer response status {response.status}"
        )
    header_map = _header_map(response)
    _require_common_headers(header_map, response.body)
    if response.status == 200:
        if header_map.get(RESULT_HEADER) != "found":
            raise SignerProtocolError("signer result marker is inconsistent")
        receipt = validate_receipt(
            parse_canonical_object(
                response.body,
                label="runtime signer receipt",
                maximum=MAX_RECEIPT_BYTES,
            )
        )
        if receipt["operation_id"] != exact_operation_id:
            raise SignerProtocolError("served receipt names a different operation")
        return response.body
    if response.status == 404:
        code = _rejection_code(response)
        if code == "operation_not_found":
            if header_map.get(RESULT_HEADER) != "not-found":
                raise SignerProtocolError("signer result marker is inconsistent")
            return None
        raise _classify_error(response.status, code)
    raise _classify_error(response.status, _rejection_code(response))


__all__ = [
    "OPERATION_SCHEMA",
    "RECEIPT_SCHEMA",
    "DETACHED_SIGNATURE_SCHEMA",
    "REQUEST_AUTHENTICATION_SCHEMA",
    "OPERATION_ID_MAGIC",
    "DETACHED_SIGNATURE_MAGIC",
    "SIGNER_RECEIPT_SIGNATURE_MAGIC",
    "SIGNER_RECEIPT_SIGNATURE_DOMAIN",
    "SIGNER_RECEIPT_SIGNATURE_PURPOSE",
    "REQUEST_AUTHENTICATION_MAGIC",
    "SIGNATURE_PATH",
    "OPERATION_LOOKUP_PATH_PREFIX",
    "REQUESTER_KEY_ID_HEADER",
    "REQUESTER_SIGNATURE_HEADER",
    "SUPPORTED_SIGNATURE_PURPOSES",
    "NONCLAIM_KEYS",
    "OPERATION_KEYS",
    "RECEIPT_KEYS",
    "RECEIPT_PROJECTION_KEYS",
    "MAX_JSON_DEPTH",
    "MAX_PAYLOAD_BYTES",
    "MAX_AUTHORIZATION_RECEIPT_BYTES",
    "MAX_OPERATION_BYTES",
    "MAX_RECEIPT_BYTES",
    "SignerClientError",
    "SignerProtocolError",
    "SignerRejectedError",
    "SignerUnresolvedError",
    "SignerAmbiguousOutcome",
    "ReceiptVerificationError",
    "Ed25519Verifier",
    "HttpResponse",
    "SignerOutcome",
    "canonical_json_bytes",
    "parse_canonical_object",
    "sha256_hex",
    "require_sha256",
    "require_key_id",
    "decode_canonical_base64",
    "key_id_from_raw_public_key",
    "frame_message",
    "derive_operation_id",
    "build_operation",
    "validate_operation",
    "parse_operation_bytes",
    "operation_payload_bytes",
    "signature_message",
    "validate_receipt",
    "signer_receipt_signature_message",
    "verify_receipt",
    "request_signature_message",
    "request_auth_headers",
    "validate_base_url",
    "default_transport",
    "post_signature",
    "get_receipt",
]
