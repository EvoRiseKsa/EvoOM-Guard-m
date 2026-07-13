# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""Optional Ed25519 signing of Guard verdicts — tamper-evident evidence.

A Guard verdict is only as trustworthy as its storage: a JSON report sitting in
an artifact bucket can be edited after the fact. Signing closes that hole — the
judge (e.g. the CI job) holds an Ed25519 private key and emits a detached
signature next to the verdict; anyone holding the public key can verify,
offline, that the verdict bytes are exactly what the judge wrote.

What a signature does — and does not — prove:

  * it proves the verdict file was **not altered after signing**, and that it
    was signed by the holder of the private key;
  * it does **not** prove the run itself was honest — that trust comes from the
    key belonging to a judge you control (a CI secret, not the patch author).

The signature covers the **exact bytes of the verdict file** (no
canonicalization step to get subtly wrong), and is written as base64 to a
``<file>.sig`` sidecar.

This module is the integration point for signed-evidence pipelines (e.g.
feeding verdicts into an audit trail such as Sentinel AI's Merkle log — see
``docs/SIGNED_VERDICTS.md``). The core gate stays stdlib-only: ``cryptography``
is imported lazily and only needed if you actually sign or verify — install it
with the extra: ``pip install "evoom-guard[sign]"``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
from dataclasses import dataclass
from typing import Any


class SigningUnavailableError(RuntimeError):
    """Raised when the optional ``cryptography`` dependency is not installed."""


@dataclass(frozen=True)
class _PrivateKeySnapshot:
    """One loaded private key and the identity derived from that same object."""

    key: Any
    key_id: str


def _crypto():
    """Lazily import the Ed25519 primitives (the ``sign`` extra)."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - exercised via the CLI tests
        raise SigningUnavailableError(
            "verdict signing needs the 'cryptography' package — "
            "install the extra: pip install \"evoom-guard[sign]\""
        ) from exc
    return ed25519, serialization


def _require_bytes(value: object, *, name: str) -> bytes:
    """Return ``value`` when it is bytes; reject ambiguous implicit coercions."""
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes, got {type(value).__name__}")
    return value


def _load_private_key(private_key_path: str):
    """Load an unencrypted PEM Ed25519 private key with stable diagnostics."""
    ed25519, serialization = _crypto()
    with open(private_key_path, "rb") as f:
        pem = f.read()
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"unable to load an unencrypted PEM private key: {private_key_path}"
        ) from exc
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError(f"not an Ed25519 private key: {private_key_path}")
    return key


def _load_private_key_snapshot(private_key_path: str) -> _PrivateKeySnapshot:
    """Load a signing key once for a multi-step, identity-bound operation.

    Callers that must place ``key_id`` inside the bytes they sign cannot safely
    derive the ID and sign through two independent path opens: the file may be
    rotated between them.  This opaque snapshot keeps both operations bound to
    one loaded key object.
    """

    key = _load_private_key(private_key_path)
    return _PrivateKeySnapshot(key=key, key_id=_key_id(key.public_key()))


def _load_public_key(public_key_path: str):
    """Load a PEM Ed25519 public key with stable diagnostics."""
    ed25519, serialization = _crypto()
    with open(public_key_path, "rb") as f:
        pem = f.read()
    try:
        key = serialization.load_pem_public_key(pem)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"unable to load a PEM public key: {public_key_path}") from exc
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError(f"not an Ed25519 public key: {public_key_path}")
    return key


def _public_key_der(key) -> bytes:
    """Serialize an Ed25519 public key as canonical DER SubjectPublicKeyInfo."""
    _ed25519, serialization = _crypto()
    return key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _key_id(key) -> str:
    """Return the stable content identity of a public key."""
    return "sha256:" + hashlib.sha256(_public_key_der(key)).hexdigest()


def generate_keypair(private_path: str, public_path: str) -> None:
    """Generate an Ed25519 keypair as PEM files (private: PKCS8, public: SPKI).

    The private key is written ``0600``; keep it as a CI secret — it *is* the
    judge's identity. Refuses to overwrite an existing file.
    """
    ed25519, serialization = _crypto()
    for p in (private_path, public_path):
        if os.path.exists(p):
            raise FileExistsError(f"refusing to overwrite an existing key: {p}")
    key = ed25519.Ed25519PrivateKey.generate()
    priv = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(priv)
    with open(public_path, "wb") as f:
        f.write(pub)


def sign_bytes(payload: bytes, private_key_path: str) -> bytes:
    """Return a raw 64-byte Ed25519 signature of ``payload``.

    ``payload`` must already be the exact byte representation the caller wants
    authenticated. This function performs no text encoding or canonicalization.
    The key must be an unencrypted PEM Ed25519 private key.
    """
    signature, _key_id_value = sign_bytes_with_key_id(payload, private_key_path)
    return signature


def sign_bytes_with_key_id(
    payload: bytes,
    private_key_path: str,
) -> tuple[bytes, str]:
    """Sign bytes and derive the public-key ID from the same path snapshot."""

    return _sign_bytes_with_key_id(payload, private_key_path)


def _sign_bytes_with_key_id(
    payload: bytes,
    private_key: str | _PrivateKeySnapshot,
) -> tuple[bytes, str]:
    """Internal multi-step signer accepting an already loaded key snapshot.

    The public API remains path-based. Evidence-envelope construction uses this
    helper so the key ID embedded in its payload and the signature come from one
    private-key load without exposing the opaque snapshot type publicly.
    """

    payload = _require_bytes(payload, name="payload")
    snapshot = (
        _load_private_key_snapshot(private_key)
        if isinstance(private_key, str)
        else private_key
    )
    return snapshot.key.sign(payload), snapshot.key_id


def verify_bytes(payload: bytes, signature: bytes, public_key_path: str) -> bool:
    """Return whether a raw Ed25519 ``signature`` authenticates ``payload``.

    A cryptographically invalid signature, including a raw value of the wrong
    length, returns ``False``. Malformed API inputs or an unusable/non-Ed25519
    public key raise a clear exception instead of being mistaken for a verdict.
    """
    verified, _key_id_value = verify_bytes_with_key_id(payload, signature, public_key_path)
    return verified


def verify_bytes_with_key_id(
    payload: bytes,
    signature: bytes,
    public_key_path: str,
) -> tuple[bool, str]:
    """Verify bytes and derive the trusted key ID from one public-key snapshot."""

    payload = _require_bytes(payload, name="payload")
    signature = _require_bytes(signature, name="signature")
    key = _load_public_key(public_key_path)
    key_id = _key_id(key)
    if len(signature) != 64:
        return False, key_id

    from cryptography.exceptions import InvalidSignature

    try:
        key.verify(signature, payload)
        return True, key_id
    except InvalidSignature:
        return False, key_id


def public_key_id(public_key_path: str) -> str:
    """Return ``sha256:<hex>`` over the public key's DER SPKI encoding."""
    return _key_id(_load_public_key(public_key_path))


def private_key_public_id(private_key_path: str) -> str:
    """Return the public-key ID corresponding to an Ed25519 private key."""
    return _key_id(_load_private_key(private_key_path).public_key())


def sign_file(path: str, private_key_path: str) -> str:
    """Sign the exact bytes of ``path``; write base64 to ``<path>.sig``.

    Returns the sidecar path. The signature is a detached Ed25519 signature of
    the file content as-is — byte-for-byte, no canonicalization.
    """
    with open(path, "rb") as f:
        payload = f.read()
    sig_path = path + ".sig"
    with open(sig_path, "wb") as f:
        f.write(base64.b64encode(sign_bytes(payload, private_key_path)) + b"\n")
    return sig_path


def verify_file(path: str, sig_path: str, public_key_path: str) -> bool:
    """True iff ``sig_path`` is a valid signature of ``path`` under the key.

    Never raises on an *invalid* signature — that is the ``False`` return; it
    does raise on unusable inputs (missing files, a non-Ed25519 key, or
    undecodable base64), which are caller errors rather than verdicts.
    """
    with open(path, "rb") as f:
        payload = f.read()
    with open(sig_path, "rb") as f:
        encoded = f.read().strip()
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"invalid base64 signature: {sig_path}") from exc
    return verify_bytes(payload, signature, public_key_path)
