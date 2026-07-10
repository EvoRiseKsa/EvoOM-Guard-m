# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Sole owner & author: Mana Alharbi (مانع الحربي).
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
import os


class SigningUnavailableError(RuntimeError):
    """Raised when the optional ``cryptography`` dependency is not installed."""


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


def sign_file(path: str, private_key_path: str) -> str:
    """Sign the exact bytes of ``path``; write base64 to ``<path>.sig``.

    Returns the sidecar path. The signature is a detached Ed25519 signature of
    the file content as-is — byte-for-byte, no canonicalization.
    """
    ed25519, serialization = _crypto()
    with open(private_key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError(f"not an Ed25519 private key: {private_key_path}")
    with open(path, "rb") as f:
        payload = f.read()
    sig_path = path + ".sig"
    with open(sig_path, "wb") as f:
        f.write(base64.b64encode(key.sign(payload)) + b"\n")
    return sig_path


def verify_file(path: str, sig_path: str, public_key_path: str) -> bool:
    """True iff ``sig_path`` is a valid signature of ``path`` under the key.

    Never raises on an *invalid* signature — that is the ``False`` return; it
    does raise on unusable inputs (missing files, a non-Ed25519 key, or
    undecodable base64), which are caller errors rather than verdicts.
    """
    ed25519, serialization = _crypto()
    from cryptography.exceptions import InvalidSignature

    with open(public_key_path, "rb") as f:
        key = serialization.load_pem_public_key(f.read())
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError(f"not an Ed25519 public key: {public_key_path}")
    with open(path, "rb") as f:
        payload = f.read()
    with open(sig_path, "rb") as f:
        signature = base64.b64decode(f.read().strip(), validate=True)
    try:
        key.verify(signature, payload)
        return True
    except InvalidSignature:
        return False
