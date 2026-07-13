# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Signed verdicts (``evoom_guard/signing.py`` + the CLI surface).

The signature must be a real Ed25519 detached signature of the verdict file's
exact bytes: a valid roundtrip verifies, and ANY byte change after signing —
the attack the feature exists to catch — must flip verification to invalid.
Skipped as a module when the optional ``cryptography`` extra is absent.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import unittest
from contextlib import redirect_stdout

try:
    import cryptography  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - environment dependent
    HAVE_CRYPTO = False

import tempfile

from evoom_guard import cli
from evoom_guard.signing import SigningUnavailableError  # noqa: F401  (public name)


@unittest.skipUnless(HAVE_CRYPTO, "needs the 'sign' extra (cryptography)")
class SigningRoundtripTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key = os.path.join(self.tmp.name, "k.pem")
        self.pub = os.path.join(self.tmp.name, "k.pub")
        self.assertEqual(cli.main(["keygen", "--key", self.key, "--pub", self.pub]), 0)

    def _verdict(self, payload: dict) -> str:
        p = os.path.join(self.tmp.name, "verdict.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        return p

    def test_keygen_writes_pem_pair_and_refuses_overwrite(self) -> None:
        with open(self.key, encoding="utf-8") as f:
            self.assertIn("PRIVATE KEY", f.read())
        with open(self.pub, encoding="utf-8") as f:
            self.assertIn("PUBLIC KEY", f.read())
        # A second keygen at the same paths must not clobber the judge's identity.
        self.assertEqual(cli.main(["keygen", "--key", self.key, "--pub", self.pub]), 2)

    def test_sign_and_verify_roundtrip(self) -> None:
        from evoom_guard.signing import sign_bytes, sign_file, verify_bytes

        p = self._verdict({"verdict": "PASS", "reason_code": "tests_passed"})
        sig = sign_file(p, self.key)
        self.assertEqual(sig, p + ".sig")
        with open(p, "rb") as f:
            payload = f.read()
        raw = sign_bytes(payload, self.key)
        self.assertEqual(len(raw), 64)
        self.assertTrue(verify_bytes(payload, raw, self.pub))
        with open(sig, "rb") as f:
            sidecar_raw = base64.b64decode(f.read().strip(), validate=True)
        self.assertTrue(verify_bytes(payload, sidecar_raw, self.pub))
        captured = io.StringIO()
        with redirect_stdout(captured):
            self.assertEqual(cli.main(["verify-verdict", p, "--pub", self.pub]), 0)
        self.assertIn(hashlib.sha256(payload).hexdigest(), captured.getvalue())

    def test_bytes_api_rejects_tampering_and_wrong_length(self) -> None:
        from evoom_guard.signing import sign_bytes, verify_bytes

        payload = b"exact evidence bytes\x00\xff"
        signature = sign_bytes(payload, self.key)
        corrupted = bytearray(signature)
        corrupted[-1] ^= 0x01
        self.assertFalse(verify_bytes(payload + b"!", signature, self.pub))
        self.assertFalse(verify_bytes(payload, bytes(corrupted), self.pub))
        self.assertFalse(verify_bytes(payload, signature[:-1], self.pub))

    def test_bytes_api_requires_bytes_without_implicit_coercion(self) -> None:
        from evoom_guard.signing import sign_bytes, verify_bytes

        with self.assertRaisesRegex(TypeError, "payload must be bytes"):
            sign_bytes("text", self.key)  # type: ignore[arg-type]
        with self.assertRaisesRegex(TypeError, "payload must be bytes"):
            verify_bytes("text", b"x" * 64, self.pub)  # type: ignore[arg-type]
        with self.assertRaisesRegex(TypeError, "signature must be bytes"):
            verify_bytes(b"payload", bytearray(64), self.pub)  # type: ignore[arg-type]

    def test_key_ids_are_sha256_of_der_spki_and_match_private_key(self) -> None:
        from cryptography.hazmat.primitives import serialization

        from evoom_guard.signing import private_key_public_id, public_key_id

        with open(self.pub, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        expected = "sha256:" + hashlib.sha256(der).hexdigest()
        self.assertEqual(public_key_id(self.pub), expected)
        self.assertEqual(private_key_public_id(self.key), expected)

    def test_combined_bytes_apis_bind_key_id_and_operation_to_one_load(self) -> None:
        from evoom_guard.signing import (
            sign_bytes_with_key_id,
            verify_bytes_with_key_id,
        )

        payload = b"one key snapshot"
        signature, signing_key_id = sign_bytes_with_key_id(payload, self.key)
        verified, verification_key_id = verify_bytes_with_key_id(
            payload, signature, self.pub
        )
        self.assertTrue(verified)
        self.assertEqual(signing_key_id, verification_key_id)

    def test_malformed_or_non_ed25519_keys_raise_clear_errors(self) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        from evoom_guard.signing import (
            private_key_public_id,
            public_key_id,
            sign_bytes,
            verify_bytes,
        )

        malformed = os.path.join(self.tmp.name, "malformed.pem")
        with open(malformed, "wb") as f:
            f.write(b"not a PEM key")
        with self.assertRaisesRegex(ValueError, "unable to load.*PEM private key"):
            sign_bytes(b"payload", malformed)
        with self.assertRaisesRegex(ValueError, "unable to load a PEM public key"):
            verify_bytes(b"payload", b"x" * 64, malformed)

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_private = os.path.join(self.tmp.name, "rsa-private.pem")
        rsa_public = os.path.join(self.tmp.name, "rsa-public.pem")
        with open(rsa_private, "wb") as f:
            f.write(
                rsa_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        with open(rsa_public, "wb") as f:
            f.write(
                rsa_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        with self.assertRaisesRegex(ValueError, "not an Ed25519 private key"):
            private_key_public_id(rsa_private)
        with self.assertRaisesRegex(ValueError, "not an Ed25519 public key"):
            public_key_id(rsa_public)

    def test_tampered_verdict_is_invalid(self) -> None:
        from evoom_guard.signing import sign_file

        p = self._verdict({"verdict": "FAIL", "reason_code": "tests_failed"})
        sign_file(p, self.key)
        # The attack: upgrade FAIL to PASS after the judge signed.
        with open(p, encoding="utf-8") as f:
            forged = f.read().replace("FAIL", "PASS")
        with open(p, "w", encoding="utf-8") as f:
            f.write(forged)
        self.assertEqual(cli.main(["verify-verdict", p, "--pub", self.pub]), 1)

    def test_tampered_signature_is_invalid_or_unusable(self) -> None:
        from evoom_guard.signing import sign_file

        p = self._verdict({"verdict": "PASS"})
        sig = sign_file(p, self.key)
        with open(sig, "rb") as f:
            raw = bytearray(f.read())
        raw[0] ^= 0x01  # corrupt the base64 head
        with open(sig, "wb") as f:
            f.write(raw)
        self.assertIn(cli.main(["verify-verdict", p, "--pub", self.pub]), (1, 2))

    def test_wrong_key_is_invalid(self) -> None:
        from evoom_guard.signing import sign_file

        p = self._verdict({"verdict": "PASS"})
        sign_file(p, self.key)
        other_key = os.path.join(self.tmp.name, "other.pem")
        other_pub = os.path.join(self.tmp.name, "other.pub")
        self.assertEqual(cli.main(["keygen", "--key", other_key, "--pub", other_pub]), 0)
        self.assertEqual(cli.main(["verify-verdict", p, "--pub", other_pub]), 1)

    def test_guard_sign_key_signs_the_json_verdict(self) -> None:
        # A REJECTED run still signs: the signature covers the verdict, whatever it is.
        repo = os.path.join(self.tmp.name, "repo")
        os.makedirs(os.path.join(repo, "tests"))
        with open(os.path.join(repo, "tests", "test_x.py"), "w", encoding="utf-8") as f:
            f.write("def test_x():\n    assert True\n")
        patch = os.path.join(self.tmp.name, "cheat.txt")
        with open(patch, "w", encoding="utf-8") as f:
            f.write("<<<FILE: tests/test_x.py>>>\ndef test_x():\n    assert True\n<<<END FILE>>>\n")
        jout = os.path.join(self.tmp.name, "out.json")
        rc = cli.main([
            "guard", repo, "--patch", patch,
            "--json", jout, "--sign-key", self.key,
            "--report", os.path.join(self.tmp.name, "r.md"),
        ])
        self.assertEqual(rc, 1)  # REJECTED
        self.assertTrue(os.path.exists(jout + ".sig"))
        self.assertEqual(cli.main(["verify-verdict", jout, "--pub", self.pub]), 0)


class SignKeyUsageTests(unittest.TestCase):
    def test_sign_key_without_json_is_a_usage_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            os.makedirs(repo)
            patch = os.path.join(tmp, "p.txt")
            with open(patch, "w", encoding="utf-8") as f:
                f.write("<<<FILE: a.py>>>\nx = 1\n<<<END FILE>>>\n")
            rc = cli.main([
                "guard", repo, "--patch", patch, "--sign-key", "nonexistent.pem",
                "--report", os.path.join(tmp, "r.md"),
            ])
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
