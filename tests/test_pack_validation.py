# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Pack manifest contract — fail-closed validation + ``evo-guard pack-doctor``.

``pack.json`` turns a folder of judge tests into a *versioned behaviour
contract* (id / version / description / target_type). It stays optional — a
plain folder of tests is a valid pack — but a PRESENT-and-broken manifest must
stop the run, never be silently judged as an anonymous folder while the verdict
still names a contract.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from evoom_guard import cli
from evoom_guard.blackbox import (
    PackManifestError,
    _pack_digest_and_manifest,
    run_blackbox,
)

PACK_TEST = (
    "def test_trivial():\n    assert True\n"
)


class ManifestValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pack = tempfile.mkdtemp(prefix="evo_pack_t_")
        with open(os.path.join(self.pack, "test_protocol.py"), "w", encoding="utf-8") as f:
            f.write(PACK_TEST)

    def tearDown(self) -> None:
        shutil.rmtree(self.pack, ignore_errors=True)

    def _manifest(self, payload: str) -> None:
        with open(os.path.join(self.pack, "pack.json"), "w", encoding="utf-8") as f:
            f.write(payload)

    def test_no_manifest_is_a_valid_pack(self) -> None:
        digest, manifest = _pack_digest_and_manifest(self.pack)
        self.assertTrue(digest)
        self.assertIsNone(manifest)

    def test_valid_manifest_is_extracted(self) -> None:
        self._manifest(json.dumps({
            "id": "calc-protocol", "version": "1.2.0",
            "description": "d", "target_type": "cli",
        }))
        _digest, manifest = _pack_digest_and_manifest(self.pack)
        assert manifest is not None
        self.assertEqual(manifest["id"], "calc-protocol")
        self.assertEqual(manifest["version"], "1.2.0")

    def test_malformed_manifest_is_fail_closed(self) -> None:
        self._manifest("{not json")
        with self.assertRaises(PackManifestError):
            _pack_digest_and_manifest(self.pack)

    def test_missing_id_or_version_is_fail_closed(self) -> None:
        for payload in ({"version": "1.0"}, {"id": "x"}, {"id": "", "version": "1"}):
            self._manifest(json.dumps(payload))
            with self.assertRaises(PackManifestError):
                _pack_digest_and_manifest(self.pack)

    def test_run_blackbox_surfaces_a_clean_error_not_a_crash(self) -> None:
        self._manifest("{broken")
        repo = tempfile.mkdtemp(prefix="evo_pack_repo_")
        try:
            with open(os.path.join(repo, "app.py"), "w", encoding="utf-8") as f:
                f.write("x = 1\n")
            bx = run_blackbox(
                repo, "<<<FILE: app.py>>>\nx = 1\n<<<END FILE>>>", self.pack,
                timeout=60,
            )
            self.assertFalse(bx.ran)
            self.assertEqual(bx.error, "invalid pack manifest")
        finally:
            shutil.rmtree(repo, ignore_errors=True)


class PackDoctorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pack = tempfile.mkdtemp(prefix="evo_packdoc_")

    def tearDown(self) -> None:
        shutil.rmtree(self.pack, ignore_errors=True)

    def _write(self, name: str, content: str) -> None:
        with open(os.path.join(self.pack, name), "w", encoding="utf-8") as f:
            f.write(content)

    def test_valid_pack_exits_zero(self) -> None:
        self._write("test_protocol.py", PACK_TEST)
        self._write("pack.json", json.dumps({"id": "p", "version": "1"}))
        self.assertEqual(cli.main(["pack-doctor", self.pack]), 0)

    def test_manifestless_pack_is_still_ok(self) -> None:
        self._write("test_protocol.py", PACK_TEST)
        self.assertEqual(cli.main(["pack-doctor", self.pack]), 0)

    def test_empty_pack_fails(self) -> None:
        self.assertEqual(cli.main(["pack-doctor", self.pack]), 1)

    def test_broken_manifest_fails_with_named_problem(self) -> None:
        self._write("test_protocol.py", PACK_TEST)
        self._write("pack.json", "{broken")
        report = cli.validate_pack(self.pack)
        self.assertFalse(report["ok"])
        self.assertTrue(any("readable JSON" in p for p in report["problems"]))

    def test_unknown_manifest_field_is_flagged(self) -> None:
        self._write("test_protocol.py", PACK_TEST)
        self._write("pack.json", json.dumps({"id": "p", "version": "1", "verion": "2"}))
        report = cli.validate_pack(self.pack)
        self.assertFalse(report["ok"])
        self.assertTrue(any("unknown field" in p for p in report["problems"]))

    def test_shipped_example_packs_are_valid(self) -> None:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for rel in ("examples/blackbox-cli/pack", "examples/blackbox-pack"):
            with self.subTest(pack=rel):
                report = cli.validate_pack(os.path.join(root, rel))
                self.assertTrue(report["ok"], report["problems"])


if __name__ == "__main__":
    unittest.main()
