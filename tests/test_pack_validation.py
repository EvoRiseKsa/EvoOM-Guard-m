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
import sys
import tempfile
import unittest
from unittest import mock

from evoom_guard import cli
from evoom_guard.blackbox import (
    PackManifestError,
    _pack_digest_and_manifest,
    run_blackbox,
)
from evoom_guard.guard import ERROR, TAMPERED, guard
from evoom_guard.pack_manifest import pack_digest, snapshot_pack
from evoom_guard.verifiers.repo_verifier import RepoVerifier

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

    def test_every_consumer_records_the_same_canonical_manifest(self) -> None:
        expected = {
            "id": "calc-protocol", "version": "1.2.0", "description": "d",
            "target_type": "cli", "protocol": "stdio-v1",
        }
        self._manifest(json.dumps(expected))
        _digest, blackbox_manifest = _pack_digest_and_manifest(self.pack)
        repo = tempfile.mkdtemp(prefix="evo_pack_repo_")
        try:
            with open(os.path.join(repo, "app.py"), "w", encoding="utf-8") as f:
                f.write("x = 1\n")
            result = RepoVerifier(
                test_command=[sys.executable, "-c", "raise SystemExit(0)"],
                mem_limit_mb=0,
            ).verify(
                "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>",
                {"repo_path": repo, "verifier_pack": self.pack},
            )
            self.assertEqual(blackbox_manifest, expected)
            self.assertEqual(result.artifact["verifier_pack_manifest"], expected)
            self.assertEqual(cli.validate_pack(self.pack)["manifest"], expected)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_malformed_manifest_is_fail_closed(self) -> None:
        self._manifest("{not json")
        with self.assertRaises(PackManifestError):
            _pack_digest_and_manifest(self.pack)

    def test_duplicate_manifest_keys_are_fail_closed(self) -> None:
        self._manifest('{"id":"first","id":"second","version":"1"}')
        with self.assertRaisesRegex(PackManifestError, "duplicate JSON key"):
            _pack_digest_and_manifest(self.pack)

    def test_missing_id_or_version_is_fail_closed(self) -> None:
        for payload in ({"version": "1.0"}, {"id": "x"}, {"id": "", "version": "1"}):
            self._manifest(json.dumps(payload))
            with self.assertRaises(PackManifestError):
                _pack_digest_and_manifest(self.pack)

    def test_digest_records_are_unambiguous(self) -> None:
        left = tempfile.mkdtemp(prefix="evo_pack_left_")
        right = tempfile.mkdtemp(prefix="evo_pack_right_")
        try:
            with open(os.path.join(left, "a"), "wb") as f:
                f.write(b"bc")
            with open(os.path.join(right, "ab"), "wb") as f:
                f.write(b"c")
            self.assertNotEqual(pack_digest(left), pack_digest(right))
        finally:
            shutil.rmtree(left, ignore_errors=True)
            shutil.rmtree(right, ignore_errors=True)

    def test_digest_binds_empty_directories_that_can_affect_imports(self) -> None:
        left = tempfile.mkdtemp(prefix="evo_pack_left_")
        right = tempfile.mkdtemp(prefix="evo_pack_right_")
        try:
            with open(os.path.join(left, "test_x.py"), "w", encoding="utf-8") as f:
                f.write(PACK_TEST)
            with open(os.path.join(right, "test_x.py"), "w", encoding="utf-8") as f:
                f.write(PACK_TEST)
            os.makedirs(os.path.join(right, "namespace_only"))
            self.assertNotEqual(pack_digest(left), pack_digest(right))
        finally:
            shutil.rmtree(left, ignore_errors=True)
            shutil.rmtree(right, ignore_errors=True)

    def test_digest_v2_has_a_stable_cross_process_vector(self) -> None:
        vector = tempfile.mkdtemp(prefix="evo_pack_vector_")
        try:
            os.mkdir(os.path.join(vector, "empty"))
            with open(os.path.join(vector, "pack.json"), "wb") as f:
                f.write(b'{"id":"vector","version":"1"}\n')
            with open(os.path.join(vector, "test_contract.py"), "wb") as f:
                f.write(b"def test_ok():\n    assert True\n")
            self.assertEqual(
                pack_digest(vector),
                "aceeb43f1a84fa539fde649de9e54381a1b77d4fc2e0afcf637d14d47405cc25",
            )
        finally:
            shutil.rmtree(vector, ignore_errors=True)

    def test_symlink_is_refused_as_unbound_pack_content(self) -> None:
        target = os.path.join(self.pack, "target.py")
        link = os.path.join(self.pack, "test_link.py")
        with open(target, "w", encoding="utf-8") as f:
            f.write(PACK_TEST)
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(PackManifestError):
            pack_digest(self.pack)

    def test_symlinked_pack_root_is_refused(self) -> None:
        link = self.pack + "_link"
        try:
            os.symlink(self.pack, link, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symlinks unavailable")
        try:
            with self.assertRaises(PackManifestError):
                pack_digest(link)
        finally:
            try:
                os.unlink(link)
            except OSError:
                pass

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO unavailable")
    def test_special_pack_file_is_refused_without_being_opened(self) -> None:
        pipe = os.path.join(self.pack, "contract.pipe")
        os.mkfifo(pipe)
        with self.assertRaises(PackManifestError):
            pack_digest(self.pack)

    def test_snapshot_copy_race_is_detected(self) -> None:
        destination = self.pack + "_snapshot"
        real_copytree = shutil.copytree

        def moving_copy(source, target, **kwargs):
            result = real_copytree(source, target, **kwargs)
            with open(os.path.join(target, "test_protocol.py"), "a", encoding="utf-8") as f:
                f.write("# changed during copy\n")
            return result

        try:
            with mock.patch(
                "evoom_guard.pack_manifest.shutil.copytree", side_effect=moving_copy
            ):
                with self.assertRaisesRegex(PackManifestError, "changed"):
                    snapshot_pack(self.pack, destination)
        finally:
            shutil.rmtree(destination, ignore_errors=True)

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
            self.assertEqual(bx.error, "verifier pack invalid")
            result = guard(
                repo,
                "<<<FILE: app.py>>>\nx = 1\n<<<END FILE>>>",
                verifier_pack=self.pack,
            )
            self.assertEqual(result.verdict, ERROR)
            self.assertEqual(result.reason_code, "verifier_pack_invalid")
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_repo_native_pack_failure_is_mandatory(self) -> None:
        self._manifest(json.dumps({"id": "mandatory", "version": "1"}))
        with open(os.path.join(self.pack, "test_protocol.py"), "w", encoding="utf-8") as f:
            f.write("def test_pack_contract():\n    assert False\n")
        repo = tempfile.mkdtemp(prefix="evo_pack_repo_")
        try:
            with open(os.path.join(repo, "app.py"), "w", encoding="utf-8") as f:
                f.write("x = 1\n")
            result = RepoVerifier(
                test_command=[sys.executable, "-c", "raise SystemExit(0)"],
                mem_limit_mb=0,
            ).verify(
                "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>",
                {"repo_path": repo, "verifier_pack": self.pack},
            )
            self.assertFalse(result.passed)
            self.assertEqual(result.artifact["verifier_pack_tests_total"], 1)
            self.assertEqual(result.artifact["verifier_pack_tests_passed"], 0)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_expected_pack_digest_matches_the_exact_accepted_snapshot(self) -> None:
        expected = pack_digest(self.pack)
        repo = tempfile.mkdtemp(prefix="evo_pack_repo_")
        try:
            with open(os.path.join(repo, "app.py"), "w", encoding="utf-8") as f:
                f.write("x = 1\n")
            result = RepoVerifier(
                test_command=[sys.executable, "-c", "raise SystemExit(0)"],
                mem_limit_mb=0,
            ).verify(
                "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>",
                {
                    "repo_path": repo,
                    "verifier_pack": self.pack,
                    "expect_verifier_pack_sha256": expected.upper(),
                },
            )
            self.assertTrue(result.passed, result.diagnostics)
            self.assertEqual(result.artifact["verifier_pack_sha256"], expected)
            self.assertEqual(result.artifact["expected_verifier_pack_sha256"], expected)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_pack_digest_mismatch_stops_before_candidate_code(self) -> None:
        repo = tempfile.mkdtemp(prefix="evo_pack_repo_")
        marker = os.path.join(repo, "candidate-ran")
        try:
            with open(os.path.join(repo, "app.py"), "w", encoding="utf-8") as f:
                f.write("x = 1\n")
            result = RepoVerifier(
                test_command=[
                    sys.executable,
                    "-c",
                    f"open({marker!r}, 'w').write('bad')",
                ],
                mem_limit_mb=0,
            ).verify(
                "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>",
                {
                    "repo_path": repo,
                    "verifier_pack": self.pack,
                    "expect_verifier_pack_sha256": "0" * 64,
                },
            )
            self.assertFalse(result.passed)
            self.assertEqual(result.artifact["outcome"], "pack_identity_mismatch")
            self.assertFalse(os.path.exists(marker))
            bx = run_blackbox(
                repo,
                "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>",
                self.pack,
                expect_verifier_pack_sha256="0" * 64,
            )
            self.assertFalse(bx.ran)
            self.assertEqual(bx.error, "verifier pack identity mismatch")
            self.assertEqual(bx.pack_sha256, pack_digest(self.pack))
            guarded = guard(
                repo,
                "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>",
                test_command=[
                    sys.executable,
                    "-c",
                    f"open({marker!r}, 'w').write('bad')",
                ],
                verifier_pack=self.pack,
                expect_verifier_pack_sha256="0" * 64,
                blackbox=True,
            )
            self.assertEqual(guarded.verdict, ERROR)
            self.assertEqual(
                guarded.reason_code, "verifier_pack_identity_mismatch"
            )
            self.assertFalse(os.path.exists(marker))
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_repo_suite_cannot_replace_the_accepted_pack(self) -> None:
        with open(os.path.join(self.pack, "test_protocol.py"), "w", encoding="utf-8") as f:
            f.write("def test_pack_contract():\n    assert False\n")
        repo = tempfile.mkdtemp(prefix="evo_pack_repo_")
        try:
            with open(os.path.join(repo, "app.py"), "w", encoding="utf-8") as f:
                f.write("x = 1\n")
            overwrite = (
                "import os; "
                "os.makedirs('evoguard_verifier_pack', exist_ok=True); "
                "open('evoguard_verifier_pack/test_protocol.py', 'w').write("
                "'def test_pack_contract():\\n    assert True\\n')"
            )
            result = RepoVerifier(
                test_command=[sys.executable, "-c", overwrite], mem_limit_mb=0
            ).verify(
                "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>",
                {"repo_path": repo, "verifier_pack": self.pack},
            )
            self.assertFalse(result.passed)
            self.assertTrue(result.artifact["tamper"])
            self.assertIn("evoguard_verifier_pack", result.diagnostics)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_repo_suite_cannot_rewrite_candidate_to_satisfy_the_pack(self) -> None:
        with open(os.path.join(self.pack, "test_protocol.py"), "w", encoding="utf-8") as f:
            f.write("import app\n\ndef test_contract():\n    assert app.x == 999\n")
        repo = tempfile.mkdtemp(prefix="evo_pack_repo_")
        try:
            with open(os.path.join(repo, "app.py"), "w", encoding="utf-8") as f:
                f.write("x = 1\n")
            result = RepoVerifier(
                test_command=[
                    sys.executable,
                    "-c",
                    "open('app.py', 'w').write('x = 999\\n')",
                ],
                mem_limit_mb=0,
            ).verify(
                "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>",
                {"repo_path": repo, "verifier_pack": self.pack},
            )
            self.assertFalse(result.passed)
            self.assertTrue(result.artifact["tamper"])
            self.assertEqual(result.artifact["candidate_fidelity_changes"], ["app.py"])
            self.assertIn("modified the candidate tree", result.diagnostics)
            guarded = guard(
                repo,
                "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>",
                test_command=[
                    sys.executable,
                    "-c",
                    "open('app.py', 'w').write('x = 999\\n')",
                ],
                verifier_pack=self.pack,
                mem_limit_mb=0,
            )
            self.assertEqual(guarded.verdict, TAMPERED)
            self.assertEqual(
                guarded.reason_code, "candidate_tree_changed_during_run"
            )
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    @unittest.skipIf(os.name == "nt", "black-box subprocess launcher requires POSIX")
    def test_blackbox_rejects_junit_exit_disagreement(self) -> None:
        with open(os.path.join(self.pack, "test_protocol.py"), "w", encoding="utf-8") as f:
            f.write("def test_contract():\n    assert False\n")
        with open(os.path.join(self.pack, "conftest.py"), "w", encoding="utf-8") as f:
            f.write(
                "def pytest_sessionfinish(session, exitstatus):\n"
                "    session.exitstatus = 0\n"
            )
        repo = tempfile.mkdtemp(prefix="evo_pack_repo_")
        try:
            with open(os.path.join(repo, "app.py"), "w", encoding="utf-8") as f:
                f.write("x = 1\n")
            bx = run_blackbox(
                repo,
                "<<<FILE: app.py>>>\nx = 1\n<<<END FILE>>>",
                self.pack,
                timeout=60,
            )
            self.assertFalse(bx.ran)
            self.assertEqual(bx.error, "black-box JUnit/exit mismatch")
            result = guard(
                repo,
                "<<<FILE: app.py>>>\nx = 1\n<<<END FILE>>>",
                verifier_pack=self.pack,
                blackbox=True,
                blackbox_only=True,
            )
            self.assertEqual(result.verdict, TAMPERED)
            self.assertEqual(result.reason_code, "junit_exit_mismatch")
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_pack_snapshot_drift_has_its_own_reason_code(self) -> None:
        repo = tempfile.mkdtemp(prefix="evo_pack_repo_")
        try:
            with open(os.path.join(repo, "app.py"), "w", encoding="utf-8") as f:
                f.write("x = 1\n")
            with mock.patch(
                "evoom_guard.verifiers.repo_verifier.verify_pack_snapshot",
                side_effect=PackManifestError("changed"),
            ):
                result = guard(
                    repo,
                    "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>",
                    test_command=[sys.executable, "-c", "raise SystemExit(0)"],
                    verifier_pack=self.pack,
                    mem_limit_mb=0,
                )
            self.assertEqual(result.verdict, TAMPERED)
            self.assertEqual(
                result.reason_code, "verifier_pack_snapshot_changed"
            )
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    @unittest.skipIf(sys.platform == "win32", "launcher regression uses POSIX execution")
    def test_blackbox_does_not_publish_the_pack_under_candidate_home(self) -> None:
        with open(os.path.join(self.pack, "test_protocol.py"), "w", encoding="utf-8") as f:
            f.write(
                "import os, subprocess, sys\n"
                "def test_pack_is_not_in_candidate_home():\n"
                "    py = os.environ.get('EVOGUARD_PYTHON') or sys.executable\n"
                "    ex = os.environ.get('EVOGUARD_EXEC')\n"
                "    cmd = [ex, py, 'probe.py'] if ex else [py, 'probe.py']\n"
                "    cwd = None if ex else os.environ['EVOGUARD_TARGET']\n"
                "    got = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)\n"
                "    assert got.stdout.strip() == 'SAFE'\n"
            )
        repo = tempfile.mkdtemp(prefix="evo_pack_repo_")
        try:
            with open(os.path.join(repo, "probe.py"), "w", encoding="utf-8") as f:
                f.write(
                    "from pathlib import Path\n"
                    "print('LEAK' if (Path.home() / 'pack' / "
                    "'test_protocol.py').exists() else 'SAFE')\n"
                )
            bx = run_blackbox(
                repo,
                "<<<FILE: note.txt>>>\nunchanged\n<<<END FILE>>>",
                self.pack,
                timeout=60,
            )
            self.assertTrue(bx.passed, bx.diagnostics)
            self.assertEqual((bx.tests_passed, bx.tests_total), (1, 1))
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_zero_collected_pack_tests_cannot_produce_pass(self) -> None:
        with open(os.path.join(self.pack, "test_protocol.py"), "w", encoding="utf-8") as f:
            f.write("# valid filename, but no test cases\n")
        repo = tempfile.mkdtemp(prefix="evo_pack_repo_")
        try:
            with open(os.path.join(repo, "app.py"), "w", encoding="utf-8") as f:
                f.write("x = 1\n")
            result = RepoVerifier(
                test_command=[sys.executable, "-c", "raise SystemExit(0)"],
                mem_limit_mb=0,
            ).verify(
                "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>",
                {"repo_path": repo, "verifier_pack": self.pack},
            )
            self.assertFalse(result.passed)
            self.assertEqual(result.artifact["verifier_pack_tests_total"], 0)
            if os.name != "nt":
                bx = run_blackbox(
                    repo,
                    "<<<FILE: app.py>>>\nx = 2\n<<<END FILE>>>",
                    self.pack,
                    timeout=60,
                )
                self.assertFalse(bx.passed)
                self.assertFalse(bx.ran)
                self.assertIn("no judge-owned test results", bx.error or "")
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

    def test_wrong_typed_optional_field_is_flagged_everywhere(self) -> None:
        self._write("test_protocol.py", PACK_TEST)
        self._write(
            "pack.json",
            json.dumps({"id": "p", "version": "1", "protocol": ["stdio"]}),
        )
        report = cli.validate_pack(self.pack)
        self.assertFalse(report["ok"])
        self.assertTrue(any("protocol" in p for p in report["problems"]))

    def test_shipped_example_packs_are_valid(self) -> None:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for rel in ("examples/blackbox-cli/pack", "examples/blackbox-pack"):
            with self.subTest(pack=rel):
                report = cli.validate_pack(os.path.join(root, rel))
                self.assertTrue(report["ok"], report["problems"])


if __name__ == "__main__":
    unittest.main()
