# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""v2.2 evidence layer: changed-line coverage, the Independent Verifier Pack,
and the attestation context block.

The core claims under test:

  * changed-line arithmetic is exact (FILE and PATCH blocks, new files);
  * a green suite that never EXECUTES the changed lines is exposed — and can be
    gated (``min_diff_coverage`` flips a hollow PASS to FAIL);
  * a pack test the patch cannot modify fails an overfitted patch even though
    the visible suite passes — and the candidate cannot pre-plant or write into
    the pack mount point;
  * the pack is tamper-proof but NOT secret — a documented limitation: code
    under test can read the pack off disk (guarded by an explicit test so the
    claim can never silently drift back to "hidden");
  * the attestation block binds the verdict to the candidate/policy digests and
    survives the signing roundtrip byte-for-byte.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from evoom_guard.evidence import changed_lines, collect_diff_coverage
from evoom_guard.guard import (
    FAIL,
    PASS,
    REASON_DIFF_COVERAGE_BELOW_THRESHOLD,
    REASON_PROTECTED_HARNESS_EDIT,
    guard,
)

try:
    import coverage  # noqa: F401
    HAVE_COVERAGE = True
except ImportError:  # pragma: no cover - environment dependent
    HAVE_COVERAGE = False


def _write(root: str, rel: str, content: str) -> None:
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path) or root, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


TWO_FUNCS = (
    "def covered(x):\n"
    "    return x + 1\n"
    "\n"
    "def uncovered(x):\n"
    "    return x - 1\n"
)

# The suite exercises covered() ONLY — uncovered() is a blind spot by design.
SUITE = (
    "from pkg.m import covered\n"
    "\n"
    "def test_covered():\n"
    "    assert covered(1) == 2\n"
)


def _repo(tmp: str) -> str:
    repo = os.path.join(tmp, "repo")
    _write(repo, "pkg/__init__.py", "")
    _write(repo, "pkg/m.py", TWO_FUNCS)
    _write(repo, "tests/test_m.py", SUITE)
    return repo


def _block(path: str, content: str) -> str:
    return f"<<<FILE: {path}>>>\n{content}<<<END FILE>>>\n"


class ChangedLinesTests(unittest.TestCase):
    def test_file_block_changed_lines_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            new = TWO_FUNCS.replace("return x - 1", "return x - 2")
            got = changed_lines(repo, _block("pkg/m.py", new))
            self.assertEqual(got, {"pkg/m.py": {5}})  # only the edited line

    def test_new_file_counts_every_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            got = changed_lines(repo, _block("pkg/new.py", "A = 1\nB = 2\n"))
            self.assertEqual(got, {"pkg/new.py": {1, 2}})

    def test_patch_block_lines_via_in_memory_apply(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            cand = (
                "<<<PATCH: pkg/m.py>>>\n<<<SEARCH>>>\n    return x - 1\n"
                "<<<REPLACE>>>\n    return x - 3\n<<<END PATCH>>>\n"
            )
            got = changed_lines(repo, cand)
            self.assertEqual(got, {"pkg/m.py": {5}})


@unittest.skipUnless(HAVE_COVERAGE, "needs the 'cov' extra (coverage)")
class DiffCoverageTests(unittest.TestCase):
    def test_unexecuted_change_is_exposed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            new = TWO_FUNCS.replace("return x - 1", "return x - 2")
            dc = collect_diff_coverage(repo, _block("pkg/m.py", new))
            self.assertTrue(dc["measured"])
            self.assertEqual(dc["executed"], 0)
            self.assertEqual(dc["total"], 1)
            self.assertEqual(dc["files"]["pkg/m.py"]["missed"], [5])
            self.assertIn("executed is not asserted", dc["caveat"])

    def test_executed_change_measures_full(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            new = TWO_FUNCS.replace("return x + 1", "return 1 + x")
            dc = collect_diff_coverage(repo, _block("pkg/m.py", new))
            self.assertTrue(dc["measured"])
            self.assertEqual((dc["executed"], dc["total"]), (1, 1))
            self.assertEqual(dc["percent"], 100.0)

    def test_comment_only_change_is_not_a_fake_gap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            new = TWO_FUNCS.replace(
                "def uncovered(x):", "def uncovered(x):  # a comment edit\n    # noqa"
            )
            dc = collect_diff_coverage(repo, _block("pkg/m.py", new))
            self.assertTrue(dc["measured"])
            # The pure-comment line must not appear in the denominator.
            self.assertNotIn(6, dc["files"].get("pkg/m.py", {}).get("missed", []))

    def test_min_diff_coverage_gates_a_hollow_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            new = TWO_FUNCS.replace("return x - 1", "return x - 2")
            r = guard(
                repo, _block("pkg/m.py", new),
                diff_coverage=True, min_diff_coverage=80.0,
            )
            self.assertEqual(r.verdict, FAIL)
            self.assertEqual(r.reason_code, REASON_DIFF_COVERAGE_BELOW_THRESHOLD)
            self.assertIn("unexercised", r.reason)

    def test_evidence_without_gate_keeps_the_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            new = TWO_FUNCS.replace("return x - 1", "return x - 2")
            r = guard(repo, _block("pkg/m.py", new), diff_coverage=True)
            self.assertEqual(r.verdict, PASS)  # evidence, not judgment
            self.assertIsNotNone(r.diff_coverage)
            assert r.diff_coverage is not None
            self.assertEqual(r.diff_coverage["executed"], 0)

    def test_degrades_explicitly_for_non_pytest_runners(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            new = TWO_FUNCS.replace("return x - 1", "return x - 2")
            dc = collect_diff_coverage(
                repo, _block("pkg/m.py", new), test_command=["make", "test"]
            )
            self.assertFalse(dc["measured"])
            self.assertIn("pytest", dc["note"])


class VerifierPackTests(unittest.TestCase):
    def _pack(self, tmp: str) -> str:
        pack = os.path.join(tmp, "pack")
        # The hidden invariant the visible suite never checks.
        _write(
            pack, "test_hidden_invariant.py",
            "from pkg.m import uncovered\n\n"
            "def test_uncovered_still_correct():\n"
            "    assert uncovered(5) == 4\n",
        )
        return pack

    def test_overfitted_patch_fails_the_hidden_pack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            # Visible suite still passes; the hidden invariant breaks.
            new = TWO_FUNCS.replace("return x - 1", "return x - 999")
            r = guard(repo, _block("pkg/m.py", new), verifier_pack=self._pack(tmp))
            self.assertEqual(r.verdict, FAIL)
            self.assertEqual((r.tests_passed, r.tests_total), (1, 2))

    def test_honest_patch_passes_pack_and_suite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            new = TWO_FUNCS.replace("return x + 1", "return 1 + x")
            r = guard(repo, _block("pkg/m.py", new), verifier_pack=self._pack(tmp))
            self.assertEqual(r.verdict, PASS)
            self.assertEqual((r.tests_passed, r.tests_total), (2, 2))
            assert r.attestation is not None
            self.assertTrue(r.attestation["verifier_pack_sha256"])
            self.assertTrue(r.to_dict()["test_command_ran"])
            assert r.assurance is not None
            self.assertNotEqual(r.assurance["overall_profile"], "static_gate")
            pack_assurance = r.assurance["verifier_pack"]
            assert pack_assurance is not None
            self.assertTrue(pack_assurance["present"])
            self.assertEqual(
                pack_assurance["integrity"], "verified_snapshot_pre_post"
            )

    def test_candidate_writing_into_the_mount_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            cand = _block(
                "evoguard_verifier_pack/test_hidden_invariant.py",
                "def test_uncovered_still_correct():\n    assert True\n",
            )
            r = guard(repo, cand, verifier_pack=self._pack(tmp))
            self.assertEqual(r.verdict, "REJECTED")
            self.assertEqual(r.reason_code, REASON_PROTECTED_HARNESS_EDIT)

    def test_pack_runs_without_diff_coverage_flag(self) -> None:
        # The pack is orthogonal to the coverage evidence: no coverage field set.
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            new = TWO_FUNCS.replace("return x + 1", "return 1 + x")
            r = guard(repo, _block("pkg/m.py", new), verifier_pack=self._pack(tmp))
            self.assertIsNone(r.diff_coverage)

    def test_pack_is_not_published_at_a_predictable_repo_path(self) -> None:
        # The accepted snapshot is outside the candidate tree and no longer exposed
        # at the old evoguard_verifier_pack/ path. Repo-native packs still are not a
        # secrecy boundary (candidate code shares the judge process); black-box plus
        # container isolation is required for that stronger property.
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            evil = (
                "import glob, re\n"
                "def uncovered(x):\n"
                "    for p in glob.glob('evoguard_verifier_pack/**/*.py', recursive=True):\n"
                "        m = re.search(r'uncovered\\((\\d+)\\)\\s*==\\s*(\\d+)', open(p).read())\n"
                "        if m and int(m.group(1)) == x:\n"
                "            return int(m.group(2))\n"
                "    return 0\n"
                "def covered(x):\n    return x + 1\n"
            )
            r = guard(repo, _block("pkg/m.py", evil), verifier_pack=self._pack(tmp))
            # The old direct lookup no longer reveals the accepted snapshot.
            self.assertEqual(r.verdict, FAIL)
            self.assertEqual((r.tests_passed, r.tests_total), (1, 2))

    def test_pack_manifest_lands_in_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            pack = self._pack(tmp)
            with open(os.path.join(pack, "pack.json"), "w", encoding="utf-8") as f:
                json.dump({"id": "org-invariants", "version": "1.3.0"}, f)
            new = TWO_FUNCS.replace("return x + 1", "return 1 + x")
            r = guard(repo, _block("pkg/m.py", new), verifier_pack=pack)
            assert r.attestation is not None
            self.assertEqual(
                r.attestation["verifier_pack_manifest"],
                {"id": "org-invariants", "version": "1.3.0"},
            )


class AttestationTests(unittest.TestCase):
    def test_attestation_binds_candidate_and_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            cand = _block("pkg/m.py", TWO_FUNCS.replace("x + 1", "1 + x"))
            r = guard(repo, cand, protected=("src/billing/*",))
            att = r.attestation
            assert att is not None
            import hashlib
            self.assertEqual(
                att["candidate_sha256"], hashlib.sha256(cand.encode()).hexdigest()
            )
            for key in ("created_utc", "guard_version", "policy_sha256", "junit_sha256"):
                self.assertTrue(att[key], key)
            # Policy digest must move when the policy moves.
            r2 = guard(repo, cand, protected=("other/*",))
            assert r2.attestation is not None
            self.assertNotEqual(att["policy_sha256"], r2.attestation["policy_sha256"])

    def test_attestation_is_inside_the_signed_json(self) -> None:
        try:
            import cryptography  # noqa: F401
        except ImportError:  # pragma: no cover - environment dependent
            self.skipTest("needs the 'sign' extra")
        from evoom_guard import cli

        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp)
            patch = os.path.join(tmp, "p.txt")
            with open(patch, "w", encoding="utf-8") as f:
                f.write(_block("pkg/m.py", TWO_FUNCS.replace("x + 1", "1 + x")))
            key, pub = os.path.join(tmp, "k.pem"), os.path.join(tmp, "k.pub")
            self.assertEqual(cli.main(["keygen", "--key", key, "--pub", pub]), 0)
            jout = os.path.join(tmp, "v.json")
            rc = cli.main([
                "guard", repo, "--patch", patch, "--json", jout,
                "--sign-key", key, "--report", os.path.join(tmp, "r.md"),
            ])
            self.assertEqual(rc, 0)
            with open(jout, encoding="utf-8") as f:
                payload = json.load(f)
            self.assertIn("attestation", payload)
            self.assertTrue(payload["attestation"]["candidate_sha256"])
            self.assertEqual(cli.main(["verify-verdict", jout, "--pub", pub]), 0)


class ReasonCodeAndRiskTests(unittest.TestCase):
    def test_timeout_is_test_timeout_not_patch_apply_failed(self) -> None:
        from evoom_guard.guard import REASON_TEST_TIMEOUT

        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            _write(repo, "pkg/__init__.py", "")
            _write(repo, "pkg/m.py", "def f():\n    return 1\n")
            _write(
                repo, "tests/test_slow.py",
                "import time\n\ndef test_slow():\n    time.sleep(30)\n",
            )
            r = guard(repo, _block("pkg/m.py", "def f():\n    return 2\n"), timeout=1)
            self.assertEqual(r.reason_code, REASON_TEST_TIMEOUT)
            self.assertNotEqual(r.reason_code, "patch_apply_failed")

    def test_deletion_raises_blast_radius(self) -> None:
        # Deleting a large source file must not read as lower risk than editing it.
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            _write(repo, "pkg/__init__.py", "")
            _write(repo, "pkg/big.py", "\n".join(f"x{i} = {i}" for i in range(300)) + "\n")
            _write(repo, "tests/test_x.py", "def test_ok():\n    assert True\n")
            # A no-op source addition + a big deletion.
            r = guard(
                repo, _block("pkg/note.py", "# note\n"),
                deleted=("pkg/big.py",),
            )
            self.assertEqual(r.risk_level, "high")  # 300 removed lines dominate


if __name__ == "__main__":
    unittest.main()
