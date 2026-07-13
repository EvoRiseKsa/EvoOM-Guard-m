# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Cross-mode policy consistency (schema 1.9) — no requested gate is ever
silently dropped.

An external review of v3.3.0 found the exact failure this file pins: the new
gates (``require_demonstrated_fix``, ``min_diff_coverage``) ran only under the
subprocess judge, but nothing stopped a caller from combining them with
black-box or container isolation — the requirement was then skipped and a PASS
could ship WITHOUT the check the caller explicitly demanded (fail-open). The
1.7 contract: an unenforceable GATE is ``ERROR policy_requirement_unsupported``;
an unenforceable EVIDENCE request degrades explicitly (an unmeasured record
with a note), never silently. And ``policy_sha256`` now covers the COMPLETE
effective policy, so two materially different policies can no longer share a
fingerprint.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

from evoom_guard.guard import ERROR, PASS, SCHEMA_VERSION, guard

HAS_PYTEST = True
try:
    import pytest as _pytest  # noqa: F401
except ImportError:  # pragma: no cover
    HAS_PYTEST = False

TEST_CMD = [sys.executable, "-m", "pytest", "-q", "--color=no", "-p", "no:cacheprovider"]
SAFE = "<<<FILE: app.py>>>\nx = 1\n<<<END FILE>>>"


def _make_repo(root: str) -> None:
    os.makedirs(os.path.join(root, "tests"))
    with open(os.path.join(root, "app.py"), "w", encoding="utf-8") as f:
        f.write("x = 1\n")
    with open(os.path.join(root, "tests", "test_app.py"), "w", encoding="utf-8") as f:
        f.write("import app\n\ndef test_x():\n    assert app.x == 1\n")


class UnsupportedGateFailsClosedTests(unittest.TestCase):
    """A gate the selected judge cannot enforce must ERROR — before anything runs."""

    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="evo_polc_")
        _make_repo(self.root)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _expect_unsupported(self, **kwargs) -> None:
        r = guard(self.root, SAFE, test_command=TEST_CMD, timeout=60, **kwargs)
        self.assertEqual(r.verdict, ERROR, r.reason)
        self.assertEqual(r.reason_code, "policy_requirement_unsupported")
        self.assertIsNone(r.verdict_source)  # nothing ran

    def test_require_demonstrated_fix_with_docker_errors(self) -> None:
        # No docker daemon needed: the policy check fires before any isolation
        # is even probed — that is the point (fail-fast, fail-closed).
        self._expect_unsupported(require_demonstrated_fix=True, isolation="docker")

    def test_require_demonstrated_fix_with_gvisor_errors(self) -> None:
        self._expect_unsupported(require_demonstrated_fix=True, isolation="gvisor")

    def test_require_demonstrated_fix_with_blackbox_errors(self) -> None:
        # No verifier pack needed either — the check precedes the blackbox path.
        self._expect_unsupported(require_demonstrated_fix=True, blackbox=True)

    def test_min_diff_coverage_with_docker_errors(self) -> None:
        self._expect_unsupported(min_diff_coverage=80.0, isolation="docker")

    def test_min_diff_coverage_with_blackbox_errors(self) -> None:
        self._expect_unsupported(min_diff_coverage=80.0, blackbox=True)

    def test_blackbox_setup_is_rejected_instead_of_silently_ignored(self) -> None:
        self._expect_unsupported(
            blackbox=True, setup_command=[sys.executable, "-c", "pass"]
        )

    @unittest.skipUnless(HAS_PYTEST, "pytest runs the suite")
    def test_supported_combination_still_passes(self) -> None:
        r = guard(self.root, SAFE, test_command=TEST_CMD, timeout=120,
                  require_demonstrated_fix=False, baseline_evidence=True)
        self.assertEqual(r.verdict, PASS, r.reason)


@unittest.skipUnless(HAS_PYTEST, "pytest runs the suite")
class EffectivePolicyHashTests(unittest.TestCase):
    """policy_sha256 must commit to the WHOLE policy, not five fields."""

    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="evo_polh_")
        _make_repo(self.root)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def _sha(self, **kwargs) -> str:
        r = guard(self.root, SAFE, test_command=TEST_CMD, timeout=120, **kwargs)
        assert r.attestation is not None
        return r.attestation["policy_sha256"]

    def test_assurance_floor_changes_the_fingerprint(self) -> None:
        # Pre-1.7 these two hashed IDENTICALLY — a verify-verdict
        # --expect-policy-sha proved less than it appeared to.
        base = self._sha()
        floored = self._sha(require_report_integrity="same_process_candidate_writable")
        self.assertNotEqual(base, floored)

    def test_min_diff_coverage_changes_the_fingerprint(self) -> None:
        self.assertNotEqual(self._sha(), self._sha(min_diff_coverage=80.0))

    def test_demonstrated_fix_gate_changes_the_fingerprint(self) -> None:
        self.assertNotEqual(self._sha(), self._sha(require_demonstrated_fix=True))

    def test_policy_identity_changes_the_fingerprint(self) -> None:
        self.assertNotEqual(self._sha(), self._sha(policy_id="org/prod"))

    def test_setup_boundary_changes_the_fingerprint(self) -> None:
        self.assertNotEqual(self._sha(), self._sha(trust_setup_on_host=True))

    def test_setup_output_contract_changes_the_fingerprint(self) -> None:
        self.assertNotEqual(
            self._sha(), self._sha(setup_output_globs=("generated/**",))
        )

    def test_expected_pack_identity_changes_the_fingerprint(self) -> None:
        self.assertNotEqual(
            self._sha(), self._sha(expect_verifier_pack_sha256="a" * 64)
        )

    def test_effective_policy_ships_in_the_attestation(self) -> None:
        r = guard(self.root, SAFE, test_command=TEST_CMD, timeout=120,
                  min_diff_coverage=None, policy_id="org/prod", policy_version="2")
        assert r.attestation is not None
        ep = r.attestation["effective_policy"]
        for key in (
            "mode", "isolation", "protected", "allow", "allow_new_tests",
            "test_command", "setup_command", "trust_setup_on_host",
            "setup_output_globs", "timeout", "mem_limit_mb",
            "expect_verifier_pack_sha256",
            "require_report_integrity", "require_candidate_isolation",
            "min_diff_coverage", "baseline_evidence", "require_demonstrated_fix",
            "blackbox", "blackbox_only", "verifier_pack_required",
            "docker_image", "docker_network", "policy_id", "policy_version",
        ):
            self.assertIn(key, ep, f"effective_policy missing {key!r}")
        self.assertEqual(ep["policy_id"], "org/prod")
        self.assertEqual(r.to_dict()["schema_version"], SCHEMA_VERSION)


@unittest.skipUnless(HAS_PYTEST, "pytest runs the suite")
class ExplicitEvidenceDegradationTests(unittest.TestCase):
    """Evidence-only requests in unsupported modes degrade LOUDLY, not silently."""

    @unittest.skipIf(os.name == "nt", "black-box subprocess launcher requires POSIX")
    def test_blackbox_baseline_request_yields_unmeasured_record(self) -> None:
        # A real (trivial) judge-owned pack, subprocess black-box: the verdict
        # works, and the baseline request comes back as an explicit unmeasured
        # record instead of disappearing.
        root = tempfile.mkdtemp(prefix="evo_polbx_")
        pack = tempfile.mkdtemp(prefix="evo_polbx_pack_")
        try:
            _make_repo(root)
            with open(os.path.join(pack, "test_protocol.py"), "w", encoding="utf-8") as f:
                f.write("def test_trivial():\n    assert True\n")
            r = guard(
                root, SAFE, test_command=TEST_CMD, timeout=120,
                blackbox=True, blackbox_only=True, verifier_pack=pack,
                baseline_evidence=True,
            )
            self.assertEqual(r.verdict, PASS, r.reason)
            assert r.baseline is not None
            self.assertEqual(r.baseline["repair_effect"], "unmeasured")
            self.assertEqual(r.baseline["scope"], "unsupported_mode")
            self.assertIn("subprocess repo judge only", r.baseline["note"])
        finally:
            shutil.rmtree(root, ignore_errors=True)
            shutil.rmtree(pack, ignore_errors=True)

    def test_subprocess_baseline_records_repo_suite_scope(self) -> None:
        root = tempfile.mkdtemp(prefix="evo_polsc_")
        try:
            _make_repo(root)
            r = guard(root, SAFE, test_command=TEST_CMD, timeout=120,
                      baseline_evidence=True)
            self.assertEqual(r.verdict, PASS, r.reason)
            assert r.baseline is not None
            self.assertEqual(r.baseline["scope"], "repo_suite_only")
        finally:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
