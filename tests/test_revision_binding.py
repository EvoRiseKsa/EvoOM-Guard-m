# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Exact-revision binding + context-aware verify-verdict (schema 1.6).

A signed verdict used to prove only "these bytes did not change" — in the
common Action path (a plain ``git diff``, which carries no commit identity) it
was NOT bound to the commit being merged, and the repo-native attestation
dropped base/head entirely (they were wired only through the black-box path).
These tests pin the fixed contract:

* repo-native attestations carry base/head COMMIT and TREE SHAs plus the
  policy identity;
* ``verify-verdict --expect-head-sha/--expect-policy-sha/...`` fails a verdict
  whose signature is valid but whose context is wrong — chain of custody, not
  just file integrity.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest

from evoom_guard import cli
from evoom_guard.guard import PASS, guard, write_json

HAS_PYTEST = True
try:
    import pytest as _pytest  # noqa: F401
except ImportError:  # pragma: no cover
    HAS_PYTEST = False
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: F401
    HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    HAS_CRYPTO = False

TEST_CMD = [sys.executable, "-m", "pytest", "-q", "--color=no", "-p", "no:cacheprovider"]
HEAD = "a" * 40
BASE = "b" * 40


def _make_repo(root: str) -> None:
    os.makedirs(os.path.join(root, "tests"))
    with open(os.path.join(root, "app.py"), "w", encoding="utf-8") as f:
        f.write("x = 1\n")
    with open(os.path.join(root, "tests", "test_app.py"), "w", encoding="utf-8") as f:
        f.write("import app\n\ndef test_x():\n    assert app.x == 1\n")


@unittest.skipUnless(HAS_PYTEST, "pytest needed to run the suite")
class RepoModeRevisionBindingTests(unittest.TestCase):
    def test_repo_native_attestation_carries_revision_and_policy(self) -> None:
        root = tempfile.mkdtemp(prefix="evo_bind_")
        try:
            _make_repo(root)
            r = guard(
                root, "<<<FILE: app.py>>>\nx = 1\n<<<END FILE>>>",
                test_command=TEST_CMD, timeout=120,
                base_sha=BASE, head_sha=HEAD,
                base_tree_sha="c" * 40, head_tree_sha="d" * 40,
                policy_id="org/prod", policy_version="7",
            )
            self.assertEqual(r.verdict, PASS, r.reason)
            att = r.attestation or {}
            self.assertEqual(att["base_sha"], BASE)
            self.assertEqual(att["head_sha"], HEAD)
            self.assertEqual(att["base_tree_sha"], "c" * 40)
            self.assertEqual(att["head_tree_sha"], "d" * 40)
            self.assertEqual(att["policy_id"], "org/prod")
            self.assertEqual(att["policy_version"], "7")
        finally:
            shutil.rmtree(root, ignore_errors=True)


@unittest.skipUnless(HAS_PYTEST and HAS_CRYPTO, "needs pytest + the sign extra")
class ContextAwareVerifyTests(unittest.TestCase):
    """End-to-end: sign a real verdict, then verify signature AND context."""

    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="evo_ctx_")
        self.repo = os.path.join(self.dir, "repo")
        os.makedirs(self.repo)
        _make_repo(self.repo)
        self.key = os.path.join(self.dir, "k.pem")
        self.pub = os.path.join(self.dir, "k.pub")
        from evoom_guard.signing import generate_keypair, sign_file
        generate_keypair(self.key, self.pub)
        result = guard(
            self.repo, "<<<FILE: app.py>>>\nx = 1\n<<<END FILE>>>",
            test_command=TEST_CMD, timeout=120,
            base_sha=BASE, head_sha=HEAD, policy_id="org/prod",
        )
        self.verdict_path = os.path.join(self.dir, "verdict.json")
        write_json(result, self.verdict_path)
        sign_file(self.verdict_path, self.key)
        with open(self.verdict_path, encoding="utf-8") as f:
            self.policy_sha = json.load(f)["attestation"]["policy_sha256"]

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_matching_context_passes(self) -> None:
        code = cli.main([
            "verify-verdict", self.verdict_path, "--pub", self.pub,
            "--expect-head-sha", HEAD,
            "--expect-base-sha", BASE,
            "--expect-policy-id", "org/prod",
            "--expect-policy-sha", self.policy_sha,
        ])
        self.assertEqual(code, 0)

    def test_valid_signature_wrong_commit_fails(self) -> None:
        # The whole point: perfectly signed, but for a DIFFERENT commit.
        code = cli.main([
            "verify-verdict", self.verdict_path, "--pub", self.pub,
            "--expect-head-sha", "f" * 40,
        ])
        self.assertEqual(code, 1)

    def test_valid_signature_wrong_policy_fails(self) -> None:
        code = cli.main([
            "verify-verdict", self.verdict_path, "--pub", self.pub,
            "--expect-policy-sha", "0" * 64,
        ])
        self.assertEqual(code, 1)

    def test_no_expectations_stays_signature_only(self) -> None:
        code = cli.main(["verify-verdict", self.verdict_path, "--pub", self.pub])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
