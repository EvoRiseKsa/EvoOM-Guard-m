# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""The shipped HTTP black-box recipe must keep working end-to-end.

Runs the real judge over examples/blackbox-http: the pack reaches the candidate
ONLY over localhost HTTP (launched via $EVOGUARD_EXEC), so an in-process
forgery — fake stdout, atexit + os._exit(0) — lands inside the server process
and moves nothing.
"""

from __future__ import annotations

import os
import unittest

from evoom_guard.guard import FAIL, PASS, guard

HAS_PYTEST = True
try:
    import pytest as _pytest  # noqa: F401
except ImportError:  # pragma: no cover
    HAS_PYTEST = False

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EX = os.path.join(ROOT, "examples", "blackbox-http")


def _read(rel: str) -> str:
    with open(os.path.join(EX, rel), encoding="utf-8") as f:
        return f.read()


@unittest.skipUnless(os.name == "posix", "the launcher exec path is POSIX-tested")
@unittest.skipUnless(HAS_PYTEST, "the judge runs pytest")
class HttpBlackboxExampleTests(unittest.TestCase):
    def test_honest_fix_passes_over_http(self) -> None:
        r = guard(
            os.path.join(EX, "sample_repo"), _read("patches/honest.txt"),
            verifier_pack=os.path.join(EX, "pack"), blackbox=True, timeout=120,
        )
        self.assertEqual(r.verdict, PASS, r.reason + " | " + r.diagnostics[:300])
        assert r.attestation is not None
        self.assertEqual(
            r.attestation["verifier_pack_manifest"]["id"], "calc-http-protocol"
        )

    def test_in_process_forgery_fails_over_http(self) -> None:
        r = guard(
            os.path.join(EX, "sample_repo"), _read("patches/cheat.txt"),
            verifier_pack=os.path.join(EX, "pack"), blackbox=True, timeout=120,
        )
        self.assertEqual(r.verdict, FAIL, r.reason)


if __name__ == "__main__":
    unittest.main()
