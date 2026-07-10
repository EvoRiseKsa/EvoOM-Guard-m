# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Sole owner & author: Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""Guard the EvoGuard Action's *sticky* PR-comment behaviour (issue #16).

The Action must update one EvoGuard comment per PR (keyed on a stable hidden
marker) instead of appending a fresh comment on every run. This is a cheap text
assertion on ``action.yml`` so the upsert logic can't silently regress back to an
unconditional ``createComment`` — it does not run the Action (that is covered by
live validation). Stdlib-only.
"""

from __future__ import annotations

import os
import unittest

ACTION_YML = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "action.yml",
)
MARKER = "<!-- evoguard-report -->"


class ActionStickyCommentTests(unittest.TestCase):
    def setUp(self) -> None:
        with open(ACTION_YML, encoding="utf-8") as f:
            self.text = f.read()

    def test_uses_stable_marker(self) -> None:
        self.assertIn(MARKER, self.text)

    def test_upserts_instead_of_always_creating(self) -> None:
        # Must look up existing comments, update on a hit, create only as fallback.
        self.assertIn("listComments", self.text)
        self.assertIn("updateComment", self.text)
        self.assertIn("createComment", self.text)  # the no-prior-comment fallback

    def test_finds_prior_comment_by_marker(self) -> None:
        # The lookup must key off the marker, not a brittle title match.
        self.assertIn("includes(MARKER)", self.text)


class ActionCliParityTests(unittest.TestCase):
    """Every gate-relevant CLI flag must be reachable from the Action (issue: the
    v1.7.0 'Action ↔ CLI parity' goal). Each input below must be *declared* and
    *forwarded* as the matching ``--flag`` — so a new CLI flag can't ship without
    being exposed in the Action (which is how ``--docker-network`` slipped through
    in v1.8.0 before this guard)."""

    # input-name == CLI flag name (the Action forwards inputs.<name> as --<name>).
    FORWARDED = (
        "test-command", "protected", "allow", "allow-new-tests",
        "isolation", "docker-image", "docker-network",
        "timeout", "mem-limit", "sarif",
        # v2.2 evidence flags — a Marketplace user must be able to reach them.
        "verifier-pack", "diff-coverage", "min-diff-coverage",
    )

    def setUp(self) -> None:
        with open(ACTION_YML, encoding="utf-8") as f:
            self.text = f.read()

    def test_each_flag_is_declared_and_forwarded(self) -> None:
        for name in self.FORWARDED:
            with self.subTest(input=name):
                self.assertIn(f"\n  {name}:", self.text, f"input '{name}' not declared")
                self.assertIn(f"inputs.{name}", self.text, f"input '{name}' not used")
                self.assertIn(f"--{name}", self.text, f"flag '--{name}' not forwarded")


if __name__ == "__main__":
    unittest.main()
