# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Guard the composite Action's candidate-job authority boundary."""

from __future__ import annotations

import os
import unittest

ACTION_YML = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "action.yml",
)
class ActionCommentAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        with open(ACTION_YML, encoding="utf-8") as f:
            self.text = f.read()

    def test_composite_action_has_no_pr_write_primitive(self) -> None:
        self.assertNotIn("actions/github-script@", self.text)
        self.assertNotIn("pull-requests: write", self.text)
        self.assertNotIn("createComment", self.text)
        self.assertNotIn("updateComment", self.text)

    def test_legacy_comment_input_is_safe_by_default_and_refused(self) -> None:
        block = self.text[
            self.text.index("\n  comment:") : self.text.index("\n  fail-on:")
        ]
        self.assertIn('default: "false"', block)
        refusal = self.text.index("- name: Refuse in-job PR commenting")
        candidate = self.text.index("- name: Run EvoGuard")
        self.assertLess(refusal, candidate)
        self.assertIn("inputs.comment == 'true'", self.text[refusal:candidate])
        self.assertIn("exit 2", self.text[refusal:candidate])

    def test_persisted_checkout_auth_is_rejected_before_candidate_execution(self) -> None:
        refusal = self.text.index("- name: Refuse persisted checkout credentials")
        candidate = self.text.index("- name: Run EvoGuard")
        self.assertLess(refusal, candidate)
        guard = self.text[refusal:candidate]
        self.assertIn("git config --includes --show-origin --get-regexp", guard)
        self.assertIn(r"^http\..*\.extraheader$", guard)
        self.assertNotIn("git config --local", guard)
        self.assertIn(
            "GIT_ASKPASS SSH_ASKPASS SSH_AUTH_SOCK GH_TOKEN GITHUB_TOKEN",
            guard,
        )
        self.assertIn(r"^https?://[^/@]+@", guard)
        self.assertIn("persist-credentials: false", guard)
        self.assertIn(">/dev/null 2>&1", guard)
        self.assertIn('case "$config_status" in', guard)
        self.assertIn("could not safely inspect Git config", guard)
        self.assertIn("git config exited $config_status", guard)
        self.assertRegex(guard, r"(?ms)1\)\s+return 0\s+;;")
        self.assertRegex(guard, r"(?ms)\*\)\s+echo .*?\s+exit 2\s+;;")

    def test_report_remains_available_without_api_authority(self) -> None:
        self.assertIn("\n  report-path:", self.text)
        self.assertIn('cat "$RUNNER_TEMP/guard-report.md"', self.text)
        self.assertIn("<details><summary>Detailed Guard report</summary>", self.text)


class ActionCliParityTests(unittest.TestCase):
    """Every gate-relevant CLI flag must be reachable from the Action (issue: the
    v1.7.0 'Action ↔ CLI parity' goal). Each input below must be *declared* and
    *forwarded* as the matching ``--flag`` — so a new CLI flag can't ship without
    being exposed in the Action (which is how ``--docker-network`` slipped through
    in v1.8.0 before this guard)."""

    # input-name == CLI flag name (the Action forwards inputs.<name> as --<name>).
    FORWARDED = (
        "test-command", "protected", "allow", "allow-new-tests",
        "isolation", "docker-image", "docker-network", "operating-profile",
        "timeout", "mem-limit", "sarif",
        # v2.2 evidence flags — a Marketplace user must be able to reach them.
        "verifier-pack", "blackbox", "require-report-integrity", "require-candidate-isolation", "diff-coverage", "min-diff-coverage",
        # v3.3 differential evidence — the before/after counterfactual.
        "baseline-evidence", "require-demonstrated-fix",
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
