# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Sole owner & author: Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""EvoOM Guard (EvoGuard) — the merge gate an AI agent can't game the test harness.

A reward-hack-resistant patch verification gate. Given a base repo and a candidate
change (an edit-block patch, a base/head pair, or a unified diff), it decides
whether the change fixes the repo **without gaming the tests**:

  * the verdict is read from a *judge-owned* JUnit report plus the process exit
    code — never from stdout — so a forged ``"N passed"`` cannot fool it;
  * any edit to the tests or their configuration is rejected *before* the suite
    runs, so an agent cannot pass by rewriting the harness.

The public surface is :func:`evoom_guard.guard.guard`, :func:`evoom_guard.guard.guard_from_diff`
and the ``evo-guard guard`` CLI. The core is stdlib-only.
"""

from evoom_guard.contracts import Problem, VerdictResult, Verifier

__all__ = ["Problem", "VerdictResult", "Verifier"]

__version__ = "2.2.1"
