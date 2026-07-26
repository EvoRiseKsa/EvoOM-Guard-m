# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Evidence-bound verification for untrusted software changes.

AI-generated patches are the primary use case, but the mechanism does not depend
on authorship. Given a base repo and a candidate change (an edit-block patch, a
base/head pair, or a unified diff), it decides whether the change satisfies the
selected judge while blocking the explicitly modelled evidence-gaming paths:

  * the verdict is read from a *judge-owned* JUnit report plus the process exit
    code — never from stdout — so a forged ``"N passed"`` cannot fool it;
  * any edit to the tests or their configuration is rejected *before* the suite
    runs, so an agent cannot pass by rewriting the harness.

The public surface is :func:`evoom_guard.guard.guard`, :func:`evoom_guard.guard.guard_from_diff`
and the ``evo-guard guard`` CLI. The core is stdlib-only.
"""

from evoom_guard.contracts import Problem, VerdictResult, Verifier

__all__ = ["Problem", "VerdictResult", "Verifier"]

__version__ = "4.4.0"

# These schemas retain their v3.8.0 identities until their contracts change.
# A schema identity denotes its stable shape, not the runtime version carrying it.
SCHEMA_ID_RELEASE = "3.8.0"
