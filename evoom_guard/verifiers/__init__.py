# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ─────────────────────────────────────────────────────────────────────────────
"""Verifiers used by the guard.

``RepoVerifier`` is the security-critical judge: it applies a patch to a throwaway
copy, runs the repo's test command, and reads the verdict from a judge-owned JUnit
report + the process exit code (not stdout). ``fraction_score`` (in ``grading``)
provides the partial-credit gradient it reuses.
"""

from evoom_guard.verifiers.grading import fraction_score
from evoom_guard.verifiers.repo_verifier import RepoVerifier

__all__ = ["RepoVerifier", "fraction_score"]
