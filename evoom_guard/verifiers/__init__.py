# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
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
