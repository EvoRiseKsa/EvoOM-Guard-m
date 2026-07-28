# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Canonical, non-exemptible inputs for repository-native test commands.

Conventional tests and runner configuration are covered by the built-in
harness policy. A custom repository-local command wrapper is ambiguous,
however: the same ``python src/cli.py`` token can mean either the program under
test or a judge-owned wrapper. EvoGuard therefore never guesses. A trusted
policy explicitly lists every judge-owned wrapper/helper file in
``harness_inputs``; those exact files are policy-digest-bound and cannot be
waived by the ordinary candidate allowlist.
"""

from evoom_guard.domain.harness import (
    HarnessInputPolicyError,
    harness_input_path_conflicts,
    is_harness_input_path,
    is_portable_repo_path,
    is_windows_ambiguous_path_segment,
    normalize_harness_inputs,
    setup_output_harness_conflicts,
)

__all__ = [
    "HarnessInputPolicyError",
    "harness_input_path_conflicts",
    "is_harness_input_path",
    "is_portable_repo_path",
    "is_windows_ambiguous_path_segment",
    "normalize_harness_inputs",
    "setup_output_harness_conflicts",
]
