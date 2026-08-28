# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ------------------------------------------------------------------------------
"""Trusted policy parsing and normalization interfaces."""

from evoom_guard.domain import (
    OPERATING_PROFILES,
    EffectivePolicy,
    is_verifier_pack_sha256,
    operating_profile_violations,
)
from evoom_guard.policy.config import ConfigError, load_config
from evoom_guard.policy.effective import (
    DEFAULT_TEST_COMMAND_MARKER,
    build_effective_policy,
    effective_policy_payload,
    effective_policy_sha256,
)
from evoom_guard.policy.harness import (
    HarnessInputPolicyError,
    harness_input_path_conflicts,
    is_harness_input_path,
    normalize_harness_inputs,
    setup_output_harness_conflicts,
)

__all__ = (
    "DEFAULT_TEST_COMMAND_MARKER",
    "ConfigError",
    "EffectivePolicy",
    "HarnessInputPolicyError",
    "harness_input_path_conflicts",
    "OPERATING_PROFILES",
    "build_effective_policy",
    "effective_policy_payload",
    "effective_policy_sha256",
    "is_verifier_pack_sha256",
    "is_harness_input_path",
    "load_config",
    "normalize_harness_inputs",
    "operating_profile_violations",
    "setup_output_harness_conflicts",
)
