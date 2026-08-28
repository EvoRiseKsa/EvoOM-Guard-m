# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# -----------------------------------------------------------------------------
"""Canonical construction and serialization of effective Guard policy."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

from evoom_guard.domain import EffectivePolicy
from evoom_guard.policy.harness import normalize_harness_inputs

DEFAULT_TEST_COMMAND_MARKER = "default:python -m pytest"


def build_effective_policy(
    *,
    mode: str,
    isolation: str,
    docker_image: str | None,
    docker_network: str,
    test_command: list[str] | None,
    setup_command: list[str] | None,
    trust_setup_on_host: bool,
    setup_output_globs: tuple[str, ...],
    protected: tuple[str, ...],
    allow: tuple[str, ...],
    allow_new_tests: bool,
    timeout: int,
    mem_limit_mb: int,
    verifier_pack: str | None,
    expect_verifier_pack_sha256: str | None,
    blackbox: bool,
    blackbox_only: bool,
    require_report_integrity: str | None,
    require_candidate_isolation: str | None,
    min_diff_coverage: float | None,
    baseline_evidence: bool,
    require_demonstrated_fix: bool,
    strict_harness: bool,
    policy_id: str | None,
    policy_version: str | None,
    operating_profile: str | None = None,
    harness_inputs: tuple[str, ...] = (),
) -> EffectivePolicy:
    """Build the immutable value behind the versioned verdict-policy payload.

    Callers remain responsible for input validation. Keeping validation outside
    this constructor preserves Guard's historical exception timing and text.
    """

    return EffectivePolicy(
        mode=mode,
        isolation=isolation,
        docker_image=docker_image,
        docker_network=docker_network,
        test_command=tuple(test_command) if test_command else None,
        setup_command=tuple(setup_command) if setup_command else None,
        trust_setup_on_host=trust_setup_on_host,
        setup_output_globs=tuple(sorted(setup_output_globs)),
        protected=tuple(sorted(protected)),
        allow=tuple(sorted(allow)),
        allow_new_tests=allow_new_tests,
        timeout=timeout,
        mem_limit_mb=mem_limit_mb,
        verifier_pack_required=bool(verifier_pack),
        expect_verifier_pack_sha256=(
            expect_verifier_pack_sha256.lower()
            if expect_verifier_pack_sha256
            else None
        ),
        blackbox=blackbox,
        blackbox_only=blackbox_only,
        require_report_integrity=require_report_integrity,
        require_candidate_isolation=require_candidate_isolation,
        min_diff_coverage=(
            float(min_diff_coverage)
            if min_diff_coverage is not None
            else None
        ),
        baseline_evidence=baseline_evidence,
        require_demonstrated_fix=require_demonstrated_fix,
        strict_harness=strict_harness,
        policy_id=policy_id,
        policy_version=policy_version,
        operating_profile=operating_profile,
        harness_inputs=normalize_harness_inputs(harness_inputs),
    )


def effective_policy_payload(policy: EffectivePolicy) -> dict[str, object]:
    """Return the exact ordered payload used by the 1.11/1.12 contracts."""

    payload: dict[str, object] = {
        "mode": policy.mode,
        "isolation": policy.isolation,
        "docker_image": policy.docker_image,
        "docker_network": policy.docker_network,
        "test_command": (
            list(policy.test_command)
            if policy.test_command
            else DEFAULT_TEST_COMMAND_MARKER
        ),
        "setup_command": list(policy.setup_command) if policy.setup_command else None,
        "trust_setup_on_host": policy.trust_setup_on_host,
        "setup_output_globs": list(policy.setup_output_globs),
        "protected": list(policy.protected),
        "allow": list(policy.allow),
        "allow_new_tests": policy.allow_new_tests,
        "timeout": policy.timeout,
        "mem_limit_mb": policy.mem_limit_mb,
        "verifier_pack_required": policy.verifier_pack_required,
        "expect_verifier_pack_sha256": policy.expect_verifier_pack_sha256,
        "blackbox": policy.blackbox,
        "blackbox_only": policy.blackbox_only,
        "require_report_integrity": policy.require_report_integrity,
        "require_candidate_isolation": policy.require_candidate_isolation,
        "min_diff_coverage": policy.min_diff_coverage,
        "baseline_evidence": policy.baseline_evidence,
        "require_demonstrated_fix": policy.require_demonstrated_fix,
        "strict_harness": policy.strict_harness,
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
    }
    # Profiles belong to schema 1.12. Omitting an unselected profile preserves
    # the exact 1.11 payload and every historical policy digest; selecting one
    # makes it part of the signed/hashed 1.12 policy contract.
    if policy.operating_profile is not None:
        payload["operating_profile"] = policy.operating_profile
    if policy.harness_inputs:
        payload["harness_inputs"] = list(policy.harness_inputs)
    return payload


def effective_policy_sha256(policy: Mapping[str, object]) -> str:
    """Return the frozen JSON fingerprint used by Guard attestations."""

    encoded = json.dumps(policy, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
