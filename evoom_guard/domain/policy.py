# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Dependency-free effective-policy domain contract."""

from __future__ import annotations

import re
from dataclasses import dataclass

OPERATING_PROFILES = ("local", "protected", "hostile")
_SHA256_HEX = re.compile(r"[0-9a-fA-F]{64}\Z")


def is_verifier_pack_sha256(value: object) -> bool:
    """Return whether ``value`` is one complete hexadecimal SHA-256 pin."""

    return isinstance(value, str) and _SHA256_HEX.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class EffectivePolicy:
    """Immutable policy values that shape one Guard judgment.

    This is a domain value only. Canonical wire representation, hashing, and
    trusted-input validation belong to the policy and schema layers.
    """

    mode: str
    isolation: str
    docker_image: str | None
    docker_network: str
    test_command: tuple[str, ...] | None
    setup_command: tuple[str, ...] | None
    trust_setup_on_host: bool
    setup_output_globs: tuple[str, ...]
    protected: tuple[str, ...]
    allow: tuple[str, ...]
    allow_new_tests: bool
    timeout: int
    mem_limit_mb: int
    verifier_pack_required: bool
    expect_verifier_pack_sha256: str | None
    blackbox: bool
    blackbox_only: bool
    require_report_integrity: str | None
    require_candidate_isolation: str | None
    min_diff_coverage: float | None
    baseline_evidence: bool
    require_demonstrated_fix: bool
    strict_harness: bool
    policy_id: str | None
    policy_version: str | None
    operating_profile: str | None = None
    harness_inputs: tuple[str, ...] = ()


def operating_profile_violations(
    operating_profile: str | None,
    *,
    isolation: str,
    docker_image_present: bool,
    docker_network: str,
    setup_command_present: bool,
    trust_setup_on_host: bool,
    mem_limit_mb: int,
    verifier_pack_required: bool,
    expect_verifier_pack_sha256: str | None,
    blackbox: bool,
    blackbox_only: bool,
    require_report_integrity: str | None,
    require_candidate_isolation: str | None,
) -> tuple[str, ...]:
    """Return contradictions in an explicitly selected operating profile.

    This is the producer-side policy predicate in the dependency-free domain
    layer. The offline record verifier deliberately re-derives the versioned
    profile rules in its own verifier-layer implementation.
    """

    if operating_profile is None:
        return ()
    if not isinstance(operating_profile, str) or operating_profile not in (
        OPERATING_PROFILES
    ):
        return (
            "operating_profile must be one of "
            + ", ".join(repr(value) for value in OPERATING_PROFILES),
        )
    if operating_profile == "local":
        return ()

    violations: list[str] = []
    if not blackbox:
        violations.append("requires blackbox=true")
    if not blackbox_only:
        violations.append("requires blackbox_only=true")
    if setup_command_present:
        violations.append("forbids setup_command in black-box-only mode")
    if trust_setup_on_host:
        violations.append("requires trust_setup_on_host=false")
    if not verifier_pack_required:
        violations.append("requires a verifier_pack")
    if not is_verifier_pack_sha256(expect_verifier_pack_sha256):
        violations.append("requires expect_verifier_pack_sha256")
    if require_report_integrity != "external_process_isolated":
        violations.append(
            "requires require_report_integrity='external_process_isolated'"
        )
    if docker_network != "none":
        violations.append("requires docker_network='none'")
    if not docker_image_present:
        violations.append("requires docker_image")

    if operating_profile == "protected":
        if isolation not in {"docker", "gvisor"}:
            violations.append("requires isolation='docker' or 'gvisor'")
        if require_candidate_isolation != isolation:
            violations.append(
                "requires require_candidate_isolation to match isolation"
            )
    else:
        if isolation != "gvisor":
            violations.append("requires isolation='gvisor'")
        if require_candidate_isolation != "gvisor":
            violations.append("requires require_candidate_isolation='gvisor'")
        if mem_limit_mb <= 0:
            violations.append("requires a non-zero mem_limit")
    return tuple(violations)


__all__ = [
    "EffectivePolicy",
    "OPERATING_PROFILES",
    "is_verifier_pack_sha256",
    "operating_profile_violations",
]
