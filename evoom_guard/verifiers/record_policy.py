# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Verifier-owned operating-profile semantics.

This module intentionally does not import the producer's policy predicate.
Sharing immutable vocabulary is acceptable, but sharing the decision function
would let one defect bless the same false claim on both sides of the record.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PROFILES = frozenset({"local", "protected", "hostile"})


def check_operating_profile(policy: Mapping[str, object]) -> tuple[str, ...]:
    """Re-derive schema-1.12 profile contradictions from raw policy data."""

    profile = policy.get("operating_profile")
    if not isinstance(profile, str) or profile not in _PROFILES:
        return ()
    if profile == "local":
        return ()

    errors: list[str] = []
    if policy.get("blackbox") is not True:
        errors.append("requires blackbox=true")
    if policy.get("blackbox_only") is not True:
        errors.append("requires blackbox_only=true")
    if policy.get("setup_command") is not None:
        errors.append("forbids setup_command in black-box-only mode")
    if policy.get("trust_setup_on_host") is not False:
        errors.append("requires trust_setup_on_host=false")
    if policy.get("verifier_pack_required") is not True:
        errors.append("requires a verifier_pack")

    expected_pack = policy.get("expect_verifier_pack_sha256")
    if not isinstance(expected_pack, str) or _SHA256.fullmatch(expected_pack) is None:
        errors.append("requires expect_verifier_pack_sha256")
    if policy.get("require_report_integrity") != "external_process_isolated":
        errors.append("requires require_report_integrity='external_process_isolated'")
    if policy.get("docker_network") != "none":
        errors.append("requires docker_network='none'")
    docker_image = policy.get("docker_image")
    if not isinstance(docker_image, str) or not docker_image:
        errors.append("requires docker_image")

    isolation = policy.get("isolation")
    isolation_floor = policy.get("require_candidate_isolation")
    if profile == "protected":
        if isolation not in {"docker", "gvisor"}:
            errors.append("requires isolation='docker' or 'gvisor'")
        if isolation_floor != isolation:
            errors.append("requires require_candidate_isolation to match isolation")
    else:
        if isolation != "gvisor":
            errors.append("requires isolation='gvisor'")
        if isolation_floor != "gvisor":
            errors.append("requires require_candidate_isolation='gvisor'")
        memory = policy.get("mem_limit_mb")
        if isinstance(memory, bool) or not isinstance(memory, int) or memory <= 0:
            errors.append("requires a non-zero mem_limit")
    return tuple(errors)


__all__ = ["check_operating_profile"]
