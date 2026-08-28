# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# -----------------------------------------------------------------------------
"""Dependency-free vocabulary for candidate isolation policy."""

from __future__ import annotations

SUPPORTED_ISOLATION_MODES = ("subprocess", "docker", "gvisor")
_SUPPORTED_ISOLATION_MODE_SET = frozenset(SUPPORTED_ISOLATION_MODES)


def validate_isolation_mode(value: object) -> str:
    """Return one supported mode or reject it before any execution effect."""

    if type(value) is not str or value not in _SUPPORTED_ISOLATION_MODE_SET:
        raise ValueError(
            "unsupported isolation mode "
            f"{value!r}; expected one of: subprocess, docker, gvisor"
        )
    return value


__all__ = ("SUPPORTED_ISOLATION_MODES", "validate_isolation_mode")
