# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# -----------------------------------------------------------------------------
"""Judge-owned, phase-specific subprocess scratch environments.

Repository verification deliberately keeps these writable paths beside, never
inside, the materialized candidate tree.  They reduce incidental cache/temp
writes without creating exclusions in candidate runtime identity.  They are
process hygiene only: a host subprocess still shares the judge's OS account and
is not turned into a filesystem sandbox by environment variables.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Mapping
from typing import Literal

JudgePhase = Literal["setup", "repo-suite", "verifier-pack"]

_JUDGE_PHASES = frozenset(("setup", "repo-suite", "verifier-pack"))


def create_judge_phase_environment(
    judgment_root: str,
    phase: JudgePhase,
    *,
    ambient: Mapping[str, str] | None = None,
    platform_name: str | None = None,
) -> dict[str, str]:
    """Create one private phase scratch tree and its minimal environment.

    ``judgment_root`` is the already allocated judge-owned workspace whose
    ``repo/`` child contains the candidate.  A fresh, unpredictable root is
    allocated atomically for each phase so an earlier phase cannot prepare the
    cache/temp path a later phase will receive.
    """

    if phase not in _JUDGE_PHASES:
        raise ValueError(f"unsupported judge phase: {phase!r}")

    root = os.path.abspath(judgment_root)
    phase_root = tempfile.mkdtemp(prefix=f".evoguard-{phase}-", dir=root)

    home = os.path.join(phase_root, "home")
    temporary = os.path.join(phase_root, "tmp")
    cache = os.path.join(phase_root, "cache")
    go_cache = os.path.join(cache, "go-build")
    for directory in (home, temporary, cache, go_cache):
        os.mkdir(directory, mode=0o700)

    source = os.environ if ambient is None else ambient
    environment = {
        "PATH": source.get("PATH", "/usr/bin"),
        "HOME": home,
        "LANG": "C.UTF-8",
        "TMPDIR": temporary,
        "TEMP": temporary,
        "TMP": temporary,
        "XDG_CACHE_HOME": cache,
        # Go on Windows derives its default build cache from LOCALAPPDATA and
        # does not consult XDG_CACHE_HOME.  LOCALAPPDATA is deliberately absent
        # from this minimal environment, so bind an explicit phase-private
        # cache rather than inheriting a user cache or disabling Go builds.
        "GOCACHE": go_cache,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }
    platform = os.name if platform_name is None else platform_name
    if platform == "nt":
        for key in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
            value = source.get(key)
            if value:
                environment[key] = value
    return environment


__all__ = ["JudgePhase", "create_judge_phase_environment"]
