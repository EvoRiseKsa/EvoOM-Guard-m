# ------------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# ------------------------------------------------------------------------------
"""Compatibility facade for the historical candidate patch path."""

from evoom_guard.candidate.patch import (
    AmbiguousMatchError as AmbiguousMatchError,
)
from evoom_guard.candidate.patch import (
    NoMatchError as NoMatchError,
)
from evoom_guard.candidate.patch import (
    PatchError as PatchError,
)
from evoom_guard.candidate.patch import (
    apply_patch as apply_patch,
)
