# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
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
