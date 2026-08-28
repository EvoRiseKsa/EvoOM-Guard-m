# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
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
