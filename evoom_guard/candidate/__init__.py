# ------------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# ------------------------------------------------------------------------------
"""Dependency-free candidate parsing and patch transforms."""

from evoom_guard.candidate.edits import (
    PatchBlock as PatchBlock,
)
from evoom_guard.candidate.edits import (
    parse_blocks_lenient as parse_blocks_lenient,
)
from evoom_guard.candidate.edits import (
    parse_file_blocks as parse_file_blocks,
)
from evoom_guard.candidate.edits import (
    parse_patch_blocks as parse_patch_blocks,
)
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

__all__ = (
    "AmbiguousMatchError",
    "NoMatchError",
    "PatchBlock",
    "PatchError",
    "apply_patch",
    "parse_blocks_lenient",
    "parse_file_blocks",
    "parse_patch_blocks",
)
