# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Compatibility facade for the historical candidate-edit parser path."""

from __future__ import annotations

import re as re
from typing import NamedTuple as NamedTuple

from evoom_guard.candidate import edits as _edits
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

_BLOCK_RE = _edits._BLOCK_RE
_LENIENT_FILE_RE = _edits._LENIENT_FILE_RE
_LENIENT_PATCH_RE = _edits._LENIENT_PATCH_RE
_PATCH_BLOCK_RE = _edits._PATCH_BLOCK_RE
