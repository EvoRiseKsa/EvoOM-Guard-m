# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
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
