# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Candidate edit-block parsing for the repository verifier.

This module owns only the textual ``FILE``/``PATCH`` candidate formats.  The
legacy names remain re-exported by :mod:`evoom_guard.verifiers.repo_verifier`.
"""

from __future__ import annotations

import re
from typing import NamedTuple

_BLOCK_RE = re.compile(
    r"<<<FILE:\s*(?P<path>[^>\n]+?)\s*>>>\r?\n(?P<body>.*?)\r?\n?<<<END\s*FILE>>>",
    re.DOTALL,
)

# A surgical-edit block: one search/replace hunk for one file,
# applied with a unique anchor (issue #15). Multiple blocks apply in order.
_PATCH_BLOCK_RE = re.compile(
    r"<<<PATCH:\s*(?P<path>[^>\n]+?)\s*>>>\r?\n"
    r"<<<SEARCH>>>\r?\n(?P<search>.*?)\r?\n"
    r"<<<REPLACE>>>\r?\n(?P<replace>.*?)\r?\n?"
    r"<<<END\s*PATCH>>>",
    re.DOTALL,
)

# Lenient fallbacks — used ONLY when the strict parsers above find nothing.
_LENIENT_FILE_RE = re.compile(
    r"<+\s*FILE\s*:\s*(?P<path>[^>\n]+?)\s*>+\r?\n?"
    r"(?P<body>.*?)\r?\n?"
    r"<+\s*/?\s*(?:END\s*)?FILE\s*>+",
    re.DOTALL | re.IGNORECASE,
)
_LENIENT_PATCH_RE = re.compile(
    r"<+\s*PATCH\s*(?::\s*(?P<path>[^>\n]*?))?\s*>+\s*"
    r"<+\s*SEARCH\s*>+\r?\n?(?P<search>.*?)\s*(?:<+\s*/\s*SEARCH\s*>+\s*)?"
    r"<+\s*REPLACE\s*>+\r?\n?(?P<replace>.*?)\s*(?:<+\s*/\s*REPLACE\s*>+\s*)?"
    r"<+\s*/?\s*(?:END\s*)?PATCH\s*>+",
    re.DOTALL | re.IGNORECASE,
)


def parse_file_blocks(hypothesis: str) -> dict[str, str]:
    """Extract ``{relative_path: content}`` from the hypothesis."""
    blocks: dict[str, str] = {}
    for match in _BLOCK_RE.finditer(hypothesis or ""):
        blocks[match.group("path").strip()] = match.group("body")
    return blocks


class PatchBlock(NamedTuple):
    """One unique-anchor search/replace edit for one file."""

    path: str
    search: str
    replace: str


def parse_patch_blocks(hypothesis: str) -> list[PatchBlock]:
    """Extract ordered ``<<<PATCH>>>`` edits from the hypothesis."""
    return [
        PatchBlock(
            match.group("path").strip(),
            match.group("search"),
            match.group("replace"),
        )
        for match in _PATCH_BLOCK_RE.finditer(hypothesis or "")
    ]


def parse_blocks_lenient(
    hypothesis: str, default_path: str | None = None
) -> tuple[dict[str, str], list[PatchBlock]]:
    """Best-effort recovery of near-miss block formats."""
    files: dict[str, str] = {}
    for match in _LENIENT_FILE_RE.finditer(hypothesis or ""):
        files[match.group("path").strip()] = match.group("body")
    patches: list[PatchBlock] = []
    for match in _LENIENT_PATCH_RE.finditer(hypothesis or ""):
        path = (match.group("path") or "").strip() or (default_path or "")
        if path:
            patches.append(
                PatchBlock(path, match.group("search"), match.group("replace"))
            )
    return files, patches
