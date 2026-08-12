# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Unambiguous framing and cryptographic identities for candidate text maps.

The historical human-readable FILE-block representation is intentionally kept
for Guard execution compatibility.  It is not an injective encoding: marker
text inside a file can make two different maps serialize to the same bytes.
This module owns the versioned, length-prefixed identity encoding used by new
admission contracts.  The framing is injective over valid input maps; its
SHA-256 digest relies on SHA-256 collision resistance.  It is dependency-free
so independent verifiers can reimplement it from the published test vectors.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Mapping
from dataclasses import dataclass

CANDIDATE_TEXT_MAP_IDENTITY_FORMAT = "EVOGUARD_CANDIDATE_TEXT_MAP_V2"
AGENT_CHANGE_CANDIDATE_SELECTION_PROFILE = (
    "EVOGUARD_AGENT_CHANGE_CANDIDATE_SELECTION_V1"
)
AGENT_CHANGE_CANDIDATE_IGNORED_BASENAMES = (
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    ".evo_runs",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
)
_DOMAIN = CANDIDATE_TEXT_MAP_IDENTITY_FORMAT.encode("ascii") + b"\0"
_ENTRY_TAG = b"F"
_U64 = struct.Struct(">Q")
MAX_IDENTITY_COMPONENT_BYTES = (1 << 64) - 1


class CandidateIdentityError(ValueError):
    """A candidate map cannot be represented by the V2 identity contract."""


@dataclass(frozen=True, slots=True)
class CandidateTextMapIdentity:
    """Digest and closed framing facts for one candidate text map."""

    sha256: str
    size: int
    file_count: int

    @property
    def payload(self) -> dict[str, object]:
        return {
            "format": CANDIDATE_TEXT_MAP_IDENTITY_FORMAT,
            "sha256": self.sha256,
            "size": self.size,
            "file_count": self.file_count,
        }


def _utf8(value: object, *, label: str) -> bytes:
    if not isinstance(value, str):
        raise CandidateIdentityError(f"{label} must be a string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CandidateIdentityError(f"{label} must be valid Unicode") from exc
    if len(encoded) > MAX_IDENTITY_COMPONENT_BYTES:
        raise CandidateIdentityError(f"{label} exceeds the V2 framing limit")
    return encoded


def candidate_path_order_key(path: str) -> bytes:
    """Return the locale-independent ordering key used by V2 path arrays."""

    return _utf8(path, label="candidate path")


def agent_change_candidate_path_is_ignored(path: str) -> bool:
    """Apply the frozen Agent Change candidate-selection profile."""

    candidate_path_order_key(path)
    ignored = set(AGENT_CHANGE_CANDIDATE_IGNORED_BASENAMES)
    return any(segment in ignored for segment in path.split("/"))


def candidate_text_map_identity_bytes(blocks: Mapping[str, str]) -> bytes:
    """Return the injective V2 framing for a path-to-text mapping.

    Every path and content value is UTF-8 encoded and preceded by an unsigned
    64-bit big-endian byte length.  A domain separator, entry count, and literal
    entry tag make the mapping unambiguous without reserving any marker text.
    Entries are sorted lexicographically by their strict UTF-8 path bytes.  No
    Unicode normalization is performed.
    """

    if not isinstance(blocks, Mapping):
        raise CandidateIdentityError("candidate text map must be a mapping")
    if len(blocks) > MAX_IDENTITY_COMPONENT_BYTES:
        raise CandidateIdentityError("candidate text map exceeds the V2 entry limit")
    entries: list[tuple[bytes, str, bytes]] = []
    for path, content in blocks.items():
        path_bytes = candidate_path_order_key(path)
        content_bytes = _utf8(content, label=f"candidate content for {path!r}")
        entries.append((path_bytes, path, content_bytes))
    entries.sort(key=lambda entry: entry[0])
    framed = bytearray(_DOMAIN)
    framed.extend(_U64.pack(len(entries)))
    for path_bytes, _path, content_bytes in entries:
        framed.extend(_ENTRY_TAG)
        framed.extend(_U64.pack(len(path_bytes)))
        framed.extend(path_bytes)
        framed.extend(_U64.pack(len(content_bytes)))
        framed.extend(content_bytes)
    return bytes(framed)


def candidate_text_map_identity(
    blocks: Mapping[str, str],
) -> CandidateTextMapIdentity:
    """Return the V2 identity for one candidate text map."""

    framed = candidate_text_map_identity_bytes(blocks)
    return CandidateTextMapIdentity(
        sha256=hashlib.sha256(framed).hexdigest(),
        size=len(framed),
        file_count=len(blocks),
    )


__all__ = (
    "AGENT_CHANGE_CANDIDATE_IGNORED_BASENAMES",
    "AGENT_CHANGE_CANDIDATE_SELECTION_PROFILE",
    "CANDIDATE_TEXT_MAP_IDENTITY_FORMAT",
    "CandidateIdentityError",
    "CandidateTextMapIdentity",
    "agent_change_candidate_path_is_ignored",
    "candidate_path_order_key",
    "candidate_text_map_identity",
    "candidate_text_map_identity_bytes",
)
