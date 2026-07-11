# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""Search-replace patcher.

issue #15 ("Patch output") — lifts the large-file constraint: instead of
rewriting a whole file, the generator applies a search/replace block keyed on a
unique anchor.

Contract:
    - empty ``search`` → ValueError.
    - ``search`` not found in ``source`` → NoMatchError (for any ``count``).
    - ``count == 1`` (the default) and ``search`` occurs more than once →
      AmbiguousMatchError (a unique anchor is required).
    - ``count == 1`` and exactly one occurrence → replace it and return the text.
    - ``count == -1`` → replace every occurrence.
    - ``count == N > 1`` → replace the first N (lenient if fewer match).
"""


class PatchError(Exception):
    """Base exception class for patching operations."""
    pass


class NoMatchError(PatchError):
    """Raised when the search string is not found in the source."""
    pass


class AmbiguousMatchError(PatchError):
    """Raised when the search string is found more than once with count=1.

    A unique anchor is required.
    """
    pass


def apply_patch(source: str, search: str, replace: str, count: int = 1) -> str:
    """Apply a search/replace edit to a piece of text.

    Replaces the search string with another while preserving the rest of the
    text verbatim.

    Args:
        source (str): The original text.
        search (str): The text to search for.
        replace (str): The text to substitute in its place.
        count (int): The number of replacements:
            - 1 (default): exactly one replacement (the anchor must be unique)
            - -1: replace every occurrence
            - N > 1: replace the first N occurrences (lenient if fewer match)

    Returns:
        str: The text after the edit.

    Raises:
        ValueError: if ``search`` is empty.
        NoMatchError: if ``search`` is not found in ``source``.
        AmbiguousMatchError: if ``count == 1`` and ``search`` occurs more than once.
    """
    # Validate that the search string is not empty.
    if not search:
        raise ValueError("search string cannot be empty")

    # Find every (non-overlapping) occurrence of the search string.
    positions = []
    start = 0
    while True:
        pos = source.find(search, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + len(search)

    # No match at all.
    if not positions:
        raise NoMatchError("search string not found in source")

    # With count=1 there must be exactly one occurrence.
    if count == 1:
        if len(positions) > 1:
            raise AmbiguousMatchError(
                f"search string found {len(positions)} times; "
                "count=1 requires unique anchor"
            )
        # Replace the single occurrence.
        pos = positions[0]
        return source[:pos] + replace + source[pos + len(search):]

    # count=-1 → replace every occurrence.
    elif count == -1:
        result = source
        # Replace from the end backwards to keep earlier indices valid.
        for pos in reversed(positions):
            result = result[:pos] + replace + result[pos + len(search):]
        return result

    # count > 1 → replace the first N occurrences.
    elif count > 1:
        result = source
        # Replace from the end backwards to keep earlier indices valid;
        # take only the first `count` matches.
        to_replace = positions[:count]
        for pos in reversed(to_replace):
            result = result[:pos] + replace + result[pos + len(search):]
        return result

    else:
        raise ValueError(f"invalid count: {count}")
