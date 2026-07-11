# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""Search-replace patcher tests (evo.patch_applier).

``apply_patch`` is the surgical edit primitive the repo verifier applies to a
throwaway copy (``evo.verifiers.repo_verifier.apply_blocks_to_copy``), so it is
a live production path. It previously had no coverage in the gate (only an
arbiter under ``problems/arbiters/``); this module brings its contract into the
CI suite so a regression in the unique-anchor / count semantics fails the build.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard.patch_applier import (
    AmbiguousMatchError,
    NoMatchError,
    PatchError,
    apply_patch,
)


class ApplyPatchTests(unittest.TestCase):
    """The apply_patch contract (unique anchor + count modes)."""

    def test_basic_unique_replace(self) -> None:
        self.assertEqual(apply_patch("a b c", "b", "X"), "a X c")

    def test_default_requires_unique_anchor(self) -> None:
        with self.assertRaises(AmbiguousMatchError):
            apply_patch("a a a", "a", "X")

    def test_no_match_raises(self) -> None:
        with self.assertRaises(NoMatchError):
            apply_patch("abc", "z", "Y")

    def test_search_longer_than_source_no_match(self) -> None:
        with self.assertRaises(NoMatchError):
            apply_patch("hi", "hi there", "x")

    def test_empty_search_raises_valueerror(self) -> None:
        with self.assertRaises(ValueError):
            apply_patch("abc", "", "Y")

    def test_multiline_search_block(self) -> None:
        src = "def f():\n    return 1\n"
        self.assertEqual(
            apply_patch(src, "    return 1\n", "    return 2\n"),
            "def f():\n    return 2\n",
        )

    def test_deletion_with_empty_replace(self) -> None:
        self.assertEqual(apply_patch("hello world", " world", ""), "hello")

    def test_replace_all_with_count_minus_one(self) -> None:
        self.assertEqual(apply_patch("a a a", "a", "X", count=-1), "X X X")

    def test_replace_first_n_occurrences(self) -> None:
        self.assertEqual(apply_patch("a a a a", "a", "X", count=2), "X X a a")

    def test_count_n_is_lenient_when_fewer_matches(self) -> None:
        # "lenient if fewer matches": count exceeds the 2 available occurrences.
        self.assertEqual(apply_patch("a a", "a", "X", count=5), "X X")

    def test_count_minus_one_still_raises_on_no_match(self) -> None:
        with self.assertRaises(NoMatchError):
            apply_patch("abc", "z", "Y", count=-1)

    def test_invalid_count_zero_raises_valueerror(self) -> None:
        with self.assertRaises(ValueError):
            apply_patch("a a", "a", "X", count=0)

    def test_preserves_crlf_and_trailing_newline(self) -> None:
        self.assertEqual(apply_patch("a\r\nb\r\n", "b", "B"), "a\r\nB\r\n")

    def test_no_op_when_replace_equals_search(self) -> None:
        self.assertEqual(apply_patch("a b c", "b", "b"), "a b c")

    def test_does_not_touch_other_text(self) -> None:
        self.assertEqual(apply_patch("foo BAR foo", "BAR", "baz"), "foo baz foo")

    def test_replace_longer_than_search_shifts_correctly(self) -> None:
        # Replacing from the end keeps earlier offsets valid even when the
        # replacement changes the length — the repo verifier relies on this.
        self.assertEqual(apply_patch("x.x.x", ".", "::", count=-1), "x::x::x")

    def test_exceptions_subclass_patcherror(self) -> None:
        self.assertTrue(issubclass(NoMatchError, PatchError))
        self.assertTrue(issubclass(AmbiguousMatchError, PatchError))

    def test_returns_str(self) -> None:
        self.assertIsInstance(apply_patch("x y", "y", "z"), str)


if __name__ == "__main__":
    unittest.main()
