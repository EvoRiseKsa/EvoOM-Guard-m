# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Sole owner & author: Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────

"""Patch minimization + risk scoring tests (stdlib only, deterministic)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard.patchmin import (
    RiskScore,
    minimize_patch,
    parse_unified_diff,
    risk_score,
)


class MinimizePatchTests(unittest.TestCase):
    def test_single_required_edit(self) -> None:
        # Only "KEEP" is required; everything else is removable.
        passes = lambda s: "KEEP" in s  # noqa: E731
        result = minimize_patch(["a", "KEEP", "b", "c"], passes)
        self.assertEqual(result, ["KEEP"])

    def test_two_required_edits_are_both_kept_and_minimal(self) -> None:
        # Predicate needs both X and Y; the minimal subset is exactly {X, Y}.
        passes = lambda s: {"X", "Y"} <= set(s)  # noqa: E731
        result = minimize_patch(["X", "p", "Y", "q"], passes)
        self.assertEqual(len(result), 2)
        self.assertEqual(set(result), {"X", "Y"})
        # 1-minimality: removing either remaining edit must break the predicate.
        for i in range(len(result)):
            self.assertFalse(passes(result[:i] + result[i + 1 :]))

    def test_order_preserved(self) -> None:
        # Surviving edits keep their original relative order.
        passes = lambda s: {"X", "Y"} <= set(s)  # noqa: E731
        result = minimize_patch(["X", "p", "Y", "q"], passes)
        self.assertEqual(result, ["X", "Y"])

    def test_always_true_returns_empty(self) -> None:
        # If the empty patch passes, the patch was unnecessary -> [].
        result = minimize_patch(["a", "b", "c"], lambda s: True)
        self.assertEqual(result, [])

    def test_full_patch_fails_raises_value_error(self) -> None:
        # A patch that never passes cannot be minimized.
        with self.assertRaises(ValueError):
            minimize_patch(["a", "b"], lambda s: False)

    def test_one_minimality_property(self) -> None:
        # General 1-minimality: for the returned subset R, dropping any single
        # element must make `passes` False.
        passes = lambda s: {"A", "B", "C"} <= set(s)  # noqa: E731
        edits = ["z", "A", "y", "B", "x", "C", "w"]
        result = minimize_patch(edits, passes)
        self.assertEqual(set(result), {"A", "B", "C"})
        for i in range(len(result)):
            self.assertFalse(
                passes(result[:i] + result[i + 1 :]),
                f"removing index {i} should fail the predicate",
            )

    def test_determinism(self) -> None:
        # Two identical calls produce identical results.
        passes = lambda s: {"X", "Y"} <= set(s)  # noqa: E731
        edits = ["X", "p", "Y", "q", "r"]
        first = minimize_patch(list(edits), passes)
        second = minimize_patch(list(edits), passes)
        self.assertEqual(first, second)

    def test_does_not_mutate_input(self) -> None:
        # The caller's list must be left untouched.
        edits = ["a", "KEEP", "b"]
        original = list(edits)
        minimize_patch(edits, lambda s: "KEEP" in s)
        self.assertEqual(edits, original)


# A hand-written 2-file unified diff used by several parse/score tests.
TWO_FILE_DIFF = """\
diff --git a/evo/foo.py b/evo/foo.py
index 1111111..2222222 100644
--- a/evo/foo.py
+++ b/evo/foo.py
@@ -1,4 +1,5 @@
 import os
-import sys
+import sys  # noqa
+import json
 x = 1
 y = 2
diff --git a/server/bar.py b/server/bar.py
index 3333333..4444444 100644
--- a/server/bar.py
+++ b/server/bar.py
@@ -10,3 +10,3 @@
-old_line = 1
+new_line = 1
 unchanged = 0
"""


class ParseUnifiedDiffTests(unittest.TestCase):
    def test_two_file_diff_counts(self) -> None:
        parsed = parse_unified_diff(TWO_FILE_DIFF)
        # foo.py: two '+' content lines, one '-' content line.
        # bar.py: one '+' content line, one '-' content line.
        self.assertEqual(parsed, {"evo/foo.py": (2, 1), "server/bar.py": (1, 1)})

    def test_headers_are_not_counted_as_content(self) -> None:
        # The +++/---/@@ headers must never be tallied. If they were, foo.py
        # would over-count (the '+++ b/...' and '@@' lines would inflate '+').
        parsed = parse_unified_diff(TWO_FILE_DIFF)
        added_foo, removed_foo = parsed["evo/foo.py"]
        self.assertEqual(added_foo, 2)   # exactly the two real '+' lines
        self.assertEqual(removed_foo, 1)  # exactly the one real '-' line

    def test_new_file_against_dev_null(self) -> None:
        # A brand-new file: old side is /dev/null, all content is added.
        diff = """\
diff --git a/new.py b/new.py
new file mode 100644
--- /dev/null
+++ b/new.py
@@ -0,0 +1,2 @@
+line one
+line two
"""
        self.assertEqual(parse_unified_diff(diff), {"new.py": (2, 0)})

    def test_deleted_file_to_dev_null_ignored_as_destination(self) -> None:
        # A deletion targets /dev/null; with no destination path the removed
        # lines are not attributed to a new file (no phantom path appears).
        diff = """\
diff --git a/gone.py b/gone.py
deleted file mode 100644
--- a/gone.py
+++ /dev/null
@@ -1,2 +0,0 @@
-line one
-line two
"""
        self.assertEqual(parse_unified_diff(diff), {})

    def test_plain_paths_without_git_prefix(self) -> None:
        # "+++ path" (no b/ prefix) is accepted too.
        diff = "--- foo.py\n+++ foo.py\n@@ -1 +1 @@\n-a\n+b\n"
        self.assertEqual(parse_unified_diff(diff), {"foo.py": (1, 1)})


class RiskScoreTests(unittest.TestCase):
    def test_small_diff_is_low(self) -> None:
        diff = "--- a/foo.py\n+++ b/foo.py\n@@ -1 +1 @@\n-a\n+b\n"
        rs = risk_score(diff)
        self.assertEqual(rs.level, "low")
        self.assertEqual(rs.protected_hits, [])
        self.assertGreaterEqual(rs.score, 0.0)
        self.assertLess(rs.score, 1.0)
        self.assertEqual(rs.files_touched, 1)

    def test_large_diff_by_lines_is_high(self) -> None:
        # One file but >= high_lines (200) changed lines -> high.
        body = "".join(f"+line{i}\n" for i in range(250))
        diff = f"--- a/big.py\n+++ b/big.py\n@@ -0,0 +1,250 @@\n{body}"
        rs = risk_score(diff)
        self.assertEqual(rs.level, "high")
        self.assertEqual(rs.lines_added, 250)
        self.assertTrue(0.0 <= rs.score <= 1.0)

    def test_large_diff_by_files_is_high(self) -> None:
        # >= high_files (8) distinct files touched -> high, via a dict input.
        mapping = {f"f{i}.py": (1, 0) for i in range(8)}
        rs = risk_score(mapping)
        self.assertEqual(rs.files_touched, 8)
        self.assertEqual(rs.level, "high")
        self.assertTrue(0.0 <= rs.score <= 1.0)

    def test_protected_hit_forces_high(self) -> None:
        # A tiny diff, but it touches a protected path -> high regardless.
        diff = (
            "--- a/app/secrets.py\n+++ b/app/secrets.py\n@@ -1 +1 @@\n-x\n+y\n"
        )
        rs = risk_score(diff, protected=["*/secrets.py", "package.json"])
        self.assertEqual(rs.protected_hits, ["app/secrets.py"])
        self.assertEqual(rs.level, "high")
        self.assertTrue(0.0 <= rs.score <= 1.0)

    def test_protected_hits_sorted_unique(self) -> None:
        # Multiple protected files -> sorted, de-duplicated list.
        mapping = {"package.json": (1, 1), "a/secrets.py": (2, 0), "b/secrets.py": (0, 3)}
        rs = risk_score(mapping, protected=["*/secrets.py", "package.json"])
        self.assertEqual(rs.protected_hits, ["a/secrets.py", "b/secrets.py", "package.json"])

    def test_medium_by_files(self) -> None:
        # 3 files (>= medium_files) but small + not protected -> medium.
        mapping = {"a.py": (1, 0), "b.py": (1, 0), "c.py": (1, 0)}
        rs = risk_score(mapping)
        self.assertEqual(rs.level, "medium")

    def test_medium_by_lines(self) -> None:
        # 1 file, but >= medium_lines (40) total changed lines -> medium.
        mapping = {"a.py": (30, 15)}
        rs = risk_score(mapping)
        self.assertEqual(rs.level, "medium")

    def test_accepts_diff_string_and_dict_equivalently(self) -> None:
        # The same change as a diff string and as a dict yields the same score.
        diff = "--- a/foo.py\n+++ b/foo.py\n@@ -1,2 +1,2 @@\n-a\n-b\n+c\n+d\n"
        from_str = risk_score(diff)
        from_dict = risk_score({"foo.py": (2, 2)})
        self.assertEqual(from_str.score, from_dict.score)
        self.assertEqual(from_str.level, from_dict.level)
        self.assertEqual(from_str.files_touched, from_dict.files_touched)

    def test_score_always_in_unit_interval(self) -> None:
        # Across a spread of inputs the score never leaves [0, 1].
        cases: list = [
            {},
            {"a.py": (0, 0)},
            {"a.py": (1, 1)},
            {f"f{i}.py": (50, 50) for i in range(20)},  # huge
        ]
        for mapping in cases:
            rs = risk_score(mapping, protected=["*.py"])
            self.assertTrue(0.0 <= rs.score <= 1.0, f"{mapping} -> {rs.score}")

    def test_empty_diff_is_low_zero_score(self) -> None:
        rs = risk_score({})
        self.assertEqual(rs.files_touched, 0)
        self.assertEqual(rs.level, "low")
        self.assertEqual(rs.score, 0.0)
        self.assertEqual(rs.protected_hits, [])

    def test_returns_riskscore_dataclass(self) -> None:
        rs = risk_score({"a.py": (1, 0)})
        self.assertIsInstance(rs, RiskScore)


if __name__ == "__main__":
    unittest.main()
