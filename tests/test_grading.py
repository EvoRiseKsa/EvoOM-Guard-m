# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Sole owner & author: Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""The shared score gradient (`evoom_guard/verifiers/grading.py`).

Pure, offline tests for the two helpers the verdict engine reuses: the
SyntaxError < NameError < AssertionError ordering of ``partial_score`` and the
monotone ``fraction_score`` (floor when nothing passes, 1.0 only on a full pass).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard.verifiers.grading import PARTIAL_CEIL, PARTIAL_FLOOR, fraction_score, partial_score


def test_partial_score_orders_syntax_below_name_below_assertion():
    assert partial_score("SyntaxError: bad") == 0.05
    assert partial_score("NameError: x") == 0.10
    assert partial_score("AssertionError") == 0.25
    assert partial_score("") == 0.25  # ran, but an assertion failed


def test_partial_score_syntax_takes_precedence():
    # A SyntaxError anywhere is the worst signal even if other names appear.
    assert partial_score("SyntaxError then NameError") == 0.05


def test_fraction_score_full_pass_is_one():
    assert fraction_score(3, 3) == 1.0
    assert fraction_score(1, 1) == 1.0


def test_fraction_score_zero_pass_delegates_to_partial():
    assert fraction_score(0, 3) == 0.25                       # no stderr → assertion floor
    assert fraction_score(0, 3, "SyntaxError") == 0.05        # syntax error floor
    assert fraction_score(0, 0) == 0.25                       # nothing ran


def test_fraction_score_partial_is_monotone_and_bounded():
    s1 = fraction_score(1, 3)
    s2 = fraction_score(2, 3)
    assert PARTIAL_FLOOR < s1 < s2 < 1.0
    assert s2 <= PARTIAL_CEIL
    # exact formula: FLOOR + (CEIL - FLOOR) * (passed/total)
    assert abs(s2 - (PARTIAL_FLOOR + (PARTIAL_CEIL - PARTIAL_FLOOR) * (2 / 3))) < 1e-9
