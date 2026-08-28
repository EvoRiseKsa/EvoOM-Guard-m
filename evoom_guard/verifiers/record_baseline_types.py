# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ------------------------------------------------------------------------------
"""Pure producer-shape projection for baseline evidence in verdict records.

The public record verifier retains report mutation, sequencing, policy
semantics, repair-effect interpretation, and verdict authority. This owner
only returns immutable ordered validation errors for the baseline producer
shape. It performs no I/O, hashing, execution, cleanup, or report mutation.
"""

from __future__ import annotations

from typing import Any, TypeGuard

_BASELINE_KEYS = frozenset(
    {
        "verdict",
        "tests_passed",
        "tests_total",
        "repair_effect",
        "scope",
        "note",
    }
)
_BASELINE_SETUP_KEYS = frozenset({"setup_fidelity", "setup_fidelity_changes"})


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_string_list(value: object) -> TypeGuard[list[str]]:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _valid_count_pair(passed: object, total: object) -> bool:
    if passed is None or total is None:
        return passed is None and total is None
    if not _is_int(passed) or not _is_int(total):
        return False
    return 0 <= passed <= total


def _unsupported_errors(
    keys: frozenset[object],
    *,
    verdict: object,
    passed: object,
    total: object,
    effect: object,
) -> list[str]:
    errors: list[str] = []
    if keys != _BASELINE_KEYS:
        errors.append("unsupported-mode baseline cannot contain setup fields")
    if not (
        verdict is None
        and passed is None
        and total is None
        and effect == "unmeasured"
    ):
        errors.append("unsupported-mode baseline must contain only null evidence")
    return errors


def _count_errors(
    *,
    verdict: object,
    passed: object,
    total: object,
) -> list[str]:
    errors: list[str] = []
    if not _valid_count_pair(passed, total):
        errors.append("baseline counts must be a null or ordered integer pair")
    if verdict in ("PASS", "FAIL") and not (_is_int(passed) and _is_int(total)):
        errors.append("clean baseline verdicts require integer counts")
    if verdict == "PASS" and _is_int(passed) and _is_int(total):
        if not (passed == total == 0 or total > 0 and passed == total):
            errors.append("a PASS baseline must have all-passing counts")
    if verdict == "FAIL" and _is_int(passed) and _is_int(total):
        if not (passed == total == 0 or total > 0 and passed < total):
            errors.append(
                "a FAIL baseline must have zero exit-only counts or a failed test"
            )
    return errors


def _repair_effect_errors(*, verdict: object, effect: object) -> list[str]:
    if verdict == "NO_CLEAN_VERDICT":
        if effect != "unmeasured":
            return ["NO_CLEAN_VERDICT requires an unmeasured repair effect"]
    elif effect not in ("demonstrated", "not_demonstrated"):
        return ["clean baseline verdict requires a measured repair effect"]
    return []


def _repo_suite_errors(
    *,
    scope: object,
    verdict: object,
    passed: object,
    total: object,
    effect: object,
) -> list[str]:
    errors: list[str] = []
    if scope != "repo_suite_only":
        errors.append("baseline.scope is invalid")
    if verdict not in ("PASS", "FAIL", "NO_CLEAN_VERDICT"):
        errors.append("baseline.verdict is invalid")
    errors.extend(_count_errors(verdict=verdict, passed=passed, total=total))
    errors.extend(_repair_effect_errors(verdict=verdict, effect=effect))
    return errors


def _setup_errors(
    baseline: dict[str, Any],
    *,
    setup: object,
    changes: object,
    verdict: object,
    effect: object,
) -> list[str]:
    errors: list[str] = []
    if "setup_fidelity" in baseline:
        if setup not in ("unverified", "setup_failed", "changed_judged_tree"):
            errors.append("setup_fidelity is invalid")
        if verdict != "NO_CLEAN_VERDICT" or effect != "unmeasured":
            errors.append("setup fidelity failures require an unclean baseline")
    if setup == "changed_judged_tree":
        if not (
            _is_string_list(changes)
            and bool(changes)
            and changes == sorted(set(changes))
        ):
            errors.append("changed judged tree requires sorted unique changed paths")
    elif "setup_fidelity_changes" in baseline:
        errors.append("setup_fidelity_changes requires changed_judged_tree")
    return errors


def project_baseline_type_errors(baseline: dict[str, Any]) -> tuple[str, ...]:
    """Return exact ordered producer-shape errors without mutating input state."""

    if any(not isinstance(key, str) for key in baseline):
        return ("all baseline keys must be strings",)
    keys = frozenset(baseline)
    errors: list[str] = []
    if not _BASELINE_KEYS <= keys or not keys <= _BASELINE_KEYS | _BASELINE_SETUP_KEYS:
        errors.append("baseline has missing or unknown producer keys")
    note = baseline.get("note")
    if not (isinstance(note, str) and bool(note)):
        errors.append("baseline.note must be a non-empty string")
    scope = baseline.get("scope")
    verdict = baseline.get("verdict")
    passed = baseline.get("tests_passed")
    total = baseline.get("tests_total")
    effect = baseline.get("repair_effect")
    if scope == "unsupported_mode":
        errors.extend(
            _unsupported_errors(
                keys,
                verdict=verdict,
                passed=passed,
                total=total,
                effect=effect,
            )
        )
        return tuple(errors)
    errors.extend(
        _repo_suite_errors(
            scope=scope,
            verdict=verdict,
            passed=passed,
            total=total,
            effect=effect,
        )
    )
    setup = baseline.get("setup_fidelity")
    changes = baseline.get("setup_fidelity_changes")
    errors.extend(
        _setup_errors(
            baseline,
            setup=setup,
            changes=changes,
            verdict=verdict,
            effect=effect,
        )
    )
    return tuple(errors)
