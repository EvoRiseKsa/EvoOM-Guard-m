# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Branch coverage for runtime-identity budgets, root checks, and drift details.

``test_runtime_identity.py`` covers the happy scan and the symlink-containment
rules. These complementary tests drive the rejection and reporting branches
the scan path skips: budget validation, non-directory / symlink / missing
roots, and every shape of ``runtime_identity_changes`` output — modification,
addition, deletion, the digest-only fallback, and the truncation guard.

The change-detection function is pure and platform-independent, so those
assertions bind on every host; the capture-side root checks bind through the
public API on both the POSIX descriptor and Windows best-effort paths.
"""

from __future__ import annotations

import os

import pytest

import evoom_guard.runtime_identity as ri
from evoom_guard.runtime_identity import (
    RuntimeEntry,
    RuntimeIdentity,
    RuntimeIdentityError,
    capture_runtime_identity,
    runtime_identity_changes,
    verify_runtime_identity,
)


def _identity(records: tuple[RuntimeEntry, ...], *, sha: str = "x") -> RuntimeIdentity:
    return RuntimeIdentity(
        sha256=sha,
        entries=len(records),
        regular_bytes=0,
        elapsed_ms=0.0,
        records=records,
    )


def _file(path: str, payload: str = "p", *, size: int = 1) -> RuntimeEntry:
    return RuntimeEntry(path=path, kind="file", permissions=0o644, size=size, payload=payload)


# --------------------------------------------------------------------------- #
# Budget validation                                                           #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "kwargs",
    [
        {"deadline_seconds": 0},
        {"deadline_seconds": -1.0},
        {"max_entries": 0},
        {"max_path_bytes": 0},
        {"max_logical_bytes": 0},
        {"max_file_bytes": 0},
    ],
)
def test_non_positive_budgets_are_rejected(tmp_path, kwargs) -> None:
    with pytest.raises(RuntimeIdentityError):
        capture_runtime_identity(str(tmp_path), **kwargs)


# --------------------------------------------------------------------------- #
# Root shape                                                                  #
# --------------------------------------------------------------------------- #


def test_missing_root_is_a_runtime_identity_error(tmp_path) -> None:
    with pytest.raises(RuntimeIdentityError):
        capture_runtime_identity(str(tmp_path / "does-not-exist"))


def test_file_root_is_rejected(tmp_path) -> None:
    target = tmp_path / "a-file"
    target.write_text("x", encoding="utf-8")
    with pytest.raises(RuntimeIdentityError):
        capture_runtime_identity(str(target))


def test_symlinked_root_is_rejected(tmp_path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    try:
        os.symlink(str(real), str(link), target_is_directory=True)
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("symlink creation not permitted on this host")
    with pytest.raises(RuntimeIdentityError):
        capture_runtime_identity(str(link))


# --------------------------------------------------------------------------- #
# Capture happy shapes the scan tests do not assert directly                  #
# --------------------------------------------------------------------------- #


def test_empty_tree_captures_deterministically(tmp_path) -> None:
    first = capture_runtime_identity(str(tmp_path))
    second = capture_runtime_identity(str(tmp_path))
    assert first.sha256 == second.sha256
    assert first.entries == second.entries


def test_verify_reports_no_change_for_a_stable_tree(tmp_path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "m.py").write_text("x = 1\n", encoding="utf-8")
    expected = capture_runtime_identity(str(tmp_path))
    _observed, changes = verify_runtime_identity(str(tmp_path), expected)
    assert changes == []


# --------------------------------------------------------------------------- #
# runtime_identity_changes: every output branch (pure, platform-independent)  #
# --------------------------------------------------------------------------- #


def test_no_records_and_equal_digests_report_nothing() -> None:
    identity = _identity((), sha="same")
    assert runtime_identity_changes(identity, identity) == []


def test_identical_records_but_differing_digest_fall_back_to_tree_marker() -> None:
    records = (_file("a"),)
    before = _identity(records, sha="one")
    after = _identity(records, sha="two")
    assert runtime_identity_changes(before, after) == ["<runtime-tree-digest>"]


def test_modified_record_is_reported_by_path() -> None:
    before = _identity((_file("a", "old"),))
    after = _identity((_file("a", "new"),))
    assert runtime_identity_changes(before, after) == ["a"]


def test_added_and_deleted_paths_are_both_reported() -> None:
    before = _identity((_file("a"), _file("c")))
    after = _identity((_file("a"), _file("b")))
    # 'c' only in before (deleted), 'b' only in after (added); byte-order merge.
    assert sorted(runtime_identity_changes(before, after)) == ["b", "c"]


def test_trailing_additions_and_deletions_drain_both_sides() -> None:
    before = _identity((_file("a"), _file("b"), _file("c")))
    after = _identity((_file("a"),))
    assert sorted(runtime_identity_changes(before, after)) == ["b", "c"]

    before2 = _identity((_file("a"),))
    after2 = _identity((_file("a"), _file("y"), _file("z")))
    assert sorted(runtime_identity_changes(before2, after2)) == ["y", "z"]


def test_change_list_is_truncated_at_the_reported_ceiling(monkeypatch) -> None:
    monkeypatch.setattr(ri, "RUNTIME_IDENTITY_MAX_REPORTED_CHANGES", 3)
    before = _identity(tuple(_file(f"f{i:03d}") for i in range(10)))
    after = _identity(())  # every path deleted
    changes = runtime_identity_changes(before, after)
    assert changes[-1] == "<runtime-change-list-truncated>"
    assert len(changes) == 4  # 3 reported paths + the truncation marker
