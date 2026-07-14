# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Branch coverage for the setup-fidelity snapshot and change primitives.

The fidelity layer decides whether a setup command mutated files it was not
allowed to touch. It is exercised only indirectly through the guard flow,
leaving its glob exceptions, default-output-tree handling, hardlink rejection,
and change diffing under-covered. These tests drive the helpers directly.

``_setup_fidelity_snapshot`` runs the POSIX descriptor scan or the Windows
best-effort scan behind one signature, so the assertions bind both paths; the
CI Linux job covers the descriptor branch a single-OS run cannot.
"""

from __future__ import annotations

import os

import pytest

from evoom_guard.verifiers.fidelity import (
    SetupFidelityError,
    _fidelity_entry_state,
    _is_default_setup_output,
    _matches_globs,
    _setup_fidelity_changes,
    _setup_fidelity_snapshot,
)

# --------------------------------------------------------------------------- #
# Pure predicates                                                             #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "path,globs,expected",
    [
        ("build/x.o", ("build/*",), True),
        ("BUILD/X.O", ("build/*",), True),  # case-insensitive
        ("src/app.py", ("build/*",), False),
        ("gen/out.txt", ("gen/**", "other/*"), True),
        ("src/app.py", (), False),
    ],
)
def test_matches_globs(path, globs, expected) -> None:
    assert _matches_globs(path, globs) is expected


@pytest.mark.parametrize(
    "path,expected",
    [
        ("node_modules/lib/index.js", True),
        ("pkg/.venv/bin/python", True),
        ("a/__pycache__/m.pyc", True),
        ("src/app.py", False),
        ("", False),
    ],
)
def test_is_default_setup_output(path, expected) -> None:
    assert _is_default_setup_output(path) is expected


# --------------------------------------------------------------------------- #
# _setup_fidelity_changes                                                     #
# --------------------------------------------------------------------------- #


def test_changes_reports_added_removed_and_modified() -> None:
    before = {"a": ("file", 0o644, "h1"), "b": ("file", 0o644, "h2")}
    after = {
        "a": ("file", 0o644, "h1"),       # unchanged
        "b": ("file", 0o644, "DIFFERENT"),  # content changed
        "c": ("file", 0o644, "h3"),       # added
    }
    # 'b' modified, 'c' added; nothing removed here.
    assert _setup_fidelity_changes(before, after) == ["b", "c"]


def test_changes_reports_a_mode_only_change() -> None:
    before = {"s.sh": ("file", 0o644, "same")}
    after = {"s.sh": ("file", 0o755, "same")}
    assert _setup_fidelity_changes(before, after) == ["s.sh"]


def test_changes_reports_a_removed_path() -> None:
    before = {"gone": ("file", 0o644, "h")}
    assert _setup_fidelity_changes(before, {}) == ["gone"]


def test_no_changes_is_empty() -> None:
    snap = {"a": ("file", 0o644, "h")}
    assert _setup_fidelity_changes(snap, dict(snap)) == []


# --------------------------------------------------------------------------- #
# _fidelity_entry_state                                                       #
# --------------------------------------------------------------------------- #


def test_entry_state_hashes_a_regular_file(tmp_path) -> None:
    f = tmp_path / "m.py"
    f.write_text("value = 1\n", encoding="utf-8")
    kind, _mode, payload = _fidelity_entry_state(str(f))
    assert kind == "file"
    assert len(payload) == 64  # sha256 hex


def test_entry_state_reports_a_directory(tmp_path) -> None:
    d = tmp_path / "sub"
    d.mkdir()
    kind, _mode, payload = _fidelity_entry_state(str(d))
    assert kind == "dir"
    assert payload == ""


def test_entry_state_rejects_a_hardlinked_file(tmp_path) -> None:
    original = tmp_path / "orig"
    original.write_text("shared", encoding="utf-8")
    try:
        os.link(str(original), str(tmp_path / "alias"))
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("hard links unavailable on this filesystem")
    with pytest.raises(SetupFidelityError):
        _fidelity_entry_state(str(original))


def test_entry_state_binds_a_symlink_without_following(tmp_path) -> None:
    target = tmp_path / "real.txt"
    target.write_text("x", encoding="utf-8")
    link = tmp_path / "ln"
    try:
        os.symlink(str(target), str(link))
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("symlink creation not permitted on this host")
    kind, _mode, payload = _fidelity_entry_state(str(link))
    # Bound as a link, not followed to the file. The stored target is whatever
    # os.readlink returns verbatim; on Windows that carries a `\\?\`
    # extended-length prefix, so compare by resolved identity, not raw string.
    assert kind == "link"
    assert os.path.basename(payload.rstrip("/\\")) == "real.txt"
    assert os.path.realpath(payload) == os.path.realpath(str(target))


# --------------------------------------------------------------------------- #
# _setup_fidelity_snapshot                                                    #
# --------------------------------------------------------------------------- #


def test_snapshot_binds_files_and_dirs(tmp_path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "m.py").write_text("x = 1\n", encoding="utf-8")
    snap = _setup_fidelity_snapshot(str(tmp_path))
    assert "pkg" in snap and snap["pkg"][0] == "dir"
    assert "pkg/m.py" in snap and snap["pkg/m.py"][0] == "file"


def test_snapshot_ignores_explicit_output_globs(tmp_path) -> None:
    (tmp_path / "gen").mkdir()
    (tmp_path / "gen" / "out.txt").write_text("generated", encoding="utf-8")
    (tmp_path / "src.py").write_text("keep", encoding="utf-8")
    snap = _setup_fidelity_snapshot(str(tmp_path), ("gen/**",))
    assert "src.py" in snap
    assert not any(path.startswith("gen/") for path in snap)


def test_post_setup_scan_ignores_new_entries_under_default_output_trees(tmp_path) -> None:
    # A baseline (pre-setup) snapshot without node_modules; the post-setup scan
    # gets a fresh node_modules tree, which must be ignored as setup output.
    baseline = _setup_fidelity_snapshot(str(tmp_path))
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("installed", encoding="utf-8")
    after = _setup_fidelity_snapshot(str(tmp_path), baseline=baseline)
    assert not any("node_modules" in path for path in after)
