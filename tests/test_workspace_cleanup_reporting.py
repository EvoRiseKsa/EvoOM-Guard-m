"""Adversarial contracts for shared workspace-cleanup diagnostics."""

from __future__ import annotations

import sys

import pytest

import evoom_guard.workspace.repository as workspace_owner


class HostileStringError(RuntimeError):
    """A cleanup failure whose diagnostic conversion is itself unsafe."""

    def __str__(self) -> str:
        raise KeyboardInterrupt("secondary stringification interrupted")


def _raise(error: BaseException) -> None:
    raise error


def test_hostile_cleanup_stringification_cannot_mask_active_primary() -> None:
    primary = KeyboardInterrupt("exact primary")
    cleanup_error = HostileStringError()
    notes: list[tuple[BaseException, str]] = []

    def run() -> None:
        try:
            raise primary
        finally:
            workspace_owner.cleanup_repo_workspaces(
                (("candidate workspace", "candidate"),),
                primary=sys.exc_info()[1],
                remove_tree=lambda _path: _raise(cleanup_error),
                note_failure=lambda target, message: notes.append((target, message)),
            )

    with pytest.raises(KeyboardInterrupt) as caught:
        run()

    assert caught.value is primary
    assert notes == [
        (
            primary,
            "RepoVerifier candidate workspace cleanup failed while preserving the "
            "primary exception: HostileStringError: <unprintable; __str__ raised "
            "KeyboardInterrupt>",
        )
    ]


def test_hostile_secondary_stringification_preserves_first_cleanup_failure() -> None:
    first = OSError("first cleanup failure")
    hostile = HostileStringError()
    failures = iter((first, hostile))
    notes: list[tuple[BaseException, str]] = []

    with pytest.raises(OSError) as caught:
        workspace_owner.cleanup_repo_workspaces(
            (("candidate workspace", "candidate"), ("pack workspace", "pack")),
            primary=None,
            remove_tree=lambda _path: _raise(next(failures)),
            note_failure=lambda target, message: notes.append((target, message)),
        )

    assert caught.value is first
    assert notes == [
        (first, "RepoVerifier candidate workspace cleanup failed"),
        (
            first,
            "Additional RepoVerifier pack workspace cleanup failure: "
            "HostileStringError: <unprintable; __str__ raised KeyboardInterrupt>",
        ),
    ]


def test_active_primary_cleanup_diagnostic_is_deterministically_bounded() -> None:
    primary = RuntimeError("exact primary")
    cleanup_error = OSError("X" * 200_000)
    notes: list[str] = []

    workspace_owner.cleanup_repo_workspaces(
        (("candidate workspace", "candidate"),),
        primary=primary,
        remove_tree=lambda _path: _raise(cleanup_error),
        note_failure=lambda _target, message: notes.append(message),
    )

    assert len(notes) == 1
    assert len(notes[0]) == 2_000
    assert notes[0].endswith("...")
    assert notes[0] == workspace_owner._bounded_cleanup_diagnostic(
        "RepoVerifier candidate workspace cleanup failed while preserving the "
        f"primary exception: OSError: {'X' * 200_000}"
    )


def test_no_primary_secondary_diagnostic_is_bounded_and_first_stays_primary() -> None:
    first = OSError("first cleanup failure")
    oversized = RuntimeError("Y" * 200_000)
    failures = iter((first, oversized))
    notes: list[tuple[BaseException, str]] = []

    with pytest.raises(OSError) as caught:
        workspace_owner.cleanup_repo_workspaces(
            (("candidate workspace", "candidate"), ("pack workspace", "pack")),
            primary=None,
            remove_tree=lambda _path: _raise(next(failures)),
            note_failure=lambda target, message: notes.append((target, message)),
        )

    assert caught.value is first
    assert len(notes) == 2
    assert all(target is first for target, _message in notes)
    assert len(notes[1][1]) == 2_000
    assert notes[1][1].endswith("...")


def test_note_callback_baseexception_cannot_mask_active_primary() -> None:
    primary = KeyboardInterrupt("exact primary")
    cleanup_error = OSError("cleanup denied")
    callback_error = SystemExit("reporter exited")

    def run() -> None:
        try:
            raise primary
        finally:
            workspace_owner.cleanup_repo_workspaces(
                (("candidate workspace", "candidate"),),
                primary=sys.exc_info()[1],
                remove_tree=lambda _path: _raise(cleanup_error),
                note_failure=lambda _target, _message: _raise(callback_error),
            )

    with pytest.raises(KeyboardInterrupt) as caught:
        run()

    assert caught.value is primary
    notes = getattr(primary, "__notes__", ())
    assert len(notes) == 1
    assert "OSError: cleanup denied" in notes[0]
    assert "cleanup diagnostic callback failed: SystemExit: reporter exited" in notes[0]
    assert len(notes[0]) <= 2_000


def test_note_callback_baseexception_cannot_replace_first_cleanup_failure() -> None:
    first = OSError("first cleanup failure")
    callback_error = KeyboardInterrupt("reporter interrupted")

    with pytest.raises(OSError) as caught:
        workspace_owner.cleanup_repo_workspaces(
            (("candidate workspace", "candidate"),),
            primary=None,
            remove_tree=lambda _path: _raise(first),
            note_failure=lambda _target, _message: _raise(callback_error),
        )

    assert caught.value is first
    notes = getattr(first, "__notes__", ())
    assert len(notes) == 1
    assert notes[0].startswith("RepoVerifier candidate workspace cleanup failed")
    assert "cleanup diagnostic callback failed: KeyboardInterrupt" in notes[0]
    assert len(notes[0]) <= 2_000


def test_default_note_reporter_bounds_direct_diagnostics() -> None:
    target = RuntimeError("target")

    workspace_owner.note_cleanup_failure(target, "Z" * 200_000)

    notes = getattr(target, "__notes__", ())
    assert len(notes) == 1
    assert len(notes[0]) == 2_000
    assert notes[0].endswith("...")
