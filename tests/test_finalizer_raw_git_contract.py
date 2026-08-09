from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from evoom_guard import (
    finalizer_derivation,
    release_source_producer_receipt,
)

_TARGET_COMMIT = "c" * 40
_TARGET_TREE = "d" * 40
_PRODUCER_BLOB = "1" * 40
_TRIGGER_BLOB = "2" * 40
_ADMITTER_BLOB = "3" * 40
_PRODUCER_PATH = ".github/workflows/produce.yml"
_TRIGGER_PATH = ".github/workflows/reverify.yml"
_ADMITTER_PATH = ".github/workflows/admit.yml"


def _source() -> dict[str, Any]:
    return {
        "repository": "owner/project",
        "repository_id": "12345",
        "default_branch": "main",
        "workflow_run_id": "1000",
        "workflow_run_attempt": 1,
        "protected_ref": "refs/heads/main",
        "target_commit_sha": _TARGET_COMMIT,
        "target_tree_sha": _TARGET_TREE,
    }


def _producer() -> dict[str, Any]:
    return {
        "workflow_repository": "owner/project",
        "workflow_repository_id": "12345",
        "workflow_id": "55555",
        "workflow_path": _PRODUCER_PATH,
        "workflow_blob_sha": _PRODUCER_BLOB,
        "workflow_run_id": "1001",
        "workflow_run_attempt": 1,
        "workflow_event": "workflow_run",
        "workflow_ref": "refs/heads/main",
        "workflow_commit_sha": _TARGET_COMMIT,
        "trigger_workflow_id": "44444",
        "trigger_workflow_path": _TRIGGER_PATH,
        "trigger_workflow_blob_sha": _TRIGGER_BLOB,
        "trigger_workflow_run_id": "1000",
        "trigger_workflow_run_attempt": 1,
        "runner_class": "github-hosted",
    }


def _admitter() -> dict[str, Any]:
    return {
        "workflow_repository": "owner/project",
        "workflow_repository_id": "12345",
        "workflow_id": "66666",
        "workflow_path": _ADMITTER_PATH,
        "workflow_blob_sha": _ADMITTER_BLOB,
        "workflow_run_id": "1002",
        "workflow_run_attempt": 1,
        "workflow_event": "workflow_run",
        "workflow_ref": "refs/heads/main",
        "workflow_commit_sha": _TARGET_COMMIT,
        "trigger_workflow_id": "55555",
        "trigger_workflow_path": _PRODUCER_PATH,
        "trigger_workflow_blob_sha": _PRODUCER_BLOB,
        "trigger_workflow_run_id": "1001",
        "trigger_workflow_run_attempt": 1,
        "runner_class": "github-hosted",
    }


class _ProjectedEntry:
    def __init__(
        self,
        *,
        path: str,
        object_id: str,
        regular: bool,
        events: list[object],
    ) -> None:
        self.path = path
        self.object_id = object_id
        self._regular = regular
        self._events = events

    @property
    def regular(self) -> bool:
        self._events.append(("project", self.path))
        return self._regular


def _reader_type(
    events: list[object],
    entries: dict[str, object] | Callable[[], dict[str, object]],
) -> type[object]:
    class CharacterizedReader:
        def __init__(
            self,
            repository: str,
            *,
            bare: bool,
            git_executable: object | None = None,
        ) -> None:
            events.append(("init", repository, bare, git_executable))

        def __enter__(self) -> CharacterizedReader:
            events.append("enter")
            return self

        def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
            del traceback
            events.append(("exit", exc_type, exc))

        def tree(self, treeish: str) -> dict[str, object]:
            events.append(("tree", treeish))
            return entries() if callable(entries) else entries

    return CharacterizedReader


def _entries(events: list[object]) -> dict[str, object]:
    return {
        _PRODUCER_PATH: _ProjectedEntry(
            path=_PRODUCER_PATH,
            object_id=_PRODUCER_BLOB,
            regular=True,
            events=events,
        ),
        _TRIGGER_PATH: _ProjectedEntry(
            path=_TRIGGER_PATH,
            object_id=_TRIGGER_BLOB,
            regular=True,
            events=events,
        ),
        _ADMITTER_PATH: _ProjectedEntry(
            path=_ADMITTER_PATH,
            object_id=_ADMITTER_BLOB,
            regular=True,
            events=events,
        ),
        "vendor/submodule": _ProjectedEntry(
            path="vendor/submodule",
            object_id="4" * 40,
            regular=False,
            events=events,
        ),
    }


def test_public_regular_blob_projection_keeps_reader_live_and_private(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[object] = []
    pin = object()
    monkeypatch.setattr(finalizer_derivation, "_GitReader", _reader_type(events, _entries(events)))

    blobs = finalizer_derivation.resolve_raw_git_regular_blobs(
        repository="raw.git",
        treeish=_TARGET_TREE,
        paths=(
            _PRODUCER_PATH,
            ".github/workflows/missing.yml",
            _ADMITTER_PATH,
            "vendor/submodule",
        ),
        bare=True,
        git_executable=pin,  # type: ignore[arg-type]
    )

    assert blobs == {
        _PRODUCER_PATH: _PRODUCER_BLOB,
        _ADMITTER_PATH: _ADMITTER_BLOB,
    }
    assert all(type(path) is str and type(blob) is str for path, blob in blobs.items())
    assert events == [
        ("init", "raw.git", True, pin),
        "enter",
        ("tree", _TARGET_TREE),
        ("exit", None, None),
        ("project", _PRODUCER_PATH),
        ("project", _ADMITTER_PATH),
        ("project", "vendor/submodule"),
    ]


@pytest.mark.parametrize(
    "paths",
    (
        _PRODUCER_PATH,
        ("",),
        ("../outside.yml",),
        (".github\\workflows\\produce.yml",),
        (object(),),
        None,
    ),
    ids=("scalar-string", "empty", "parent", "backslash", "non-string", "non-iterable"),
)
def test_public_regular_blob_projection_rejects_unexpanded_path_inputs(
    monkeypatch: pytest.MonkeyPatch,
    paths: object,
) -> None:
    events: list[object] = []
    monkeypatch.setattr(finalizer_derivation, "_GitReader", _reader_type(events, {}))

    with pytest.raises(finalizer_derivation.FinalizerDerivationError, match="safe relative paths?"):
        finalizer_derivation.resolve_raw_git_regular_blobs(
            repository="raw.git",
            treeish=_TARGET_TREE,
            paths=paths,  # type: ignore[arg-type]
        )

    assert events == []


def test_receipt_workflow_consumers_preserve_one_reader_lifecycle_each(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[object] = []
    pin = object()
    monkeypatch.setattr(finalizer_derivation, "_GitReader", _reader_type(events, _entries(events)))

    release_source_producer_receipt._verify_producer_workflow_blobs(
        source=_source(),
        producer=_producer(),
        git_repository="raw.git",
        git_repository_is_bare=True,
        git_executable=pin,  # type: ignore[arg-type]
    )
    checked_admitter = (
        release_source_producer_receipt.verify_release_source_admitter_workflow_blob(
            source=_source(),
            producer=_producer(),
            admitter=_admitter(),
            git_repository="raw.git",
            git_repository_is_bare=True,
            git_executable=pin,  # type: ignore[arg-type]
        )
    )

    assert checked_admitter == _admitter()
    lifecycle = [event for event in events if not (isinstance(event, tuple) and event[0] == "project")]
    assert lifecycle == [
        ("init", "raw.git", True, pin),
        "enter",
        ("tree", _TARGET_TREE),
        ("exit", None, None),
        ("init", "raw.git", True, pin),
        "enter",
        ("tree", _TARGET_TREE),
        ("exit", None, None),
    ]


def test_raw_git_primary_error_identity_and_cleanup_context_are_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[object] = []
    primary = finalizer_derivation.FinalizerDerivationError("characterized raw-Git failure")

    class FailingReader:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            events.append("init")

        def __enter__(self) -> FailingReader:
            events.append("enter")
            return self

        def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
            del traceback
            events.append(("exit", exc_type, exc))

        def tree(self, treeish: str) -> dict[str, object]:
            events.append(("tree", treeish))
            raise primary

    monkeypatch.setattr(finalizer_derivation, "_GitReader", FailingReader)

    with pytest.raises(
        release_source_producer_receipt.ReleaseSourceProducerReceiptError,
        match="could not resolve producer workflow from raw Git: characterized raw-Git failure$",
    ) as caught:
        release_source_producer_receipt._verify_producer_workflow_blobs(
            source=_source(),
            producer=_producer(),
            git_repository="raw.git",
            git_repository_is_bare=False,
        )

    assert caught.value.__cause__ is primary
    assert events == [
        "init",
        "enter",
        ("tree", _TARGET_TREE),
        ("exit", finalizer_derivation.FinalizerDerivationError, primary),
    ]


def test_producer_workflow_error_precedence_remains_producer_before_trigger(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[object] = []
    entries = _entries(events)
    del entries[_PRODUCER_PATH]
    monkeypatch.setattr(finalizer_derivation, "_GitReader", _reader_type(events, entries))
    producer = dict(
        _producer(),
        trigger_workflow_blob_sha="f" * 40,
    )

    with pytest.raises(
        release_source_producer_receipt.ReleaseSourceProducerReceiptError,
        match="producer workflow path is not a regular blob in the protected-main tree$",
    ):
        release_source_producer_receipt._verify_producer_workflow_blobs(
            source=_source(),
            producer=producer,
            git_repository="raw.git",
            git_repository_is_bare=False,
        )

    exit_index = events.index(("exit", None, None))
    first_projection_index = next(
        index
        for index, event in enumerate(events)
        if isinstance(event, tuple) and event[0] == "project"
    )
    assert exit_index < first_projection_index
