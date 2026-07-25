"""Deterministic characterization of repository-judgment cleanup effects."""

from __future__ import annotations

import json
from contextlib import ExitStack
from pathlib import Path
from typing import Any
from unittest.mock import patch

from evoom_guard.verifiers import repo_verifier

SCHEMA_VERSION = "repo-cleanup-characterization-v1"
CASE_NAMES = (
    "all_success",
    "file_not_found_absent",
    "file_not_found_present",
    "no_primary_multiple_failures",
    "note_facade_live_provider",
    "outer_finally_callable_capture",
    "primary_baseexception_multiple_failures",
    "proof_baseexception",
    "provider_capture_order",
)

_WORKSPACES = (
    ("candidate workspace", "candidate"),
    ("verifier-pack snapshot", "pack"),
    ("unused workspace", None),
)


def canonical_json(value: Any) -> str:
    """Return stable, human-reviewable JSON."""

    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _exception_payload(
    error: BaseException | None,
    identities: dict[str, BaseException],
) -> dict[str, str] | None:
    if error is None:
        return None
    token = next(
        (
            name
            for name, candidate in identities.items()
            if error is candidate
        ),
        "<unrecognized>",
    )
    return {
        "message": str(error),
        "token": token,
        "type": type(error).__name__,
    }


def _capture_cleanup_semantics(case_name: str) -> dict[str, Any]:
    events: list[dict[str, str]] = []
    notes: list[dict[str, str]] = []
    primary: BaseException | None = None
    identities: dict[str, BaseException] = {}
    failures: dict[str, BaseException] = {}
    proof_result: bool | BaseException | None = None

    if case_name == "primary_baseexception_multiple_failures":
        primary = KeyboardInterrupt("operator interruption")
        identities["primary"] = primary
        failures = {
            "candidate": OSError("candidate busy"),
            "pack": SystemExit("pack cleanup interrupted"),
        }
        identities.update(
            {
                "candidate_failure": failures["candidate"],
                "pack_failure": failures["pack"],
            }
        )
    elif case_name == "no_primary_multiple_failures":
        failures = {
            "candidate": OSError("candidate busy"),
            "pack": SystemExit("pack cleanup interrupted"),
        }
        identities.update(
            {
                "candidate_failure": failures["candidate"],
                "pack_failure": failures["pack"],
            }
        )
    elif case_name == "file_not_found_absent":
        failures = {
            "candidate": FileNotFoundError("raced child disappeared"),
        }
        identities["candidate_failure"] = failures["candidate"]
        proof_result = True
    elif case_name == "file_not_found_present":
        failures = {
            "candidate": FileNotFoundError("raced child disappeared"),
        }
        identities["candidate_failure"] = failures["candidate"]
        proof_result = False
    elif case_name == "proof_baseexception":
        failures = {
            "candidate": FileNotFoundError("raced child disappeared"),
        }
        proof_error = SystemExit("absence proof interrupted")
        identities.update(
            {
                "candidate_failure": failures["candidate"],
                "proof_failure": proof_error,
            }
        )
        proof_result = proof_error

    def token(error: BaseException) -> str:
        return next(
            (
                name
                for name, candidate in identities.items()
                if error is candidate
            ),
            "<unrecognized>",
        )

    def remove_tree(path: str) -> None:
        events.append({"op": "remove", "path": path})
        failure = failures.get(path)
        if failure is not None:
            raise failure

    def note_failure(error: BaseException, message: str) -> None:
        notes.append(
            {
                "error": token(error),
                "message": message,
            }
        )

    def path_absent(path: str) -> bool:
        events.append({"op": "prove-absent", "path": path})
        if isinstance(proof_result, BaseException):
            raise proof_result
        assert isinstance(proof_result, bool)
        return proof_result

    raised: BaseException | None = None
    with ExitStack() as stack:
        stack.enter_context(
            patch.object(repo_verifier.shutil, "rmtree", remove_tree)
        )
        stack.enter_context(
            patch.object(
                repo_verifier,
                "_note_repo_cleanup_failure",
                note_failure,
            )
        )
        if proof_result is not None:
            stack.enter_context(
                patch.object(
                    repo_verifier._repository_workspace,
                    "repository_path_absent",
                    path_absent,
                )
            )
        try:
            repo_verifier._cleanup_repo_workspaces(
                _WORKSPACES,
                primary=primary,
            )
        except BaseException as error:
            raised = error

    return {
        "events": events,
        "exception": _exception_payload(raised, identities),
        "notes": notes,
        "primary": _exception_payload(primary, identities),
    }


def _capture_note_facade_live_provider() -> dict[str, Any]:
    events: list[dict[str, str]] = []
    primary = RuntimeError("primary")

    def note_failure(error: BaseException, message: str) -> None:
        events.append(
            {
                "error_is_primary": str(error is primary).lower(),
                "message": message,
                "op": "call-note-provider",
            }
        )

    class WorkspaceProxy:
        @property
        def note_cleanup_failure(self) -> object:
            events.append({"op": "lookup-note-provider"})
            return note_failure

    with patch.object(
        repo_verifier,
        "_repository_workspace",
        WorkspaceProxy(),
    ):
        repo_verifier._note_repo_cleanup_failure(primary, "diagnostic")

    return {"events": events}


def _capture_provider_order() -> dict[str, Any]:
    events: list[dict[str, str]] = []
    primary = RuntimeError("primary")

    def unexpected(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a provider was snapshotted at the wrong time")

    def late_remove(path: str) -> None:
        events.append({"op": "call-late-remove", "path": path})

    def late_note(error: BaseException, message: str) -> None:
        events.append(
            {
                "error_is_primary": str(error is primary).lower(),
                "message": message,
                "op": "call-late-note",
            }
        )

    def cleanup_owner(
        workspaces: tuple[tuple[str, str | None], ...],
        *,
        primary: BaseException | None,
        remove_tree: object,
        note_failure: object,
        owner_name: str,
    ) -> None:
        events.append(
            {
                "op": "call-cleanup-owner",
                "owner_name": owner_name,
                "primary": type(primary).__name__ if primary is not None else "none",
                "workspaces": str(len(workspaces)),
            }
        )
        repo_verifier.shutil = EarlyShutil()
        repo_verifier._note_repo_cleanup_failure = unexpected
        assert callable(remove_tree)
        assert callable(note_failure)
        remove_tree("captured-path")
        note_failure(primary, "captured-note")

    class EarlyShutil:
        @property
        def rmtree(self) -> object:
            events.append({"op": "lookup-unexpected-early-remove"})
            return unexpected

    class LateShutil:
        @property
        def rmtree(self) -> object:
            events.append({"op": "lookup-late-remove"})
            repo_verifier._note_repo_cleanup_failure = late_note
            return late_remove

    class WorkspaceProxy:
        @property
        def cleanup_repo_workspaces(self) -> object:
            events.append({"op": "lookup-cleanup-owner"})
            repo_verifier.shutil = LateShutil()
            return cleanup_owner

    with ExitStack() as stack:
        stack.enter_context(
            patch.object(
                repo_verifier,
                "_repository_workspace",
                WorkspaceProxy(),
            )
        )
        stack.enter_context(
            patch.object(repo_verifier, "shutil", EarlyShutil())
        )
        stack.enter_context(
            patch.object(
                repo_verifier,
                "_note_repo_cleanup_failure",
                unexpected,
            )
        )
        repo_verifier._cleanup_repo_workspaces(
            _WORKSPACES,
            primary=primary,
        )

    return {"events": events}


def _capture_outer_finally_callable(
    workspace: Path,
) -> dict[str, Any]:
    source = workspace / "source"
    source.mkdir(parents=True)
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    events: list[dict[str, str]] = []
    failure = RuntimeError("controlled copy failure")

    def early_cleanup(
        workspaces: tuple[tuple[str, str | None], ...],
        *,
        primary: BaseException | None,
    ) -> None:
        events.append(
            {
                "op": "early-cleanup",
                "primary_is_failure": str(primary is failure).lower(),
                "workspaces": repr(workspaces),
            }
        )

    def late_cleanup(
        _workspaces: tuple[tuple[str, str | None], ...],
        *,
        primary: BaseException | None,
    ) -> None:
        events.append(
            {
                "op": "late-cleanup",
                "primary_is_failure": str(primary is failure).lower(),
            }
        )

    class FakeLifetime:
        candidate_root = "candidate-root"
        candidate_copy = "candidate-copy"

        def cleanup_targets(
            self,
        ) -> tuple[tuple[str, str | None], ...]:
            events.append({"op": "evaluate-cleanup-targets"})
            repo_verifier._cleanup_repo_workspaces = late_cleanup
            return (
                ("candidate workspace", self.candidate_root),
                ("verifier-pack snapshot", None),
            )

    class LifetimeFactory:
        @classmethod
        def create(
            cls,
            *,
            prefix: str,
            create_workspace: object,
            join_path: object,
        ) -> FakeLifetime:
            del cls, create_workspace, join_path
            events.append({"op": "create-lifetime", "prefix": prefix})
            return FakeLifetime()

    def fail_copy(source_path: str, destination_path: str) -> None:
        events.append(
            {
                "destination": destination_path,
                "op": "copy",
                "source_is_expected": str(
                    source_path == str(source)
                ).lower(),
            }
        )
        raise failure

    raised: BaseException | None = None
    with ExitStack() as stack:
        stack.enter_context(
            patch.object(
                repo_verifier,
                "RepositoryWorkspaceLifetime",
                LifetimeFactory,
            )
        )
        stack.enter_context(
            patch.object(repo_verifier, "copy_repo_tree", fail_copy)
        )
        stack.enter_context(
            patch.object(
                repo_verifier,
                "_cleanup_repo_workspaces",
                early_cleanup,
            )
        )
        try:
            repo_verifier.RepoVerifier(mem_limit_mb=0).verify(
                "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>\n",
                {"repo_path": str(source)},
            )
        except BaseException as error:
            raised = error

    return {
        "events": events,
        "exception": _exception_payload(raised, {"copy_failure": failure}),
    }


def capture_case(case_name: str, workspace: Path) -> dict[str, Any]:
    """Capture one reviewed cleanup branch through the legacy facade."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown repository-cleanup case: {case_name}")
    if case_name == "note_facade_live_provider":
        return _capture_note_facade_live_provider()
    if case_name == "provider_capture_order":
        return _capture_provider_order()
    if case_name == "outer_finally_callable_capture":
        return _capture_outer_finally_callable(workspace)
    return _capture_cleanup_semantics(case_name)


def capture_all(workspace: Path) -> dict[str, Any]:
    """Capture every reviewed repository-cleanup case."""

    return {
        "cases": {
            name: capture_case(name, workspace / name)
            for name in CASE_NAMES
        },
        "schema_version": SCHEMA_VERSION,
    }
