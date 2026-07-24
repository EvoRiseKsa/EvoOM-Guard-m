"""Direct contracts for the repository pack-continuity owner."""

from __future__ import annotations

import sys
from dataclasses import FrozenInstanceError
from typing import Any

import pytest

from evoom_guard.pack_manifest import PackManifestError
from evoom_guard.verifiers import repo_verifier
from evoom_guard.verifiers.repo_pack_continuity import (
    AcceptedRepoPackIdentity,
    RepoPackContinuity,
    RepoPackContinuityRequest,
    RepoPackContinuityServices,
)


def _identity(
    manifest: dict[str, Any] | None = None,
) -> AcceptedRepoPackIdentity:
    return AcceptedRepoPackIdentity(
        sha256="a" * 64,
        manifest=manifest,
    )


def _owner(provider: Any) -> RepoPackContinuity:
    return RepoPackContinuity(
        RepoPackContinuityRequest(
            pack_snapshot="accepted-pack",
            identity=_identity({"id": "pack", "version": "1"}),
        ),
        RepoPackContinuityServices(
            verify_snapshot=lambda: provider,
        ),
    )


def test_accepted_identity_is_an_immutable_isolated_snapshot() -> None:
    manifest: dict[str, Any] = {
        "id": "pack",
        "version": "1",
        "nested": {"value": "accepted"},
    }
    identity = _identity(manifest)

    manifest["id"] = "caller-mutated"
    manifest["nested"]["value"] = "caller-mutated"
    concrete = identity.concrete()
    assert concrete == (
        "a" * 64,
        {
            "id": "pack",
            "version": "1",
            "nested": {"value": "accepted"},
        },
    )

    assert concrete[1] is not None
    concrete[1]["id"] = "provider-mutated"
    assert identity.concrete()[1]["id"] == "pack"  # type: ignore[index]
    with pytest.raises(TypeError):
        identity.manifest["id"] = "changed"  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        identity.sha256 = "b" * 64  # type: ignore[misc]


def test_live_provider_and_same_identity_are_used_at_both_checkpoints() -> None:
    events: list[tuple[str, str, dict[str, Any] | None]] = []
    state: dict[str, Any] = {}

    def after(snapshot: str, identity: tuple[str, dict[str, Any] | None]) -> None:
        events.append(("after", snapshot, identity[1]))

    def before(snapshot: str, identity: tuple[str, dict[str, Any] | None]) -> None:
        events.append(("before", snapshot, identity[1]))
        assert identity[1] is not None
        identity[1]["id"] = "provider-mutated-copy"
        state["provider"] = after

    state["provider"] = before
    owner = RepoPackContinuity(
        RepoPackContinuityRequest(
            pack_snapshot="accepted-pack",
            identity=_identity({"id": "pack", "version": "1"}),
        ),
        RepoPackContinuityServices(
            verify_snapshot=lambda: state["provider"],
        ),
    )

    assert owner.verify_before_execution() is None
    assert owner.phase == "pre_execution_verified"
    assert owner.verify_after_execution() is None
    assert owner.phase == "delivered"
    assert events == [
        (
            "before",
            "accepted-pack",
            {"id": "provider-mutated-copy", "version": "1"},
        ),
        (
            "after",
            "accepted-pack",
            {"id": "pack", "version": "1"},
        ),
    ]
    assert owner.identity.concrete()[1] == {"id": "pack", "version": "1"}


def test_pre_execution_snapshot_failure_is_typed_and_sticky() -> None:
    calls = 0

    def changed(
        _snapshot: str,
        _identity: tuple[str, dict[str, Any] | None],
    ) -> None:
        nonlocal calls
        calls += 1
        raise PackManifestError("controlled pre-execution drift")

    owner = _owner(changed)
    failure = owner.verify_before_execution()

    assert failure is not None
    assert failure.kind == "snapshot_changed"
    assert failure.checkpoint == "before_execution"
    assert failure.diagnostics == (
        "verifier pack was changed before execution: "
        "controlled pre-execution drift"
    )
    assert owner.phase == "failed"
    assert owner.verify_before_execution() is failure
    assert owner.verify_after_execution() is failure
    assert calls == 1


def test_post_execution_snapshot_failure_cannot_be_recovered() -> None:
    calls = 0

    def verify(
        _snapshot: str,
        _identity: tuple[str, dict[str, Any] | None],
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise PackManifestError("controlled post-execution drift")

    owner = _owner(verify)
    assert owner.verify_before_execution() is None
    failure = owner.verify_after_execution()

    assert failure is not None
    assert failure.kind == "snapshot_changed"
    assert failure.checkpoint == "after_execution"
    assert failure.diagnostics == (
        "verifier pack changed while executing: "
        "controlled post-execution drift"
    )
    assert owner.phase == "failed"
    assert owner.verify_after_execution() is failure
    assert calls == 2


def test_after_execution_cannot_skip_the_pre_execution_checkpoint() -> None:
    owner = _owner(lambda *_args: None)

    with pytest.raises(
        RuntimeError,
        match="expected 'pre_execution_verified'",
    ):
        owner.verify_after_execution()

    assert owner.phase == "accepted"


def test_delivered_owner_cannot_repeat_or_reverse_a_checkpoint() -> None:
    calls = 0

    def verify(*_args: Any) -> None:
        nonlocal calls
        calls += 1

    owner = _owner(verify)
    assert owner.verify_before_execution() is None
    assert owner.verify_after_execution() is None

    with pytest.raises(RuntimeError, match="phase 'delivered'"):
        owner.verify_after_execution()
    with pytest.raises(RuntimeError, match="phase 'delivered'"):
        owner.verify_before_execution()
    assert calls == 2


def test_unexpected_provider_failure_is_re_raised_and_terminal() -> None:
    provider_failure = KeyboardInterrupt("controlled provider interruption")
    calls = 0

    def interrupt(*_args: Any) -> None:
        nonlocal calls
        calls += 1
        raise provider_failure

    owner = _owner(interrupt)

    with pytest.raises(KeyboardInterrupt) as first:
        owner.verify_before_execution()
    assert first.value is provider_failure
    assert owner.phase == "failed"
    assert owner.provider_failure is provider_failure

    with pytest.raises(KeyboardInterrupt) as second:
        owner.verify_after_execution()
    assert second.value is provider_failure
    assert calls == 1


def test_facade_injects_a_live_provider_at_both_checkpoints(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "test_contract.py").write_text(
        "def test_contract():\n    assert True\n",
        encoding="utf-8",
    )
    events: list[str] = []
    original_owner = repo_verifier.RepoPackContinuity

    def unexpected(*_args: Any) -> None:
        raise AssertionError("facade snapshotted the pack verifier early")

    def after(*_args: Any) -> None:
        events.append("after")

    def before(*_args: Any) -> None:
        events.append("before")
        monkeypatch.setattr(
            repo_verifier,
            "verify_pack_snapshot",
            after,
        )

    def construct_owner(*args: Any, **kwargs: Any) -> RepoPackContinuity:
        owner = original_owner(*args, **kwargs)
        monkeypatch.setattr(
            repo_verifier,
            "verify_pack_snapshot",
            before,
        )
        return owner

    monkeypatch.setattr(repo_verifier, "verify_pack_snapshot", unexpected)
    monkeypatch.setattr(repo_verifier, "RepoPackContinuity", construct_owner)

    result = repo_verifier.RepoVerifier(
        test_command=[
            sys.executable,
            "-c",
            "raise SystemExit(0)",
        ],
        mem_limit_mb=0,
    ).verify(
        "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
        {
            "repo_path": str(source),
            "verifier_pack": str(pack),
        },
    )

    assert result.passed, result.diagnostics
    assert events == ["before", "after"]


def test_facade_provider_failure_reaches_outer_cleanup_as_primary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "test_contract.py").write_text(
        "def test_contract():\n    assert True\n",
        encoding="utf-8",
    )
    provider_failure = KeyboardInterrupt("controlled provider interruption")
    cleanup_observations: list[
        tuple[tuple[tuple[str, str | None], ...], BaseException | None]
    ] = []
    original_cleanup = repo_verifier._cleanup_repo_workspaces

    def interrupting_verify(*_args: Any) -> None:
        raise provider_failure

    def recording_cleanup(workspaces, *, primary):
        cleanup_observations.append((tuple(workspaces), primary))
        return original_cleanup(workspaces, primary=primary)

    monkeypatch.setattr(
        repo_verifier,
        "verify_pack_snapshot",
        interrupting_verify,
    )
    monkeypatch.setattr(
        repo_verifier,
        "_cleanup_repo_workspaces",
        recording_cleanup,
    )

    with pytest.raises(KeyboardInterrupt) as caught:
        repo_verifier.RepoVerifier(
            test_command=[
                sys.executable,
                "-c",
                "raise SystemExit(0)",
            ],
            mem_limit_mb=0,
        ).verify(
            "<<<FILE: app.py>>>\nVALUE = 2\n<<<END FILE>>>",
            {
                "repo_path": str(source),
                "verifier_pack": str(pack),
            },
        )

    assert caught.value is provider_failure
    assert len(cleanup_observations) == 1
    workspaces, primary = cleanup_observations[0]
    assert primary is provider_failure
    assert workspaces[0][0] == "candidate workspace"
    assert workspaces[0][1]
    assert workspaces[1][0] == "verifier-pack snapshot"
    assert workspaces[1][1]
