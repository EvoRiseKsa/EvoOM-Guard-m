"""Focused contracts for typed candidate path preflight."""

from __future__ import annotations

import importlib
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from evoom_guard.verifiers import candidate_preflight as preflight_module
from evoom_guard.verifiers.candidate_preflight import (
    CandidatePreflightRequest,
    evaluate_candidate_preflight,
)

guard_module = importlib.import_module("evoom_guard.guard")


def _request(
    repo: Path,
    *,
    changed: tuple[str, ...],
    deleted: tuple[str, ...] = (),
    protected: tuple[str, ...] = (),
    allow: tuple[str, ...] = (),
    allow_new_tests: bool = False,
    strict_harness: bool = False,
) -> CandidatePreflightRequest:
    return CandidatePreflightRequest(
        repo_path=str(repo),
        changed_paths=changed,
        deleted_paths=deleted,
        protected=protected,
        allow=allow,
        allow_new_tests=allow_new_tests,
        strict_harness=strict_harness,
    )


def test_contracts_are_immutable_and_execute_only_after_admission(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path, changed=("src/app.py",))
    result = evaluate_candidate_preflight(request)

    assert result.changed_paths == ("src/app.py",)
    assert result.all_touched_paths == ("src/app.py",)
    assert result.may_execute is True
    with pytest.raises(FrozenInstanceError):
        result.unsafe_paths = ("late",)  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        request.changed_paths = ("late",)  # type: ignore[misc]


def test_empty_candidate_never_executes(tmp_path: Path) -> None:
    result = evaluate_candidate_preflight(_request(tmp_path, changed=()))
    assert result.all_touched_paths == ()
    assert result.may_execute is False


def test_unsafe_paths_fail_closed_and_never_become_safe_deletions(
    tmp_path: Path,
) -> None:
    result = evaluate_candidate_preflight(
        _request(
            tmp_path,
            changed=("src/app.py", "../escape.py"),
            deleted=("../escape.py", "src/old.py"),
        )
    )

    assert result.all_touched_paths == (
        "src/app.py",
        "../escape.py",
        "src/old.py",
    )
    assert result.unsafe_paths == ("../escape.py",)
    assert result.safe_deleted_paths == ("src/old.py",)
    assert result.may_execute is False


def test_reserved_pack_namespace_is_never_candidate_writable(
    tmp_path: Path,
) -> None:
    result = evaluate_candidate_preflight(
        _request(
            tmp_path,
            changed=("evoguard_verifier_pack/helper.py",),
            protected=("*",),
            allow=("*",),
            allow_new_tests=True,
        )
    )
    assert result.protected_violations == (
        "evoguard_verifier_pack/helper.py",
    )
    assert result.may_execute is False


def test_builtin_harness_path_cannot_be_allowlisted(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_existing.py").write_text(
        "def test_existing(): pass\n",
        encoding="utf-8",
    )
    result = evaluate_candidate_preflight(
        _request(
            tmp_path,
            changed=("tests/test_existing.py",),
            allow=("tests/*",),
        )
    )
    assert result.protected_violations == ("tests/test_existing.py",)


def test_feature_mode_relaxes_only_a_new_plain_test(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_existing.py").write_text(
        "def test_existing(): pass\n",
        encoding="utf-8",
    )
    new_test = evaluate_candidate_preflight(
        _request(
            tmp_path,
            changed=("tests/test_new.py",),
            allow_new_tests=True,
        )
    )
    existing_test = evaluate_candidate_preflight(
        _request(
            tmp_path,
            changed=("tests/test_existing.py",),
            allow_new_tests=True,
        )
    )

    assert new_test.new_paths == frozenset({"tests/test_new.py"})
    assert new_test.protected_violations == ()
    assert new_test.may_execute is True
    assert existing_test.new_paths == frozenset()
    assert existing_test.protected_violations == ("tests/test_existing.py",)
    assert existing_test.may_execute is False


def test_local_action_helper_is_bound_from_the_base_tree(tmp_path: Path) -> None:
    workflow = tmp_path / ".github" / "workflows"
    action = tmp_path / ".ci" / "guard"
    workflow.mkdir(parents=True)
    action.mkdir(parents=True)
    (action / "action.yml").write_text("runs:\n  using: composite\n", encoding="utf-8")
    (workflow / "guard.yml").write_text(
        "jobs:\n  guard:\n    steps:\n      - uses: ./.ci/guard\n",
        encoding="utf-8",
    )

    result = evaluate_candidate_preflight(
        _request(tmp_path, changed=(".ci/guard/check.py",))
    )

    assert result.local_action_dirs == (".ci/guard",)
    assert result.protected_violations == (".ci/guard/check.py",)


def test_protected_deletion_is_not_in_safe_deletion_set(tmp_path: Path) -> None:
    result = evaluate_candidate_preflight(
        _request(
            tmp_path,
            changed=("src/app.py",),
            deleted=("tests/test_existing.py", "src/old.py"),
            allow_new_tests=True,
        )
    )

    assert result.protected_violations == ("tests/test_existing.py",)
    assert result.safe_deleted_paths == ("src/old.py",)


def test_path_existence_is_checked_before_local_action_discovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fail_exists(path: str) -> bool:
        calls.append(f"exists:{path}")
        raise RuntimeError("synthetic path lookup failure")

    def discover(_repo: str) -> tuple[str, ...]:
        calls.append("discover")
        return ()

    monkeypatch.setattr(preflight_module.os.path, "exists", fail_exists)
    monkeypatch.setattr(preflight_module, "discover_local_action_dirs", discover)

    with pytest.raises(RuntimeError, match="synthetic path lookup failure"):
        evaluate_candidate_preflight(
            _request(tmp_path, changed=("src/new.py",))
        )
    assert len(calls) == 1
    assert calls[0].startswith("exists:")


def test_deletion_violation_is_rechecked_before_it_is_declared_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[str] = []
    original = preflight_module.is_judge_autoexec

    def traced(path: str) -> bool:
        observed.append(path)
        return original(path)

    monkeypatch.setattr(preflight_module, "is_judge_autoexec", traced)
    result = evaluate_candidate_preflight(
        _request(tmp_path, changed=(), deleted=("src/old.py",))
    )

    assert result.safe_deleted_paths == ("src/old.py",)
    assert observed == ["src/old.py", "src/old.py"]


def test_guard_adapter_preserves_historical_path_policy_patch_seams(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(guard_module, "is_safe_relpath", lambda _path: False)
    candidate = "<<<FILE: src/app.py>>>\nVALUE = 1\n<<<END FILE>>>"

    result = guard_module.guard(str(tmp_path), candidate)

    assert result.verdict == "ERROR"
    assert result.reason_code == "unsafe_path"
    assert result.files_changed == ["src/app.py"]


def test_guard_adapter_resolves_later_policy_seams_after_discovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An earlier callback may replace a later historical Guard seam."""

    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("VALUE = 1\n", encoding="utf-8")

    def discover_and_replace(_repo: str) -> tuple[str, ...]:
        monkeypatch.setattr(
            guard_module,
            "is_judge_autoexec",
            lambda path: path == "src/app.py",
        )
        return ()

    monkeypatch.setattr(
        guard_module,
        "discover_local_action_dirs",
        discover_and_replace,
    )
    candidate = "<<<FILE: src/app.py>>>\nVALUE = 2\n<<<END FILE>>>"

    result = guard_module.guard(str(tmp_path), candidate)

    assert result.verdict == "REJECTED"
    assert result.protected_violations == ["src/app.py"]
    assert result.test_command_ran is False


def test_guard_adapter_injects_the_live_reserved_pack_namespace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The historical Guard constant remains a live compatibility seam."""

    monkeypatch.setattr(guard_module, "VERIFIER_PACK_DIR", "custom_pack")
    candidate = "<<<FILE: custom_pack/helper.py>>>\nVALUE = 1\n<<<END FILE>>>"

    result = guard_module.guard(str(tmp_path), candidate)

    assert result.verdict == "REJECTED"
    assert result.protected_violations == ["custom_pack/helper.py"]
    assert result.test_command_ran is False


def test_guard_adapter_reads_reserved_namespace_after_discovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reserved namespace stays live across earlier patched callbacks."""

    def discover_and_replace(_repo: str) -> tuple[str, ...]:
        monkeypatch.setattr(guard_module, "VERIFIER_PACK_DIR", "late_pack")
        return ()

    monkeypatch.setattr(
        guard_module,
        "discover_local_action_dirs",
        discover_and_replace,
    )
    candidate = "<<<FILE: late_pack/helper.py>>>\nVALUE = 1\n<<<END FILE>>>"

    result = guard_module.guard(str(tmp_path), candidate)

    assert result.verdict == "REJECTED"
    assert result.protected_violations == ["late_pack/helper.py"]
    assert result.test_command_ran is False
