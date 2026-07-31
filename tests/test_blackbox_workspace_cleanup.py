# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Black-box workspaces are owned resources with fail-closed cleanup proof."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

import evoom_guard.blackbox as blackbox_module
from evoom_guard.blackbox import BlackboxResult, run_blackbox
from evoom_guard.guard import ERROR, REASON_RUNTIME_CLEANUP_FAILED, guard


class _Evidence:
    def as_dict(self) -> dict[str, object]:
        return {
            "requested": "subprocess",
            "delivered": "subprocess",
            "note": "workspace cleanup test boundary",
        }


class _Recorder:
    path = "workspace-cleanup-test.sock"
    token = "workspace-cleanup-test-token"

    def drain(self) -> int:
        return 0

    def close(self) -> None:
        return None


def _install_runtime(
    monkeypatch: pytest.MonkeyPatch,
    judge: object,
) -> None:
    def prepare(
        _runner: object,
        _workdir: str,
        target_dir: str,
    ) -> tuple[str, dict[str, str], _Evidence]:
        return (
            "launcher",
            {
                "EVOGUARD_EXEC": "workspace-cleanup-launcher",
                "EVOGUARD_TARGET": target_dir,
            },
            _Evidence(),
        )

    monkeypatch.setattr(
        blackbox_module._InvocationRecorder,
        "create",
        lambda _workdir: _Recorder(),
    )
    monkeypatch.setattr(blackbox_module.CandidateRunner, "prepare", prepare)
    monkeypatch.setattr(blackbox_module, "_run_judge_process", judge)


def _repo_pack_candidate(tmp_path: Path) -> tuple[Path, Path, str]:
    repo = tmp_path / "repo"
    pack = tmp_path / "pack"
    repo.mkdir()
    pack.mkdir()
    (repo / "app.py").write_text("value = 1\n", encoding="utf-8")
    (pack / "test_protocol.py").write_text(
        "def test_protocol():\n    assert True\n",
        encoding="utf-8",
    )
    candidate = "<<<FILE: app.py>>>\nvalue = 2\n<<<END FILE>>>\n"
    return repo, pack, candidate


def _completed_judge(
    command: list[str], **_kwargs: object
) -> subprocess.CompletedProcess[str]:
    xml_arg = next(part for part in command if part.startswith("--junitxml="))
    Path(xml_arg.split("=", 1)[1]).write_text(
        '<testsuites><testsuite tests="1" failures="0" errors="0">'
        '<testcase name="ok"/></testsuite></testsuites>',
        encoding="utf-8",
    )
    return subprocess.CompletedProcess(command, 0, "", "")


def _failed_judge(
    command: list[str], **_kwargs: object
) -> subprocess.CompletedProcess[str]:
    xml_arg = next(part for part in command if part.startswith("--junitxml="))
    Path(xml_arg.split("=", 1)[1]).write_text(
        '<testsuites><testsuite tests="1" failures="1" errors="0">'
        '<testcase name="broken"><failure message="expected"/>'
        "</testcase></testsuite></testsuites>",
        encoding="utf-8",
    )
    return subprocess.CompletedProcess(command, 1, "", "")


def _workspace_label(path: str) -> str:
    name = Path(str(path)).name
    return "pack" if name.startswith("evo_blackbox_pack_") else "candidate"


def test_blackbox_removes_both_nominally_owned_workspaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    real_remove_tree = shutil.rmtree
    removals: list[tuple[str, str, str]] = []

    def observed_remove(path: str) -> None:
        removals.append((_workspace_label(path), type(path).__name__, str(path)))
        real_remove_tree(path)

    _install_runtime(monkeypatch, _completed_judge)
    monkeypatch.setattr(blackbox_module.shutil, "rmtree", observed_remove)

    result = run_blackbox(str(repo), candidate, str(pack))

    assert result.passed is True
    assert [label for label, _type, _path in removals] == ["candidate", "pack"]
    assert all(path_type == "_OwnedWorkspacePath" for _, path_type, _ in removals)
    assert all(not os.path.lexists(path) for _, _, path in removals)


@pytest.mark.parametrize(
    "judge",
    [_completed_judge, _failed_judge],
    ids=["pending-pass", "pending-fail"],
)
@pytest.mark.parametrize("failed_root", ["candidate", "pack"])
def test_normal_workspace_cleanup_failure_invalidates_pending_verdict_and_attempts_all(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    judge: object,
    failed_root: str,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    real_remove_tree = shutil.rmtree
    removals: list[tuple[str, str]] = []

    def failing_candidate_remove(path: str) -> None:
        label = _workspace_label(path)
        removals.append((label, str(path)))
        if label == failed_root:
            raise OSError(f"{label} workspace retained")
        real_remove_tree(path)

    _install_runtime(monkeypatch, judge)
    monkeypatch.setattr(blackbox_module.shutil, "rmtree", failing_candidate_remove)

    try:
        result = run_blackbox(str(repo), candidate, str(pack))
    finally:
        for _label, path in removals:
            if os.path.lexists(path):
                real_remove_tree(path)

    assert [label for label, _path in removals] == ["candidate", "pack"]
    assert result.passed is False
    assert result.ran is False
    assert result.error == "black-box workspace cleanup failed"
    assert result.started is True
    assert result.completed is False
    assert result.execution_state == "started_incomplete"
    assert f"OSError: {failed_root} workspace retained" in result.diagnostics
    assert len(result.diagnostics) <= 2000


def test_file_not_found_without_fresh_absence_proof_is_not_silenced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    real_remove_tree = shutil.rmtree
    retained: list[str] = []

    def raced_remove(path: str) -> None:
        if _workspace_label(path) == "candidate":
            retained.append(str(path))
            raise FileNotFoundError("child raced while root remains")
        real_remove_tree(path)

    _install_runtime(monkeypatch, _completed_judge)
    monkeypatch.setattr(blackbox_module.shutil, "rmtree", raced_remove)

    try:
        result = run_blackbox(str(repo), candidate, str(pack))
    finally:
        for path in retained:
            if os.path.lexists(path):
                real_remove_tree(path)

    assert result.error == "black-box workspace cleanup failed"
    assert "FileNotFoundError" in result.diagnostics


def test_cleanup_keyboard_interrupt_is_visible_and_does_not_skip_pack_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    real_remove_tree = shutil.rmtree
    removals: list[tuple[str, str]] = []
    primary = KeyboardInterrupt("operator interrupted workspace cleanup")

    def interrupted_remove(path: str) -> None:
        label = _workspace_label(path)
        removals.append((label, str(path)))
        if label == "candidate":
            raise primary
        real_remove_tree(path)

    _install_runtime(monkeypatch, _completed_judge)
    monkeypatch.setattr(blackbox_module.shutil, "rmtree", interrupted_remove)

    try:
        with pytest.raises(KeyboardInterrupt) as caught:
            run_blackbox(str(repo), candidate, str(pack))
    finally:
        for _label, path in removals:
            if os.path.lexists(path):
                real_remove_tree(path)

    assert caught.value is primary
    assert [label for label, _path in removals] == ["candidate", "pack"]


def test_workspace_cleanup_failures_are_notes_on_the_exact_active_primary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    real_remove_tree = shutil.rmtree
    allocated: list[str] = []
    primary = KeyboardInterrupt("operator stopped black-box judge")

    def interrupted_judge(*_args: object, **_kwargs: object) -> None:
        raise primary

    def failing_remove(path: str) -> None:
        allocated.append(str(path))
        raise OSError(f"retained {_workspace_label(path)} workspace")

    _install_runtime(monkeypatch, interrupted_judge)
    monkeypatch.setattr(blackbox_module.shutil, "rmtree", failing_remove)

    try:
        with pytest.raises(KeyboardInterrupt) as caught:
            run_blackbox(str(repo), candidate, str(pack))
    finally:
        for path in allocated:
            if os.path.lexists(path):
                real_remove_tree(path)

    assert caught.value is primary
    notes = getattr(primary, "__notes__", ())
    assert len(notes) == 2
    assert "candidate workspace cleanup failed" in notes[0]
    assert "verifier-pack snapshot workspace cleanup failed" in notes[1]


def test_workspace_failures_remain_visible_beneath_reportable_container_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    real_remove_tree = shutil.rmtree
    allocated: list[str] = []

    def container_cleanup(*_args: object, **_kwargs: object) -> None:
        raise blackbox_module.CandidateContainerCleanupError(
            "candidate container absence unproven"
        )

    def failing_remove(path: str) -> None:
        allocated.append(str(path))
        raise OSError(f"retained {_workspace_label(path)} workspace")

    _install_runtime(monkeypatch, _completed_judge)
    monkeypatch.setattr(
        blackbox_module,
        "_cleanup_candidate_containers",
        container_cleanup,
    )
    monkeypatch.setattr(blackbox_module.shutil, "rmtree", failing_remove)

    try:
        result = run_blackbox(str(repo), candidate, str(pack))
    finally:
        for path in allocated:
            if os.path.lexists(path):
                real_remove_tree(path)

    assert result.error == "candidate container cleanup failed"
    assert "candidate container absence unproven" in result.diagnostics
    assert "secondary cleanup:" in result.diagnostics
    assert "candidate workspace cleanup failed" in result.diagnostics
    assert "verifier-pack snapshot workspace cleanup failed" in result.diagnostics
    assert len(result.diagnostics) <= 2000


def test_long_prior_diagnostics_cannot_hide_either_workspace_cleanup_failure() -> None:
    result = BlackboxResult(
        False,
        0,
        0,
        "prior-" + "d" * 4000,
        False,
        "candidate container cleanup failed",
    )
    failure = blackbox_module._BlackboxCleanupFailure(result)
    blackbox_module._repository_workspace.note_cleanup_failure(
        failure,
        "Blackbox candidate workspace cleanup failed: " + "a" * 4000,
    )
    blackbox_module._repository_workspace.note_cleanup_failure(
        failure,
        "Blackbox verifier-pack snapshot workspace cleanup failed: " + "b" * 4000
    )

    projected = blackbox_module._cleanup_failure_result_with_notes(failure)

    assert len(projected.diagnostics) <= 2000
    assert projected.diagnostics.startswith("secondary cleanup:")
    assert "candidate workspace cleanup failed" in projected.diagnostics
    assert "verifier-pack snapshot workspace cleanup failed" in projected.diagnostics


@pytest.mark.skipif(os.name != "nt", reason="Windows READONLY cleanup contract")
def test_windows_blackbox_repairs_readonly_entries_in_both_owned_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    roots: list[Path] = []

    def judge(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        xml_arg = next(part for part in command if part.startswith("--junitxml="))
        candidate_root = Path(xml_arg.split("=", 1)[1]).parent
        raw_cwd = kwargs.get("cwd")
        assert isinstance(raw_cwd, str)
        pack_root = Path(raw_cwd).parent
        roots.extend((candidate_root, pack_root))
        for root in roots:
            readonly = root / "cleanup-readonly.txt"
            readonly.write_text("owned\n", encoding="utf-8")
            os.chmod(readonly, stat.S_IREAD)
        return _completed_judge(command, **kwargs)

    _install_runtime(monkeypatch, judge)

    result = run_blackbox(str(repo), candidate, str(pack))

    assert result.passed is True
    assert len(roots) == 2
    assert all(not root.exists() for root in roots)


def test_first_repository_join_failure_still_cleans_the_owned_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    real_join = os.path.join
    real_remove_tree = shutil.rmtree
    removed: list[str] = []
    primary = OSError("repository child path rejected")

    def guarded_join(*parts: str) -> str:
        if (
            len(parts) == 2
            and type(parts[0]).__name__ == "_OwnedWorkspacePath"
            and parts[1] == "repo"
        ):
            raise primary
        return real_join(*parts)

    def observed_remove(path: str) -> None:
        removed.append(str(path))
        real_remove_tree(path)

    monkeypatch.setattr(blackbox_module.os.path, "join", guarded_join)
    monkeypatch.setattr(blackbox_module.shutil, "rmtree", observed_remove)

    with pytest.raises(OSError) as caught:
        run_blackbox(str(repo), candidate, str(pack))

    assert caught.value is primary
    assert len(removed) == 1
    assert not os.path.lexists(removed[0])


def test_cleanup_stage_reuses_prebound_cid_path_and_attempts_both_owned_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    real_join = os.path.join
    real_remove_tree = shutil.rmtree
    removed: list[str] = []
    late_failure = OSError("late candidate cid path provider used")
    cid_joins = 0

    def guarded_join(*parts: str) -> str:
        nonlocal cid_joins
        if (
            len(parts) == 2
            and type(parts[0]).__name__ == "_OwnedWorkspacePath"
            and parts[1] == blackbox_module.CANDIDATE_CID_DIRNAME
        ):
            cid_joins += 1
        return real_join(*parts)

    class LatePath:
        def join(self, *_parts: str) -> str:
            raise late_failure

        def __getattr__(self, name: str) -> object:
            return getattr(os.path, name)

    class LateOs:
        path = LatePath()

        def __getattr__(self, name: str) -> object:
            return getattr(os, name)

    def completed_then_rebind(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        completed = _completed_judge(command, **kwargs)
        monkeypatch.setattr(blackbox_module, "os", LateOs())
        return completed

    def observed_remove(path: str) -> None:
        removed.append(str(path))
        real_remove_tree(path)

    _install_runtime(monkeypatch, completed_then_rebind)
    monkeypatch.setattr(blackbox_module.os.path, "join", guarded_join)
    monkeypatch.setattr(blackbox_module.shutil, "rmtree", observed_remove)

    result = run_blackbox(str(repo), candidate, str(pack))

    assert result.passed is True
    assert cid_joins == 1
    assert len(removed) == 2
    assert all(not os.path.lexists(path) for path in removed)


@pytest.mark.parametrize("body_raises", [False, True], ids=["return", "exception"])
def test_finalization_dependencies_are_bound_before_first_owned_allocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    body_raises: bool,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    real_owner = blackbox_module._repository_workspace
    real_allocate = real_owner.allocate_owned_workspace
    real_os = blackbox_module.os
    real_shutil = blackbox_module.shutil
    real_sys = blackbox_module.sys
    expected_cid_dirname = blackbox_module.CANDIDATE_CID_DIRNAME
    real_mkdtemp = blackbox_module.tempfile.mkdtemp
    real_remove_tree = shutil.rmtree
    allocated: list[str] = []
    allocation_calls = 0
    container_cleanups = 0
    cleanup_cidfile_dirs: list[str] = []
    primary = KeyboardInterrupt("judge primary after provider rebinding")

    class PoisonedPath:
        def join(self, *_parts: str) -> str:
            raise RuntimeError("late path provider used")

        def __getattr__(self, name: str) -> object:
            return getattr(real_os.path, name)

    class PoisonedOs:
        path = PoisonedPath()

        def __getattr__(self, name: str) -> object:
            return getattr(real_os, name)

    class PoisonedShutil:
        def rmtree(self, _path: str) -> None:
            raise RuntimeError("late remove provider used")

        def __getattr__(self, name: str) -> object:
            return getattr(real_shutil, name)

    class PoisonedSys:
        def exc_info(self) -> object:
            raise RuntimeError("late exc-info provider used")

        def __getattr__(self, name: str) -> object:
            return getattr(real_sys, name)

    class PoisonedOwner:
        def __getattr__(self, name: str) -> object:
            raise RuntimeError(f"late workspace owner used: {name}")

    def captured_mkdtemp(**kwargs: object) -> str:
        path = real_mkdtemp(**kwargs)
        allocated.append(path)
        return path

    def poisoning_allocate(**kwargs: object) -> str:
        nonlocal allocation_calls
        allocation_calls += 1
        if allocation_calls == 1:
            monkeypatch.setattr(
                real_owner,
                "repository_path_absent",
                lambda _path: True,
            )
            monkeypatch.setattr(
                blackbox_module,
                "_repository_workspace",
                PoisonedOwner(),
            )
            monkeypatch.setattr(blackbox_module, "os", PoisonedOs())
            monkeypatch.setattr(blackbox_module, "shutil", PoisonedShutil())
            monkeypatch.setattr(blackbox_module, "sys", PoisonedSys())
            monkeypatch.setattr(
                blackbox_module,
                "CANDIDATE_CID_DIRNAME",
                "late-poisoned-cidfiles",
            )
            monkeypatch.setattr(
                blackbox_module,
                "_cleanup_candidate_containers",
                lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    RuntimeError("late container cleanup provider used")
                ),
            )
        return real_allocate(**kwargs)

    def observed_container_cleanup(
        cidfile_dir: str,
        **_kwargs: object,
    ) -> None:
        nonlocal container_cleanups
        container_cleanups += 1
        cleanup_cidfile_dirs.append(cidfile_dir)

    def observed_remove(path: str) -> None:
        real_remove_tree(path)

    def judge(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        if body_raises:
            raise primary
        return _completed_judge(command, **kwargs)

    _install_runtime(monkeypatch, judge)
    monkeypatch.setattr(real_owner, "allocate_owned_workspace", poisoning_allocate)
    monkeypatch.setattr(blackbox_module.tempfile, "mkdtemp", captured_mkdtemp)
    monkeypatch.setattr(
        blackbox_module,
        "_cleanup_candidate_containers",
        observed_container_cleanup,
    )
    monkeypatch.setattr(blackbox_module.shutil, "rmtree", observed_remove)

    if body_raises:
        with pytest.raises(KeyboardInterrupt) as caught:
            run_blackbox(str(repo), candidate, str(pack))
        assert caught.value is primary
    else:
        result = run_blackbox(str(repo), candidate, str(pack))
        assert result.passed is True

    assert allocation_calls == 2
    assert container_cleanups == 1
    assert [Path(path).name for path in cleanup_cidfile_dirs] == [
        expected_cid_dirname
    ]
    assert len(allocated) == 2
    assert all(not os.path.lexists(path) for path in allocated)


def test_exc_info_call_failure_is_deferred_until_both_roots_are_cleaned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    real_sys = blackbox_module.sys
    real_mkdtemp = blackbox_module.tempfile.mkdtemp
    allocated: list[str] = []
    provider_failure = RuntimeError("second exc-info call failed")

    class FailingExcInfoSys:
        calls = 0

        def exc_info(self) -> tuple[object, object, object]:
            self.calls += 1
            if self.calls == 2:
                raise provider_failure
            return (None, None, None)

        def __getattr__(self, name: str) -> object:
            return getattr(real_sys, name)

    failing_sys = FailingExcInfoSys()

    def captured_mkdtemp(**kwargs: object) -> str:
        path = real_mkdtemp(**kwargs)
        allocated.append(path)
        return path

    _install_runtime(monkeypatch, _completed_judge)
    monkeypatch.setattr(blackbox_module, "sys", failing_sys)
    monkeypatch.setattr(blackbox_module.tempfile, "mkdtemp", captured_mkdtemp)

    with pytest.raises(RuntimeError) as caught:
        run_blackbox(str(repo), candidate, str(pack))

    assert caught.value is provider_failure
    assert failing_sys.calls == 2
    assert len(allocated) == 2
    assert all(not os.path.lexists(path) for path in allocated)


@pytest.mark.parametrize("cleanup_stage", ["container", "workspace"])
def test_outer_handled_exception_is_not_adopted_as_the_cleanup_primary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cleanup_stage: str,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    real_remove_tree = shutil.rmtree
    retained: list[str] = []
    ambient = ValueError("caller is handling this exception")

    def workspace_remove(path: str) -> None:
        if cleanup_stage == "workspace" and _workspace_label(path) == "candidate":
            retained.append(str(path))
            raise OSError("candidate workspace retained")
        real_remove_tree(path)

    _install_runtime(monkeypatch, _completed_judge)
    if cleanup_stage == "container":
        monkeypatch.setattr(
            blackbox_module,
            "_cleanup_candidate_containers",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                blackbox_module.CandidateContainerCleanupError(
                    "candidate container retained"
                )
            ),
        )
    monkeypatch.setattr(blackbox_module.shutil, "rmtree", workspace_remove)

    try:
        try:
            raise ambient
        except ValueError as caught:
            assert caught is ambient
            result = run_blackbox(str(repo), candidate, str(pack))
    finally:
        for path in retained:
            if os.path.lexists(path):
                real_remove_tree(path)

    expected_error = (
        "candidate container cleanup failed"
        if cleanup_stage == "container"
        else "black-box workspace cleanup failed"
    )
    assert result.passed is False
    assert result.error == expected_error
    assert getattr(ambient, "__notes__", ()) == ()


def test_recorder_close_cannot_replace_container_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)

    class ClosingRecorder(_Recorder):
        def close(self) -> None:
            raise SystemExit("recorder close secondary")

    container_failure = blackbox_module.CandidateContainerCleanupError(
        "candidate container absence unproven"
    )

    _install_runtime(monkeypatch, _completed_judge)
    monkeypatch.setattr(
        blackbox_module._InvocationRecorder,
        "create",
        lambda _workdir: ClosingRecorder(),
    )
    monkeypatch.setattr(
        blackbox_module,
        "_cleanup_candidate_containers",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(container_failure),
    )

    result = run_blackbox(str(repo), candidate, str(pack))

    assert result.error == "candidate container cleanup failed"
    assert "candidate container absence unproven" in result.diagnostics
    assert "invocation recorder cleanup failed" in result.diagnostics
    assert "SystemExit: recorder close secondary" in result.diagnostics
    assert result.diagnostics.startswith("secondary cleanup:")
    assert "workspace cleanup:" not in result.diagnostics
    assert len(result.diagnostics) <= 2000


def test_active_primary_receives_safe_container_and_recorder_cleanup_notes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    primary = KeyboardInterrupt("judge primary")

    class HostileContainerCleanup(
        blackbox_module.CandidateContainerCleanupError
    ):
        def __str__(self) -> str:
            raise SystemExit("hostile container cleanup string")

    class ClosingRecorder(_Recorder):
        def close(self) -> None:
            raise OSError("recorder socket retained")

    def interrupted_judge(*_args: object, **_kwargs: object) -> None:
        raise primary

    def failing_note_callback(*_args: object, **_kwargs: object) -> None:
        raise SystemExit("note callback failed")

    _install_runtime(monkeypatch, interrupted_judge)
    monkeypatch.setattr(
        blackbox_module._InvocationRecorder,
        "create",
        lambda _workdir: ClosingRecorder(),
    )
    monkeypatch.setattr(
        blackbox_module,
        "_cleanup_candidate_containers",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            HostileContainerCleanup("hidden")
        ),
    )
    monkeypatch.setattr(
        blackbox_module._repository_workspace,
        "note_cleanup_failure",
        failing_note_callback,
    )

    with pytest.raises(KeyboardInterrupt) as caught:
        run_blackbox(str(repo), candidate, str(pack))

    assert caught.value is primary
    notes = getattr(primary, "__notes__", ())
    assert len(notes) == 2
    assert all(len(note) <= 2000 for note in notes)
    assert "candidate container cleanup failed" in notes[0]
    assert "unprintable cleanup exception" in notes[0]
    assert "invocation recorder cleanup failed" in notes[1]
    assert all("note callback failed" in note for note in notes)


def test_active_primary_survives_hostile_workspace_cleanup_reporting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    real_remove_tree = shutil.rmtree
    attempted: list[str] = []
    primary = KeyboardInterrupt("judge primary")

    class HostileWorkspaceCleanup(OSError):
        def __str__(self) -> str:
            raise SystemExit("hostile workspace cleanup string")

    def interrupted_judge(*_args: object, **_kwargs: object) -> None:
        raise primary

    def hostile_remove(path: str) -> None:
        attempted.append(str(path))
        raise HostileWorkspaceCleanup("hidden")

    _install_runtime(monkeypatch, interrupted_judge)
    monkeypatch.setattr(blackbox_module.shutil, "rmtree", hostile_remove)

    try:
        with pytest.raises(KeyboardInterrupt) as caught:
            run_blackbox(str(repo), candidate, str(pack))
    finally:
        for path in attempted:
            if os.path.lexists(path):
                real_remove_tree(path)

    assert caught.value is primary
    assert len(attempted) == 2
    notes = getattr(primary, "__notes__", ())
    assert notes
    assert all(len(note) <= 2000 for note in notes)
    assert any(
        "hostile workspace cleanup" in note
        or "unprintable cleanup exception" in note
        for note in notes
    )


def test_recorder_close_method_is_bound_before_candidate_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)

    class MutableRecorder(_Recorder):
        closed = False

        def close(self) -> None:
            self.closed = True

    recorder = MutableRecorder()

    def completed_then_rebind(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        completed = _completed_judge(command, **kwargs)

        def late_close() -> None:
            raise RuntimeError("late recorder close provider used")

        recorder.close = late_close  # type: ignore[method-assign]
        return completed

    _install_runtime(monkeypatch, completed_then_rebind)
    monkeypatch.setattr(
        blackbox_module._InvocationRecorder,
        "create",
        lambda _workdir: recorder,
    )

    result = run_blackbox(str(repo), candidate, str(pack))

    assert result.passed is True
    assert recorder.closed is True


def test_hostile_container_cleanup_stringification_returns_bounded_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)

    class HostileContainerCleanup(
        blackbox_module.CandidateContainerCleanupError
    ):
        def __str__(self) -> str:
            raise SystemExit("hostile container cleanup string")

    _install_runtime(monkeypatch, _completed_judge)
    monkeypatch.setattr(
        blackbox_module,
        "_cleanup_candidate_containers",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            HostileContainerCleanup("hidden")
        ),
    )

    result = run_blackbox(str(repo), candidate, str(pack))

    assert result.error == "candidate container cleanup failed"
    assert "unprintable candidate container cleanup failure" in result.diagnostics
    assert "SystemExit" in result.diagnostics
    assert len(result.diagnostics) <= 2000


def test_hostile_workspace_cleanup_stringification_returns_bounded_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    real_remove_tree = shutil.rmtree
    retained: list[str] = []

    class HostileWorkspaceCleanup(OSError):
        def __str__(self) -> str:
            raise SystemExit("hostile workspace cleanup string")

    def hostile_remove(path: str) -> None:
        if _workspace_label(path) == "candidate":
            retained.append(str(path))
            raise HostileWorkspaceCleanup("hidden")
        real_remove_tree(path)

    _install_runtime(monkeypatch, _completed_judge)
    monkeypatch.setattr(blackbox_module.shutil, "rmtree", hostile_remove)

    try:
        result = run_blackbox(str(repo), candidate, str(pack))
    finally:
        for path in retained:
            if os.path.lexists(path):
                real_remove_tree(path)

    assert result.error == "black-box workspace cleanup failed"
    assert "HostileWorkspaceCleanup" in result.diagnostics
    assert "unprintable cleanup exception" in result.diagnostics
    assert "SystemExit" in result.diagnostics
    assert len(result.diagnostics) <= 2000


def test_workspace_note_callback_failure_cannot_replace_cleanup_primary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    real_remove_tree = shutil.rmtree
    retained: list[str] = []

    def failing_remove(path: str) -> None:
        if _workspace_label(path) == "candidate":
            retained.append(str(path))
            raise OSError("candidate workspace retained")
        real_remove_tree(path)

    def hostile_note_callback(*_args: object, **_kwargs: object) -> None:
        raise SystemExit("workspace note callback failed")

    _install_runtime(monkeypatch, _completed_judge)
    monkeypatch.setattr(blackbox_module.shutil, "rmtree", failing_remove)
    monkeypatch.setattr(
        blackbox_module._repository_workspace,
        "note_cleanup_failure",
        hostile_note_callback,
    )

    try:
        result = run_blackbox(str(repo), candidate, str(pack))
    finally:
        for path in retained:
            if os.path.lexists(path):
                real_remove_tree(path)

    assert result.error == "black-box workspace cleanup failed"
    assert "candidate workspace retained" in result.diagnostics
    assert "workspace note callback failed" in result.diagnostics
    assert len(result.diagnostics) <= 2000


def test_workspace_owner_projects_each_cleanup_note_exactly_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    real_remove_tree = shutil.rmtree
    real_note_cleanup_failure = (
        blackbox_module._repository_workspace.note_cleanup_failure
    )
    retained: list[str] = []
    reported: list[str] = []

    def failing_remove(path: str) -> None:
        if _workspace_label(path) == "candidate":
            retained.append(str(path))
            raise OSError("candidate workspace retained")
        real_remove_tree(path)

    def observed_note(primary: BaseException, message: str) -> None:
        reported.append(message)
        real_note_cleanup_failure(primary, message)

    _install_runtime(monkeypatch, _completed_judge)
    monkeypatch.setattr(blackbox_module.shutil, "rmtree", failing_remove)
    monkeypatch.setattr(
        blackbox_module._repository_workspace,
        "note_cleanup_failure",
        observed_note,
    )

    try:
        result = run_blackbox(str(repo), candidate, str(pack))
    finally:
        for path in retained:
            if os.path.lexists(path):
                real_remove_tree(path)

    assert result.error == "black-box workspace cleanup failed"
    assert reported == ["Blackbox candidate workspace cleanup failed"]


def test_two_hostile_workspace_failures_preserve_the_first_and_both_attempts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    real_remove_tree = shutil.rmtree
    attempted: list[str] = []

    class HostileWorkspaceCleanup(OSError):
        def __str__(self) -> str:
            raise SystemExit("hostile workspace cleanup string")

    def hostile_remove(path: str) -> None:
        attempted.append(str(path))
        raise HostileWorkspaceCleanup(_workspace_label(path))

    _install_runtime(monkeypatch, _completed_judge)
    monkeypatch.setattr(blackbox_module.shutil, "rmtree", hostile_remove)

    try:
        result = run_blackbox(str(repo), candidate, str(pack))
    finally:
        for path in attempted:
            if os.path.lexists(path):
                real_remove_tree(path)

    assert [_workspace_label(path) for path in attempted] == ["candidate", "pack"]
    assert result.error == "black-box workspace cleanup failed"
    assert "candidate workspace cleanup failed" in result.diagnostics
    assert "verifier-pack snapshot workspace cleanup failed" in result.diagnostics
    assert "unprintable cleanup exception" in result.diagnostics
    assert len(result.diagnostics) <= 2000


def test_cleanup_text_normalizes_hostile_str_subclass_before_bounding() -> None:
    class HostileRenderedText(str):
        def __len__(self) -> int:
            raise SystemExit("hostile rendered length")

        def __getitem__(self, _key: object) -> str:
            raise SystemExit("hostile rendered slice")

    class HostileCleanup(OSError):
        def __str__(self) -> str:
            return HostileRenderedText("normalized safely")

    rendered = blackbox_module._safe_blackbox_cleanup_text(
        HostileCleanup("hidden"),
        unavailable="unprintable cleanup exception",
    )

    assert type(rendered) is str
    assert rendered == "normalized safely"


def test_hostile_and_excess_cleanup_notes_are_projected_safely() -> None:
    class HostileNote:
        def __str__(self) -> str:
            raise SystemExit("hostile note string")

    raw = BlackboxResult(False, 0, 0, "prior", False, "cleanup failed")
    failure = blackbox_module._BlackboxCleanupFailure(raw)
    failure.__notes__ = [HostileNote(), *("x" * 10_000 for _ in range(32))]

    projected = blackbox_module._cleanup_failure_result_with_notes(failure)

    assert "unprintable cleanup note" in projected.diagnostics
    assert "additional cleanup notes omitted" in projected.diagnostics
    assert len(projected.diagnostics) <= 2000


def test_cleanup_note_callback_fallback_supports_python310_notes_storage() -> None:
    class LegacyPrimary(RuntimeError):
        def __getattribute__(self, name: str) -> object:
            if name == "add_note":
                return None
            return super().__getattribute__(name)

    primary = LegacyPrimary("primary")

    def hostile_note_callback(*_args: object, **_kwargs: object) -> None:
        raise SystemExit("legacy note callback failed")

    blackbox_module._attach_blackbox_cleanup_note(
        primary,
        "workspace retained",
        note_failure=hostile_note_callback,
    )

    notes = getattr(primary, "__notes__", ())
    assert len(notes) == 1
    assert "workspace retained" in notes[0]
    assert "legacy note callback failed" in notes[0]
    assert len(notes[0]) <= 2000


@pytest.mark.parametrize(
    "cleanup_stage",
    ["container", "workspace"],
)
def test_cleanup_results_reuse_evidence_without_a_second_live_drain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cleanup_stage: str,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    real_remove_tree = shutil.rmtree
    retained: list[str] = []

    class SecondDrainFails(_Recorder):
        def __init__(self) -> None:
            self.drain_calls = 0

        def drain(self) -> int:
            self.drain_calls += 1
            if self.drain_calls > 1:
                raise RuntimeError("cleanup evidence drain repeated")
            return 0

    recorder = SecondDrainFails()

    def workspace_remove(path: str) -> None:
        if cleanup_stage == "workspace" and _workspace_label(path) == "candidate":
            retained.append(str(path))
            raise OSError("candidate workspace retained")
        real_remove_tree(path)

    _install_runtime(monkeypatch, _completed_judge)
    monkeypatch.setattr(
        blackbox_module._InvocationRecorder,
        "create",
        lambda _workdir: recorder,
    )
    if cleanup_stage == "container":
        monkeypatch.setattr(
            blackbox_module,
            "_cleanup_candidate_containers",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                blackbox_module.CandidateContainerCleanupError(
                    "candidate container retained"
                )
            ),
        )
    monkeypatch.setattr(blackbox_module.shutil, "rmtree", workspace_remove)

    try:
        result = run_blackbox(str(repo), candidate, str(pack))
    finally:
        for path in retained:
            if os.path.lexists(path):
                real_remove_tree(path)

    assert recorder.drain_calls == 1
    if cleanup_stage == "container":
        assert result.error == "candidate container cleanup failed"
    else:
        assert result.error == "black-box workspace cleanup failed"


def test_workspace_cleanup_error_maps_to_runtime_cleanup_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, pack, candidate = _repo_pack_candidate(tmp_path)
    raw = BlackboxResult(
        False,
        0,
        0,
        "black-box workspace absence could not be proven",
        False,
        "black-box workspace cleanup failed",
        started=True,
        completed=False,
        execution_state="started_incomplete",
        execution_phase="blackbox_pack",
        pack_present=True,
    )
    monkeypatch.setattr(blackbox_module, "run_blackbox", lambda *_a, **_k: raw)

    public = guard(
        str(repo),
        candidate,
        verifier_pack=str(pack),
        blackbox=True,
        blackbox_only=True,
    )

    assert public.verdict == ERROR
    assert public.reason_code == REASON_RUNTIME_CLEANUP_FAILED
    assert public.execution_state == "started_incomplete"
