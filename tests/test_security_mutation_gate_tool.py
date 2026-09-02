"""Contracts for the mutation gate's independent watchdog and classification."""

from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tools.ci import run_security_mutation_gate as mutation_gate

_FINALIZER_GIT_OWNER = "evoom_guard/finalizer/git_command.py"
_FINALIZER_GIT_FACADE = "evoom_guard/finalizer_derivation.py"
_EXTRACTED_FINALIZER_GIT_MUTATIONS = {
    "finalizer-git-abort-cleanup-bypass",
    "finalizer-git-abort-primary-reraise",
    "finalizer-git-abort-reader-exact-proof-bypass",
    "finalizer-git-abort-reader-false-observability-bypass",
    "finalizer-git-abort-reader-raised-observability-bypass",
    "finalizer-git-abort-second-cleanup-stage-bypass",
    "finalizer-git-abort-tree-exact-proof-bypass",
    "finalizer-git-abort-tree-false-observability-bypass",
    "finalizer-git-abort-tree-raised-observability-bypass",
    "finalizer-git-env-scrub-bypass",
    "finalizer-git-interrupt-cleanup-bypass",
    "finalizer-git-interrupt-exact-proof-bypass",
    "finalizer-git-live-reader-error-cleanup-bypass",
    "finalizer-git-no-replace-bypass",
    "finalizer-git-overflow-state-bypass",
    "finalizer-git-posix-exact-proof-bypass",
    "finalizer-git-posix-post-completion-proof-bypass",
    "finalizer-git-post-poll-silent-cleanup-restore",
    "finalizer-git-process-group-launch-bypass",
    "finalizer-git-reader-baseexception-narrowing",
    "finalizer-git-reader-error-record-bypass",
    "finalizer-git-reader-start-tracking-bypass",
}
_FACADE_FINALIZER_GIT_MUTATIONS = {
    "finalizer-git-live-reader-close-bypass",
    "finalizer-git-reader-join-bound-bypass",
    "finalizer-git-reader-join-cap-bypass",
    "finalizer-git-reader-join-primary-suppression",
    "finalizer-git-tree-cleanup-proof-bypass",
}


def test_every_reviewed_mutation_has_exactly_one_current_source_site() -> None:
    """Refactors must retarget reviewed mutants before the long gate starts."""

    mismatches: list[str] = []
    for mutation in mutation_gate.MUTATIONS:
        source = (mutation_gate.ROOT / mutation.path).read_text(encoding="utf-8")
        count = source.count(mutation.before)
        if count != 1:
            mismatches.append(f"{mutation.name}: {count}")
        if mutation.before == mutation.after:
            mismatches.append(f"{mutation.name}: unchanged")

    assert not mismatches, "\n".join(mismatches)


def test_finalizer_git_mutants_follow_the_extracted_owner_boundary() -> None:
    """Lifecycle mutants must load the owner, not an obsolete facade copy."""

    inventory = {
        mutation.name: mutation.path
        for mutation in mutation_gate.MUTATIONS
        if mutation.name.startswith("finalizer-git-")
    }

    assert set(inventory) == (
        _EXTRACTED_FINALIZER_GIT_MUTATIONS | _FACADE_FINALIZER_GIT_MUTATIONS
    )
    assert {
        name: inventory[name] for name in _EXTRACTED_FINALIZER_GIT_MUTATIONS
    } == {
        name: _FINALIZER_GIT_OWNER for name in _EXTRACTED_FINALIZER_GIT_MUTATIONS
    }
    assert {name: inventory[name] for name in _FACADE_FINALIZER_GIT_MUTATIONS} == {
        name: _FINALIZER_GIT_FACADE for name in _FACADE_FINALIZER_GIT_MUTATIONS
    }


class _FinishedProcess:
    pid = 4242

    def poll(self) -> int:
        return 0

    def kill(self) -> None:  # pragma: no cover - fail-closed branch must not need it
        raise AssertionError("finished root must not be accepted as cleanup proof")

    def communicate(self, timeout: float) -> tuple[str, str]:
        del timeout
        return "", ""


def test_windows_watchdog_rejects_nonzero_taskkill_after_root_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dead root cannot turn a failed /T request into descendant proof."""

    monkeypatch.setattr(mutation_gate, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        mutation_gate.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["taskkill"], 128
        ),
    )

    with pytest.raises(RuntimeError, match="taskkill exited 128"):
        mutation_gate._stop_watchdog_tree(_FinishedProcess())  # type: ignore[arg-type]


def test_mutant_timeout_is_infrastructure_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The watchdog is never allowed to convert a hang into a killed mutant."""

    calls = 0

    def fake_overlay_run(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(["pytest"], 0, "", "")
        raise subprocess.TimeoutExpired(["pytest"], 1)

    monkeypatch.setattr(mutation_gate, "_run_overlay_test", fake_overlay_run)
    monkeypatch.setattr(mutation_gate, "_apply_mutation", lambda *_args: None)

    status, detail = mutation_gate._run_mutant(mutation_gate.MUTATIONS[0], 1)

    assert status == "infrastructure-error"
    assert detail == "mutant exceeded 1s"


def test_parallel_results_match_sequential_inventory_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Completion order cannot reorder or otherwise change gate results."""

    selected = list(mutation_gate.MUTATIONS[:4])
    positions = {mutation.name: index for index, mutation in enumerate(selected)}

    def fake_run(
        mutation: mutation_gate.Mutation, timeout: float
    ) -> tuple[str, str]:
        del timeout
        time.sleep((len(selected) - positions[mutation.name]) * 0.005)
        return "killed", mutation.name

    monkeypatch.setattr(mutation_gate, "_run_mutant", fake_run)

    sequential = mutation_gate._run_selected(selected, 1, 1)
    parallel = mutation_gate._run_selected(selected, 1, 4)

    assert parallel == sequential
    assert [detail for _status, detail in parallel] == [
        mutation.name for mutation in selected
    ]


def test_parallel_worker_exception_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A worker exception is infrastructure failure, never a killed mutant."""

    selected = list(mutation_gate.MUTATIONS[:2])

    def fake_run(
        mutation: mutation_gate.Mutation, timeout: float
    ) -> tuple[str, str]:
        del timeout
        if mutation == selected[0]:
            raise ValueError("worker exploded")
        return "killed", mutation.name

    monkeypatch.setattr(mutation_gate, "_run_mutant", fake_run)

    results = mutation_gate._run_selected(selected, 1, 2)

    assert results == [
        ("infrastructure-error", "ValueError: worker exploded"),
        ("killed", selected[1].name),
    ]


def test_overlay_process_receives_only_its_private_temp_roots(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Each pytest child binds generic and pytest-specific temp state to its overlay."""

    captured: dict[str, Any] = {}

    class _ImmediateProcess:
        def __init__(self, args: list[str]) -> None:
            self.args = args
            self.returncode = 1

        def communicate(self, timeout: float) -> tuple[str, str]:
            del timeout
            return "", ""

    def fake_popen(args: list[str], **kwargs: Any) -> _ImmediateProcess:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _ImmediateProcess(args)

    overlay = tmp_path / "overlay"
    overlay.mkdir()
    monkeypatch.setenv("PYTHONPATH", "must-be-removed")
    monkeypatch.setattr(mutation_gate, "_watchdog_popen_kwargs", lambda: {})
    monkeypatch.setattr(mutation_gate.subprocess, "Popen", fake_popen)

    completed = mutation_gate._run_overlay_test(
        overlay,
        mutation_gate.MUTATIONS[0],
        1,
    )

    assert completed.returncode == 1
    kwargs = captured["kwargs"]
    environment = kwargs["env"]
    process_temp = str((overlay / ".process-tmp").resolve())
    assert environment["TMPDIR"] == process_temp
    assert environment["TEMP"] == process_temp
    assert environment["TMP"] == process_temp
    assert "PYTHONPATH" not in environment
    bootstrap = captured["args"][2]
    assert "no:cacheprovider" in bootstrap
    assert repr(str((overlay / ".pytest-tmp").resolve())) in bootstrap


def test_parallel_mutants_use_distinct_isolated_roots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Concurrent mutants cannot share package, pytest, or process temp roots."""

    selected = list(mutation_gate.MUTATIONS[:4])
    barrier = threading.Barrier(len(selected))
    lock = threading.Lock()
    calls: dict[str, list[Path]] = {mutation.name: [] for mutation in selected}

    def fake_overlay_run(
        overlay: Path,
        mutation: mutation_gate.Mutation,
        timeout: float,
    ) -> subprocess.CompletedProcess[str]:
        del timeout
        with lock:
            calls[mutation.name].append(overlay.resolve())
            call_number = len(calls[mutation.name])
        if call_number == 1:
            barrier.wait(timeout=5)
            return subprocess.CompletedProcess(["pytest"], 0, "", "")
        return subprocess.CompletedProcess(["pytest"], 1, "", "")

    monkeypatch.setattr(mutation_gate, "_run_overlay_test", fake_overlay_run)
    monkeypatch.setattr(mutation_gate, "_apply_mutation", lambda *_args: None)

    results = mutation_gate._run_selected(selected, 1, 4)

    assert results == [("killed", "")] * len(selected)
    overlays = [paths[0] for paths in calls.values()]
    assert len(set(overlays)) == len(selected)
    for paths in calls.values():
        assert len(paths) == 2
        assert paths[0] == paths[1]
    assert len({path / ".process-tmp" for path in overlays}) == len(selected)
    assert len({path / ".pytest-tmp" for path in overlays}) == len(selected)
