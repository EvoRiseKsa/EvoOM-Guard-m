"""Contracts for the mutation gate's independent watchdog and classification."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace
from typing import Any

import pytest

from tools.ci import run_security_mutation_gate as mutation_gate


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
