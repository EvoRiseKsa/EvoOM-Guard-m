"""Direct contracts for the extracted black-box pack phase owner."""

from __future__ import annotations

import subprocess
from dataclasses import FrozenInstanceError

import pytest

from evoom_guard.domain.verification import JUnitCounts
from evoom_guard.pack_manifest import PackManifestError
from evoom_guard.verifiers.blackbox_pack import (
    BlackboxPackCompleted,
    BlackboxPackExecutionOutcome,
    BlackboxPackExecutionRequest,
    BlackboxPackExecutionServices,
    BlackboxPackInterpretationRequest,
    BlackboxPackInterpretationServices,
    BlackboxPackLifecycle,
    BlackboxPackVerdictFacts,
    execute_blackbox_pack,
    interpret_blackbox_pack,
)


def test_pack_outcome_requires_exactly_one_branch() -> None:
    terminal = BlackboxPackVerdictFacts(
        passed=False,
        tests_passed=0,
        tests_total=0,
        diagnostics="frozen",
        ran=False,
        error="frozen",
    )
    completed = BlackboxPackCompleted(
        process=subprocess.CompletedProcess(["judge"], 0, "", ""),
        xml_path="/judge/result.xml",
        started_at=1.0,
    )

    with pytest.raises(ValueError, match="exactly one"):
        BlackboxPackExecutionOutcome()
    with pytest.raises(ValueError, match="exactly one"):
        BlackboxPackExecutionOutcome(terminal=terminal, completed=completed)

    assert BlackboxPackExecutionOutcome(terminal=terminal).terminal is terminal
    assert BlackboxPackExecutionOutcome(completed=completed).completed is completed


def test_execute_preserves_identity_lookup_timing_and_lifecycle() -> None:
    identity = ("a" * 64, {"id": "pack", "version": "1"})
    environment = {"SAFE": "1"}
    lifecycle = BlackboxPackLifecycle()
    events: list[str] = []
    command = ["judge"]
    runner_seen: dict[str, object] = {}

    def verify(path: str, observed: object) -> None:
        events.append("verify")
        assert path == "/accepted/pack"
        assert observed is identity

    def run(
        observed_command: list[str],
        *,
        cwd: str,
        env: dict[str, str],
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        events.append("run")
        runner_seen.update(
            command=observed_command,
            cwd=cwd,
            env=env,
            timeout=timeout,
        )
        return subprocess.CompletedProcess(observed_command, 0, "out", "err")

    def command_builder(_pack: str, _xml: str) -> list[str]:
        events.append("command")
        return command

    outcome = execute_blackbox_pack(
        BlackboxPackExecutionRequest(
            pack_snapshot="/accepted/pack",
            pack_identity=identity,
            xml_path="/judge/result.xml",
            environment=environment,
            timeout=7,
        ),
        lifecycle=lifecycle,
        services=BlackboxPackExecutionServices(
            verify_snapshot=lambda: verify,
            build_command=lambda: command_builder,
            # Provider resolution is intentionally observed before command
            # construction, matching the historical nested-call evaluation.
            run_judge=lambda: events.append("resolve-runner") or run,
            perf_counter=lambda: events.append("clock") or 10.0,
        ),
    )

    assert events == [
        "clock",
        "verify",
        "resolve-runner",
        "command",
        "run",
        "verify",
    ]
    assert lifecycle.started is True
    assert lifecycle.active is False
    assert outcome.terminal is None
    assert outcome.completed is not None
    assert outcome.completed.process.args is command
    assert runner_seen == {
        "command": command,
        "cwd": "/accepted/pack",
        "env": environment,
        "timeout": 7,
    }
    assert runner_seen["env"] is environment


def test_pack_error_from_command_preserves_historical_cleanup_state() -> None:
    lifecycle = BlackboxPackLifecycle()

    def fail_command(_pack: str, _xml: str) -> list[str]:
        raise PackManifestError("command-side pack error")

    outcome = execute_blackbox_pack(
        BlackboxPackExecutionRequest(
            pack_snapshot="/accepted/pack",
            pack_identity=("a" * 64, None),
            xml_path="/judge/result.xml",
            environment={},
            timeout=7,
        ),
        lifecycle=lifecycle,
        services=BlackboxPackExecutionServices(
            verify_snapshot=lambda: lambda _path, _identity: None,
            build_command=lambda: fail_command,
            run_judge=lambda: lambda _command, **_kwargs: pytest.fail("runner must not be called"),
            perf_counter=lambda: 1.0,
        ),
    )

    assert lifecycle.started is True
    assert lifecycle.active is True
    assert outcome.completed is None
    assert outcome.terminal == BlackboxPackVerdictFacts(
        passed=False,
        tests_passed=0,
        tests_total=0,
        diagnostics="command-side pack error",
        ran=False,
        error="verifier pack snapshot changed",
    )


def test_interpretation_binds_raw_report_hash_and_effect_order() -> None:
    report = "<raw-junit/>"
    process = subprocess.CompletedProcess(
        ["judge"],
        1,
        stdout="stdout",
        stderr="stderr",
    )
    completed = BlackboxPackCompleted(
        process=process,
        xml_path="/judge/result.xml",
        started_at=10.0,
    )
    events: list[str] = []

    def read(path: str) -> str:
        events.append("read")
        assert path == completed.xml_path
        return report

    def parse(text: str) -> JUnitCounts:
        events.append("parse")
        assert text is report
        return JUnitCounts(passed=1, total=2, failures=1, errors=0)

    def digest(text: str) -> str:
        events.append("digest")
        assert text is report
        return "b" * 64

    def distill(output: str) -> str:
        events.append("distill")
        assert output == "stdout\nstderr"
        return "bounded"

    facts = interpret_blackbox_pack(
        BlackboxPackInterpretationRequest(completed=completed),
        services=BlackboxPackInterpretationServices(
            read_report=lambda: read,
            parse_report=lambda: parse,
            digest_text=digest,
            distill_diagnostics=lambda: distill,
            perf_counter=lambda: events.append("clock") or 10.5,
        ),
    )

    assert events == ["read", "parse", "digest", "clock", "distill"]
    assert facts == BlackboxPackVerdictFacts(
        passed=False,
        tests_passed=1,
        tests_total=2,
        diagnostics="bounded",
        ran=True,
        error=None,
        junit_sha256="b" * 64,
        started=True,
        completed=True,
        execution_state="completed",
        execution_phase="blackbox_pack",
        attach_candidate_evidence=True,
    )


def test_phase_requests_are_immutable_but_cleanup_lifecycle_is_mutable() -> None:
    request = BlackboxPackExecutionRequest(
        pack_snapshot="/accepted/pack",
        pack_identity=("a" * 64, None),
        xml_path="/judge/result.xml",
        environment={},
        timeout=7,
    )
    with pytest.raises(FrozenInstanceError):
        request.timeout = 8  # type: ignore[misc]

    lifecycle = BlackboxPackLifecycle()
    lifecycle.active = True
    lifecycle.started = True
    assert (lifecycle.active, lifecycle.started) == (True, True)
