# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Adversarial contracts for judge-owned abort-cleanup evidence."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

import evoom_guard.execution.judge as judge_module

_GROUP_FALSE_NOTE = (
    "Judge process-group abort cleanup was not proven while preserving the primary exception"
)
_READER_FALSE_NOTE = (
    "Judge output-reader abort cleanup was not proven while preserving the primary exception"
)


class _ReaderStartFailure(RuntimeError):
    """Distinct primary failure used to prove exact exception identity."""


class _Pipe:
    def close(self) -> None:
        return None


class _Process:
    pid = 8192

    def __init__(self) -> None:
        self.stdout = _Pipe()
        self.stderr = _Pipe()
        self.returncode = 0

    def poll(self) -> int:
        return self.returncode


class _Reader:
    created: list[_Reader] = []
    primary: BaseException | None = None

    def __init__(
        self,
        *,
        target: Callable[..., object],
        args: tuple[object, ...],
        daemon: bool,
    ) -> None:
        self.target = target
        self.args = args
        self.daemon = daemon
        type(self).created.append(self)

    def start(self) -> None:
        assert type(self).primary is not None
        raise type(self).primary


def _exercise_abort_cleanup(
    *,
    primary: BaseException,
    process_group_terminator: Callable[[Any], object],
    pipe_join: Callable[[list[Any], list[Any]], object],
) -> None:
    process = _Process()
    request = judge_module.JudgeProcessRequest(
        command=["judge"],
        cwd="/judge",
        env={},
        timeout_seconds=1,
    )
    _Reader.created.clear()
    _Reader.primary = primary

    with pytest.raises(type(primary)) as caught:
        judge_module.execute_judge_process(
            request,
            popen_factory=lambda *_args, **_kwargs: process,
            thread_factory=_Reader,
            output_factory=lambda _limit: object(),
            pipe_drain=lambda *_args: None,
            pipe_join=pipe_join,  # type: ignore[arg-type]
            process_group_terminator=process_group_terminator,  # type: ignore[arg-type]
        )

    assert caught.value is primary


def test_abort_cleanup_characterization_preserves_primary_and_attempt_order() -> None:
    """Both independent cleanup stages run while the exact primary survives."""

    primary = _ReaderStartFailure("reader bootstrap failed")
    events: list[str] = []

    def terminate(_process: object) -> None:
        events.append("process-group")
        raise SystemExit("terminator failed")

    def join(_readers: list[object], _streams: list[object]) -> bool:
        events.append("pipe-readers")
        raise GeneratorExit("pipe join failed")

    _exercise_abort_cleanup(
        primary=primary,
        process_group_terminator=terminate,
        pipe_join=join,
    )

    assert events == ["process-group", "pipe-readers"]
    traceback_frames: list[str] = []
    traceback = primary.__traceback__
    while traceback is not None:
        traceback_frames.append(traceback.tb_frame.f_code.co_name)
        traceback = traceback.tb_next
    assert traceback_frames.count("execute_judge_process") == 1


def _exercise_cleanup_effects(
    *,
    primary: BaseException,
    terminator_effect: object,
    reader_effect: object,
) -> list[str]:
    events: list[str] = []

    def apply(effect: object) -> object:
        if isinstance(effect, BaseException):
            raise effect
        return effect

    def terminate(_process: object) -> object:
        events.append("process-group")
        return apply(terminator_effect)

    def join(_readers: list[object], _streams: list[object]) -> object:
        events.append("pipe-readers")
        return apply(reader_effect)

    _exercise_abort_cleanup(
        primary=primary,
        process_group_terminator=terminate,
        pipe_join=join,
    )

    assert events == ["process-group", "pipe-readers"]
    return list(getattr(primary, "__notes__", []))


@pytest.mark.parametrize(
    ("terminator_effect", "reader_effect", "expected_notes"),
    [
        pytest.param(False, True, [_GROUP_FALSE_NOTE], id="terminator-false"),
        pytest.param(None, False, [_READER_FALSE_NOTE], id="reader-false"),
        pytest.param(
            None,
            GeneratorExit("reader cleanup raised"),
            [
                "Judge output-reader abort cleanup raised while preserving the "
                "primary exception: GeneratorExit: reader cleanup raised"
            ],
            id="reader-raised",
        ),
        pytest.param(
            True,
            True,
            [_GROUP_FALSE_NOTE],
            id="terminator-non-contract-return",
        ),
        pytest.param(
            None,
            1,
            [_READER_FALSE_NOTE],
            id="reader-truthy-non-bool",
        ),
        pytest.param(None, True, [], id="both-proven"),
    ],
)
def test_abort_cleanup_requires_owner_specific_positive_proof(
    terminator_effect: object,
    reader_effect: object,
    expected_notes: list[str],
) -> None:
    """Only exact contract success may suppress an abort-cleanup diagnostic."""

    primary = KeyboardInterrupt("operator cancellation")

    notes = _exercise_cleanup_effects(
        primary=primary,
        terminator_effect=terminator_effect,
        reader_effect=reader_effect,
    )

    assert notes == expected_notes


def test_abort_cleanup_preserves_ordered_raised_and_false_diagnostics() -> None:
    primary = KeyboardInterrupt("operator cancellation")

    notes = _exercise_cleanup_effects(
        primary=primary,
        terminator_effect=SystemExit("terminate raised"),
        reader_effect=False,
    )

    assert notes == [
        "Judge process-group abort cleanup raised while preserving the primary "
        "exception: SystemExit: terminate raised",
        _READER_FALSE_NOTE,
    ]


@pytest.mark.parametrize("primary_kind", ["python-310", "hostile-add-note"])
def test_abort_cleanup_tolerates_hostile_rendering_and_note_api(
    primary_kind: str,
) -> None:
    class UnprintableCleanupFailure(SystemExit):
        def __str__(self) -> str:
            raise RuntimeError("hostile cleanup __str__")

    class Python310Primary(KeyboardInterrupt):
        add_note = None

    class HostileAddNotePrimary(KeyboardInterrupt):
        def add_note(self, _note: str) -> None:
            raise GeneratorExit("hostile add_note")

    primary: BaseException
    if primary_kind == "python-310":
        primary = Python310Primary("operator cancellation")
    else:
        primary = HostileAddNotePrimary("operator cancellation")

    notes = _exercise_cleanup_effects(
        primary=primary,
        terminator_effect=UnprintableCleanupFailure(),
        reader_effect=False,
    )

    assert notes == [
        "Judge process-group abort cleanup raised while preserving the primary "
        "exception: UnprintableCleanupFailure: <unprintable; __str__ raised "
        "RuntimeError>",
        _READER_FALSE_NOTE,
    ]


def test_abort_cleanup_diagnostics_are_individually_bounded() -> None:
    primary = KeyboardInterrupt("operator cancellation")

    notes = _exercise_cleanup_effects(
        primary=primary,
        terminator_effect=OSError("X" * 200_000),
        reader_effect=False,
    )

    assert len(notes) == 2
    assert len(notes[0]) == 2_000
    assert notes[0].endswith("...")
    assert notes[1] == _READER_FALSE_NOTE
