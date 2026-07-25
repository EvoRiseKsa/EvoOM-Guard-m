"""Pre-extraction characterization of black-box candidate runtime seams.

This harness calls only the existing compatibility functions in
``evoom_guard.blackbox``.  It freezes provider lookup timing, mutation
visibility, and ``BaseException`` identity before any R2 owner is introduced.
"""

from __future__ import annotations

import copy
import json
import subprocess
from collections.abc import Callable, Iterable, Iterator
from contextlib import ExitStack
from typing import Any, cast
from unittest.mock import patch

import evoom_guard.blackbox as blackbox_module
from evoom_guard.blackbox import (
    BlackboxResult,
    CandidateContainerCleanupError,
)
from evoom_guard.isolation import (
    DockerCandidateCleanupResult,
    DockerCidScanResult,
)

SCHEMA_VERSION = "blackbox-candidate-runtime-characterization-v1"
CASE_NAMES = (
    "cleanup_control_interrupt_identity",
    "cleanup_kernel_interrupt_identity",
    "cleanup_live_binding_schedule",
    "cleanup_non_strict_scan_failure",
    "cleanup_scan_interrupt_identity",
    "cleanup_sleep_interrupt_identity",
    "cleanup_strict_scan_failure",
    "evidence_drain_interrupt_identity",
    "evidence_live_retry_rebinding",
    "evidence_observation_interrupt_identity",
    "evidence_scan_interrupt_identity",
    "evidence_sleep_interrupt_identity",
)

_CID_A = "a" * 64
_CID_B = "b" * 64


def canonical_json(value: Any) -> str:
    """Return the stable, reviewable vector encoding."""

    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _result() -> BlackboxResult:
    return BlackboxResult(
        passed=True,
        tests_passed=2,
        tests_total=2,
        diagnostics="controlled",
        ran=True,
        error=None,
        isolation={
            "requested": "docker",
            "delivered": "docker",
            "note": "prepared boundary",
        },
        started=True,
        completed=True,
        execution_state="completed",
        execution_phase="blackbox_pack",
        pack_present=True,
    )


def _serialize_result(result: BlackboxResult) -> dict[str, object]:
    return {
        field: copy.deepcopy(getattr(result, field))
        for field in result._fields
    }


def _exception_projection(
    exc: BaseException,
    *,
    sentinel: BaseException | None,
) -> dict[str, object]:
    return {
        "type": type(exc).__name__,
        "message": str(exc),
        "same_object": exc is sentinel if sentinel is not None else None,
        "cause_type": (
            type(exc.__cause__).__name__
            if exc.__cause__ is not None
            else None
        ),
        "context_type": (
            type(exc.__context__).__name__
            if exc.__context__ is not None
            else None
        ),
    }


def _capture(
    operation: Callable[[], object],
    *,
    events: list[dict[str, object]],
    sentinel: BaseException | None = None,
    observed: set[str] | None = None,
) -> dict[str, object]:
    try:
        returned = operation()
    except BaseException as exc:
        return {
            "events": events,
            "returned": None,
            "exception": _exception_projection(exc, sentinel=sentinel),
            "observed_container_ids": (
                sorted(set(observed)) if observed is not None else None
            ),
        }
    if isinstance(returned, BlackboxResult):
        projected: object = _serialize_result(returned)
    else:
        projected = returned
    return {
        "events": events,
        "returned": projected,
        "exception": None,
        "observed_container_ids": (
            sorted(set(observed)) if observed is not None else None
        ),
    }


class _TrackingObservedSet(set[str]):
    def __init__(
        self,
        events: list[dict[str, object]],
        values: Iterable[str] = (),
    ) -> None:
        super().__init__(values)
        self._events = events

    def update(self, *others: Iterable[str]) -> None:
        incoming = [
            item
            for other in others
            for item in other
        ]
        self._events.append(
            {
                "op": "observed-update",
                "incoming": incoming,
                "before": sorted(set(self)),
            }
        )
        super().update(incoming)
        self._events.append(
            {
                "op": "observed-updated",
                "after": sorted(set(self)),
            }
        )

    def __iter__(self) -> Iterator[str]:
        self._events.append(
            {
                "op": "observed-iterate",
                "values": sorted(set.copy(self)),
            }
        )
        return set.__iter__(self)


class _InterruptingObservedSet(set[str]):
    def __init__(
        self,
        events: list[dict[str, object]],
        sentinel: BaseException,
    ) -> None:
        super().__init__()
        self._events = events
        self._sentinel = sentinel

    def update(self, *others: Iterable[str]) -> None:
        incoming = [
            item
            for other in others
            for item in other
        ]
        super().update(incoming)
        self._events.append(
            {
                "op": "observed-update-then-interrupt",
                "after": sorted(set(self)),
            }
        )
        raise self._sentinel


def _evidence_live_retry_rebinding() -> dict[str, object]:
    events: list[dict[str, object]] = []
    observed = _TrackingObservedSet(events)

    class Recorder:
        def drain(self) -> int:
            events.append({"op": "drain-initial"})
            self.drain = self.late_drain  # type: ignore[method-assign]
            blackbox_module._candidate_container_ids = scan_after_drain
            return 0

        def late_drain(self) -> int:
            events.append({"op": "drain-late"})
            return 2

    def unexpected_scan(
        _path: str,
        *,
        strict: bool = False,
    ) -> list[str]:
        del strict
        raise AssertionError("scan provider was snapshotted before drain")

    def scan_after_drain(
        path: str,
        *,
        strict: bool = False,
    ) -> list[str]:
        events.append(
            {"op": "scan-after-drain", "path": path, "strict": strict}
        )
        blackbox_module.time.sleep = sleep_late
        return []

    def unexpected_sleep(_seconds: float) -> None:
        raise AssertionError("sleep provider was snapshotted before scan")

    def sleep_late(seconds: float) -> None:
        events.append({"op": "sleep-late", "seconds": seconds})
        blackbox_module._candidate_container_ids = scan_late

    def scan_late(
        path: str,
        *,
        strict: bool = False,
    ) -> list[str]:
        events.append(
            {"op": "scan-late", "path": path, "strict": strict}
        )
        return [_CID_B, _CID_A]

    with (
        patch.object(
            blackbox_module,
            "_candidate_container_ids",
            unexpected_scan,
        ),
        patch.object(blackbox_module.time, "sleep", unexpected_sleep),
    ):
        return _capture(
            lambda: blackbox_module._attach_candidate_execution_evidence(
                _result(),
                recorder=Recorder(),  # type: ignore[arg-type]
                cidfile_dir="/judge/cids",
                wait_for_late_container_evidence=True,
                observed_container_ids=observed,
            ),
            events=events,
            observed=observed,
        )


def _evidence_provider_interrupt(
    provider: str,
) -> dict[str, object]:
    events: list[dict[str, object]] = []
    observed: set[str] = set()
    sentinel = KeyboardInterrupt(f"{provider} interrupted")

    class Recorder:
        def drain(self) -> int:
            events.append({"op": "drain"})
            if provider == "drain":
                raise sentinel
            return 0 if provider == "sleep" else 1

    def scan(
        path: str,
        *,
        strict: bool = False,
    ) -> list[str]:
        events.append({"op": "scan", "path": path, "strict": strict})
        if provider == "scan":
            raise sentinel
        return []

    def sleep(seconds: float) -> None:
        events.append({"op": "sleep", "seconds": seconds})
        raise sentinel

    with (
        patch.object(blackbox_module, "_candidate_container_ids", scan),
        patch.object(blackbox_module.time, "sleep", sleep),
    ):
        return _capture(
            lambda: blackbox_module._attach_candidate_execution_evidence(
                _result(),
                recorder=Recorder(),  # type: ignore[arg-type]
                cidfile_dir="/judge/cids",
                wait_for_late_container_evidence=(provider == "sleep"),
                observed_container_ids=observed,
            ),
            events=events,
            sentinel=sentinel,
            observed=observed,
        )


def _evidence_observation_interrupt() -> dict[str, object]:
    events: list[dict[str, object]] = []
    sentinel = KeyboardInterrupt("observation interrupted")
    observed = _InterruptingObservedSet(events, sentinel)

    class Recorder:
        def drain(self) -> int:
            events.append({"op": "drain"})
            return 1

    def scan(
        path: str,
        *,
        strict: bool = False,
    ) -> list[str]:
        events.append({"op": "scan", "path": path, "strict": strict})
        return [_CID_A]

    with patch.object(
        blackbox_module,
        "_candidate_container_ids",
        scan,
    ):
        return _capture(
            lambda: blackbox_module._attach_candidate_execution_evidence(
                _result(),
                recorder=Recorder(),  # type: ignore[arg-type]
                cidfile_dir="/judge/cids",
                observed_container_ids=observed,
            ),
            events=events,
            sentinel=sentinel,
            observed=observed,
        )


def _cleanup_live_binding_schedule() -> dict[str, object]:
    events: list[dict[str, object]] = []

    def kernel_late(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("kernel lookup moved after request construction")

    def control_late(
        command: list[str],
        *,
        timeout: float,
    ) -> subprocess.CompletedProcess[str]:
        events.append(
            {
                "op": "control-late",
                "command": command,
                "timeout": timeout,
            }
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    def sleep_late(seconds: float) -> None:
        events.append({"op": "sleep-late", "seconds": seconds})

    def exists_late(path: str) -> bool:
        events.append({"op": "exists-late", "path": path})
        return True

    class RebindingKnown:
        def __bool__(self) -> bool:
            return True

        def __iter__(self) -> Iterator[str]:
            events.append({"op": "known-iterate"})
            blackbox_module._cleanup_candidate_containers_kernel = (
                kernel_late
            )
            blackbox_module._run_docker_control = control_late
            blackbox_module.time.sleep = sleep_late
            blackbox_module.os.path.lexists = exists_late
            return iter((_CID_B,))

    known = RebindingKnown()

    def scan_initial(
        _path: str,
        *,
        strict: bool = False,
    ) -> list[str]:
        del strict
        raise AssertionError("scanner lookup was snapshotted by facade")

    def scan_late(
        path: str,
        *,
        strict: bool = False,
    ) -> list[str]:
        events.append(
            {"op": "scan-late", "path": path, "strict": strict}
        )
        return [_CID_A]

    def control_initial(
        _command: list[str],
        *,
        timeout: float,
    ) -> subprocess.CompletedProcess[str]:
        del timeout
        raise AssertionError("control provider resolved before request")

    def sleep_initial(_seconds: float) -> None:
        raise AssertionError("sleep provider resolved before request")

    def exists_initial(_path: str) -> bool:
        raise AssertionError("path provider resolved before request")

    def kernel_initial(
        request: object,
        *,
        scanner: Callable[[str], DockerCidScanResult],
        control_runner: Callable[..., object],
        sleeper: Callable[[float], None],
        path_exists: Callable[[str], bool],
    ) -> DockerCandidateCleanupResult:
        cleanup_request = cast(Any, request)
        events.append(
            {
                "op": "kernel-initial",
                "known_container_ids": sorted(
                    cleanup_request.known_container_ids
                ),
                "wait_for_late_cidfiles": (
                    cleanup_request.wait_for_late_cidfiles
                ),
            }
        )
        blackbox_module._candidate_container_ids = scan_late
        scanned = scanner(cleanup_request.cidfile_dir)
        control_runner(["docker", "ps"], timeout=30)
        sleeper(0.05)
        path_exists(cleanup_request.cidfile_dir)
        return DockerCandidateCleanupResult(
            scanned.container_ids,
            scanned.failures,
        )

    with ExitStack() as stack:
        stack.enter_context(
            patch.object(
                blackbox_module,
                "_cleanup_candidate_containers_kernel",
                kernel_initial,
            )
        )
        stack.enter_context(
            patch.object(
                blackbox_module,
                "_candidate_container_ids",
                scan_initial,
            )
        )
        stack.enter_context(
            patch.object(
                blackbox_module,
                "_run_docker_control",
                control_initial,
            )
        )
        stack.enter_context(
            patch.object(blackbox_module.time, "sleep", sleep_initial)
        )
        stack.enter_context(
            patch.object(
                blackbox_module.os.path,
                "lexists",
                exists_initial,
            )
        )
        return _capture(
            lambda: blackbox_module._cleanup_candidate_containers(
                "/judge/cids",
                wait_for_late_cidfiles=True,
                strict=True,
                known_container_ids=known,
            ),
            events=events,
        )


def _cleanup_provider_interrupt(provider: str) -> dict[str, object]:
    events: list[dict[str, object]] = []
    sentinel = KeyboardInterrupt(f"{provider} interrupted")

    def scan(
        path: str,
        *,
        strict: bool = False,
    ) -> list[str]:
        events.append({"op": "scan", "path": path, "strict": strict})
        if provider == "scan":
            raise sentinel
        return [_CID_A]

    def control(
        command: list[str],
        *,
        timeout: float,
    ) -> subprocess.CompletedProcess[str]:
        events.append(
            {"op": "control", "command": command, "timeout": timeout}
        )
        raise sentinel

    def sleep(seconds: float) -> None:
        events.append({"op": "sleep", "seconds": seconds})
        raise sentinel

    def kernel(
        request: object,
        *,
        scanner: Callable[[str], DockerCidScanResult],
        control_runner: Callable[..., object],
        sleeper: Callable[[float], None],
        path_exists: Callable[[str], bool],
    ) -> DockerCandidateCleanupResult:
        del path_exists
        cleanup_request = cast(Any, request)
        events.append({"op": "kernel"})
        if provider == "kernel":
            raise sentinel
        scanned = scanner(cleanup_request.cidfile_dir)
        if provider == "control":
            control_runner(["docker", "ps"], timeout=30)
        if provider == "sleep":
            sleeper(0.05)
        return DockerCandidateCleanupResult(
            scanned.container_ids,
            scanned.failures,
        )

    with (
        patch.object(
            blackbox_module,
            "_cleanup_candidate_containers_kernel",
            kernel,
        ),
        patch.object(blackbox_module, "_candidate_container_ids", scan),
        patch.object(blackbox_module, "_run_docker_control", control),
        patch.object(blackbox_module.time, "sleep", sleep),
    ):
        return _capture(
            lambda: blackbox_module._cleanup_candidate_containers(
                "/judge/cids",
                wait_for_late_cidfiles=True,
                strict=True,
            ),
            events=events,
            sentinel=sentinel,
        )


def _cleanup_scan_failure(*, strict: bool) -> dict[str, object]:
    events: list[dict[str, object]] = []
    scan_error = CandidateContainerCleanupError(
        "controlled scan evidence failure"
    )

    def scan(
        path: str,
        *,
        strict: bool = False,
    ) -> list[str]:
        events.append({"op": "scan", "path": path, "strict": strict})
        raise scan_error

    def kernel(
        request: object,
        *,
        scanner: Callable[[str], DockerCidScanResult],
        control_runner: Callable[..., object],
        sleeper: Callable[[float], None],
        path_exists: Callable[[str], bool],
    ) -> DockerCandidateCleanupResult:
        del control_runner, sleeper, path_exists
        cleanup_request = cast(Any, request)
        events.append({"op": "kernel"})
        scanned = scanner(cleanup_request.cidfile_dir)
        events.append(
            {
                "op": "kernel-scan-result",
                "container_ids": list(scanned.container_ids),
                "failures": list(scanned.failures),
            }
        )
        return DockerCandidateCleanupResult((), scanned.failures)

    with (
        patch.object(
            blackbox_module,
            "_cleanup_candidate_containers_kernel",
            kernel,
        ),
        patch.object(blackbox_module, "_candidate_container_ids", scan),
    ):
        return _capture(
            lambda: blackbox_module._cleanup_candidate_containers(
                "/judge/cids",
                strict=strict,
            ),
            events=events,
            sentinel=scan_error,
        )


def capture_case(case_name: str) -> dict[str, object]:
    """Capture one reviewed pre-extraction behavior."""

    if case_name not in CASE_NAMES:
        raise ValueError(
            f"unknown blackbox candidate runtime case: {case_name}"
        )
    if case_name == "evidence_live_retry_rebinding":
        return _evidence_live_retry_rebinding()
    if case_name == "evidence_drain_interrupt_identity":
        return _evidence_provider_interrupt("drain")
    if case_name == "evidence_scan_interrupt_identity":
        return _evidence_provider_interrupt("scan")
    if case_name == "evidence_sleep_interrupt_identity":
        return _evidence_provider_interrupt("sleep")
    if case_name == "evidence_observation_interrupt_identity":
        return _evidence_observation_interrupt()
    if case_name == "cleanup_live_binding_schedule":
        return _cleanup_live_binding_schedule()
    if case_name == "cleanup_kernel_interrupt_identity":
        return _cleanup_provider_interrupt("kernel")
    if case_name == "cleanup_scan_interrupt_identity":
        return _cleanup_provider_interrupt("scan")
    if case_name == "cleanup_control_interrupt_identity":
        return _cleanup_provider_interrupt("control")
    if case_name == "cleanup_sleep_interrupt_identity":
        return _cleanup_provider_interrupt("sleep")
    if case_name == "cleanup_strict_scan_failure":
        return _cleanup_scan_failure(strict=True)
    if case_name == "cleanup_non_strict_scan_failure":
        return _cleanup_scan_failure(strict=False)
    raise AssertionError(f"unhandled case: {case_name}")


def capture_all() -> dict[str, object]:
    """Capture the complete reviewed matrix."""

    return {
        "schema_version": SCHEMA_VERSION,
        "cases": {
            case_name: capture_case(case_name)
            for case_name in CASE_NAMES
        },
    }


if __name__ == "__main__":
    print(canonical_json(capture_all()), end="")
