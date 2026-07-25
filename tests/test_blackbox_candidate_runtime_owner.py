"""Direct contracts for the extracted black-box candidate runtime owner."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

import evoom_guard.verifiers.blackbox_candidate_runtime as runtime_owner
from evoom_guard.blackbox import CandidateContainerCleanupError
from evoom_guard.verifiers.blackbox_candidate_runtime import (
    CandidateContainerCleanupRequest,
    CandidateContainerCleanupServices,
    CandidateExecutionEvidenceRequest,
    CandidateExecutionEvidenceServices,
    attach_candidate_execution_evidence,
    cleanup_candidate_containers,
)

_CID_A = "a" * 64


@dataclass(frozen=True)
class _KernelRequest:
    cidfile_dir: str
    wait_for_late_cidfiles: bool
    known_container_ids: frozenset[str]


@dataclass(frozen=True)
class _ScanResult:
    container_ids: tuple[str, ...]
    failures: tuple[str, ...] = ()


@dataclass(frozen=True)
class _CleanupResult:
    failures: tuple[str, ...] = ()


def _services(
    *,
    kernel: Any,
    scanner: Any = lambda _path, *, strict=False: [],
    request_factory: Any = _KernelRequest,
    scan_result_factory: Any = _ScanResult,
    cleanup_error_factory: Any = CandidateContainerCleanupError,
) -> CandidateContainerCleanupServices:
    return CandidateContainerCleanupServices(
        cleanup_kernel_provider=lambda: kernel,
        cleanup_request_factory_provider=lambda: request_factory,
        scan_result_factory_provider=lambda: scan_result_factory,
        container_ids_provider=lambda: scanner,
        control_runner_provider=lambda: (
            lambda _command, *, timeout=30.0: None
        ),
        sleeper_provider=lambda: lambda _seconds: None,
        path_exists_provider=lambda: lambda _path: True,
        scan_failure_type_provider=lambda: CandidateContainerCleanupError,
        cleanup_error_factory_provider=lambda: cleanup_error_factory,
    )


def test_cleanup_error_keeps_the_historical_facade_identity() -> None:
    assert CandidateContainerCleanupError.__module__ == "evoom_guard.blackbox"
    assert not hasattr(runtime_owner, "CandidateContainerCleanupError")


def test_cleanup_freezes_known_ids_once_and_preserves_provider_order() -> None:
    events: list[str] = []

    class KnownIds:
        def __bool__(self) -> bool:
            events.append("known-bool")
            return True

        def __iter__(self):
            events.append("known-iterate")
            yield _CID_A

    known_ids = KnownIds()

    def scanner_provider():
        events.append("scanner-provider")

        def scanner(path: str, *, strict: bool = False) -> list[str]:
            events.append(f"scanner-call:{path}:{strict}")
            return []

        return scanner

    def scan_result_provider():
        events.append("scan-result-provider")
        return _ScanResult

    def request_factory_provider():
        events.append("request-factory-provider")

        def request_factory(
            *,
            cidfile_dir: str,
            wait_for_late_cidfiles: bool,
            known_container_ids: frozenset[str],
        ) -> _KernelRequest:
            events.append("request-factory")
            assert type(known_container_ids) is frozenset
            return _KernelRequest(
                cidfile_dir,
                wait_for_late_cidfiles,
                known_container_ids,
            )

        return request_factory

    def kernel(
        request: _KernelRequest,
        *,
        scanner: Any,
        control_runner: Any,
        sleeper: Any,
        path_exists: Any,
    ) -> _CleanupResult:
        del control_runner, sleeper, path_exists
        events.append("kernel-call")
        assert tuple(request.known_container_ids) == (_CID_A,)
        assert tuple(request.known_container_ids) == (_CID_A,)
        scanner(request.cidfile_dir)
        return _CleanupResult()

    services = CandidateContainerCleanupServices(
        cleanup_kernel_provider=lambda: (
            events.append("kernel-provider") or kernel
        ),
        cleanup_request_factory_provider=request_factory_provider,
        scan_result_factory_provider=scan_result_provider,
        container_ids_provider=scanner_provider,
        control_runner_provider=lambda: (
            events.append("control-provider")
            or (lambda _command, *, timeout=30.0: None)
        ),
        sleeper_provider=lambda: (
            events.append("sleep-provider") or (lambda _seconds: None)
        ),
        path_exists_provider=lambda: (
            events.append("path-provider") or (lambda _path: True)
        ),
        scan_failure_type_provider=lambda: CandidateContainerCleanupError,
        cleanup_error_factory_provider=lambda: (
            CandidateContainerCleanupError
        ),
    )

    cleanup_candidate_containers(
        CandidateContainerCleanupRequest(
            "/judge/cids",
            wait_for_late_cidfiles=True,
            known_container_ids=known_ids,
        ),
        services=services,
    )

    assert events == [
        "kernel-provider",
        "request-factory-provider",
        "known-bool",
        "known-iterate",
        "request-factory",
        "control-provider",
        "sleep-provider",
        "path-provider",
        "kernel-call",
        "scan-result-provider",
        "scanner-provider",
        "scanner-call:/judge/cids:False",
    ]


@pytest.mark.parametrize("error_type", [RuntimeError, OSError])
def test_scan_adapter_propagates_unclassified_exceptions_by_identity(
    error_type: type[Exception],
) -> None:
    sentinel = error_type("unclassified scanner failure")

    def scanner(_path: str, *, strict: bool = False) -> list[str]:
        del strict
        raise sentinel

    def kernel(
        request: _KernelRequest,
        *,
        scanner: Any,
        control_runner: Any,
        sleeper: Any,
        path_exists: Any,
    ) -> _CleanupResult:
        del control_runner, sleeper, path_exists
        scanner(request.cidfile_dir)
        raise AssertionError("scanner exception was hidden")

    with pytest.raises(error_type) as caught:
        cleanup_candidate_containers(
            CandidateContainerCleanupRequest("/judge/cids", strict=True),
            services=_services(kernel=kernel, scanner=scanner),
        )

    assert caught.value is sentinel
    assert caught.value.__cause__ is None


def test_kernel_cleanup_error_propagates_by_identity_without_aggregation() -> None:
    sentinel = CandidateContainerCleanupError("kernel-owned failure")

    def kernel(*_args: Any, **_kwargs: Any) -> _CleanupResult:
        raise sentinel

    with pytest.raises(CandidateContainerCleanupError) as caught:
        cleanup_candidate_containers(
            CandidateContainerCleanupRequest("/judge/cids", strict=True),
            services=_services(kernel=kernel),
        )

    assert caught.value is sentinel
    assert str(caught.value) == "kernel-owned failure"


def test_strict_cleanup_aggregates_failures_once_in_kernel_order() -> None:
    def kernel(*_args: Any, **_kwargs: Any) -> _CleanupResult:
        return _CleanupResult(("first", "second"))

    with pytest.raises(
        CandidateContainerCleanupError,
        match=(
            "^candidate container cleanup could not prove absence: "
            "first; second$"
        ),
    ) as caught:
        cleanup_candidate_containers(
            CandidateContainerCleanupRequest("/judge/cids", strict=True),
            services=_services(kernel=kernel),
        )

    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_non_strict_cleanup_does_not_construct_an_aggregate_error() -> None:
    def kernel(*_args: Any, **_kwargs: Any) -> _CleanupResult:
        return _CleanupResult(("first", "second"))

    def forbidden_factory(_message: str) -> Exception:
        raise AssertionError("non-strict cleanup constructed an error")

    assert (
        cleanup_candidate_containers(
            CandidateContainerCleanupRequest("/judge/cids", strict=False),
            services=_services(
                kernel=kernel,
                cleanup_error_factory=forbidden_factory,
            ),
        )
        is None
    )


def test_evidence_projection_copies_isolation_and_keeps_input_unchanged() -> None:
    isolation: dict[str, object] = {
        "requested": "docker",
        "delivered": "docker",
        "note": "prepared",
    }

    class Recorder:
        def drain(self) -> int:
            return 0

    evidence = attach_candidate_execution_evidence(
        CandidateExecutionEvidenceRequest(
            isolation=isolation,
            recorder=Recorder(),
            cidfile_dir="/judge/cids",
        ),
        services=CandidateExecutionEvidenceServices(
            container_ids_provider=lambda: (
                lambda _path, *, strict=False: []
            ),
            sleeper_provider=lambda: lambda _seconds: None,
        ),
    )

    assert isolation == {
        "requested": "docker",
        "delivered": "docker",
        "note": "prepared",
    }
    assert evidence.isolation is not isolation
    assert evidence.isolation["delivered"] == "not_run"
    assert evidence.isolation["prepared"] == "docker"
