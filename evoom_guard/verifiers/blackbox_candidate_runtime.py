# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# -----------------------------------------------------------------------------
"""Candidate-container observation and cleanup orchestration.

This dependency-free owner preserves the black-box runtime's established
effect order while leaving concrete Docker types and compatibility patch seams
in :mod:`evoom_guard.blackbox`.  Providers are resolved at their historical
operation sites: the evidence loop observes a fresh scanner and sleeper on
every retry, while cleanup captures the kernel before freezing the known IDs
and resolves the remaining effects only after request construction.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol


class InvocationRecorder(Protocol):
    """Minimal live receipt source used by candidate evidence collection."""

    def drain(self) -> int: ...


class CandidateContainerIdScanner(Protocol):
    """Read the currently valid candidate container IDs."""

    def __call__(
        self,
        cidfile_dir: str,
        *,
        strict: bool = False,
    ) -> list[str]: ...


class CandidateCidScanObservation(Protocol):
    """Structural scan result consumed by the concrete cleanup kernel."""

    @property
    def container_ids(self) -> tuple[str, ...]: ...

    @property
    def failures(self) -> tuple[str, ...]: ...


class CandidateCleanupKernelRequest(Protocol):
    """Structural request accepted by the concrete cleanup kernel."""

    @property
    def cidfile_dir(self) -> str: ...

    @property
    def wait_for_late_cidfiles(self) -> bool: ...

    @property
    def known_container_ids(self) -> frozenset[str]: ...


class CandidateCleanupKernelResult(Protocol):
    """Cleanup facts required by the strict facade."""

    @property
    def failures(self) -> Sequence[str]: ...


class CandidateCleanupRequestFactory(Protocol):
    """Construct the concrete kernel request after the kernel is captured."""

    def __call__(
        self,
        *,
        cidfile_dir: str,
        wait_for_late_cidfiles: bool,
        known_container_ids: frozenset[str],
    ) -> CandidateCleanupKernelRequest: ...


class CandidateCidScanResultFactory(Protocol):
    """Construct the concrete scan observation consumed by the kernel."""

    def __call__(
        self,
        container_ids: tuple[str, ...],
        failures: tuple[str, ...] = (),
    ) -> CandidateCidScanObservation: ...


class DockerControlRunner(Protocol):
    """Concrete Docker control seam forwarded untouched to the kernel."""

    def __call__(
        self,
        command: list[str],
        *,
        timeout: float = 30.0,
    ) -> object: ...


class CandidateContainerCleanupKernel(Protocol):
    """Concrete bounded cleanup algorithm owned by the isolation layer."""

    def __call__(
        self,
        request: CandidateCleanupKernelRequest,
        *,
        scanner: Callable[[str], CandidateCidScanObservation],
        control_runner: DockerControlRunner,
        sleeper: Callable[[float], None],
        path_exists: Callable[[str], bool],
    ) -> CandidateCleanupKernelResult: ...


@dataclass(frozen=True, slots=True)
class CandidateExecutionEvidenceRequest:
    """One black-box result awaiting launcher/CID evidence projection."""

    isolation: Mapping[str, object] | None
    recorder: InvocationRecorder | None
    cidfile_dir: str
    wait_for_late_container_evidence: bool = False
    observed_container_ids: set[str] | None = None


@dataclass(frozen=True, slots=True)
class CandidateExecutionEvidenceServices:
    """Live scanner and sleeper providers for the bounded retry loop."""

    container_ids_provider: Callable[[], CandidateContainerIdScanner]
    sleeper_provider: Callable[[], Callable[[float], None]]


@dataclass(frozen=True, slots=True)
class CandidateExecutionEvidence:
    """Exact evidence fields projected back onto ``BlackboxResult``."""

    isolation: dict[str, object]
    candidate_invocations: int
    candidate_launcher_invocation_observed: bool


@dataclass(frozen=True, slots=True)
class CandidateContainerCleanupRequest:
    """Facade inputs for one candidate-container absence proof."""

    cidfile_dir: str
    wait_for_late_cidfiles: bool = False
    strict: bool = False
    known_container_ids: Iterable[str] | None = None


@dataclass(frozen=True, slots=True)
class CandidateContainerCleanupServices:
    """Live concrete adapters resolved in the historical cleanup order."""

    cleanup_kernel_provider: Callable[[], CandidateContainerCleanupKernel]
    cleanup_request_factory_provider: Callable[
        [], CandidateCleanupRequestFactory
    ]
    scan_result_factory_provider: Callable[[], CandidateCidScanResultFactory]
    container_ids_provider: Callable[[], CandidateContainerIdScanner]
    control_runner_provider: Callable[[], DockerControlRunner]
    sleeper_provider: Callable[[], Callable[[float], None]]
    path_exists_provider: Callable[[], Callable[[str], bool]]
    scan_failure_type_provider: Callable[[], type[Exception]]
    cleanup_error_factory_provider: Callable[
        [], Callable[[str], Exception]
    ]


def attach_candidate_execution_evidence(
    request: CandidateExecutionEvidenceRequest,
    *,
    services: CandidateExecutionEvidenceServices,
) -> CandidateExecutionEvidence:
    """Observe launcher receipts and runtime CIDs without weakening retries."""

    isolation = dict(request.isolation or {})
    delivered = str(isolation.get("delivered") or "")
    attempts = (
        10
        if (
            request.wait_for_late_container_evidence
            and delivered in {"docker", "gvisor"}
        )
        else 1
    )
    launcher_events = 0
    container_ids: list[str] = []
    candidate_invocations = 0
    for attempt in range(attempts):
        launcher_events = (
            request.recorder.drain()
            if request.recorder is not None
            else 0
        )
        container_ids = services.container_ids_provider()(
            request.cidfile_dir
        )
        if request.observed_container_ids is not None:
            # Mutation is deliberately immediate.  Even an interrupt raised by
            # a tracking set after ``update`` must leave the observed CID sticky.
            request.observed_container_ids.update(container_ids)
            container_ids = sorted(request.observed_container_ids)
        if delivered == "subprocess":
            candidate_invocations = launcher_events
        elif delivered in {"docker", "gvisor"}:
            candidate_invocations = min(
                launcher_events,
                len(container_ids),
            )
        else:
            candidate_invocations = 0
        if candidate_invocations > 0 or attempt + 1 == attempts:
            break
        services.sleeper_provider()(0.05)

    candidate_launcher_invocation_observed = candidate_invocations > 0
    if (
        not candidate_launcher_invocation_observed
        and delivered not in {"", "not_run", "unavailable"}
    ):
        preparation_note = isolation.get("note")
        isolation["prepared"] = delivered
        isolation["delivered"] = "not_run"
        if preparation_note:
            isolation["preparation_note"] = preparation_note
        isolation["note"] = (
            "the boundary was prepared, but the required launcher/runtime "
            "invocation evidence was not observed; no candidate isolation is "
            "claimed"
        )
    isolation.update(
        {
            "candidate_launcher_events": launcher_events,
            "candidate_container_ids_observed": len(container_ids),
            "candidate_invocations": candidate_invocations,
            "candidate_launcher_invocation_observed": (
                candidate_launcher_invocation_observed
            ),
            "candidate_invocation_evidence_note": (
                "proves the trusted pack invoked EVOGUARD_EXEC; it does not by "
                "itself prove that the pack-supplied argv exercised candidate code. "
                "Only the zero/nonzero fact is security-relevant; same-host code "
                "could discover the sidecar after its first invocation, so the raw "
                "receipt count is not an audited exact call count"
            ),
        }
    )
    return CandidateExecutionEvidence(
        isolation=isolation,
        candidate_invocations=candidate_invocations,
        candidate_launcher_invocation_observed=(
            candidate_launcher_invocation_observed
        ),
    )


def cleanup_candidate_containers(
    request: CandidateContainerCleanupRequest,
    *,
    services: CandidateContainerCleanupServices,
) -> None:
    """Run the concrete cleanup kernel and enforce the established strict gate."""

    def scan(path: str) -> CandidateCidScanObservation:
        # Preserve callable evaluation order: the concrete result factory is
        # selected before the scanner can rebind any facade seam.
        scan_result_factory = services.scan_result_factory_provider()
        try:
            return scan_result_factory(
                tuple(
                    services.container_ids_provider()(
                        path,
                        strict=request.strict,
                    )
                )
            )
        except services.scan_failure_type_provider() as exc:
            return scan_result_factory((), (str(exc),))

    # Python historically resolved the kernel before constructing its request.
    # Freezing known IDs may execute user-supplied iteration and rebind the
    # facade's remaining seams; those effects must not replace this in-flight
    # kernel, but the control/sleep/path providers below must observe them.
    cleanup_kernel = services.cleanup_kernel_provider()
    cleanup_request_factory = services.cleanup_request_factory_provider()
    known_container_ids = frozenset(request.known_container_ids or ())
    kernel_request = cleanup_request_factory(
        cidfile_dir=request.cidfile_dir,
        wait_for_late_cidfiles=request.wait_for_late_cidfiles,
        known_container_ids=known_container_ids,
    )
    cleanup = cleanup_kernel(
        kernel_request,
        scanner=scan,
        control_runner=services.control_runner_provider(),
        sleeper=services.sleeper_provider(),
        path_exists=services.path_exists_provider(),
    )
    if request.strict and cleanup.failures:
        raise services.cleanup_error_factory_provider()(
            "candidate container cleanup could not prove absence: "
            + "; ".join(cleanup.failures)
        )


__all__ = [
    "CandidateCleanupKernelRequest",
    "CandidateCleanupKernelResult",
    "CandidateCleanupRequestFactory",
    "CandidateCidScanObservation",
    "CandidateCidScanResultFactory",
    "CandidateContainerCleanupKernel",
    "CandidateContainerCleanupRequest",
    "CandidateContainerCleanupServices",
    "CandidateContainerIdScanner",
    "CandidateExecutionEvidence",
    "CandidateExecutionEvidenceRequest",
    "CandidateExecutionEvidenceServices",
    "DockerControlRunner",
    "InvocationRecorder",
    "attach_candidate_execution_evidence",
    "cleanup_candidate_containers",
]
