# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Typed preparation of one Guard request and its legacy runtime projection.

This module owns only public scalar validation, immutable request capture,
canonical effective-policy construction, and projection back to the historical
local values consumed by ``guard()``. It does not classify paths, inspect a
repository, decide policy-mode support, execute candidate code, or assemble
evidence.

Constructors and policy providers are injected deliberately. The ``guard.py``
compatibility facade resolves its current module globals on every call so the
established monkeypatch seams remain live rather than being snapshotted here.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from evoom_guard.domain import (
    CandidateInput,
    EffectivePolicy,
    GuardRequest,
    RepositoryInput,
    SourceIdentity,
)


class _RepositoryInputFactory(Protocol):
    def __call__(self, *, path: str) -> RepositoryInput: ...


class _SourceIdentityFactory(Protocol):
    def __call__(
        self,
        *,
        base_sha: str | None,
        head_sha: str | None,
        base_tree_sha: str | None,
        head_tree_sha: str | None,
    ) -> SourceIdentity: ...


class _EffectivePolicyFactory(Protocol):
    def __call__(
        self,
        *,
        mode: str,
        isolation: str,
        docker_image: str | None,
        docker_network: str,
        test_command: list[str] | None,
        setup_command: list[str] | None,
        trust_setup_on_host: bool,
        setup_output_globs: tuple[str, ...],
        protected: tuple[str, ...],
        allow: tuple[str, ...],
        allow_new_tests: bool,
        timeout: int,
        mem_limit_mb: int,
        verifier_pack: str | None,
        expect_verifier_pack_sha256: str | None,
        blackbox: bool,
        blackbox_only: bool,
        require_report_integrity: str | None,
        require_candidate_isolation: str | None,
        min_diff_coverage: float | None,
        baseline_evidence: bool,
        require_demonstrated_fix: bool,
        strict_harness: bool,
        policy_id: str | None,
        policy_version: str | None,
    ) -> EffectivePolicy: ...


class _GuardRequestFactory(Protocol):
    def __call__(
        self,
        *,
        repository: RepositoryInput,
        candidate: CandidateInput,
        source: SourceIdentity,
        policy: EffectivePolicy,
        verifier_pack_path: str | None,
        collect_diff_coverage: bool,
    ) -> GuardRequest: ...


@dataclass(frozen=True, slots=True)
class GuardRequestPreparationInput:
    """Raw compatibility inputs passed through Guard's public API."""

    repository_path: str
    candidate_text: str
    deleted_paths: Sequence[str]
    test_command: list[str] | None
    setup_command: list[str] | None
    trust_setup_on_host: bool
    setup_output_globs: tuple[str, ...]
    protected: tuple[str, ...]
    allow: tuple[str, ...]
    allow_new_tests: bool
    timeout: int
    mem_limit_mb: int
    isolation: str
    docker_image: str | None
    docker_network: str
    verifier_pack_path: str | None
    expect_verifier_pack_sha256: str | None
    collect_diff_coverage: bool
    min_diff_coverage: float | None
    blackbox: bool
    blackbox_only: bool
    require_report_integrity: str | None
    require_candidate_isolation: str | None
    base_sha: str | None
    head_sha: str | None
    base_tree_sha: str | None
    head_tree_sha: str | None
    policy_id: str | None
    policy_version: str | None
    baseline_evidence: bool
    require_demonstrated_fix: bool
    strict_harness: bool
    file_blocks: Mapping[str, str] | None


@dataclass(frozen=True, slots=True)
class GuardRequestPreparationServices:
    """Resolvers for callables used at their historical evaluation positions."""

    repository_input_provider: Callable[[], _RepositoryInputFactory]
    candidate_input_provider: Callable[[], Callable[..., CandidateInput]]
    source_identity_provider: Callable[[], _SourceIdentityFactory]
    effective_policy_provider: Callable[[], _EffectivePolicyFactory]
    guard_request_provider: Callable[[], _GuardRequestFactory]
    effective_policy_payload_provider: Callable[
        [], Callable[[EffectivePolicy], dict[str, object]]
    ]


@dataclass(frozen=True, slots=True)
class GuardCompatibilityProjection:
    """Owned legacy-shaped values consumed by the unchanged Guard orchestrator.

    ``file_blocks`` and the two commands intentionally remain private mutable
    copies: downstream compatibility code historically consumes ``dict`` and
    ``list`` values. The frozen aggregate prevents rebinding, while the
    authoritative request remains deeply owned and immutable.
    """

    repository_path: str
    candidate_text: str
    deleted_paths: tuple[str, ...]
    file_blocks: dict[str, str] | None
    base_sha: str | None
    head_sha: str | None
    base_tree_sha: str | None
    head_tree_sha: str | None
    test_command: list[str] | None
    setup_command: list[str] | None
    trust_setup_on_host: bool
    setup_output_globs: tuple[str, ...]
    protected: tuple[str, ...]
    allow: tuple[str, ...]
    allow_new_tests: bool
    timeout: int
    mem_limit_mb: int
    isolation: str
    docker_image: str | None
    docker_network: str
    verifier_pack_path: str | None
    expect_verifier_pack_sha256: str | None
    collect_diff_coverage: bool
    min_diff_coverage: float | None
    blackbox: bool
    blackbox_only: bool
    require_report_integrity: str | None
    require_candidate_isolation: str | None
    policy_id: str | None
    policy_version: str | None
    baseline_evidence: bool
    require_demonstrated_fix: bool
    strict_harness: bool


@dataclass(frozen=True, slots=True)
class PreparedGuardRequest:
    """One owned request, canonical policy payload, and compatibility view."""

    request: GuardRequest
    effective_policy: dict[str, object]
    compatibility: GuardCompatibilityProjection


def prepare_guard_request(
    raw: GuardRequestPreparationInput,
    *,
    services: GuardRequestPreparationServices,
) -> PreparedGuardRequest:
    """Validate, snapshot, canonicalize, and project one Guard invocation.

    Validation order, exception text, provider order, coverage-floor
    implication, and projection shapes are frozen compatibility behavior.
    """

    # Python's type hints do not reject bool/float at runtime, and subprocess
    # accepts non-positive/float timeouts in inconsistent ways.
    if type(raw.timeout) is not int or raw.timeout < 1:
        raise ValueError("timeout must be a positive integer")
    if type(raw.mem_limit_mb) is not int or raw.mem_limit_mb < 0:
        raise ValueError("mem_limit_mb must be a non-negative integer")
    if type(raw.strict_harness) is not bool:
        raise ValueError("strict_harness must be a boolean")
    if (
        raw.min_diff_coverage is not None
        and (
            isinstance(raw.min_diff_coverage, bool)
            or not isinstance(raw.min_diff_coverage, (int, float))
            or not 0 <= raw.min_diff_coverage <= 100
            or not math.isfinite(raw.min_diff_coverage)
        )
    ):
        raise ValueError("min_diff_coverage must be a finite number between 0 and 100")

    # A floor cannot exist without the measurement that proves it.
    collect_diff_coverage = (
        raw.collect_diff_coverage or raw.min_diff_coverage is not None
    )
    if raw.blackbox_only and not raw.blackbox:
        raise ValueError("blackbox_only requires blackbox")
    if raw.expect_verifier_pack_sha256 and not raw.verifier_pack_path:
        raise ValueError("expect_verifier_pack_sha256 requires verifier_pack")

    # Python resolves the outer callable first, then each nested callable
    # immediately before that nested call's arguments. Keep those positions
    # explicit: integrations have historically monkeypatched these private
    # seams, including from argument coercion and property access.
    guard_request_factory = services.guard_request_provider()
    repository = services.repository_input_provider()(path=raw.repository_path)
    candidate = services.candidate_input_provider()(
        text=raw.candidate_text,
        deleted_paths=raw.deleted_paths,
        file_blocks=raw.file_blocks,
    )
    source = services.source_identity_provider()(
        base_sha=raw.base_sha,
        head_sha=raw.head_sha,
        base_tree_sha=raw.base_tree_sha,
        head_tree_sha=raw.head_tree_sha,
    )
    policy = services.effective_policy_provider()(
        mode="blackbox" if raw.blackbox else "repo",
        isolation=raw.isolation,
        docker_image=raw.docker_image,
        docker_network=raw.docker_network,
        test_command=raw.test_command,
        setup_command=raw.setup_command,
        trust_setup_on_host=raw.trust_setup_on_host,
        setup_output_globs=raw.setup_output_globs,
        protected=raw.protected,
        allow=raw.allow,
        allow_new_tests=raw.allow_new_tests,
        timeout=raw.timeout,
        mem_limit_mb=raw.mem_limit_mb,
        verifier_pack=raw.verifier_pack_path,
        expect_verifier_pack_sha256=raw.expect_verifier_pack_sha256,
        blackbox=raw.blackbox,
        blackbox_only=raw.blackbox_only,
        require_report_integrity=raw.require_report_integrity,
        require_candidate_isolation=raw.require_candidate_isolation,
        min_diff_coverage=raw.min_diff_coverage,
        baseline_evidence=raw.baseline_evidence,
        require_demonstrated_fix=raw.require_demonstrated_fix,
        strict_harness=raw.strict_harness,
        policy_id=raw.policy_id,
        policy_version=raw.policy_version,
    )
    request = guard_request_factory(
        repository=repository,
        candidate=candidate,
        source=source,
        policy=policy,
        verifier_pack_path=raw.verifier_pack_path,
        collect_diff_coverage=collect_diff_coverage,
    )
    effective_policy = services.effective_policy_payload_provider()(request.policy)

    compatibility = GuardCompatibilityProjection(
        repository_path=request.repository.path,
        candidate_text=request.candidate.text,
        deleted_paths=request.candidate.deleted_paths,
        file_blocks=(
            dict(request.candidate.file_blocks)
            if request.candidate.file_blocks is not None
            else None
        ),
        base_sha=request.source.base_sha,
        head_sha=request.source.head_sha,
        base_tree_sha=request.source.base_tree_sha,
        head_tree_sha=request.source.head_tree_sha,
        test_command=(
            list(request.policy.test_command)
            if request.policy.test_command is not None
            else None
        ),
        setup_command=(
            list(request.policy.setup_command)
            if request.policy.setup_command is not None
            else None
        ),
        trust_setup_on_host=request.policy.trust_setup_on_host,
        setup_output_globs=request.policy.setup_output_globs,
        protected=request.policy.protected,
        allow=request.policy.allow,
        allow_new_tests=request.policy.allow_new_tests,
        timeout=request.policy.timeout,
        mem_limit_mb=request.policy.mem_limit_mb,
        isolation=request.policy.isolation,
        docker_image=request.policy.docker_image,
        docker_network=request.policy.docker_network,
        verifier_pack_path=request.verifier_pack_path,
        expect_verifier_pack_sha256=request.policy.expect_verifier_pack_sha256,
        collect_diff_coverage=request.collect_diff_coverage,
        min_diff_coverage=request.policy.min_diff_coverage,
        blackbox=request.policy.blackbox,
        blackbox_only=request.policy.blackbox_only,
        require_report_integrity=request.policy.require_report_integrity,
        require_candidate_isolation=request.policy.require_candidate_isolation,
        policy_id=request.policy.policy_id,
        policy_version=request.policy.policy_version,
        baseline_evidence=request.policy.baseline_evidence,
        require_demonstrated_fix=request.policy.require_demonstrated_fix,
        strict_harness=request.policy.strict_harness,
    )
    return PreparedGuardRequest(
        request=request,
        effective_policy=effective_policy,
        compatibility=compatibility,
    )


__all__ = [
    "GuardCompatibilityProjection",
    "GuardRequestPreparationInput",
    "GuardRequestPreparationServices",
    "PreparedGuardRequest",
    "prepare_guard_request",
]
