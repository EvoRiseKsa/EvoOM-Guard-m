# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Ordered unified-diff verification behind Guard's compatibility facade.

This module owns only the established application sequence: reject an
unrepresentable diff, reconstruct its base in a throwaway workspace, derive
structured candidate edits, and delegate the actual judgment.  Filesystem,
process, verifier, error-result, and cleanup effects stay in ``guard.py`` and
are resolved through live providers at their historical operation boundaries.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, Protocol, TypeVar


class MutableDiffResult(Protocol):
    """Minimum result surface annotated by the diff compatibility path."""

    source: str | None
    base_reconstruction: str | None


ResultT = TypeVar("ResultT", bound=MutableDiffResult)
ResultCo = TypeVar("ResultCo", bound=MutableDiffResult, covariant=True)


class DiffErrorFactory(Protocol[ResultCo]):
    """Build a historical fail-closed diff result."""

    def __call__(
        self,
        reason: str,
        *,
        reason_code: str,
        base_reconstruction: str = "failed",
    ) -> ResultCo: ...


class InputErrorFactory(Protocol[ResultCo]):
    """Build a historical input error before candidate materialization."""

    def __call__(
        self,
        reason: str,
        *,
        reason_code: str,
        source: str,
        base_reconstruction: str | None = None,
        verifier_pack: str | None = None,
    ) -> ResultCo: ...


class VerifierPackTrustCheck(Protocol):
    """Validate that a verifier pack is not candidate controlled."""

    def __call__(
        self,
        candidate_dir: str,
        verifier_pack: str | None,
        expect_verifier_pack_sha256: str | None,
    ) -> str | None: ...


class WorkspaceFactory(Protocol):
    """Create the throwaway diff reconstruction workspace."""

    def __call__(self, *, prefix: str) -> str: ...


@dataclass(frozen=True, slots=True)
class DiffVerificationOptions:
    """Exact keyword inputs accepted by ``guard_from_diff()``.

    Mutable command lists are intentionally retained by reference.  The value
    is shallow-frozen so extraction does not silently change the public
    identity or mutation semantics of established integration seams.
    """

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
    verifier_pack: str | None
    expect_verifier_pack_sha256: str | None
    diff_coverage: bool
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


@dataclass(frozen=True, slots=True)
class DiffVerificationRequest:
    """One unified-diff verification request at the application boundary."""

    head_dir: str
    diff_text: str
    options: DiffVerificationOptions


@dataclass(frozen=True, slots=True)
class DiffVerificationServices(Generic[ResultT]):
    """Live effect providers owned by the public Guard facade.

    Each outer callable returns the operation used at that exact point in the
    sequence.  This deliberately preserves historical monkeypatch/rebinding
    behavior between operations instead of snapshotting effect functions when
    the service aggregate is constructed.
    """

    diff_error_provider: Callable[[], DiffErrorFactory[ResultT]]
    input_error_provider: Callable[[], InputErrorFactory[ResultT]]
    empty_diff_reason_code_provider: Callable[[], str]
    binary_patch_reason_code_provider: Callable[[], str]
    unsafe_path_reason_code_provider: Callable[[], str]
    verifier_pack_invalid_reason_code_provider: Callable[[], str]
    reverse_apply_failed_reason_code_provider: Callable[[], str]
    no_verifiable_changes_reason_code_provider: Callable[[], str]
    binary_diff_provider: Callable[[], Callable[[str], bool]]
    diff_target_paths_provider: Callable[[], Callable[[str], list[str]]]
    safe_relpath_provider: Callable[[], Callable[[str], bool]]
    verifier_pack_trust_check_provider: Callable[[], VerifierPackTrustCheck]
    workspace_factory_provider: Callable[[], WorkspaceFactory]
    path_join_provider: Callable[[], Callable[[str, str], str]]
    copy_repo_tree_provider: Callable[[], Callable[[str, str], None]]
    diff_writer_provider: Callable[[], Callable[[str, str], None]]
    reverse_apply_provider: Callable[[], Callable[[str, str], bool]]
    blocks_from_dirs_provider: Callable[
        [], Callable[[str, str], tuple[dict[str, str], list[str]]]
    ]
    unverifiable_errors_provider: Callable[
        [], tuple[type[BaseException], ...]
    ]
    guard_provider: Callable[[], Callable[..., ResultT]]
    diff_base_sha_provider: Callable[[], Callable[[str], str | None]]
    diff_head_sha_provider: Callable[[], Callable[[str], str | None]]
    cleanup_workspace_provider: Callable[
        [], Callable[..., None]
    ]


@dataclass(frozen=True, slots=True)
class DiffVerificationOutcome(Generic[ResultT]):
    """Result and deletion list returned through the compatibility facade."""

    result: ResultT
    deleted: list[str]


def verify_diff(
    request: DiffVerificationRequest,
    services: DiffVerificationServices[ResultT],
) -> DiffVerificationOutcome[ResultT]:
    """Execute the established fail-closed diff reconstruction sequence."""

    diff_text = request.diff_text
    options = request.options

    if not (diff_text or "").strip():
        return DiffVerificationOutcome(
            result=services.diff_error_provider()(
                "empty diff — nothing to verify",
                reason_code=services.empty_diff_reason_code_provider(),
            ),
            deleted=[],
        )
    if services.binary_diff_provider()(diff_text):
        return DiffVerificationOutcome(
            result=services.diff_error_provider()(
                "binary patches are not supported — Guard verifies text source "
                "changes; the diff contains a binary file change",
                reason_code=services.binary_patch_reason_code_provider(),
            ),
            deleted=[],
        )
    unsafe = sorted(
        {
            path
            for path in services.diff_target_paths_provider()(diff_text)
            if not services.safe_relpath_provider()(path)
        }
    )
    if unsafe:
        return DiffVerificationOutcome(
            result=services.diff_error_provider()(
                "the diff references unsafe path(s) outside the repo (absolute, "
                "'..', or escaping the root) — refusing to apply: "
                f"{', '.join(unsafe)}",
                reason_code=services.unsafe_path_reason_code_provider(),
            ),
            deleted=[],
        )
    pack_trust_problem = services.verifier_pack_trust_check_provider()(
        request.head_dir,
        options.verifier_pack,
        options.expect_verifier_pack_sha256,
    )
    if pack_trust_problem:
        return DiffVerificationOutcome(
            result=services.input_error_provider()(
                pack_trust_problem,
                reason_code=(
                    services.verifier_pack_invalid_reason_code_provider()
                ),
                source="diff",
                base_reconstruction="failed",
                verifier_pack=options.verifier_pack,
            ),
            deleted=[],
        )

    workdir = services.workspace_factory_provider()(prefix="evo_guard_diff_")
    base = services.path_join_provider()(workdir, "base")
    try:
        services.copy_repo_tree_provider()(request.head_dir, base)
        diff_file = services.path_join_provider()(workdir, "patch.diff")
        services.diff_writer_provider()(diff_file, diff_text)
        if not services.reverse_apply_provider()(base, diff_file):
            return DiffVerificationOutcome(
                result=services.diff_error_provider()(
                    "the diff did not reverse-apply to the working tree — make "
                    "sure you are in the head checkout and the diff is "
                    "'base...HEAD' (git/patch needed)",
                    reason_code=(
                        services.reverse_apply_failed_reason_code_provider()
                    ),
                ),
                deleted=[],
            )
        try:
            file_blocks, deleted = services.blocks_from_dirs_provider()(
                base,
                request.head_dir,
            )
        except services.unverifiable_errors_provider() as exc:
            return DiffVerificationOutcome(
                result=services.diff_error_provider()(
                    "the diff includes changed path(s) Guard cannot safely verify: "
                    f"{exc}",
                    reason_code=(
                        services.no_verifiable_changes_reason_code_provider()
                    ),
                    base_reconstruction="ok",
                ),
                deleted=[],
            )
        candidate = "\n".join(
            f"<<<FILE: {relative_path}>>>\n{new_content}\n<<<END FILE>>>"
            for relative_path, new_content in file_blocks.items()
        )
        if not file_blocks and not deleted:
            return DiffVerificationOutcome(
                result=services.diff_error_provider()(
                    "the diff changed no verifiable source files",
                    reason_code=(
                        services.no_verifiable_changes_reason_code_provider()
                    ),
                    base_reconstruction="ok",
                ),
                deleted=deleted,
            )

        # Resolve the callable before evaluating SHA keyword expressions.  This
        # is the observable Python call order of the historical direct call and
        # matters when integrations rebind providers between operations.
        run_guard = services.guard_provider()
        result = run_guard(
            base,
            candidate,
            deleted=tuple(deleted),
            test_command=options.test_command,
            setup_command=options.setup_command,
            trust_setup_on_host=options.trust_setup_on_host,
            setup_output_globs=options.setup_output_globs,
            protected=options.protected,
            allow=options.allow,
            allow_new_tests=options.allow_new_tests,
            timeout=options.timeout,
            mem_limit_mb=options.mem_limit_mb,
            isolation=options.isolation,
            docker_image=options.docker_image,
            docker_network=options.docker_network,
            verifier_pack=options.verifier_pack,
            expect_verifier_pack_sha256=options.expect_verifier_pack_sha256,
            diff_coverage=options.diff_coverage,
            min_diff_coverage=options.min_diff_coverage,
            blackbox=options.blackbox,
            blackbox_only=options.blackbox_only,
            require_report_integrity=options.require_report_integrity,
            require_candidate_isolation=options.require_candidate_isolation,
            base_sha=options.base_sha
            or services.diff_base_sha_provider()(diff_text),
            head_sha=options.head_sha
            or services.diff_head_sha_provider()(diff_text),
            base_tree_sha=options.base_tree_sha,
            head_tree_sha=options.head_tree_sha,
            policy_id=options.policy_id,
            policy_version=options.policy_version,
            baseline_evidence=options.baseline_evidence,
            require_demonstrated_fix=options.require_demonstrated_fix,
            strict_harness=options.strict_harness,
            file_blocks=file_blocks,
        )
        result.source = "diff"
        result.base_reconstruction = "ok"
        return DiffVerificationOutcome(result=result, deleted=deleted)
    finally:
        services.cleanup_workspace_provider()(workdir, ignore_errors=True)
