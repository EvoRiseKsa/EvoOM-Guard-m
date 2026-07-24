# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Pristine repository-suite baseline execution.

This owner runs the repository-native suite on a judge-created copy of the
pristine base. It deliberately does not interpret the candidate transition or
apply the demonstrated-fix gate; ordered finalization retains those concerns.

The report remains judge-owned but candidate-produced, exactly like the
repository suite. Host commands therefore retain bounded output, timeout,
resource-limit, and strict process-group cleanup requirements. Runtime effects
are supplied through narrow providers so Guard can resolve its historical
compatibility seams at the same operation sites.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

BaselineEvidence = dict[str, Any]
FidelitySnapshot = dict[str, Any]
ExceptionType = type[BaseException]


class BaselineProcess(Protocol):
    """Minimal completed-process evidence used by baseline policy."""

    returncode: int


class BaselineVerifier(Protocol):
    """Repository-verifier operations reused by the pristine run."""

    def _limits(self) -> Any: ...

    def _command(self, problem: dict[str, str]) -> list[str]: ...


class BuildBaselineVerifier(Protocol):
    """Construct the compatibility repository verifier."""

    def __call__(
        self,
        *,
        timeout: int,
        mem_limit_mb: int,
        strict_harness: bool,
    ) -> BaselineVerifier: ...


class MakeWorkspace(Protocol):
    """Create one judge-owned temporary baseline workspace."""

    def __call__(self, *, prefix: str) -> str: ...


class CopyRepository(Protocol):
    """Copy the pristine repository into the owned workspace."""

    def __call__(self, source: str, destination: str) -> None: ...


class BuildJudgeEnvironment(Protocol):
    """Build the baseline subprocess environment."""

    def __call__(self, workdir: str) -> dict[str, str]: ...


class CaptureSetupFidelity(Protocol):
    """Capture a setup-fidelity snapshot before or after setup."""

    def __call__(
        self,
        root: str,
        output_globs: Sequence[str] = (),
        *,
        baseline: FidelitySnapshot | None = None,
    ) -> FidelitySnapshot: ...


class CompareSetupFidelity(Protocol):
    """Return judged-tree changes introduced by setup."""

    def __call__(
        self,
        before: FidelitySnapshot,
        after: FidelitySnapshot,
    ) -> list[str]: ...


class InstrumentBaselineCommand(Protocol):
    """Bind a repository command to a judge-owned structured report."""

    def __call__(
        self,
        command: list[str],
        report_path: str,
    ) -> tuple[list[str], bool, dict[str, str]]: ...


class ResolveHostCommand(Protocol):
    """Resolve one host command at its historical operation site."""

    def __call__(
        self,
        command: list[str],
        *,
        cwd: str,
        env: Mapping[str, str],
    ) -> list[str]: ...


class RunBoundedHostProcess(Protocol):
    """Run one bounded host phase."""

    def __call__(
        self,
        command: list[str],
        *,
        cwd: str | None,
        env: Mapping[str, str],
        timeout: int,
        preexec_fn: Any,
        require_process_group_cleanup_proof: bool,
    ) -> BaselineProcess: ...


class ReadJUnitReport(Protocol):
    """Read the judge-owned JUnit file through the bounded oracle."""

    def __call__(self, path: str) -> str | None: ...


class ParseJUnitReport(Protocol):
    """Parse one JUnit document."""

    def __call__(self, text: str) -> Any | None: ...


class ParseJUnitDirectory(Protocol):
    """Parse the owned sibling directory when the file is unavailable."""

    def __call__(self, path: str) -> Any | None: ...


class GradeBaselineRun(Protocol):
    """Grade exit and JUnit evidence through repository-suite policy."""

    def __call__(
        self,
        returncode: int,
        junit: Any | None,
        *,
        report_expected: bool,
    ) -> tuple[bool, float, int | None, int | None]: ...


class DetectBaselineTamper(Protocol):
    """Detect disagreement between exit and structured evidence."""

    def __call__(
        self,
        returncode: int,
        junit: Any | None,
        *,
        report_expected: bool,
    ) -> bool: ...


class CleanupWorkspace(Protocol):
    """Remove the owned workspace with the historical cleanup policy."""

    def __call__(self, path: str, *, ignore_errors: bool) -> None: ...


class JoinPath(Protocol):
    """Join one judge-owned workspace path at its historical lookup site."""

    def __call__(self, *parts: str) -> str: ...


@dataclass(frozen=True, slots=True)
class RepoBaselineRequest:
    """Frozen field bindings for one pristine repository-suite run.

    The two command lists deliberately retain their caller-owned references.
    That historical aliasing is observable through the Guard compatibility
    facade; a defensive tuple snapshot would be a separate semantic change.
    """

    repository_path: str
    test_command: list[str] | None
    setup_command: list[str] | None
    setup_output_globs: tuple[str, ...]
    timeout: int
    mem_limit_mb: int
    strict_harness: bool


@dataclass(frozen=True, slots=True)
class RepoBaselineServices:
    """Judge-owned effects resolved by the compatibility facade."""

    verifier_factory: BuildBaselineVerifier
    workspace_factory_provider: Callable[[], MakeWorkspace]
    path_join_provider: Callable[[], JoinPath]
    platform_name_provider: Callable[[], str]
    os_error_provider: Callable[[], ExceptionType]
    setup_fidelity_error_provider: Callable[[], ExceptionType]
    containment_error_provider: Callable[[], ExceptionType]
    output_limit_error_provider: Callable[[], ExceptionType]
    timeout_error_provider: Callable[[], ExceptionType]
    copy_repository_provider: Callable[[], CopyRepository]
    judge_environment_provider: Callable[[], BuildJudgeEnvironment]
    setup_fidelity_snapshot: CaptureSetupFidelity
    setup_fidelity_changes: CompareSetupFidelity
    instrument_command: InstrumentBaselineCommand
    resolve_host_command_provider: Callable[[], ResolveHostCommand]
    run_bounded_subprocess_provider: Callable[[], RunBoundedHostProcess]
    read_junit_xml: ReadJUnitReport
    parse_junit_xml: ParseJUnitReport
    parse_junit_dir: ParseJUnitDirectory
    grade_repo_run: GradeBaselineRun
    detect_tamper: DetectBaselineTamper
    cleanup_workspace_provider: Callable[[], CleanupWorkspace]


def _empty_evidence(**extra: Any) -> BaselineEvidence:
    return {
        "verdict": "NO_CLEAN_VERDICT",
        "tests_passed": None,
        "tests_total": None,
        **extra,
    }


def run_repo_baseline(
    request: RepoBaselineRequest,
    *,
    services: RepoBaselineServices,
) -> BaselineEvidence:
    """Run the pristine suite with the repository judge's evidence boundary."""

    verifier = services.verifier_factory(
        timeout=request.timeout,
        mem_limit_mb=request.mem_limit_mb,
        strict_harness=request.strict_harness,
    )
    workdir = services.workspace_factory_provider()(prefix="evo_baseline_")
    candidate_copy = services.path_join_provider()(workdir, "repo")
    try:
        services.copy_repository_provider()(
            request.repository_path,
            candidate_copy,
        )
        environment = services.judge_environment_provider()(workdir)
        if request.setup_command:
            try:
                setup_before = services.setup_fidelity_snapshot(
                    candidate_copy,
                    request.setup_output_globs,
                )
                setup_environment = dict(environment)
                resolve_host_command = services.resolve_host_command_provider()
                setup_command = resolve_host_command(
                    list(request.setup_command),
                    cwd=candidate_copy,
                    env=setup_environment,
                )
                # Baseline remains candidate-adjacent execution: neither setup
                # nor suite may regain unbounded stdout/stderr on the base tree.
                run_bounded_subprocess = (
                    services.run_bounded_subprocess_provider()
                )
                setup_process = run_bounded_subprocess(
                    setup_command,
                    cwd=candidate_copy,
                    env=setup_environment,
                    timeout=request.timeout,
                    preexec_fn=(
                        verifier._limits()
                        if services.platform_name_provider() == "posix"
                        else None
                    ),
                    require_process_group_cleanup_proof=(
                        request.strict_harness
                    ),
                )
                setup_after = services.setup_fidelity_snapshot(
                    candidate_copy,
                    request.setup_output_globs,
                    baseline=setup_before,
                )
            except (
                services.os_error_provider(),
                services.setup_fidelity_error_provider(),
                services.containment_error_provider(),
                services.output_limit_error_provider(),
                services.timeout_error_provider(),
            ):
                return _empty_evidence(setup_fidelity="unverified")
            if setup_process.returncode != 0:
                return _empty_evidence(setup_fidelity="setup_failed")
            setup_changes = services.setup_fidelity_changes(
                setup_before,
                setup_after,
            )
            if setup_changes:
                return _empty_evidence(
                    setup_fidelity="changed_judged_tree",
                    setup_fidelity_changes=setup_changes,
                )

        base_command = verifier._command(
            {"repo_path": request.repository_path}
        )
        if request.test_command:
            base_command = list(request.test_command)
        report_path = services.path_join_provider()(
            workdir,
            "judge-result.xml",
        )
        command, report_expected, report_environment = (
            services.instrument_command(base_command, report_path)
        )
        run_environment = {
            **environment,
            **report_environment,
        }
        resolve_host_command = services.resolve_host_command_provider()
        command = resolve_host_command(
            command,
            cwd=candidate_copy,
            env=run_environment,
        )
        try:
            run_bounded_subprocess = (
                services.run_bounded_subprocess_provider()
            )
            process = run_bounded_subprocess(
                command,
                cwd=candidate_copy,
                env=run_environment,
                preexec_fn=(
                    verifier._limits()
                    if services.platform_name_provider() == "posix"
                    else None
                ),
                timeout=request.timeout,
                require_process_group_cleanup_proof=(
                    request.strict_harness
                ),
            )
        except (
            services.os_error_provider(),
            services.containment_error_provider(),
            services.output_limit_error_provider(),
            services.timeout_error_provider(),
        ):
            return _empty_evidence()

        # The path is judge-owned but the contents are candidate-produced.
        # Missing, oversized, racing, or inconsistent reports are not clean.
        xml_text = services.read_junit_xml(report_path) or ""
        junit = services.parse_junit_xml(xml_text)
        if junit is None:
            junit = services.parse_junit_dir(report_path + ".d")
        passed, _score, tests_passed, tests_total = services.grade_repo_run(
            process.returncode,
            junit,
            report_expected=report_expected,
        )
        tampered = services.detect_tamper(
            process.returncode,
            junit,
            report_expected=report_expected,
        )
        if (
            tampered
            or (junit is None and report_expected)
            or (
                request.strict_harness
                and (
                    not report_expected
                    or junit is None
                    or junit.total <= 0
                )
            )
        ):
            return {
                "verdict": "NO_CLEAN_VERDICT",
                "tests_passed": tests_passed,
                "tests_total": tests_total,
            }
        return {
            "verdict": "PASS" if passed else "FAIL",
            "tests_passed": tests_passed,
            "tests_total": tests_total,
        }
    finally:
        services.cleanup_workspace_provider()(
            workdir,
            ignore_errors=True,
        )


__all__ = [
    "RepoBaselineRequest",
    "RepoBaselineServices",
    "run_repo_baseline",
]
