# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ------------------------------------------------------------------------------
"""Typed application adapter for the public ``evo-guard guard`` command.

This module owns only command-level policy resolution, input-mode routing, and
output publication.  The package facade injects every historical runtime seam;
candidate judgment, repository materialization, evidence, and signing remain
owned by their existing modules.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Generic, Protocol, TypedDict, TypeVar


class _GuardResult(Protocol):
    source: str | None

    @property
    def exit_code(self) -> int: ...


_ResultT = TypeVar("_ResultT", bound=_GuardResult)
_ResultCo = TypeVar("_ResultCo", bound=_GuardResult, covariant=True)
_ResultContra = TypeVar(
    "_ResultContra", bound=_GuardResult, contravariant=True
)


class _LoadConfig(Protocol):
    def __call__(
        self,
        path: str,
        *,
        required: bool,
        out: Callable[[str], None],
    ) -> dict[str, Any]: ...


class _JoinPath(Protocol):
    def __call__(self, *parts: str) -> str: ...


class _GuardCall(Protocol[_ResultCo]):
    def __call__(
        self,
        repo_path: str,
        candidate: str,
        *,
        deleted: tuple[str, ...] = ...,
        test_command: list[str] | None = ...,
        setup_command: list[str] | None = ...,
        trust_setup_on_host: bool = ...,
        setup_output_globs: tuple[str, ...] = ...,
        protected: tuple[str, ...] = ...,
        allow: tuple[str, ...] = ...,
        allow_new_tests: bool = ...,
        timeout: int = ...,
        mem_limit_mb: int = ...,
        isolation: str = ...,
        docker_image: str | None = ...,
        docker_network: str = ...,
        verifier_pack: str | None = ...,
        expect_verifier_pack_sha256: str | None = ...,
        diff_coverage: bool = ...,
        min_diff_coverage: float | None = ...,
        blackbox: bool = ...,
        blackbox_only: bool = ...,
        require_report_integrity: str | None = ...,
        require_candidate_isolation: str | None = ...,
        base_sha: str | None = ...,
        head_sha: str | None = ...,
        base_tree_sha: str | None = ...,
        head_tree_sha: str | None = ...,
        policy_id: str | None = ...,
        policy_version: str | None = ...,
        baseline_evidence: bool = ...,
        require_demonstrated_fix: bool = ...,
        strict_harness: bool = ...,
        file_blocks: dict[str, str] | None = ...,
        operating_profile: str | None = ...,
        harness_inputs: tuple[str, ...] = ...,
        require_suite_continuity: bool = ...,
        require_assert_liveness: bool = ...,
        require_structured_verdict: bool = ...,
    ) -> _ResultCo: ...


class _GuardFromDiffCall(Protocol[_ResultCo]):
    def __call__(
        self,
        head_dir: str,
        diff_text: str,
        *,
        test_command: list[str] | None = ...,
        setup_command: list[str] | None = ...,
        trust_setup_on_host: bool = ...,
        setup_output_globs: tuple[str, ...] = ...,
        protected: tuple[str, ...] = ...,
        allow: tuple[str, ...] = ...,
        allow_new_tests: bool = ...,
        timeout: int = ...,
        mem_limit_mb: int = ...,
        isolation: str = ...,
        docker_image: str | None = ...,
        docker_network: str = ...,
        verifier_pack: str | None = ...,
        expect_verifier_pack_sha256: str | None = ...,
        diff_coverage: bool = ...,
        min_diff_coverage: float | None = ...,
        blackbox: bool = ...,
        blackbox_only: bool = ...,
        require_report_integrity: str | None = ...,
        require_candidate_isolation: str | None = ...,
        base_sha: str | None = ...,
        head_sha: str | None = ...,
        base_tree_sha: str | None = ...,
        head_tree_sha: str | None = ...,
        policy_id: str | None = ...,
        policy_version: str | None = ...,
        baseline_evidence: bool = ...,
        require_demonstrated_fix: bool = ...,
        strict_harness: bool = ...,
        operating_profile: str | None = ...,
        harness_inputs: tuple[str, ...] = ...,
        require_suite_continuity: bool = ...,
        require_assert_liveness: bool = ...,
        require_structured_verdict: bool = ...,
    ) -> tuple[_ResultCo, list[str]]: ...


class _InputErrorResult(Protocol[_ResultCo]):
    def __call__(
        self,
        reason: str,
        *,
        reason_code: str,
        source: str,
        base_reconstruction: str | None = ...,
        verifier_pack: str | None = ...,
        effective_policy: dict[str, Any] | None = ...,
        test_command: list[str] | None = ...,
        base_sha: str | None = ...,
        head_sha: str | None = ...,
        base_tree_sha: str | None = ...,
        head_tree_sha: str | None = ...,
        policy_id: str | None = ...,
        policy_version: str | None = ...,
    ) -> _ResultCo: ...


class _EffectivePolicy(Protocol):
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
        operating_profile: str | None = ...,
        harness_inputs: tuple[str, ...] = ...,
    ) -> dict[str, Any]: ...


class _RenderReport(Protocol[_ResultContra]):
    def __call__(
        self,
        result: _ResultContra,
        *,
        deleted: list[str] | None = ...,
        title: str = ...,
    ) -> str: ...


class _WriteJson(Protocol[_ResultContra]):
    def __call__(
        self,
        result: _ResultContra,
        path: str,
        *,
        deleted: list[str] | None = ...,
    ) -> None: ...


class _WriteSarif(Protocol[_ResultContra]):
    def __call__(self, result: _ResultContra, path: str) -> None: ...


class _OperatingProfileViolations(Protocol):
    def __call__(
        self,
        operating_profile: str | None,
        *,
        isolation: str,
        docker_image_present: bool,
        docker_network: str,
        setup_command_present: bool,
        trust_setup_on_host: bool,
        mem_limit_mb: int,
        verifier_pack_required: bool,
        expect_verifier_pack_sha256: str | None,
        blackbox: bool,
        blackbox_only: bool,
        require_report_integrity: str | None,
        require_candidate_isolation: str | None,
    ) -> tuple[str, ...]: ...


class ChangeInputError(ValueError):
    """A candidate change could not be read within the CLI trust boundary."""

    @classmethod
    def read(
        cls,
        reader: Callable[[str], str],
        path: str,
        *,
        kind: str,
    ) -> str:
        try:
            return reader(path)
        except (OSError, TypeError, UnicodeError, ValueError) as exc:
            raise cls(f"change input error (fail-closed): {kind}: {exc}") from exc


class _OperatingProfileOptions(TypedDict, total=False):
    operating_profile: str


class _HarnessInputOptions(TypedDict, total=False):
    harness_inputs: tuple[str, ...]


class _InputErrorProfileOptions(TypedDict, total=False):
    effective_policy: dict[str, Any]
    test_command: list[str] | None
    base_sha: str | None
    head_sha: str | None
    base_tree_sha: str | None
    head_tree_sha: str | None
    policy_id: str | None
    policy_version: str | None


@dataclass(frozen=True, slots=True)
class GuardCommandServices(Generic[_ResultT]):
    """Injected compatibility seams for one ``guard`` command invocation."""

    config_path_for_guard: Callable[[argparse.Namespace], str | None]
    load_config: _LoadConfig
    config_error_type: Callable[[], type[Exception]]
    read_text: Callable[[str], str]
    path_is_absolute: Callable[[str], bool]
    absolute_path: Callable[[str], str]
    directory_name: Callable[[str], str]
    join_path: _JoinPath
    current_directory: Callable[[], str]
    path_is_file: Callable[[str], bool]
    is_hex_sha256: Callable[[str], bool]
    is_finite: Callable[[float], bool]
    no_verifiable_changes_reason: str
    invalid_verifier_pack_reason: str
    unverifiable_changed_paths_error: type[Exception]
    blocks_from_dirs: Callable[[str, str], tuple[dict[str, str], list[str]]]
    guard: _GuardCall[_ResultT]
    guard_from_diff: _GuardFromDiffCall[_ResultT]
    input_error_result: _InputErrorResult[_ResultT]
    render_report: _RenderReport[_ResultT]
    serialize_candidate_blocks: Callable[[Mapping[str, str]], str]
    verifier_pack_trust_error: Callable[[str, str | None, str | None], str | None]
    write_json: _WriteJson[_ResultT]
    write_sarif: _WriteSarif[_ResultT]
    write_report: Callable[[str, str], None]
    sign_file_provider: Callable[[], Callable[[str, str], str]]
    operating_profile_violations: _OperatingProfileViolations
    effective_policy: _EffectivePolicy


def execute_guard_command(
    args: argparse.Namespace,
    *,
    services: GuardCommandServices[_ResultT],
    out: Callable[[str], None] = print,
) -> int:
    """Execute the already-parsed ``guard`` command through typed services."""

    sign_key = getattr(args, "sign_key", None)
    if sign_key and not args.json_out:
        out("--sign-key needs --json: the signature covers the JSON verdict file")
        return 2
    if sign_key and not getattr(args, "acknowledge_local_key_exposure", False):
        out(
            "refusing direct --sign-key: guard executes candidate-controlled code "
            "before signing under the same OS identity. Use Trusted Finalizer for "
            "untrusted candidates, or pass --acknowledge-local-key-exposure only "
            "for trusted local inputs."
        )
        return 2

    # Effective settings: an explicit CLI flag wins; else a policy loaded from
    # the trusted baseline; else the built-in default. In --diff mode a trusted
    # policy or an explicit --no-config choice is required. A present but broken
    # trusted policy is fail-closed: exit 2, never weaker defaults.
    try:
        config_path = services.config_path_for_guard(args)
        cfg = (
            services.load_config(
                config_path,
                required=args.config is not None,
                out=out,
            )
            if config_path
            else {}
        )
    except Exception as exc:
        if not isinstance(exc, services.config_error_type()):
            raise
        out(f"config error (fail-closed): {exc}")
        return 2

    cfg_operating_profile = cfg.get("operating_profile")
    operating_profile: str | None = (
        args.operating_profile
        if getattr(args, "operating_profile", None) is not None
        else (
            cfg_operating_profile
            if isinstance(cfg_operating_profile, str)
            else None
        )
    )
    if sign_key and operating_profile in {"protected", "hostile"}:
        out(
            f"refusing direct --sign-key under operating profile "
            f"{operating_profile!r}: candidate execution and key custody must be "
            "separated; use Trusted Finalizer"
        )
        return 2

    def _policy_bool(key: str, cli_value: bool | None) -> bool:
        """Resolve a tri-state CLI flag against the already trusted policy."""

        if cli_value is not None:
            return cli_value
        value = cfg.get(key)
        return value if isinstance(value, bool) else False

    # These must be resolved *before* validation. In pull_request mode the
    # Action deliberately supplies no candidate workflow flags, so the verified
    # base policy is the only source for these judge-shaping settings.
    blackbox = _policy_bool("blackbox", args.blackbox)
    blackbox_only = _policy_bool("blackbox_only", args.blackbox_only)
    diff_coverage_requested = _policy_bool("diff_coverage", args.diff_coverage)
    baseline_evidence = _policy_bool("baseline_evidence", args.baseline_evidence)
    require_demonstrated_fix = _policy_bool(
        "require_demonstrated_fix", args.require_demonstrated_fix
    )
    strict_harness = _policy_bool("strict_harness", args.strict_harness)
    # Trusted-local only: not a policy field. Like --sign-key, it is never
    # supplied by the Action's candidate-controlled PR path, so it is read
    # straight from the flag rather than through the verified base policy.
    require_suite_continuity = bool(
        getattr(args, "require_suite_continuity", False)
    )
    require_assert_liveness = bool(
        getattr(args, "require_assert_liveness", False)
    )
    require_structured_verdict = bool(
        getattr(args, "require_structured_verdict", False)
    )

    if blackbox_only and not blackbox:
        out("usage: --blackbox-only requires --blackbox")
        return 2

    cfg_tc = (
        args.test_command
        if args.test_command is not None
        else cfg.get("test_command")
    )
    if isinstance(cfg_tc, str):
        # A string test_command containing shell operators must be wrapped in
        # sh -c rather than naively split.
        shell_ops = ("&&", "||", ";", "|", ">", "<", "$(", "`")
        if any(op in cfg_tc for op in shell_ops):
            test_command: list[str] | None = ["sh", "-c", cfg_tc]
        else:
            test_command = cfg_tc.split()
    elif isinstance(cfg_tc, list):
        test_command = [str(token) for token in cfg_tc]
    else:
        test_command = None

    cfg_sc = cfg.get("setup_command")
    setup_command: list[str] | None = (
        [str(token) for token in cfg_sc] if isinstance(cfg_sc, list) else None
    )
    cfg_tsoh = cfg.get("trust_setup_on_host")
    trust_setup_on_host = (
        args.trust_setup_on_host
        if args.trust_setup_on_host is not None
        else (cfg_tsoh if isinstance(cfg_tsoh, bool) else False)
    )
    cfg_sog = cfg.get("setup_output_globs")
    setup_output_globs = (
        tuple(str(glob) for glob in cfg_sog) if isinstance(cfg_sog, list) else ()
    )

    # Relative policy pack paths are relative to the trusted policy file, never
    # the candidate cwd.
    cfg_pack = cfg.get("verifier_pack")
    verifier_pack = args.verifier_pack
    if verifier_pack is None and isinstance(cfg_pack, str):
        if config_path is None:
            raise AssertionError("configured verifier pack without a policy path")
        verifier_pack = (
            cfg_pack
            if services.path_is_absolute(cfg_pack)
            else services.absolute_path(
                services.join_path(
                    services.directory_name(services.absolute_path(config_path)),
                    cfg_pack,
                )
            )
        )
    cfg_pack_sha = cfg.get("expect_verifier_pack_sha256")
    expect_verifier_pack_sha256 = (
        args.expect_verifier_pack_sha256
        if args.expect_verifier_pack_sha256 is not None
        else (cfg_pack_sha if isinstance(cfg_pack_sha, str) else None)
    )
    if expect_verifier_pack_sha256 is not None:
        if not services.is_hex_sha256(expect_verifier_pack_sha256):
            out(
                "usage: --expect-verifier-pack-sha256 must be exactly "
                "64 hex characters"
            )
            return 2
        if not verifier_pack:
            out("usage: --expect-verifier-pack-sha256 requires --verifier-pack")
            return 2
        expect_verifier_pack_sha256 = expect_verifier_pack_sha256.lower()

    if args.protected is not None:
        protected: tuple[str, ...] = tuple(args.protected)
    else:
        cfg_prot = cfg.get("protected")
        protected = (
            tuple(str(glob) for glob in cfg_prot)
            if isinstance(cfg_prot, list)
            else ()
        )

    if args.allow is not None:
        allow: tuple[str, ...] = tuple(args.allow)
    else:
        cfg_allow = cfg.get("allow")
        allow = (
            tuple(str(glob) for glob in cfg_allow)
            if isinstance(cfg_allow, list)
            else ()
        )

    cfg_harness_inputs = cfg.get("harness_inputs")
    harness_inputs = (
        tuple(str(path) for path in cfg_harness_inputs)
        if isinstance(cfg_harness_inputs, list)
        else ()
    )

    cfg_to = cfg.get("timeout")
    timeout = (
        args.timeout
        if args.timeout is not None
        else (cfg_to if isinstance(cfg_to, int) else 120)
    )
    cfg_ml = cfg.get("mem_limit")
    mem_limit_is_explicit = args.mem_limit is not None or type(cfg_ml) is int
    mem_limit = (
        args.mem_limit
        if args.mem_limit is not None
        else (cfg_ml if isinstance(cfg_ml, int) else 1024)
    )
    if timeout < 1:
        out("usage: --timeout must be a positive integer")
        return 2
    if mem_limit < 0:
        out("usage: --mem-limit must be a non-negative integer")
        return 2

    cfg_ant = cfg.get("allow_new_tests")
    allow_new_tests = (
        args.allow_new_tests
        if args.allow_new_tests is not None
        else (cfg_ant if isinstance(cfg_ant, bool) else False)
    )

    cfg_rri = cfg.get("require_report_integrity")
    require_report_integrity: str | None = (
        args.require_report_integrity
        if args.require_report_integrity is not None
        else (cfg_rri if isinstance(cfg_rri, str) else None)
    )
    cfg_rci = cfg.get("require_candidate_isolation")
    require_candidate_isolation: str | None = (
        args.require_candidate_isolation
        if args.require_candidate_isolation is not None
        else (cfg_rci if isinstance(cfg_rci, str) else None)
    )
    cfg_mdc = cfg.get("min_diff_coverage")
    min_diff_coverage: float | None = (
        args.min_diff_coverage
        if args.min_diff_coverage is not None
        else (cfg_mdc if isinstance(cfg_mdc, float) else None)
    )
    if min_diff_coverage is not None and (
        not services.is_finite(min_diff_coverage)
        or not 0 <= min_diff_coverage <= 100
    ):
        out(
            "usage: --min-diff-coverage must be a finite number "
            "between 0 and 100"
        )
        return 2
    cfg_pid = cfg.get("policy_id")
    policy_id: str | None = cfg_pid if isinstance(cfg_pid, str) else None
    cfg_pv = cfg.get("policy_version")
    policy_version: str | None = cfg_pv if isinstance(cfg_pv, str) else None
    diff_coverage = diff_coverage_requested or min_diff_coverage is not None

    # V8 reserves a large virtual address range. Keep the historical Node
    # auto-detection only for the implicit legacy default. An explicit 1024 MiB
    # policy is still a policy, and hostile mode must never weaken its required
    # non-zero memory ceiling merely because the repository contains Node.
    if (
        mem_limit == 1024
        and not mem_limit_is_explicit
        and operating_profile != "hostile"
    ):
        node_root = args.repo or args.head or args.base or services.current_directory()
        if services.path_is_file(services.join_path(node_root, "package.json")):
            mem_limit = 0

    cfg_isolation = cfg.get("isolation")
    isolation = (
        args.isolation
        if args.isolation is not None
        else (cfg_isolation if isinstance(cfg_isolation, str) else "subprocess")
    )
    cfg_docker_image = cfg.get("docker_image")
    docker_image = (
        args.docker_image
        if args.docker_image is not None
        else (cfg_docker_image if isinstance(cfg_docker_image, str) else None)
    )
    cfg_docker_network = cfg.get("docker_network")
    docker_network = (
        args.docker_network
        if args.docker_network is not None
        else (
            cfg_docker_network
            if isinstance(cfg_docker_network, str)
            else "none"
        )
    )
    profile_violations = services.operating_profile_violations(
        operating_profile,
        isolation=isolation,
        docker_image_present=bool(docker_image),
        docker_network=docker_network,
        setup_command_present=bool(setup_command),
        trust_setup_on_host=trust_setup_on_host,
        mem_limit_mb=mem_limit,
        verifier_pack_required=bool(verifier_pack),
        expect_verifier_pack_sha256=expect_verifier_pack_sha256,
        blackbox=blackbox,
        blackbox_only=blackbox_only,
        require_report_integrity=require_report_integrity,
        require_candidate_isolation=require_candidate_isolation,
    )
    if profile_violations:
        out(
            f"usage: operating profile {operating_profile!r} is not satisfied: "
            + "; ".join(profile_violations)
        )
        return 2
    if isolation in ("docker", "gvisor") and not docker_image:
        out(
            f"usage: --isolation {isolation} requires --docker-image <image> "
            "(an image carrying the repo's test runner, e.g. node:22-slim)"
        )
        return 2

    # Preserve the historical injected-call surface when no profile is chosen.
    # Compatibility consumers may provide a guard callable that predates the
    # optional keyword, so an absent profile must not become ``profile=None``.
    profile_options: _OperatingProfileOptions = (
        {"operating_profile": operating_profile}
        if operating_profile is not None
        else {}
    )
    harness_input_options: _HarnessInputOptions = (
        {"harness_inputs": harness_inputs}
        if harness_inputs
        else {}
    )

    def _input_error_profile_options() -> _InputErrorProfileOptions:
        """Bind profiled early errors to the same complete policy as a run."""
        if operating_profile is None and not harness_inputs:
            return {}
        return {
            "effective_policy": services.effective_policy(
                mode="blackbox" if blackbox else "repo",
                isolation=isolation,
                docker_image=docker_image,
                docker_network=docker_network,
                test_command=test_command,
                setup_command=setup_command,
                trust_setup_on_host=trust_setup_on_host,
                setup_output_globs=setup_output_globs,
                protected=protected,
                allow=allow,
                allow_new_tests=allow_new_tests,
                timeout=timeout,
                mem_limit_mb=mem_limit,
                verifier_pack=verifier_pack,
                expect_verifier_pack_sha256=expect_verifier_pack_sha256,
                blackbox=blackbox,
                blackbox_only=blackbox_only,
                require_report_integrity=require_report_integrity,
                require_candidate_isolation=require_candidate_isolation,
                min_diff_coverage=min_diff_coverage,
                baseline_evidence=baseline_evidence,
                require_demonstrated_fix=require_demonstrated_fix,
                strict_harness=strict_harness,
                policy_id=policy_id,
                policy_version=policy_version,
                operating_profile=operating_profile,
                **harness_input_options,
            ),
            "test_command": test_command,
            "base_sha": args.base_sha,
            "head_sha": args.head_sha,
            "base_tree_sha": args.base_tree_sha,
            "head_tree_sha": args.head_tree_sha,
            "policy_id": policy_id,
            "policy_version": policy_version,
        }

    deleted: list[str] = []

    if args.diff is not None:
        head = args.repo or services.current_directory()
        result, deleted = services.guard_from_diff(
            head,
            ChangeInputError.read(services.read_text, args.diff, kind="unified diff"),
            test_command=test_command,
            setup_command=setup_command,
            trust_setup_on_host=trust_setup_on_host,
            setup_output_globs=setup_output_globs,
            protected=protected,
            allow=allow,
            allow_new_tests=allow_new_tests,
            timeout=timeout,
            mem_limit_mb=mem_limit,
            isolation=isolation,
            docker_image=docker_image,
            docker_network=docker_network,
            verifier_pack=verifier_pack,
            expect_verifier_pack_sha256=expect_verifier_pack_sha256,
            diff_coverage=diff_coverage,
            min_diff_coverage=min_diff_coverage,
            blackbox=blackbox,
            blackbox_only=blackbox_only,
            require_report_integrity=require_report_integrity,
            require_candidate_isolation=require_candidate_isolation,
            base_sha=args.base_sha,
            head_sha=args.head_sha,
            base_tree_sha=args.base_tree_sha,
            head_tree_sha=args.head_tree_sha,
            policy_id=policy_id,
            policy_version=policy_version,
            baseline_evidence=baseline_evidence,
            require_demonstrated_fix=require_demonstrated_fix,
            strict_harness=strict_harness,
            require_suite_continuity=require_suite_continuity,
            require_assert_liveness=require_assert_liveness,
            require_structured_verdict=require_structured_verdict,
            **profile_options,
            **harness_input_options,
        )
    elif args.base and args.head:
        pack_trust_problem = services.verifier_pack_trust_error(
            args.head, verifier_pack, expect_verifier_pack_sha256
        )
        if pack_trust_problem:
            result = services.input_error_result(
                pack_trust_problem,
                reason_code=services.invalid_verifier_pack_reason,
                source="base/head",
                verifier_pack=verifier_pack,
                **_input_error_profile_options(),
            )
        else:
            try:
                file_blocks, deleted = services.blocks_from_dirs(
                    args.base, args.head
                )
            except services.unverifiable_changed_paths_error as exc:
                result = services.input_error_result(
                    "the base/head input includes changed path(s) Guard cannot "
                    f"safely verify: {exc}",
                    reason_code=services.no_verifiable_changes_reason,
                    source="base/head",
                    verifier_pack=verifier_pack,
                    **_input_error_profile_options(),
                )
            else:
                candidate = services.serialize_candidate_blocks(file_blocks)
                result = services.guard(
                    args.base,
                    candidate,
                    deleted=tuple(deleted),
                    file_blocks=file_blocks,
                    test_command=test_command,
                    setup_command=setup_command,
                    trust_setup_on_host=trust_setup_on_host,
                    setup_output_globs=setup_output_globs,
                    protected=protected,
                    allow=allow,
                    allow_new_tests=allow_new_tests,
                    timeout=timeout,
                    mem_limit_mb=mem_limit,
                    isolation=isolation,
                    docker_image=docker_image,
                    docker_network=docker_network,
                    verifier_pack=verifier_pack,
                    expect_verifier_pack_sha256=expect_verifier_pack_sha256,
                    diff_coverage=diff_coverage,
                    min_diff_coverage=min_diff_coverage,
                    blackbox=blackbox,
                    blackbox_only=blackbox_only,
                    require_report_integrity=require_report_integrity,
                    require_candidate_isolation=require_candidate_isolation,
                    base_sha=args.base_sha,
                    head_sha=args.head_sha,
                    base_tree_sha=args.base_tree_sha,
                    head_tree_sha=args.head_tree_sha,
                    policy_id=policy_id,
                    policy_version=policy_version,
                    baseline_evidence=baseline_evidence,
                    require_demonstrated_fix=require_demonstrated_fix,
                    strict_harness=strict_harness,
                    require_suite_continuity=require_suite_continuity,
                    require_assert_liveness=require_assert_liveness,
                    require_structured_verdict=require_structured_verdict,
                    **profile_options,
                    **harness_input_options,
                )
                result.source = "base/head"
    elif args.repo and args.patch:
        result = services.guard(
            args.repo,
            ChangeInputError.read(
                services.read_text,
                args.patch,
                kind="edit-block patch",
            ),
            test_command=test_command,
            setup_command=setup_command,
            trust_setup_on_host=trust_setup_on_host,
            setup_output_globs=setup_output_globs,
            protected=protected,
            allow=allow,
            allow_new_tests=allow_new_tests,
            timeout=timeout,
            mem_limit_mb=mem_limit,
            isolation=isolation,
            docker_image=docker_image,
            docker_network=docker_network,
            verifier_pack=verifier_pack,
            expect_verifier_pack_sha256=expect_verifier_pack_sha256,
            diff_coverage=diff_coverage,
            min_diff_coverage=min_diff_coverage,
            blackbox=blackbox,
            blackbox_only=blackbox_only,
            require_report_integrity=require_report_integrity,
            require_candidate_isolation=require_candidate_isolation,
            base_sha=args.base_sha,
            head_sha=args.head_sha,
            base_tree_sha=args.base_tree_sha,
            head_tree_sha=args.head_tree_sha,
            policy_id=policy_id,
            policy_version=policy_version,
            baseline_evidence=baseline_evidence,
            require_demonstrated_fix=require_demonstrated_fix,
            strict_harness=strict_harness,
            require_suite_continuity=require_suite_continuity,
            require_assert_liveness=require_assert_liveness,
            require_structured_verdict=require_structured_verdict,
            **profile_options,
            **harness_input_options,
        )
        result.source = "edit blocks"
    else:
        out(
            "usage: evo-guard guard <repo> --patch <file|->   |   "
            "evo-guard guard --base <dir> --head <dir>   |   "
            "evo-guard guard [<repo>] --diff <file|->"
        )
        return 2

    report = services.render_report(result, deleted=deleted)
    if args.report:
        services.write_report(args.report, report)
        out(f"wrote {args.report}")
    else:
        out(report)
    if args.json_out:
        services.write_json(result, args.json_out, deleted=deleted)
    if sign_key:
        sign_file = services.sign_file_provider()
        signature = sign_file(args.json_out, sign_key)
        out(f"signed {args.json_out} -> {signature}")
    if args.sarif:
        services.write_sarif(result, args.sarif)
    return result.exit_code


__all__ = ["GuardCommandServices", "execute_guard_command"]
