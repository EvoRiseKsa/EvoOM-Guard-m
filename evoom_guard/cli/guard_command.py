# ------------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
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
from typing import Any, Protocol


class _GuardResult(Protocol):
    source: str | None

    @property
    def exit_code(self) -> int: ...


class _LoadConfig(Protocol):
    def __call__(
        self,
        path: str,
        *,
        required: bool,
        out: Callable[[str], None],
    ) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class GuardCommandServices:
    """Injected compatibility seams for one ``guard`` command invocation."""

    config_path_for_guard: Callable[[argparse.Namespace], str | None]
    load_config: _LoadConfig
    config_error_type: Callable[[], type[Exception]]
    read_text: Callable[[str], str]
    path_is_absolute: Callable[[str], bool]
    absolute_path: Callable[[str], str]
    directory_name: Callable[[str], str]
    join_path: Callable[..., str]
    current_directory: Callable[[], str]
    path_is_file: Callable[[str], bool]
    is_hex_sha256: Callable[[str], bool]
    is_finite: Callable[[float], bool]
    no_verifiable_changes_reason: str
    invalid_verifier_pack_reason: str
    unverifiable_changed_paths_error: type[Exception]
    blocks_from_dirs: Callable[[str, str], tuple[dict[str, str], list[str]]]
    guard: Callable[..., _GuardResult]
    guard_from_diff: Callable[..., tuple[_GuardResult, list[str]]]
    input_error_result: Callable[..., _GuardResult]
    render_report: Callable[..., str]
    serialize_candidate_blocks: Callable[[Mapping[str, str]], str]
    verifier_pack_trust_error: Callable[[str, str | None, str | None], str | None]
    write_json: Callable[..., None]
    write_sarif: Callable[..., None]
    write_report: Callable[[str, str], None]
    sign_file_provider: Callable[[], Callable[[str, str], str]]


def execute_guard_command(
    args: argparse.Namespace,
    *,
    services: GuardCommandServices,
    out: Callable[[str], None] = print,
) -> int:
    """Execute the already-parsed ``guard`` command through typed services."""

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

    cfg_to = cfg.get("timeout")
    timeout = (
        args.timeout
        if args.timeout is not None
        else (cfg_to if isinstance(cfg_to, int) else 120)
    )
    cfg_ml = cfg.get("mem_limit")
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
    # auto-detection when the default address-space limit remains effective.
    if mem_limit == 1024:
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
    if isolation in ("docker", "gvisor") and not docker_image:
        out(
            f"usage: --isolation {isolation} requires --docker-image <image> "
            "(an image carrying the repo's test runner, e.g. node:22-slim)"
        )
        return 2

    deleted: list[str] = []

    if args.diff is not None:
        head = args.repo or services.current_directory()
        result, deleted = services.guard_from_diff(
            head,
            services.read_text(args.diff),
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
                )
                result.source = "base/head"
    elif args.repo and args.patch:
        result = services.guard(
            args.repo,
            services.read_text(args.patch),
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
    if getattr(args, "sign_key", None):
        if not args.json_out:
            out("--sign-key needs --json: the signature covers the JSON verdict file")
            return 2
        sign_file = services.sign_file_provider()
        signature = sign_file(args.json_out, args.sign_key)
        out(f"signed {args.json_out} -> {signature}")
    if args.sarif:
        services.write_sarif(result, args.sarif)
    return result.exit_code


__all__ = ["GuardCommandServices", "execute_guard_command"]
