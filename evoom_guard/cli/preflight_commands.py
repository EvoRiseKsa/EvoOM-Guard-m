# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ------------------------------------------------------------------------------
"""CLI owner for repository-aware, non-executing Guard preflight."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from evoom_guard.policy.preflight import PreflightCheck, PreflightReport
from evoom_guard.runners.registry import instrument_command as _instrument_command


@dataclass(frozen=True, slots=True)
class PreflightServices:
    """Injected effects and analyzer contracts used by ``preflight``."""

    load_config: Callable[..., dict[str, object]]
    config_error_type: Callable[[], type[Exception]]
    normalize_command: Callable[..., tuple[str, ...]]
    analyze: Callable[..., PreflightReport]
    validate_pack: Callable[[str], dict[str, object]]
    is_pack_sha256: Callable[[object], bool]
    locate_executable: Callable[[str, str], str | None]
    operating_profile_violations: Callable[..., tuple[str, ...]]
    absolute_path: Callable[[str], str] = os.path.abspath
    join_path: Callable[..., str] = os.path.join


def _configured_bool(
    args: argparse.Namespace,
    cfg: Mapping[str, object],
    name: str,
) -> bool:
    override = getattr(args, name, None)
    if isinstance(override, bool):
        return override
    configured = cfg.get(name)
    return configured if isinstance(configured, bool) else False


def _render_text(report: PreflightReport, *, out: Callable[[str], None]) -> None:
    out(f"preflight: {report.repository}")
    out(
        "  ready: "
        + ("yes" if report.ready else "no")
        + f"  isolation={report.isolation}"
    )
    out("  test command: " + " ".join(report.test_command))
    for check in report.checks:
        out(f"  {check.status.upper():7} {check.code}: {check.message}")
        if check.remediation:
            out(f"           fix: {check.remediation}")


def execute_preflight(
    args: argparse.Namespace,
    *,
    services: PreflightServices,
    out: Callable[[str], None] = print,
) -> int:
    """Analyze trusted policy and host readiness without running candidate code."""

    repository = services.absolute_path(args.repo)
    config_path: str | None
    if args.no_config:
        config_path = None
    elif args.config:
        config_path = (
            args.config
            if os.path.isabs(args.config)
            else services.join_path(repository, args.config)
        )
        config_path = services.absolute_path(config_path)
    else:
        config_path = services.join_path(repository, ".evoguard.json")

    try:
        cfg = (
            services.load_config(
                config_path,
                required=args.config is not None,
                out=lambda _message: None,
            )
            if config_path is not None
            else {}
        )
    except Exception as exc:
        if not isinstance(exc, services.config_error_type()):
            raise
        out(f"config error (fail-closed): {exc}")
        return 2

    configured_isolation = cfg.get("isolation")
    isolation = (
        args.isolation
        if args.isolation is not None
        else (
            configured_isolation
            if isinstance(configured_isolation, str)
            else "subprocess"
        )
    )
    raw_command: str | Sequence[str] | None = (
        args.test_command
        if args.test_command is not None
        else _command_from_config(cfg)
    )
    command = services.normalize_command(
        raw_command,
        default_python=(
            "python" if isolation in {"docker", "gvisor"} else None
        ),
    )
    configured_pack = cfg.get("verifier_pack")
    raw_pack = (
        args.verifier_pack
        if args.verifier_pack is not None
        else (configured_pack if isinstance(configured_pack, str) else None)
    )
    pack_path = _resolve_pack_path(
        raw_pack,
        repository=repository,
        config_path=config_path,
        from_config=args.verifier_pack is None,
        services=services,
    )
    configured_pack_pin = cfg.get("expect_verifier_pack_sha256")
    expected_pack_sha256 = (
        args.expect_verifier_pack_sha256
        if args.expect_verifier_pack_sha256 is not None
        else (
            configured_pack_pin
            if isinstance(configured_pack_pin, str)
            else None
        )
    )
    configured_blackbox = cfg.get("blackbox")
    blackbox = (
        args.blackbox
        if isinstance(args.blackbox, bool)
        else (
            configured_blackbox
            if isinstance(configured_blackbox, bool)
            else False
        )
    )
    configured_docker_image = cfg.get("docker_image")
    docker_image = (
        args.docker_image
        if args.docker_image is not None
        else (
            configured_docker_image
            if isinstance(configured_docker_image, str)
            else None
        )
    )
    blackbox_only = _configured_bool(args, cfg, "blackbox_only")
    configured_setup = cfg.get("setup_command")
    setup_command = (
        tuple(str(token) for token in configured_setup)
        if isinstance(configured_setup, list)
        else None
    )
    trust_setup_on_host = _configured_bool(args, cfg, "trust_setup_on_host")
    require_demonstrated_fix = _configured_bool(
        args,
        cfg,
        "require_demonstrated_fix",
    )
    strict_harness = _configured_bool(args, cfg, "strict_harness")
    configured_coverage = cfg.get("min_diff_coverage")
    min_diff_coverage = (
        configured_coverage if isinstance(configured_coverage, float) else None
    )
    configured_profile = cfg.get("operating_profile")
    operating_profile = (
        configured_profile if isinstance(configured_profile, str) else None
    )
    configured_network = cfg.get("docker_network")
    docker_network = (
        configured_network if isinstance(configured_network, str) else "none"
    )
    configured_mem_limit = cfg.get("mem_limit")
    mem_limit = (
        configured_mem_limit
        if type(configured_mem_limit) is int
        else 1024
    )
    configured_report_integrity = cfg.get("require_report_integrity")
    require_report_integrity = (
        configured_report_integrity
        if isinstance(configured_report_integrity, str)
        else None
    )
    configured_candidate_isolation = cfg.get("require_candidate_isolation")
    require_candidate_isolation = (
        configured_candidate_isolation
        if isinstance(configured_candidate_isolation, str)
        else None
    )
    profile_violations = services.operating_profile_violations(
        operating_profile,
        isolation=isolation,
        docker_image_present=bool(docker_image),
        docker_network=docker_network,
        setup_command_present=bool(setup_command),
        trust_setup_on_host=trust_setup_on_host,
        mem_limit_mb=mem_limit,
        verifier_pack_required=pack_path is not None,
        expect_verifier_pack_sha256=expected_pack_sha256,
        blackbox=blackbox,
        blackbox_only=blackbox_only,
        require_report_integrity=require_report_integrity,
        require_candidate_isolation=require_candidate_isolation,
    )
    report = services.analyze(
        repository=repository,
        command=command,
        raw_command=raw_command,
        isolation=isolation,
        blackbox=blackbox,
        docker_image=docker_image,
        verifier_pack_path=pack_path,
        expect_verifier_pack_sha256=expected_pack_sha256,
        verifier_pack_configured=pack_path is not None,
        blackbox_only=blackbox_only,
        setup_command=setup_command,
        trust_setup_on_host=trust_setup_on_host,
        require_demonstrated_fix=require_demonstrated_fix,
        min_diff_coverage=min_diff_coverage,
        strict_harness=strict_harness,
        operating_profile=operating_profile,
        profile_violations=profile_violations,
        which=lambda executable: services.locate_executable(
            executable,
            repository,
        ),
    )
    report = replace(
        report,
        checks=report.checks
        + _pack_checks(
            pack_path,
            expected_pack_sha256,
            services=services,
        )
        + _structured_verdict_checks(command, blackbox_only=blackbox_only),
    )

    if args.preflight_json:
        out(json.dumps(report.to_dict(), indent=2))
    else:
        _render_text(report, out=out)

    warnings_block = args.strict and any(
        check.status == "warning" for check in report.checks
    )
    return 0 if report.ready and not warnings_block else 1


def _command_from_config(cfg: Mapping[str, object]) -> str | Sequence[str] | None:
    command: Any = cfg.get("test_command")
    if isinstance(command, str) and command.strip():
        return command
    if (
        isinstance(command, list)
        and command
        and all(isinstance(token, str) for token in command)
    ):
        return command
    return None


def _resolve_pack_path(
    value: str | None,
    *,
    repository: str,
    config_path: str | None,
    from_config: bool,
    services: PreflightServices,
) -> str | None:
    if not value:
        return None
    if os.path.isabs(value):
        return services.absolute_path(value)
    if not from_config:
        return services.absolute_path(value)
    base = os.path.dirname(config_path) if config_path else repository
    return services.absolute_path(services.join_path(base, value))




def _structured_verdict_checks(
    command: Sequence[str],
    *,
    blackbox_only: bool,
    instrument: Callable[
        [list[str], str], tuple[list[str], bool, dict[str, str]]
    ] = _instrument_command,
) -> tuple[PreflightCheck, ...]:
    """Report whether the repo-suite verdict would be JUnit-backed.

    Probes the same live runner registry execution uses (instrumentation is a
    pure argv/env transform; nothing runs).  Skipped under ``--blackbox-only``,
    where the repository suite is not a verdict source at all, and for an empty
    command, which ``test_command.nonempty`` already reports as an error.
    """

    if blackbox_only or not command:
        return ()
    _, report_expected, _ = instrument(
        [str(token) for token in command], "judge-result.xml"
    )
    if report_expected:
        return (
            PreflightCheck(
                code="test_command.structured_verdict",
                status="pass",
                message=(
                    "a structured runner adapter instruments this command: the "
                    "repo-suite verdict is JUnit-backed and exit/report "
                    "tamper-cross-checked"
                ),
                remediation=None,
            ),
        )
    return (
        PreflightCheck(
            code="test_command.exit_code_only_verdict",
            status="warning",
            message=(
                "no structured runner adapter matches this command: the "
                "repo-suite verdict would be graded from the process exit code "
                "alone, with no judge-owned JUnit evidence and no exit/report "
                "tamper cross-check (reward-hack resistance is reduced)"
            ),
            remediation=(
                "invoke a recognized runner (pytest, node --test, vitest, jest, "
                "mocha, gotestsum, rspec, maven) directly or behind a supported "
                "launcher, or wrap your runner so it is one of those forms; "
                "verify with `evo-guard preflight` until this check passes"
            ),
        ),
    )


def _pack_checks(
    pack_path: str | None,
    expected_sha256: str | None,
    *,
    services: PreflightServices,
) -> tuple[PreflightCheck, ...]:
    checks: list[PreflightCheck] = []
    if pack_path is None:
        if expected_sha256 is not None:
            checks.append(
                PreflightCheck(
                    code="verifier_pack.pin_without_pack",
                    status="error",
                    message="a verifier-pack identity is configured without a pack",
                    remediation="configure verifier_pack or remove its identity pin",
                )
            )
        return tuple(checks)

    report = services.validate_pack(pack_path)
    pack_ok = report.get("ok") is True
    problems = report.get("problems")
    problem_text = (
        "; ".join(str(item) for item in problems)
        if isinstance(problems, list) and problems
        else "pack validation failed"
    )
    checks.append(
        PreflightCheck(
            code="verifier_pack.valid",
            status="pass" if pack_ok else "error",
            message=(
                "verifier pack is present and structurally valid"
                if pack_ok
                else f"verifier pack is unavailable or invalid: {problem_text}"
            ),
            remediation=(
                None
                if pack_ok
                else "select an existing pack that passes `evo-guard pack-doctor`"
            ),
        )
    )
    if expected_sha256 is None:
        checks.append(
            PreflightCheck(
                code="verifier_pack.identity_pin",
                status="warning",
                message="the verifier pack has no expected identity pin",
                remediation=(
                    "record pack-doctor's EVOGUARD_PACK_V2 digest as "
                    "expect_verifier_pack_sha256"
                ),
            )
        )
        return tuple(checks)
    if not services.is_pack_sha256(expected_sha256):
        checks.append(
            PreflightCheck(
                code="verifier_pack.identity_pin",
                status="error",
                message="the expected verifier-pack identity is not 64 hex characters",
                remediation="copy the exact EVOGUARD_PACK_V2 digest from pack-doctor",
            )
        )
        return tuple(checks)
    observed = report.get("pack_sha256")
    matches = isinstance(observed, str) and observed == expected_sha256.lower()
    checks.append(
        PreflightCheck(
            code="verifier_pack.identity_pin",
            status="pass" if matches else "error",
            message=(
                "verifier-pack identity matches the expected digest"
                if matches
                else "verifier-pack identity does not match the expected digest"
            ),
            remediation=(
                None
                if matches
                else "review the pack bytes and update the trusted pin separately"
            ),
        )
    )
    return tuple(checks)


__all__ = ["PreflightServices", "execute_preflight"]
