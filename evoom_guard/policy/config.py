# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Fail-closed parser for the trusted repository policy file.

This module deliberately sits below CLI and finalizer adapters. Both consumers
must validate ``.evoguard.json`` through one public implementation without a
lower-level trust component importing the command-line surface.
"""

from __future__ import annotations

import os
from collections.abc import Callable

from evoom_guard.domain import (
    OPERATING_PROFILES,
    is_verifier_pack_sha256,
    operating_profile_violations,
)
from evoom_guard.policy.harness import (
    normalize_harness_inputs,
    setup_output_harness_conflicts,
)
from evoom_guard.strict_json import strict_json_loads


class ConfigError(ValueError):
    """A missing required or present-but-invalid trusted policy file."""


_CONFIG_KEYS = frozenset(
    {
        "test_command",
        "setup_command",
        "protected",
        "allow",
        "timeout",
        "mem_limit",
        "allow_new_tests",
        "trust_setup_on_host",
        "setup_output_globs",
        "strict_harness",
        "harness_inputs",
        "operating_profile",
        "isolation",
        "docker_image",
        "docker_network",
        "blackbox",
        "blackbox_only",
        "diff_coverage",
        "baseline_evidence",
        "require_demonstrated_fix",
        "verifier_pack",
        "expect_verifier_pack_sha256",
        "require_report_integrity",
        "require_candidate_isolation",
        "min_diff_coverage",
        "policy_id",
        "policy_version",
    }
)
_REPORT_INTEGRITY_VALUES = (
    "same_process_candidate_writable",
    "external_process_isolated",
)
_ISOLATION_VALUES = ("subprocess", "docker", "gvisor")


def _validated_path_policy(
    data: dict[str, object],
    *,
    invalid: Callable[[str, str], ConfigError],
) -> dict[str, object]:
    """Validate and normalize the trusted path/harness policy as one phase."""

    cfg: dict[str, object] = {}
    for key in ("protected", "allow", "setup_output_globs", "harness_inputs"):
        if key in data:
            value = data[key]
            if not isinstance(value, list) or not all(
                isinstance(pattern, str) for pattern in value
            ):
                expected = (
                    "expected a list of exact repository-relative file paths"
                    if key == "harness_inputs"
                    else "expected a list of glob strings"
                )
                raise invalid(key, expected)
            if key == "harness_inputs":
                try:
                    cfg[key] = list(normalize_harness_inputs(value))
                except ValueError as exc:
                    raise invalid(key, str(exc)) from exc
            else:
                cfg[key] = value
    harness_values = cfg.get("harness_inputs")
    setup_glob_values = cfg.get("setup_output_globs")
    if isinstance(harness_values, list) and isinstance(setup_glob_values, list):
        conflicts = setup_output_harness_conflicts(
            harness_values,
            setup_glob_values,
        )
        if conflicts:
            raise invalid(
                "setup_output_globs",
                "cannot exclude harness_inputs: " + ", ".join(conflicts),
            )
    return cfg


def load_config(
    path: str,
    *,
    required: bool = False,
    out: Callable[[str], None] = print,
) -> dict[str, object]:
    """Load and validate one trusted ``.evoguard.json`` fail-closed.

    ``out`` remains part of the compatibility contract even though strict
    validation currently emits no warnings. A missing optional path yields an
    empty mapping. Missing required input, unreadable/duplicate-key JSON,
    unknown keys, and invalid values raise :class:`ConfigError`.
    """

    if not path or not os.path.exists(path):
        if required:
            raise ConfigError(f"trusted policy file does not exist: {path}")
        return {}
    try:
        with open(path, encoding="utf-8") as stream:
            data = strict_json_loads(stream.read())
    except (OSError, ValueError) as exc:
        raise ConfigError(f"{path} is not readable JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected a JSON object, got {type(data).__name__}")
    unknown = sorted(set(data) - _CONFIG_KEYS)
    if unknown:
        raise ConfigError(
            f"{path}: unknown key(s) {', '.join(unknown)} — a misspelled policy "
            "key must not be silently ignored; the accepted keys are: "
            + ", ".join(sorted(_CONFIG_KEYS))
        )

    def invalid(key: str, reason: str) -> ConfigError:
        return ConfigError(f"{path}: invalid {key!r} — {reason}")

    cfg: dict[str, object] = {}
    if "test_command" in data:
        command = data["test_command"]
        if not isinstance(command, (str, list)) or (
            isinstance(command, list)
            and not all(isinstance(token, str) for token in command)
        ):
            raise invalid("test_command", "expected a string or a list of strings")
        cfg["test_command"] = command
    if "setup_command" in data:
        command = data["setup_command"]
        if not isinstance(command, list) or not all(
            isinstance(token, str) for token in command
        ):
            raise invalid(
                "setup_command",
                "expected a list of strings (never a shell string — splitting on "
                "spaces is unsafe for paths)",
            )
        cfg["setup_command"] = command
    cfg.update(_validated_path_policy(data, invalid=invalid))
    for key in ("timeout", "mem_limit"):
        if key in data:
            value = data[key]
            if not isinstance(value, int) or isinstance(value, bool):
                raise invalid(key, "expected an integer")
            if key == "timeout" and value < 1:
                raise invalid(key, "expected a positive integer")
            if key == "mem_limit" and value < 0:
                raise invalid(key, "expected a non-negative integer")
            cfg[key] = value
    for key in (
        "allow_new_tests",
        "trust_setup_on_host",
        "strict_harness",
        "blackbox",
        "blackbox_only",
        "diff_coverage",
        "baseline_evidence",
        "require_demonstrated_fix",
    ):
        if key in data:
            value = data[key]
            if not isinstance(value, bool):
                raise invalid(key, "expected true or false")
            cfg[key] = value
    if data.get("blackbox_only") is True and data.get("blackbox") is not True:
        raise invalid("blackbox_only", "requires blackbox: true")
    if "isolation" in data:
        value = data["isolation"]
        if value not in _ISOLATION_VALUES:
            raise invalid("isolation", f"expected one of {list(_ISOLATION_VALUES)}")
        cfg["isolation"] = value
    if "operating_profile" in data:
        value = data["operating_profile"]
        if value not in OPERATING_PROFILES:
            raise invalid(
                "operating_profile",
                f"expected one of {list(OPERATING_PROFILES)}",
            )
        cfg["operating_profile"] = value
    for key in ("docker_image", "docker_network"):
        if key in data:
            value = data[key]
            if not isinstance(value, str) or not value.strip() or "\x00" in value:
                raise invalid(key, "expected a non-empty string without NUL")
            cfg[key] = value
    if "verifier_pack" in data:
        value = data["verifier_pack"]
        if not isinstance(value, str) or not value.strip():
            raise invalid("verifier_pack", "expected a non-empty path string")
        cfg["verifier_pack"] = value
    if "expect_verifier_pack_sha256" in data:
        value = data["expect_verifier_pack_sha256"]
        if not is_verifier_pack_sha256(value):
            raise invalid(
                "expect_verifier_pack_sha256",
                "expected exactly 64 hexadecimal SHA-256 characters",
            )
        cfg["expect_verifier_pack_sha256"] = value.lower()
    if "require_report_integrity" in data:
        value = data["require_report_integrity"]
        if value not in _REPORT_INTEGRITY_VALUES:
            raise invalid(
                "require_report_integrity",
                f"expected one of {list(_REPORT_INTEGRITY_VALUES)}",
            )
        cfg["require_report_integrity"] = value
    if "require_candidate_isolation" in data:
        value = data["require_candidate_isolation"]
        if value not in _ISOLATION_VALUES:
            raise invalid(
                "require_candidate_isolation",
                f"expected one of {list(_ISOLATION_VALUES)}",
            )
        cfg["require_candidate_isolation"] = value
    if "min_diff_coverage" in data:
        value = data["min_diff_coverage"]
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not 0 <= value <= 100
        ):
            raise invalid("min_diff_coverage", "expected a number between 0 and 100")
        cfg["min_diff_coverage"] = float(value)
    for key in ("policy_id", "policy_version"):
        if key in data:
            value = data[key]
            if not isinstance(value, str) or not value.strip():
                raise invalid(key, "expected a non-empty string")
            cfg[key] = value

    operating_profile = cfg.get("operating_profile")
    if isinstance(operating_profile, str):
        isolation = cfg.get("isolation")
        mem_limit = cfg.get("mem_limit")
        docker_network_value = cfg.get("docker_network")
        docker_network = (
            docker_network_value
            if isinstance(docker_network_value, str)
            else "none"
        )
        expected_pack_value = cfg.get("expect_verifier_pack_sha256")
        expected_pack = (
            expected_pack_value
            if isinstance(expected_pack_value, str)
            else None
        )
        report_integrity_value = cfg.get("require_report_integrity")
        report_integrity = (
            report_integrity_value
            if isinstance(report_integrity_value, str)
            else None
        )
        candidate_isolation_value = cfg.get("require_candidate_isolation")
        candidate_isolation = (
            candidate_isolation_value
            if isinstance(candidate_isolation_value, str)
            else None
        )
        violations = operating_profile_violations(
            operating_profile,
            isolation=isolation if isinstance(isolation, str) else "subprocess",
            docker_image_present=isinstance(cfg.get("docker_image"), str),
            docker_network=docker_network,
            setup_command_present=cfg.get("setup_command") is not None,
            trust_setup_on_host=cfg.get("trust_setup_on_host") is True,
            mem_limit_mb=mem_limit if type(mem_limit) is int else 1024,
            verifier_pack_required=isinstance(cfg.get("verifier_pack"), str),
            expect_verifier_pack_sha256=expected_pack,
            blackbox=cfg.get("blackbox") is True,
            blackbox_only=cfg.get("blackbox_only") is True,
            require_report_integrity=report_integrity,
            require_candidate_isolation=candidate_isolation,
        )
        if violations:
            raise invalid(
                "operating_profile",
                f"{operating_profile!r} " + "; ".join(violations),
            )
    return cfg
