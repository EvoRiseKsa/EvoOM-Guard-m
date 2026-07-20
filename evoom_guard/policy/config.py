# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Fail-closed parser for the trusted repository policy file.

This module deliberately sits below CLI and finalizer adapters. Both consumers
must validate ``.evoguard.json`` through one public implementation without a
lower-level trust component importing the command-line surface.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable

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
    for key in ("protected", "allow", "setup_output_globs"):
        if key in data:
            value = data[key]
            if not isinstance(value, list) or not all(
                isinstance(pattern, str) for pattern in value
            ):
                raise invalid(key, "expected a list of glob strings")
            cfg[key] = value
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
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
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
    return cfg
