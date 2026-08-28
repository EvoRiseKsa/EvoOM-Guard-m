# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ------------------------------------------------------------------------------
"""Typed stdlib-only owners for CLI diagnostics and verifier-pack inspection."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class DoctorServices:
    """Effects and runtime values required to build one doctor report."""

    version: Callable[[], str]
    platform_name: Callable[[], str]
    machine: Callable[[], str]
    python_version: Callable[[], str]
    which: Callable[[str], str | None]


@dataclass(frozen=True, slots=True)
class PackValidationServices:
    """Effects and contracts required to inspect one verifier pack."""

    is_directory: Callable[[str], bool]
    test_files: Callable[[str], list[str]]
    load_manifest: Callable[[str], dict[str, Any] | None]
    digest: Callable[[str], str]
    digest_format: Callable[[], str]
    manifest_error: Callable[[], type[Exception]]


def build_doctor_report(services: DoctorServices) -> dict[str, object]:
    """Return the stable environment report consumed by ``doctor``."""

    has_git = services.which("git") is not None
    has_patch = services.which("patch") is not None
    return {
        "tool": "evoguard",
        "version": services.version(),
        "platform": f"{services.platform_name()}-{services.machine()}",
        "python": services.python_version(),
        "git": has_git,
        "patch": has_patch,
        "supported": has_git or has_patch,
    }


def execute_doctor(
    args: argparse.Namespace,
    *,
    report_provider: Callable[[], dict[str, object]],
    json_dumps: Callable[..., str],
    out: Callable[[str], None] = print,
) -> int:
    """Render one already-parsed ``doctor`` command."""

    info = report_provider()
    if getattr(args, "doctor_json", False):
        out(json_dumps(info, indent=2))
    else:
        out(f"evoguard {info['version']}  ({info['platform']}, python {info['python']})")
        out(f"  git:   {'found' if info['git'] else 'MISSING'}")
        out(f"  patch: {'found' if info['patch'] else 'MISSING'}")
        out(f"  supported: {'yes' if info['supported'] else 'no — need git or patch'}")
    return 0 if info["supported"] else 1


def validate_pack(
    pack_dir: str,
    *,
    services: PackValidationServices,
) -> dict[str, object]:
    """Validate one verifier-pack directory into the stable report shape."""

    report: dict[str, object] = {"pack": pack_dir, "ok": False, "problems": []}
    problems: list[str] = report["problems"]  # type: ignore[assignment]
    if not services.is_directory(pack_dir):
        problems.append("not a directory")
        return report
    try:
        test_files = services.test_files(pack_dir)
        report["test_files"] = sorted(test_files)
        if not test_files:
            problems.append(
                "no pytest test files (test_*.py) — the judge would have nothing to run"
            )
        report["manifest"] = services.load_manifest(pack_dir)
        report["pack_sha256"] = services.digest(pack_dir)
        report["pack_digest_format"] = services.digest_format()
    except services.manifest_error() as exc:
        problems.append(str(exc))
        report["test_files"] = []
        report["manifest"] = None
        report["pack_sha256"] = ""
        report["pack_digest_format"] = services.digest_format()
    report["ok"] = not problems
    return report


def execute_pack_doctor(
    args: argparse.Namespace,
    *,
    report_provider: Callable[[str], dict[str, object]],
    json_dumps: Callable[..., str],
    out: Callable[[str], None] = print,
) -> int:
    """Render one already-parsed ``pack-doctor`` command."""

    report = report_provider(args.pack)
    problems = report.get("problems")
    problems_list = problems if isinstance(problems, list) else []
    if getattr(args, "pack_json", False):
        out(json_dumps(report, indent=2))
    else:
        out(f"pack: {report['pack']}")
        manifest = report.get("manifest")
        if isinstance(manifest, dict):
            out(
                f"  manifest: id={manifest.get('id')!r} "
                f"version={manifest.get('version')!r}"
            )
        elif "manifest" in report:
            out("  manifest: none (optional — plain folder of judge tests)")
        test_files = report.get("test_files")
        out(f"  test files: {len(test_files) if isinstance(test_files, list) else 0}")
        out(f"  pack sha256: {report.get('pack_sha256', '')}")
        for problem in problems_list:
            out(f"  PROBLEM: {problem}")
        out("  ok" if report["ok"] else "  INVALID")
    return 0 if report["ok"] else 1


def execute_version(
    _args: argparse.Namespace,
    *,
    version: Callable[[], str],
    out: Callable[[str], None] = print,
) -> int:
    """Render the stable public version line."""

    out(f"evo-guard {version()}")
    return 0


__all__ = [
    "DoctorServices",
    "PackValidationServices",
    "build_doctor_report",
    "execute_doctor",
    "execute_pack_doctor",
    "execute_version",
    "validate_pack",
]
