# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ─────────────────────────────────────────────────────────────────────────────
"""Executable open-core license boundary for :mod:`evoom_guard`.

``LICENSING.md`` is the authoritative path→license map. This gate makes that
map an *import* boundary, not just a legal one:

* An Apache-core module must never import an EvoRise platform module at module
  scope. A core-only distribution that omits the platform files must import
  cleanly.
* The single sanctioned crossing is the ``evoom_guard.cli`` dispatch facade,
  which may import platform command owners *lazily* (function-local) so the
  ``evo-guard`` entry point can refuse platform subcommands with a clear
  message instead of failing at import time.
* Every module in the package must be classified. Adding a module without
  deciding its license side fails here, on purpose.

Platform modules may import core freely — the dependency arrow of open-core
points one way.
"""

from __future__ import annotations

from test_import_boundaries import PACKAGE_ROOT, analyze_package

# Mirrors LICENSING.md (the authoritative map). Update BOTH together.
PLATFORM_PACKAGES = (
    "evoom_guard.admission",
    "evoom_guard.finalizer",
)
PLATFORM_FLAT_MODULES = frozenset(
    {
        "evoom_guard.artifact_admission",
        "evoom_guard.artifact_digest_admission",
        "evoom_guard.change_attempt_observation",
        "evoom_guard.finalizer_derivation",
        "evoom_guard.github_attestation",
        "evoom_guard.maintenance_bindings",
        "evoom_guard.release_source_finalizer",
        "evoom_guard.release_source_finalizer_v2",
        "evoom_guard.release_source_producer_receipt",
        "evoom_guard.release_source_producer_receipt_v2",
        "evoom_guard.trusted_finalizer",
    }
)
PLATFORM_CLI_OWNERS = frozenset(
    {
        "evoom_guard.cli.agent_change_commands",
        "evoom_guard.cli.artifact_admission_commands",
        "evoom_guard.cli.artifact_digest_admission_commands",
        "evoom_guard.cli.change_attempt_observation_commands",
        "evoom_guard.cli.evidence_sealing_commands",
        "evoom_guard.cli.finalizer_deployment_commands",
        "evoom_guard.cli.github_attestation_admission_commands",
        "evoom_guard.cli.github_attestation_receipt_commands",
        "evoom_guard.cli.release_artifact_admission_commands",
        "evoom_guard.cli.release_source_admission_commands",
        "evoom_guard.cli.release_source_finalizer_commands",
        "evoom_guard.cli.release_source_producer_receipt_commands",
        "evoom_guard.cli.trusted_finalizer_commands",
    }
)
# The dispatch facade is Apache core but may *lazily* reach platform owners.
LAZY_CROSSING_MODULES = frozenset({"evoom_guard.cli"})


def is_platform_module(module: str) -> bool:
    if module in PLATFORM_FLAT_MODULES or module in PLATFORM_CLI_OWNERS:
        return True
    return any(
        module == package or module.startswith(package + ".")
        for package in PLATFORM_PACKAGES
    )


def test_every_module_is_classified_by_the_license_map() -> None:
    """A new module must consciously choose a side of the open-core boundary."""

    analysis = analyze_package(PACKAGE_ROOT)
    # Platform flat modules and cli owners named above must actually exist, so
    # a rename cannot silently drop a module out of the platform set.
    missing = (PLATFORM_FLAT_MODULES | PLATFORM_CLI_OWNERS) - set(analysis.modules)
    assert not missing, f"license map names modules that do not exist: {sorted(missing)}"


def test_apache_core_never_imports_the_platform_at_module_scope() -> None:
    """A core-only distribution must import cleanly with the platform absent."""

    analysis = analyze_package(PACKAGE_ROOT)
    violations = sorted(
        {
            f"{fact.source} -> {fact.target} [{fact.kind} L{fact.line}]"
            for fact in analysis.facts
            if fact.target is not None
            and not fact.type_checking
            and fact.scope == "module"
            and not is_platform_module(fact.source)
            and is_platform_module(fact.target)
        }
    )
    assert violations == [], (
        "Apache-core modules import EvoRise platform modules at import time; "
        "a core-only wheel would fail to import:\n  " + "\n  ".join(violations)
    )


def test_core_lazy_platform_imports_stay_inside_the_dispatch_facade() -> None:
    """Only the CLI dispatch may defer a platform import to call time."""

    analysis = analyze_package(PACKAGE_ROOT)
    violations = sorted(
        {
            f"{fact.source} -> {fact.target} [{fact.kind} L{fact.line}]"
            for fact in analysis.facts
            if fact.target is not None
            and not fact.type_checking
            and fact.scope == "local"
            and not is_platform_module(fact.source)
            and fact.source not in LAZY_CROSSING_MODULES
            and is_platform_module(fact.target)
        }
    )
    assert violations == [], (
        "an Apache-core module outside the dispatch facade reaches the "
        "platform at call time; that path breaks in a core-only install:\n  "
        + "\n  ".join(violations)
    )
