# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ─────────────────────────────────────────────────────────────────────────────
"""Ordered runner registry and command instrumentation dispatch."""

from __future__ import annotations

from collections.abc import Sequence

from evoom_guard.runners.gotestsum import GotestsumAdapter
from evoom_guard.runners.jest import JestAdapter
from evoom_guard.runners.maven import MavenAdapter
from evoom_guard.runners.mocha import MochaAdapter
from evoom_guard.runners.node_test import NodeTestAdapter
from evoom_guard.runners.protocol import RunnerAdapter
from evoom_guard.runners.pytest import PytestAdapter
from evoom_guard.runners.rspec import RspecAdapter
from evoom_guard.runners.shell import ShellAdapter
from evoom_guard.runners.vitest import VitestAdapter

INNER_ADAPTERS: tuple[RunnerAdapter, ...] = (
    PytestAdapter(),
    NodeTestAdapter(),
    VitestAdapter(),
    JestAdapter(),
    GotestsumAdapter(),
    RspecAdapter(),
    MochaAdapter(),
    MavenAdapter(),
)

# Keep direct ``ShellAdapter().instrument(...)`` behavior identical without a
# reverse import from the concrete-adapter module into this registry.
ShellAdapter._default_inner_adapters = INNER_ADAPTERS

# Shell must inspect its command string before direct runner adapters inspect argv.
ADAPTERS: tuple[RunnerAdapter, ...] = (ShellAdapter(), *INNER_ADAPTERS)


def instrument_with_registry(
    cmd: list[str],
    report_path: str,
    adapters: Sequence[RunnerAdapter],
    inner_adapters: Sequence[RunnerAdapter],
) -> tuple[list[str], bool, dict[str, str]]:
    """Instrument using explicitly supplied live registries.

    Supplying both sequences keeps compatibility facades and tests able to
    monkeypatch their historical module globals without copying dispatch logic.
    """

    for adapter in adapters:
        if not adapter.matches(cmd):
            continue
        if type(adapter) is ShellAdapter:
            instrumented = adapter.instrument_with_adapters(
                cmd,
                report_path,
                inner_adapters,
            )
        else:
            instrumented = adapter.instrument(cmd, report_path)
        if instrumented is not None:
            env_fn = getattr(adapter, "report_env", None)
            report_env: dict[str, str] = env_fn(report_path) if env_fn else {}
            return instrumented, True, report_env
        return list(cmd), False, {}
    return list(cmd), False, {}


def instrument_command(
    cmd: list[str],
    report_path: str,
) -> tuple[list[str], bool, dict[str, str]]:
    """Wire a judge-owned JUnit reporter through the live default registry."""

    return instrument_with_registry(
        cmd,
        report_path,
        ADAPTERS,
        INNER_ADAPTERS,
    )


__all__ = [
    "ADAPTERS",
    "INNER_ADAPTERS",
    "instrument_command",
    "instrument_with_registry",
]
