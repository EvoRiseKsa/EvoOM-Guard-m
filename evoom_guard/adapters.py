# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ─────────────────────────────────────────────────────────────────────────────
"""Compatibility facade for :mod:`evoom_guard.runners`.

The implementation is owned by the classified ``runners`` package. This module
retains the complete historical class/function surface and resolves its live
registries for every call so existing monkeypatches keep their original timing.
"""

from __future__ import annotations

import ntpath  # noqa: F401  (historical monkeypatch surface)
import re  # noqa: F401  (historical monkeypatch surface)
import shlex  # noqa: F401  (historical monkeypatch surface)
from typing import Protocol, runtime_checkable  # noqa: F401

import evoom_guard.runners.adapters as _runner_adapters
import evoom_guard.runners.protocol as _runner_protocol
import evoom_guard.runners.registry as _runner_registry

# Public historical surface: retain exact class/protocol identities.
RunnerAdapter = _runner_protocol.RunnerAdapter
PytestAdapter = _runner_adapters.PytestAdapter
NodeTestAdapter = _runner_adapters.NodeTestAdapter
VitestAdapter = _runner_adapters.VitestAdapter
JestAdapter = _runner_adapters.JestAdapter
GotestsumAdapter = _runner_adapters.GotestsumAdapter
RspecAdapter = _runner_adapters.RspecAdapter
MochaAdapter = _runner_adapters.MochaAdapter
MavenAdapter = _runner_adapters.MavenAdapter
ShellAdapter = _runner_adapters.ShellAdapter

# Historical module globals remain addressable. The registry globals are copied
# only as initial values; ``instrument_command`` deliberately reads these facade
# names live so assignment-based monkeypatches remain effective.
ADAPTERS = _runner_registry.ADAPTERS
_INNER_ADAPTERS = _runner_registry.INNER_ADAPTERS
_WINDOWS_EXECUTABLE_SUFFIXES = _runner_adapters._WINDOWS_EXECUTABLE_SUFFIXES
_PYTHON_EXECUTABLE_RE = _runner_adapters._PYTHON_EXECUTABLE_RE
_executable_name = _runner_adapters._executable_name
_option_value_end = _runner_adapters._option_value_end
_wrapped_command_index = _runner_adapters._wrapped_command_index
_invokes_runner = _runner_adapters._invokes_runner
_is_python_executable = _runner_adapters._is_python_executable
_invokes_python_module = _runner_adapters._invokes_python_module


def instrument_command(
    cmd: list[str],
    report_path: str,
) -> tuple[list[str], bool, dict[str, str]]:
    """Wire a report through the facade's live compatibility registries."""

    return _runner_registry.instrument_with_registry(
        cmd,
        report_path,
        ADAPTERS,
        _INNER_ADAPTERS,
    )
