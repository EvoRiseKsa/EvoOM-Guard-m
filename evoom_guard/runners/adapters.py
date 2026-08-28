# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
"""Compatibility facade for the historical combined adapter module.

Concrete implementations live in one owner module per runner. This facade
retains exact object identities, wildcard exports, private grammar aliases, and
historically importable stdlib/type names.
"""

from __future__ import annotations

import ntpath  # noqa: F401  (historical direct-import surface)
import re  # noqa: F401  (historical direct-import surface)
import shlex  # noqa: F401  (historical direct-import surface)
from collections.abc import Sequence  # noqa: F401

import evoom_guard.runners._command as _command
from evoom_guard.runners.gotestsum import GotestsumAdapter
from evoom_guard.runners.jest import JestAdapter
from evoom_guard.runners.maven import MavenAdapter
from evoom_guard.runners.mocha import MochaAdapter
from evoom_guard.runners.node_test import NodeTestAdapter
from evoom_guard.runners.protocol import RunnerAdapter  # noqa: F401
from evoom_guard.runners.pytest import PytestAdapter
from evoom_guard.runners.rspec import RspecAdapter
from evoom_guard.runners.shell import ShellAdapter
from evoom_guard.runners.vitest import VitestAdapter

_WINDOWS_EXECUTABLE_SUFFIXES = _command._WINDOWS_EXECUTABLE_SUFFIXES
_PYTHON_EXECUTABLE_RE = _command._PYTHON_EXECUTABLE_RE
_executable_name = _command._executable_name
_option_value_end = _command._option_value_end
_wrapped_command_index = _command._wrapped_command_index
_invokes_runner = _command._invokes_runner
_is_python_executable = _command._is_python_executable
_invokes_python_module = _command._invokes_python_module

__all__ = [
    "GotestsumAdapter",
    "JestAdapter",
    "MavenAdapter",
    "MochaAdapter",
    "NodeTestAdapter",
    "PytestAdapter",
    "RspecAdapter",
    "ShellAdapter",
    "VitestAdapter",
]
