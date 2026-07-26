# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Runner recognition and judge-owned report instrumentation."""

from evoom_guard.runners.gotestsum import GotestsumAdapter
from evoom_guard.runners.jest import JestAdapter
from evoom_guard.runners.maven import MavenAdapter
from evoom_guard.runners.mocha import MochaAdapter
from evoom_guard.runners.node_test import NodeTestAdapter
from evoom_guard.runners.protocol import RunnerAdapter
from evoom_guard.runners.pytest import PytestAdapter
from evoom_guard.runners.registry import ADAPTERS, instrument_command
from evoom_guard.runners.rspec import RspecAdapter
from evoom_guard.runners.shell import ShellAdapter
from evoom_guard.runners.vitest import VitestAdapter

__all__ = [
    "ADAPTERS",
    "GotestsumAdapter",
    "JestAdapter",
    "MavenAdapter",
    "MochaAdapter",
    "NodeTestAdapter",
    "PytestAdapter",
    "RspecAdapter",
    "RunnerAdapter",
    "ShellAdapter",
    "VitestAdapter",
    "instrument_command",
]
