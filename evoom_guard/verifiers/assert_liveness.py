# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ─────────────────────────────────────────────────────────────────────────────
"""Auto-injection of the judge-owned assertion-liveness canary (catalog row 11b).

``guard --require-assert-liveness`` turns on this defense against
*assertion-neutering* (threat-model class D): candidate-imported source
monkeypatches ``unittest.TestCase.assert*`` to no-ops so a genuinely broken suite
reports an honest all-pass. The gate installs a judge-owned pytest plugin and the
shipped canary into a ``.evoguard/`` directory inside the prepared candidate copy,
puts that directory on ``PYTHONPATH``, and loads the plugin with
``-p assert_liveness_plugin``. The plugin appends the canary to whatever the
command already collects, so the repository suite still runs and the canary runs
*with* it — in the same session, the only place a candidate's import-time
monkeypatch is active. The canary enforces with a bare ``assert`` (a statement the
candidate cannot rebind), so a neutered run fails instead of yielding a false
``PASS``.

Why a plugin rather than a positional test path: a positional path suppresses the
repository's own ``testpaths`` collection and would skip the real suite. A plugin
adds the canary without changing what else is collected, for both ``testpaths``-
and explicit-path commands, and coexists with any repository ``conftest.py``.

Why it is robust under isolation: the ``.evoguard/`` directory lives inside the
copy, which is the working directory on the host (``subprocess``) and mounted at
``/work`` in the container (``docker``/``gvisor``). Under ``--isolation docker`` the
copy is mounted read-only, so the candidate cannot rewrite or delete the plugin or
canary at runtime — the hardened profile makes the probe fully tamper-resistant;
the default same-process profile raises the bar (the demonstrated naive neuter is
caught) but is not immune to a canary-aware in-process rewrite, as documented for
classes C/D.

This is a pytest-only mechanism. A non-pytest test command with the flag set is a
configuration error, surfaced before any suite runs (see :func:`command_is_pytest`).
"""

from __future__ import annotations

import os
from importlib import resources

from evoom_guard.runners.pytest import PytestAdapter

# Judge-owned directory (inside the prepared copy) that holds the plugin + canary.
# A dotted directory so pytest's default ``norecursedirs`` never auto-collects it
# and it is clearly not part of the repository's own sources.
CANARY_DIRNAME = ".evoguard"

# The plugin module name loaded via ``-p``; its file basename without the suffix.
PLUGIN_MODULE = "assert_liveness_plugin"
_PLUGIN_RESOURCE = "assert_liveness_plugin.py"
_CANARY_RESOURCE = "assert_liveness_canary.py"

# The single test node id the canary defines (kept in sync with the canary file).
CANARY_TESTID = "test_evoguard_assertion_liveness"


def _resource_text(name: str) -> str:
    return resources.files("evoom_guard.verifiers").joinpath(name).read_text(encoding="utf-8")


def command_is_pytest(cmd: list[str]) -> bool:
    """Is ``cmd`` a pytest invocation the canary plugin can be loaded into?

    Delegates to the same :class:`PytestAdapter` matcher the gate uses to select
    the runner, so detection here can never diverge from the runner the report is
    actually instrumented for. Deliberately conservative: an unrecognised runner
    returns ``False`` so the caller refuses ``--require-assert-liveness`` rather
    than silently skipping the probe on a command it cannot extend.
    """

    return PytestAdapter().matches([t for t in (cmd or []) if t])


def install_into(copy_root: str) -> str:
    """Materialise the judge-owned plugin + canary into ``copy_root``/.evoguard/.

    Written by the judge after the candidate is applied, so both files are
    judge-owned even though they sit in the prepared tree. Returns the absolute
    path of the ``.evoguard`` directory (the ``PYTHONPATH`` entry on the host).
    """

    directory = os.path.join(copy_root, CANARY_DIRNAME)
    os.makedirs(directory, exist_ok=True)
    for name in (_PLUGIN_RESOURCE, _CANARY_RESOURCE):
        with open(os.path.join(directory, name), "w", encoding="utf-8") as handle:
            handle.write(_resource_text(name))
    return directory


def plugin_command_args() -> list[str]:
    """The pytest flags that load the canary plugin (never a positional path)."""

    return ["-p", PLUGIN_MODULE]


def prepend_pythonpath(env: dict[str, str], entry: str) -> dict[str, str]:
    """Return ``env`` with ``entry`` prepended to ``PYTHONPATH`` (no mutation)."""

    previous = env.get("PYTHONPATH")
    combined = entry + (os.pathsep + previous if previous else "")
    return {**env, "PYTHONPATH": combined}


__all__ = [
    "CANARY_DIRNAME",
    "CANARY_TESTID",
    "PLUGIN_MODULE",
    "command_is_pytest",
    "install_into",
    "plugin_command_args",
    "prepend_pythonpath",
]
