# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ─────────────────────────────────────────────────────────────────────────────
"""Judge-owned pytest plugin that injects the assertion-liveness canary.

``guard --require-assert-liveness`` writes this file and its sibling
``assert_liveness_canary.py`` into a judge-owned ``.evoguard/`` directory inside
the prepared candidate copy, puts that directory on ``PYTHONPATH``, and loads this
module with ``-p assert_liveness_plugin``. Loading the canary as a *plugin* (rather
than a positional test path) is deliberate: a positional path would suppress the
repository's own ``testpaths`` collection and skip the real suite. As a plugin the
canary is added to whatever the command already collects, so the repository suite
still runs and the canary runs *with* it, in the same session — the only place a
candidate's import-time assertion monkeypatch is active.

Fail-closed: if the canary cannot be injected, collection errors and the run fails
rather than silently proceeding without the probe.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_CANARY = Path(__file__).with_name("assert_liveness_canary.py")


def pytest_collection_modifyitems(session, config, items):  # noqa: ANN001, ANN201
    """Append the canary's test item to the collected suite.

    Runs after collection, so any import-time monkeypatch a candidate planted is
    already in effect process-wide when the canary later executes.
    """

    canary = pytest.Module.from_parent(session, path=_CANARY)
    items.extend(session.genitems(canary))
