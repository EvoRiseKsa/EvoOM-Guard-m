# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# -----------------------------------------------------------------------------
"""Pure diagnostic-output distillation for verifier feedback."""

from __future__ import annotations

import re

_DIAG_LINE_RE = re.compile(
    r"FAIL|×|✗|Expected|Received|expected|received|Counterexample|"
    r"AssertionError|Error:|assert|Tests\s|Test Files|=== |--- |E\s{3}"
)
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def distill_diagnostics(output: str, *, max_chars: int = 1600) -> str:
    """Distill a test run's output to what the generator can act on."""
    clean = _ANSI_RE.sub("", output or "")
    picked = [ln.strip() for ln in clean.splitlines() if _DIAG_LINE_RE.search(ln)]
    picked = [ln for ln in picked if not ln.lstrip().startswith(("❯", "at "))]
    if not picked:
        return clean[-800:]
    text = "\n".join(picked)
    return text[-max_chars:]


__all__ = ["distill_diagnostics"]
