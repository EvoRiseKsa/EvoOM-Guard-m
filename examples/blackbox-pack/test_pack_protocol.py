# ─────────────────────────────────────────────────────────────────────────────
# Example black-box verifier pack. Judge-owned tests that invoke the candidate
# ACROSS A PROCESS BOUNDARY (never `import` it) so the verdict comes from this
# pack's own pytest process — which the candidate never runs in.
#
# Guard sets these env vars for the pack:
#   EVOGUARD_EXEC    — a launcher that runs its argv under the DELIVERED isolation
#                      boundary (host subprocess, or a read-only container) with the
#                      repo copy as the working root. Prefer it — it is how docker/
#                      gVisor isolation reaches the candidate.
#   EVOGUARD_PYTHON  — the interpreter token to launch a python candidate with.
#   EVOGUARD_TARGET  — path to the patched repo copy (used only in the no-launcher
#                      fallback for older Guard versions).
#
# The env is read lazily INSIDE the helper (never at import) so this file also
# collects cleanly under a plain `python -m pytest -q` on the whole repo.
#
# Run it:  evo-guard guard ./repo --patch p.txt \
#              --verifier-pack examples/blackbox-pack --blackbox
# ─────────────────────────────────────────────────────────────────────────────
import os
import subprocess
import sys

import pytest

# This pack is meaningful only when the Guard judge runs it (it sets EVOGUARD_*
# and points the launcher at a candidate). Collected on its own — e.g. a bare
# `pytest examples/` — it has no candidate to exercise, so skip rather than fail.
if not (os.environ.get("EVOGUARD_EXEC") or os.environ.get("EVOGUARD_TARGET")):
    pytest.skip(
        "black-box verifier pack runs only under the EvoOM Guard judge",
        allow_module_level=True,
    )


def _run(*args: str) -> str:
    """Invoke the candidate CLI out-of-process and return its stdout."""
    python = os.environ.get("EVOGUARD_PYTHON") or sys.executable
    launcher = os.environ.get("EVOGUARD_EXEC")
    if launcher:
        # The launcher enforces the delivered isolation and sets the working root.
        cmd = [launcher, python, "-m", "calc", *args]
        cwd = None
    else:  # fallback: run on the host at the target copy
        cmd = [python, "-m", "calc", *args]
        cwd = os.environ.get("EVOGUARD_TARGET") or "."
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True).stdout.strip()


def test_addition_is_correct() -> None:
    assert _run("add", "2", "3") == "5"


def test_addition_is_commutative() -> None:
    assert _run("add", "7", "5") == _run("add", "5", "7")
