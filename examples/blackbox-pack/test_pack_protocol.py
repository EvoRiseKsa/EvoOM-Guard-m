# ─────────────────────────────────────────────────────────────────────────────
# Example black-box verifier pack. Judge-owned tests that invoke the candidate
# ACROSS A PROCESS BOUNDARY (never `import` it) so the verdict comes from this
# pack's own pytest process — which the candidate never runs in.
#
# Guard sets two env vars for the pack:
#   EVOGUARD_TARGET  — path to the patched repo copy
#   EVOGUARD_PYTHON  — interpreter to launch the candidate with
#
# Run it:  evo-guard guard ./repo --patch p.txt \
#              --verifier-pack examples/blackbox-pack --blackbox
# ─────────────────────────────────────────────────────────────────────────────
import os
import subprocess
import sys

TARGET = os.environ["EVOGUARD_TARGET"]
PYTHON = os.environ.get("EVOGUARD_PYTHON", sys.executable)


def _run(*args: str) -> str:
    """Invoke the candidate CLI out-of-process and return its stdout."""
    return subprocess.run(
        [PYTHON, "-m", "calc", *args],
        cwd=TARGET, capture_output=True, text=True,
    ).stdout.strip()


def test_addition_is_correct() -> None:
    assert _run("add", "2", "3") == "5"


def test_addition_is_commutative() -> None:
    assert _run("add", "7", "5") == _run("add", "5", "7")
