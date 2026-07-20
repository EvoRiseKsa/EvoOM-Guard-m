# Judge-owned protocol pack. It invokes the candidate ACROSS A PROCESS BOUNDARY
# (never `import`s it) via $EVOGUARD_EXEC, so the verdict comes from THIS pytest
# process — one the candidate never runs in. Env is read lazily so a bare
# `pytest examples/` skips instead of failing.
import os
import subprocess
import sys

import pytest

if not (os.environ.get("EVOGUARD_EXEC") or os.environ.get("EVOGUARD_TARGET")):
    pytest.skip("runs only under the EvoOM Guard judge", allow_module_level=True)


def _run(*args):
    py = os.environ.get("EVOGUARD_PYTHON") or sys.executable
    launcher = os.environ.get("EVOGUARD_EXEC")
    if launcher:
        return subprocess.run([launcher, py, "-m", "calc", *args],
                              capture_output=True, text=True).stdout.strip()
    return subprocess.run([py, "-m", "calc", *args], cwd=os.environ.get("EVOGUARD_TARGET"),
                          capture_output=True, text=True).stdout.strip()


def test_add_is_correct():
    assert _run("add", "2", "3") == "5"


def test_add_is_commutative():
    assert _run("add", "7", "5") == _run("add", "5", "7")
