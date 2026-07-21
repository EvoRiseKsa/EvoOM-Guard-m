"""Compatibility contracts for the extracted invocation receipt transport."""

from __future__ import annotations

import subprocess
import sys

import evoom_guard.blackbox as blackbox
import evoom_guard.isolation as isolation
import evoom_guard.isolation.invocation as implementation


def test_blackbox_alias_and_package_export_preserve_recorder_identity() -> None:
    assert blackbox._InvocationRecorder is implementation.InvocationRecorder
    assert isolation.InvocationRecorder is implementation.InvocationRecorder


def test_invocation_module_import_does_not_load_blackbox() -> None:
    script = (
        "import sys\n"
        "import evoom_guard.isolation.invocation as invocation\n"
        "assert invocation.InvocationRecorder\n"
        "assert 'evoom_guard.blackbox' not in sys.modules\n"
    )
    subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )
