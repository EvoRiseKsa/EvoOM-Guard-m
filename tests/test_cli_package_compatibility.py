"""Compatibility contracts for the atomic CLI module-to-package migration."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from evoom_guard.cli import cmd_version, main


def test_console_entrypoint_import_path_is_unchanged() -> None:
    assert main.__module__ == "evoom_guard.cli"


def test_python_module_entrypoint_matches_the_public_version_command() -> None:
    expected: list[str] = []
    assert cmd_version(argparse.Namespace(), out=expected.append) == 0

    completed = subprocess.run(
        [sys.executable, "-m", "evoom_guard.cli", "version"],
        cwd=Path(__file__).resolve().parents[1],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0
    assert completed.stdout.splitlines() == expected
    assert completed.stderr == ""
