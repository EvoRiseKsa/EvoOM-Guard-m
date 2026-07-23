# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Direct contract tests for host-command resolution."""

from __future__ import annotations

from unittest.mock import Mock

import evoom_guard.execution.command as command_module


def test_windows_bare_command_resolves_pathex_shim(monkeypatch) -> None:
    concrete = r"C:\trusted-tools\vitest.CMD"
    isfile = Mock(side_effect=lambda path: path == concrete)
    monkeypatch.setattr(command_module.os.path, "isfile", isfile)

    resolved = command_module.resolve_host_command(
        ["vitest", "run"],
        cwd=r"C:\candidate",
        env={"PATH": r"C:\trusted-tools", "PATHEXT": ".CMD;.EXE"},
        platform="nt",
    )

    assert resolved == [concrete, "run"]
    assert concrete in {call.args[0] for call in isfile.call_args_list}


def test_windows_bare_command_ignores_relative_path_entries(monkeypatch) -> None:
    checked: list[str] = []

    def record_candidate(path: str) -> bool:
        checked.append(path)
        return False

    monkeypatch.setattr(command_module.os.path, "isfile", record_candidate)

    resolved = command_module.resolve_host_command(
        ["python", "-m", "pytest"],
        cwd=r"C:\candidate",
        env={
            "PATH": r".;candidate-tools;C:\trusted-tools",
            "PATHEXT": ".CMD;.EXE",
        },
        platform="nt",
    )

    assert resolved == ["python", "-m", "pytest"]
    assert checked
    assert all(path.startswith("C:\\trusted-tools\\") for path in checked)


def test_windows_explicit_relative_command_uses_cwd(monkeypatch) -> None:
    concrete = r"C:\candidate\tools\runner.CMD"
    monkeypatch.setattr(
        command_module.os.path,
        "isfile",
        lambda path: path == concrete,
    )

    assert command_module.resolve_host_command(
        [r"tools\runner", "--check"],
        cwd=r"C:\candidate",
        env={"PATH": r"C:\trusted-tools", "PATHEXT": ".CMD;.EXE"},
        platform="nt",
    ) == [concrete, "--check"]


def test_windows_command_with_extension_is_not_duplicated(monkeypatch) -> None:
    concrete = r"C:\trusted-tools\runner.EXE"
    checked: list[str] = []

    def record_candidate(path: str) -> bool:
        checked.append(path)
        return path == concrete

    monkeypatch.setattr(command_module.os.path, "isfile", record_candidate)

    assert command_module.resolve_host_command(
        ["runner.EXE"],
        env={"PATH": r"C:\trusted-tools", "PATHEXT": ".CMD;.EXE"},
        platform="nt",
    ) == [concrete]
    assert checked == [concrete]


def test_posix_and_empty_commands_are_unchanged(monkeypatch) -> None:
    isfile = Mock(side_effect=AssertionError("resolution must be skipped"))
    monkeypatch.setattr(command_module.os.path, "isfile", isfile)

    assert command_module.resolve_host_command(
        ["vitest", "run"], platform="posix"
    ) == ["vitest", "run"]
    assert command_module.resolve_host_command([], platform="nt") == []
    isfile.assert_not_called()
