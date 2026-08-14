# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Direct contract tests for host-command resolution."""

from __future__ import annotations

import os
import shutil
import subprocess
from unittest.mock import Mock

import pytest

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

    with pytest.raises(FileNotFoundError, match="trusted Windows host command"):
        command_module.resolve_host_command(
            ["python", "-m", "pytest"],
            cwd=r"C:\candidate",
            env={
                "PATH": r".;candidate-tools;C:\trusted-tools",
                "PATHEXT": ".CMD;.EXE",
            },
            platform="nt",
        )

    assert checked
    assert all(path.startswith("C:\\trusted-tools\\") for path in checked)


def test_windows_bare_command_prefers_native_exe_before_pathex_shims(
    monkeypatch,
) -> None:
    executable = r"C:\trusted-tools\probe.EXE"
    shim = r"C:\trusted-tools\probe.CMD"
    monkeypatch.setattr(
        command_module.os.path,
        "isfile",
        lambda path: path in {executable, shim},
    )

    assert command_module.resolve_host_command(
        ["probe"],
        env={"PATH": r"C:\trusted-tools", "PATHEXT": ".CMD;.EXE"},
        platform="nt",
    ) == [executable]


@pytest.mark.skipif(os.name != "nt", reason="requires real Windows launch semantics")
def test_windows_unresolved_bare_command_cannot_execute_candidate_cmd(
    monkeypatch,
    tmp_path,
) -> None:
    checkout = tmp_path / "checkout"
    candidate = tmp_path / "candidate"
    checkout.mkdir()
    candidate.mkdir()
    script = "candidate-runner.cmd"
    for root in (checkout, candidate):
        (root / script).write_text(
            "@echo CANDIDATE_SHADOW_EXECUTED>shadow-ran.txt\r\n",
            encoding="utf-8",
        )

    monkeypatch.chdir(checkout)
    environment = dict(os.environ)
    environment["PATH"] = ""
    environment["PATHEXT"] = ".CMD;.EXE"

    def resolve_then_launch() -> None:
        command = command_module.resolve_host_command(
            [script],
            cwd=str(candidate),
            env=environment,
            platform="nt",
        )
        subprocess.run(
            command,
            cwd=candidate,
            env=environment,
            check=True,
            timeout=10,
        )

    with pytest.raises(FileNotFoundError, match="trusted Windows host command"):
        resolve_then_launch()
    assert not (candidate / "shadow-ran.txt").exists()


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


def test_locate_windows_command_uses_absolute_path_entries_only(monkeypatch) -> None:
    concrete = r"C:\trusted-tools\shadow.CMD"
    monkeypatch.setattr(
        command_module.os.path,
        "isfile",
        lambda path: path == concrete,
    )

    assert command_module.locate_host_command(
        "shadow",
        cwd=r"C:\candidate",
        env={
            "PATH": r".;candidate-tools;C:\trusted-tools",
            "PATHEXT": ".CMD;.EXE",
        },
        platform="nt",
    ) == concrete


def test_locate_windows_command_does_not_accept_relative_path_shadow(
    monkeypatch,
) -> None:
    monkeypatch.setattr(command_module.os.path, "isfile", lambda _path: True)

    assert command_module.locate_host_command(
        "shadow",
        cwd=r"C:\candidate",
        env={"PATH": r".;candidate-tools", "PATHEXT": ".CMD;.EXE"},
        platform="nt",
    ) is None


@pytest.mark.parametrize("pathext", (".CMD;.EXE", "CMD;EXE;PY"))
def test_locate_windows_explicit_non_native_script_is_not_accepted(
    monkeypatch,
    pathext: str,
) -> None:
    script = r"C:\trusted-tools\runner.py"
    monkeypatch.setattr(command_module.os.path, "isfile", lambda path: path == script)

    assert command_module.locate_host_command(
        script,
        env={"PATH": r"C:\trusted-tools", "PATHEXT": pathext},
        platform="nt",
    ) is None
    with pytest.raises(FileNotFoundError, match="unsupported explicit Windows"):
        command_module.resolve_host_command(
            [script],
            env={"PATH": r"C:\trusted-tools", "PATHEXT": pathext},
            platform="nt",
        )


def test_locate_windows_explicit_exe_does_not_depend_on_pathex(monkeypatch) -> None:
    executable = r"C:\trusted-tools\runner.exe"
    monkeypatch.setattr(
        command_module.os.path,
        "isfile",
        lambda path: path == executable,
    )

    assert command_module.locate_host_command(
        executable,
        env={"PATH": r"C:\trusted-tools", "PATHEXT": ".CMD;.PY"},
        platform="nt",
    ) == executable


def test_windows_arbitrary_pathex_does_not_resolve_bare_script(monkeypatch) -> None:
    script = r"C:\trusted-tools\runner.PY"
    monkeypatch.setattr(command_module.os.path, "isfile", lambda path: path == script)

    assert command_module.locate_host_command(
        "runner",
        env={"PATH": r"C:\trusted-tools", "PATHEXT": ".PY"},
        platform="nt",
    ) is None
    with pytest.raises(FileNotFoundError, match="trusted Windows host command"):
        command_module.resolve_host_command(
            ["runner"],
            env={"PATH": r"C:\trusted-tools", "PATHEXT": ".PY"},
            platform="nt",
        )


@pytest.mark.skipif(os.name != "nt", reason="requires real Windows launch semantics")
def test_windows_explicit_exe_runs_when_pathex_omits_exe(tmp_path) -> None:
    executable = tmp_path / "runner.exe"
    shutil.copy2(os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe"), executable)
    environment = dict(os.environ)
    environment["PATHEXT"] = ".CMD;.PY"

    located = command_module.locate_host_command(
        str(executable),
        cwd=str(tmp_path),
        env=environment,
        platform="nt",
    )
    assert located == str(executable)
    completed = subprocess.run(
        command_module.resolve_host_command(
            [str(executable), "/d", "/c", "echo EXPLICIT_EXE_EXECUTED"],
            cwd=str(tmp_path),
            env=environment,
            platform="nt",
        ),
        cwd=tmp_path,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.stdout.strip() == "EXPLICIT_EXE_EXECUTED"


@pytest.mark.skipif(os.name != "nt", reason="requires real Windows launch semantics")
def test_windows_explicit_extensionless_pe_is_rejected(tmp_path) -> None:
    executable = tmp_path / "runner"
    shutil.copy2(os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe"), executable)
    environment = dict(os.environ)

    # CreateProcess can execute this PE image despite the absent suffix, so the
    # resolver must reject rather than return the explicit token unchanged.
    unguarded = subprocess.run(
        [str(executable), "/d", "/c", "echo EXTENSIONLESS_PE_EXECUTED"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert unguarded.stdout.strip() == "EXTENSIONLESS_PE_EXECUTED"

    with pytest.raises(FileNotFoundError, match="native executable"):
        command_module.resolve_host_command(
            [str(executable)],
            cwd=str(tmp_path),
            env=environment,
            platform="nt",
        )
