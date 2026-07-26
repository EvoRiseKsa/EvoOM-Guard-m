# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
"""Shared, side-effect-free command recognition grammar for runner adapters."""

from __future__ import annotations

import ntpath
import re

_WINDOWS_EXECUTABLE_SUFFIXES = frozenset((".bat", ".cmd", ".com", ".exe"))
_PYTHON_EXECUTABLE_RE = re.compile(r"python(?:\d+(?:\.\d+)?)?\Z")


def _executable_name(token: object) -> str:
    r"""Return a portable, case-normalised executable basename.

    Commands are configuration data and may be authored on a different platform
    from the judge. ``ntpath`` recognises POSIX and Windows separators, and
    stripping Windows launcher suffixes gives checked-in commands the same
    meaning on every host.
    """

    name = ntpath.basename(str(token).rstrip("/\\")).casefold()
    stem, suffix = ntpath.splitext(name)
    return stem if suffix in _WINDOWS_EXECUTABLE_SUFFIXES else name


def _option_value_end(tokens: list[str], start: int, value_options: frozenset[str]) -> int:
    """Skip launcher options and return the first possible command position."""

    i = start
    while i < len(tokens):
        token = tokens[i]
        if token == "--":
            return i + 1
        if not token.startswith("-"):
            return i
        option = token.split("=", 1)[0]
        if "=" not in token and option in value_options:
            i += 2
        else:
            i += 1
    return i


def _wrapped_command_index(cmd: list[str]) -> int | None:
    """Locate a command invoked by one of the explicitly supported launchers.

    This is deliberately a small grammar, not an ``any(token == runner)`` search.
    A later token may be a test filename or user argument and must never select an
    adapter. Unknown launcher forms fail closed and retain exit-code grading.
    """

    tokens = [str(token) for token in cmd]
    if not tokens:
        return None
    launcher = _executable_name(tokens[0])

    if launcher in {"npx", "bunx"}:
        return _option_value_end(
            tokens,
            1,
            frozenset(("-p", "--package", "-c", "--call")),
        )

    if launcher == "pnpm":
        i = _option_value_end(
            tokens,
            1,
            frozenset(("-C", "--dir", "-F", "--filter", "--config-dir")),
        )
        if i < len(tokens) and tokens[i] in {"dlx", "exec", "run"}:
            return _option_value_end(tokens, i + 1, frozenset(("-c", "--shell-mode")))
        return i

    if launcher in {"yarn", "yarnpkg"}:
        i = _option_value_end(
            tokens,
            1,
            frozenset(("--cwd", "--use-yarnrc", "--cache-folder", "--mutex")),
        )
        if i < len(tokens) and tokens[i] in {"dlx", "exec", "run"}:
            return _option_value_end(tokens, i + 1, frozenset())
        return i

    if launcher == "npm":
        try:
            marker = next(i for i, token in enumerate(tokens[1:], 1) if token in {"exec", "x"})
        except StopIteration:
            return None
        return _option_value_end(
            tokens,
            marker + 1,
            frozenset(("-c", "--call", "--package")),
        )

    if launcher == "bundle" and len(tokens) >= 3 and tokens[1] == "exec":
        return 2

    if launcher in {"poetry", "pipenv", "uv"} and len(tokens) >= 3 and tokens[1] == "run":
        return 2

    return None


def _invokes_runner(cmd: list[str], runner: str) -> bool:
    """Return whether ``runner`` is the command's executable, not an argument."""

    if not cmd:
        return False
    if _executable_name(cmd[0]) == runner:
        return True
    wrapped = _wrapped_command_index(cmd)
    return wrapped is not None and wrapped < len(cmd) and _executable_name(cmd[wrapped]) == runner


def _is_python_executable(token: object) -> bool:
    """Recognise only standard Python executables and the Windows ``py`` launcher."""

    executable = _executable_name(token)
    return executable == "py" or _PYTHON_EXECUTABLE_RE.fullmatch(executable) is not None


def _invokes_python_module(cmd: list[str], module: str) -> bool:
    """Recognise ``python -m <module>`` directly or behind a known launcher."""

    tokens = [str(token) for token in cmd]
    starts = [0]
    wrapped = _wrapped_command_index(tokens)
    if wrapped is not None:
        starts.append(wrapped)
    for start in starts:
        if (
            start + 2 < len(tokens)
            and _is_python_executable(tokens[start])
            and tokens[start + 1] == "-m"
            and tokens[start + 2].casefold() == module
        ):
            return True
    return False
