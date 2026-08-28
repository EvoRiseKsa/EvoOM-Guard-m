# ------------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech.
# Author / original creator: Mana Alharbi.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE-APACHE.
# ------------------------------------------------------------------------------
"""Host command resolution without shell invocation.

The resolver is deliberately stdlib-only and does not consult a
candidate-controlled working directory for bare Windows commands.
"""

from __future__ import annotations

import ntpath
import os
from collections.abc import Mapping

_WINDOWS_NATIVE_EXECUTABLE_EXTENSIONS = (".COM", ".EXE", ".BAT", ".CMD")
_WINDOWS_NATIVE_EXECUTABLE_EXTENSION_KEYS = frozenset(
    extension.casefold() for extension in _WINDOWS_NATIVE_EXECUTABLE_EXTENSIONS
)


def _windows_executable_extensions(search_env: Mapping[str, str]) -> tuple[str, ...]:
    """Return safe native suffixes used when resolving an extensionless token.

    ``PATHEXT`` is a command-shell lookup hint, not proof that ``CreateProcess``
    can execute an arbitrary script suffix. Keep only the four Windows-native
    executable forms this shell-free resolver supports. ``.EXE`` is always
    searched because ``CreateProcess`` appends it to extensionless modules even
    when a caller supplied an unusual ``PATHEXT``.
    """

    configured: list[str] = []
    for item in search_env.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";"):
        extension = item.strip()
        if not extension:
            continue
        normalized = extension if extension.startswith(".") else f".{extension}"
        if normalized.casefold() in _WINDOWS_NATIVE_EXECUTABLE_EXTENSION_KEYS:
            configured.append(normalized.upper())
    configured = list(dict.fromkeys(configured))
    return (
        ".EXE",
        *(extension for extension in configured if extension.casefold() != ".exe"),
    )


def _existing_windows_candidate(
    base: str,
    *,
    extensions: tuple[str, ...],
) -> str | None:
    """Resolve one explicit base against supported native Windows suffixes."""

    suffix = ntpath.splitext(base)[1].casefold()
    candidates = (
        ((base,) if suffix in _WINDOWS_NATIVE_EXECUTABLE_EXTENSION_KEYS else ())
        if suffix
        else tuple(f"{base}{extension}" for extension in extensions)
    )
    return next((candidate for candidate in candidates if os.path.isfile(candidate)), None)


def _resolve_explicit_windows_executable(
    executable: str,
    *,
    cwd: str | None,
    extensions: tuple[str, ...],
) -> str:
    explicit = executable
    if cwd and not ntpath.isabs(explicit):
        explicit = ntpath.join(cwd, explicit)
    explicit_suffix = ntpath.splitext(explicit)[1].casefold()
    if explicit_suffix and explicit_suffix not in _WINDOWS_NATIVE_EXECUTABLE_EXTENSION_KEYS:
        raise FileNotFoundError(
            "unsupported explicit Windows host command suffix: "
            f"{explicit_suffix!r}"
        )
    resolved = _existing_windows_candidate(explicit, extensions=extensions)
    if resolved is None:
        raise FileNotFoundError(
            "trusted explicit Windows host command was not found as a native "
            f"executable: {executable!r}"
        )
    return resolved


def _resolve_bare_windows_executable(
    executable: str,
    *,
    search_env: Mapping[str, str],
    extensions: tuple[str, ...],
) -> str:
    for item in search_env.get("PATH", "").split(";"):
        directory = os.path.expandvars(item.strip().strip('"'))
        if not directory or not ntpath.isabs(directory):
            continue
        resolved = _existing_windows_candidate(
            ntpath.join(directory, executable),
            extensions=extensions,
        )
        if resolved:
            return resolved
    raise FileNotFoundError(
        "trusted Windows host command was not found on an absolute PATH entry: "
        f"{executable!r}"
    )


def resolve_host_command(
    command: list[str],
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    platform: str | None = None,
) -> list[str]:
    """Resolve Windows ``.cmd``/``.bat`` shims before ``subprocess`` execution.

    Windows command prompts consult ``PATHEXT`` for a bare command such as
    ``vitest`` or ``npm``; ``CreateProcess`` (used by ``subprocess`` without a
    shell) does not. Resolve the concrete shim without enabling ``shell=True``.

    The search is intentionally implemented here instead of with
    :func:`shutil.which`: recent Python versions may implicitly prepend the
    process working directory on Windows. A candidate-controlled checkout must
    not shadow a judge command unless the adopter explicitly supplied a relative
    command path or put that directory in ``PATH``. Bare commands therefore use
    absolute ``PATH`` entries only. POSIX behavior is unchanged.

    An unresolved bare Windows token raises :class:`FileNotFoundError` instead
    of being handed back to ``CreateProcess``. Returning it would re-enable the
    current-process directory search this resolver exists to exclude.
    Explicit commands likewise resolve only to ``.exe``, ``.com``, ``.bat``,
    or ``.cmd`` files; Windows can execute suffixless PE images, so an
    unresolved explicit token must not be returned unchanged either.

    ``platform`` is an internal test seam; production callers use ``os.name``.
    """
    if (os.name if platform is None else platform) != "nt" or not command:
        return list(command)

    executable = command[0]
    search_env = os.environ if env is None else env
    extensions = _windows_executable_extensions(search_env)

    if "/" in executable or "\\" in executable:
        resolved = _resolve_explicit_windows_executable(
            executable,
            cwd=cwd,
            extensions=extensions,
        )
    else:
        resolved = _resolve_bare_windows_executable(
            executable,
            search_env=search_env,
            extensions=extensions,
        )
    return [resolved, *command[1:]]


def locate_host_command(
    executable: str,
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    platform: str | None = None,
) -> str | None:
    """Locate one executable using the same search boundary as execution.

    On Windows this delegates to :func:`resolve_host_command`, so bare
    commands never inherit ``shutil.which``'s candidate-working-directory
    behavior and relative ``PATH`` entries remain ignored.  On POSIX it mirrors
    ``execvpe`` lookup, including relative ``PATH`` entries resolved from the
    subprocess working directory.
    """

    if not executable:
        return None
    active_platform = os.name if platform is None else platform
    search_env = dict(os.environ if env is None else env)
    active_cwd = os.getcwd() if cwd is None else cwd

    if active_platform == "nt":
        try:
            resolved = resolve_host_command(
                [executable],
                cwd=active_cwd,
                env=search_env,
                platform="nt",
            )[0]
        except FileNotFoundError:
            return None
        if resolved != executable:
            return resolved
        if "/" in executable or "\\" in executable:
            candidate = (
                executable
                if ntpath.isabs(executable)
                else ntpath.join(active_cwd, executable)
            )
            suffix = ntpath.splitext(candidate)[1].casefold()
            return (
                candidate
                if suffix in _WINDOWS_NATIVE_EXECUTABLE_EXTENSION_KEYS
                and os.path.isfile(candidate)
                else None
            )
        return None

    if "/" in executable:
        candidate = (
            executable
            if os.path.isabs(executable)
            else os.path.join(active_cwd, executable)
        )
        return (
            candidate
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK)
            else None
        )

    for item in search_env.get("PATH", "").split(os.pathsep):
        directory = item or active_cwd
        if not os.path.isabs(directory):
            directory = os.path.join(active_cwd, directory)
        candidate = os.path.join(directory, executable)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


__all__ = ["locate_host_command", "resolve_host_command"]
