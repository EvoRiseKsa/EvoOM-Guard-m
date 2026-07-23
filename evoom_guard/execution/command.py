# ------------------------------------------------------------------------------
# Copyright (c) 2026 Mana Alharbi. All rights reserved.
# Source-available — see LICENSE for permitted use.
# ------------------------------------------------------------------------------
"""Host command resolution without shell invocation.

The resolver is deliberately stdlib-only and does not consult a
candidate-controlled working directory for bare Windows commands.
"""

from __future__ import annotations

import ntpath
import os


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

    ``platform`` is an internal test seam; production callers use ``os.name``.
    """
    if (os.name if platform is None else platform) != "nt" or not command:
        return list(command)

    executable = command[0]
    search_env = os.environ if env is None else env
    raw_extensions = search_env.get("PATHEXT", ".COM;.EXE;.BAT;.CMD")
    extensions = tuple(
        ext if ext.startswith(".") else f".{ext}"
        for item in raw_extensions.split(";")
        if (ext := item.strip())
    )

    def existing_candidate(base: str) -> str | None:
        direct = (
            (base,)
            if any(base.lower().endswith(ext.lower()) for ext in extensions)
            else ()
        )
        for candidate in (*direct, *(f"{base}{ext}" for ext in extensions)):
            if os.path.isfile(candidate):
                return candidate
        return None

    if "/" in executable or "\\" in executable:
        explicit = executable
        if cwd and not ntpath.isabs(explicit):
            explicit = ntpath.join(cwd, explicit)
        resolved = existing_candidate(explicit)
        return [resolved, *command[1:]] if resolved else list(command)

    for item in search_env.get("PATH", "").split(";"):
        directory = os.path.expandvars(item.strip().strip('"'))
        if not directory or not ntpath.isabs(directory):
            continue
        resolved = existing_candidate(ntpath.join(directory, executable))
        if resolved:
            return [resolved, *command[1:]]
    return list(command)
