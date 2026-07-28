# Copyright © 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
"""Shell-wrapper adapter with semantics-preserving final-segment instrumentation."""

from __future__ import annotations

import shlex
from collections.abc import Sequence

import evoom_guard.runners._command as _command
from evoom_guard.runners.protocol import RunnerAdapter


class ShellAdapter:
    """Instrument the final supported runner segment inside ``sh -c``."""

    name = "sh -c"
    _SHELLS = frozenset(("sh", "bash", "zsh", "dash"))
    _default_inner_adapters: Sequence[RunnerAdapter] = ()

    def matches(self, cmd: list[str]) -> bool:
        tokens = [str(token) for token in cmd]
        return (
            len(tokens) >= 3
            and _command._executable_name(tokens[0]) in self._SHELLS
            and tokens[1] == "-c"
        )

    def instrument(self, cmd: list[str], report_path: str) -> list[str] | None:
        """Instrument through the registry-configured default inner adapters."""

        return self.instrument_with_adapters(
            cmd,
            report_path,
            self._default_inner_adapters,
        )

    def instrument_with_adapters(
        self,
        cmd: list[str],
        report_path: str,
        inner_adapters: Sequence[RunnerAdapter],
    ) -> list[str] | None:
        """Instrument with an explicit inner registry for compatibility facades."""

        shell = str(cmd[0])
        shell_str = str(cmd[2])
        prefix, operator, last_str = self._split_last_cmd(shell_str)
        try:
            last_tokens = shlex.split(last_str)
        except ValueError:
            return None
        for adapter in inner_adapters:
            if adapter.matches(last_tokens):
                instrumented = adapter.instrument(last_tokens, report_path)
                if instrumented is None:
                    return None
                # Reconstructing the whole command with shlex.join() changes shell
                # expansion/globbing/redirection semantics. Preserve the original
                # segment when instrumentation is an argv suffix.
                if instrumented[: len(last_tokens)] == last_tokens:
                    extra_tokens = instrumented[len(last_tokens) :]
                    new_last = last_str.rstrip()
                    if extra_tokens:
                        new_last += " " + shlex.join(extra_tokens)
                elif shlex.join(last_tokens) == last_str.strip():
                    # Canonical simple segments can safely accept fixed-position
                    # options used by node --test and gotestsum.
                    new_last = shlex.join(instrumented)
                else:
                    return None
                env_fn = getattr(adapter, "report_env", None)
                if env_fn:
                    prefix_env = " ".join(
                        f"{key}={shlex.quote(value)}"
                        for key, value in env_fn(report_path).items()
                    )
                    if prefix_env:
                        new_last = f"{prefix_env} {new_last}"
                new_shell_str = (
                    prefix + operator + new_last if operator else new_last
                )
                return [shell, "-c", new_shell_str]
        return None

    @classmethod
    def _split_last_cmd(cls, shell_str: str) -> tuple[str, str, str]:
        """Split on the last unquoted top-level shell operator."""

        operators: list[tuple[int, int]] = []
        quote = ""
        escaped = False
        command_substitution_depth = 0
        i = 0
        while i < len(shell_str):
            char = shell_str[i]
            if escaped:
                escaped = False
                i += 1
                continue
            if char == "\\" and quote != "'":
                escaped = True
                i += 1
                continue
            if quote:
                if char == quote:
                    quote = ""
                i += 1
                continue
            if char in {"'", '"', "`"}:
                quote = char
                i += 1
                continue
            if shell_str.startswith(("$(", "<(", ">("), i):
                command_substitution_depth += 1
                i += 2
                continue
            if command_substitution_depth:
                if char == ")":
                    command_substitution_depth -= 1
                elif char == "(":
                    command_substitution_depth += 1
                i += 1
                continue
            if shell_str.startswith(("&&", "||"), i):
                operators.append((i, 2))
                i += 2
                continue
            if shell_str.startswith("|&", i):
                operators.append((i, 2))
                i += 2
                continue
            if char == "|":
                operators.append((i, 1))
            elif char == "&":
                previous = shell_str[i - 1] if i else ""
                following = shell_str[i + 1] if i + 1 < len(shell_str) else ""
                if previous not in "<>" and following != ">":
                    operators.append((i, 1))
            elif char in {";", "\n"}:
                operators.append((i, 1))
            elif char == "#" and (i == 0 or shell_str[i - 1].isspace()):
                operators.append((i, 1))
            i += 1

        if not operators:
            return "", "", shell_str.strip()
        start, width = operators[-1]
        left = start
        while left > 0 and shell_str[left - 1].isspace():
            left -= 1
        right = start + width
        while right < len(shell_str) and shell_str[right].isspace():
            right += 1
        return shell_str[:left], shell_str[left:right], shell_str[right:].strip()


__all__ = ["ShellAdapter"]
