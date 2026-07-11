# ─────────────────────────────────────────────────────────────────────────────
# Copyright (c) 2026 Mana Alharbi (مانع الحربي). All rights reserved.
# Source-available — see LICENSE for permitted use.
# Maintained and released by Mana Alharbi (مانع الحربي).
# ─────────────────────────────────────────────────────────────────────────────
"""Per-runner adapters: wire a *judge-owned* JUnit report into a test command.

Each test runner exposes a structured verdict differently — pytest's
``--junitxml``, node ``--test``'s ``--test-reporter``, vitest's
``--reporter=junit`` / ``--outputFile``, jest's ``jest-junit`` (whose output path
is set through the ``JEST_JUNIT_OUTPUT_FILE`` environment variable, as jest has no
CLI option for it), Go's ``gotestsum --junitfile``, Ruby's
``rspec --format RspecJunitFormatter --out``, mocha's ``mocha-junit-reporter``
(``--reporter-options mochaFile=…``), and Maven Surefire's
``-Dsurefire.reportsDirectory`` (a *directory* of per-class reports) — but all of
the supported ones write JUnit XML to a path the **judge** controls (outside the
repo copy), which the dialect-agnostic
:func:`evoom_guard.verifiers.repo_verifier.parse_junit_xml` (or, for the directory form,
:func:`evoom_guard.verifiers.repo_verifier.parse_junit_dir`) then reads.
An adapter encapsulates that per-runner wiring so the verifier core stays
runner-agnostic and adding a runner (jest, mocha, …) is a single localized class.

Security invariant every adapter MUST uphold: the structured report is written to
a judge-controlled **file**, never scraped from candidate-influenceable *stdout*.
A test under judgement can print anything to stdout (a fake ``"9999 passed"`` or a
forged ``--- PASS`` line), so a runner whose only machine-readable output is stdout
(e.g. ``go test -json``) does **not** qualify for a structured verdict here and is
left to exit-code grading. This file is stdlib-only.
"""

from __future__ import annotations

import shlex
from typing import Protocol, runtime_checkable


@runtime_checkable
class RunnerAdapter(Protocol):
    """One test runner's report wiring.

    ``matches`` recognises the runner from the judge command; ``instrument``
    returns that command with a judge-owned JUnit reporter spliced in, writing to
    ``report_path`` (a path *outside* the repo copy). ``instrument`` returns
    ``None`` when it recognises the runner but the caller already configured a
    reporter — we never clobber an explicit choice (the verdict then falls back to
    the exit code).
    """

    name: str

    def matches(self, cmd: list[str]) -> bool: ...

    def instrument(self, cmd: list[str], report_path: str) -> list[str] | None: ...


class PytestAdapter:
    """pytest — append ``--junitxml=<path>`` (pytest accepts options after the
    positional test paths)."""

    name = "pytest"

    def matches(self, cmd: list[str]) -> bool:
        return any("pytest" in str(tok) for tok in cmd)

    def instrument(self, cmd: list[str], report_path: str) -> list[str] | None:
        return [*cmd, f"--junitxml={report_path}", "-o", "junit_family=xunit2"]


class NodeTestAdapter:
    """node's built-in ``node --test`` runner.

    Matches a ``node`` executable (by exact token or basename, so
    ``/opt/node/bin/node`` counts) together with a ``--test`` flag. ``npm test`` is
    *not* matched: it runs a package.json script, so a reporter cannot be spliced in.

    Splices ``--test-reporter=junit`` (to the judge-owned file) plus a ``spec``
    reporter (to stdout, so diagnostics survive) *after the ``--test`` flag but
    before the test-file positionals* — node ignores reporter flags that trail the
    file arguments, so position matters.
    """

    name = "node --test"

    def matches(self, cmd: list[str]) -> bool:
        toks = [str(t) for t in cmd]
        has_node = any(t == "node" or t.rsplit("/", 1)[-1] == "node" for t in toks)
        return has_node and "--test" in toks

    def instrument(self, cmd: list[str], report_path: str) -> list[str] | None:
        toks = [str(t) for t in cmd]
        if any(t.startswith("--test-reporter") for t in toks):
            return None  # caller already chose a reporter — don't clobber it
        report = [
            "--test-reporter=junit", f"--test-reporter-destination={report_path}",
            "--test-reporter=spec", "--test-reporter-destination=stdout",
        ]
        i = toks.index("--test")
        return [*cmd[: i + 1], *report, *cmd[i + 1 :]]


class VitestAdapter:
    """vitest (``vitest run`` / ``npx vitest`` / a ``.bin/vitest`` path).

    Matched on a token whose basename is ``vitest``. The expected gate form is
    ``vitest run`` — bare ``vitest`` watches and would hang until the timeout.
    Appends ``--reporter=junit --outputFile=<path>`` (to the judge-owned file) plus
    the ``default`` reporter (to stdout, for diagnostics); vitest accepts a trailing
    reporter list and writes the absolute ``--outputFile`` even with the cwd inside
    the repo copy.
    """

    name = "vitest"

    def matches(self, cmd: list[str]) -> bool:
        return any(str(t).rsplit("/", 1)[-1] == "vitest" for t in cmd)

    def instrument(self, cmd: list[str], report_path: str) -> list[str] | None:
        if any(str(t).startswith(("--reporter", "--outputFile")) for t in cmd):
            return None  # caller already chose a reporter / output file
        return [*cmd, "--reporter=default", "--reporter=junit", f"--outputFile={report_path}"]


class JestAdapter:
    """jest (``jest`` / ``npx jest`` / a ``.bin/jest`` path).

    Matched on a token whose basename is ``jest``. Unlike the other runners, jest
    cannot take a per-reporter option (the output path) on the command line, so this
    adapter only splices the *reporter selection* (``--reporters=default``, keeping
    diagnostics on stdout, plus ``--reporters=jest-junit``) into the command and
    hands the judge-owned output path to ``jest-junit`` via the environment in
    :meth:`report_env`. ``jest-junit`` must resolve in the repo copy (e.g. installed
    by ``setup_command``). The verdict is still read only from the judge-owned file,
    never candidate stdout.
    """

    name = "jest"

    def matches(self, cmd: list[str]) -> bool:
        return any(str(t).rsplit("/", 1)[-1] == "jest" for t in cmd)

    def instrument(self, cmd: list[str], report_path: str) -> list[str] | None:
        if any(str(t).startswith("--reporters") for t in cmd):
            return None  # caller already chose reporters — don't clobber them
        return [*cmd, "--reporters=default", "--reporters=jest-junit"]

    def report_env(self, report_path: str) -> dict[str, str]:
        """Point ``jest-junit`` at the judge-owned report (no CLI option exists)."""
        return {"JEST_JUNIT_OUTPUT_FILE": report_path}


class GotestsumAdapter:
    """Go via ``gotestsum`` (``gotestsum --junitfile <path> -- ./...``).

    Bare ``go test -json`` is **deliberately not supported**: its only
    machine-readable output is *stdout*, which the candidate can forge (printing a
    fake ``--- PASS``), so it violates the judge-owned-channel invariant. ``gotestsum``
    wraps ``go test`` and writes a JUnit report to a **file** we can point outside the
    repo copy with an absolute ``--junitfile`` — so the verdict stays judge-owned.

    ``gotestsum``'s own flags must precede the ``--`` separator that passes the rest
    to ``go test``; the reporter flag is inserted before that separator (or appended
    when there is none). ``gotestsum`` must resolve on PATH in the repo copy.
    """

    name = "gotestsum"

    def matches(self, cmd: list[str]) -> bool:
        return any(str(t).rsplit("/", 1)[-1] == "gotestsum" for t in cmd)

    def instrument(self, cmd: list[str], report_path: str) -> list[str] | None:
        toks = [str(t) for t in cmd]
        if any(t.startswith("--junitfile") for t in toks):
            return None  # caller already chose a report file — don't clobber it
        flag = f"--junitfile={report_path}"
        # gotestsum flags must come *before* the `--` that hands off to `go test`.
        if "--" in toks:
            i = toks.index("--")
            return [*toks[:i], flag, *toks[i:]]
        return [*toks, flag]


class RspecAdapter:
    """Ruby via RSpec (``rspec`` / ``bundle exec rspec``).

    Splices the JUnit formatter (``rspec_junit_formatter`` — which must resolve in the
    repo copy, e.g. via the project's Gemfile) writing to a judge-owned ``--out``
    path, plus the ``progress`` formatter so human diagnostics still reach stdout.
    RSpec pairs each ``--out`` with the immediately preceding ``--format``, so the
    order matters. Declines if the caller already configured a formatter.
    """

    name = "rspec"

    def matches(self, cmd: list[str]) -> bool:
        return any(str(t).rsplit("/", 1)[-1] == "rspec" for t in cmd)

    def instrument(self, cmd: list[str], report_path: str) -> list[str] | None:
        toks = [str(t) for t in cmd]
        if any(t in ("--format", "-f") or t.startswith(("--format=", "--out")) for t in toks):
            return None  # caller already chose a formatter / output — don't clobber it
        return [
            *toks,
            "--format", "progress",
            "--format", "RspecJunitFormatter", "--out", report_path,
        ]


class MochaAdapter:
    """JavaScript via mocha (``mocha`` / ``npx mocha`` / a ``.bin/mocha`` path).

    Splices ``mocha-junit-reporter`` (which must resolve in the repo copy) with the
    judge-owned output file passed through ``--reporter-options mochaFile=<path>``.
    Declines if the caller already chose a reporter. (mocha runs a single reporter at
    a time, so spec output is traded for the structured report; the verdict — read
    from the JUnit file — is what matters, and full stdout is still captured.)
    """

    name = "mocha"

    def matches(self, cmd: list[str]) -> bool:
        return any(str(t).rsplit("/", 1)[-1] == "mocha" for t in cmd)

    def instrument(self, cmd: list[str], report_path: str) -> list[str] | None:
        toks = [str(t) for t in cmd]
        if any(t in ("--reporter", "-R") or t.startswith(("--reporter=", "--reporter-options")) for t in toks):
            return None  # caller already chose a reporter — don't clobber it
        return [
            *toks,
            "--reporter", "mocha-junit-reporter",
            "--reporter-options", f"mochaFile={report_path}",
        ]


class MavenAdapter:
    """Java / Kotlin via Maven (``mvn test`` / ``./mvnw test``).

    Maven Surefire writes **one ``TEST-*.xml`` per test class into a directory**
    (``target/surefire-reports`` by default — *inside* the repo copy, where the
    candidate could overwrite it). This adapter redirects that directory to a
    judge-owned location *outside* the copy via ``-Dsurefire.reportsDirectory`` (a
    documented Surefire property), deriving ``<report_path>.d`` from the judge-owned
    report path. The verifier then merges every ``*.xml`` there — see
    :func:`evoom_guard.verifiers.repo_verifier.parse_junit_dir`. Declines if the caller
    already set the property.

    Note: a ``pom.xml`` Surefire ``<excludes>`` could still deselect failing tests,
    so ``pom.xml`` is treated as protected config (use ``--allow pom.xml`` to permit
    dependency edits in the same change).
    """

    name = "maven"

    def matches(self, cmd: list[str]) -> bool:
        return any(str(t).rsplit("/", 1)[-1] in ("mvn", "mvnw") for t in cmd)

    def instrument(self, cmd: list[str], report_path: str) -> list[str] | None:
        toks = [str(t) for t in cmd]
        if any(t.startswith("-Dsurefire.reportsDirectory") for t in toks):
            return None  # caller already chose a reports directory — don't clobber it
        return [*toks, f"-Dsurefire.reportsDirectory={report_path}.d"]


# The runner adapters the ShellAdapter delegates to when unwrapping ``sh -c``.
# (Itself excluded — a shell cannot nest another shell wrapper here.)
_INNER_ADAPTERS: tuple[RunnerAdapter, ...] = (
    PytestAdapter(), NodeTestAdapter(), VitestAdapter(), JestAdapter(),
    GotestsumAdapter(), RspecAdapter(), MochaAdapter(), MavenAdapter(),
)


class ShellAdapter:
    """Unwrap ``sh -c \"...\"`` (and bash/zsh/dash) and delegate to the inner runner.

    When a ``test_command`` is ``["sh", "-c", "pnpm install && vitest run"]``, only
    the *last* pipeline segment is a test runner (``vitest run``); the earlier
    segments are setup steps fused into the same shell string. This adapter splits
    on the last ``&&`` / ``||`` / ``;`` operator, instruments the inner runner, and
    reassembles the shell string — restoring the TAMPERED detection that would
    otherwise be lost for Node.js commands that use this pattern.

    With the separate ``setup_command`` field now available, the recommended pattern
    is to move the setup step there and use a bare token-list ``test_command``. This
    adapter exists as a fallback for existing configs that still use the fused form.
    """

    name = "sh -c"
    _SHELLS = frozenset(("sh", "bash", "zsh", "dash"))
    _OPS = (" && ", " || ", "; ")

    def matches(self, cmd: list[str]) -> bool:
        toks = [str(t) for t in cmd]
        return (
            len(toks) >= 3
            and toks[0].rsplit("/", 1)[-1] in self._SHELLS
            and toks[1] == "-c"
        )

    def instrument(self, cmd: list[str], report_path: str) -> list[str] | None:
        shell = str(cmd[0])
        shell_str = str(cmd[2])
        prefix, op, last_str = self._split_last_cmd(shell_str)
        try:
            last_tokens = shlex.split(last_str)
        except ValueError:
            return None
        for adapter in _INNER_ADAPTERS:
            if adapter.matches(last_tokens):
                instrumented = adapter.instrument(last_tokens, report_path)
                if instrumented is None:
                    return None
                new_last = shlex.join(instrumented)
                # A runner whose reporter path comes from the environment (jest) gets
                # it inlined as a shell var assignment on its own segment, so the
                # judge-owned path survives the sh -c wrapper without a separate env.
                env_fn = getattr(adapter, "report_env", None)
                if env_fn:
                    prefix_env = " ".join(
                        f"{k}={shlex.quote(v)}" for k, v in env_fn(report_path).items()
                    )
                    if prefix_env:
                        new_last = f"{prefix_env} {new_last}"
                new_shell_str = (prefix + op + new_last) if op else new_last
                return [shell, "-c", new_shell_str]
        return None

    @classmethod
    def _split_last_cmd(cls, shell_str: str) -> tuple[str, str, str]:
        """Split ``shell_str`` on the last shell operator.

        Returns ``(prefix, op, last_cmd)``. For ``"a && b || c"`` returns
        ``("a && b", " || ", "c")``. For a string with no operator returns
        ``("", "", shell_str)``.
        """
        best, best_op = -1, ""
        for op in cls._OPS:
            idx = shell_str.rfind(op)
            if idx > best:
                best, best_op = idx, op
        if best == -1:
            return "", "", shell_str.strip()
        return shell_str[:best], best_op, shell_str[best + len(best_op):].strip()


# Registry, tried in order. Mutually exclusive in practice (a command invokes one
# runner), so order only decides ties that cannot occur today. Add a runner by
# appending its adapter here. ShellAdapter is last: it matches only the sh/-c
# wrapper and delegates to the inner adapters above.
ADAPTERS: tuple[RunnerAdapter, ...] = (*_INNER_ADAPTERS, ShellAdapter())


def instrument_command(cmd: list[str], report_path: str) -> tuple[list[str], bool, dict[str, str]]:
    """Wire a judge-owned JUnit reporter into ``cmd`` for the first matching adapter.

    Returns ``(command, report_expected, report_env)``. ``report_expected`` is
    ``True`` when a reporter was wired in (so a later missing/unparseable report
    means *no trustworthy verdict* — see
    :func:`evoom_guard.verifiers.repo_verifier.grade_repo_run`), and ``False`` for an
    unknown runner, or a recognised one that already has a reporter configured (the
    verdict then grades on the exit code alone). ``report_env`` carries any extra
    environment a runner needs to point its reporter at ``report_path`` (jest's
    ``jest-junit`` has no CLI option for it); it is ``{}`` for runners that take the
    path as a flag, and the caller MUST merge it into the suite's environment.
    """
    for adapter in ADAPTERS:
        if adapter.matches(cmd):
            instrumented = adapter.instrument(cmd, report_path)
            if instrumented is not None:
                env_fn = getattr(adapter, "report_env", None)
                report_env: dict[str, str] = env_fn(report_path) if env_fn else {}
                return instrumented, True, report_env
            return list(cmd), False, {}
    return list(cmd), False, {}
