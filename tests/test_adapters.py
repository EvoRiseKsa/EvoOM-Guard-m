# ─────────────────────────────────────────────────────────────────────────────
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# ─────────────────────────────────────────────────────────────────────────────
"""Per-runner report adapters (owned by ``evoom_guard.runners``).

Pure, offline tests for the command-instrumentation registry: each adapter's
``matches`` / ``instrument`` and the legacy ``evoom_guard.adapters`` dispatch.
The actual JUnit reading is covered by ``parse_junit_xml`` tests; the end-to-end
runs live in ``test_node_oracle.py`` / ``test_vitest_oracle.py``.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evoom_guard.adapters import (
    ADAPTERS,
    GotestsumAdapter,
    JestAdapter,
    MavenAdapter,
    MochaAdapter,
    NodeTestAdapter,
    PytestAdapter,
    RspecAdapter,
    ShellAdapter,
    VitestAdapter,
    instrument_command,
)


# ───────────────────────────── pytest adapter ─────────────────────────────────
def test_pytest_matches_and_instruments():
    a = PytestAdapter()
    assert a.matches(["pytest", "-q"])
    assert a.matches([sys.executable, "-m", "pytest"])
    assert a.matches(["py.exe", "-m", "pytest"])
    assert a.matches(["uv", "run", "python3.12", "-m", "pytest"])
    assert not a.matches(["node", "--test"])
    assert not a.matches(["python", "build_pytest_report.py"])
    assert not a.matches(["python-malicious", "-m", "pytest"])
    assert not a.matches(["vitest", "run", "tests/pytest-regression.test.ts"])
    assert a.instrument(["pytest", "-q"], "/x.xml") == [
        "pytest", "-q", "--junitxml=/x.xml", "-o", "junit_family=xunit2",
    ]


# ───────────────────────────── node --test adapter ────────────────────────────
def test_node_matches():
    a = NodeTestAdapter()
    assert a.matches(["node", "--test", "f.mjs"])
    assert a.matches(["/opt/node22/bin/node", "--test"])
    assert not a.matches(["npm", "test"])        # script wrapper, not node --test
    assert not a.matches(["node", "script.js"])  # no --test
    assert not a.matches(["pytest", "-q"])


def test_node_instrument_splices_before_files():
    cmd = NodeTestAdapter().instrument(["node", "--test", "a.test.mjs"], "/x.xml")
    assert cmd is not None
    # reporter flags must precede the positional file (node ignores trailing ones)
    assert cmd.index("--test-reporter=junit") < cmd.index("a.test.mjs")
    assert "--test-reporter-destination=/x.xml" in cmd
    assert "--test-reporter-destination=stdout" in cmd  # diagnostics still reach stdout


def test_node_declines_when_reporter_present():
    assert NodeTestAdapter().instrument(
        ["node", "--test", "--test-reporter=tap", "a.test.mjs"], "/x.xml"
    ) is None


# ───────────────────────────── vitest adapter ─────────────────────────────────
def test_vitest_matches():
    a = VitestAdapter()
    assert a.matches(["vitest", "run"])
    assert a.matches(["npx", "vitest", "run"])
    assert a.matches(["pnpm", "run", "vitest"])
    assert a.matches(["yarn", "run", "vitest"])
    assert a.matches(["/opt/node22/bin/vitest", "run"])
    assert a.matches(["node_modules/.bin/vitest", "run"])
    assert not a.matches(["node", "--test"])
    assert not a.matches(["pytest", "-q"])


def test_vitest_instrument_appends_file_and_stdout_reporters():
    assert VitestAdapter().instrument(["vitest", "run"], "/x.xml") == [
        "vitest", "run", "--reporter=default", "--reporter=junit", "--outputFile=/x.xml",
    ]


def test_vitest_declines_when_reporter_present():
    assert VitestAdapter().instrument(["vitest", "run", "--reporter=verbose"], "/x") is None
    assert VitestAdapter().instrument(["vitest", "run", "--outputFile=o.xml"], "/x") is None


# ───────────────────────────── jest adapter ───────────────────────────────────
def test_jest_matches():
    a = JestAdapter()
    assert a.matches(["jest"])
    assert a.matches(["npx", "jest"])
    assert a.matches(["/opt/node22/bin/jest"])
    assert a.matches(["node_modules/.bin/jest"])
    assert a.matches(["pnpm", "--filter", "@pkg", "exec", "jest"])
    assert not a.matches(["vitest", "run"])      # basename 'vitest' != 'jest'
    assert not a.matches(["node", "--test"])
    assert not a.matches(["pytest", "-q"])


def test_jest_instrument_appends_reporters():
    # jest takes the output *path* from the environment (report_env), not a flag,
    # so instrument only selects the reporters (keeping default on stdout).
    assert JestAdapter().instrument(["jest"], "/x.xml") == [
        "jest", "--reporters=default", "--reporters=jest-junit",
    ]


def test_jest_report_env_carries_output_path():
    assert JestAdapter().report_env("/out/judge-result.xml") == {
        "JEST_JUNIT_OUTPUT_FILE": "/out/judge-result.xml",
    }


def test_jest_declines_when_reporters_present():
    assert JestAdapter().instrument(["jest", "--reporters=jest-junit"], "/x") is None
    assert JestAdapter().instrument(["jest", "--reporters=default"], "/x") is None


# ───────────────────────────── gotestsum (Go) adapter ────────────────────────
def test_gotestsum_matches():
    a = GotestsumAdapter()
    assert a.matches(["gotestsum", "--", "./..."])
    assert a.matches(["/usr/local/bin/gotestsum"])
    assert not a.matches(["go", "test", "./..."])   # bare go test = stdout-only, unsupported
    assert not a.matches(["pytest", "-q"])


def test_gotestsum_inserts_before_separator():
    cmd = GotestsumAdapter().instrument(["gotestsum", "--", "./..."], "/x.xml")
    assert cmd == ["gotestsum", "--junitfile=/x.xml", "--", "./..."]


def test_gotestsum_appends_when_no_separator():
    cmd = GotestsumAdapter().instrument(["gotestsum"], "/x.xml")
    assert cmd == ["gotestsum", "--junitfile=/x.xml"]


def test_gotestsum_declines_when_junitfile_present():
    assert GotestsumAdapter().instrument(["gotestsum", "--junitfile=o.xml"], "/x") is None


# ───────────────────────────── rspec (Ruby) adapter ──────────────────────────
def test_rspec_matches():
    a = RspecAdapter()
    assert a.matches(["rspec"])
    assert a.matches(["bundle", "exec", "rspec"])
    assert a.matches(["/usr/local/bin/rspec", "spec/"])
    assert not a.matches(["pytest", "-q"])


def test_rspec_instrument_appends_junit_and_progress():
    cmd = RspecAdapter().instrument(["rspec", "spec/"], "/x.xml")
    assert cmd == [
        "rspec", "spec/",
        "--format", "progress",
        "--format", "RspecJunitFormatter", "--out", "/x.xml",
    ]


def test_rspec_declines_when_formatter_present():
    assert RspecAdapter().instrument(["rspec", "--format", "doc"], "/x") is None
    assert RspecAdapter().instrument(["rspec", "-f", "doc"], "/x") is None
    assert RspecAdapter().instrument(["rspec", "--out", "o.xml"], "/x") is None


# ───────────────────────────── mocha (JS) adapter ────────────────────────────
def test_mocha_matches():
    a = MochaAdapter()
    assert a.matches(["mocha"])
    assert a.matches(["npx", "mocha", "test/"])
    assert a.matches(["node_modules/.bin/mocha"])
    assert not a.matches(["vitest", "run"])
    assert not a.matches(["jest"])


def test_mocha_instrument_appends_junit_reporter():
    cmd = MochaAdapter().instrument(["mocha", "test/"], "/x.xml")
    assert cmd == [
        "mocha", "test/",
        "--reporter", "mocha-junit-reporter",
        "--reporter-options", "mochaFile=/x.xml",
    ]


def test_mocha_declines_when_reporter_present():
    assert MochaAdapter().instrument(["mocha", "--reporter", "spec"], "/x") is None
    assert MochaAdapter().instrument(["mocha", "-R", "dot"], "/x") is None


# ───────────────────────────── maven (Java) adapter ──────────────────────────
def test_maven_matches():
    a = MavenAdapter()
    assert a.matches(["mvn", "test"])
    assert a.matches(["./mvnw", "test"])
    assert a.matches(["/usr/bin/mvn", "-q", "test"])
    assert not a.matches(["gradle", "test"])
    assert not a.matches(["pytest", "-q"])


def test_maven_instrument_redirects_reports_dir():
    cmd = MavenAdapter().instrument(["mvn", "test"], "/out/judge-result.xml")
    assert cmd == ["mvn", "test", "-Dsurefire.reportsDirectory=/out/judge-result.xml.d"]


def test_maven_declines_when_reports_dir_present():
    assert MavenAdapter().instrument(
        ["mvn", "test", "-Dsurefire.reportsDirectory=x"], "/out/r.xml"
    ) is None


# ───────────────────────────── ShellAdapter ───────────────────────────────────
def test_shell_adapter_matches():
    a = ShellAdapter()
    assert a.matches(["sh", "-c", "vitest run"])
    assert a.matches(["bash", "-c", "pytest -q"])
    assert a.matches(["/bin/sh", "-c", "node --test src/"])
    assert not a.matches(["sh", "script.sh"])     # no -c flag
    assert not a.matches(["vitest", "run"])        # not a shell
    assert not a.matches(["sh", "-c"])             # too short (no shell string arg)


def test_shell_adapter_instruments_vitest():
    a = ShellAdapter()
    cmd = ["sh", "-c", "pnpm install --frozen-lockfile && vitest run"]
    result = a.instrument(cmd, "/x.xml")
    assert result is not None
    assert result[0] == "sh" and result[1] == "-c"
    shell_str = result[2]
    assert "pnpm install --frozen-lockfile" in shell_str
    assert "--reporter=junit" in shell_str
    assert "--outputFile=/x.xml" in shell_str


def test_shell_adapter_instruments_pytest():
    a = ShellAdapter()
    result = a.instrument(["sh", "-c", "pytest -q"], "/x.xml")
    assert result is not None
    assert "--junitxml=/x.xml" in result[2]


def test_shell_adapter_instruments_node_test():
    a = ShellAdapter()
    result = a.instrument(["bash", "-c", "node --test src/"], "/x.xml")
    assert result is not None
    assert "--test-reporter=junit" in result[2]


def test_shell_adapter_instruments_jest_inlines_env():
    a = ShellAdapter()
    result = a.instrument(["sh", "-c", "pnpm install && jest"], "/out/j.xml")
    assert result is not None
    shell_str = result[2]
    assert shell_str.startswith("pnpm install")             # prefix intact
    assert "--reporters=jest-junit" in shell_str            # reporter selected
    # the env path is baked into the shell string (no separate env for sh -c)
    assert "JEST_JUNIT_OUTPUT_FILE=/out/j.xml" in shell_str


def test_shell_adapter_returns_none_for_unknown_runner():
    a = ShellAdapter()
    assert a.instrument(["sh", "-c", "make test"], "/x.xml") is None


def test_shell_adapter_split_last_cmd():
    a = ShellAdapter()
    assert a._split_last_cmd("a && b") == ("a", " && ", "b")
    assert a._split_last_cmd("a && b && c") == ("a && b", " && ", "c")
    assert a._split_last_cmd("a; b || c") == ("a; b", " || ", "c")
    assert a._split_last_cmd("vitest run") == ("", "", "vitest run")
    assert a._split_last_cmd("pytest -k 'a && b'") == ("", "", "pytest -k 'a && b'")
    assert a._split_last_cmd(r"pytest -k a\;\ b") == ("", "", r"pytest -k a\;\ b")


def test_shell_adapter_declines_when_inner_already_has_reporter():
    a = ShellAdapter()
    assert a.instrument(["sh", "-c", "vitest run --reporter=verbose"], "/x.xml") is None


def test_shell_adapter_prefix_preserved_after_instrument():
    a = ShellAdapter()
    result = a.instrument(["sh", "-c", "pnpm install && pnpm --filter @pkg vitest run"], "/r.xml")
    assert result is not None
    shell_str = result[2]
    # prefix segment is intact
    assert shell_str.startswith("pnpm install")
    # the last segment got the reporters injected
    assert "--reporter=junit" in shell_str
    assert "--outputFile=/r.xml" in shell_str


# ───────────────────────────── registry dispatch ─────────────────────────────
def test_instrument_command_dispatches_per_runner():
    cmd, exp, env = instrument_command(["pytest", "-q"], "/x.xml")
    assert exp is True and "--junitxml=/x.xml" in cmd and env == {}
    cmd, exp, env = instrument_command(["node", "--test", "a.mjs"], "/x.xml")
    assert exp is True and "--test-reporter=junit" in cmd and env == {}
    cmd, exp, env = instrument_command(["vitest", "run"], "/x.xml")
    assert exp is True and "--outputFile=/x.xml" in cmd and env == {}
    cmd, exp, env = instrument_command(["sh", "-c", "vitest run"], "/x.xml")
    assert exp is True and "--outputFile=/x.xml" in cmd[2] and env == {}


def test_registry_instruments_pytest_inside_shell_string():
    cmd, expected, env = instrument_command(["sh", "-c", "pytest -q"], "/judge/result.xml")

    assert expected is True
    assert cmd[:2] == ["sh", "-c"]
    assert len(cmd) == 3
    assert "--junitxml=/judge/result.xml" in cmd[2]
    assert env == {}


def test_shell_instrumentation_preserves_expansion_globbing_and_redirection():
    original = 'pytest "$TEST_TARGET" tests/*.py 2>&1'

    cmd, expected, env = instrument_command(
        ["sh", "-c", original],
        "/judge/result.xml",
    )

    assert expected is True
    assert cmd[2].startswith(original + " ")
    assert '"$TEST_TARGET"' in cmd[2]
    assert "tests/*.py" in cmd[2]
    assert "--junitxml=/judge/result.xml" in cmd[2]
    assert env == {}


def test_shell_pipeline_instruments_only_a_safe_final_runner_segment():
    untouched = ["sh", "-c", "pytest -q | tee results.log"]
    cmd, expected, env = instrument_command(untouched, "/judge/result.xml")
    assert expected is False
    assert cmd == untouched
    assert env == {}

    cmd, expected, env = instrument_command(
        ["sh", "-c", "printf ready | pytest -q"],
        "/judge/result.xml",
    )
    assert expected is True
    assert cmd[2].startswith("printf ready | pytest -q ")
    assert "--junitxml=/judge/result.xml" in cmd[2]
    assert env == {}


def test_shell_declines_token_reordering_when_expansion_must_be_preserved():
    for shell_command in (
        'node --test "$TEST_FILE"',
        'gotestsum -- "$GO_PATTERN"',
    ):
        original = ["sh", "-c", shell_command]
        cmd, expected, env = instrument_command(original, "/judge/result.xml")
        assert expected is False
        assert cmd == original
        assert env == {}


def test_registry_does_not_select_pytest_from_argument_substrings():
    vitest, expected, env = instrument_command(
        ["vitest", "run", "tests/pytest-regression.test.ts"],
        "/judge/result.xml",
    )
    assert expected is True
    assert "--outputFile=/judge/result.xml" in vitest
    assert "--junitxml=/judge/result.xml" not in vitest
    assert env == {}

    python = ["python", "build_pytest_report.py"]
    untouched, expected, env = instrument_command(python, "/judge/result.xml")
    assert expected is False
    assert untouched == python
    assert env == {}


def test_registry_recognises_windows_executable_paths():
    node, expected, env = instrument_command(
        [r"C:\Program Files\nodejs\node.exe", "--test", "test.mjs"],
        r"C:\judge\result.xml",
    )
    assert expected is True
    assert "--test-reporter=junit" in node
    assert env == {}

    vitest, expected, env = instrument_command(
        [r"C:\repo\node_modules\.bin\vitest.cmd", "run"],
        r"C:\judge\result.xml",
    )
    assert expected is True
    assert r"--outputFile=C:\judge\result.xml" in vitest
    assert env == {}


def test_instrument_command_jest_returns_reporter_env():
    # jest carries its output path in report_env (no CLI flag); the caller merges it.
    cmd, exp, env = instrument_command(["jest"], "/x.xml")
    assert exp is True
    assert cmd == ["jest", "--reporters=default", "--reporters=jest-junit"]
    assert env == {"JEST_JUNIT_OUTPUT_FILE": "/x.xml"}


def test_instrument_command_unknown_runner_untouched():
    cmd, exp, env = instrument_command(["make", "test"], "/x.xml")
    assert exp is False and cmd == ["make", "test"] and env == {}


def test_instrument_command_matched_but_reporter_present_is_not_expected():
    base = ["node", "--test", "--test-reporter=tap", "a.test.mjs"]
    cmd, exp, env = instrument_command(base, "/x.xml")
    assert exp is False and cmd == base and env == {}


def test_instrument_command_dispatches_new_runners():
    cmd, exp, env = instrument_command(["gotestsum", "--", "./..."], "/x.xml")
    assert exp is True and "--junitfile=/x.xml" in cmd and env == {}
    cmd, exp, env = instrument_command(["rspec", "spec/"], "/x.xml")
    assert exp is True and "--out" in cmd and "/x.xml" in cmd and env == {}
    cmd, exp, env = instrument_command(["mocha", "test/"], "/x.xml")
    assert exp is True and "mochaFile=/x.xml" in cmd and env == {}
    cmd, exp, env = instrument_command(["mvn", "test"], "/x.xml")
    assert exp is True and "-Dsurefire.reportsDirectory=/x.xml.d" in cmd and env == {}


def test_registry_has_all_runners():
    assert {a.name for a in ADAPTERS} == {
        "pytest", "node --test", "vitest", "jest",
        "gotestsum", "rspec", "mocha", "maven", "sh -c",
    }


def test_pytest_append_wins_over_candidate_supplied_junitxml():
    # pytest honors the LAST --junitxml, so the judge-owned path must be
    # appended AFTER any candidate-supplied reporter and grading must stay
    # structured. Guarding with "reporter present -> None" here would downgrade
    # to exit-code-only — the reward-hack-friendly direction.
    base = ["pytest", "--junitxml=/attacker/own.xml", "-q"]
    cmd, exp, env = instrument_command(base, "/judge/report.xml")
    assert exp is True and env == {}
    junit_flags = [item for item in cmd if item.startswith("--junitxml=")]
    assert junit_flags[-1] == "--junitxml=/judge/report.xml"
    assert cmd.index("--junitxml=/judge/report.xml") > cmd.index(
        "--junitxml=/attacker/own.xml"
    )


def test_pytest_module_form_append_wins_over_candidate_junitxml():
    base = ["python", "-m", "pytest", "--junitxml=own.xml"]
    cmd, exp, env = instrument_command(base, "/judge/report.xml")
    assert exp is True and env == {}
    junit_flags = [item for item in cmd if item.startswith("--junitxml=")]
    assert junit_flags[-1] == "--junitxml=/judge/report.xml"
