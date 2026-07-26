"""Compatibility contracts for the ``adapters`` to ``runners`` extraction."""

from __future__ import annotations

import inspect

import evoom_guard.adapters as legacy
import evoom_guard.runners as runners
import evoom_guard.runners._command as command_grammar
import evoom_guard.runners.adapters as concrete
import evoom_guard.runners.gotestsum as gotestsum_owner
import evoom_guard.runners.jest as jest_owner
import evoom_guard.runners.maven as maven_owner
import evoom_guard.runners.mocha as mocha_owner
import evoom_guard.runners.node_test as node_test_owner
import evoom_guard.runners.protocol as protocol
import evoom_guard.runners.pytest as pytest_owner
import evoom_guard.runners.registry as registry
import evoom_guard.runners.rspec as rspec_owner
import evoom_guard.runners.shell as shell_owner
import evoom_guard.runners.vitest as vitest_owner

OWNER_CLASSES = {
    "GotestsumAdapter": gotestsum_owner.GotestsumAdapter,
    "JestAdapter": jest_owner.JestAdapter,
    "MavenAdapter": maven_owner.MavenAdapter,
    "MochaAdapter": mocha_owner.MochaAdapter,
    "NodeTestAdapter": node_test_owner.NodeTestAdapter,
    "PytestAdapter": pytest_owner.PytestAdapter,
    "RspecAdapter": rspec_owner.RspecAdapter,
    "ShellAdapter": shell_owner.ShellAdapter,
    "VitestAdapter": vitest_owner.VitestAdapter,
}
PUBLIC_CLASSES = tuple(OWNER_CLASSES)


def test_legacy_facade_reexports_exact_owner_objects() -> None:
    assert legacy.RunnerAdapter is runners.RunnerAdapter is protocol.RunnerAdapter
    for name, owner_class in OWNER_CLASSES.items():
        assert (
            getattr(legacy, name)
            is getattr(runners, name)
            is getattr(concrete, name)
            is owner_class
        )
        assert owner_class.__module__ not in {
            legacy.__name__,
            concrete.__name__,
            runners.__name__,
        }
    assert legacy.ADAPTERS is runners.ADAPTERS is registry.ADAPTERS
    assert inspect.signature(legacy.instrument_command) == inspect.signature(
        registry.instrument_command
    )


def test_legacy_wildcard_surface_remains_complete() -> None:
    namespace: dict[str, object] = {}
    exec("from evoom_guard.adapters import *", namespace)

    assert {
        "ADAPTERS",
        "Protocol",
        "RunnerAdapter",
        "instrument_command",
        "ntpath",
        "re",
        "runtime_checkable",
        "shlex",
        *PUBLIC_CLASSES,
    } <= set(namespace)


def test_combined_runner_facade_retains_its_exact_wildcard_surface() -> None:
    namespace: dict[str, object] = {}
    exec("from evoom_guard.runners.adapters import *", namespace)

    assert set(namespace) - {"__builtins__"} == set(PUBLIC_CLASSES)
    assert concrete.__all__ == list(PUBLIC_CLASSES)
    assert concrete.RunnerAdapter is protocol.RunnerAdapter
    assert concrete.Sequence is shell_owner.Sequence


def test_legacy_private_detection_helpers_remain_exact_aliases() -> None:
    helper_names = (
        "_executable_name",
        "_invokes_python_module",
        "_invokes_runner",
        "_is_python_executable",
        "_option_value_end",
        "_wrapped_command_index",
    )

    for name in helper_names:
        assert (
            getattr(legacy, name)
            is getattr(concrete, name)
            is getattr(command_grammar, name)
        )
    assert legacy.ntpath is concrete.ntpath is command_grammar.ntpath
    assert legacy.re is concrete.re is command_grammar.re
    assert legacy.shlex is concrete.shlex is shell_owner.shlex
    assert legacy.Protocol is protocol.Protocol
    assert legacy.runtime_checkable is protocol.runtime_checkable


def test_owner_modules_resolve_the_shared_command_grammar_live(monkeypatch) -> None:
    monkeypatch.setattr(
        command_grammar,
        "_invokes_runner",
        lambda cmd, runner: cmd == ["synthetic"] and runner == "vitest",
    )

    assert vitest_owner.VitestAdapter().matches(["synthetic"]) is True


def test_legacy_registry_monkeypatch_is_resolved_at_call_time(monkeypatch) -> None:
    class FakeAdapter:
        name = "fake"

        def matches(self, cmd: list[str]) -> bool:
            return cmd == ["fake"]

        def instrument(self, cmd: list[str], report_path: str) -> list[str]:
            return [*cmd, f"--report={report_path}"]

        def report_env(self, report_path: str) -> dict[str, str]:
            return {"FAKE_REPORT": report_path}

    monkeypatch.setattr(legacy, "ADAPTERS", (FakeAdapter(),))

    assert legacy.instrument_command(["fake"], "/judge.xml") == (
        ["fake", "--report=/judge.xml"],
        True,
        {"FAKE_REPORT": "/judge.xml"},
    )


def test_legacy_shell_inner_registry_monkeypatch_remains_live(monkeypatch) -> None:
    class InnerAdapter:
        name = "inner"

        def matches(self, cmd: list[str]) -> bool:
            return cmd == ["inner"]

        def instrument(self, cmd: list[str], report_path: str) -> list[str]:
            return [*cmd, f"--report={report_path}"]

    monkeypatch.setattr(legacy, "ADAPTERS", (legacy.ShellAdapter(),))
    monkeypatch.setattr(legacy, "_INNER_ADAPTERS", (InnerAdapter(),))

    assert legacy.instrument_command(["sh", "-c", "inner"], "/judge.xml") == (
        ["sh", "-c", "inner --report=/judge.xml"],
        True,
        {},
    )


def test_owner_registry_monkeypatch_is_resolved_at_call_time(monkeypatch) -> None:
    class UnknownAdapter:
        name = "unknown"

        def matches(self, cmd: list[str]) -> bool:
            return False

        def instrument(self, cmd: list[str], report_path: str) -> list[str]:
            raise AssertionError("an unmatched adapter must not be called")

    monkeypatch.setattr(registry, "ADAPTERS", (UnknownAdapter(),))

    assert registry.instrument_command(["other"], "/judge.xml") == (
        ["other"],
        False,
        {},
    )


def test_owner_shell_inner_registry_monkeypatch_is_resolved_live(monkeypatch) -> None:
    class InnerAdapter:
        name = "inner"

        def matches(self, cmd: list[str]) -> bool:
            return cmd == ["inner"]

        def instrument(self, cmd: list[str], report_path: str) -> list[str]:
            return [*cmd, f"--report={report_path}"]

    monkeypatch.setattr(registry, "ADAPTERS", (shell_owner.ShellAdapter(),))
    monkeypatch.setattr(registry, "INNER_ADAPTERS", (InnerAdapter(),))

    assert registry.instrument_command(["sh", "-c", "inner"], "/judge.xml") == (
        ["sh", "-c", "inner --report=/judge.xml"],
        True,
        {},
    )
