"""Emit a deterministic public characterization of the CLI parser.

Run directly with::

    python tests/cli_parser_characterization_harness.py

The snapshot intentionally records parser structure, every top-level
subcommand's help output, representative defaults, immutable-release parsing,
and the existing live helper lookup seam.  It is a behavior contract for
parser-owner extraction, not a new CLI specification.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evoom_guard import cli  # noqa: E402


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _callable_name(value: object) -> str:
    module = getattr(value, "__module__", "")
    qualname = getattr(value, "__qualname__", getattr(value, "__name__", ""))
    return f"{module}.{qualname}".strip(".")


def _normalize(value: object) -> object:
    if value == argparse.SUPPRESS:
        return "<SUPPRESS>"
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        return {
            str(key): _normalize(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    if callable(value):
        return {"callable": _callable_name(value)}
    return {"type": f"{type(value).__module__}.{type(value).__qualname__}"}


def _action_contract(action: argparse.Action) -> dict[str, object]:
    contract: dict[str, object] = {
        "class": type(action).__name__,
        "option_strings": list(action.option_strings),
        "dest": action.dest,
        "nargs": _normalize(action.nargs),
        "const": _normalize(action.const),
        "default": _normalize(action.default),
        "type": _normalize(action.type),
        "choices": (
            sorted(action.choices)
            if action.choices is not None
            and not isinstance(action, argparse._SubParsersAction)
            else None
        ),
        "required": action.required,
        "help": _normalize(action.help),
        "metavar": _normalize(action.metavar),
    }
    if isinstance(action, argparse._SubParsersAction):
        contract["subparsers"] = {
            name: _parser_contract(subparser)
            for name, subparser in sorted(action.choices.items())
        }
    return contract


def _parser_contract(parser: argparse.ArgumentParser) -> dict[str, object]:
    return {
        "prog": parser.prog,
        "description": parser.description,
        "epilog": parser.epilog,
        "prefix_chars": parser.prefix_chars,
        "fromfile_prefix_chars": parser.fromfile_prefix_chars,
        "argument_default": _normalize(parser.argument_default),
        "allow_abbrev": parser.allow_abbrev,
        "conflict_handler": parser.conflict_handler,
        "actions": [_action_contract(action) for action in parser._actions],
        "action_groups": [
            {
                "title": group.title,
                "description": group.description,
                "actions": [action.dest for action in group._group_actions],
            }
            for group in parser._action_groups
        ],
        "mutually_exclusive_groups": [
            {
                "required": group.required,
                "actions": [action.dest for action in group._group_actions],
            }
            for group in parser._mutually_exclusive_groups
        ],
    }


def _subcommands(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return dict(sorted(action.choices.items()))
    raise AssertionError("CLI parser has no subcommand action")


def _help_text(parser: argparse.ArgumentParser, argv: Sequence[str]) -> str:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            parser.parse_args([*argv, "--help"])
        except SystemExit as exc:
            if exc.code != 0:
                raise AssertionError(f"help exited with {exc.code}: {argv!r}") from exc
        else:
            raise AssertionError(f"help did not exit: {argv!r}")
    assert stderr.getvalue() == ""
    return stdout.getvalue()


def _parse_error(parser: argparse.ArgumentParser, argv: Sequence[str]) -> dict[str, object]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            parser.parse_args(list(argv))
        except SystemExit as exc:
            code = exc.code
        else:
            raise AssertionError(f"invalid vector unexpectedly parsed: {argv!r}")
    return {
        "argv": list(argv),
        "exit_code": code,
        "stdout_sha256": _sha256_text(stdout.getvalue()),
        "stderr_sha256": _sha256_text(stderr.getvalue()),
    }


def _live_helper_contract() -> dict[str, object]:
    names = (
        "_add_github_attestation_policy_arguments",
        "_add_github_attestation_verifier_arguments",
        "_add_release_artifact_key_registry_arguments",
        "_add_nested_release_source_expectation_arguments",
    )
    originals: dict[str, Callable[[argparse.ArgumentParser], None]] = {}
    observed: dict[str, list[str]] = {name: [] for name in names}
    for name in names:
        original = getattr(cli, name)
        originals[name] = original

        def wrapper(
            parser: argparse.ArgumentParser,
            *,
            _name: str = name,
            _original: Callable[[argparse.ArgumentParser], None] = original,
        ) -> None:
            observed[_name].append(parser.prog)
            _original(parser)

        setattr(cli, name, wrapper)

    original_ref = cli._immutable_release_ref
    ref_calls: list[str] = []

    def immutable_release_ref(value: object) -> str:
        ref_calls.append(str(value))
        return original_ref(value)

    cli._immutable_release_ref = immutable_release_ref
    try:
        parser = cli.build_parser()
        parsed = parser.parse_args(["init", "--ref", "v4.3.0"])
    finally:
        cli._immutable_release_ref = original_ref
        for name, original in originals.items():
            setattr(cli, name, original)

    return {
        "helper_calls": observed,
        "immutable_ref_calls": ref_calls,
        "parsed_ref": parsed.ref,
    }


def snapshot() -> dict[str, object]:
    parser = cli.build_parser()
    subcommands = _subcommands(parser)
    structure = json.dumps(
        _parser_contract(parser),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    parse_vectors = {
        "guard_defaults": _normalize(vars(parser.parse_args(["guard"]))),
        "doctor_defaults": _normalize(vars(parser.parse_args(["doctor"]))),
        "init_valid_ref": _normalize(
            vars(parser.parse_args(["init", "--ref", "v4.3.0"]))
        ),
        "version": _normalize(vars(parser.parse_args(["version"]))),
    }
    return {
        "schema": 1,
        "program": parser.prog,
        "subcommand_count": len(subcommands),
        "subcommands": list(subcommands),
        "structure_sha256": _sha256_text(structure),
        "root_help_sha256": _sha256_text(_help_text(parser, [])),
        "subcommand_help_sha256": {
            name: _sha256_text(_help_text(parser, [name])) for name in subcommands
        },
        "parse_vectors": parse_vectors,
        "invalid_immutable_ref": _parse_error(
            parser,
            ["init", "--ref", "main"],
        ),
        "live_helper_contract": _live_helper_contract(),
    }


if __name__ == "__main__":
    print(json.dumps(snapshot(), ensure_ascii=False, indent=2, sort_keys=True))
