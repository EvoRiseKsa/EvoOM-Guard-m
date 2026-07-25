"""Deterministic characterization of the public ``init`` CLI command.

The vector freezes workflow bytes, policy projection, effect and failure
order, callable-before-argument evaluation, and the historical live-lookup
seams before the command owner is extracted. It uses a small in-memory
filesystem so the reviewed result is platform-independent.
"""

from __future__ import annotations

import argparse
import json
import posixpath
from typing import Any

from evoom_guard import cli

_POSIX_BASENAME = posixpath.basename
_POSIX_DIRNAME = posixpath.dirname
_POSIX_JOIN = posixpath.join

SCHEMA_VERSION = "cli-init-command-characterization-v1"
CASE_NAMES = (
    "conventional_final_dirname_rebinds_join",
    "custom_path_existing_policy",
    "existing_workflow_refused",
    "explicit_policy_path",
    "fallback_getcwd_rebinds_join",
    "filesystem_midcall_rebinding",
    "force_overwrite_inferred_policy",
    "json_dump_failure",
    "policy_exit_failure",
    "policy_write_failure",
    "private_invalid_secret",
    "private_midcall_rebinding",
    "private_stdout_custom_secret",
    "property_credential_rebinds_provider",
    "property_ref_rebinds_provider",
    "property_test_command_rebinds_provider",
    "public_ignores_invalid_secret",
    "public_stdout",
    "workflow_exit_failure",
    "workflow_open_failure",
    "workflow_write_failure",
)


def canonical_json(value: Any) -> str:
    """Return the stable human-reviewable vector encoding."""

    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


class _MemoryWriter:
    """Minimal text context manager used by the in-memory filesystem."""

    def __init__(
        self,
        path: str,
        *,
        files: dict[str, str],
        events: list[dict[str, object]],
        write_failure: str | None = None,
        exit_failure: str | None = None,
    ) -> None:
        self._path = path
        self._files = files
        self._events = events
        self._write_failure = write_failure
        self._exit_failure = exit_failure

    def __enter__(self) -> _MemoryWriter:
        self._events.append({"op": "enter", "path": self._path})
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> bool:
        del exc, traceback
        self._events.append(
            {
                "op": "exit",
                "path": self._path,
                "exception": exc_type.__name__ if exc_type is not None else None,
                "characters": len(self._files.get(self._path, "")),
            }
        )
        if self._exit_failure is not None:
            raise OSError(self._exit_failure)
        return False

    def write(self, value: str) -> int:
        if self._write_failure is not None:
            raise OSError(self._write_failure)
        self._files[self._path] = self._files.get(self._path, "") + value
        return len(value)


class _SideEffectNamespace(argparse.Namespace):
    """Namespace whose selected property reads perform one deterministic effect."""

    def __getattribute__(self, name: str) -> object:
        namespace = object.__getattribute__(self, "__dict__")
        side_effects = namespace.get("_property_side_effects", {})
        side_effect = side_effects.pop(name, None)
        if side_effect is not None:
            side_effect()
        return super().__getattribute__(name)


def _args_for(case_name: str) -> argparse.Namespace:
    args = _SideEffectNamespace(
        force=False,
        github_actions_credential_key="EVOGUARD_TOKEN",
        path="/repo/.github/workflows/evoguard.yml",
        policy_path=None,
        private_evoguard=False,
        ref="v9.9.9",
        stdout=False,
        test_command="python -m pytest -q",
    )
    args._property_side_effects = {}
    if case_name == "custom_path_existing_policy":
        args.path = "/repo/custom/guard.yml"
    elif case_name == "explicit_policy_path":
        args.policy_path = "/trusted/policy.json"
    elif case_name == "fallback_getcwd_rebinds_join":
        args.path = "guard.yml"
    elif case_name == "force_overwrite_inferred_policy":
        args.force = True
        args.test_command = "pytest -q app/"
    elif case_name in {
        "private_invalid_secret",
        "private_midcall_rebinding",
        "private_stdout_custom_secret",
    }:
        args.private_evoguard = True
        args.stdout = True
        args.github_actions_credential_key = (
            "bad-name" if case_name == "private_invalid_secret" else "CUSTOM_PAT"
        )
    elif case_name == "property_credential_rebinds_provider":
        args.private_evoguard = True
        args.stdout = True
        args.github_actions_credential_key = "CUSTOM_PAT"
    elif case_name == "property_ref_rebinds_provider":
        args.stdout = True
    elif case_name == "public_ignores_invalid_secret":
        args.stdout = True
        args.github_actions_credential_key = "bad-name"
    elif case_name == "public_stdout":
        args.stdout = True
    return args


def capture_case(case_name: str) -> dict[str, object]:
    """Capture one command through its historical public facade."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown init characterization case: {case_name}")

    args = _args_for(case_name)
    events: list[dict[str, object]] = []
    files: dict[str, str] = {}
    messages: list[str] = []
    exception: dict[str, str] | None = None
    exit_code: int | None = None
    missing = object()
    original_open = getattr(cli, "open", missing)
    originals = {
        "abspath": cli.os.path.abspath,
        "basename": cli.os.path.basename,
        "credential": cli._github_actions_credential_key,
        "default_policy": cli._default_policy_path,
        "dirname": cli.os.path.dirname,
        "dump": cli.json.dump,
        "exists": cli.os.path.exists,
        "getcwd": cli.os.getcwd,
        "join": cli.os.path.join,
        "makedirs": cli.os.makedirs,
        "private_workflow": cli._workflow_yaml_private,
        "public_workflow": cli._workflow_yaml,
    }

    def absolute_path(path: str) -> str:
        events.append({"op": "abspath", "path": path})
        if case_name == "fallback_getcwd_rebinds_join":
            return path
        return path if path.startswith("/") else f"/cwd/{path}"

    def base_name(path: str) -> str:
        events.append({"op": "basename", "path": path})
        return _POSIX_BASENAME(path)

    def directory_name(path: str) -> str:
        event: dict[str, object] = {"op": "dirname", "path": path}
        if case_name == "conventional_final_dirname_rebinds_join" and path == "/repo/.github":
            event["rebind"] = "join"
            cli.os.path.join = late_join
        events.append(event)
        return _POSIX_DIRNAME(path)

    def current_directory() -> str:
        event: dict[str, object] = {"op": "getcwd"}
        if case_name == "fallback_getcwd_rebinds_join":
            event["rebind"] = "join"
            cli.os.path.join = late_join
        events.append(event)
        return "/cwd"

    def join_path(*parts: str) -> str:
        events.append({"op": "join", "parts": list(parts)})
        return _POSIX_JOIN(*parts)

    def late_join(*parts: str) -> str:
        events.append({"op": "join-late", "parts": list(parts)})
        return _POSIX_JOIN("/late-provider", *parts)

    def path_exists(path: str) -> bool:
        events.append({"op": "exists", "path": path})
        if case_name == "existing_workflow_refused":
            return path == args.path
        if case_name == "force_overwrite_inferred_policy":
            return path == args.path
        if case_name == "custom_path_existing_policy":
            return path == "/repo/custom/.evoguard.json"
        return False

    def make_directories(path: str, *, exist_ok: bool = False) -> None:
        events.append({"op": "makedirs", "path": path, "exist_ok": exist_ok})

    def open_text(
        path: str,
        mode: str,
        *,
        encoding: str,
    ) -> _MemoryWriter:
        events.append({"op": "open", "path": path, "mode": mode, "encoding": encoding})
        if case_name == "workflow_open_failure" and path == args.path:
            raise OSError("controlled workflow open failure")
        if case_name == "policy_write_failure" and path.endswith(".evoguard.json"):
            raise OSError("controlled policy write failure")
        files[path] = ""
        return _MemoryWriter(
            path,
            files=files,
            events=events,
            write_failure=(
                "controlled workflow write failure"
                if case_name == "workflow_write_failure" and path == args.path
                else None
            ),
            exit_failure=(
                "controlled workflow exit failure"
                if case_name == "workflow_exit_failure" and path == args.path
                else (
                    "controlled policy exit failure"
                    if case_name == "policy_exit_failure" and path.endswith(".evoguard.json")
                    else None
                )
            ),
        )

    def dump_json(
        value: object,
        handle: _MemoryWriter,
        *,
        indent: int | None = None,
    ) -> None:
        events.append({"op": "json-dump", "indent": indent, "value": value})
        if case_name == "json_dump_failure":
            raise OSError("controlled JSON dump failure")
        originals["dump"](value, handle, indent=indent)

    def validate_credential(value: object) -> str:
        events.append({"op": "validate-credential", "value": value})
        return originals["credential"](value)

    def public_workflow(ref: str) -> str:
        events.append({"op": "public-workflow", "ref": ref})
        return originals["public_workflow"](ref)

    def private_workflow(ref: str, credential_key: str = "EVOGUARD_TOKEN") -> str:
        events.append(
            {
                "op": "private-workflow",
                "ref": ref,
                "credential_key": credential_key,
            }
        )
        return originals["private_workflow"](ref, credential_key)

    def default_policy(path: str) -> str:
        events.append({"op": "default-policy", "path": path})
        return originals["default_policy"](path)

    cli.os.path.abspath = absolute_path
    cli.os.path.basename = base_name
    cli.os.path.dirname = directory_name
    cli.os.path.exists = path_exists
    cli.os.path.join = join_path
    cli.os.getcwd = current_directory
    cli.os.makedirs = make_directories
    cli.json.dump = dump_json
    cli.open = open_text
    cli._github_actions_credential_key = validate_credential
    cli._default_policy_path = default_policy
    cli._workflow_yaml = public_workflow
    cli._workflow_yaml_private = private_workflow

    if case_name == "private_midcall_rebinding":

        def rebinding_credential(value: object) -> str:
            events.append({"op": "validate-credential-initial", "value": value})

            def late_private(ref: str, credential_key: str) -> str:
                events.append(
                    {
                        "op": "private-workflow-late",
                        "ref": ref,
                        "credential_key": credential_key,
                    }
                )
                return f"LATE-PRIVATE:{ref}:{credential_key}\n"

            cli._workflow_yaml_private = late_private
            return originals["credential"](value)

        cli._github_actions_credential_key = rebinding_credential

    if case_name == "filesystem_midcall_rebinding":

        def rebinding_public(ref: str) -> str:
            events.append({"op": "public-workflow-initial", "ref": ref})

            def late_exists(path: str) -> bool:
                events.append({"op": "exists-late", "path": path})
                cli.os.path.dirname = rebinding_dirname
                return False

            cli.os.path.exists = late_exists
            return "LATE-PROVIDER-WORKFLOW\n"

        def late_makedirs(path: str, *, exist_ok: bool = False) -> None:
            events.append({"op": "makedirs-late", "path": path, "exist_ok": exist_ok})
            cli.open = late_open

        def rebinding_dirname(path: str) -> str:
            events.append({"op": "dirname-rebinding", "path": path})
            cli.os.makedirs = late_makedirs
            return _POSIX_DIRNAME(path)

        def late_open(
            path: str,
            mode: str,
            *,
            encoding: str,
        ) -> _MemoryWriter:
            events.append(
                {
                    "op": "open-late",
                    "path": path,
                    "mode": mode,
                    "encoding": encoding,
                }
            )
            files[path] = ""
            if path == args.path:

                def late_default(candidate: str) -> str:
                    events.append({"op": "default-policy-late", "path": candidate})

                    def policy_exists(policy: str) -> bool:
                        events.append({"op": "policy-exists-late", "path": policy})
                        cli.os.path.dirname = policy_dirname
                        return False

                    cli.os.path.exists = policy_exists
                    return "/late/policy.json"

                cli._default_policy_path = late_default
            return _MemoryWriter(path, files=files, events=events)

        def policy_dirname(path: str) -> str:
            events.append({"op": "policy-dirname-late", "path": path})
            cli.os.makedirs = policy_makedirs
            return _POSIX_DIRNAME(path)

        def policy_makedirs(path: str, *, exist_ok: bool = False) -> None:
            events.append(
                {
                    "op": "policy-makedirs-late",
                    "path": path,
                    "exist_ok": exist_ok,
                }
            )
            cli.open = policy_open

        def policy_open(
            path: str,
            mode: str,
            *,
            encoding: str,
        ) -> _MemoryWriter:
            events.append(
                {
                    "op": "policy-open-late",
                    "path": path,
                    "mode": mode,
                    "encoding": encoding,
                }
            )
            files[path] = ""
            cli.json.dump = late_dump
            return _MemoryWriter(path, files=files, events=events)

        def late_dump(
            value: object,
            handle: _MemoryWriter,
            *,
            indent: int | None = None,
        ) -> None:
            events.append({"op": "json-dump-late", "indent": indent, "value": value})
            originals["dump"](value, handle, indent=indent)

        cli._workflow_yaml = rebinding_public

    if case_name == "explicit_policy_path":

        def unexpected_default(path: str) -> str:
            events.append({"op": "UNEXPECTED-default-policy", "path": path})
            raise AssertionError("explicit policy path must short-circuit inference")

        cli._default_policy_path = unexpected_default

    if case_name == "property_credential_rebinds_provider":

        def credential_property_side_effect() -> None:
            events.append(
                {
                    "op": "property-side-effect",
                    "property": "github_actions_credential_key",
                    "rebind": "credential",
                }
            )

            def late_credential(value: object) -> str:
                events.append({"op": "validate-credential-late", "value": value})
                return "LATE_CREDENTIAL"

            cli._github_actions_credential_key = late_credential

        args._property_side_effects["github_actions_credential_key"] = (
            credential_property_side_effect
        )

    if case_name == "property_ref_rebinds_provider":

        def ref_property_side_effect() -> None:
            events.append(
                {
                    "op": "property-side-effect",
                    "property": "ref",
                    "rebind": "public-workflow",
                }
            )

            def late_public(ref: str) -> str:
                events.append({"op": "public-workflow-late", "ref": ref})
                return f"LATE-PUBLIC:{ref}\n"

            cli._workflow_yaml = late_public

        args._property_side_effects["ref"] = ref_property_side_effect

    if case_name == "property_test_command_rebinds_provider":

        def test_command_property_side_effect() -> None:
            events.append(
                {
                    "op": "property-side-effect",
                    "property": "test_command",
                    "rebind": "json-dump",
                }
            )

            def late_json_dump(
                value: object,
                handle: _MemoryWriter,
                *,
                indent: int | None = None,
            ) -> None:
                events.append({"op": "json-dump-late", "indent": indent, "value": value})
                originals["dump"]({"late": True}, handle, indent=indent)

            cli.json.dump = late_json_dump

        args._property_side_effects["test_command"] = test_command_property_side_effect

    try:
        try:
            exit_code = cli.cmd_init(args, out=messages.append)
        except Exception as exc:  # noqa: BLE001 - the vector freezes propagation
            exception = {"type": type(exc).__name__, "message": str(exc)}
        return {
            "events": events,
            "exception": exception,
            "exit_code": exit_code,
            "files": files,
            "messages": messages,
        }
    finally:
        cli.os.path.abspath = originals["abspath"]
        cli.os.path.basename = originals["basename"]
        cli.os.path.dirname = originals["dirname"]
        cli.os.path.exists = originals["exists"]
        cli.os.path.join = originals["join"]
        cli.os.getcwd = originals["getcwd"]
        cli.os.makedirs = originals["makedirs"]
        cli.json.dump = originals["dump"]
        cli._github_actions_credential_key = originals["credential"]
        cli._default_policy_path = originals["default_policy"]
        cli._workflow_yaml = originals["public_workflow"]
        cli._workflow_yaml_private = originals["private_workflow"]
        if original_open is missing:
            delattr(cli, "open")
        else:
            cli.open = original_open


def capture_all() -> dict[str, object]:
    """Capture every reviewed initialization case."""

    return {
        "cases": {name: capture_case(name) for name in CASE_NAMES},
        "schema_version": SCHEMA_VERSION,
    }


if __name__ == "__main__":
    print(canonical_json(capture_all()), end="")
