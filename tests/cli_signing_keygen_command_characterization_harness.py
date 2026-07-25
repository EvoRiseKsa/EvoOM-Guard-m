"""Deterministic characterization of the public ``keygen`` CLI command.

The vector freezes provider snapshot timing, argument read order, success
projection, the historical ``FileExistsError`` mapping, and exception identity
before the command owner is extracted.
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from evoom_guard import cli, signing

BASELINE_COMMIT = "1262d987497a3be6fce5b71b9c4d90d299a1ba91"
SCHEMA_VERSION = "cli-signing-keygen-command-characterization-v1"
CASE_NAMES = (
    "file_exists",
    "file_exists_output_failure_identity",
    "key_property_failure_identity",
    "key_property_rebinds_provider",
    "provider_keyboard_interrupt_identity",
    "provider_oserror_identity",
    "pub_property_rebinds_provider",
    "success",
    "success_output_failure_identity",
    "success_provider_mutates_paths_before_report",
)


def canonical_json(value: Any) -> str:
    """Return the stable human-reviewable vector encoding."""

    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


class _SideEffectNamespace(argparse.Namespace):
    """Namespace whose selected property reads perform one deterministic effect."""

    def __getattribute__(self, name: str) -> object:
        namespace = object.__getattribute__(self, "__dict__")
        if name in {"key", "pub"}:
            events = namespace["_events"]
            events.append(
                {
                    "op": "read-arg",
                    "name": name,
                    "value": namespace[name],
                }
            )
            effect = namespace["_property_effects"].pop(name, None)
            if effect is not None:
                effect()
        return super().__getattribute__(name)


def capture_case(case_name: str) -> dict[str, object]:
    """Capture one key-generation case through the historical public facade."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown keygen characterization case: {case_name}")

    events: list[dict[str, object]] = []
    messages: list[str] = []
    args = _SideEffectNamespace(
        key="/keys/private.pem",
        pub="/keys/public.pem",
    )
    args._events = events
    args._property_effects = {}

    expected_exception: BaseException | None = None
    provider_exception: BaseException | None = None
    output_exception: BaseException | None = None

    if case_name == "file_exists":
        provider_exception = FileExistsError("private key already exists")
    elif case_name == "file_exists_output_failure_identity":
        provider_exception = FileExistsError("private key already exists")
        output_exception = RuntimeError("output failed")
        expected_exception = output_exception
    elif case_name == "key_property_failure_identity":
        expected_exception = RuntimeError("key property failed")
    elif case_name == "provider_keyboard_interrupt_identity":
        provider_exception = KeyboardInterrupt("provider interrupted")
        expected_exception = provider_exception
    elif case_name == "provider_oserror_identity":
        provider_exception = OSError("provider failed")
        expected_exception = provider_exception
    elif case_name == "success_output_failure_identity":
        output_exception = RuntimeError("output failed")
        expected_exception = output_exception

    original_provider = signing.generate_keypair

    def late_provider(key: str, public_key: str) -> None:
        events.append(
            {
                "op": "provider-late",
                "key": key,
                "public_key": public_key,
            }
        )

    def rebind_provider() -> None:
        events.append({"op": "rebind-provider"})
        signing.generate_keypair = late_provider

    def fail_key_property() -> None:
        events.append({"op": "key-property-failure"})
        assert expected_exception is not None
        raise expected_exception

    if case_name == "key_property_rebinds_provider":
        args._property_effects["key"] = rebind_provider
    elif case_name == "pub_property_rebinds_provider":
        args._property_effects["pub"] = rebind_provider
    elif case_name == "key_property_failure_identity":
        args._property_effects["key"] = fail_key_property

    def provider(key: str, public_key: str) -> None:
        events.append(
            {
                "op": "provider-entry",
                "key": key,
                "public_key": public_key,
            }
        )
        if case_name == "success_provider_mutates_paths_before_report":
            args.key = "/rotated/private.pem"
            args.pub = "/rotated/public.pem"
            events.append(
                {
                    "op": "provider-mutated-paths",
                    "key": args.key,
                    "public_key": args.pub,
                }
            )
        if provider_exception is not None:
            raise provider_exception
        events.append({"op": "provider-return"})

    def emit(message: str) -> None:
        events.append({"op": "output-entry", "message": message})
        if output_exception is not None:
            raise output_exception
        messages.append(message)
        events.append({"op": "output-return"})

    signing.generate_keypair = provider
    exit_code: int | None = None
    exception: dict[str, object] | None = None
    try:
        exit_code = cli.cmd_keygen(args, out=emit)
    except BaseException as exc:
        exception = {
            "type": type(exc).__name__,
            "message": str(exc),
            "same_identity": exc is expected_exception,
        }
    finally:
        signing.generate_keypair = original_provider

    return {
        "events": events,
        "exception": exception,
        "exit_code": exit_code,
        "messages": messages,
    }


def capture_vector() -> dict[str, object]:
    """Return all cases in stable order."""

    return {
        "baseline_commit": BASELINE_COMMIT,
        "schema_version": SCHEMA_VERSION,
        "cases": {
            case_name: capture_case(case_name)
            for case_name in sorted(CASE_NAMES)
        },
    }


if __name__ == "__main__":
    print(canonical_json(capture_vector()), end="")
