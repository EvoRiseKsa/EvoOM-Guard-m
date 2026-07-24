"""Deterministic characterization of ``derive-finalizer-bindings``."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = Path(os.environ.get("EVOGUARD_CHARACTERIZATION_SOURCE_ROOT", str(ROOT))).resolve()
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from evoom_guard import cli, finalizer_derivation  # noqa: E402

SCHEMA_VERSION = "cli-derive-finalizer-bindings-characterization-v1"
CASE_NAMES = (
    "derive_domain_error",
    "derive_invalid_error",
    "derive_success",
    "derive_write_failure",
)


def canonical_json(value: Any) -> str:
    """Return the stable human-reviewable vector encoding."""

    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _normalized(value: object, root: str) -> object:
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            decoded = None
        if isinstance(decoded, (dict, list)):
            return json.dumps(
                _normalized(decoded, root),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        escaped_root = root.replace("\\", "\\\\")
        return value.replace(escaped_root, "<ROOT>").replace(root, "<ROOT>").replace("\\", "/")
    if isinstance(value, dict):
        return {
            str(key): _normalized(item, root)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_normalized(item, root) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return f"<{type(value).__name__}>"


def _command_argv(root: str) -> list[str]:
    return [
        "derive-finalizer-bindings",
        "--base-repo",
        os.path.join(root, "base.git"),
        "--head-repo",
        os.path.join(root, "head.git"),
        "--base-bare",
        "--head-bare",
        "--base-sha",
        "1" * 40,
        "--head-sha",
        "2" * 40,
        "--base-tree-sha",
        "3" * 40,
        "--head-tree-sha",
        "4" * 40,
        "--repository",
        "org/repo",
        "--repository-id",
        "1234",
        "--pr-number",
        "17",
        "--run-id",
        "run-9",
        "--run-attempt",
        "2",
        "--guard-artifact-sha",
        "a" * 64,
        "--out",
        os.path.join(root, "bindings.json"),
        "--force",
    ]


def capture_case(case_name: str) -> dict[str, Any]:
    """Capture one case through the historical public facade."""

    if case_name not in CASE_NAMES:
        raise ValueError("unknown derive-finalizer-bindings characterization case: " + case_name)

    events: list[dict[str, object]] = []
    messages: list[str] = []
    bindings = SimpleNamespace(
        candidate_sha256="b" * 64,
        policy_sha256="c" * 64,
        verifier_pack_sha256="d" * 64,
    )

    with tempfile.TemporaryDirectory(
        prefix="cli_derive_finalizer_bindings_characterization_"
    ) as root:
        args = cli.build_parser().parse_args(_command_argv(root))
        original_derive = finalizer_derivation.derive_finalizer_bindings
        original_write = finalizer_derivation.write_finalizer_bindings

        def derive(**kwargs: object) -> object:
            events.append({"op": "derive-bindings", "kwargs": kwargs})
            if case_name == "derive_domain_error":
                raise finalizer_derivation.FinalizerDerivationError(
                    "controlled derivation rejection"
                )
            if case_name == "derive_invalid_error":
                raise ValueError("controlled invalid derivation input")
            return bindings

        def write(
            value: object,
            *,
            bindings_path: str,
            force: bool,
        ) -> str:
            assert value is bindings
            events.append(
                {
                    "op": "write-bindings",
                    "bindings_path": bindings_path,
                    "force": force,
                }
            )
            if case_name == "derive_write_failure":
                raise OSError("controlled binding write failure")
            return bindings_path + ".canonical"

        try:
            finalizer_derivation.derive_finalizer_bindings = derive
            finalizer_derivation.write_finalizer_bindings = write
            exit_code = cli.cmd_derive_finalizer_bindings(args, out=messages.append)
        finally:
            finalizer_derivation.derive_finalizer_bindings = original_derive
            finalizer_derivation.write_finalizer_bindings = original_write

        return _normalized(
            {
                "exit_code": exit_code,
                "events": events,
                "messages": messages,
            },
            root,
        )


def capture_all() -> dict[str, Any]:
    """Capture the complete frozen vector."""

    return {
        "schema_version": SCHEMA_VERSION,
        "cases": {name: capture_case(name) for name in CASE_NAMES},
    }


if __name__ == "__main__":
    print(canonical_json(capture_all()), end="")
