"""Deterministic characterization of the five Agent Change CLI adapters.

The vector is intentionally captured through the public ``evoom_guard.cli``
facades before their command owner is extracted.  Domain operations are
replaced with deterministic in-memory services: no Git process, cryptographic
operation, or filesystem publication is performed.
"""

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
from evoom_guard.admission import agent_change  # noqa: E402

SCHEMA_VERSION = "cli-agent-change-command-characterization-v1"
CASE_NAMES = (
    "derive_error",
    "derive_success",
    "seal_authorization_error",
    "seal_authorization_success",
    "seal_finalized_deny",
    "seal_finalized_success",
    "validate_error",
    "validate_success",
    "verify_finalized_deny",
    "verify_finalized_success",
)


def canonical_json(value: Any) -> str:
    """Return the stable human-reviewable vector encoding."""

    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _normalized(value: object, root: str) -> object:
    if isinstance(value, str):
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


def _command_argv(case_name: str, root: str) -> list[str]:
    paths = {
        name: os.path.join(root, name)
        for name in (
            "agent-bindings.json",
            "authorization-source.json",
            "authorization.aca",
            "authorization.pub",
            "base.git",
            "bundle.evb",
            "context.json",
            "finalizer-bindings.json",
            "finalizer.pub",
            "handoff.json",
            "head.git",
            "private.key",
            "proposal.json",
            "required.json",
            "scope.json",
            "source.json",
            "verdict.json",
        )
    }
    if case_name.startswith("validate_"):
        return ["validate-agent-change-proposal", paths["proposal.json"]]
    if case_name.startswith("derive_"):
        return [
            "derive-agent-change-bindings",
            "--base-repo",
            paths["base.git"],
            "--head-repo",
            paths["head.git"],
            "--git-executable",
            "/trusted/bin/git",
            "--git-executable-sha256",
            "1" * 64,
            "--base-bare",
            "--base-sha",
            "2" * 40,
            "--head-sha",
            "3" * 40,
            "--base-tree-sha",
            "4" * 40,
            "--head-tree-sha",
            "5" * 40,
            "--out",
            os.path.join(root, "bindings.json"),
            "--force",
        ]
    if case_name.startswith("seal_authorization_"):
        return [
            "seal-agent-change-authorization",
            "--source",
            paths["source.json"],
            "--scope",
            paths["scope.json"],
            "--required",
            paths["required.json"],
            "--sign-key",
            paths["private.key"],
            "--out",
            paths["authorization.aca"],
            "--force",
        ]
    if case_name.startswith("seal_finalized_"):
        return [
            "seal-agent-change-finalized",
            paths["proposal.json"],
            paths["authorization.aca"],
            paths["handoff.json"],
            paths["verdict.json"],
            "--base-repo",
            paths["base.git"],
            "--head-repo",
            paths["head.git"],
            "--git-executable",
            "/trusted/bin/git",
            "--git-executable-sha256",
            "1" * 64,
            "--base-bare",
            "--finalizer-bindings",
            paths["finalizer-bindings.json"],
            "--authorization-source",
            paths["authorization-source.json"],
            "--authorization-pub",
            paths["authorization.pub"],
            "--expected-source",
            paths["source.json"],
            "--expected-context",
            paths["context.json"],
            "--sign-key",
            paths["private.key"],
            "--trusted-pub",
            paths["finalizer.pub"],
            "--out",
            paths["bundle.evb"],
            "--force",
        ]
    return [
        "verify-agent-change-finalized",
        paths["bundle.evb"],
        "--agent-bindings",
        paths["agent-bindings.json"],
        "--authorization-source",
        paths["authorization-source.json"],
        "--authorization-pub",
        paths["authorization.pub"],
        "--expected-source",
        paths["source.json"],
        "--expected-context",
        paths["context.json"],
        "--trusted-pub",
        paths["finalizer.pub"],
    ]


def capture_case(case_name: str) -> dict[str, Any]:
    """Capture one Agent Change command through its historical public facade."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown Agent Change CLI characterization case: {case_name}")

    events: list[dict[str, object]] = []
    messages: list[str] = []
    proposal = SimpleNamespace(
        payload={
            "source": {"repository": "org/repo", "head_sha": "3" * 40},
            "producer": {"kind": "agent", "id": "agent-7"},
            "change": {
                "candidate_sha256": "a" * 64,
                "touched_paths": ["src/app.py", "src/old.py"],
            },
        }
    )
    bindings = SimpleNamespace(
        candidate_sha256="a" * 64,
        touched_paths=("src/app.py", "src/old.py"),
        policy_sha256="b" * 64,
        verifier_pack_sha256="c" * 64,
        payload={"format": "controlled-agent-bindings"},
    )
    contract = SimpleNamespace(bindings=bindings, proposal=proposal)

    with tempfile.TemporaryDirectory(prefix="cli_agent_change_characterization_") as root:
        argv = _command_argv(case_name, root)
        args = cli.build_parser().parse_args(argv)

        original_cli = {
            "_read_external_finalizer_object": cli._read_external_finalizer_object,
        }
        original_agent = {
            "inspect_agent_change_proposal": agent_change.inspect_agent_change_proposal,
            "seal_agent_change_authorization": agent_change.seal_agent_change_authorization,
            "seal_agent_change_finalizer_bundle": (agent_change.seal_agent_change_finalizer_bundle),
            "verify_agent_change_finalized_bundle": (
                agent_change.verify_agent_change_finalized_bundle
            ),
        }
        original_derivation = {
            "derive_agent_change_bindings": (finalizer_derivation.derive_agent_change_bindings),
            "git_executable_pin": finalizer_derivation.git_executable_pin,
            "read_agent_change_bindings": (finalizer_derivation.read_agent_change_bindings),
            "read_finalizer_bindings": finalizer_derivation.read_finalizer_bindings,
            "write_agent_change_bindings": (finalizer_derivation.write_agent_change_bindings),
        }

        def read_external(path: str, *, label: str) -> dict[str, object]:
            events.append({"op": "read-external", "path": path, "label": label})
            if case_name == "seal_authorization_error" and label == "authorization requirements":
                raise ValueError("controlled requirements rejection")
            return {"label": label, "path": path}

        def inspect(path: str) -> object:
            events.append({"op": "inspect-proposal", "path": path})
            if case_name == "validate_error":
                raise agent_change.AgentChangeAdmissionError("controlled proposal rejection")
            return proposal

        def git_pin(path: str, digest: str) -> str:
            events.append({"op": "git-pin", "path": path, "digest": digest})
            return "/pinned/bin/git"

        def derive(**kwargs: object) -> object:
            events.append({"op": "derive-bindings", "kwargs": kwargs})
            if case_name == "derive_error":
                raise finalizer_derivation.FinalizerDerivationError(
                    "controlled derivation rejection"
                )
            return bindings

        def write_bindings(value: object, *, bindings_path: str, force: bool) -> str:
            assert value is bindings
            events.append(
                {
                    "op": "write-bindings",
                    "path": bindings_path,
                    "force": force,
                }
            )
            return bindings_path + ".canonical"

        def seal_authorization(
            output_path: str,
            *,
            source: object,
            scope: object,
            required: object,
            private_key_path: str,
            force: bool,
        ) -> object:
            events.append(
                {
                    "op": "seal-authorization",
                    "output": output_path,
                    "source": source,
                    "scope": scope,
                    "required": required,
                    "private_key": private_key_path,
                    "force": force,
                }
            )
            return SimpleNamespace(
                payload={
                    "authentication": {"key_id": "authorization-key"},
                    "source": source,
                    "scope": scope,
                }
            )

        def read_finalizer_bindings(path: str) -> object:
            events.append({"op": "read-finalizer-bindings", "path": path})
            return SimpleNamespace(payload={"format": "controlled-finalizer-bindings"})

        def seal_finalized(
            proposal_path: str,
            authorization_path: str,
            handoff_path: str,
            verdict_path: str,
            output_path: str,
            **kwargs: object,
        ) -> object:
            events.append(
                {
                    "op": "seal-finalized",
                    "proposal": proposal_path,
                    "authorization": authorization_path,
                    "handoff": handoff_path,
                    "verdict": verdict_path,
                    "output": output_path,
                    "kwargs": kwargs,
                }
            )
            if case_name == "seal_finalized_deny":
                raise agent_change.AgentChangeAdmissionError("controlled finalization rejection")
            return SimpleNamespace(
                decision="ALLOW",
                finalized=SimpleNamespace(
                    finalized=SimpleNamespace(bundle_path=output_path + ".canonical")
                ),
                contract=contract,
            )

        def read_agent_bindings(path: str) -> object:
            events.append({"op": "read-agent-bindings", "path": path})
            return bindings

        def verify_finalized(bundle_path: str, **kwargs: object) -> object:
            events.append(
                {
                    "op": "verify-finalized",
                    "bundle": bundle_path,
                    "kwargs": kwargs,
                }
            )
            if case_name == "verify_finalized_deny":
                raise agent_change.AgentChangeAdmissionError("controlled verification rejection")
            return SimpleNamespace(decision="ALLOW", contract=contract)

        cli._read_external_finalizer_object = read_external
        agent_change.inspect_agent_change_proposal = inspect
        agent_change.seal_agent_change_authorization = seal_authorization
        agent_change.seal_agent_change_finalizer_bundle = seal_finalized
        agent_change.verify_agent_change_finalized_bundle = verify_finalized
        finalizer_derivation.derive_agent_change_bindings = derive
        finalizer_derivation.git_executable_pin = git_pin
        finalizer_derivation.read_agent_change_bindings = read_agent_bindings
        finalizer_derivation.read_finalizer_bindings = read_finalizer_bindings
        finalizer_derivation.write_agent_change_bindings = write_bindings
        try:
            handler = getattr(cli, f"cmd_{args.command.replace('-', '_')}")
            exit_code = handler(args, out=messages.append)
        finally:
            cli._read_external_finalizer_object = original_cli["_read_external_finalizer_object"]
            for name, value in original_agent.items():
                setattr(agent_change, name, value)
            for name, value in original_derivation.items():
                setattr(finalizer_derivation, name, value)

        return {
            "events": _normalized(events, root),
            "exit_code": exit_code,
            "messages": _normalized(messages, root),
        }


def capture_all() -> dict[str, Any]:
    """Capture every reviewed command case under one versioned envelope."""

    return {
        "cases": {name: capture_case(name) for name in CASE_NAMES},
        "schema_version": SCHEMA_VERSION,
    }


if __name__ == "__main__":
    print(canonical_json(capture_all()), end="")
