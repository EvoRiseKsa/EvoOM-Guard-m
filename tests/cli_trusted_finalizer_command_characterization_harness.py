"""Deterministic characterization of the Trusted Finalizer CLI adapters.

The vector is captured through the historical :mod:`evoom_guard.cli` facades
before extraction.  Every filesystem, cryptographic, and finalizer operation is
replaced with a deterministic in-memory collaborator.
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

from evoom_guard import (  # noqa: E402
    cli,
    evidence_bundle,
    finalizer_derivation,
    record_verifier,
    trusted_finalizer,
)
from evoom_guard.signing import SigningUnavailableError  # noqa: E402

SCHEMA_VERSION = "cli-trusted-finalizer-command-characterization-v1"
CASE_NAMES = (
    "bindings_mismatch",
    "bindings_semantic_invalid",
    "bindings_stdin",
    "bindings_success",
    "handoff_create_error",
    "handoff_invalid",
    "handoff_metadata_error",
    "handoff_stdin",
    "handoff_success",
    "seal_allow",
    "seal_deny_gated",
    "seal_deny_ungated",
    "seal_invalid",
    "seal_operational_error",
    "seal_stdin",
    "seal_trusted_input_error",
    "verify_allow",
    "verify_deny_gated",
    "verify_deny_ungated",
    "verify_external_error",
    "verify_invalid",
    "verify_signing_unavailable",
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


def _command_argv(case_name: str, root: str) -> list[str]:
    paths = {
        name: os.path.join(root, name)
        for name in (
            "bindings.json",
            "bundle.evb",
            "context.json",
            "context.out.json",
            "handoff.json",
            "log.txt",
            "private.key",
            "public.key",
            "source.json",
            "source.out.json",
            "verdict.json",
        )
    }
    if case_name.startswith("bindings_"):
        verdict = "-" if case_name == "bindings_stdin" else paths["verdict.json"]
        return [
            "verify-finalizer-bindings",
            verdict,
            "--bindings",
            paths["bindings.json"],
            "--source-out",
            paths["source.out.json"],
            "--context-out",
            paths["context.out.json"],
            "--force",
        ]
    if case_name.startswith("handoff_"):
        verdict = "-" if case_name == "handoff_stdin" else paths["verdict.json"]
        return [
            "finalizer-handoff",
            verdict,
            "--out",
            paths["handoff.json"],
            "--source",
            paths["source.json"],
            "--context",
            paths["context.json"],
            "--force",
        ]
    if case_name.startswith("seal_"):
        verdict = "-" if case_name == "seal_stdin" else paths["verdict.json"]
        argv = [
            "seal-finalizer",
            paths["handoff.json"],
            verdict,
            "--out",
            paths["bundle.evb"],
            "--expected-source",
            paths["source.json"],
            "--expected-context",
            paths["context.json"],
            "--expected-derivation",
            paths["bindings.json"],
            "--sign-key",
            paths["private.key"],
            "--material",
            f"logs={paths['log.txt']}",
            "--force",
        ]
        if case_name == "seal_deny_gated":
            argv.append("--require-pass")
        return argv
    argv = [
        "verify-finalized",
        paths["bundle.evb"],
        "--trusted-pub",
        paths["public.key"],
        "--expected-source",
        paths["source.json"],
        "--expected-context",
        paths["context.json"],
    ]
    if case_name == "verify_deny_gated":
        argv.append("--require-pass")
    return argv


def capture_case(case_name: str) -> dict[str, Any]:
    """Capture one command through its historical public facade."""

    if case_name not in CASE_NAMES:
        raise ValueError(f"unknown Trusted Finalizer CLI characterization case: {case_name}")

    events: list[dict[str, object]] = []
    messages: list[str] = []
    record = {
        "format": "EVOGUARD_VERDICT_V1",
        "decision": "PASS",
    }
    source = {
        "repository": "org/repo",
        "head_sha": "3" * 40,
    }
    context = {
        "candidate_sha256": "a" * 64,
        "policy_sha256": "b" * 64,
    }
    bindings = SimpleNamespace(payload={"format": "controlled-finalizer-bindings"})

    with tempfile.TemporaryDirectory(prefix="cli_trusted_finalizer_characterization_") as root:
        args = cli.build_parser().parse_args(_command_argv(case_name, root))

        original_cli = {
            "_read_external_finalizer_object": cli._read_external_finalizer_object,
        }
        original_evidence = {
            "EvidenceMaterial": evidence_bundle.EvidenceMaterial,
            "_load_json_object": evidence_bundle._load_json_object,
            "_read_regular_file": evidence_bundle._read_regular_file,
        }
        original_derivation = {
            "context_from_verified_bindings": (finalizer_derivation.context_from_verified_bindings),
            "read_finalizer_bindings": finalizer_derivation.read_finalizer_bindings,
            "write_verified_finalizer_context": (
                finalizer_derivation.write_verified_finalizer_context
            ),
        }
        original_record_verifier = {
            "verify_record": record_verifier.verify_record,
        }
        original_finalizer = {
            "create_finalizer_handoff": trusted_finalizer.create_finalizer_handoff,
            "seal_finalizer_bundle": trusted_finalizer.seal_finalizer_bundle,
            "verify_finalized_bundle": trusted_finalizer.verify_finalized_bundle,
        }

        def read_regular(path: str, *, limit: int, label: str) -> bytes:
            events.append(
                {
                    "op": "read-regular",
                    "path": path,
                    "limit": limit,
                    "label": label,
                }
            )
            return b'{"controlled":"record"}'

        def load_object(data: bytes, label: str) -> dict[str, object]:
            events.append(
                {
                    "op": "load-object",
                    "label": label,
                    "size": len(data),
                }
            )
            return record

        def verify_record(value: object) -> dict[str, object]:
            events.append({"op": "verify-record", "record": value})
            if case_name == "bindings_semantic_invalid":
                return {
                    "ok": False,
                    "checks": [
                        {"id": "z-last", "status": "fail"},
                        {"id": "ignored", "status": "pass"},
                        {"id": "a-first", "status": "fail"},
                    ],
                }
            return {
                "ok": True,
                "checks": [{"id": "semantic-record", "status": "pass"}],
            }

        def read_bindings(path: str) -> object:
            events.append({"op": "read-bindings", "path": path})
            return bindings

        def derive_context(
            value: object,
            verdict: object,
        ) -> tuple[dict[str, object], dict[str, object]]:
            assert value is bindings
            assert verdict is record
            events.append({"op": "derive-context"})
            if case_name == "bindings_mismatch":
                raise finalizer_derivation.FinalizerDerivationError("controlled raw-Git mismatch")
            return source, context

        def write_context(
            value: object,
            verdict: object,
            *,
            source_path: str,
            context_path: str,
            force: bool,
        ) -> tuple[str, str]:
            assert value is bindings
            assert verdict is record
            events.append(
                {
                    "op": "write-context",
                    "source_path": source_path,
                    "context_path": context_path,
                    "force": force,
                }
            )
            return source_path + ".canonical", context_path + ".canonical"

        def read_external(path: str, *, label: str) -> dict[str, object]:
            events.append(
                {
                    "op": "read-external",
                    "path": path,
                    "label": label,
                }
            )
            if case_name == "handoff_metadata_error" and label == "context":
                raise ValueError("controlled metadata rejection")
            if case_name == "seal_trusted_input_error" and label == "expected context":
                raise ValueError("controlled trusted-input rejection")
            if case_name == "verify_external_error" and label == "expected source":
                raise ValueError("controlled external-trust rejection")
            return source if "source" in label else context

        def material(role: str, source_path: str) -> object:
            events.append(
                {
                    "op": "material",
                    "role": role,
                    "source_path": source_path,
                }
            )
            return SimpleNamespace(role=role, source_path=source_path)

        def create_handoff(
            verdict_path: str,
            output_path: str,
            *,
            source: object,
            context: object,
            force: bool,
        ) -> dict[str, object]:
            events.append(
                {
                    "op": "create-handoff",
                    "verdict": verdict_path,
                    "output": output_path,
                    "source": source,
                    "context": context,
                    "force": force,
                }
            )
            if case_name == "handoff_invalid":
                raise trusted_finalizer.FinalizerHandoffError("controlled handoff rejection")
            if case_name == "handoff_create_error":
                raise OSError("controlled handoff I/O failure")
            return {
                "record": {"sha256": "d" * 64},
                "source": source,
                "context": context,
            }

        def seal_bundle(
            handoff_path: str,
            verdict_path: str,
            output_path: str,
            **kwargs: object,
        ) -> object:
            events.append(
                {
                    "op": "seal-finalizer",
                    "handoff": handoff_path,
                    "verdict": verdict_path,
                    "output": output_path,
                    "kwargs": kwargs,
                }
            )
            if case_name == "seal_invalid":
                raise trusted_finalizer.FinalizerHandoffError("controlled sealing rejection")
            if case_name == "seal_operational_error":
                raise SigningUnavailableError("controlled signing outage")
            decision = "DENY" if case_name.startswith("seal_deny_") else "ALLOW"
            return SimpleNamespace(
                decision=decision,
                finalized=SimpleNamespace(
                    bundle_path=output_path + ".canonical",
                    manifest={
                        "record": {"sha256": "d" * 64},
                        "authentication": {"key_id": "trusted-finalizer-key"},
                    },
                ),
            )

        def verify_bundle(
            bundle_path: str,
            **kwargs: object,
        ) -> object:
            events.append(
                {
                    "op": "verify-finalized",
                    "bundle": bundle_path,
                    "kwargs": kwargs,
                }
            )
            if case_name == "verify_signing_unavailable":
                raise SigningUnavailableError("controlled verification outage")
            if case_name == "verify_invalid":
                raise trusted_finalizer.FinalizerHandoffError(
                    "controlled finalized-bundle rejection"
                )
            decision = "DENY" if case_name.startswith("verify_deny_") else "ALLOW"
            return SimpleNamespace(
                decision=decision,
                bundle=SimpleNamespace(
                    manifest={
                        "authentication": {"key_id": "trusted-finalizer-key"},
                    },
                    record_report={
                        "ok": True,
                        "checks": [
                            {"id": "semantic-record", "status": "pass"},
                        ],
                    },
                ),
            )

        cli._read_external_finalizer_object = read_external
        evidence_bundle.EvidenceMaterial = material
        evidence_bundle._load_json_object = load_object
        evidence_bundle._read_regular_file = read_regular
        finalizer_derivation.context_from_verified_bindings = derive_context
        finalizer_derivation.read_finalizer_bindings = read_bindings
        finalizer_derivation.write_verified_finalizer_context = write_context
        record_verifier.verify_record = verify_record
        trusted_finalizer.create_finalizer_handoff = create_handoff
        trusted_finalizer.seal_finalizer_bundle = seal_bundle
        trusted_finalizer.verify_finalized_bundle = verify_bundle
        try:
            handler = getattr(cli, f"cmd_{args.command.replace('-', '_')}")
            exit_code = handler(args, out=messages.append)
        finally:
            cli._read_external_finalizer_object = original_cli["_read_external_finalizer_object"]
            for name, value in original_evidence.items():
                setattr(evidence_bundle, name, value)
            for name, value in original_derivation.items():
                setattr(finalizer_derivation, name, value)
            for name, value in original_record_verifier.items():
                setattr(record_verifier, name, value)
            for name, value in original_finalizer.items():
                setattr(trusted_finalizer, name, value)

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
