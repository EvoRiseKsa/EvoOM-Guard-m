"""Characterization and ownership gates for the record-command extraction."""

from __future__ import annotations

import ast
import base64
import hashlib
import inspect
import json
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from evoom_guard import cli
from evoom_guard import evidence_bundle as bundle_module
from evoom_guard import record_verifier as record_module
from evoom_guard import signing as signing_module

ROOT = Path(__file__).resolve().parents[1]
FACADE = ROOT / "evoom_guard" / "cli" / "__init__.py"
OWNER = ROOT / "evoom_guard" / "cli" / "record_commands.py"
COMMANDS = (
    "cmd_verify_verdict",
    "cmd_verify_record",
    "cmd_bundle_evidence",
    "cmd_finalize_record",
    "cmd_verify_bundle",
)


def _namespace(**values: object) -> Namespace:
    return Namespace(**values)


def test_record_command_owner_exists_and_facades_are_thin() -> None:
    """The compatibility facade must delegate; orchestration belongs to one owner."""

    assert OWNER.is_file(), "record command owner has not been extracted"
    facade_tree = ast.parse(FACADE.read_text(encoding="utf-8"))
    owner_tree = ast.parse(OWNER.read_text(encoding="utf-8"))
    facade_functions = {
        node.name: node
        for node in facade_tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    owner_functions = {
        node.name
        for node in owner_tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    for command in COMMANDS:
        function = facade_functions[command]
        owner_name = "execute_" + command.removeprefix("cmd_")
        assert owner_name in owner_functions
        calls = [
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "_record_command_owner"
            and node.func.attr == owner_name
        ]
        assert len(calls) == 1, f"{command} is not a thin owner facade"


def test_public_record_command_signatures_are_frozen() -> None:
    expected = "(args: 'argparse.Namespace', *, out: 'Callable[[str], None]' = <built-in function print>) -> 'int'"
    for command in COMMANDS:
        assert str(inspect.signature(getattr(cli, command))) == expected


def test_verify_verdict_freezes_signature_provider_then_resolves_json_late(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    verdict = b'{"attestation":{"head_sha":"abc"}}'
    encoded_signature = base64.b64encode(b"signature")

    def late_verify(*_args: object, **_kwargs: object) -> bool:
        pytest.fail("signature verifier drifted after command entry")

    def parse_late(data: str) -> object:
        events.append("parse-json-late")
        return json.loads(data)

    def verify_early(payload: bytes, signature: bytes, public_key: str) -> bool:
        assert payload == verdict
        assert signature == b"signature"
        assert public_key == "trusted.pub"
        events.append("verify-signature-early")
        monkeypatch.setattr(record_module, "strict_json_loads", parse_late)
        return True

    def read(path: str, *, limit: int, label: str) -> bytes:
        events.append(f"read:{label}:{path}:{limit}")
        monkeypatch.setattr(signing_module, "verify_bytes", late_verify)
        return verdict if label == "verdict" else encoded_signature

    monkeypatch.setattr(signing_module, "verify_bytes", verify_early)
    monkeypatch.setattr(cli, "_read_bounded_bytes", read)
    monkeypatch.setattr(
        record_module,
        "strict_json_loads",
        lambda _data: pytest.fail("JSON parser was snapshotted too early"),
    )
    args = _namespace(
        verdict="verdict.json",
        sig="verdict.sig",
        pub="trusted.pub",
        expect_head_sha="abc",
        expect_base_sha=None,
        expect_policy_sha=None,
        expect_policy_id=None,
    )

    assert cli.cmd_verify_verdict(args, out=events.append) == 0
    assert events == [
        f"read:verdict:verdict.json:{cli.MAX_OFFLINE_RECORD_BYTES}",
        f"read:signature:verdict.sig:{cli.MAX_SIGNATURE_FILE_BYTES}",
        "verify-signature-early",
        f"input sha256: {hashlib.sha256(verdict).hexdigest()}",
        "signature: VALID",
        "parse-json-late",
        "context: head_sha matches (abc)",
    ]


def test_verify_record_freezes_validator_before_live_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    verdict = b'{"verdict":"PASS"}'

    def early_parse(data: str) -> object:
        events.append("parse-early")
        return json.loads(data)

    def early_verify(record: object) -> dict[str, object]:
        events.append(f"verify-early:{record!r}")
        return {"format": "CONTROLLED", "ok": True}

    def read(path: str, *, limit: int, label: str) -> bytes:
        events.append(f"read:{label}:{path}:{limit}")
        monkeypatch.setattr(
            record_module,
            "strict_json_loads",
            lambda _data: pytest.fail("record parser drifted after command entry"),
        )
        monkeypatch.setattr(
            record_module,
            "verify_record",
            lambda _value: pytest.fail("record verifier drifted after command entry"),
        )
        return verdict

    monkeypatch.setattr(record_module, "strict_json_loads", early_parse)
    monkeypatch.setattr(record_module, "verify_record", early_verify)
    monkeypatch.setattr(cli, "_read_bounded_bytes", read)

    assert (
        cli.cmd_verify_record(
            _namespace(verdict="verdict.json"),
            out=lambda message: events.append("out:" + message),
        )
        == 0
    )
    assert events[:3] == [
        f"read:verdict:verdict.json:{cli.MAX_OFFLINE_RECORD_BYTES}",
        "parse-early",
        "verify-early:{'verdict': 'PASS'}",
    ]
    report = json.loads(events[3].removeprefix("out:"))
    assert report == {
        "format": "CONTROLLED",
        "input_sha256": hashlib.sha256(verdict).hexdigest(),
        "input_size": len(verdict),
        "ok": True,
    }


def test_bundle_evidence_preserves_validate_then_create_then_report_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    verdict = b'{"verdict":"PASS"}'
    context = b'{"repository":"org/repo"}'

    class Material:
        def __init__(self, *, role: str, source_path: str) -> None:
            events.append(f"material:{role}:{source_path}")
            self.role = role
            self.source_path = source_path

    def parse(data: str) -> object:
        events.append("parse:" + data)
        return json.loads(data)

    def verify(record: object) -> dict[str, object]:
        events.append(f"verify:{record!r}")
        return {"ok": True}

    def create(
        verdict_path: str,
        output_path: str,
        **kwargs: object,
    ) -> dict[str, Any]:
        events.append(f"create:{verdict_path}:{output_path}:{sorted(kwargs)}")
        return {
            "record": {"sha256": "a" * 64},
            "authentication": {"key_id": "key-1"},
        }

    def read(path: str, *, limit: int, label: str) -> bytes:
        events.append(f"read:{label}:{path}:{limit}")
        monkeypatch.setattr(
            bundle_module,
            "create_evidence_bundle",
            lambda *_args, **_kwargs: pytest.fail("bundle creator drifted after entry"),
        )
        return verdict if label == "verdict" else context

    def late_report(_out: object, value: dict[str, object]) -> None:
        events.append("report:" + json.dumps(value, sort_keys=True))

    monkeypatch.setattr(bundle_module, "EvidenceMaterial", Material)
    monkeypatch.setattr(bundle_module, "create_evidence_bundle", create)
    monkeypatch.setattr(record_module, "strict_json_loads", parse)
    monkeypatch.setattr(record_module, "verify_record", verify)
    monkeypatch.setattr(cli, "_read_bounded_bytes", read)
    monkeypatch.setattr(cli, "_machine_report", late_report)
    args = _namespace(
        verdict="verdict.json",
        context="context.json",
        material=["logs=judge.log"],
        out="evidence.evb",
        sign_key="private.key",
        force=True,
    )

    assert cli.cmd_bundle_evidence(args, out=lambda _message: None) == 0
    assert [event.split(":", 1)[0] for event in events] == [
        "read",
        "read",
        "parse",
        "parse",
        "verify",
        "material",
        "create",
        "report",
    ]
    assert '"status": "CREATED"' in events[-1]


def test_finalize_record_preserves_read_verify_finalize_report_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    verdict = b'{"verdict":"PASS"}'
    context = b'{"candidate_sha256":"abc"}'

    class Material:
        def __init__(self, *, role: str, source_path: str) -> None:
            events.append(f"material:{role}:{source_path}")

    def read(path: str, *, limit: int, label: str) -> bytes:
        events.append(f"read:{label}:{path}:{limit}")
        return verdict if label == "verdict" else context

    def parse(data: str) -> object:
        events.append("parse:" + data)
        return json.loads(data)

    def verify(record: object) -> dict[str, object]:
        events.append(f"verify:{record!r}")
        return {"ok": True}

    def finalize(
        verdict_path: str,
        output_path: str,
        **kwargs: object,
    ) -> object:
        events.append(f"finalize:{verdict_path}:{output_path}:{sorted(kwargs)}")
        return SimpleNamespace(
            manifest={
                "record": {"sha256": "a" * 64},
                "authentication": {"key_id": "key-1"},
            },
            decision="ALLOW",
            bundle_path="evidence.evb",
            record_report={"ok": True},
        )

    monkeypatch.setattr(bundle_module, "EvidenceMaterial", Material)
    monkeypatch.setattr(bundle_module, "finalize_evidence_bundle", finalize)
    monkeypatch.setattr(record_module, "strict_json_loads", parse)
    monkeypatch.setattr(record_module, "verify_record", verify)
    monkeypatch.setattr(cli, "_read_bounded_bytes", read)
    monkeypatch.setattr(
        cli,
        "_machine_report",
        lambda _out, value: events.append(
            "report:" + json.dumps(value, sort_keys=True)
        ),
    )
    args = _namespace(
        verdict="verdict.json",
        expected_context="context.json",
        material=["logs=judge.log"],
        out="evidence.evb",
        sign_key="private.key",
        force=True,
        require_pass=True,
    )

    assert cli.cmd_finalize_record(args, out=lambda _message: None) == 0
    assert [event.split(":", 1)[0] for event in events] == [
        "read",
        "read",
        "parse",
        "parse",
        "verify",
        "material",
        "finalize",
        "report",
    ]
    assert '"status": "FINALIZED"' in events[-1]


def test_verify_bundle_preserves_authentication_pipeline_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    expected_context = b'{"repository":"org/repo"}'
    verdict = {"verdict": "PASS", "passed": True, "reason_code": "PASS", "exit_code": 0}
    inspected = SimpleNamespace(
        verdict=verdict,
        manifest={
            "authentication": {"key_id": "key-1"},
            "context": {"repository": "org/repo"},
        },
    )

    def read(path: str, *, limit: int, label: str) -> bytes:
        events.append(f"read:{label}:{path}:{limit}")
        return expected_context

    def parse(data: str) -> object:
        events.append("parse:" + data)
        return json.loads(data)

    def inspect_bundle(path: str) -> object:
        events.append("inspect:" + path)
        return inspected

    def verify_signature(value: object, *, trusted_public_key_path: str) -> None:
        assert value is inspected
        events.append("signature:" + trusted_public_key_path)

    def verify_context(value: object, *, expected_context: object) -> None:
        assert value is inspected
        events.append(f"context:{expected_context!r}")

    def verify_record(value: object) -> dict[str, object]:
        assert value is verdict
        events.append("record")
        return {"ok": True}

    monkeypatch.setattr(cli, "_read_bounded_bytes", read)
    monkeypatch.setattr(record_module, "strict_json_loads", parse)
    monkeypatch.setattr(record_module, "verify_record", verify_record)
    monkeypatch.setattr(bundle_module, "inspect_evidence_bundle", inspect_bundle)
    monkeypatch.setattr(bundle_module, "verify_bundle_signature", verify_signature)
    monkeypatch.setattr(bundle_module, "verify_bundle_context", verify_context)
    monkeypatch.setattr(
        cli,
        "_machine_report",
        lambda _out, value: events.append(
            "report:" + json.dumps(value, sort_keys=True)
        ),
    )
    args = _namespace(
        expect_context="context.json",
        bundle="evidence.evb",
        trusted_pub="trusted.pub",
        require_pass=True,
    )

    assert cli.cmd_verify_bundle(args, out=lambda _message: None) == 0
    assert [event.split(":", 1)[0] for event in events] == [
        "read",
        "parse",
        "inspect",
        "signature",
        "context",
        "record",
        "report",
    ]
    assert '"pass_gate": "ALLOW"' in events[-1]
