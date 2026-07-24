"""Frozen equivalence gates for the Trusted Finalizer CLI extraction."""

from __future__ import annotations

import difflib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from evoom_guard import (
    cli,
    evidence_bundle,
    finalizer_derivation,
    record_verifier,
    trusted_finalizer,
)
from tests.cli_trusted_finalizer_command_characterization_harness import (
    CASE_NAMES,
    SCHEMA_VERSION,
    _normalized,
    canonical_json,
    capture_case,
)

VECTOR = (
    Path(__file__).parent / "fixtures" / "refactor-safety" / "cli-trusted-finalizer-command-v1.json"
)


def _frozen() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_cli_trusted_finalizer_command_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_cli_trusted_finalizer_command_behavior(case_name: str) -> None:
    expected = _frozen()["cases"][case_name]
    actual = capture_case(case_name)
    if actual != expected:
        diff = "".join(
            difflib.unified_diff(
                canonical_json(expected).splitlines(keepends=True),
                canonical_json(actual).splitlines(keepends=True),
                fromfile=f"frozen/{case_name}",
                tofile=f"current/{case_name}",
            )
        )
        pytest.fail("Trusted Finalizer CLI command behavior drifted:\n" + diff)


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_machine_report_schema_order_is_canonical(case_name: str) -> None:
    messages = capture_case(case_name)["messages"]

    assert len(messages) == 1
    payload = json.loads(messages[0])
    assert messages[0] == json.dumps(payload, indent=2, sort_keys=True)


def test_characterization_paths_are_canonical_across_platform_encodings() -> None:
    root = r"C:\work\root"
    raw_path = root + r"\nested\file.json"
    embedded = json.dumps({"path": raw_path}, indent=2, sort_keys=True)

    assert _normalized(raw_path, root) == "<ROOT>/nested/file.json"
    assert _normalized(embedded, root) == json.dumps(
        {"path": "<ROOT>/nested/file.json"},
        indent=2,
        sort_keys=True,
    )


def test_semantic_record_dependencies_snapshot_at_helper_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All helper-local imports, including the byte limit, freeze together."""

    events: list[str] = []
    record = {"format": "controlled"}
    original_limit = evidence_bundle.MAX_VERDICT_BYTES

    def late_load(_data: bytes, _label: str) -> dict[str, object]:
        pytest.fail("JSON loader was resolved after the helper entry import")

    def late_verify(_record: object) -> dict[str, object]:
        pytest.fail("record verifier was resolved after the helper entry import")

    def read_regular(path: str, *, limit: int, label: str) -> bytes:
        assert path == "verdict.json"
        assert limit == original_limit
        assert label == "verdict"
        events.append("early-read")
        monkeypatch.setattr(evidence_bundle, "_load_json_object", late_load)
        monkeypatch.setattr(record_verifier, "verify_record", late_verify)
        monkeypatch.setattr(evidence_bundle, "MAX_VERDICT_BYTES", 1)
        return b"{}"

    def load_object(_data: bytes, label: str) -> dict[str, object]:
        assert label == "verdict"
        events.append("early-load")
        return record

    def verify(value: object) -> dict[str, object]:
        assert value is record
        events.append("early-verify")
        return {"ok": True, "checks": []}

    monkeypatch.setattr(evidence_bundle, "_read_regular_file", read_regular)
    monkeypatch.setattr(evidence_bundle, "_load_json_object", load_object)
    monkeypatch.setattr(record_verifier, "verify_record", verify)

    assert cli._read_semantic_finalizer_record("verdict.json") is record
    assert events == ["early-read", "early-load", "early-verify"]


def test_binding_imports_snapshot_but_semantic_reader_and_reporter_stay_live(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Entry imports freeze while facade globals resolve at their call sites."""

    args = cli.build_parser().parse_args(
        [
            "verify-finalizer-bindings",
            "verdict.json",
            "--bindings",
            "bindings.json",
            "--source-out",
            "source.json",
            "--context-out",
            "context.json",
        ]
    )
    events: list[str] = []
    bindings = SimpleNamespace()
    record = {"format": "controlled"}

    def late_context(*_args: object, **_kwargs: object) -> object:
        pytest.fail("context helper was resolved after command entry")

    def late_write(*_args: object, **_kwargs: object) -> object:
        pytest.fail("context writer was resolved after command entry")

    def late_semantic(path: str) -> dict[str, object]:
        assert path == "verdict.json"
        events.append("late-semantic")
        return record

    def late_report(_out: object, value: dict[str, object]) -> None:
        events.append(f"late-report:{value['status']}")

    def read_bindings(path: str) -> object:
        assert path == "bindings.json"
        events.append("early-bindings")
        monkeypatch.setattr(
            finalizer_derivation,
            "context_from_verified_bindings",
            late_context,
        )
        monkeypatch.setattr(
            finalizer_derivation,
            "write_verified_finalizer_context",
            late_write,
        )
        monkeypatch.setattr(cli, "_read_semantic_finalizer_record", late_semantic)
        monkeypatch.setattr(cli, "_machine_report", late_report)
        return bindings

    def context(value: object, verdict: object) -> tuple[dict, dict]:
        assert value is bindings
        assert verdict is record
        events.append("early-context")
        return {"source": True}, {"context": True}

    def write(
        value: object,
        verdict: object,
        *,
        source_path: str,
        context_path: str,
        force: bool,
    ) -> tuple[str, str]:
        assert value is bindings
        assert verdict is record
        assert (source_path, context_path, force) == (
            "source.json",
            "context.json",
            False,
        )
        events.append("early-write")
        return source_path, context_path

    monkeypatch.setattr(
        finalizer_derivation,
        "read_finalizer_bindings",
        read_bindings,
    )
    monkeypatch.setattr(
        finalizer_derivation,
        "context_from_verified_bindings",
        context,
    )
    monkeypatch.setattr(
        finalizer_derivation,
        "write_verified_finalizer_context",
        write,
    )

    assert cli.cmd_verify_finalizer_bindings(args, out=lambda _value: None) == 0
    assert events == [
        "early-bindings",
        "late-semantic",
        "early-context",
        "early-write",
        "late-report:VERIFIED",
    ]


def test_handoff_reads_and_path_stay_live_but_creator_snapshots_at_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """External reads/path/report stay live while the creator is entry-bound."""

    args = cli.build_parser().parse_args(
        [
            "finalizer-handoff",
            "verdict.json",
            "--out",
            "handoff.json",
            "--source",
            "source.json",
            "--context",
            "context.json",
        ]
    )
    events: list[str] = []

    def late_create(*_args: object, **_kwargs: object) -> object:
        pytest.fail("handoff creator was resolved after command entry")

    def late_read(path: str, *, label: str) -> dict[str, object]:
        events.append(f"late-read:{label}")
        return {"path": path, "label": label}

    def late_abspath(path: str) -> str:
        events.append("late-abspath")
        return "ABS:" + path

    def late_report(_out: object, value: dict[str, object]) -> None:
        events.append(f"late-report:{value['status']}")

    def first_read(path: str, *, label: str) -> dict[str, object]:
        events.append(f"first-read:{label}")
        monkeypatch.setattr(cli, "_read_external_finalizer_object", late_read)
        monkeypatch.setattr(
            trusted_finalizer,
            "create_finalizer_handoff",
            late_create,
        )
        monkeypatch.setattr(cli.os.path, "abspath", late_abspath)
        monkeypatch.setattr(cli, "_machine_report", late_report)
        return {"path": path, "label": label}

    def early_create(
        _verdict: str,
        _output: str,
        *,
        source: object,
        context: object,
        force: bool,
    ) -> dict[str, object]:
        del force
        events.append("early-create")
        return {
            "record": {"sha256": "d" * 64},
            "source": source,
            "context": context,
        }

    monkeypatch.setattr(cli, "_read_external_finalizer_object", first_read)
    monkeypatch.setattr(
        trusted_finalizer,
        "create_finalizer_handoff",
        early_create,
    )

    assert cli.cmd_finalizer_handoff(args, out=lambda _value: None) == 0
    assert events == [
        "first-read:source",
        "late-read:context",
        "early-create",
        "late-abspath",
        "late-report:CREATED",
    ]


def test_seal_imports_snapshot_but_readers_and_material_parser_stay_live(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Trusted inputs are live; imported binding/sealing functions stay fixed."""

    args = cli.build_parser().parse_args(
        [
            "seal-finalizer",
            "handoff.json",
            "verdict.json",
            "--out",
            "bundle.evb",
            "--expected-source",
            "source.json",
            "--expected-context",
            "context.json",
            "--expected-derivation",
            "bindings.json",
            "--sign-key",
            "private.key",
            "--material",
            "logs=log.txt",
        ]
    )
    events: list[str] = []
    bindings = SimpleNamespace(payload={"format": "bindings"})

    def late_bindings(_path: str) -> object:
        pytest.fail("binding reader was resolved after command entry")

    def late_seal(*_args: object, **_kwargs: object) -> object:
        pytest.fail("sealer was resolved after command entry")

    def late_read(path: str, *, label: str) -> dict[str, object]:
        events.append(f"late-read:{label}")
        return {"path": path, "label": label}

    def late_materials(values: list[str]) -> list[object]:
        assert values == ["logs=log.txt"]
        events.append("late-materials")
        return [SimpleNamespace(role="logs", source_path="log.txt")]

    def late_report(_out: object, value: dict[str, object]) -> None:
        events.append(f"late-report:{value['status']}")

    def first_read(path: str, *, label: str) -> dict[str, object]:
        events.append(f"first-read:{label}")
        monkeypatch.setattr(cli, "_read_external_finalizer_object", late_read)
        monkeypatch.setattr(cli, "_parse_finalizer_materials", late_materials)
        monkeypatch.setattr(
            finalizer_derivation,
            "read_finalizer_bindings",
            late_bindings,
        )
        monkeypatch.setattr(
            trusted_finalizer,
            "seal_finalizer_bundle",
            late_seal,
        )
        monkeypatch.setattr(cli, "_machine_report", late_report)
        return {"path": path, "label": label}

    def early_bindings(path: str) -> object:
        assert path == "bindings.json"
        events.append("early-bindings")
        return bindings

    def early_seal(*_args: object, **_kwargs: object) -> object:
        events.append("early-seal")
        return SimpleNamespace(
            decision="ALLOW",
            finalized=SimpleNamespace(
                bundle_path="bundle.evb",
                manifest={
                    "record": {"sha256": "d" * 64},
                    "authentication": {"key_id": "key"},
                },
            ),
        )

    monkeypatch.setattr(cli, "_read_external_finalizer_object", first_read)
    monkeypatch.setattr(
        finalizer_derivation,
        "read_finalizer_bindings",
        early_bindings,
    )
    monkeypatch.setattr(
        trusted_finalizer,
        "seal_finalizer_bundle",
        early_seal,
    )

    assert cli.cmd_seal_finalizer(args, out=lambda _value: None) == 0
    assert events == [
        "first-read:expected source",
        "late-read:expected context",
        "early-bindings",
        "late-materials",
        "early-seal",
        "late-report:FINALIZED",
    ]


def test_verify_reads_stay_live_but_verifier_snapshots_at_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verifier imports freeze at entry while each external read stays live."""

    args = cli.build_parser().parse_args(
        [
            "verify-finalized",
            "bundle.evb",
            "--trusted-pub",
            "public.key",
            "--expected-source",
            "source.json",
            "--expected-context",
            "context.json",
        ]
    )
    events: list[str] = []

    def late_verify(*_args: object, **_kwargs: object) -> object:
        pytest.fail("finalized verifier was resolved after command entry")

    def late_read(path: str, *, label: str) -> dict[str, object]:
        events.append(f"late-read:{label}")
        return {"path": path, "label": label}

    def late_report(_out: object, value: dict[str, object]) -> None:
        events.append(f"late-report:{value['status']}")

    def first_read(path: str, *, label: str) -> dict[str, object]:
        events.append(f"first-read:{label}")
        monkeypatch.setattr(cli, "_read_external_finalizer_object", late_read)
        monkeypatch.setattr(
            trusted_finalizer,
            "verify_finalized_bundle",
            late_verify,
        )
        monkeypatch.setattr(cli, "_machine_report", late_report)
        return {"path": path, "label": label}

    def early_verify(*_args: object, **_kwargs: object) -> object:
        events.append("early-verify")
        return SimpleNamespace(
            decision="ALLOW",
            bundle=SimpleNamespace(
                manifest={"authentication": {"key_id": "key"}},
                record_report={"ok": True},
            ),
        )

    monkeypatch.setattr(cli, "_read_external_finalizer_object", first_read)
    monkeypatch.setattr(
        trusted_finalizer,
        "verify_finalized_bundle",
        early_verify,
    )

    assert cli.cmd_verify_finalized(args, out=lambda _value: None) == 0
    assert events == [
        "first-read:expected source",
        "late-read:expected context",
        "early-verify",
        "late-report:VERIFIED",
    ]
