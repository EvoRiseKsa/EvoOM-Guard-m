"""Frozen equivalence gates for the bounded Agent Change CLI extraction."""

from __future__ import annotations

import difflib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from evoom_guard import cli, finalizer_derivation
from evoom_guard.admission import agent_change
from tests.cli_agent_change_command_characterization_harness import (
    CASE_NAMES,
    SCHEMA_VERSION,
    _normalized,
    canonical_json,
    capture_case,
)

VECTOR = Path(__file__).parent / "fixtures" / "refactor-safety" / "cli-agent-change-command-v1.json"


def _frozen() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_cli_agent_change_command_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_cli_agent_change_command_behavior(case_name: str) -> None:
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
        pytest.fail("Agent Change CLI command behavior drifted:\n" + diff)


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
    assert _normalized("/tmp/root/nested/file.json", "/tmp/root") == ("<ROOT>/nested/file.json")


def test_derive_dependencies_snapshot_at_entry_but_reporter_resolves_late(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Function-local imports freeze together; the CLI reporter stays live."""

    args = cli.build_parser().parse_args(
        [
            "derive-agent-change-bindings",
            "--base-repo",
            "base.git",
            "--head-repo",
            "head.git",
            "--git-executable",
            "/trusted/git",
            "--git-executable-sha256",
            "1" * 64,
            "--base-sha",
            "2" * 40,
            "--head-sha",
            "3" * 40,
            "--base-tree-sha",
            "4" * 40,
            "--head-tree-sha",
            "5" * 40,
            "--out",
            "bindings.json",
        ]
    )
    events: list[str] = []
    bindings = SimpleNamespace(
        candidate_sha256="a" * 64,
        touched_paths=("app.py",),
        policy_sha256="b" * 64,
        verifier_pack_sha256=None,
    )

    def late_derive(**_kwargs: object) -> object:
        pytest.fail("derive helper was resolved after the entry-time import")

    def late_write(
        _bindings: object,
        *,
        bindings_path: str,
        force: bool,
    ) -> str:
        pytest.fail("writer helper was resolved after the entry-time import")

    def late_report(
        _out: object,
        value: dict[str, object],
    ) -> None:
        events.append(f"late-report:{value['status']}")

    def pin(_path: str, _digest: str) -> str:
        events.append("pin")
        monkeypatch.setattr(
            finalizer_derivation,
            "derive_agent_change_bindings",
            late_derive,
        )
        monkeypatch.setattr(
            finalizer_derivation,
            "write_agent_change_bindings",
            late_write,
        )
        monkeypatch.setattr(cli, "_machine_report", late_report)
        return "/pinned/git"

    def derive(**_kwargs: object) -> object:
        events.append("early-derive")
        return bindings

    def write(
        value: object,
        *,
        bindings_path: str,
        force: bool,
    ) -> str:
        assert value is bindings
        assert bindings_path == "bindings.json"
        assert force is False
        events.append("early-write")
        return "bindings.json"

    monkeypatch.setattr(finalizer_derivation, "git_executable_pin", pin)
    monkeypatch.setattr(
        finalizer_derivation,
        "derive_agent_change_bindings",
        derive,
    )
    monkeypatch.setattr(
        finalizer_derivation,
        "write_agent_change_bindings",
        write,
    )

    assert cli.cmd_derive_agent_change_bindings(args, out=lambda _value: None) == 0
    assert events == [
        "pin",
        "early-derive",
        "early-write",
        "late-report:DERIVED",
    ]


def test_authorization_reads_stay_live_but_sealer_snapshots_at_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each facade read is late-bound while the imported sealer stays fixed."""

    args = cli.build_parser().parse_args(
        [
            "seal-agent-change-authorization",
            "--source",
            "source.json",
            "--scope",
            "scope.json",
            "--required",
            "required.json",
            "--sign-key",
            "private.key",
            "--out",
            "authorization.aca",
        ]
    )
    events: list[str] = []

    def late_seal(*_args: object, **_kwargs: object) -> object:
        pytest.fail("sealer helper was resolved after the entry-time import")

    def late_read(path: str, *, label: str) -> dict[str, object]:
        events.append(f"late-read:{label}")
        return {"path": path, "label": label}

    def first_read(path: str, *, label: str) -> dict[str, object]:
        events.append(f"first-read:{label}")
        monkeypatch.setattr(cli, "_read_external_finalizer_object", late_read)
        monkeypatch.setattr(
            agent_change,
            "seal_agent_change_authorization",
            late_seal,
        )
        return {"path": path, "label": label}

    def early_seal(
        _output_path: str,
        *,
        source: object,
        scope: object,
        required: object,
        private_key_path: str,
        force: bool,
    ) -> object:
        del required, private_key_path, force
        events.append("early-seal")
        return SimpleNamespace(
            payload={
                "authentication": {"key_id": "key"},
                "source": source,
                "scope": scope,
            }
        )

    monkeypatch.setattr(cli, "_read_external_finalizer_object", first_read)
    monkeypatch.setattr(
        agent_change,
        "seal_agent_change_authorization",
        early_seal,
    )

    assert (
        cli.cmd_seal_agent_change_authorization(
            args,
            out=lambda _value: None,
        )
        == 0
    )
    assert events == [
        "first-read:authorization source",
        "late-read:authorization scope",
        "late-read:authorization requirements",
        "early-seal",
    ]
