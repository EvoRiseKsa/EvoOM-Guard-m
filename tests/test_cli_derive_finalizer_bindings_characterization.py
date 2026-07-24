"""Frozen equivalence gates for ``derive-finalizer-bindings`` extraction."""

from __future__ import annotations

import difflib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from evoom_guard import cli, finalizer_derivation
from tests.cli_derive_finalizer_bindings_characterization_harness import (
    CASE_NAMES,
    SCHEMA_VERSION,
    canonical_json,
    capture_case,
)

VECTOR = (
    Path(__file__).parent / "fixtures" / "refactor-safety" / "cli-derive-finalizer-bindings-v1.json"
)


def _frozen() -> dict:
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def test_cli_derive_finalizer_bindings_vector_metadata_is_exact() -> None:
    frozen = _frozen()
    assert frozen["schema_version"] == SCHEMA_VERSION
    assert tuple(frozen["cases"]) == tuple(sorted(CASE_NAMES))


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_frozen_cli_derive_finalizer_bindings_behavior(case_name: str) -> None:
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
        pytest.fail("derive-finalizer-bindings behavior drifted:\n" + diff)


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_machine_report_schema_order_is_canonical(case_name: str) -> None:
    messages = capture_case(case_name)["messages"]

    assert len(messages) == 1
    payload = json.loads(messages[0])
    assert messages[0] == json.dumps(payload, indent=2, sort_keys=True)


def test_dependencies_snapshot_at_entry_but_reporter_resolves_late(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Domain functions freeze at entry while the facade reporter stays live."""

    args = cli.build_parser().parse_args(
        [
            "derive-finalizer-bindings",
            "--base-repo",
            "base.git",
            "--head-repo",
            "head.git",
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
            "bindings.json",
        ]
    )
    events: list[str] = []
    bindings = SimpleNamespace(
        candidate_sha256="b" * 64,
        policy_sha256="c" * 64,
        verifier_pack_sha256=None,
    )

    def late_derive(**_kwargs: object) -> object:
        pytest.fail("derivation helper was resolved after command entry")

    def late_write(*_args: object, **_kwargs: object) -> str:
        pytest.fail("binding writer was resolved after command entry")

    def late_report(_out: object, value: dict[str, object]) -> None:
        events.append(f"late-report:{value['status']}")

    def early_derive(**_kwargs: object) -> object:
        events.append("early-derive")
        monkeypatch.setattr(
            finalizer_derivation,
            "derive_finalizer_bindings",
            late_derive,
        )
        monkeypatch.setattr(
            finalizer_derivation,
            "write_finalizer_bindings",
            late_write,
        )
        monkeypatch.setattr(cli, "_machine_report", late_report)
        return bindings

    def early_write(
        value: object,
        *,
        bindings_path: str,
        force: bool,
    ) -> str:
        assert value is bindings
        assert (bindings_path, force) == ("bindings.json", False)
        events.append("early-write")
        return bindings_path

    monkeypatch.setattr(
        finalizer_derivation,
        "derive_finalizer_bindings",
        early_derive,
    )
    monkeypatch.setattr(
        finalizer_derivation,
        "write_finalizer_bindings",
        early_write,
    )

    assert cli.cmd_derive_finalizer_bindings(args, out=lambda _value: None) == 0
    assert events == ["early-derive", "early-write", "late-report:DERIVED"]
