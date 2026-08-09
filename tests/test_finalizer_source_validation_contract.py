# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from evoom_guard import artifact_admission, artifact_digest_admission, trusted_finalizer


def _source() -> dict[str, object]:
    return {
        "pull_request_number": 42,
        "workflow_run_id": "123456",
        "workflow_run_attempt": 1,
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
    }


def _context() -> dict[str, object]:
    return {
        "repository": "owner/project",
        "repository_id": "12345",
        "run_id": "123456",
        "run_attempt": 1,
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
        "base_tree_sha": "c" * 40,
        "head_tree_sha": "d" * 40,
        "candidate_sha256": "e" * 64,
        "policy_sha256": "f" * 64,
        "verifier_pack_sha256": None,
        "guard_artifact_sha256": "0" * 64,
    }


def _finalizer() -> dict[str, object]:
    return {
        "bundle_sha256": "1" * 64,
        "record_sha256": "2" * 64,
        "key_id": "sha256:" + "3" * 64,
        "source": _source(),
        "context": _context(),
    }


def test_public_finalizer_source_validators_preserve_legacy_identity_and_errors() -> None:
    assert trusted_finalizer._validate_source is trusted_finalizer.validate_finalizer_source
    assert (
        trusted_finalizer._validate_source_context
        is trusted_finalizer.validate_finalizer_source_context
    )

    source = _source()
    verified = trusted_finalizer.validate_finalizer_source(source)
    assert verified == source
    assert verified is not source
    assert trusted_finalizer.validate_finalizer_source_context(verified, _context()) is None

    bad_source = dict(source, head_sha="not-a-digest")
    failures: list[trusted_finalizer.FinalizerHandoffError] = []
    for validator in (
        trusted_finalizer.validate_finalizer_source,
        trusted_finalizer._validate_source,
    ):
        with pytest.raises(trusted_finalizer.FinalizerHandoffError) as caught:
            validator(bad_source)
        failures.append(caught.value)
    assert type(failures[0]) is type(failures[1]) is trusted_finalizer.FinalizerHandoffError
    assert failures[0].args == failures[1].args == (
        "source.head_sha must be a lowercase 40/64-character Git digest",
    )

    mismatched_context = dict(_context(), head_sha="c" * 40)
    context_failures: list[trusted_finalizer.FinalizerHandoffError] = []
    for validator in (
        trusted_finalizer.validate_finalizer_source_context,
        trusted_finalizer._validate_source_context,
    ):
        with pytest.raises(trusted_finalizer.FinalizerHandoffError) as caught:
            validator(source, mismatched_context)
        context_failures.append(caught.value)
    assert context_failures[0].args == context_failures[1].args == (
        "source.head_sha must exactly match context.head_sha",
    )


def test_trusted_finalizer_legacy_aliases_remain_late_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    source_validator = trusted_finalizer.validate_finalizer_source
    context_validator = trusted_finalizer.validate_finalizer_source_context

    def legacy_source(value: Mapping[str, Any]) -> dict[str, Any]:
        events.append("source")
        return source_validator(value)

    def legacy_context(source: Mapping[str, Any], context: Mapping[str, Any]) -> None:
        events.append("context")
        context_validator(source, context)

    monkeypatch.setattr(trusted_finalizer, "_validate_source", legacy_source)
    monkeypatch.setattr(trusted_finalizer, "_validate_source_context", legacy_context)
    handoff = tmp_path / "handoff.json"
    handoff.write_bytes(
        trusted_finalizer._canonical_json(
            {
                "format": trusted_finalizer.FINALIZER_HANDOFF_FORMAT,
                "source": _source(),
                "context": _context(),
                "record": {"sha256": "4" * 64, "size": 1},
            }
        )
    )

    inspected = trusted_finalizer.inspect_finalizer_handoff(str(handoff))
    assert inspected.source == _source()
    assert events == ["source", "context"]


@pytest.mark.parametrize(
    ("consumer", "error_type", "error_prefix"),
    (
        (
            artifact_admission,
            artifact_admission.ArtifactAdmissionError,
            "invalid artifact binding finalizer: contract sentinel",
        ),
        (
            artifact_digest_admission,
            artifact_digest_admission.ArtifactDigestAdmissionError,
            "invalid artifact digest binding finalizer: contract sentinel",
        ),
    ),
    ids=("artifact-admission-v1", "artifact-digest-admission-v2"),
)
def test_artifact_admission_consumers_late_bind_public_source_contracts(
    monkeypatch: pytest.MonkeyPatch,
    consumer: ModuleType,
    error_type: type[ValueError],
    error_prefix: str,
) -> None:
    events: list[str] = []

    def validate_source(value: object) -> dict[str, object]:
        assert value == _source()
        events.append("source")
        return dict(_source(), workflow_run_id="late-bound")

    def validate_context(source: object, context: object) -> None:
        assert source == dict(_source(), workflow_run_id="late-bound")
        assert context == _context()
        events.append("context")

    monkeypatch.setattr(consumer, "validate_finalizer_source", validate_source)
    monkeypatch.setattr(consumer, "validate_finalizer_source_context", validate_context)

    verified = consumer._validate_finalizer(_finalizer())
    assert events == ["source", "context"]
    assert verified["source"] == dict(_source(), workflow_run_id="late-bound")

    sentinel = trusted_finalizer.FinalizerHandoffError("contract sentinel")

    def reject_source(_value: object) -> dict[str, object]:
        raise sentinel

    monkeypatch.setattr(consumer, "validate_finalizer_source", reject_source)
    with pytest.raises(error_type, match=error_prefix) as caught:
        consumer._validate_finalizer(_finalizer())
    assert caught.value.__cause__ is sentinel
