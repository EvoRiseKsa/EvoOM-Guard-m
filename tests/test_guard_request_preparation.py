# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Focused contracts for typed Guard request preparation."""

from __future__ import annotations

import importlib
from dataclasses import FrozenInstanceError, replace

import pytest

from evoom_guard.application.request_preparation import (
    GuardCompatibilityProjection,
    GuardRequestPreparationInput,
    GuardRequestPreparationServices,
    PreparedGuardRequest,
    prepare_guard_request,
)
from evoom_guard.domain import (
    CandidateInput,
    EffectivePolicy,
    GuardRequest,
    RepositoryInput,
    SourceIdentity,
)
from evoom_guard.policy import build_effective_policy, effective_policy_payload


def _raw(**overrides: object) -> GuardRequestPreparationInput:
    values: dict[str, object] = {
        "repository_path": "/trusted/base",
        "candidate_text": "opaque candidate",
        "deleted_paths": ("old.py",),
        "test_command": ["python", "-m", "pytest"],
        "setup_command": None,
        "trust_setup_on_host": False,
        "setup_output_globs": (),
        "protected": (),
        "allow": (),
        "allow_new_tests": False,
        "timeout": 120,
        "mem_limit_mb": 1024,
        "isolation": "subprocess",
        "docker_image": None,
        "docker_network": "none",
        "verifier_pack_path": None,
        "expect_verifier_pack_sha256": None,
        "collect_diff_coverage": False,
        "min_diff_coverage": None,
        "blackbox": False,
        "blackbox_only": False,
        "require_report_integrity": None,
        "require_candidate_isolation": None,
        "base_sha": None,
        "head_sha": None,
        "base_tree_sha": None,
        "head_tree_sha": None,
        "policy_id": None,
        "policy_version": None,
        "baseline_evidence": False,
        "require_demonstrated_fix": False,
        "strict_harness": False,
        "file_blocks": {"app.py": "VALUE = 2\n"},
    }
    values.update(overrides)
    return GuardRequestPreparationInput(**values)  # type: ignore[arg-type]


def _services() -> GuardRequestPreparationServices:
    return GuardRequestPreparationServices(
        repository_input_provider=lambda: RepositoryInput,
        candidate_input_provider=lambda: CandidateInput,
        source_identity_provider=lambda: SourceIdentity,
        effective_policy_provider=lambda: build_effective_policy,
        guard_request_provider=lambda: GuardRequest,
        effective_policy_payload_provider=lambda: effective_policy_payload,
    )


def test_preparation_contracts_are_frozen_and_scoped_before_mode_support() -> None:
    raw = _raw(
        isolation="docker",
        min_diff_coverage=85.0,
        require_demonstrated_fix=True,
    )
    prepared = prepare_guard_request(raw, services=_services())

    assert isinstance(prepared, PreparedGuardRequest)
    assert isinstance(prepared.compatibility, GuardCompatibilityProjection)
    assert prepared.request.collect_diff_coverage is True
    assert prepared.compatibility.collect_diff_coverage is True
    # Unsupported-mode policy is intentionally the next Guard-owned stage.
    assert prepared.compatibility.require_demonstrated_fix is True
    with pytest.raises(FrozenInstanceError):
        raw.timeout = 1  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        prepared.request = prepared.request  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        prepared.compatibility.timeout = 1  # type: ignore[misc]


def test_preparation_rejects_unknown_isolation_before_any_provider() -> None:
    calls: list[str] = []

    def unexpected(name: str):
        def provider():
            calls.append(name)
            raise AssertionError(f"{name} must not resolve")

        return provider

    services = GuardRequestPreparationServices(
        repository_input_provider=unexpected("repository"),
        candidate_input_provider=unexpected("candidate"),
        source_identity_provider=unexpected("source"),
        effective_policy_provider=unexpected("policy"),
        guard_request_provider=unexpected("request"),
        effective_policy_payload_provider=unexpected("payload"),
    )

    with pytest.raises(ValueError, match="unsupported isolation mode 'gvisro'"):
        prepare_guard_request(
            _raw(isolation="gvisro"),
            services=services,
        )

    assert calls == []


def test_projection_uses_owned_request_containers_not_caller_containers() -> None:
    deleted = ["old.py"]
    command = ["python", "-m", "pytest"]
    setup_command = ["python", "setup.py"]
    file_blocks = {"app.py": "VALUE = 2\n"}
    raw = _raw(
        deleted_paths=deleted,
        test_command=command,
        setup_command=setup_command,
        file_blocks=file_blocks,
    )
    services = _services()

    def payload_and_mutate(policy: EffectivePolicy) -> dict[str, object]:
        payload = effective_policy_payload(policy)
        deleted.append("late.py")
        command.append("--late")
        setup_command.append("--late")
        file_blocks["late.py"] = "LATE = True\n"
        return payload

    prepared = prepare_guard_request(
        raw,
        services=replace(
            services,
            effective_policy_payload_provider=lambda: payload_and_mutate,
        ),
    )

    assert prepared.compatibility.deleted_paths == ("old.py",)
    assert prepared.compatibility.test_command == ["python", "-m", "pytest"]
    assert prepared.compatibility.setup_command == ["python", "setup.py"]
    assert prepared.compatibility.file_blocks == {"app.py": "VALUE = 2\n"}
    assert prepared.compatibility.test_command is not command
    assert prepared.compatibility.setup_command is not setup_command
    assert prepared.compatibility.file_blocks is not file_blocks


def test_guard_facade_resolves_providers_at_each_historical_call_position(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A provider replaced by an earlier provider remains live in the same call."""

    guard_module = importlib.import_module("evoom_guard.guard")
    original_repository = guard_module.RepositoryInput
    original_candidate = guard_module.CandidateInput
    original_source = guard_module.SourceIdentity
    original_policy = guard_module._build_effective_policy_contract
    original_payload = guard_module._effective_policy_payload
    late_calls: list[str] = []

    def late_candidate(**values: object) -> CandidateInput:
        late_calls.append("candidate")
        monkeypatch.setattr(guard_module, "SourceIdentity", late_source)
        return original_candidate(**values)

    def late_source(**values: object) -> SourceIdentity:
        late_calls.append("source")
        monkeypatch.setattr(
            guard_module,
            "_build_effective_policy_contract",
            late_policy,
        )
        return original_source(**values)

    def late_policy(**values: object) -> EffectivePolicy:
        late_calls.append("policy")
        monkeypatch.setattr(guard_module, "_effective_policy_payload", late_payload)
        return original_policy(**values)

    def late_payload(policy: EffectivePolicy) -> dict[str, object]:
        late_calls.append("payload")
        payload = original_payload(policy)
        payload["provider_position_proof"] = "late"
        return payload

    def repository_provider(**values: object) -> RepositoryInput:
        monkeypatch.setattr(guard_module, "CandidateInput", late_candidate)
        return original_repository(**values)

    monkeypatch.setattr(guard_module, "RepositoryInput", repository_provider)

    result = guard_module.guard(
        "not-read-for-preflight",
        "opaque candidate",
        file_blocks={"app.py": "VALUE = 2\n"},
        isolation="docker",
        min_diff_coverage=80.0,
    )

    assert late_calls == ["candidate", "source", "policy", "payload"]
    assert result.attestation is not None
    assert (
        result.attestation["effective_policy"]["provider_position_proof"]  # type: ignore[index]
        == "late"
    )
