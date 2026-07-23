# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Frozen pre-extraction behavior for Guard request and policy preparation."""

from __future__ import annotations

import importlib
import math
from collections.abc import Callable
from typing import Any

import pytest

from evoom_guard.domain import (
    CandidateInput,
    EffectivePolicy,
    GuardRequest,
    RepositoryInput,
    SourceIdentity,
)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"timeout": 0}, "timeout must be a positive integer"),
        ({"timeout": True}, "timeout must be a positive integer"),
        ({"timeout": 1.5}, "timeout must be a positive integer"),
        ({"mem_limit_mb": -1}, "mem_limit_mb must be a non-negative integer"),
        ({"mem_limit_mb": False}, "mem_limit_mb must be a non-negative integer"),
        ({"mem_limit_mb": 1.5}, "mem_limit_mb must be a non-negative integer"),
        ({"strict_harness": 1}, "strict_harness must be a boolean"),
        ({"strict_harness": None}, "strict_harness must be a boolean"),
        (
            {"min_diff_coverage": True},
            "min_diff_coverage must be a finite number between 0 and 100",
        ),
        (
            {"min_diff_coverage": -0.01},
            "min_diff_coverage must be a finite number between 0 and 100",
        ),
        (
            {"min_diff_coverage": 100.01},
            "min_diff_coverage must be a finite number between 0 and 100",
        ),
        (
            {"min_diff_coverage": math.inf},
            "min_diff_coverage must be a finite number between 0 and 100",
        ),
        (
            {"min_diff_coverage": math.nan},
            "min_diff_coverage must be a finite number between 0 and 100",
        ),
        (
            {"min_diff_coverage": "80"},
            "min_diff_coverage must be a finite number between 0 and 100",
        ),
    ],
    ids=(
        "timeout-zero",
        "timeout-bool",
        "timeout-float",
        "memory-negative",
        "memory-bool",
        "memory-float",
        "strict-int",
        "strict-none",
        "coverage-bool",
        "coverage-negative",
        "coverage-over-100",
        "coverage-infinite",
        "coverage-nan",
        "coverage-string",
    ),
)
def test_invalid_runtime_values_fail_before_any_request_provider(
    monkeypatch: pytest.MonkeyPatch,
    kwargs: dict[str, object],
    message: str,
) -> None:
    guard_module = importlib.import_module("evoom_guard.guard")

    def unexpected_request(**_values: object) -> GuardRequest:
        raise AssertionError("request provider ran before public input validation")

    monkeypatch.setattr(guard_module, "GuardRequest", unexpected_request)
    with pytest.raises(ValueError, match=message):
        guard_module.guard(".", "", **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {"blackbox_only": True},
            "blackbox_only requires blackbox",
        ),
        (
            {"expect_verifier_pack_sha256": "A" * 64},
            "expect_verifier_pack_sha256 requires verifier_pack",
        ),
    ],
    ids=("blackbox-only-without-blackbox", "pack-digest-without-pack"),
)
def test_policy_contradictions_fail_before_any_request_provider(
    monkeypatch: pytest.MonkeyPatch,
    kwargs: dict[str, object],
    message: str,
) -> None:
    guard_module = importlib.import_module("evoom_guard.guard")

    def unexpected_request(**_values: object) -> GuardRequest:
        raise AssertionError("request provider ran for a contradictory policy")

    monkeypatch.setattr(guard_module, "GuardRequest", unexpected_request)
    with pytest.raises(ValueError, match=message):
        guard_module.guard(".", "", **kwargs)  # type: ignore[arg-type]


def test_frozen_request_policy_projection_and_provider_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Freeze ownership, canonicalization, and every provider call position."""

    guard_module = importlib.import_module("evoom_guard.guard")
    originals: dict[str, Callable[..., object]] = {
        "repository": guard_module.RepositoryInput,
        "candidate": guard_module.CandidateInput,
        "source": guard_module.SourceIdentity,
        "policy": guard_module._build_effective_policy_contract,
        "request": guard_module.GuardRequest,
        "payload": guard_module._effective_policy_payload,
    }
    provider_order: list[str] = []
    captured_requests: list[GuardRequest] = []
    deleted = ["old.py"]
    test_command = ["python", "-m", "pytest"]
    setup_command = ["python", "setup.py"]
    file_blocks = {
        "z.py": "VALUE = 'z'\n",
        "a.py": "VALUE = 'a'\n",
    }

    def repository_provider(**values: object) -> RepositoryInput:
        provider_order.append("repository")
        return originals["repository"](**values)  # type: ignore[return-value]

    def candidate_provider(**values: object) -> CandidateInput:
        provider_order.append("candidate")
        return originals["candidate"](**values)  # type: ignore[return-value]

    def source_provider(**values: object) -> SourceIdentity:
        provider_order.append("source")
        return originals["source"](**values)  # type: ignore[return-value]

    def policy_provider(**values: object) -> EffectivePolicy:
        provider_order.append("policy")
        return originals["policy"](**values)  # type: ignore[return-value]

    def request_provider(**values: object) -> GuardRequest:
        provider_order.append("request")
        request = originals["request"](**values)
        assert isinstance(request, GuardRequest)
        captured_requests.append(request)
        return request

    def payload_provider(policy: EffectivePolicy) -> dict[str, object]:
        provider_order.append("payload")
        payload = originals["payload"](policy)
        assert isinstance(payload, dict)
        # These mutations occur at the historical seam after the owned request
        # exists but before Guard projects it back to legacy local containers.
        deleted.append("late-delete.py")
        test_command.append("--late-test")
        setup_command.append("--late-setup")
        file_blocks["late.py"] = "LATE = True\n"
        return payload

    monkeypatch.setattr(guard_module, "RepositoryInput", repository_provider)
    monkeypatch.setattr(guard_module, "CandidateInput", candidate_provider)
    monkeypatch.setattr(guard_module, "SourceIdentity", source_provider)
    monkeypatch.setattr(
        guard_module,
        "_build_effective_policy_contract",
        policy_provider,
    )
    monkeypatch.setattr(guard_module, "GuardRequest", request_provider)
    monkeypatch.setattr(guard_module, "_effective_policy_payload", payload_provider)

    result = guard_module.guard(
        "not-read-for-preflight",
        "opaque candidate",
        deleted=deleted,  # type: ignore[arg-type]
        test_command=test_command,
        setup_command=setup_command,
        trust_setup_on_host=True,
        setup_output_globs=("z/**", "a/**", "z/**"),
        protected=("z/**", "a/**"),
        allow=("z.py", "a.py"),
        allow_new_tests=True,
        timeout=23,
        mem_limit_mb=456,
        isolation="docker",
        docker_image="example.invalid/judge@sha256:" + "1" * 64,
        docker_network="bridge",
        verifier_pack="packs/core",
        expect_verifier_pack_sha256="A" * 64,
        diff_coverage=False,
        min_diff_coverage=80.0,
        blackbox=False,
        blackbox_only=False,
        require_report_integrity="same_process_candidate_writable",
        require_candidate_isolation="docker",
        base_sha="a" * 40,
        head_sha="b" * 40,
        base_tree_sha="c" * 40,
        head_tree_sha="d" * 40,
        policy_id="org/prod",
        policy_version="4",
        baseline_evidence=True,
        require_demonstrated_fix=False,
        strict_harness=True,
        file_blocks=file_blocks,
    )

    assert provider_order == [
        "repository",
        "candidate",
        "source",
        "policy",
        "request",
        "payload",
    ]
    assert len(captured_requests) == 1
    request = captured_requests[0]
    assert request.repository == RepositoryInput(path="not-read-for-preflight")
    assert request.candidate.text == "opaque candidate"
    assert request.candidate.deleted_paths == ("old.py",)
    assert dict(request.candidate.file_blocks or {}) == {
        "z.py": "VALUE = 'z'\n",
        "a.py": "VALUE = 'a'\n",
    }
    assert request.source == SourceIdentity(
        base_sha="a" * 40,
        head_sha="b" * 40,
        base_tree_sha="c" * 40,
        head_tree_sha="d" * 40,
    )
    # A coverage floor turns collection on before policy construction.
    assert request.collect_diff_coverage is True
    assert request.policy.test_command == ("python", "-m", "pytest")
    assert request.policy.setup_command == ("python", "setup.py")
    assert request.policy.setup_output_globs == ("a/**", "z/**", "z/**")
    assert request.policy.protected == ("a/**", "z/**")
    assert request.policy.allow == ("a.py", "z.py")
    assert request.policy.expect_verifier_pack_sha256 == "a" * 64

    expected_policy: dict[str, Any] = {
        "mode": "repo",
        "isolation": "docker",
        "docker_image": "example.invalid/judge@sha256:" + "1" * 64,
        "docker_network": "bridge",
        "test_command": ["python", "-m", "pytest"],
        "setup_command": ["python", "setup.py"],
        "trust_setup_on_host": True,
        "setup_output_globs": ["a/**", "z/**", "z/**"],
        "protected": ["a/**", "z/**"],
        "allow": ["a.py", "z.py"],
        "allow_new_tests": True,
        "timeout": 23,
        "mem_limit_mb": 456,
        "verifier_pack_required": True,
        "expect_verifier_pack_sha256": "a" * 64,
        "blackbox": False,
        "blackbox_only": False,
        "require_report_integrity": "same_process_candidate_writable",
        "require_candidate_isolation": "docker",
        "min_diff_coverage": 80.0,
        "baseline_evidence": True,
        "require_demonstrated_fix": False,
        "strict_harness": True,
        "policy_id": "org/prod",
        "policy_version": "4",
    }
    assert result.verdict == "ERROR"
    assert result.reason_code == "policy_requirement_unsupported"
    assert result.files_changed == ["a.py", "z.py"]
    assert result.attestation is not None
    assert result.attestation["effective_policy"] == expected_policy
    assert result.attestation["test_command"] == ["python", "-m", "pytest"]


def test_outer_request_provider_is_resolved_before_nested_providers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Freeze Python's historical outer-callable evaluation timing."""

    guard_module = importlib.import_module("evoom_guard.guard")
    original_repository = guard_module.RepositoryInput
    original_request = guard_module.GuardRequest
    calls: list[str] = []

    def late_request(**values: object) -> GuardRequest:
        calls.append("late-request")
        return original_request(**values)

    def initial_request(**values: object) -> GuardRequest:
        calls.append("initial-request")
        return original_request(**values)

    def repository_provider(**values: object) -> RepositoryInput:
        calls.append("repository")
        monkeypatch.setattr(guard_module, "GuardRequest", late_request)
        return original_repository(**values)

    monkeypatch.setattr(guard_module, "GuardRequest", initial_request)
    monkeypatch.setattr(guard_module, "RepositoryInput", repository_provider)

    result = guard_module.guard(
        "not-read-for-preflight",
        "opaque candidate",
        file_blocks={"app.py": "VALUE = 2\n"},
        isolation="docker",
        min_diff_coverage=80.0,
    )

    assert result.reason_code == "policy_requirement_unsupported"
    assert calls == ["repository", "initial-request"]
