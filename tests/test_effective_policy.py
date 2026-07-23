# -----------------------------------------------------------------------------
# Copyright (c) 2026 EvoRise Tech. All rights reserved.
# Source-available — see LICENSE for permitted use.
# Original creator: Mana Alharbi (مانع الحربي).
# -----------------------------------------------------------------------------
"""Compatibility gates for the extracted effective-policy contract."""

from __future__ import annotations

import inspect
from dataclasses import FrozenInstanceError

import pytest

from evoom_guard import domain
from evoom_guard import policy as policy_api
from evoom_guard.guard import (
    _effective_policy as legacy_effective_policy,
)
from evoom_guard.guard import (
    effective_policy_sha256 as legacy_effective_policy_sha256,
)
from evoom_guard.guard import guard


def _defaults() -> dict[str, object]:
    return {
        "mode": "repo",
        "isolation": "subprocess",
        "docker_image": None,
        "docker_network": "none",
        "test_command": None,
        "setup_command": None,
        "trust_setup_on_host": False,
        "setup_output_globs": (),
        "protected": (),
        "allow": (),
        "allow_new_tests": False,
        "timeout": 120,
        "mem_limit_mb": 1024,
        "verifier_pack": None,
        "expect_verifier_pack_sha256": None,
        "blackbox": False,
        "blackbox_only": False,
        "require_report_integrity": None,
        "require_candidate_isolation": None,
        "min_diff_coverage": None,
        "baseline_evidence": False,
        "require_demonstrated_fix": False,
        "strict_harness": False,
        "policy_id": None,
        "policy_version": None,
    }


def _build_defaults() -> domain.EffectivePolicy:
    return policy_api.build_effective_policy(
        mode="repo",
        isolation="subprocess",
        docker_image=None,
        docker_network="none",
        test_command=None,
        setup_command=None,
        trust_setup_on_host=False,
        setup_output_globs=(),
        protected=(),
        allow=(),
        allow_new_tests=False,
        timeout=120,
        mem_limit_mb=1024,
        verifier_pack=None,
        expect_verifier_pack_sha256=None,
        blackbox=False,
        blackbox_only=False,
        require_report_integrity=None,
        require_candidate_isolation=None,
        min_diff_coverage=None,
        baseline_evidence=False,
        require_demonstrated_fix=False,
        strict_harness=False,
        policy_id=None,
        policy_version=None,
    )


def test_policy_public_api_reexports_the_dependency_free_domain_type() -> None:
    assert policy_api.EffectivePolicy is domain.EffectivePolicy
    assert policy_api.build_effective_policy.__module__ == "evoom_guard.policy.effective"
    assert policy_api.effective_policy_payload.__module__ == "evoom_guard.policy.effective"


def test_effective_policy_is_frozen_and_uses_immutable_sequences() -> None:
    value = _build_defaults()
    assert value.test_command is None
    assert value.protected == ()
    with pytest.raises(FrozenInstanceError):
        value.timeout = 1  # type: ignore[misc]


def test_default_payload_and_digest_remain_frozen() -> None:
    payload = policy_api.effective_policy_payload(_build_defaults())
    assert payload == {
        "mode": "repo",
        "isolation": "subprocess",
        "docker_image": None,
        "docker_network": "none",
        "test_command": "default:python -m pytest",
        "setup_command": None,
        "trust_setup_on_host": False,
        "setup_output_globs": [],
        "protected": [],
        "allow": [],
        "allow_new_tests": False,
        "timeout": 120,
        "mem_limit_mb": 1024,
        "verifier_pack_required": False,
        "expect_verifier_pack_sha256": None,
        "blackbox": False,
        "blackbox_only": False,
        "require_report_integrity": None,
        "require_candidate_isolation": None,
        "min_diff_coverage": None,
        "baseline_evidence": False,
        "require_demonstrated_fix": False,
        "strict_harness": False,
        "policy_id": None,
        "policy_version": None,
    }
    assert (
        policy_api.effective_policy_sha256(payload)
        == "38fe5c6017c500608cb50ea3ee687b89eecb35ac8dd47bb68ccc158df42caf25"
    )


def test_full_payload_preserves_order_normalization_and_digest() -> None:
    value = policy_api.build_effective_policy(
        mode="blackbox",
        isolation="docker",
        docker_image="example@sha256:abc",
        docker_network="none",
        test_command=["python", "-m", "pytest", "-q"],
        setup_command=["python", "setup.py"],
        trust_setup_on_host=True,
        setup_output_globs=("z/**", "a/**"),
        protected=("z", "a"),
        allow=("b", "a"),
        allow_new_tests=True,
        timeout=9,
        mem_limit_mb=512,
        verifier_pack="packs/core",
        expect_verifier_pack_sha256="A" * 64,
        blackbox=True,
        blackbox_only=True,
        require_report_integrity="signed",
        require_candidate_isolation="external_process_isolated",
        min_diff_coverage=91.5,
        baseline_evidence=True,
        require_demonstrated_fix=False,
        strict_harness=True,
        policy_id="org/core",
        policy_version="7",
    )
    payload = policy_api.effective_policy_payload(value)

    assert list(payload) == [
        "mode",
        "isolation",
        "docker_image",
        "docker_network",
        "test_command",
        "setup_command",
        "trust_setup_on_host",
        "setup_output_globs",
        "protected",
        "allow",
        "allow_new_tests",
        "timeout",
        "mem_limit_mb",
        "verifier_pack_required",
        "expect_verifier_pack_sha256",
        "blackbox",
        "blackbox_only",
        "require_report_integrity",
        "require_candidate_isolation",
        "min_diff_coverage",
        "baseline_evidence",
        "require_demonstrated_fix",
        "strict_harness",
        "policy_id",
        "policy_version",
    ]
    assert payload["test_command"] == ["python", "-m", "pytest", "-q"]
    assert payload["setup_command"] == ["python", "setup.py"]
    assert payload["setup_output_globs"] == ["a/**", "z/**"]
    assert payload["protected"] == ["a", "z"]
    assert payload["allow"] == ["a", "b"]
    assert payload["expect_verifier_pack_sha256"] == "a" * 64
    assert (
        policy_api.effective_policy_sha256(payload)
        == "a4ff9326fa418fd05f501ea8d14abcc92aeb39f924ab28c49bb453df405a4fdf"
    )


def test_legacy_guard_policy_facades_remain_exact() -> None:
    defaults = _defaults()
    legacy = legacy_effective_policy(**defaults)  # type: ignore[arg-type]
    public = policy_api.effective_policy_payload(_build_defaults())
    assert legacy == public
    assert legacy_effective_policy_sha256(legacy) == policy_api.effective_policy_sha256(
        public
    )


def test_guard_callable_surface_is_frozen_during_internal_extraction() -> None:
    signature = inspect.signature(guard)
    assert tuple(signature.parameters) == (
        "repo_path",
        "candidate",
        "deleted",
        "test_command",
        "setup_command",
        "trust_setup_on_host",
        "setup_output_globs",
        "protected",
        "allow",
        "allow_new_tests",
        "timeout",
        "mem_limit_mb",
        "isolation",
        "docker_image",
        "docker_network",
        "verifier_pack",
        "expect_verifier_pack_sha256",
        "diff_coverage",
        "min_diff_coverage",
        "blackbox",
        "blackbox_only",
        "require_report_integrity",
        "require_candidate_isolation",
        "base_sha",
        "head_sha",
        "base_tree_sha",
        "head_tree_sha",
        "policy_id",
        "policy_version",
        "baseline_evidence",
        "require_demonstrated_fix",
        "strict_harness",
        "file_blocks",
    )
    assert signature.parameters["repo_path"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert signature.parameters["candidate"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in tuple(signature.parameters.values())[2:]
    )
