"""Independent verifier vectors for schema-1.12 operating profiles."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from evoom_guard.verifiers.record_policy import check_operating_profile


def _protected_policy() -> dict[str, object]:
    return {
        "operating_profile": "protected",
        "blackbox": True,
        "blackbox_only": True,
        "setup_command": None,
        "trust_setup_on_host": False,
        "verifier_pack_required": True,
        "expect_verifier_pack_sha256": "a" * 64,
        "require_report_integrity": "external_process_isolated",
        "docker_network": "none",
        "docker_image": "python@sha256:" + "b" * 64,
        "isolation": "docker",
        "require_candidate_isolation": "docker",
        "mem_limit_mb": 0,
    }


def test_verifier_profile_checker_has_no_producer_policy_dependency() -> None:
    source = Path("evoom_guard/verifiers/record_policy.py").read_text(encoding="utf-8")
    imports = {
        alias.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module or ""
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom)
    )
    assert not any(name.startswith("evoom_guard.domain") for name in imports)
    assert "operating_profile_violations" not in source


def test_verifier_accepts_frozen_protected_and_hostile_vectors() -> None:
    protected = _protected_policy()
    assert check_operating_profile(protected) == ()

    hostile = dict(protected)
    hostile.update(
        {
            "operating_profile": "hostile",
            "isolation": "gvisor",
            "require_candidate_isolation": "gvisor",
            "mem_limit_mb": 512,
        }
    )
    assert check_operating_profile(hostile) == ()


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    (
        ("blackbox", False, "requires blackbox=true"),
        ("blackbox_only", False, "requires blackbox_only=true"),
        (
            "setup_command",
            ["python", "-m", "build"],
            "forbids setup_command in black-box-only mode",
        ),
        ("trust_setup_on_host", True, "requires trust_setup_on_host=false"),
        ("verifier_pack_required", False, "requires a verifier_pack"),
        (
            "expect_verifier_pack_sha256",
            None,
            "requires expect_verifier_pack_sha256",
        ),
        (
            "expect_verifier_pack_sha256",
            "A" * 64,
            "requires expect_verifier_pack_sha256",
        ),
        (
            "require_report_integrity",
            None,
            "requires require_report_integrity='external_process_isolated'",
        ),
        ("docker_network", "bridge", "requires docker_network='none'"),
        ("docker_image", None, "requires docker_image"),
        (
            "isolation",
            "subprocess",
            "requires isolation='docker' or 'gvisor'",
        ),
        (
            "require_candidate_isolation",
            "gvisor",
            "requires require_candidate_isolation to match isolation",
        ),
    ),
)
def test_verifier_rejects_each_protected_profile_mutation(
    field: str,
    value: object,
    expected: str,
) -> None:
    policy = _protected_policy()
    policy[field] = value
    assert expected in check_operating_profile(policy)


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    (
        ("isolation", "docker", "requires isolation='gvisor'"),
        (
            "require_candidate_isolation",
            "docker",
            "requires require_candidate_isolation='gvisor'",
        ),
        ("mem_limit_mb", 0, "requires a non-zero mem_limit"),
    ),
)
def test_verifier_rejects_each_hostile_profile_mutation(
    field: str,
    value: object,
    expected: str,
) -> None:
    policy = _protected_policy()
    policy.update(
        {
            "operating_profile": "hostile",
            "isolation": "gvisor",
            "require_candidate_isolation": "gvisor",
            "mem_limit_mb": 512,
        }
    )
    policy[field] = value
    assert expected in check_operating_profile(policy)
