"""Frozen public characterization for unified-diff verification."""

from __future__ import annotations

from pathlib import Path

import pytest
from diff_verification_characterization_harness import CASE_NAMES, capture_case


@pytest.mark.parametrize("case_name", CASE_NAMES)
def test_diff_verification_case_is_deterministic(
    case_name: str,
    tmp_path: Path,
) -> None:
    assert capture_case(case_name, tmp_path) == capture_case(
        case_name,
        tmp_path / "repeat",
    )


@pytest.mark.parametrize(
    ("case_name", "reason_code"),
    (
        ("empty_preflight", "empty_diff"),
        ("binary_preflight", "binary_patch"),
        ("unsafe_path_preflight", "unsafe_path"),
        ("pack_trust_preflight", "verifier_pack_invalid"),
    ),
)
def test_preflight_failures_allocate_nothing(
    case_name: str,
    reason_code: str,
    tmp_path: Path,
) -> None:
    case = capture_case(case_name, tmp_path)

    assert case["decision"]["reason_code"] == reason_code
    assert case["deleted"] == []
    assert case["exception"] is None
    assert not any(event.startswith("workspace:create") for event in case["timeline"])
    assert case["guard_call"] is None


def test_reverse_apply_failure_still_cleans_up(tmp_path: Path) -> None:
    case = capture_case("reverse_apply_failure", tmp_path)

    assert case["decision"]["reason_code"] == "reverse_apply_failed"
    assert case["timeline"][-2:] == [
        "reverse:early",
        "workspace:cleanup:True:True",
    ]


def test_unverifiable_paths_are_fail_closed_after_reconstruction(
    tmp_path: Path,
) -> None:
    case = capture_case("unverifiable_paths", tmp_path)

    assert case["decision"]["reason_code"] == "no_verifiable_changes"
    assert case["decision"]["base_reconstruction"] == "ok"
    assert "blob.bin: binary file" in case["decision"]["reason"]
    assert case["timeline"][-2:] == [
        "blocks:early",
        "workspace:cleanup:True:True",
    ]


def test_empty_reconstruction_does_not_invoke_guard(tmp_path: Path) -> None:
    case = capture_case("no_verifiable_changes", tmp_path)

    assert case["decision"]["reason_code"] == "no_verifiable_changes"
    assert case["decision"]["base_reconstruction"] == "ok"
    assert case["guard_call"] is None
    assert case["deleted"] == []


def test_success_serializes_and_forwards_every_historical_input(
    tmp_path: Path,
) -> None:
    case = capture_case("success_forwards_every_option", tmp_path)
    call = case["guard_call"]

    assert case["exception"] is None
    assert case["decision"] == {
        "type": "ProbeResult",
        "verdict": None,
        "reason_code": None,
        "reason": None,
        "source": "diff",
        "base_reconstruction": "ok",
        "marker": "early",
    }
    assert case["deleted"] == ["old.py"]
    assert call["candidate"] == "<<<FILE: app.py>>>\nVALUE = 2\n\n<<<END FILE>>>"
    assert call["keyword_order"] == [
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
    ]
    assert call["kwargs"] == {
        "deleted": ("old.py",),
        "trust_setup_on_host": True,
        "setup_output_globs": ("generated/**",),
        "protected": ("policy/**",),
        "allow": ("policy/approved.py",),
        "allow_new_tests": True,
        "timeout": 37,
        "mem_limit_mb": 731,
        "isolation": "docker",
        "docker_image": "python@sha256:" + ("a" * 64),
        "docker_network": "none",
        "verifier_pack": "trusted-pack",
        "expect_verifier_pack_sha256": "b" * 64,
        "diff_coverage": True,
        "min_diff_coverage": 87.5,
        "blackbox": True,
        "blackbox_only": True,
        "require_report_integrity": "external_process",
        "require_candidate_isolation": "container",
        "base_sha": "inferred-base",
        "head_sha": "inferred-head",
        "base_tree_sha": "base-tree",
        "head_tree_sha": "head-tree",
        "policy_id": "policy-id",
        "policy_version": "2026.07",
        "baseline_evidence": True,
        "require_demonstrated_fix": True,
        "strict_harness": True,
        "file_blocks": {"app.py": "VALUE = 2\n"},
        "test_command_identity": True,
        "setup_command_identity": True,
    }
    assert case["timeline"][-4:] == [
        "sha:base:early",
        "sha:head:early",
        "guard:early",
        "workspace:cleanup:True:True",
    ]


def test_explicit_revision_identity_short_circuits_diff_parsers(
    tmp_path: Path,
) -> None:
    case = capture_case("explicit_sha_short_circuit", tmp_path)

    assert case["exception"] is None
    assert not any(event.startswith("sha:") for event in case["timeline"])
    assert case["guard_call"]["kwargs"]["base_sha"] == "explicit-base"
    assert case["guard_call"]["kwargs"]["head_sha"] == "explicit-head"


def test_live_provider_rebinding_is_preserved(tmp_path: Path) -> None:
    case = capture_case("live_provider_rebinding", tmp_path)

    assert case["exception"] is None
    assert "reverse:early" not in case["timeline"]
    assert "blocks:early" not in case["timeline"]
    assert case["timeline"][-6:] == [
        "reverse:late",
        "blocks:late",
        "sha:base:late",
        "sha:head:late",
        "guard:late",
        "workspace:cleanup:True:True",
    ]
    assert case["guard_call"]["label"] == "late"
    assert case["guard_call"]["kwargs"]["base_sha"] == "late-base"
    assert case["guard_call"]["kwargs"]["head_sha"] == "late-head"


@pytest.mark.parametrize(
    ("case_name", "message", "required_tail"),
    (
        (
            "copy_exception_cleans_up",
            "synthetic copy failure",
            ["copy:HEAD:True", "workspace:cleanup:True:True"],
        ),
        (
            "write_exception_cleans_up",
            "synthetic write failure",
            ["write:exit", "workspace:cleanup:True:True"],
        ),
        (
            "guard_exception_cleans_up",
            "synthetic guard failure",
            ["guard:early", "workspace:cleanup:True:True"],
        ),
    ),
)
def test_primary_exceptions_propagate_after_cleanup(
    case_name: str,
    message: str,
    required_tail: list[str],
    tmp_path: Path,
) -> None:
    case = capture_case(case_name, tmp_path)

    assert case["decision"] is None
    assert case["exception"] == {"type": "ProbeError", "message": message}
    assert case["timeline"][-2:] == required_tail


def test_cleanup_exception_preserves_historical_masking(tmp_path: Path) -> None:
    case = capture_case("cleanup_exception_masks_success", tmp_path)

    assert case["decision"] is None
    assert case["deleted"] is None
    assert case["exception"] == {
        "type": "ProbeError",
        "message": "synthetic cleanup failure",
    }
    assert case["timeline"][-2:] == [
        "guard:early",
        "workspace:cleanup:True:True",
    ]


def test_base_path_join_failure_occurs_outside_cleanup_boundary(
    tmp_path: Path,
) -> None:
    case = capture_case("workspace_join_exception_precedes_cleanup", tmp_path)

    assert case["exception"] == {
        "type": "ProbeError",
        "message": "synthetic base-path failure",
    }
    assert case["timeline"][-2:] == [
        "workspace:create:evo_guard_diff_",
        "path:join:base",
    ]
    assert not any(event.startswith("workspace:cleanup") for event in case["timeline"])
