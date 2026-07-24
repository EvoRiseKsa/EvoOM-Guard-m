"""Architecture contracts for the extracted diff-verification coordinator."""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import evoom_guard.application as application
from evoom_guard.application.diff_verification import (
    DiffVerificationOptions,
    DiffVerificationOutcome,
    DiffVerificationRequest,
    verify_diff,
)


def _options() -> DiffVerificationOptions:
    return DiffVerificationOptions(
        test_command=None,
        setup_command=None,
        trust_setup_on_host=False,
        setup_output_globs=(),
        protected=(),
        allow=(),
        allow_new_tests=False,
        timeout=120,
        mem_limit_mb=1024,
        isolation="subprocess",
        docker_image=None,
        docker_network="none",
        verifier_pack=None,
        expect_verifier_pack_sha256=None,
        diff_coverage=False,
        min_diff_coverage=None,
        blackbox=False,
        blackbox_only=False,
        require_report_integrity=None,
        require_candidate_isolation=None,
        base_sha=None,
        head_sha=None,
        base_tree_sha=None,
        head_tree_sha=None,
        policy_id=None,
        policy_version=None,
        baseline_evidence=False,
        require_demonstrated_fix=False,
        strict_harness=False,
    )


def test_diff_owner_is_public_and_contracts_are_frozen_slotted() -> None:
    request = DiffVerificationRequest(
        head_dir="head",
        diff_text="diff",
        options=_options(),
    )
    result = type("Result", (), {"source": None, "base_reconstruction": None})()
    outcome = DiffVerificationOutcome(result=result, deleted=[])

    assert application.verify_diff is verify_diff
    assert application.DiffVerificationRequest is DiffVerificationRequest
    assert application.DiffVerificationOutcome is DiffVerificationOutcome
    assert not hasattr(request, "__dict__")
    assert not hasattr(outcome, "__dict__")
    with pytest.raises(FrozenInstanceError):
        request.head_dir = "changed"  # type: ignore[misc]


def test_diff_owner_has_no_runtime_effect_imports() -> None:
    root = Path(__file__).resolve().parents[1]
    tree = ast.parse(
        (
            root
            / "evoom_guard"
            / "application"
            / "diff_verification.py"
        ).read_text(encoding="utf-8")
    )
    imported_modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    forbidden_prefixes = (
        "evoom_guard",
        "os",
        "pathlib",
        "shutil",
        "subprocess",
        "tempfile",
    )

    assert not {
        module
        for module in imported_modules
        if module.startswith(forbidden_prefixes)
    }


def test_guard_from_diff_delegates_once_and_retains_no_sequence() -> None:
    root = Path(__file__).resolve().parents[1]
    tree = ast.parse(
        (root / "evoom_guard" / "guard.py").read_text(encoding="utf-8")
    )
    facade = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "guard_from_diff"
    )
    delegated_calls = [
        node
        for node in ast.walk(facade)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "verify_diff"
    ]
    forbidden_calls = {
        "mkdtemp",
        "copy_repo_tree",
        "_reverse_apply",
        "blocks_from_dirs",
        "guard",
        "rmtree",
    }

    assert len(delegated_calls) == 1
    assert not {
        node.func.id
        for node in ast.walk(facade)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in forbidden_calls
    }
