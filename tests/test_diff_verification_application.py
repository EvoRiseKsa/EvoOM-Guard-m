"""Architecture contracts for the extracted diff-verification coordinator."""

from __future__ import annotations

import ast
from collections.abc import Callable
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest

import evoom_guard.application as application
from evoom_guard.application.diff_verification import (
    DiffVerificationOptions,
    DiffVerificationOutcome,
    DiffVerificationRequest,
    DiffVerificationServices,
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


def _unreachable_provider() -> Any:
    raise AssertionError("unexpected provider lookup")


def _cleanup_boundary_services(
    *,
    cleanup_workspace_provider: Callable[[], Any],
    workspace_factory_provider: Callable[[], Any],
    path_join_provider: Callable[[], Any] = _unreachable_provider,
) -> DiffVerificationServices[Any]:
    """Build the minimal live-provider surface needed by boundary tests."""

    return DiffVerificationServices(
        diff_error_provider=_unreachable_provider,
        input_error_provider=_unreachable_provider,
        empty_diff_reason_code_provider=_unreachable_provider,
        binary_patch_reason_code_provider=_unreachable_provider,
        unsafe_path_reason_code_provider=_unreachable_provider,
        verifier_pack_invalid_reason_code_provider=_unreachable_provider,
        reverse_apply_failed_reason_code_provider=_unreachable_provider,
        no_verifiable_changes_reason_code_provider=_unreachable_provider,
        binary_diff_provider=lambda: lambda _diff_text: False,
        diff_target_paths_provider=lambda: lambda _diff_text: [],
        safe_relpath_provider=lambda: lambda _path: True,
        verifier_pack_trust_check_provider=(
            lambda: lambda _head_dir, _pack, _pin: None
        ),
        workspace_factory_provider=workspace_factory_provider,
        path_join_provider=path_join_provider,
        copy_repo_tree_provider=_unreachable_provider,
        diff_writer_provider=_unreachable_provider,
        reverse_apply_provider=_unreachable_provider,
        blocks_from_dirs_provider=_unreachable_provider,
        unverifiable_errors_provider=_unreachable_provider,
        guard_provider=_unreachable_provider,
        diff_base_sha_provider=_unreachable_provider,
        diff_head_sha_provider=_unreachable_provider,
        cleanup_workspace_provider=cleanup_workspace_provider,
    )


def _cleanup_boundary_request() -> DiffVerificationRequest:
    return DiffVerificationRequest(
        head_dir="HEAD",
        diff_text="synthetic non-empty text diff",
        options=_options(),
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


def test_cleanup_provider_lookup_failure_precedes_workspace_factory() -> None:
    events: list[str] = []
    lookup_failure = SystemExit("cleanup provider lookup failed")

    def cleanup_provider() -> Any:
        events.append("cleanup:resolve")
        raise lookup_failure

    def workspace_provider() -> Any:
        events.append("workspace:resolve")

        def create_workspace(*, prefix: str) -> str:
            events.append(f"workspace:create:{prefix}")
            return "owned-workspace"

        return create_workspace

    services = _cleanup_boundary_services(
        cleanup_workspace_provider=cleanup_provider,
        workspace_factory_provider=workspace_provider,
    )

    with pytest.raises(SystemExit) as caught:
        verify_diff(_cleanup_boundary_request(), services)

    assert caught.value is lookup_failure
    assert events == ["cleanup:resolve"]


def test_cleanup_provider_is_bound_before_allocation_and_later_primary() -> None:
    events: list[str] = []
    primary = KeyboardInterrupt("path construction interrupted")

    def early_cleanup(
        path: str,
        *,
        primary: BaseException | None,
    ) -> None:
        events.append(f"cleanup:early:{path}:{type(primary).__name__}")

    def late_cleanup(
        _path: str,
        *,
        primary: BaseException | None,
    ) -> None:
        del primary
        events.append("cleanup:late")

    cleanup_operation = {"current": early_cleanup}

    def cleanup_provider() -> Any:
        events.append("cleanup:resolve")
        return cleanup_operation["current"]

    def workspace_provider() -> Any:
        events.append("workspace:resolve")

        def create_workspace(*, prefix: str) -> str:
            events.append(f"workspace:create:{prefix}")
            cleanup_operation["current"] = late_cleanup
            return "owned-workspace"

        return create_workspace

    def path_provider() -> Any:
        events.append("path:resolve")

        def join_path(_parent: str, _child: str) -> str:
            events.append("path:join")
            raise primary

        return join_path

    services = _cleanup_boundary_services(
        cleanup_workspace_provider=cleanup_provider,
        workspace_factory_provider=workspace_provider,
        path_join_provider=path_provider,
    )

    with pytest.raises(KeyboardInterrupt) as caught:
        verify_diff(_cleanup_boundary_request(), services)

    assert caught.value is primary
    assert events == [
        "cleanup:resolve",
        "workspace:resolve",
        "workspace:create:evo_guard_diff_",
        "path:resolve",
        "path:join",
        "cleanup:early:owned-workspace:KeyboardInterrupt",
    ]
