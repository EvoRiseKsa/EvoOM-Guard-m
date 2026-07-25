# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Focused contracts for repository-verification workspace bookkeeping."""

from __future__ import annotations

import pytest

from evoom_guard.workspace.repository_lifetime import RepositoryWorkspaceLifetime


def test_candidate_and_pack_allocation_preserve_provider_order() -> None:
    timeline: list[str] = []

    def create_workspace(*, prefix: str) -> str:
        timeline.append(f"create:{prefix}")
        return f"/judge/{prefix.rstrip('_')}"

    def join_path(root: str, child: str) -> str:
        timeline.append(f"join:{root}:{child}")
        return f"{root}/{child}"

    lifetime = RepositoryWorkspaceLifetime.create(
        prefix="evo_repo_",
        create_workspace=create_workspace,
        join_path=join_path,
    )

    assert timeline == [
        "create:evo_repo_",
        "join:/judge/evo_repo:repo",
    ]
    assert lifetime.candidate_root == "/judge/evo_repo"
    assert lifetime.candidate_copy == "/judge/evo_repo/repo"
    assert lifetime.cleanup_targets() == (
        ("candidate workspace", "/judge/evo_repo"),
        ("verifier-pack snapshot", None),
    )

    pack_root = lifetime.create_pack(
        "evo_pack_snapshot_",
        create_workspace=create_workspace,
    )

    assert pack_root == "/judge/evo_pack_snapshot"
    assert timeline[-1] == "create:evo_pack_snapshot_"
    assert lifetime.cleanup_targets() == (
        ("candidate workspace", "/judge/evo_repo"),
        ("verifier-pack snapshot", "/judge/evo_pack_snapshot"),
    )


def test_pack_root_is_not_recorded_when_allocation_raises() -> None:
    lifetime = RepositoryWorkspaceLifetime(
        candidate_root="candidate",
        candidate_copy="candidate/repo",
    )
    failure = OSError("pack allocation failed")

    def fail_workspace(*, prefix: str) -> str:
        assert prefix == "evo_pack_snapshot_"
        raise failure

    with pytest.raises(OSError) as caught:
        lifetime.create_pack(
            "evo_pack_snapshot_",
            create_workspace=fail_workspace,
        )

    assert caught.value is failure
    assert lifetime.pack_root is None


def test_observed_pack_root_retains_historical_fallback_semantics() -> None:
    lifetime = RepositoryWorkspaceLifetime(
        candidate_root="candidate",
        candidate_copy="candidate/repo",
        pack_root="callback-pack",
    )

    lifetime.retain_pack_root(None)
    assert lifetime.pack_root == "callback-pack"

    lifetime.retain_pack_root("")
    assert lifetime.pack_root == "callback-pack"

    lifetime.retain_pack_root("intake-pack")
    assert lifetime.pack_root == "intake-pack"
