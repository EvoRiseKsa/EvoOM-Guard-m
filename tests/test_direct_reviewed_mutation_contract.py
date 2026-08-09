# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
"""Focused contracts for direct reviewed mutants in weak trust modules.

Each test binds one narrow security invariant used by the deterministic mutation
gate.  Passing these contracts does not imply a whole-module mutation score.
"""

from __future__ import annotations

import pytest

from evoom_guard import (
    artifact_admission,
    artifact_digest_admission,
    release_source_finalizer,
    release_source_producer_receipt,
    runtime_identity,
    workspace,
)
from evoom_guard.admission import agent_change, release_artifact, release_source
from evoom_guard.finalizer import deployment
from evoom_guard.verifiers import fidelity


def test_workspace_rejects_parent_components() -> None:
    assert workspace._is_safe_relative_path("safe/../escape") is False


def test_runtime_identity_binds_the_fallback_tree_digest() -> None:
    record = runtime_identity.RuntimeEntry(
        path="candidate.py",
        kind="file",
        permissions=0o644,
        size=1,
        payload="a",
    )
    before = runtime_identity.RuntimeIdentity(
        sha256="a" * 64,
        entries=1,
        regular_bytes=1,
        elapsed_ms=0.0,
        records=(record,),
    )
    after = runtime_identity.RuntimeIdentity(
        sha256="b" * 64,
        entries=1,
        regular_bytes=1,
        elapsed_ms=0.0,
        records=(record,),
    )

    assert runtime_identity.runtime_identity_changes(before, after) == ["<runtime-tree-digest>"]


def test_fidelity_keeps_preexisting_default_outputs_bound() -> None:
    path = "node_modules/pkg/index.js"
    baseline = {path: ("file", 0o644, "a" * 64)}

    assert (
        fidelity._scan_entry_is_ignored(
            path,
            is_directory=False,
            extra_output_globs=(),
            baseline=baseline,
            baseline_keys=frozenset(baseline),
        )
        is False
    )


def test_release_artifact_builder_and_admitter_runs_are_distinct() -> None:
    builder = {
        "workflow_id": "builder-id",
        "workflow_path": ".github/workflows/build.yml",
        "workflow_run_id": "shared-run",
    }
    admitter = {
        "workflow_id": "admitter-id",
        "workflow_path": ".github/workflows/admit.yml",
        "workflow_run_id": "shared-run",
    }
    release_source_manifest = {
        "producer": {
            "workflow_id": "producer-id",
            "workflow_path": ".github/workflows/produce.yml",
            "workflow_run_id": "producer-run",
            "trigger_workflow_id": "trigger-id",
            "trigger_workflow_path": ".github/workflows/trigger.yml",
            "trigger_workflow_run_id": "trigger-run",
        },
        "admitter": {
            "workflow_id": "source-admitter-id",
            "workflow_path": ".github/workflows/source-admit.yml",
            "workflow_run_id": "source-admitter-run",
        },
    }

    with pytest.raises(
        release_artifact.ReleaseArtifactAdmissionError,
        match="workflow_run_id must differ from the builder",
    ):
        release_artifact._validate_role_separation(
            builder,
            admitter,
            release_source_manifest,
        )


def test_agent_change_cannot_authorize_judge_owned_tests() -> None:
    assert agent_change._is_forbidden_control_path("tests/test_app.py") is True


def test_finalizer_deployment_rejects_parent_paths() -> None:
    with pytest.raises(
        deployment.FinalizerDeploymentError,
        match="must stay inside the repository",
    ):
        deployment._safe_relative_path("../escape", label="workflow")


def test_artifact_v1_rejects_nonfile_subjects() -> None:
    with pytest.raises(
        artifact_admission.ArtifactAdmissionError,
        match="subject.kind",
    ):
        artifact_admission._validate_subject({"kind": "oci", "sha256": "a" * 64, "size": 1})


def test_release_source_receipt_rejects_host_isolation() -> None:
    with pytest.raises(
        release_source_producer_receipt.ReleaseSourceProducerReceiptError,
        match="candidate_isolation",
    ):
        release_source_producer_receipt._validate_execution(
            {
                "outcome": "PASS",
                "guard_exit_code": 0,
                "candidate_isolation": "host",
                "network": "none",
                "report_integrity": "external_process_isolated",
                "overall_profile": "black_box_external_judge",
            }
        )


def test_artifact_v2_rejects_unsupported_digest_algorithms() -> None:
    with pytest.raises(
        artifact_digest_admission.ArtifactDigestAdmissionError,
        match="exact lowercase sha256",
    ):
        artifact_digest_admission.artifact_digest_subject(
            "artifact-sha256",
            "sha512:" + "a" * 128,
        )


def test_release_source_admission_requires_distinct_domain_keys() -> None:
    domains = sorted(release_source.RELEASE_SOURCE_ADMISSION_DISTINCT_KEY_DOMAINS)
    separation = {
        domain: "sha256:" + f"{index:064x}" for index, domain in enumerate(domains, start=1)
    }
    separation[domains[1]] = separation[domains[0]]

    with pytest.raises(
        release_source.ReleaseSourceAdmissionError,
        match="mutually distinct keys",
    ):
        release_source._validate_key_separation(separation)


def test_release_source_v1_remains_deny_only() -> None:
    assert release_source_finalizer.release_source_decision({"verdict": "PASS"}) == "DENY"
