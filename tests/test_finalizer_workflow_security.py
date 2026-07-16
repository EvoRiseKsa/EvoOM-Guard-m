from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REVERIFY = ROOT / "examples" / "trusted-finalizer" / "reverify.yml"
SEAL = ROOT / "examples" / "trusted-finalizer" / "seal.yml"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_reference_finalizer_separates_candidate_execution_from_key() -> None:
    reverify = _text(REVERIFY)
    seal = _text(SEAL)

    assert "workflow_dispatch:" in reverify
    assert 'run-name: "EvoGuard Reverify PR #${{ inputs.pr_number }}"' in reverify
    assert "workflow_run:" not in reverify
    assert "pull_request_target" not in reverify
    assert "secrets." not in reverify
    assert "EVOGUARD_FINALIZER_KEY" not in reverify
    assert "--sign-key" not in reverify
    assert "contents: read" in reverify
    assert "contents: write" not in reverify
    assert "pull-requests: write" not in reverify
    assert "checks: write" in reverify
    candidate_job = reverify.split("\n  reverify:\n", 1)[1]
    assert "    permissions:\n      contents: read" in candidate_job
    assert "checks: write" not in candidate_job.split("\n    steps:", 1)[0]
    assert "actions/setup-python" in candidate_job
    assert 'python-version: "3.12"' in candidate_job
    assert "Install hash-locked judge test dependencies" in candidate_job
    assert "pytest==9.0.3" in candidate_job
    assert "--require-hashes" in candidate_job
    assert "--only-binary=:all:" in candidate_job

    assert "workflow_run:" in seal
    assert "pull_request_target" not in seal
    assert "actions/checkout" not in seal
    assert "environment: evoguard-finalizer" in seal
    assert "secrets.EVOGUARD_FINALIZER_KEY" in seal
    assert "--sign-key" in seal
    assert "--expected-source" in seal
    assert "--expected-context" in seal
    assert "run-id: ${{ github.event.workflow_run.id }}" in seal
    assert "github.event.workflow_run.workflow_id" in seal
    assert "actions/setup-python" in seal
    assert "--require-hashes" in seal
    assert "--only-binary=:all:" in seal
    assert "python-version: \"3.12\"" in seal
    reconcile = seal.split("\n  reconcile:\n", 1)[1].split("\n  seal:\n", 1)[0]
    assert "environment:" not in reconcile
    assert "secrets." not in reconcile
    assert "checks: write" in reconcile


def test_reference_finalizer_pins_every_action_and_uploads_only_data_from_reverify() -> None:
    combined = _text(REVERIFY) + "\n" + _text(SEAL)
    actions = re.findall(r"uses:\s*(actions/[A-Za-z0-9_.-]+)@([^\s#]+)", combined)
    assert actions
    assert all(re.fullmatch(r"[0-9a-f]{40}", ref) for _name, ref in actions)

    reverify = _text(REVERIFY)
    seal = _text(SEAL)
    assert "name: evoguard-reverify-evidence-v1-${{ github.run_attempt }}" in reverify
    assert "${{ runner.temp }}/verdict.json" in reverify
    assert "${{ runner.temp }}/handoff.json" in reverify
    assert "finalizer-handoff" in reverify
    assert "seal-finalizer" not in reverify
    assert "name: evoguard-reverify-control-v1-${{ github.run_attempt }}" in reverify
    assert "finalizer-control.json" in reverify
    assert "overwrite: false" in reverify
    assert "Create an attempt-bound pending finalizer check" in reverify
    assert "github.rest.checks.create" in reverify
    assert "check_run_id" in reverify
    assert "workflow must be dispatched from the default branch" in reverify
    assert "Refuse a partial workflow re-run" in reverify
    assert "Re-run all jobs or dispatch a new workflow" in reverify
    assert "  reverify:\n    needs: metadata" in reverify
    assert reverify.index("Upload immutable control-plane binding") < reverify.index("\n  reverify:")
    assert "name: evoguard-reverify-control-v1-${{ github.event.workflow_run.run_attempt }}" in seal
    assert "name: evoguard-reverify-evidence-v1-${{ github.event.workflow_run.run_attempt }}" in seal
    assert "CONTROL_DIR" in seal
    assert "steps.control.outputs.pull_request_number" in seal
    assert "handoff.source" not in seal
    assert "const rawSource" not in seal
    assert "  reconcile:" in seal
    assert "github.event.workflow_run.conclusion != 'success'" in seal
    assert "github.rest.checks.listForRef" not in reverify
    assert "github.rest.checks.listForRef" not in seal


def test_reference_finalizer_documents_the_immutable_executable_root_and_current_head_check() -> None:
    reverify = _text(REVERIFY)
    seal = _text(SEAL)
    assert "EVOGUARD_GUARD_ARTIFACT_SHA256" in reverify
    assert "sha256sum --check" in reverify
    assert "EVOGUARD_GUARD_ARTIFACT_SHA256" in seal
    assert "[[ \"$GUARD_ARTIFACT_SHA256\" =~ ^[0-9a-f]{64}$ ]]" in reverify
    assert "[[ \"$GUARD_ARTIFACT_SHA256\" =~ ^[0-9a-f]{64}$ ]]" in seal
    assert "PR changed after re-verification" in seal
    assert "protected default branch as PR base" in reverify
    assert "protected default branch as PR base" in seal
    assert "EvoGuard Trusted Finalizer" in seal
    assert "format('{0}', github.event.workflow_run.workflow_id)" in seal
    assert "fromJSON(vars.EVOGUARD_REVERIFY_WORKFLOW_ID)" not in seal
    assert "CHECK_RUN_ID: ${{ steps.control.outputs.check_run_id }}" in seal
    assert "check_run_id: checkRunId" in seal
    assert "steps.derive.outputs.head_sha" not in seal
    assert "github.rest.checks.update" in seal
    assert "Round 1 audit" in _text(ROOT / "docs" / "TRUSTED_FINALIZER.md")
