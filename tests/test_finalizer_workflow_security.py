from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_REVERIFY = ROOT / "examples" / "trusted-finalizer" / "reverify.yml"
EXAMPLES_SEAL = ROOT / "examples" / "trusted-finalizer" / "seal.yml"
WORKFLOW_REVERIFY = ROOT / ".github" / "workflows" / "evoguard-reverify.yml"
WORKFLOW_SEAL = ROOT / ".github" / "workflows" / "evoguard-seal.yml"

REFERENCE_PAIRS = (
    ("examples", EXAMPLES_REVERIFY, EXAMPLES_SEAL),
    ("repo-workflows", WORKFLOW_REVERIFY, WORKFLOW_SEAL),
)

FROZEN_EXAMPLE_RELEASE = "v3.7.0"
CURRENT_REFERENCE_RELEASE = "v4.2.0"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _assert_reverify_candidate_is_untrusted(reverify: str) -> None:
    assert "workflow_dispatch:" in reverify
    assert 'run-name: "EvoGuard Reverify PR #${{ inputs.pr_number }}"' in reverify
    assert "workflow_run:" not in reverify
    assert "pull_request_target" not in reverify
    assert "secrets." not in reverify
    assert "EVOGUARD_FINALIZER_KEY" not in reverify
    assert "--sign-key" not in reverify
    assert "derive-finalizer-bindings" in reverify
    assert "verify-finalizer-bindings" in reverify
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


def _assert_reverify_outputs_and_rigidity(reverify: str) -> None:
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
    assert reverify.index("Upload immutable control-plane binding") < reverify.index(
        "\n  reverify:"
    )
    assert "github.rest.checks.listForRef" not in reverify


def _assert_seal_holds_privileged_boundary(seal: str) -> None:
    assert "workflow_run:" in seal
    assert "pull_request_target" not in seal
    assert "actions/checkout" not in seal
    assert "environment: evoguard-finalizer" in seal
    assert "secrets.EVOGUARD_FINALIZER_KEY" in seal
    assert "--sign-key" in seal
    assert "--expected-source" in seal
    assert "--expected-context" in seal
    assert "--expected-derivation" in seal
    assert "trusted-finalizer-git-bindings" in seal
    assert "git init --bare" in seal
    assert "derive-finalizer-bindings" in seal
    assert "verify-finalizer-bindings" in seal
    assert "actions/checkout" not in seal
    seal_step = seal.index("- id: seal")
    assert seal.index("id: derive_and_compare") < seal_step
    assert seal.index("EVOGUARD_FINALIZER_KEY", seal_step) > seal_step
    assert 'attestation["candidate_sha256"]' not in seal
    assert 'attestation["policy_sha256"]' not in seal
    assert 'attestation["verifier_pack_sha256"]' not in seal
    assert "run-id: ${{ github.event.workflow_run.id }}" in seal
    assert "github.event.workflow_run.workflow_id" in seal
    assert "actions/setup-python" in seal
    assert "--require-hashes" in seal
    assert "--only-binary=:all:" in seal
    assert 'python-version: "3.12"' in seal
    reconcile = seal.split("\n  reconcile:\n", 1)[1].split("\n  seal:\n", 1)[0]
    assert "environment:" not in reconcile
    assert "secrets." not in reconcile
    assert "checks: write" in reconcile


def _assert_pins_and_outputs(seal: str) -> None:
    assert "name: evoguard-reverify-control-v1-${{ github.event.workflow_run.run_attempt }}" in seal
    assert (
        "name: evoguard-reverify-evidence-v1-${{ github.event.workflow_run.run_attempt }}"
        in seal
    )
    assert "CONTROL_DIR" in seal
    assert "steps.control.outputs.pull_request_number" in seal
    assert "handoff.source" not in seal
    assert "const rawSource" not in seal
    assert "  reconcile:" in seal
    assert "github.event.workflow_run.conclusion != 'success'" in seal


def _assert_guard_root_and_head_binding(reverify: str, seal: str) -> None:
    assert "EVOGUARD_GUARD_ARTIFACT_SHA256" in reverify
    assert "sha256sum --check" in reverify
    assert "EVOGUARD_GUARD_ARTIFACT_SHA256" in seal
    assert '[[ "$GUARD_ARTIFACT_SHA256" =~ ^[0-9a-f]{64}$ ]]' in reverify
    assert '[[ "$GUARD_ARTIFACT_SHA256" =~ ^[0-9a-f]{64}$ ]]' in seal
    assert "PR changed after re-verification" in seal
    assert "protected default branch as PR base" in reverify
    assert "protected default branch as PR base" in seal
    assert "EvoGuard Trusted Finalizer" in seal
    assert "format('{0}', github.event.workflow_run.workflow_id)" in seal
    assert "fromJSON(vars.EVOGUARD_REVERIFY_WORKFLOW_ID)" not in seal
    assert "CHECK_RUN_ID: ${{ steps.control.outputs.check_run_id }}" in seal
    assert "check_run_id: checkRunId" in seal
    assert "steps.derive.outputs.head_sha" in seal
    assert "github.rest.checks.update" in seal


def _assert_full_pair(reverify_path: Path, seal_path: Path) -> None:
    reverify = _text(reverify_path)
    seal = _text(seal_path)

    _assert_reverify_candidate_is_untrusted(reverify)
    _assert_reverify_outputs_and_rigidity(reverify)
    _assert_seal_holds_privileged_boundary(seal)
    _assert_pins_and_outputs(seal)
    _assert_guard_root_and_head_binding(reverify, seal)


def test_reference_finalizer_security_invariants() -> None:
    for _label, reverify, seal in REFERENCE_PAIRS:
        _assert_full_pair(reverify, seal)


def test_reference_finalizer_actions_are_pinned_and_actions_only() -> None:
    for label, reverify, seal in REFERENCE_PAIRS:
        reverify_text = _text(reverify)
        seal_text = _text(seal)
        combined = reverify_text + "\n" + seal_text
        actions = re.findall(r"uses:\s*(actions/[A-Za-z0-9_.-]+)@([^\s#]+)", combined)
        assert actions, f"{label}: no GitHub actions refs found"
        assert all(
            re.fullmatch(r"[0-9a-f]{40}", ref) for _name, ref in actions
        ), f"{label}: unpinned action reference detected"


def test_reference_finalizer_documents_the_immutable_executable_root() -> None:
    documentation = _text(ROOT / "docs" / "TRUSTED_FINALIZER.md")
    assert "Round 1 audit" in documentation
    assert CURRENT_REFERENCE_RELEASE in documentation
    assert "SHA256SUMS" in documentation
    assert "EVOGUARD_GUARD_ARTIFACT_SHA256" in documentation


def test_reference_finalizer_release_downloads_are_explicit_and_versioned() -> None:
    expected = {
        EXAMPLES_REVERIFY: FROZEN_EXAMPLE_RELEASE,
        EXAMPLES_SEAL: FROZEN_EXAMPLE_RELEASE,
        WORKFLOW_REVERIFY: CURRENT_REFERENCE_RELEASE,
        WORKFLOW_SEAL: CURRENT_REFERENCE_RELEASE,
    }
    pattern = re.compile(
        r"https://github\.com/EvoRiseKsa/EvoOM-Guard-m/releases/download/"
        r"(?P<tag>v\d+\.\d+\.\d+)/evo-guard\.pyz"
    )
    for path, expected_release in expected.items():
        releases = pattern.findall(_text(path))
        assert releases == [expected_release], (
            f"{path.relative_to(ROOT)} must download exactly "
            f"{expected_release}, found {releases}"
        )
