from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "examples" / "release-source-admission"
REVERIFY = REFERENCE / "reverify.yml"
RECEIPT = REFERENCE / "produce-receipt.yml"
PREFLIGHT = REFERENCE / "admission-preflight.yml"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_reference_topology_separates_candidate_execution_from_attestation() -> None:
    reverify = _text(REVERIFY)
    receipt = _text(RECEIPT)
    preflight = _text(PREFLIGHT)

    assert "workflow_dispatch:" in reverify
    assert "workflow_run:" not in reverify
    assert "pull_request_target" not in reverify
    assert "secrets." not in reverify
    assert "id-token: write" not in reverify
    assert "attestations: write" not in reverify
    assert "contents: write" not in reverify
    assert "release-source-handoff" in reverify
    assert "derive-release-source-controls" in reverify
    assert "  reverify:\n    needs: metadata" in reverify
    candidate = reverify.split("\n  reverify:\n", 1)[1]
    assert "    permissions:\n      contents: read" in candidate
    assert "environment:" not in candidate
    assert "sign-key" not in candidate

    assert "workflow_run:" in receipt
    assert 'workflows: ["EvoGuard Release Source Reverify"]' in receipt
    assert "String(run.workflow_id)" in receipt
    assert "EVOGUARD_RELEASE_SOURCE_REVERIFY_WORKFLOW_ID" in receipt
    assert "actions/checkout" not in receipt
    assert "secrets." not in receipt
    assert "environment:" not in receipt
    assert "contents: write" not in receipt
    assert "attestations: write" in receipt
    assert "id-token: write" in receipt
    assert "create-release-source-producer-receipt" in receipt
    assert "actions/attest" in receipt
    assert receipt.index("create-release-source-producer-receipt") < receipt.index("actions/attest")
    assert "refs/heads/main:refs/heads/main" in receipt
    assert "EVOGUARD_RELEASE_SOURCE_RECEIPT_WORKFLOW_ID" in receipt
    assert "EVOGUARD_RELEASE_SOURCE_REVERIFY_WORKFLOW_BLOB_SHA" in receipt
    assert "EVOGUARD_RELEASE_SOURCE_RECEIPT_WORKFLOW_BLOB_SHA" in receipt
    assert "Snapshot only regular bounded reverify inputs before reading them" in receipt
    assert "O_NOFOLLOW" in receipt
    assert "# v4.2.0" in receipt

    assert "workflow_run:" in preflight
    assert 'workflows: ["EvoGuard Produce Release Source Receipt"]' in preflight
    assert "EVOGUARD_RELEASE_SOURCE_RECEIPT_WORKFLOW_ID" in preflight
    assert "EVOGUARD_RELEASE_SOURCE_REVERIFY_WORKFLOW_ID" in preflight
    assert "reverify-attested-release-source-producer-receipt" in preflight
    assert "Bind the downloaded inputs to both protected workflow runs" in preflight
    assert "producer.get('workflow_run_id')" in preflight
    assert "producer.get('trigger_workflow_id')" in preflight
    assert "attestations: read" in preflight
    assert "GH_TOKEN: ${{ github.token }}" in preflight
    assert "Snapshot only regular bounded producer inputs before reading them" in preflight
    assert "O_NOFOLLOW" in preflight
    assert "Preserve fresh non-admitting verification data" in preflight
    assert "actions/checkout" not in preflight
    assert "secrets." not in preflight
    assert "environment:" not in preflight
    assert "sign-key" not in preflight
    assert "contents: write" not in preflight
    assert "No release-source ALLOW" in preflight


def test_reference_topology_pins_every_github_action_and_documents_non_goals() -> None:
    combined = "\n".join(_text(path) for path in (REVERIFY, RECEIPT, PREFLIGHT))
    actions = re.findall(r"uses:\s*(actions/[A-Za-z0-9_.-]+)@([^\s#]+)", combined)
    assert actions
    assert all(re.fullmatch(r"[0-9a-f]{40}", revision) for _name, revision in actions)

    readme = _text(REFERENCE / "README.md")
    assert "not an active release gate" in readme
    assert "DENY-only" in readme
    assert "fresh" in readme
    assert "No release tag" in readme
    assert "settings, not Git objects" in readme
    assert "administrator-controlled trust" in readme
    assert "chains are limited by GitHub" in readme
    assert "exactly one parent" in readme
