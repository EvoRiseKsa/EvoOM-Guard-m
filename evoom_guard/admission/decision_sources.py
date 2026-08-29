# -----------------------------------------------------------------------------
# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
# -----------------------------------------------------------------------------
# DORMANT — NOT ON ANY SHIPPING PATH.
# This module is not reached by the evo-guard CLI dispatch or by any release
# workflow; it is retained only under tests (and trust-assurance mutation
# coverage). Do NOT treat it as an active trust boundary. It is a
# maintenance/admission lane kept for reference and scheduled for removal or an
# explicit experimental namespace in a post-v4.7.0 refactor. See the review plan.
"""Proof-family adapters for admission-decision projections.

Every adapter snapshots the original proof, invokes its existing authoritative
verifier with external trust roots, and only then projects a decision envelope.
An ``InspectedAdmissionDecisionEnvelope`` proves only closed canonical structure;
an action point must reverify the original proof rather than consume that value
as an authority capability.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from evoom_guard.admission.agent_change import (
    AGENT_CHANGE_PROPOSAL_FORMAT_V2,
    AgentChangeAdmissionError,
    VerifiedAgentChangeAdmission,
    verify_agent_change_finalized_bundle,
)
from evoom_guard.admission.decision_envelope import (
    ADMISSION_DECISION_PROOF_FORMAT,
    MAX_PROOF_BYTES,
    AdmissionDecisionEnvelopeError,
    InspectedAdmissionDecisionEnvelope,
    build_agent_change_admission_decision_envelope,
    canonical_admission_decision_envelope_bytes,
    inspect_admission_decision_envelope_bytes,
)
from evoom_guard.evidence_bundle import EvidenceBundleError, read_regular_file_bytes
from evoom_guard.finalizer_derivation import DerivedAgentChangeBindings


def _verify_agent_change_snapshot(
    snapshot: bytes,
    *,
    trusted_finalizer_public_key_path: str,
    authorization_public_key_path: str,
    expected_authorization_source: Mapping[str, Any],
    expected_finalizer_source: Mapping[str, Any],
    expected_context: Mapping[str, Any],
    expected_bindings: DerivedAgentChangeBindings,
) -> VerifiedAgentChangeAdmission:
    """Verify a private temporary inode containing the already captured bytes."""

    with tempfile.TemporaryDirectory(prefix=".evoguard-admission-proof-") as directory:
        proof_path = Path(directory) / "agent-change.evb"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        descriptor = os.open(proof_path, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(snapshot)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        return verify_agent_change_finalized_bundle(
            str(proof_path),
            trusted_finalizer_public_key_path=trusted_finalizer_public_key_path,
            authorization_public_key_path=authorization_public_key_path,
            expected_authorization_source=expected_authorization_source,
            expected_finalizer_source=expected_finalizer_source,
            expected_context=expected_context,
            expected_bindings=expected_bindings,
            required_proposal_format=(
                AGENT_CHANGE_PROPOSAL_FORMAT_V2
                if "candidate_identity" in expected_bindings.payload
                else "EVOGUARD_AGENT_CHANGE_PROPOSAL_V1"
            ),
        )


def _project_agent_change(
    verified: VerifiedAgentChangeAdmission,
    *,
    proof_sha256: str,
    proof_size: int,
) -> dict[str, Any]:
    authorization = verified.contract.authorization.payload
    authorization_source = authorization["source"]
    bindings = verified.contract.bindings.payload
    finalizer_authentication = verified.finalized.bundle.manifest["authentication"]
    authorization_authentication = authorization["authentication"]

    if "candidate_identity" in bindings:
        candidate_subject: dict[str, Any] = {
            "git_object_format": bindings["git_object_format"],
            "candidate_selection_profile": bindings["candidate_selection_profile"],
            "candidate_identity": bindings["candidate_identity"],
        }
    else:
        candidate_subject = {
            "candidate_sha256": bindings["candidate_sha256"],
            "candidate_size": bindings["candidate_size"],
        }

    return build_agent_change_admission_decision_envelope(
        subject={
            "kind": "git-change",
            "repository": authorization_source["repository"],
            "repository_id": authorization_source["repository_id"],
            "pull_request_number": authorization_source["pull_request_number"],
            "base_sha": bindings["base_sha"],
            "base_tree_sha": bindings["base_tree_sha"],
            "head_sha": bindings["head_sha"],
            "head_tree_sha": bindings["head_tree_sha"],
            **candidate_subject,
        },
        controls={
            "policy_sha256": bindings["policy_sha256"],
            "verifier_pack_sha256": bindings["verifier_pack_sha256"],
        },
        proof={
            "format": ADMISSION_DECISION_PROOF_FORMAT,
            "sha256": proof_sha256,
            "size": proof_size,
            "authentication": {
                "finalizer": {
                    "algorithm": finalizer_authentication["algorithm"],
                    "key_id": finalizer_authentication["key_id"],
                    "purpose": finalizer_authentication["purpose"],
                },
                "change_authorization": {
                    "algorithm": authorization_authentication["algorithm"],
                    "key_id": authorization_authentication["key_id"],
                    "purpose": authorization_authentication["purpose"],
                },
            },
        },
    )


def derive_agent_change_admission_decision(
    proof_path: str,
    *,
    trusted_finalizer_public_key_path: str,
    authorization_public_key_path: str,
    expected_authorization_source: Mapping[str, Any],
    expected_finalizer_source: Mapping[str, Any],
    expected_context: Mapping[str, Any],
    expected_bindings: DerivedAgentChangeBindings,
) -> InspectedAdmissionDecisionEnvelope:
    """Reverify a proof and return a non-authoritative inspected projection."""

    try:
        snapshot = read_regular_file_bytes(
            proof_path,
            limit=MAX_PROOF_BYTES,
            label="Agent Change admission proof",
        )
        verified = _verify_agent_change_snapshot(
            snapshot,
            trusted_finalizer_public_key_path=trusted_finalizer_public_key_path,
            authorization_public_key_path=authorization_public_key_path,
            expected_authorization_source=expected_authorization_source,
            expected_finalizer_source=expected_finalizer_source,
            expected_context=expected_context,
            expected_bindings=expected_bindings,
        )
        proof_sha256 = hashlib.sha256(snapshot).hexdigest()
        payload = _project_agent_change(
            verified,
            proof_sha256=proof_sha256,
            proof_size=len(snapshot),
        )
        inspection = inspect_admission_decision_envelope_bytes(
            canonical_admission_decision_envelope_bytes(payload)
        )
    except (AgentChangeAdmissionError, EvidenceBundleError) as exc:
        raise AdmissionDecisionEnvelopeError(f"Agent Change proof did not verify: {exc}") from exc
    return inspection


def verify_agent_change_admission_decision(
    envelope_bytes: bytes,
    proof_path: str,
    *,
    trusted_finalizer_public_key_path: str,
    authorization_public_key_path: str,
    expected_authorization_source: Mapping[str, Any],
    expected_finalizer_source: Mapping[str, Any],
    expected_context: Mapping[str, Any],
    expected_bindings: DerivedAgentChangeBindings,
) -> InspectedAdmissionDecisionEnvelope:
    """Require literal reprojection equality after full proof verification."""

    supplied = inspect_admission_decision_envelope_bytes(envelope_bytes)
    expected = derive_agent_change_admission_decision(
        proof_path,
        trusted_finalizer_public_key_path=trusted_finalizer_public_key_path,
        authorization_public_key_path=authorization_public_key_path,
        expected_authorization_source=expected_authorization_source,
        expected_finalizer_source=expected_finalizer_source,
        expected_context=expected_context,
        expected_bindings=expected_bindings,
    )
    if not hmac.compare_digest(supplied.envelope_bytes, expected.envelope_bytes):
        raise AdmissionDecisionEnvelopeError(
            "admission decision envelope is not the exact projection of its verified proof"
        )
    return expected
