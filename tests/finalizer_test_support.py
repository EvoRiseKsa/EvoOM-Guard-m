from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from evoom_guard.finalizer_derivation import (
    FINALIZER_DERIVATION_FORMAT,
    DerivedFinalizerBindings,
    validate_finalizer_bindings,
)


def finalizer_bindings_for(
    record: Mapping[str, Any],
    context: Mapping[str, Any],
    source: Mapping[str, Any],
) -> DerivedFinalizerBindings:
    """Build one closed-world synthetic binding for trusted-boundary tests."""

    attestation = record["attestation"]
    assert isinstance(attestation, dict)
    return validate_finalizer_bindings(
        {
            "format": FINALIZER_DERIVATION_FORMAT,
            "source": source,
            "repository": context["repository"],
            "repository_id": context["repository_id"],
            "guard_artifact_sha256": context["guard_artifact_sha256"],
            "base_tree_sha": context["base_tree_sha"],
            "head_tree_sha": context["head_tree_sha"],
            "candidate_sha256": attestation["candidate_sha256"],
            "deleted_paths": attestation["deleted_paths"],
            "policy_sha256": attestation["policy_sha256"],
            "verifier_pack_sha256": attestation["verifier_pack_sha256"],
            "verifier_pack_manifest": attestation["verifier_pack_manifest"],
            "effective_policy": attestation["effective_policy"],
        }
    )
