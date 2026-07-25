# Copyright © 2026 EvoRise Tech. All rights reserved.
# Author / original creator: Mana Alharbi.
# Licensor: EvoRise Tech.
# Source-available — see LICENSE for permitted use.
"""Tests for the no-secret F SPDX attestation semantic adapter."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from tools.ci import verify_spdx_attestation as verifier

REPOSITORY = "EvoRiseKsa/EvoOM-Guard-m"
REPOSITORY_ID = "1293651176"
OWNER_ID = "231647061"
SOURCE = "a" * 40
WORKFLOW = ".github/workflows/evoguard-build-release-artifact.yml"
RUN_ID = 12345
RUN_ATTEMPT = 2


def _fixture() -> tuple[bytes, bytes, bytes]:
    artifact = b"synthetic pyz\n"
    spdx_value = {"SPDXID": "SPDXRef-DOCUMENT", "spdxVersion": "SPDX-2.3"}
    spdx = verifier._canonical(spdx_value)
    signer = f"https://github.com/{REPOSITORY}/{WORKFLOW}@{SOURCE}"
    run = f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}/attempts/2"
    value: list[dict[str, Any]] = [
        {
            "attestation": {"opaque": "provider-verified"},
            "verificationResult": {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "signature": {
                    "certificate": {
                        "certificateIssuer": (
                            "CN=sigstore-intermediate,O=sigstore.dev"
                        ),
                        "subjectAlternativeName": signer,
                        "issuer": verifier.OIDC_ISSUER,
                        "githubWorkflowTrigger": "workflow_dispatch",
                        "githubWorkflowRepository": REPOSITORY,
                        "githubWorkflowSHA": SOURCE,
                        "githubWorkflowRef": "refs/heads/main",
                        "buildSignerURI": signer,
                        "buildSignerDigest": SOURCE,
                        "runnerEnvironment": "github-hosted",
                        "sourceRepositoryURI": f"https://github.com/{REPOSITORY}",
                        "sourceRepositoryDigest": SOURCE,
                        "sourceRepositoryRef": "refs/heads/main",
                        "sourceRepositoryIdentifier": REPOSITORY_ID,
                        "sourceRepositoryOwnerURI": "https://github.com/EvoRiseKsa",
                        "sourceRepositoryOwnerIdentifier": OWNER_ID,
                        "sourceRepositoryVisibilityAtSigning": "public",
                        "buildConfigURI": signer,
                        "buildConfigDigest": SOURCE,
                        "buildTrigger": "workflow_dispatch",
                        "runInvocationURI": run,
                    }
                },
                "verifiedIdentity": {
                    "subjectAlternativeName": {
                        "subjectAlternativeName": "",
                        "regexp": f"^{signer}$",
                    },
                    "issuer": {"issuer": "", "regexp": ".*"},
                    "runnerEnvironment": "github-hosted",
                },
                "statement": {
                    "_type": "https://in-toto.io/Statement/v1",
                    "subject": [
                        {
                            "name": "evo-guard.pyz",
                            "digest": {
                                "sha256": hashlib.sha256(artifact).hexdigest()
                            },
                        }
                    ],
                    "predicateType": verifier.PREDICATE_TYPE,
                    "predicate": spdx_value,
                },
            },
        }
    ]
    raw = (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    return raw, artifact, spdx


def _verify(raw: bytes, artifact: bytes, spdx: bytes) -> dict[str, Any]:
    return verifier.verify(
        raw,
        artifact,
        spdx,
        artifact_name="evo-guard.pyz",
        spdx_name="evo-guard.spdx.json",
        repository=REPOSITORY,
        repository_id=REPOSITORY_ID,
        repository_owner_id=OWNER_ID,
        workflow_path=WORKFLOW,
        source_digest=SOURCE,
        run_id=RUN_ID,
        run_attempt=RUN_ATTEMPT,
        event="workflow_dispatch",
    )


def test_exact_spdx_relation_produces_closed_receipt() -> None:
    raw, artifact, spdx = _fixture()
    receipt = _verify(raw, artifact, spdx)
    assert receipt["format"] == verifier.FORMAT
    assert receipt["artifact"]["sha256"] == hashlib.sha256(artifact).hexdigest()
    assert receipt["predicate"]["sha256"] == hashlib.sha256(spdx).hexdigest()
    assert receipt["workflow_run"] == {
        "id": RUN_ID,
        "attempt": RUN_ATTEMPT,
        "event": "workflow_dispatch",
    }


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda value: value[0]["verificationResult"]["signature"][
                "certificate"
            ].update({"sourceRepositoryIdentifier": "1"}),
            "certificate does not bind",
        ),
        (
            lambda value: value[0]["verificationResult"]["statement"].update(
                {"predicate": {"SPDXID": "SPDXRef-OTHER"}}
            ),
            "predicate does not equal",
        ),
        (
            lambda value: value[0]["verificationResult"]["verifiedIdentity"][
                "subjectAlternativeName"
            ].update({"regexp": "^https://github.com/attacker/.*$"}),
            "verified identity",
        ),
    ],
)
def test_spdx_adapter_rejects_substitution(
    mutate: Any,
    message: str,
) -> None:
    raw, artifact, spdx = _fixture()
    value = json.loads(raw)
    mutate(value)
    mutated = (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    with pytest.raises(verifier.VerificationError, match=message):
        _verify(mutated, artifact, spdx)
