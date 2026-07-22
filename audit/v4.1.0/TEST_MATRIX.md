<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# v4.1.0 external-review matrix

Run source tests only from the exact `v4.1.0` commit after verifying the
published asset. The listed tests are developer-authored entry points, not
independent evidence. Record dependency resolution, OS, architecture, Python,
Git, GitHub CLI, container runtime, image digests, and exact commands.

| Property | Focused entry points | Required adversarial boundary |
| --- | --- | --- |
| Base-owned authority and protected harness | `tests/test_action_security.py`, `tests/test_policy_consistency.py`, `tests/test_strict_harness.py`, `tests/test_safe_deletions.py` | Candidate policy, pack, workflow, test, deletion, symlink, and missing-base substitutions must not become clean acceptance. |
| Verdict, record, and evidence integrity | `tests/test_record_verifier.py`, `tests/test_evidence_bundle.py`, `tests/test_evidence_containment.py`, `tests/test_signing.py`, `tests/test_junit_hardening.py` | Mutated canonical bytes, duplicate JSON keys, schema contradictions, cross-context replay, malformed archives/reports, and embedded trust roots must fail closed. |
| Assurance and runtime truthfulness | `tests/test_candidate_invocation_evidence.py`, `tests/test_runtime_identity.py`, `tests/test_docker_isolation.py`, `tests/test_execution_process.py`, `tests/test_execution_process_reader_start.py` | Requested isolation must not become delivered evidence; started/incomplete/cleanup states must remain truthful; process-group cleanup is not a sandbox claim. |
| Pack identity and candidate execution | `tests/test_pack_validation.py`, `tests/test_blackbox.py`, `tests/test_blackbox_composite_contract.py` | Missing, mutated, non-invoking, or post-snapshot-changed packs must not pass; weaker repo-suite composition must remain visible. |
| Trusted Finalizer raw-Git derivation | `tests/test_trusted_finalizer.py`, `tests/test_finalizer_workflow_security.py`, `tests/test_finalizer_derivation.py` | Stale PR/run/attempt, changed base/head/tree, candidate/policy/pack/deletion substitution, partial rerun, or key-before-derivation paths must reject. |
| Release Source Admission V2 | `tests/test_release_source_admission.py`, `tests/test_release_source_admission_workflow_security.py`, `tests/test_release_source_producer_receipt.py`, `tests/test_release_source_finalizer.py` | Wrong A/B/C workflow ID/blob/run/attempt, moved main, altered receipt/provider result, tool/UID/GID/root substitution, key-domain reuse, or provider-readable key path must reject. |
| GitHub attestation provider adapter | `tests/test_github_attestation.py`, `tests/test_github_attestation_provider_isolation.py`, `tests/test_github_attestation_lifecycle.py` | Wrong repository, signer, source, run URI, issuer, predicate, runner class, cardinality, oversized/partial output, retained-byte change, or provider lifecycle failure must reject. |
| Artifact Admission V1/V2 | `tests/test_artifact_admission.py`, `tests/test_artifact_digest_admission.py` | Artifact digest/type, finalizer context, provenance bytes/identity, signature, or external key substitution must reject. Do not infer release or deployment authorization. |
| Action and release supply chain | `tests/test_release_security.py`, `tests/test_zipapp.py`, `tests/test_docs_version.py`, `tests/test_release_ledger.py` | Verify permissions, action pins, immutable tag/source/assets, checksums, release/build attestations, exact asset set, and failure on mutable/conflicting targets. |
| V2 Round 1 claim reconciliation | Pilot `docs/ROUND1_EVIDENCE.md`, exact Actions runs, branch/environment API snapshots, downloaded artifact hashes | Reproduce only the documented positive and negative claims. Distinguish the successful A attempt 1 from failed attempt 2; do not upgrade unexecuted matrix entries or same-owner approval to independent evidence. |

## Explicitly separate later contracts

A valid source `.rsae` does not bind an artifact. Existing artifact V1/V2
commands consume a PR Trusted Finalizer `.evb`, not Release Source Admission
V2. Treat any claimed `.rsae` → release-artifact relation as absent unless a
separately versioned adapter, verifier, protected workflow, and evidence are
implemented and reviewed.
