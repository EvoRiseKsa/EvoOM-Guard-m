<!--
  Copyright (c) 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available - see LICENSE for permitted use.
-->

# v4.5.0 external-review matrix

Run source tests only from commit
`6bb4c328e56661b661e50532886802c6ba36a997`. The paths below exist in that
tree, but they are developer-authored regression entry points, not independent
evidence. Record exact commands, selected cases, skips, environment, and raw
evidence hashes.

| Property | Frozen-source entry points | Required adversarial boundary |
| --- | --- | --- |
| Release identity and unsigned-commit truth | `tests/test_release_security.py`, `tests/test_zipapp.py`, `tests/test_docs_version.py`, `tests/test_verify_spdx_attestation.py` | Verify the immutable Release, exact three-asset set, checksums, SPDX bytes, tag/tree, release attestation, and `verified=false/reason=unsigned`. Never relabel the release attestation as a commit signature. |
| Base-owned authority and protected harness | `tests/test_action_security.py`, `tests/test_policy_consistency.py`, `tests/test_strict_harness.py`, `tests/test_safe_deletions.py` | Candidate policy, pack, workflow, test, config, deletion, symlink, and missing-base substitutions must not become clean acceptance. |
| Verdict, record, evidence, and signature integrity | `tests/test_record_verifier.py`, `tests/test_evidence_bundle.py`, `tests/test_evidence_containment.py`, `tests/test_signing.py`, `tests/test_junit_hardening.py` | Mutated canonical bytes, duplicate JSON keys, schema contradictions, cross-context replay, malformed archives/reports, embedded trust roots, and signature/key substitutions must fail closed. Exercise both supported record schemas where applicable. |
| Assurance, lifecycle, cleanup, and isolation truth | `tests/test_candidate_invocation_evidence.py`, `tests/test_runtime_identity.py`, `tests/test_execution_process.py`, `tests/test_execution_process_reader_start.py`, `tests/test_docker_isolation.py`, `tests/conformance/test_isolation_conformance.py` | Requested/prepared isolation must not become delivered evidence; partial start, timeout, output overflow, reader failure, and cleanup failure must remain truthful. Subprocess is not a sandbox; Docker/gVisor are not hostile-host or VM proofs. |
| Verifier-pack identity and actual candidate execution | `tests/test_pack_validation.py`, `tests/test_blackbox.py`, `tests/test_blackbox_composite_contract.py`, `tests/test_blackbox_invocation_recorder.py` | Missing, mutated, non-invoking, post-snapshot-changed, or report-forging packs must not pass; required phase composition and real launcher receipts must remain visible. |
| Trusted Finalizer | `tests/test_trusted_finalizer.py`, `tests/test_finalizer_workflow_security.py`, `tests/test_finalizer_derivation.py`, `tests/test_finalizer_git_lifecycle.py`, `tests/test_finalizer_git_executable_pin.py` | Stale PR/run/attempt, moved base/head/tree, raw-Git object substitution, partial rerun, candidate policy/pack/deletion substitution, Git executable drift, key-before-derivation, and cleanup failure must reject. |
| Release Source Admission V2 | `tests/test_release_source_admission.py`, `tests/test_release_source_admission_workflow_security.py`, `tests/test_release_source_producer_receipt.py`, `tests/test_release_source_finalizer.py` | Wrong A/B/C workflow identity/blob/run/attempt, altered receipts/provider output, moved main, UID/GID/root/tool substitution, key-domain reuse, and provider-readable key paths must reject. Source admission is not artifact or publication authorization. |
| GitHub Artifact Attestation adapter | `tests/test_github_attestation.py`, `tests/test_github_attestation_provider_isolation.py`, `tests/test_github_attestation_lifecycle.py` | Wrong repository, signer, source, subject digest, run URI, issuer, predicate, runner class, cardinality, oversized/partial output, retained-byte change, and provider lifecycle failure must reject. |
| Release Artifact Admission V1 and digest binding | `tests/test_release_artifact_admission.py`, `tests/test_artifact_admission.py`, `tests/test_artifact_digest_admission.py`, `tests/test_raae_release_pipeline_workflows.py` | Artifact/SBOM/checksum digest, source RSAE, finalizer context, provenance bytes/identity, signature, workflow, and external key substitution must reject. ALLOW does not prove safety, reproducibility, publication intent, or deployment. |
| Agent Change Admission and named operating profiles | `tests/test_agent_change_admission.py`, `tests/test_record_profile_contract.py`, `tests/test_assurance_policy.py`, `tests/test_effective_policy.py` | Proposal/authorization/Git binding replay, signer-domain confusion, policy-profile downgrade, absent assurance floors, and mismatched repository/base/head context must fail closed. Advisory risk signals must not silently become trust authority. |
| Action, ledger, and publication controls | `tests/test_release_ledger.py`, `tests/test_release_ledger_v2.py`, `tests/test_release_ledger_v2_assembler.py`, `tests/test_release_security.py` | Verify least privilege, immutable action pins, canonical signed-ledger bytes, external-root and disjoint-parent requirements, exact A-H bindings, release asset consistency, and failure on mutable/conflicting targets. Treat repository-control fields as bounded observations, not timeless state. |
| Later-evidence claim reconciliation | Later-main ledger, `evidence/runtime-observations/v4.5.0-gvisor-31298956172`, exact Git history, and issue #141 | Confirm the ledger and gVisor record are absent from the `v4.5.0` tree, later, same-owner, and non-independent. Do not upgrade gVisor to field/hostile-host/VM evidence or Firecracker from design-only. |

## Required environment accounting

At minimum record:

- OS, architecture, Python, Git, GitHub CLI, and clock source;
- dependency lock files and installed package hashes;
- Docker daemon, container image reference and resolved ID;
- gVisor/runsc version and digest if actually exercised;
- network, credentials, resource limits, and cleanup observations;
- exact test selection, deselection, skips, xfails, failures, and retries; and
- hashes of safe retained inputs and outputs.

An environment-gated skip is `not-tested`, not `tested-no-finding`.
