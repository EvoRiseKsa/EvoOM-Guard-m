# Maintenance release protocol V2 (inert library contracts)

This document describes additive, unreleased library contracts. It is not a
claim that a maintenance branch, protected workflow, tag, release, provider
verification, signature, publication gate, or production deployment exists.
The published V1/V2 contracts remain unchanged.

## Why a new protocol is required

The protected default branch owns workflow, policy, verifier-pack, and control
tool bytes. A maintenance branch owns a frozen historical base. A release
candidate owns the exact source being evaluated. Treating one Git commit as all
three roles makes provenance ambiguous and permits a candidate-selected
workflow or policy to appear trusted.

The new contracts preserve three separate object identities:

| Role | Required identity |
|---|---|
| Trusted workflow | commit, tree, workflow path, and workflow blob from literal `refs/heads/main` |
| Maintenance base | branch ref, commit, and tree |
| Target source | release-candidate ref, commit, and tree |

Every handoff also carries the upstream `run_id` and `run_attempt`. Policy,
verifier-pack, and control-tool materials are bound to the trusted workflow
commit/tree, never to the target source.

## Additive formats and domains

| Contract | Format | Signature/attestation role |
|---|---|---|
| Raw source | `EVOGUARD_RELEASE_SOURCE_V2` | none |
| Raw-Git bindings | `EVOGUARD_RELEASE_SOURCE_GIT_BINDINGS_V2` | none |
| Finalizer context | `EVOGUARD_RELEASE_SOURCE_CONTEXT_V2` | none |
| Finalizer handoff | `EVOGUARD_RELEASE_SOURCE_FINALIZER_HANDOFF_V2` | none |
| Finalizer evidence | `EVOGUARD_RELEASE_SOURCE_EVIDENCE_V2` | distinct deny-only Ed25519 domain `release-source-finalizer-v2` |
| Producer receipt | `EVOGUARD_RELEASE_SOURCE_PRODUCER_RECEIPT_V2` | exact GitHub-attestation subject; not admission |
| Source admission | `EVOGUARD_RELEASE_SOURCE_ADMISSION_V3` | distinct Ed25519 domain `release-source-admission-v3` |
| Artifact admission | `EVOGUARD_RELEASE_ARTIFACT_ADMISSION_V2` | distinct Ed25519 domain `release-artifact-admission-v2` |

For producer-receipt attestation, GitHub policy `source_digest` and
`signer_digest` are the trusted workflow commit. The maintenance target remains
inside the receipt `subject`. This prevents the target commit from being
misrepresented as the source of trusted workflow bytes.

## What is implemented

- strict closed-world validators with exact key sets and canonical lowercase
  Git/SHA-256 identities;
- canonical JSON byte generation and unique signature messages;
- byte-descriptor binding from source admission to the exact producer receipt,
  and from artifact admission to exact canonical
  `materials/release-source-admission-v3.json` bytes. The latter must decode to
  the same validated mapping supplied by the caller; a detached signature is a
  separate capability and is not inferred from the JSON filename;
- pairwise-distinct run IDs across evaluation, producer, source admitter,
  builder, and artifact admitter, including cross-lane comparison at the
  source-to-artifact binding boundary;
- distinct trusted workflow paths, blob identities, and workflow IDs for each
  visible control-plane role;
- exact JSON scalar types for counters, limits, booleans, sizes, attempts, and
  isolation IDs, with runtime/schema boundary tests;
- collision-free trusted material paths, non-overlapping verifier-pack roots,
  and mandatory membership of the trusted finalizer workflow path/blob in the
  trusted-main control-material inventory;
- packaged JSON Schema 2020-12 documents;
- golden byte digests plus negative tests for role swaps, path/blob/tree
  mismatches, candidate-selected trusted inputs, wrong run attempts,
  cross-version/domain replay, and legacy V1 byte preservation.

## What remains deliberately absent

- raw-Git derivation of these values from a locally pinned Git executable;
- GitHub API/control-plane verification and protected branch setup;
- provider execution or fresh attestation retrieval;
- archive sealing/verification CLI commands or key access;
- changes to release workflows A–H;
- branch, tag, release, Environment, or repository-setting mutation.

Those capabilities require separate review. Until then, these objects are
inert protocol primitives and cannot establish release or production authority.
