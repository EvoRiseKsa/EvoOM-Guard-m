<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# Raw-Git Trusted Finalizer derivation

This document specifies the raw-Git derivation boundary implemented in v3.7.0.
The frozen v3.6.1 release remains useful historical evidence,
but it does **not** gain this guarantee retroactively.

## Objective

The initial finalizer independently derived the pull request, run, attempt,
base/head commit, and tree bindings. Candidate, effective-policy, and
verifier-pack digests still arrived from an untrusted verdict. The raw-Git
boundary makes the sealing job derive those values from immutable Git objects
and compare them to the semantic verdict before it opens the signing key.

## Invariants

- The sealing job must never check out or execute candidate code.
- Downloaded handoffs, verdicts, and workflow artifacts remain untrusted data.
- Base policy and verifier-pack bytes must come from immutable base-commit blobs,
  not branch names or the candidate checkout.
- Every raw-Git query must select its repository with an explicit `-C` or
  `--git-dir`, remove ambient `GIT_*` process state, and pass
  `--no-replace-objects`. The trusted boundary still includes the selected
  repository's administrative metadata and object store, the resolved Git
  executable, and non-`GIT_*` runner configuration; this control does not make
  a hostile local object store trustworthy.
- The deletion list must also be reconstructed from the two clean Git trees.
  The candidate text digest intentionally excludes deletions, while the Guard
  decision and its attestation do not.
- The candidate representation, effective-policy derivation, and pack identity
  must have one documented canonical algorithm shared by Guard and the sealer.
- The sealer must compare independently derived values to the record and handoff
  before loading the private key. A raw-binding mismatch yields an unsigned
  attempt-bound failure: the key is not read and no apparently authoritative
  denial is fabricated. A semantic Guard denial that passed raw binding checks
  may still be signed as DENY evidence.

## Required derived bindings

1. A canonical base-to-head candidate representation and SHA-256, including the
   exact text-file semantics Guard judged, plus the independently derived
   ordered deletion list that the candidate digest deliberately excludes.
2. The effective-policy object and SHA-256, derived from the immutable base
   `.evoguard.json` plus documented trusted defaults.
3. The `EVOGUARD_PACK_V2` verifier-pack digest from its immutable, base-anchored
   path.
4. The existing PR, workflow-run, attempt, commit/tree, and reviewed Guard asset
   bindings.

The implementation exposes a small tested library/CLI contract:
`derive-finalizer-bindings` reads raw Git objects and writes canonical
`EVOGUARD_FINALIZER_GIT_BINDINGS_V1`; `verify-finalizer-bindings` accepts a
semantic record only after all raw values match and writes the existing trusted
source/context files. Reproducing this algorithm ad hoc in YAML or JavaScript is
not acceptable.

## Acceptance tests and current coverage

- Stale base/head/tree, cross-PR, cross-run, and cross-attempt swaps fail before
  the signing key is read.
- A base policy or pack blob change changes the independently derived digest and
  prevents sealing of old evidence.
- A forged record or handoff with a substituted candidate, deletion list, policy,
  or pack digest cannot obtain `ALLOW`.
- A binary, mode-only, symlink/special, or EOL-transformed candidate difference
  cannot be silently converted into a matching raw-Git identity.
- Ambient repository/object-directory variables cannot redirect a worktree or
  bare-object query, and worktree/bare replacement refs cannot substitute the
  literal tree read by the derivation.
- A partial rerun, failed run, and cancelled run preserve the attempt-bound
  `DENY` semantics.
- The privileged job has no checkout or candidate execution path, including on
  every failure branch.

## Follow-on boundary

Artifact-bound verification remains a separate layer. It binds a finalizer
admission to observed artifact bytes, but does not establish build provenance
or publication by itself; those relations require a trusted builder/provenance
adapter.
