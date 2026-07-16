<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# Trusted Finalizer hardening target

This document specifies the next finalizer boundary. It is **not** implemented
by v3.6.0 and must not be cited as a current guarantee.

## Objective

The v3.6.0 sealing workflow independently re-derives the pull request, run,
attempt, base/head commit, and tree bindings. Its candidate, effective-policy,
and verifier-pack digests still arrive from the untrusted verdict and are checked
for consistency. The next boundary makes the sealing job derive those values from
trusted Git/API data before it opens the signing key.

## Invariants

- The sealing job must never check out or execute candidate code.
- Downloaded handoffs, verdicts, and workflow artifacts remain untrusted data.
- Base policy and verifier-pack bytes must come from immutable base-commit blobs,
  not branch names or the candidate checkout.
- The candidate representation, effective-policy derivation, and pack identity
  must have one documented canonical algorithm shared by Guard and the sealer.
- The sealer must compare independently derived values to the record and handoff
  before loading the private key. A mismatch is `DENY`, never a best-effort
  downgrade.

## Required derived bindings

1. A canonical base-to-head candidate representation and SHA-256, including the
   exact text-file and deletion semantics that Guard judged.
2. The effective-policy object and SHA-256, derived from the immutable base
   `.evoguard.json` plus documented trusted defaults.
3. The `EVOGUARD_PACK_V2` verifier-pack digest from its immutable, base-anchored
   path.
4. The existing PR, workflow-run, attempt, commit/tree, and reviewed Guard asset
   bindings.

The implementation needs a small, tested library/CLI contract for canonical
derivation. Reproducing the algorithm ad hoc in YAML or JavaScript would create a
second unreviewed parser and is not acceptable.

## Acceptance tests

- Stale base/head/tree, cross-PR, cross-run, and cross-attempt swaps fail before
  the signing key is read.
- A base policy or pack blob change changes the independently derived digest and
  prevents sealing of old evidence.
- A forged record or handoff with a substituted candidate, policy, or pack digest
  cannot obtain `ALLOW`.
- A partial rerun, failed run, and cancelled run preserve the attempt-bound
  `DENY` semantics.
- The privileged job has no checkout or candidate execution path, including on
  every failure branch.

## Follow-on boundary

Artifact-bound verification is separate: it binds the signed admission decision
to the SHA-256 of a container image, package, binary, or release bundle produced
after the accepted change. It must be designed with build provenance rather than
treated as a field added to an existing record.
