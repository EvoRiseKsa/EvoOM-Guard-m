<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# Authenticated producer receipt V1

This document describes the **non-admitting receipt prerequisite** consumed by
the current-source [Release Source Admission V2](RELEASE_SOURCE_ADMISSION_V2.md).
It does not change the
meaning of [Release Source Finalizer V1](RELEASE_SOURCE_FINALIZER.md): V1 is
still `DENY`-only, and this repository does not use the receipt to publish a
tag, release, package, Marketplace action, or deployment.

The problem is narrow but important.  A raw-Git-derived source/context can
prove that a submitted verdict describes the current protected-branch objects.
It cannot prove that an unprivileged job actually ran Guard; an attacker who
controls that job can fabricate plausible JSON.  The producer receipt makes
the later provider-authentication boundary explicit without pretending that a
local JSON file is authority. Even its provider attestation proves B produced
the receipt bytes; it is **not independent proof that A executed Guard**.

## What the receipt is

`EVOGUARD_RELEASE_SOURCE_PRODUCER_RECEIPT_V1` is canonical UTF-8 JSON with a
closed set of fields.  It contains:

| Field | Binding it carries |
| --- | --- |
| `source` / `context` | The exact protected `main` commit/tree, single parent/tree, repository ID, reverify run and attempt, candidate digest, policy digest, and verifier-pack digest. |
| `record` / `handoff` | SHA-256 plus byte size of the exact Guard verdict and canonical release-source handoff. |
| `bootstrap` | SHA-256 of the byte-pinned Guard zipapp selected for reverify. The digest alone proves neither release provenance nor that it actually ran. |
| `execution` | The strong profile required by V2 admission: completed black-box-only judgment, Docker or gVisor isolation, no network, and external-process report integrity. |
| `producer` | Numeric workflow IDs, distinct runs and attempts, repository IDs, protected ref, workflow path, immutable workflow blob, and the exact `main` commit used by the receipt workflow. |

The implementation validates all cross-field equalities, re-derives source and
context from a raw-Git object store, validates the semantic `PASS` record, and
resolves the A and B workflow blobs directly from the immutable protected-main
tree. It neither checks out nor imports either workflow. This verifies a
bounded claim; it does not establish the independent trustworthiness of the A
workflow semantics, its runner, or its actual Guard execution.

The receipt is deliberately **unsigned by EvoGuard**.  It has no signing-key
argument and does not return `ALLOW`.  The authoritative provider assertion is
a GitHub Artifact Attestation made after receipt creation.  A later consumer
must freshly verify that attestation for the exact receipt bytes; retaining a
previous verification result is not enough.

## Reference topology

The reviewable examples live in
[`examples/release-source-admission`](../examples/release-source-admission/).
They are reference files, not active workflows in this repository.

```text
A. unprivileged reverify on protected main
        |
        | source control + verdict + handoff data only
        v
B. workflow_run receipt producer
        |
        | canonical receipt + GitHub Artifact Attestation
        v
C. workflow_run preflight
        |
        | raw-Git rederivation + fresh provider verification
        v
no ALLOW / no key / no release
```

### A — candidate execution

The manual protected-`main` reverify captures a canonical source control file
**before** candidate execution.  It then runs a hash-pinned prior Guard
runtime.  It has no secret, OIDC token, attestation permission, signing key,
Environment, or write-capable token.  Candidate execution therefore cannot
mint the provider assertion used later.

### B — provider-attested producer

The receipt workflow starts only through `workflow_run` from A.  Before reading
the artifact it verifies the configured **numeric** A workflow ID, successful
`workflow_dispatch` event, repository identity, branch, run ID/attempt, and
unchanged `main` tip.  It has no checkout and does not execute candidate code.
It re-derives the raw-Git controls, constructs the canonical receipt, and then
requests GitHub Artifact Attestation solely for that receipt file.

The workflow path and name are not treated as authority.  The receipt contains
the B workflow's numeric ID and raw-Git blob identity, and the V2 consumer
must pin both the workflow IDs and exact current protected-main commit.

### C — fresh verifier, still non-admitting

The final reference workflow first validates B's numeric workflow ID and
successful `workflow_run`.  It binds downloaded source, context, and producer
input files to both configured workflow IDs, both exact runs/attempts, the
current repository ID, and the protected-main target SHA.  It then re-fetches
raw Git, repeats all local receipt checks, and invokes a fresh constrained
GitHub attestation verification.

C intentionally has no checkout, Environment, user secret, signing key,
`contents: write`, release action, or deployment action. It uses the clean
job's read-only `github.token` only for the fresh GitHub attestation query.
Success means only that a necessary prerequisite was verified; it does not make
a release safe to publish.

## What this rejects

The contract and reference topology reject, before any V2 key boundary:

- a receipt for a different repository, protected ref, commit/tree, policy,
  verifier pack, source run, or run attempt;
- a producer workflow with the same name but the wrong numeric workflow ID,
  path, raw-Git blob, event, commit, or runner class;
- a receipt producer that is the same workflow or same run as the
  candidate-executing reverify stage;
- moved `main`, a partial rerun, stale artifact, or receipt from another run;
- a verdict whose exact bytes, semantic `PASS`, black-box profile, isolation,
  network, report integrity, or verifier-pack snapshot do not match; and
- a retained/provider output that is not freshly verified for the exact
  canonical receipt bytes.

These controls do **not** prove that GitHub branch protection or same-owner
review is independent, that A really executed Guard, that the bootstrap runtime
actually ran, or that an artifact was built from the source. A GitHub
attestation also does not make arbitrary predicate data trustworthy by itself;
the consumer must bind its exact artifact and its trusted workflow identity.

## Current V2 boundary and remaining operational work

Do not attach this receipt alone to `release.yml`, branch protection, a
deployment, or a Marketplace publication. `v4.1.0` introduced—and published
`v4.2.0` retains—the distinct V2 envelope/key domain,
protected C runtime capability, raw-Git A/B/C workflow bindings, replay
handling, fresh isolated provider check, and detached verifier. Those
implementation facts do not make this older data-only reference topology an
admitting workflow.

Operational reliance still requires a published bootstrap runtime, a protected
key-bearing C workflow, live positive and negative rounds, and a separately
privileged release consumer that verifies the V2 `ALLOW` and independently
binds the actual built artifact to its source. The current source is not a
production gate and the bootstrap release cannot admit itself.

The first release containing these commands could not safely use itself as the
bootstrap runtime. It was published through the existing process; only a later
reviewed run could use separately established runtime provenance and an
administrator-audited URL/SHA control-plane pin.

## Commands

The receipt layer exposes four non-admitting commands:

```text
derive-release-source-controls
create-release-source-producer-receipt
verify-release-source-producer-receipt
reverify-attested-release-source-producer-receipt
```

They accept regular files, use canonical JSON, fail closed on mismatches, and
never accept a `--sign-key` or release-admission bypass. The two verification
commands deliberately exit nonzero after a successful non-admitting result
unless `--allow-nonadmitting-evidence` is supplied for an archive-only workflow.
That switch must never be used as a release, deployment, merge, or branch-gate
success condition. The supplied reference workflows show the required
control-plane inputs; they are not an activation guide for an active production
gate.

The separate `seal-release-source-admission` and
`verify-release-source-admission` commands implement V2 and are specified in
[RELEASE_SOURCE_ADMISSION_V2.md](RELEASE_SOURCE_ADMISSION_V2.md); they do not
change the four receipt commands into authorities.
