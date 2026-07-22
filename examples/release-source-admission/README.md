# Authenticated producer receipt — reference topology

This directory is deliberately **not an active release gate**.  It is a
reviewable historical precursor for the non-admitting receipt stage now
consumed by the separate current-source
[Release Source Admission V2](../../docs/RELEASE_SOURCE_ADMISSION_V2.md).

The current `release_source_finalizer` V1 remains `DENY-only`.  These files do
not change that fact, do not open a release or admission key, and must not be
copied into `.github/workflows/` until all external control-plane values below
have been set and audited by an administrator.

```text
A. EvoGuard Release Source Reverify (workflow_dispatch on main)
   - creates source/control data before it runs the candidate
   - runs a hash-pinned prior Guard runtime without secrets, OIDC, or attestation rights
   - uploads verdict + source/context/handoff as data only

B. EvoGuard Produce Release Source Receipt (workflow_run from A)
   - checks the numerical workflow ID and exact triggering run
   - does not check out or execute the candidate
   - repeats raw-Git derivation, makes a canonical receipt, and uses GitHub Artifact Attestation

C. EvoGuard Release Source Admission Preflight (workflow_run from B)
   - repeats raw-Git and fresh provider verification
   - reports only a verified prerequisite; it has no environment, key, release, or publish step
```

The canonical receipt is still merely data until C performs a **fresh** GitHub
Artifact Attestation verification for its exact bytes.  Even that is not an
`ALLOW`: these example workflows do not invoke the implemented V2 sealer, hold
its key, or authorize a release. A separate protected V2 workflow and release
consumer are required before any publication can use the receipt.

## Required administrative trust anchors

Repository/organization Actions variables are settings, not Git objects.
They are not versioned or protected by a branch ruleset merely because the
workflow file is. Treat every value below as an administrator-controlled trust
anchor: record who changed it, restrict who can change Actions settings, and
audit it out of band. Never take a value from workflow inputs, an artifact, or
a candidate checkout. The V2 verifier likewise requires immutable pins and
trust inputs from outside its signed bundle; a separately governed control
repository remains the stronger operational source for them.

| Variable | Purpose |
| --- | --- |
| `EVOGUARD_BOOTSTRAP_RUNTIME_URL` | HTTPS URL of the byte-pinned bootstrap `evo-guard.pyz` used by A/B/C. |
| `EVOGUARD_BOOTSTRAP_RUNTIME_SHA256` | SHA-256 of that exact bootstrap byte stream. It does not by itself prove release provenance or execution. |
| `EVOGUARD_RELEASE_SOURCE_REVERIFY_WORKFLOW_ID` | Numeric ID of workflow A after it exists on the default branch. |
| `EVOGUARD_RELEASE_SOURCE_RECEIPT_WORKFLOW_ID` | Numeric ID of workflow B after it exists on the default branch. |
| `EVOGUARD_RELEASE_SOURCE_REVERIFY_WORKFLOW_BLOB_SHA` | Raw-Git blob SHA of A's exact reviewed workflow definition. |
| `EVOGUARD_RELEASE_SOURCE_RECEIPT_WORKFLOW_BLOB_SHA` | Raw-Git blob SHA of B's exact reviewed workflow definition. |

Before enabling B or C, obtain the workflow IDs and blob SHAs through GitHub's
API/raw Git, then make and record an administrator-reviewed settings change. A
name such as `EvoGuard Release Source Reverify` is not an authority by itself.

## Explicit non-goals

- No release tag, GitHub release, package, container, or binary is admitted.
- No secret, deployment Environment, signing key, or `contents: write` token
  appears in A/B/C.
- B has `attestations: write` and `id-token: write` only so GitHub can sign the
  exact receipt file.  A never has either permission.
- C does not trust a retained provider receipt: it invokes a new constrained
  `gh attestation verify` through the EvoGuard adapter using only the clean
  job's read-only `github.token` and `attestations: read` permission.
- A same owner reviewing from a second GitHub account is governance separation,
  not an independent security review.
- The receipt and its GitHub attestation prove that B processed/bound its input
  bytes. They do not independently prove that A really executed Guard or that
  the bootstrap runtime ran. A's workflow definition and runner boundary remain
  explicit trust roots. Current V2 binds A/B/C raw workflow blobs and the C
  runtime/event context, but it still does not independently prove GitHub's
  control plane or A's execution honesty.
- `workflow_run` chains are limited by GitHub. Do not append a V2 finalizer and
  release consumer as further chained `workflow_run` stages; replace C or use a
  separately designed trigger boundary.

## Evidence classification and history constraint

The artifacts contain verdicts, contexts, policy digests, and external-verifier
output. In a public repository, treat those artifacts as potentially visible to
repository readers and suitable for disclosure; move sensitive diagnostic or
customer evidence to a private audit repository.

The reference V1 derivation intentionally requires a protected-main commit with
exactly one parent. Configure squash/rebase-compatible history for the active
round, or expect the topology to fail closed on merge commits.

## Historical precursor exercise sequence

1. Release a runtime containing this code through the existing process,
   independently establish the URL/SHA's provenance and immutability, then make
   an audited administrator settings change for its pins.
2. Copy only A, merge it, dispatch it once, and verify the emitted evidence is
   a strong `PASS` with no candidate-visible credential.
3. Set A's numerical workflow-ID and reviewed raw-Git blob-SHA anchors. Copy
   B, merge it, run A again, then inspect B's GitHub Artifact Attestation.
4. Set B's numerical workflow-ID and reviewed raw-Git blob-SHA anchors. Copy
   C, run a complete A-to-B-to-C chain and preserve the data-only evidence.
5. Exercise negative cases (moved main, wrong run attempt, altered artifact,
   same-name workflow, failed run) before wiring this precursor into the
   separate V2 `ALLOW` workflow.
