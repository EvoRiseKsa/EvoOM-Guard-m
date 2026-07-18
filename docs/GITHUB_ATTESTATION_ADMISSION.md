<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# GitHub Artifact Attestation admission — protected-boundary adapter

This unreleased adapter is the narrow GitHub-specific follow-on to the generic
V2 artifact-digest binding. It is not part of the immutable v3.7.0 release and
does not close the wider artifact-provenance issue by itself.

## What it actually verifies

`evoom_guard.github_attestation.create_github_attestation_receipt()` makes a
private snapshot of one regular artifact file and invokes the configured
`gh attestation verify` executable against that snapshot with all of the
following fixed or externally supplied constraints:

1. an exact `owner/repository` scope;
2. an exact signer workflow path bound to that same repository. The API also
   accepts a canonical `github.com/...` or `https://github.com/...` alias but
   normalizes it before invoking `gh` and records only the canonical path;
3. an exact lowercase signer Git object digest;
4. an exact safe `refs/heads/...` or `refs/tags/...` source reference;
5. an exact source Git digest;
6. exactly `https://token.actions.githubusercontent.com` as the certificate
   OIDC issuer;
7. the SLSA v1 predicate type;
8. `--deny-self-hosted-runners`; and
9. an attestation lookup limit of one, so the result cardinality is exact.

The adapter independently caps live `gh` output while it is being read (4 MiB
stdout and 64 KiB stderr) and terminates the child on overflow. `--limit 1`
does not itself bound provider response bytes.

The GitHub CLI performs the signature/certificate/identity verification. The
adapter then writes two no-clobber regular files:

- a canonical `EVOGUARD_GITHUB_ATTESTATION_RECEIPT_V1` receipt; and
- the exact JSON output returned by that successful GitHub CLI verification.

The receipt records the snapshot SHA-256 and size, the exact verification
policy, and the SHA-256/size of the retained CLI output. It is deliberately not
a new signature format and is not a substitute for GitHub or Sigstore.

V1 is deliberately **same-repository only**: the normalized signer workflow
must name the exact repository passed through `--repo`. A reusable or
cross-repository builder needs a separately reviewed provider adapter and
policy contract; it must not be admitted by weakening this check to an owner,
repository wildcard, or caller-selected signer repository.

`seal_github_attestation_admission()` is the admission bridge. It will only
open the separate V2 admission-key path after the GitHub CLI verification
succeeds and after the exact GitHub `source_digest` equals the externally
expected Trusted Finalizer `context.head_sha`. It seals the exact snapshot
SHA-256 as V2 `artifact-sha256` and binds the canonical receipt as the V2
provenance-reference bytes. The retained raw verifier output is described by a
digest inside that signed receipt. The V2 provenance identity also includes a
SHA-256 commitment to the complete normalized provider policy, so its label
cannot silently describe a different signer/source/issuer policy.

## What it does **not** prove

Do not widen the claim beyond what executes:

- EvoGuard does not implement or independently reproduce GitHub/Sigstore/DSSE
  cryptographic verification; it trusts the protected `gh` execution for that
  operation.
- A later `verify_github_attestation_receipt()` checks only retained artifact,
  receipt, output bytes, and external policy. It does **not** contact GitHub,
  re-check a signature, test revocation, or establish current registry state.
  `reverify_github_attestation_receipt()` is the explicit fresh operation: it
  freezes the supplied artifact again and invokes the same constrained `gh`
  verification policy. Historic raw output is retained for audit and exact
  byte continuity, but fresh successful output need not be byte-identical to
  historic output.
- The adapter does not treat `statement.predicate`, materials, builder fields,
  invocation, annotations, or arbitrary attestation metadata as trusted
  EvoGuard facts. GitHub CLI itself warns that predicate data can be influenced
  by the originating workflow.
- It does not prove a release was published, an OCI digest exists, an image has
  the claimed media type, a deployment occurred, or the finalizer became a
  required merge gate.
- It does not turn a same-owner review into independent review. It also does
  not protect a key if candidate code can run in the same job after key access.

## Required protected workflow shape

Run the adapter only in a base-owned job that does not check out or execute
candidate-controlled code after secrets/keys become reachable. Use a pinned
GitHub CLI source and a scoped token with only the permissions required to read
attestations. Obtain the artifact from immutable build output or a
content-addressed store, not from a pull-request workspace. Then:

1. derive the expected source digest from the trusted finalizer context;
2. obtain the exact protected signer workflow, signer Git digest, and source
   ref from reviewed policy rather than from a pull request or dispatcher;
3. run the GitHub verifier adapter with the exact repository, signer identity,
   source ref, source digest, and GitHub Actions OIDC issuer; and
4. immediately call `seal_github_attestation_admission()` with a distinct
   artifact-admission key and the separately verified finalizer bundle.

Retain **both** receipt files and the final `.eab` in an immutable evidence
store. A binding without the raw verifier output cannot be independently
re-examined for the exact external verification event, even though its receipt
digest remains signed.

The adapter deliberately creates an empty per-run `GH_CONFIG_DIR` and therefore
does **not** use an operator's local `gh auth login`, keyring, or persisted
configuration. The protected job must explicitly pass `GH_TOKEN` or
`GITHUB_TOKEN` with scoped read access to GitHub attestations. Treat that token,
the GitHub CLI executable, and the GitHub-hosted/provider service as explicit
trust dependencies. It scrubs every inherited `GH_*` control except
`GH_TOKEN`; `GITHUB_TOKEN` is also preserved. Provide a reviewed/pinned
absolute CLI path or a trusted base-owned `PATH`—the adapter does not attest
the executable it launches. In particular, the default bare `gh` is suitable
only on a fresh/clean protected runner that has not executed candidate code.
If candidate code has run on that machine/job, use a separate clean protected
job or a reviewed absolute executable path established outside the candidate's
control.

## Python integration sketch

```python
from evoom_guard.github_attestation import seal_github_attestation_admission

sealed = seal_github_attestation_admission(
    artifact_path="dist/product.whl",
    receipt_path="evidence/github-attestation.receipt.json",
    raw_output_path="evidence/github-attestation.raw.json",
    finalizer_bundle_path="evidence/final.evb",
    output_path="evidence/product.eab",
    repository="owner/project",
    signer_workflow="owner/project/.github/workflows/release.yml",
    signer_digest=trusted_policy["signer_digest"],
    source_ref=trusted_policy["source_ref"],
    source_digest=trusted_context["head_sha"],
    cert_oidc_issuer="https://token.actions.githubusercontent.com",
    trusted_finalizer_public_key_path="keys/finalizer.pub",
    expected_finalizer_source=trusted_source,
    expected_finalizer_context=trusted_context,
    private_key_path="keys/artifact-admission.pem",
)
```

The function rejects a source digest that differs from
`expected_finalizer_context["head_sha"]`, a signer workflow belonging to
another repository, uppercase or malformed signer/source digests, unsafe or
ambiguous source references, every OIDC issuer other than GitHub Actions, a
path swap while the artifact is being copied to the private verifier snapshot,
non-regular inputs, verifier failure, empty or multiple result JSON, changed
retained output, receipt substitution, and all the V2
finalizer/admission-key/subject checks.

## CLI boundary commands

The unreleased CLI exposes the same policy without free-form weakening. All
policy pins, both external finalizer objects, both public keys, retained receipt
paths, and the separate admission key are explicit command inputs; no command
accepts a wildcard repository, mutable ref, optional OIDC issuer, or a
"trust receipt" switch.

```bash
evo-guard github-attestation-receipt dist/product.whl \
  --receipt-out evidence/github-attestation.receipt.json \
  --raw-output-out evidence/github-attestation.raw.json \
  --repo owner/project \
  --signer-workflow owner/project/.github/workflows/release.yml \
  --signer-digest "$SIGNER_GIT_DIGEST" \
  --source-ref refs/heads/main \
  --source-digest "$TRUSTED_FINALIZER_HEAD_SHA" \
  --cert-oidc-issuer https://token.actions.githubusercontent.com
```

`verify-github-attestation-receipt` performs the retained-byte continuity
check; `reverify-github-attestation-receipt` makes a fresh constrained GitHub
CLI verification. Neither command makes the result an admission decision: the
separate V2 admission bridge still requires a matching externally verified
Trusted Finalizer `ALLOW`.

The CLI bridge is available only through the two commands below. The sealing
command performs the live provider verification **before** it reads the
separate admission signing key. It additionally rejects the request unless
`--source-digest` equals the externally supplied finalizer context's exact
`head_sha`.

```bash
evo-guard seal-github-attestation-admission artifacts/product.json evidence/finalized.evb \
  --receipt-out evidence/github-attestation.receipt.json \
  --raw-output-out evidence/github-attestation.raw.json \
  --out evidence/product.github-attestation.eab \
  --repo owner/project \
  --signer-workflow owner/project/.github/workflows/artifact-builder.yml \
  --signer-digest "$TRUSTED_SIGNER_WORKFLOW_SHA" \
  --source-ref refs/heads/main \
  --source-digest "$TRUSTED_FINALIZER_HEAD_SHA" \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --finalizer-pub security/finalizer-public.pem \
  --expected-source evidence/expected-source.json \
  --expected-context evidence/expected-context.json \
  --sign-key "$EVOGUARD_ARTIFACT_ADMISSION_KEY" \
  --gh-executable "$PINNED_GH"

evo-guard verify-github-attestation-admission \
  evidence/product.github-attestation.eab artifacts/product.json \
  evidence/github-attestation.receipt.json evidence/github-attestation.raw.json \
  evidence/finalized.evb \
  --repo owner/project \
  --signer-workflow owner/project/.github/workflows/artifact-builder.yml \
  --signer-digest "$TRUSTED_SIGNER_WORKFLOW_SHA" \
  --source-ref refs/heads/main \
  --source-digest "$TRUSTED_FINALIZER_HEAD_SHA" \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --trusted-pub security/artifact-admission-public.pem \
  --finalizer-pub security/finalizer-public.pem \
  --expected-source evidence/expected-source.json \
  --expected-context evidence/expected-context.json
```

`seal-github-attestation-admission` intentionally has no `--force` or
stdin/stdout mode. Each receipt, raw-output, and V2 binding path is created
with no-clobber semantics, so a protected job cannot quietly replace a prior
evidence record. The operation is not all-or-nothing: if finalizer validation
or V2 sealing fails after the fresh provider verification, the valid new
receipt and raw-output files may remain without a V2 binding and must be
retained or handled explicitly by the protected job.
`verify-github-attestation-admission` rechecks retained bytes, the exact V2
binding, both public keys, and the external finalizer `ALLOW`; it does **not**
contact GitHub. Run the explicit receipt reverify command if a fresh provider
check is required.

Their machine reports make this distinction explicit: the retained check emits
`RETAINED_RECEIPT_VERIFIED` with
`verification_scope: retained-byte-continuity-only`; a fresh run emits either
`PROVIDER_VERIFIED` or `FRESH_PROVIDER_REVERIFIED` with
`verification_scope: fresh-provider-gh-attestation-verify`. None of these
statuses claims a release gate, merge gate, publication, or deployment.

The receipt structural schema is packaged at
[`evoom_guard/schemas/github-attestation-receipt-1.schema.json`](../evoom_guard/schemas/github-attestation-receipt-1.schema.json).
