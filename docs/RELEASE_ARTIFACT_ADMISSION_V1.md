<!--
  Copyright (c) 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Source-available - see LICENSE for permitted use.
-->

# Release Artifact Admission V1

Release Artifact Admission V1 is the missing protected-main adapter between a
verified source authorization and one exact built file. Its signed format is
`EVOGUARD_RELEASE_ARTIFACT_ADMISSION_V1`; its canonical extension is `.raae`.

A verified `ALLOW` means only this:

> A separately protected signer verified one exact Release Source Admission V2
> `ALLOW`, one exact regular-file artifact, the distinct protected-main builder
> and admitter workflow identities, and one fresh GitHub Artifact Attestation
> result for that artifact before a sixth, separately scoped Ed25519 key signed
> the retained evidence.

It does **not** authorize publication, release creation, package upload,
deployment, execution, or production use. It does not prove reproducibility,
absence of vulnerabilities, complete correctness, or independent review.

The implementation is `evoom_guard.admission.release_artifact`. The JSON
contract is
`evoom_guard/schemas/release-artifact-admission-1.schema.json`. The older
Artifact Admission V1/V2 formats remain PR-head contracts and are not changed
or accepted as substitutes for `.rsae` or `.raae`.

## Trust topology

The intended integration has three roles after Release Source Admission A/B/C:

1. **E — manual builder and attester.** A no-secret GitHub-hosted workflow
   verifies the exact `.rsae`, builds one bounded regular file from its admitted
   protected-main commit, requests a GitHub Artifact Attestation for the exact
   bytes, and emits closed-world builder controls. Source `ALLOW` does not
   trigger E automatically.
2. **F — protected artifact admitter.** A `workflow_run` workflow validates the
   exact successful E ID, path, commit, run, and attempt before entering a
   distinct protected Environment. It binds its own key-bearing workflow ID,
   path, raw-Git blob, run, attempt, commit, and GitHub-hosted runtime as a
   separate signed role. It freshly verifies the provider evidence, then opens
   the release-artifact key last and emits `.raae`.
3. **G — detached verifier.** A no-secret workflow verifies `.raae`, the
   embedded `.rsae`, retained provider evidence, and the external artifact
   entirely offline. It has no Environment, private key, OIDC permission, or
   provider invocation.

E and F must differ in workflow ID, path, and run. Both must also differ from
all Release Source Admission evaluation, producer, and admitter roles. Their
workflow blobs are resolved from the admitted raw Git tree; workflow names are
never authority selectors.

For a same-repository build, GitHub's attestation `buildSignerDigest` and source
digest identify the admitted workflow/source commit. The workflow file's Git
blob ID is a separate raw-Git relation and must not be substituted for that
commit digest.

## Fail-closed sealing order

The admission path performs these operations before it can produce `ALLOW`:

1. reject standard-input/output paths, aliases, a wrong extension, and an
   existing output unless a lower-level caller explicitly selected atomic
   replacement;
2. validate the closed-world five-key predecessor registry and prove that the
   sixth public key is distinct;
3. prove that the isolated provider UID/GID cannot read the exact root-owned,
   mode-`0600` private-key path;
4. read one stable bounded `.rsae` snapshot and verify it as `ALLOW` against
   external source, context, A/B/C, bootstrap, provider, toolchain, and trust
   expectations;
5. consume a runtime-bound F capability that matches both the current
   `GITHUB_*` context and the exact successful E `workflow_run` payload;
6. resolve E and F workflow paths to regular blobs in the admitted raw-Git tree
   using a SHA-256-pinned Git executable;
7. hash one stable, non-symlink, bounded external artifact without executing it;
8. run a SHA-256-pinned `gh attestation verify` snapshot as the configured
   non-root provider identity and require one exact subject, repository,
   workflow, ref, source/signer digest, GitHub-hosted runner, and E run/attempt;
9. retain canonical receipt/output bytes, remove the provider workspace, and
   only then read the private key;
10. sign the canonical manifest under the distinct
    `EVOGUARD_RELEASE_ARTIFACT_ADMISSION_V1\0` domain; and
11. stage, re-open, inspect, and verify the complete canonical archive before
    one atomic no-clobber publication.

The F-capable path is deliberately POSIX-only and starts as root solely so the
provider can be lowered to a distinct non-root UID/GID. The artifact is never
executed by sealing or detached verification.

## Independent toolchain expectations

The historical `.rsae` and the new `.raae` are different verification events.
Their Git/`gh` pins and provider UID/GID expectations are therefore supplied
and checked separately. A legitimate GitHub runner or tool rotation between
the two phases must not invalidate the source decision merely because the
outer artifact phase used a newer exact tool identity.

The `.raae` manifest signs only its own Git/`gh` pins and provider isolation.
The embedded `.rsae` retains and verifies its historical toolchain in its own
signed manifest.

## Key separation

The release-artifact signer is a sixth trust domain. Its key must differ from
the closed predecessor registry:

- `trusted_finalizer`
- `artifact_admission_v1`
- `artifact_digest_admission_v2`
- `release_source_finalizer_v1`
- `release_source_admission_v2`

Arbitrary caller-selected deny lists are not a substitute for this named,
closed-world registry.

## Envelope and detached verification

The canonical `.raae` ZIP contains exactly:

```text
admission.json
admission.sig
materials/release-source-admission.rsae
provider/github-attestation-receipt.json
provider/github-attestation-output.json
```

The artifact bytes are intentionally external. Detached verification requires
the exact file, the trusted sixth public key, the Release Source Admission V2
public key, all source/A/B/C expectations, E/F expectations, both historical
and outer toolchain expectations, and all five predecessor key identities from
outside the envelope. Embedded values never choose their own trust roots.

Detached verification re-parses the retained GitHub verifier output but does
not contact GitHub or independently redo Sigstore/DSSE validation. Fresh
provider authenticity exists at sealing time; a consumer that needs current
provider state must run a separate live re-verification before any separately
authorized publication step.

## Bootstrap rule

The first EvoOM Guard release containing this adapter cannot use the adapter to
authorize itself. It must be published through the existing reviewed release
process with its immutable runtime checksum established independently. Only a
later protected-main pilot may use that published runtime to exercise E/F/G.

The first live round must remain disabled by default, use one disposable regular
file, preserve positive and negative evidence, then disable the feature and
remove the private key. It must not create a tag, release, Marketplace update,
package publication, or deployment.

## Explicit non-claims

Release Artifact Admission V1 does not establish:

- that the artifact is reproducible or equivalent to any other build;
- that dependencies, runner images, GitHub, Sigstore, or the reviewed workflow
  definitions are independently trustworthy;
- that a GitHub-hosted runner is a VM-strength hostile-code boundary;
- that a source or artifact `ALLOW` grants a publisher any permission;
- that same-owner cross-account approvals are independent review; or
- production readiness without a separately protected consumer, independent
  assessment, and preserved field evidence.
