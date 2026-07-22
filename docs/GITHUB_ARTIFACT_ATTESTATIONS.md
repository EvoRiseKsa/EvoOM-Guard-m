<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# GitHub Artifact Attestations

## Status and exact scope

[`v4.2.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.2.0)
is the current published immutable GitHub Release. Its immutable tag identifies
the exact protected-`main` source commit, and the release's `SHA256SUMS` asset
identifies the exact `evo-guard.pyz` bytes.
The release has a GitHub release attestation, and this exact asset has a
separate GitHub Actions build-artifact attestation. Verification against the
published asset succeeds when constrained to the repository, the `Release`
workflow at `.github/workflows/release.yml@refs/heads/main`, the `main`
source ref, and GitHub-hosted runners.

`v3.7.0` has a GitHub **release** attestation. It does **not** have a GitHub
Actions build-artifact attestation for `evo-guard.pyz`. Do not describe the
v3.7.0 release attestation as build provenance. Historical release records,
including v3.8.0, remain historical evidence; they are not the current
consumer release.

The build job receives only `contents: read`, `id-token: write`, and
`attestations: write`; it does not receive `contents: write`. Artifact
attestation is not itself a reason to create a release. Follow the
[release-channel policy](../README.md#release-channel): make a new release only
for an intentional versioned product change, after its version and consumer
pins are updated and the protected release validation succeeds.

The record is a GitHub/Sigstore artifact attestation. It is not an EvoGuard
verdict, an artifact-admission record, proof of a published release, or proof
of deployment.

## Consumer verification

Download the asset and checksum manifest, then verify the exact bytes before
use:

```bash
gh release download v4.2.0 --repo EvoRiseKsa/EvoOM-Guard-m \
  --pattern evo-guard.pyz --pattern SHA256SUMS
sha256sum --check SHA256SUMS
```

Then use a current GitHub CLI in an online environment. First verify the
release attestation and its assets:

```bash
gh release verify v4.2.0 --repo EvoRiseKsa/EvoOM-Guard-m
```

Then verify the separate build-artifact attestation, supplying the exact
repository/workflow/source identity rather than relying on a broad owner-only
lookup:

```bash
SOURCE_DIGEST="$(gh api repos/EvoRiseKsa/EvoOM-Guard-m/commits/v4.2.0 --jq .sha)"
gh attestation verify ./evo-guard.pyz \
  --repo EvoRiseKsa/EvoOM-Guard-m \
  --signer-workflow EvoRiseKsa/EvoOM-Guard-m/.github/workflows/release.yml \
  --source-ref refs/heads/main \
  --source-digest "$SOURCE_DIGEST" \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --deny-self-hosted-runners \
  --format json
```

These checks are complementary: the release command verifies GitHub's signed
release attestation and asset digests, while the artifact command verifies the
GitHub Actions provenance identity for the local asset bytes. Neither command
substitutes for verifying the downloaded checksum. For offline verification,
use the GitHub CLI's downloaded attestation bundle and trusted-root procedure
rather than treating a copied JSON document as a trust root.
## Relation to EvoGuard Artifact Digest Admission V2

`EVOGUARD_ARTIFACT_BINDING_V2` deliberately treats its provenance file as
opaque. It does not parse, authenticate, or interpret a GitHub attestation.
Consequently, passing the JSON output from `gh attestation verify` directly to
V2 in an ordinary PR job does not establish verified provenance.

The only intended integration sequence is:

1. A protected build/release job creates the artifact attestation immediately
   after building the immutable artifact.
2. A separate protected admission job downloads the exact artifact bytes,
   runs `gh attestation verify` with exact `--repo`, `--signer-workflow`, and
   when known `--source-digest` constraints, and fails closed on any error.
3. That job may preserve the verifier output as a bounded receipt and bind its
   bytes and a precise identity label with `seal-artifact-digest-admission`.
   The V2 signing key must remain separate from the Trusted Finalizer key and
   be available only after the GitHub verification succeeds.
4. A consumer independently repeats both the GitHub attestation verification
   and the EvoGuard V2 verification with external keys, source/context,
   artifact digest, and receipt bytes.

No candidate-controlled workflow, artifact descriptor, tag, URL, file name,
or copied receipt is an authority-bearing input in this sequence.

## Non-claims

Even after a successful GitHub attestation verification, this project does not
thereby prove:

- that a source-level EvoGuard finalizer approved the artifact;
- that the release asset is the artifact unless its release association and
  checksum are verified separately;
- artifact reproducibility, vulnerability status, SBOM completeness, registry
  state, publication authorization, deployment authorization, or runtime
  identity; or
- independent review of the workflow, runner, GitHub service, or this project.

This is a concrete prerequisite for the provider-specific portion of issue
[#78](https://github.com/EvoRiseKsa/EvoOM-Guard-m/issues/78), not a closure of
that issue. The `v4.2.0` source contains Release Artifact Admission V1, but the
release's build attestation alone does not exercise a protected end-to-end E/F/G
admission run. A separate live pilot remains required before any such claim.
