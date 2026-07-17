<!--
  Copyright (c) 2026 Mana Alharbi. All rights reserved.
  Source-available — see LICENSE for permitted use.
-->

# GitHub Artifact Attestations for future releases

## Status and exact scope

`v3.7.0` has a GitHub **release** attestation. It does **not** have a GitHub
Actions build-artifact attestation for `evo-guard.pyz`. Do not describe the
v3.7.0 release attestation as build provenance.

After the release workflow change documented here is merged, a *future* manual
release run builds `dist/evo-guard.pyz` on the protected default branch,
checksums it, then asks GitHub to generate an artifact attestation for those
exact bytes before the file is transferred to the release-writing job. The
build job receives only `contents: read`, `id-token: write`, and
`attestations: write`; it does not receive `contents: write`.

The record is a GitHub/Sigstore artifact attestation. It is not an EvoGuard
verdict, an artifact-admission record, proof of a published release, or proof
of deployment.

## Consumer verification

Download the asset you intend to consume and verify its checksum first. Then
use a current GitHub CLI in an online environment, supplying both the linked
repository and the exact workflow identity rather than relying on a broad
owner-only lookup:

```bash
gh attestation verify ./evo-guard.pyz \
  --repo EvoRiseKsa/EvoOM-Guard-m \
  --signer-workflow EvoRiseKsa/EvoOM-Guard-m/.github/workflows/release.yml \
  --deny-self-hosted-runners \
  --format json
```

For a particular release, the caller should also constrain the source digest
to the release tag's resolved commit when its GitHub CLI supports
`--source-digest`:

```bash
gh attestation verify ./evo-guard.pyz \
  --repo EvoRiseKsa/EvoOM-Guard-m \
  --signer-workflow EvoRiseKsa/EvoOM-Guard-m/.github/workflows/release.yml \
  --source-digest "$(git rev-list -n 1 vX.Y.Z)" \
  --deny-self-hosted-runners \
  --format json
```

The second command is an additional identity constraint; it is not a
substitute for verifying the release tag and asset checksum. For offline
verification, use the GitHub CLI's downloaded attestation bundle and trusted
root procedure rather than treating a copied JSON document as a trust root.

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
that issue. The protected, end-to-end finalizer-to-artifact admission run must
still be implemented and exercised against a future release.
