<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# GitHub Artifact Attestations

## Status and exact scope

<!-- BEGIN EVOGUARD_PROJECT_STATUS:ATTESTATIONS_RELEASE_STATUS -->
Source version `4.7.0.dev0` is **unreleased development** and is not a consumer release.
The latest immutable consumer release recorded by the protected source tree is
[`v4.6.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.6.0) at commit
`d65f25f386fe6f4646ea8dd3cbbe1d5d889f73d4`. Its `evoguard-release-ledger-v2` ledger
records the release assets `evo-guard.pyz`, `evo-guard.spdx.json`, `SHA256SUMS`. Its
release attestation binds `evo-guard.pyz`, `evo-guard.spdx.json`, `SHA256SUMS`, while
its build-provenance attestation binds `evo-guard.pyz`. The ledger records the SPDX SBOM
release asset and its provenance. Canonical ledger:
`evidence/release-ledgers/v4.6.0/RELEASE_LEDGER.json`.
<!-- END EVOGUARD_PROJECT_STATUS:ATTESTATIONS_RELEASE_STATUS -->

The separate unsigned
[`v4.4.0`](../evidence/release-operations/v4.4.0/UNSEALED_STATUS.json) and
[`v4.4.1`](../evidence/release-operations/v4.4.1/UNSEALED_STATUS.json)
observation records preserve successful release-attestation and constrained
build-provenance verification. They remain outside the signed release-ledger
namespace and cannot be upgraded into canonical ledgers retroactively.

`v3.7.0` has a GitHub **release** attestation. It does **not** have a GitHub
Actions build-artifact attestation for `evo-guard.pyz`. Do not describe the
v3.7.0 release attestation as build provenance. Historical release records,
including v3.8.0, remain historical evidence; they are not the current
consumer release.

The build job receives only `contents: read`; it receives no OIDC,
attestation, or repository-write authority. A separate job with no checkout,
dependency installation, project-script execution, or zipapp execution
receives `contents: read`, `id-token: write`, and `attestations: write`. It
rechecks the exact asset set, checksum manifest, and SPDX package SHA-256
binding before requesting either provider attestation. Transfers use the
immutable artifact ID emitted by the upload step, not a mutable name lookup,
and digest mismatch is fatal. The publication job receives only the artifact
ID approved by the clean job. Artifact attestation
is not itself a reason to create a release. Follow the
[release-channel policy](../README.md#release-channel-and-accountability): make a new release only
for an intentional versioned product change, after its version and consumer
pins are updated and the protected release validation succeeds.

The record is a GitHub/Sigstore artifact attestation. It is not an EvoOM Guard
verdict, an artifact-admission record, proof of a published release, or proof
of deployment.

## Consumer verification

<!-- BEGIN EVOGUARD_PROJECT_STATUS:ATTESTATIONS_CONSUMER_VERIFICATION -->
Download the exact ledger-recorded asset set and verify its checksum
manifest:

```bash
gh release download v4.6.0 --repo EvoRiseKsa/EvoOM-Guard-m \
  --pattern evo-guard.pyz \
  --pattern evo-guard.spdx.json \
  --pattern SHA256SUMS
sha256sum --check SHA256SUMS
gh release verify v4.6.0 --repo EvoRiseKsa/EvoOM-Guard-m
```

Verify the provider statement for each non-checksum subject against the
exact workflow and source commit recorded by the validated ledger:

```bash
gh attestation verify ./evo-guard.pyz \
  --repo EvoRiseKsa/EvoOM-Guard-m \
  --signer-workflow EvoRiseKsa/EvoOM-Guard-m/.github/workflows/evoguard-build-release-artifact.yml \
  --source-ref refs/heads/main \
  --source-digest d65f25f386fe6f4646ea8dd3cbbe1d5d889f73d4 \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --deny-self-hosted-runners \
  --format json
```

```bash
gh attestation verify ./evo-guard.spdx.json \
  --repo EvoRiseKsa/EvoOM-Guard-m \
  --signer-workflow EvoRiseKsa/EvoOM-Guard-m/.github/workflows/evoguard-build-release-artifact.yml \
  --source-ref refs/heads/main \
  --source-digest d65f25f386fe6f4646ea8dd3cbbe1d5d889f73d4 \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --deny-self-hosted-runners \
  --format json
```

The release command and artifact commands are complementary. Neither
substitutes for checksum verification. The ledger records SPDX SBOM provenance for the zipapp and SPDX asset.
For offline verification, retain the provider bundles and use their
trusted-root procedure; a copied JSON document is not a trust root.
<!-- END EVOGUARD_PROJECT_STATUS:ATTESTATIONS_CONSUMER_VERIFICATION -->

## SBOM attestation contract

<!-- BEGIN EVOGUARD_PROJECT_STATUS:ATTESTATIONS_FUTURE_PIPELINE -->
The protected A-H release pipeline is implemented in source and **disabled by default**.
The legacy release workflow is hard-disabled. The externally anchored signed v2 ledger
records a completed protected A-H operation. That validated ledger also records the
resulting publication. An admitted release is contracted to exactly `evo-guard.pyz`,
`evo-guard.spdx.json`, `SHA256SUMS`; this source contract is not evidence that those
assets were published.
<!-- END EVOGUARD_PROJECT_STATUS:ATTESTATIONS_FUTURE_PIPELINE -->

For a release that actually publishes `evo-guard.spdx.json`, the
separate clean attestation job in the default-branch release workflow requests
a distinct SBOM attestation with:

- `subject-path: dist/evo-guard.pyz`; and
- `sbom-path: dist/evo-guard.spdx.json`.

The same exact zipapp is therefore the subject of both the build-provenance and
SBOM attestations. The clean job also requests a third, build-provenance
attestation whose subject is `evo-guard.spdx.json` itself. Release Artifact
Admission uses the two subject-specific build-provenance attestations to
freshly verify each published asset; the SBOM attestation separately binds the
inventory predicate to the zipapp subject. The release workflow creates the
inventory and checksums in an unprivileged build job, transfers the three files
to a clean attestation job, verifies their exact set and digest binding there,
and only then requests all three attestations. A separate write-capable job
later receives those same files for the draft release. This split prevents
candidate execution from sharing provider identity, but it is **not independent
construction or review**: the zipapp and inventory still share one workflow
and build provenance.

The in-workflow default-branch condition is a fail-closed operational guard,
not an external trust root against a maintainer who can alter the workflow at
the ref selected for `workflow_dispatch`. Do not describe this job as
environment-protected. External environment branch policy and release-artifact
admission remain prerequisites before an RAAE-governed release claim.

Before describing a release as SBOM-enabled, verify that its immutable
manually uploaded asset set contains exactly `evo-guard.pyz`,
`evo-guard.spdx.json`, and `SHA256SUMS` (GitHub-generated source archives are
separate), that both checksum lines pass, and that the provider statement
binds the downloaded zipapp to the expected SPDX predicate. The inventory
records zipapp members; it is not vulnerability scanning, VEX, license legal
review, or security/admission evidence.

## Relation to EvoOM Guard Artifact Digest Admission V2

`EVOGUARD_ARTIFACT_BINDING_V2` deliberately treats its provenance file as
opaque. It does not parse, authenticate, or interpret a GitHub attestation.
Consequently, passing the JSON output from `gh attestation verify` directly to
V2 in an ordinary PR job does not establish verified provenance.

The only intended integration sequence is:

1. An unprivileged build job creates and transfers one immutable artifact; a
   separate clean job in the reviewed default-branch workflow verifies that
   exact artifact ID and then creates its artifact attestation without
   executing candidate code.
2. A separate protected admission job downloads the exact artifact bytes,
   runs `gh attestation verify` with exact `--repo`, `--signer-workflow`, and
   when known `--source-digest` constraints, and fails closed on any error.
3. That job may preserve the verifier output as a bounded receipt and bind its
   bytes and a precise identity label with `seal-artifact-digest-admission`.
   The V2 signing key must remain separate from the Trusted Finalizer key and
   be available only after the GitHub verification succeeds.
4. A consumer independently repeats both the GitHub attestation verification
   and the EvoOM Guard V2 verification with external keys, source/context,
   artifact digest, and receipt bytes.

No candidate-controlled workflow, artifact descriptor, tag, URL, file name,
or copied receipt is an authority-bearing input in this sequence.

## Non-claims

Even after a successful GitHub attestation verification, this project does not
thereby prove:

- that a source-level EvoOM Guard finalizer approved the artifact;
- that the release asset is the artifact unless its release association and
  checksum are verified separately;
- artifact reproducibility, vulnerability status, SBOM completeness or
  correctness, registry state, publication authorization, deployment
  authorization, or runtime identity; or
- independent review of the workflow, runner, GitHub service, or this project.

This is a concrete prerequisite for the provider-specific portion of issue
[#78](https://github.com/EvoRiseKsa/EvoOM-Guard-m/issues/78), not a closure of
that issue. The `v4.3.0` source retains Release Artifact Admission V1, first
published in v4.2.0, but the release's build attestation alone does not exercise
a protected end-to-end E/F/G admission run. Separately, the later public
same-owner
[`Round 2 pilot`](https://github.com/EvoRiseKsa/evoom-guard-release-source-v2-pilot/blob/a1937ea599204751deebcbcadbd416092d8f46f9/docs/ROUND2_EVIDENCE.md)
used the immutable v4.2.0 runtime to complete one bounded E/F/G round for a
290-byte JSON descriptor. Protected F freshly verified the provider evidence
and returned `SEALED/ALLOW`; detached G returned `VERIFIED/ALLOW` over retained
evidence without a fresh provider call. That does not make the v4.3.0 release
asset admitted. Issue #78 remains open for the actual-release and OCI/registry
work it tracks; separately, this bounded pilot proves no
publication/deployment authority, reproducibility, production readiness, or
independent review.
