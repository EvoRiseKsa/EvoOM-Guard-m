<!--
  Copyright © 2026 EvoRise Tech. All rights reserved.
  Author / original creator: Mana Alharbi.
  Licensor: EvoRise Tech.
  Source-available — see LICENSE for permitted use.
-->

# GitHub Artifact Attestations

## Status and exact scope

<!-- BEGIN EVOGUARD_PROJECT_STATUS:ATTESTATIONS_RELEASE_STATUS -->
Source version `4.8.1` is a **release candidate**; it is unsupported and is not yet a
consumer release. The latest immutable consumer release selected by the protected source
tree remains [`v4.8.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.8.0)
at commit `07e361cb9a75cc1822cd905ca65df42235b3b910`. Detached-maintainer-signed record
`evidence/direct-releases/v4.8.0/DIRECT_RELEASE.json` binds the published asset
observations `evo-guard.pyz`, `evo-guard.spdx.json`, `SHA256SUMS`. It records successful
release-attestation verification for `evo-guard.pyz`, `evo-guard.spdx.json`,
`SHA256SUMS` and a provider-attestation job whose build-provenance subject is
`evo-guard.pyz` under `.github/workflows/release.yml`. The record is a same-owner
post-publication observation created after the tag; it is not part of the release, a
protected A-through-H ledger, independent review, or proof of correctness, security,
deployment, or efficacy. The latest historical validated A-through-H ledger remains
`evidence/release-ledgers/v4.6.0/RELEASE_LEDGER.json` for `v4.6.0` and does not apply to
`v4.8.0`.
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
Download the exact direct-recorded asset set and verify its checksum
manifest:

```bash
gh release download v4.8.0 --repo EvoRiseKsa/EvoOM-Guard-m \
  --pattern evo-guard.pyz \
  --pattern evo-guard.spdx.json \
  --pattern SHA256SUMS
sha256sum --check SHA256SUMS
gh release verify v4.8.0 --repo EvoRiseKsa/EvoOM-Guard-m
```

Verify the recorded provider statement for its sole build-provenance and
SBOM subject against the exact workflow and source commit:

```bash
gh attestation verify ./evo-guard.pyz \
  --repo EvoRiseKsa/EvoOM-Guard-m \
  --signer-workflow EvoRiseKsa/EvoOM-Guard-m/.github/workflows/release.yml \
  --source-ref refs/heads/main \
  --source-digest 07e361cb9a75cc1822cd905ca65df42235b3b910 \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --deny-self-hosted-runners \
  --format json
```

The release command and artifact command are complementary. Neither
substitutes for checksum verification. The provider statement covers the
zipapp; the direct record does not claim build provenance for the SPDX release
asset. For offline verification, retain provider bundles and use their
trusted-root procedure; a copied JSON document is not a trust root. The
maintainer signature authenticates the direct record, not the truth or
independence of the same-owner observations inside it.
<!-- END EVOGUARD_PROJECT_STATUS:ATTESTATIONS_CONSUMER_VERIFICATION -->

## SBOM attestation contract

<!-- BEGIN EVOGUARD_PROJECT_STATUS:ATTESTATIONS_FUTURE_PIPELINE -->
Releases ship through the manually dispatched protected-release workflow
(`.github/workflows/release.yml`): tag-equals-version validation, the full test suite,
Linux and Windows end-to-end checks, a reproducible artifact build with checksums, and
asset attestation. It prepares a byte-verified draft, then a distinct protected
Environment approval authorizes a no-checkout job to revalidate live source,
tag-ruleset, signed-tag, and asset authority, publish, and prove exact immutable
readback. No release step is gated on dates, elapsed time, or stabilization windows. The
detached-maintainer-signed direct record for `v4.8.0` records successful workflow run
`33642398535` and post-publication byte readback. Its signature authenticates the exact
maintained record bytes, but the evidence remains a same-owner observation, not
independent validation or a protected A-through-H ledger. The archived A-H signed lane
is implemented in source but inert with every activation flag false; it is a design
reference, not the current release path.
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
