# Release status

<!-- BEGIN EVOGUARD_PROJECT_STATUS:RELEASE_STATUS_SUMMARY -->
Source version `4.8.0` is a **release candidate**; it is unsupported and is not yet a
consumer release. The latest immutable consumer release selected by the protected source
tree remains [`v4.7.1`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.7.1)
at commit `b222c7df0a3eaef6e89287cd1354625b88ac8b8b`. Detached-maintainer-signed record
`evidence/direct-releases/v4.7.1/DIRECT_RELEASE.json` binds the published asset
observations `evo-guard.pyz`, `evo-guard.spdx.json`, `SHA256SUMS`. It records successful
release-attestation verification for `evo-guard.pyz`, `evo-guard.spdx.json`,
`SHA256SUMS` and a provider-attestation job whose build-provenance subject is
`evo-guard.pyz` under `.github/workflows/release.yml`. The record is a same-owner
post-publication observation created after the tag; it is not part of the release, a
protected A-through-H ledger, independent review, or proof of correctness, security,
deployment, or efficacy. The latest historical validated A-through-H ledger remains
`evidence/release-ledgers/v4.6.0/RELEASE_LEDGER.json` for `v4.6.0` and does not apply to
`v4.7.1`.

Releases ship through the manually dispatched protected-release workflow
(`.github/workflows/release.yml`): tag-equals-version validation, the full test suite,
Linux and Windows end-to-end checks, a reproducible artifact build with checksums, and
asset attestation. It prepares a byte-verified draft, then a distinct protected
Environment approval authorizes a no-checkout job to revalidate live source,
tag-ruleset, signed-tag, and asset authority, publish, and prove exact immutable
readback. No release step is gated on dates, elapsed time, or stabilization windows. The
detached-maintainer-signed direct record for `v4.7.1` records successful workflow run
`33532737067` and post-publication byte readback. Its signature authenticates the exact
maintained record bytes, but the evidence remains a same-owner observation, not
independent validation or a protected A-through-H ledger. The archived A-H signed lane
is implemented in source but inert with every activation flag false; it is a design
reference, not the current release path.
<!-- END EVOGUARD_PROJECT_STATUS:RELEASE_STATUS_SUMMARY -->

The signed `v4.7.0` tag is a preserved, unpublished release attempt—not a
consumer release. Its protected workflow stopped while reading the draft; no
publication mutation or postpublication verifier ran. The exact bounded
same-owner incident record is
[`FAILED_DRAFT_ATTEMPT.json`](../evidence/release-attempts/v4.7.0/FAILED_DRAFT_ATTEMPT.json).
The tag is not moved or reused. The exact `4.7.1.dev0` evidence chain is
finalized on protected `main`, and source `4.7.1` was promoted through the
stable-only transition. Its signed annotated tag and protected workflow have
now produced the immutable `v4.7.1` consumer release. The maintained
same-owner [`DIRECT_RELEASE.json`](../evidence/direct-releases/v4.7.1/DIRECT_RELEASE.json)
authenticates the exact postpublication record; it is not an A-through-H
release ledger or independent review.

For `v4.5.0`, after the signed ledger bytes were committed and independently revalidated,
the exact temporary publication deploy key and publication Environment secret
were removed. Their later successful HTTP 200 absence observations are bound by
the separately signed
[`KEY_RETIREMENT.json`](../evidence/release-operations/v4.5.0/KEY_RETIREMENT.json)
receipt. This same-owner point-in-time record is not proof of secure erasure,
absence of external copies, or prevention of later re-addition; the immutable
ledger correctly remains unchanged at `pending-post-ledger`.

For `v4.6.0`, the committed ledger bytes were independently revalidated before
the exact temporary publication deploy key and publication Environment secret
were removed. Their later successful, fully paginated HTTP 200 absence
observations are bound by the separately signed
[`KEY_RETIREMENT.json`](../evidence/release-operations/v4.6.0/KEY_RETIREMENT.json)
receipt. This same-owner point-in-time record has the same bounded non-claims as
the `v4.5.0` receipt above. The immutable `v4.6.0` ledger correctly remains
unchanged at `pending-post-ledger`, which was its state at ledger creation time.

For re-queried live publication facts and the separate frozen-validator failure
boundaries, see the
[`v4.4.0`](errata/V4.4.0-LEDGER.md) and
[`v4.4.1`](errata/V4.4.1-LEDGER.md) release-ledger errata. Their
machine-readable observations are unsigned and intentionally outside
`evidence/release-ledgers`. They remain historical published-unledgered
exceptions; `v4.4.2` is the completed ledger-recorded recovery release.

The `v4.3.0` release adds Agent Change Admission V1. Its archived public
same-owner pilot retained one permitted run, one ignored tracked-path
rejection before signing, and one exact-change replay with detached offline
verification. This release is the bootstrap publication of that profile: it
did not use its own not-yet-published artifact to authorize its source or
publication. Publication does not make the profile a required production
gate, hostile-runner proof, single-use authorization, or independent review.

The published `v4.2.0` source line adds Release Artifact Admission V1 and its
sixth trust-key domain. This first release carrying the contract is a bootstrap
and did not use the new contract to authorize itself. Publication does not by
itself establish a live E/F/G pilot, artifact-publication authorization,
reproducible builds, production readiness, or independent security review.

A later public same-owner pilot subsequently used the immutable v4.2.0 runtime
to complete one exact protected-main A-through-G source-to-artifact round.
Protected F returned `SEALED/ALLOW`; detached G returned `VERIFIED/ALLOW` over
retained evidence without a fresh provider call; and five retained-evidence
mutations were rejected. Its exact non-secret outputs and checksums are
preserved in
[`evidence/round2`](https://github.com/EvoRiseKsa/evoom-guard-release-source-v2-pilot/tree/a1937ea599204751deebcbcadbd416092d8f46f9/evidence/round2).
The admitted object was only a 290-byte JSON descriptor. The later pilot does
not alter the bootstrap release, admit the v4.2.0 or v4.3.0 release assets,
authorize publication/deployment, prove reproducibility or production
readiness, or constitute independent review.

The published `v4.1.0` source line added Release Source Admission V2 and
associated provider/Git hardening. That bootstrap release did not admit its own
source. A later disposable consumer used the immutable `v4.1.0` runtime for one
live source-only V2 round, preserved separately in the
[`evoom-guard-release-source-v2-pilot`](https://github.com/EvoRiseKsa/evoom-guard-release-source-v2-pilot).
That later evidence does not change the frozen release, bind a release artifact
or publication, establish production readiness, or constitute independent
security review.

<!-- BEGIN EVOGUARD_PROJECT_STATUS:RELEASE_STATUS_CONSUMER_PIN -->
Consumer usage should use maintained immutable release `v4.7.1` only when aligned with
the acceptance policy; pin commit `b222c7df0a3eaef6e89287cd1354625b88ac8b8b` for the
strictest source identity. `evo-guard init` requires `--ref` explicitly: supply `v4.7.1`
or that full commit SHA. It refuses a moving branch and does not guess a latest release.
The maintained signed direct record is not an A-through-H ledger or independent review.
<!-- END EVOGUARD_PROJECT_STATUS:RELEASE_STATUS_CONSUMER_PIN -->

Historical releases retain the license and notices that shipped with them. The
EvoRise Source-Available License 1.0 applies only to material first
distributed with a published v4 release carrying that license.

## Baseline artifacts

<!-- BEGIN EVOGUARD_PROJECT_STATUS:RELEASE_STATUS_CURRENT_LEDGER -->
The protected source tree selects detached-maintainer-signed direct record
`evidence/direct-releases/v4.7.1/DIRECT_RELEASE.json` (SHA-256
`eaa7e4f640db8a777ad2632322351825307d123a6664097e544063ef361fa4c6`) and signature
`evidence/direct-releases/v4.7.1/DIRECT_RELEASE.json.sig` (SHA-256
`e7e67ef35f760c2c86c522587b4436409a96028016a8f35652827edf73b1a5bb`) for release `v4.7.1`
at commit `b222c7df0a3eaef6e89287cd1354625b88ac8b8b`. It records immutable publication
and exact post-publication readback observations for assets `evo-guard.pyz`,
`evo-guard.spdx.json`, `SHA256SUMS`. This is a same-owner record created after the tag
and excluded from its source tree and assets. It is not a protected A-through-H release
ledger, correctness verdict, production-readiness claim, independent review, or
deployment authorization. The latest historical validated A-through-H ledger is
`evidence/release-ledgers/v4.6.0/RELEASE_LEDGER.json` for `v4.6.0` and does not apply to
`v4.7.1`.
<!-- END EVOGUARD_PROJECT_STATUS:RELEASE_STATUS_CURRENT_LEDGER -->

The same bounded identity/provenance records for earlier immutable releases
remain available at:

- `tests/baseline/v4.3.0/RELEASE_LEDGER.json`
- `tests/baseline/v4.3.0/SHA256SUMS`
- `tests/baseline/v4.3.0/pyz/evo-guard.pyz`

- `tests/baseline/v4.2.0/RELEASE_LEDGER.json`
- `tests/baseline/v4.2.0/SHA256SUMS`
- `tests/baseline/v4.2.0/pyz/evo-guard.pyz`

- `tests/baseline/v4.1.0/RELEASE_LEDGER.json`
- `tests/baseline/v4.1.0/SHA256SUMS`
- `tests/baseline/v4.1.0/pyz/evo-guard.pyz`

- `tests/baseline/v4.0.2/RELEASE_LEDGER.json`
- `tests/baseline/v4.0.2/SHA256SUMS`
- `tests/baseline/v4.0.2/pyz/evo-guard.pyz`

For byte-exact offline verification of the frozen `v4.0.1` baseline, see:

- `tests/baseline/v4.0.1/BASELINE_MANIFEST.json`
- `tests/baseline/v4.0.1/release-manifest.json`
- `tests/baseline/v4.0.1/SHA256SUMS_v4.0.1.txt`
- `tests/baseline/v4.0.1/ERRATA.md`
- `docs/RELEASE_GATE_CHECKLIST.md`

The strict `baseline-v2` set contains the frozen Action contract and benchmark,
command captures, PASS/FAIL/REJECTED sample outputs, pack identity vectors,
detached-signature evidence, and the release-identical `evo-guard.pyz` with its
checksum manifest. Offline tests validate every inventoried byte, execute the
zipapp, recompute the pack identity, and verify the Ed25519 signature over the
exact historical CRLF record bytes.

The baseline records externally observed GitHub release, workflow, Marketplace,
and provenance facts. Internal consistency tests do not replace an independent
online re-query when those external facts must be trusted at a later date. The
erratum corrects the former pre-release metadata without moving the immutable
tag or changing any published asset.
