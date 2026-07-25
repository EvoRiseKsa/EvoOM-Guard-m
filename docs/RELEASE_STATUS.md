# Release status

<!-- BEGIN EVOGUARD_PROJECT_STATUS:RELEASE_STATUS_SUMMARY -->
Source version `4.4.0.dev0` is **unreleased development** and is not a consumer release.
The latest immutable consumer release recorded by the protected source tree is
[`v4.3.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.3.0) at commit
`b8c61315a22741415c75e4e8828feb60c0ad5149`. Its `evoguard-release-ledger-v1` ledger
records the release assets `evo-guard.pyz`, `SHA256SUMS`. Its release attestation binds
`evo-guard.pyz`, `SHA256SUMS`, while its build-provenance attestation binds
`evo-guard.pyz`. The ledger records no SBOM release asset. Canonical ledger:
`tests/baseline/v4.3.0/RELEASE_LEDGER.json`.

The protected A-H release pipeline is implemented in source and **disabled by default**.
The legacy release workflow is hard-disabled. No externally anchored signed v2 ledger
records a completed protected A-H operation. No externally anchored signed v2 ledger
records publication by this pipeline. An admitted release is contracted to exactly
`evo-guard.pyz`, `evo-guard.spdx.json`, `SHA256SUMS`; this source contract is not
evidence that those assets were published.
<!-- END EVOGUARD_PROJECT_STATUS:RELEASE_STATUS_SUMMARY -->

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
Consumer usage should use ledger-recorded release `v4.3.0` only when aligned with the
acceptance policy; pin commit `b8c61315a22741415c75e4e8828feb60c0ad5149` for the
strictest reviewed identity. `evo-guard init` requires `--ref` explicitly: supply
`v4.3.0` or that full commit SHA. It refuses a moving branch and does not guess a latest
release.
<!-- END EVOGUARD_PROJECT_STATUS:RELEASE_STATUS_CONSUMER_PIN -->

Historical releases retain the license and notices that shipped with them. The
EvoRise Source-Available License 1.0 applies only to material first
distributed with a published v4 release carrying that license.

## Baseline artifacts

<!-- BEGIN EVOGUARD_PROJECT_STATUS:RELEASE_STATUS_CURRENT_LEDGER -->
The protected source tree selects `tests/baseline/v4.3.0/RELEASE_LEDGER.json` as the
latest ledger. Its validated `evoguard-release-ledger-v1` record binds release `v4.3.0`,
commit `b8c61315a22741415c75e4e8828feb60c0ad5149`, and assets `evo-guard.pyz`,
`SHA256SUMS`. It records no SBOM asset. This bounded identity/provenance record is not a
full behavioral capture, correctness verdict, production-readiness claim, independent
review, or deployment authorization.
<!-- END EVOGUARD_PROJECT_STATUS:RELEASE_STATUS_CURRENT_LEDGER -->

The same bounded identity/provenance records for earlier immutable releases
remain available at:

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
