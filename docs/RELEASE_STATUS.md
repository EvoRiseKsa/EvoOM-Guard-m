---
source_version: 4.2.0
latest_published_version: 4.2.0
state: published
---

# Release status

The repository publishes **v4.2.0** as the current immutable consumer release:
[`v4.2.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.2.0).
The immutable tag identifies the exact protected-`main` source commit. The
release's `SHA256SUMS` asset identifies the exact `evo-guard.pyz` bytes. GitHub
provides a release attestation for the immutable release and a separate GitHub
Actions build-artifact attestation for those bytes.

The `v4.2.0` source line adds Release Artifact Admission V1 and its sixth
trust-key domain. This first release carrying the contract is a bootstrap and
did not use the new contract to authorize itself. Publication does not by
itself establish a live E/F/G pilot, artifact-publication authorization,
reproducible builds, production readiness, or independent security review.

The published `v4.1.0` source line added Release Source Admission V2 and
associated provider/Git hardening. That bootstrap release did not admit its own
source. A later disposable consumer used the immutable `v4.1.0` runtime for one
live source-only V2 round, preserved separately in the
[`evoom-guard-release-source-v2-pilot`](https://github.com/EvoRiseKsa/evoom-guard-release-source-v2-pilot).
That later evidence does not change the frozen release, bind a release artifact
or publication, establish production readiness, or constitute independent
security review.

Consumer usage should pin to `v4.2.0` only when aligned with your acceptance
policy (typically strict SHA pinning in production). This release contains the
source-available baseline and hardening changes intended for general evaluation
and early adoption; it is not yet a third-party audited service.

`evo-guard init` now requires `--ref` explicitly. Supply an independently
inspected existing release tag such as `--ref v4.2.0`, or a full 40-hex commit
SHA for the strictest pin. It deliberately refuses a moving branch name and
does not guess a "latest" release.

Historical releases retain the license and notices that shipped with them. The
EvoRise Source-Available License 1.0 applies only to material first
distributed with a published v4 release carrying that license.

## Baseline artifacts

The latest committed minimal release ledger is `v4.2.0`. It records the
post-publication source identity, exact release asset bytes, release/build
attestations, the propagated Marketplace version, and successful tag CI:

- `tests/baseline/v4.2.0/RELEASE_LEDGER.json`
- `tests/baseline/v4.2.0/SHA256SUMS`
- `tests/baseline/v4.2.0/pyz/evo-guard.pyz`

It is deliberately not described as a full behavioral capture: no v4.2.0
command, verdict, signed-evidence, verifier-pack, benchmark, or live Release
Artifact Admission V1 fixture was created merely by copying historical
evidence. Shipping the RAAE implementation does not make this release ledger a
live E/F/G pilot, an artifact admission decision, or publication authorization.

The same bounded identity/provenance records for earlier immutable releases
remain available at:

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
