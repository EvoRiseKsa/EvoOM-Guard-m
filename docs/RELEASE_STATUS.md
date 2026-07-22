---
source_version: 4.1.0
latest_published_version: 4.1.0
state: published
---

# Release status

The repository publishes **v4.1.0** as the current immutable consumer release:
[`v4.1.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.1.0).
The immutable tag identifies the exact protected-`main` source commit. The
release's `SHA256SUMS` asset identifies the exact `evo-guard.pyz` bytes. GitHub
provides a release attestation for the immutable release and a separate GitHub
Actions build-artifact attestation for those bytes.

The `v4.1.0` source line adds Release Source Admission V2 and associated
provider/Git hardening. This bootstrap release cannot admit its own source and
does not by itself establish a live V2 pilot, release-artifact authorization,
production readiness, or independent security review.

Consumer usage should pin to `v4.1.0` only when aligned with your acceptance
policy (typically strict SHA pinning in production). This release contains the
source-available baseline and hardening changes intended for general evaluation
and early adoption; it is not yet a third-party audited service.

`evo-guard init` now requires `--ref` explicitly. Supply an independently
inspected existing release tag such as `--ref v4.1.0`, or a full 40-hex commit
SHA for the strictest pin. It deliberately refuses a moving branch name and
does not guess a "latest" release.

Historical releases retain the license and notices that shipped with them. The
EvoRise Source-Available License 1.0 applies only to material first
distributed with a published v4 release carrying that license.

## Baseline artifacts

The minimal `v4.0.2` release ledger records the published source identity,
exact release asset bytes, release/build attestations, Marketplace observation,
and successful tag CI:

- `tests/baseline/v4.0.2/RELEASE_LEDGER.json`
- `tests/baseline/v4.0.2/SHA256SUMS`
- `tests/baseline/v4.0.2/pyz/evo-guard.pyz`

It is deliberately not described as a full behavioral capture: no v4.0.2
command, verdict, signed-evidence, verifier-pack, or benchmark fixtures were
created merely by copying v4.0.1 evidence.

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
