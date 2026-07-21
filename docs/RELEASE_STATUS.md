---
source_version: 4.0.2
latest_published_version: 4.0.1
state: pre-release
---

# Release status

The repository source now declares **v4.0.2** as the next patch version. It is
not yet a published consumer release. The latest immutable consumer release is
[`v4.0.1`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.0.1),
published from commit
[`5ed7e84017619496521b813f859a6a8bf0a2b1df`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/commit/5ed7e84017619496521b813f859a6a8bf0a2b1df).
Its `evo-guard.pyz` asset has SHA-256
`81a5139e1e0f3c5ce1f9180db85c699eec305474f9588f7d2831099defdce2f7` and a
GitHub Actions build-artifact attestation.

Consumer usage should pin to `v4.0.1` only when aligned with your acceptance
policy (typically strict SHA pinning in production). This release contains the
source-available baseline and hardening changes intended for general evaluation
and early adoption; it is not yet a third-party audited service.

`evo-guard init` now requires `--ref` explicitly. Supply an independently
inspected existing release tag such as `--ref v4.0.1`, or a full 40-hex commit
SHA for the strictest pin. It deliberately refuses a moving branch name and
does not guess a "latest" release.

Historical releases retain the license and notices that shipped with them. The
EvoRise Source-Available License 1.0 applies only to material first
distributed with a published v4 release carrying that license.

## Baseline artifacts

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
