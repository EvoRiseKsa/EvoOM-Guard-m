---
source_version: 4.0.1
latest_published_version: 4.0.1
state: published
---

# Release status

The repository source now declares **v4.0.1** as the active release and it is
published as an immutable GitHub Release. The latest immutable consumer release
is [`v4.0.1`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.0.1),
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

For deterministic local verification of the published `v4.0.1` state, see:

- `tests/baseline/v4.0.1/BASELINE_MANIFEST.json`
- `tests/baseline/v4.0.1/SHA256SUMS_v4.0.1.txt`
- `docs/RELEASE_GATE_CHECKLIST.md`

The baseline set contains command captures, PASS/FAIL/REJECTED sample outputs,
pack identity vectors, detached-signature evidence, and a local `evo-guard.pyz`
with checksum manifest (`SHA256SUMS_v4.0.1.txt`).
