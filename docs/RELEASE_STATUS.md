---
source_version: 4.0.1
latest_published_version: 4.0.0
state: pre-release
---

# Release status

The repository source currently declares **v4.0.1**, a prepared patch that is
**not yet a published GitHub Release**. The latest immutable consumer release
is [`v4.0.0`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/releases/tag/v4.0.0),
published from commit
[`301d62f2fd3e2e53b75e153201514f0f69e4ecf8`](https://github.com/EvoRiseKsa/EvoOM-Guard-m/commit/301d62f2fd3e2e53b75e153201514f0f69e4ecf8).
Its `evo-guard.pyz` asset has SHA-256
`99f9d0ed5029e22e3e06c22b32e55cfe35ce8e97568e304d4cf88a7bd19e7332` and a
GitHub Actions build-artifact attestation.

Do not install, pin, or describe `v4.0.1` as released until its immutable tag,
GitHub Release assets, checksum, and provenance have been created and
inspected. After publication, update this file and all consumer-facing
installation examples in the same reviewed follow-up.

`evo-guard init` now requires `--ref` explicitly. Supply an independently
inspected existing release tag such as `--ref v4.0.0`, or a full 40-hex commit
SHA for the strictest pin. It deliberately refuses a moving branch name and
does not guess a "latest" release.

Historical releases retain the license and notices that shipped with them. The
EvoRise Source-Available License 1.0 applies only to material first distributed
with a published v4 release carrying that license.


## Baseline artifacts

For deterministic local verification of the pre-release `v4.0.1` state, see:

- `tests/baseline/v4.0.1/BASELINE_MANIFEST.json`
- `docs/RELEASE_GATE_CHECKLIST.md`

The baseline set contains command captures, PASS/FAIL/REJECTED sample outputs,
pack identity vectors, detached-signature evidence, and a local `evo-guard.pyz`
with checksum manifest (`SHA256SUMS_v4.0.1.txt`).

