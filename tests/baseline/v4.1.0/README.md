# EvoOM Guard v4.1.0 immutable release ledger

This directory records the externally observed identity and provenance of the
published immutable `v4.1.0` release.

The committed `pyz/evo-guard.pyz` and `SHA256SUMS` are byte-exact copies of the
two published release assets. They were copied only after independent download,
checksum, release-attestation, build-attestation, and tag-CI verification; the
zipapp was not rebuilt from this later source tree.

`RELEASE_LEDGER.json` binds:

- the release tag, commit, tree, publication state, and Marketplace version;
- the exact artifact sizes and SHA-256 digests;
- the successful release workflow and tag-triggered CI runs;
- the GitHub build-provenance and release-attestation identities; and
- the stable public evidence-format contracts shipped by the release.

The offline tests validate the ledger schema, duplicate-key rejection, artifact
inventory, checksums, cross-field bindings, and executable version. GitHub state
can change outside Git, so release, run, Marketplace, and attestation state must
be re-queried when a current online assertion is required.

## Scope boundary

This is a release identity and provenance ledger, **not** a behavioral baseline.
No Action snapshot, verifier-pack vector, verdict/report/SARIF capture, signature
fixture, benchmark, or live Release Source Admission V2 round was collected for
`v4.1.0`; none is copied from another version or implied here. The release ships
the V2 implementation but cannot admit its own source. The full frozen `v4.0.1`
behavioral baseline and the historical `v4.0.2` release ledger remain separate.
