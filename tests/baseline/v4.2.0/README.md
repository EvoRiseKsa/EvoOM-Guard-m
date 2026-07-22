# EvoOM Guard v4.2.0 immutable release ledger

This directory records the externally observed identity and provenance of the
published immutable `v4.2.0` release.

The committed `pyz/evo-guard.pyz` and `SHA256SUMS` are byte-exact copies of the
two published release assets; the zipapp was not rebuilt from this later source
tree. Their bytes were subsequently verified by checksum, release attestation,
build attestation, and successful tag CI before this ledger was finalized.

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
fixture, benchmark, or live Release Artifact Admission V1 round was collected
for `v4.2.0`; none is copied from another version or implied here. The release
ships the RAAE contract but cannot use that new contract to admit its own
artifact. It does not establish a live E/F/G pilot, artifact-publication
authorization, reproducible builds, production readiness, or independent
security review. The earlier `v4.1.0` and `v4.0.2` release ledgers and the frozen
`v4.0.1` behavioral baseline remain separate.
